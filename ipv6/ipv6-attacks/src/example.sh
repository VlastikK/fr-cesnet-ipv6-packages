#!/usr/bin/env sh

# example.sh: Example for running wrapper script (both RRA and NCP)
#
# Copyright (c) 2015 Brno University of Technology
#
# Author(s): Libor Polčák <ipolcak@fit.vutbr.cz>
#


./wrapper.py -o eth1 -t eth2 -w 2 RRA -d 11:22:33:44:55:66 -D 2001:db8::1
./wrapper.py -o eth1 -t eth2 -w 2 RRA -d 11:22:33:44:55:66 -D 2001:db8::1 -e 180
./wrapper.py -o eth1 -t eth2 -w 2 RRA -d 11:22:33:44:55:66 -D 2001:db8::1 -e 180 -f 128

./wrapper.py -o eth1 -t eth2 -w 2 NCP -d 11:22:33:44:55:66 -D 2001:db8::1 -n fe80::32e4:dbff:fe17:efa0 0 1 1
./wrapper.py -o eth1 -t eth2 -w 2 NCP -d 11:22:33:44:55:66 -D 2001:db8::1 -n fe80::32e4:dbff:fe17:efa0 0 1 1 -e 180 -f 128
