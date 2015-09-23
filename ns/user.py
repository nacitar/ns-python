#!/usr/bin/env python3
import sys
import natfw
import logging

from natfw.iptables import Protocol

def main():
    LAN = 'enp0s8'
    NET = 'enp0s3'
    LO = 'lo'

    # Log everything to stdout
    logging.basicConfig(stream = sys.stdout, level = logging.DEBUG)

    # Use a simple installation
    natfw.simple(lan = LAN, net = NET)

    # Allow ICMP (ping, etc...) from anywhere
    natfw.open(NET, Protocol.ICMP)
    # Allow everything from localhost
    natfw.open(LO)
    # Allow everything from LAN
    natfw.open(LAN)

    # User settings
    natfw.open(NET, Protocol.TCP, 64722, 22)
    natfw.open(NET, Protocol.TCP, 80)
    natfw.forward(NET, Protocol.TCP, 10122, '172.18.0.101', 22)

    return 0

if __name__ == '__main__':
    sys.exit(main())
