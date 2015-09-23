#!/usr/bin/env python3
import sys
import natfw

from natfw.iptables import Protocol

import logging
def main():
    LAN = 'enp0s8'
    NET = 'enp0s3'
    LO = 'lo'

    # Log everything to stdout
    logging.basicConfig(stream = sys.stdout, level = logging.DEBUG)

    # Load modules (GOOD PRACTICE)
    natfw.load_modules()

    # Clear everything (REQ for first time)
    natfw.clear()

    # Initialize the custom tables (REQ for first time)
    natfw.install(lan = LAN, net = NET)

    # Enable features
    natfw.enable()

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
