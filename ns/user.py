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
    natfw.initialize(lan = LAN, net = NET)

    # Enable features
    natfw.enable_nat()
    natfw.enable_firewall()

    # Only let approved incoming connections through the firewall
    natfw.close()

    # Allow ping from anywhere
    natfw.allow_ping(None)

    # Allow everything from localhost
    natfw.open_port(LO, None, None)
    natfw.allow_ping(LO)

    # Allow everything from LAN
    natfw.open_port(LAN, None, None)
    natfw.allow_ping(LAN)

    # User settings
    natfw.open_port(NET, Protocol.ICMP, None)
    natfw.allow_ping(NET)
    natfw.open_port(NET, Protocol.TCP, 64722, 22)
    natfw.open_port(NET, Protocol.TCP, 80)
    natfw.forward_port(NET, Protocol.TCP, 10122, '172.18.0.101', 22)

    return 0


if __name__ == '__main__':
    sys.exit(main())
