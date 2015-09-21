#!/usr/bin/env python3
import sys
import natfw

import logging
def main():
    # Log everything to stdout
    logging.basicConfig(stream = sys.stdout, level = logging.DEBUG)

    # Clear everything
    natfw.iptables.clear()

    # Create our router object
    router = natfw.Router(lan='enp0s8', net='enp0s3')

    # Only let approved incoming connections through the firewall
    router.close()

    # Install the router's rules
    router.reset()

    # User settings
    router.open_port(Protocol.TCP, 64722, 22)
    router.open_port(Protocol.TCP, 80)
    router.allow_ping()
    router.forward_port(Protocol.TCP, 10122, '172.18.0.101', 22)

    return 0


if __name__ == '__main__':
    sys.exit(main())
