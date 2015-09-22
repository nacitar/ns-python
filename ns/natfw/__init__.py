#!/usr/bin/env python3

# IP_NF_TARGET_REDIRECT
import sys
import logging

from . import iptables

import subprocess

logger = logging.getLogger(__name__)

# Loads modules
def modprobe(module, check = True):
    logger.debug('Loading module: %s', module)
    # TODO: python 3.5+
    #child = subprocess.run(['modprobe', module], stdin = subprocess.DEVNULL,
    #        stdout = subprocess.DEVNULL, stderr = subprocess.PIPE,
    #        check = check)
    #return child.returncode
    run = (subprocess.check_call if check else subprocess.call)
    returncode = run(['modprobe', module], stdin = subprocess.DEVNULL,
            stdout = subprocess.DEVNULL)
    return returncode


def ModuleError(Exception):
    pass

# Loads all required modules, raising exceptions otherwise
# ModuleError or CalledProcessError
def initialize():
    # Load required modules
    for module in ['ip_tables',
            'nf_conntrack', 'nf_conntrack_ftp', 'nf_conntrack_irc',
            'nf_nat', 'nf_nat_ftp',
            'iptable_mangle', 'iptable_nat', 'iptable_filter']:
        modprobe(module)
    # The state module was renamed, try to load either one
    if (modprobe('xt_state', check = False) != 0
            and modprobe('ipt_state', check = False) != 0):
        logger.error('Module required: xt_state OR ipt_state')
        raise ModuleError()

    required_sysctl = []
    for key in ['net.ipv4.ip_forward', 'net.ipv4.ip_dynaddr']:

        value = int(subprocess.check_output(['sysctl', '-n', key]))
        if value != 1:
            required_sysctl.append(key + ' = 1')
    if required_sysctl:
        raise RuntimeError('Invalid sysctl values.  You must either add them'
                ' to sysctl.conf and reboot or set them temporarily with'
                ' "sysctl -w <key>=<value>".  Really, though, you NEED to'
                ' update the configuration!  The required values are: \n%s' %
                '\n'.join(required_sysctl))
    # Kernel: Enable NAT
    #if sysctl('-w', 'net.ipv4.ip_forward=1') != 0:
    #    raise RuntimeError('Failed to enable net.ipv4.ip_forward in kernel.')
    # Kernel: Allow detection of a new dynamic address (if any)
    #if sysctl('-w', 'net.ipv4.ip_dynaddr=1') != 0:
    #    raise RuntimeError('Failed to enable net.ipv4.ip_dynaddr in kernel.')


class Router(object):
    def __init__(self, lan, net, lo = 'lo', open_port_flag = (1 << 16)):
        self._LAN = lan
        self._NET = net
        self._LO = lo
        # Set and match just the flag, ignoring other bits
        self._OPEN_PORT_FLAG = '0x%08X/0x%08X' % (
                open_port_flag, open_port_flag)

        # Load modules, check kernel settings, ...
        initialize()

    def open_port(self, protocol, packetPort, targetPort = None):
        if targetPort is None:
            targetPort = packetPort

        # A base rule
        preRule = Rule(table = Table.FILTER, chain = Chain.PREROUTING,
                command = Command.APPEND, packetInterface = self._NET,
                protocol = protocol, packetPort = packetPort)

        # Mark this packet as one we want open
        preRule.copy(table = Table.MANGLE, target = Target.MARK,
                targetMark = self._OPEN_PORT_FLAG).apply()

        if packetPort != targetPort:
            # Redirect to the desired internal port
            preRule.copy(table = Table.NAT, target = Target.REDIRECT,
                    targetPort = targetPort).apply()
        return

    def forward_port(self, protocol, packetPort, targetAddress,
            targetPort = None):
        if targetPort is None:
            targetPort = packetPort
        # DNAT the packet to the proper recipient
        iptables.Rule(
                table = iptables.Table.NAT,
                chain = iptables.Chain.PREROUTING,
                command = iptables.Command.APPEND,
                packetInterface = self._NET,
                protocol = protocol,
                packetPort = packetPort,
                target = iptables.Target.DNAT,
                targetAddress = targetAddress,
                targetPort = targetPort).apply()
        return

    def allow_ping(self):
        # Just like open_port, but for ICMP ECHO_REQUEST packets
        iptables.Rule(
                table = iptables.Table.MANGLE,
                chain = iptables.Chain.PREROUTING,
                command = iptables.Command.APPEND,
                packetInterface = self._NET,
                protocol = iptables.Protocol.ICMP,
                icmpType = iptables.ICMP.ECHO_REQUEST,
                target = iptables.Target.MARK,
                targetMark = self._OPEN_PORT_FLAG).apply()

    def set_policy(self, open = False):
        target = (open ? iptables.Target.ACCEPT : iptables.Target.DROP)
        # Set default policy for input packets
        iptables.Rule(
                table = iptables.Table.FILTER,
                chain = iptables.Chain.INPUT,
                command = iptables.Command.POLICY,
                target = target).apply()

    def open(self):
        self.set_policy(open = True)

    def close(self):
        self.set_policy(open = False)

    def reset(self):
        # Clear everything.
        iptables.clear()

        #
        # FORWARD CHAIN RULES
        #

        # DEFAULT MUST BE ACCEPT (I think)

        rule = iptables.Rule(
                table = iptables.Table.FILTER,
                chain = iptables.Chain.FORWARD,
                command = iptables.Command.APPEND,
                target = iptables.Target.ACCEPT)

        # LAN: Forward to NET
        rule.packetInterface, rule.outputInterface = self._LAN, self._NET
        rule.apply()

        # NET: Forward to LAN
        rule.packetInterface, rule.outputInterface = self._NET, self._LAN
        rule.apply()

        #
        # INPUT CHAIN RULES
        #

        # Default policy is not set here; open() and close() control it.

        # ALL: Allow all established connections
        #inputRule.copy(state = State.EXISTING).apply()
        iptables.Rule(
                table = iptables.Table.FILTER,
                chain = iptables.Chain.INPUT,
                command = iptables.Command.APPEND,
                state = iptables.State.EXISTING,
                target = iptables.Target.ACCEPT).apply()

        # LO: Allow all new connections
        #inputRule.copy(packetInterface = self._LO, state = State.NEW).apply()
        iptables.Rule(
                table = iptables.Table.FILTER,
                chain = iptables.Chain.INPUT,
                command = iptables.Command.APPEND,
                packetInterface = self._LO,
                state = iptables.State.NEW,
                target = iptables.Target.ACCEPT).apply()


        # LAN: Allow all new connections
        #inputRule.copy(packetInterface = self._LAN, state = State.NEW).apply()
        iptables.Rule(
                table = iptables.Table.FILTER,
                chain = iptables.Chain.INPUT,
                command = iptables.Command.APPEND,
                packetInterface = self._LAN,
                state = iptables.State.NEW,
                target = iptables.Target.ACCEPT).apply()

        # NET: Allow only connections with the open-port-flag set
        #inputRule.copy(packetInterface = self._NET, state = State.NEW,
        #        mark = self._OPEN_PORT_FLAG)).apply()
        iptables.Rule(
                table = iptables.Table.FILTER,
                chain = iptables.Chain.INPUT,
                command = iptables.Command.APPEND,
                packetInterface = self._NET,
                state = iptables.State.NEW,
                mark = self._OPEN_PORT_FLAG,
                target = iptables.Target.ACCEPT).apply()

        #
        # POSTROUTING CHAIN RULES
        #

        # DEFAULT MUST BE ACCEPT

        # NET: If the connection is outgoing to NET, masquerade it as your own
        #postRule.copy(outputInterface = self._NET, target = Target.MASQUERADE).apply()
        iptables.Rule(
                table = iptables.Table.NAT,
                chain = iptables.Chain.POSTROUTING,
                command = iptables.Command.APPEND,
                outputInterface = self._NET,
                target = iptables.Target.MASQUERADE).apply()


        return 0

