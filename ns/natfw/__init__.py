#!/usr/bin/env python3

# TODO: rename rule!
# TODO: hide stderr
# TODO: allow multiple initialize calls without wiping rules

# IP_NF_TARGET_REDIRECT
import sys
import logging
from enum import Enum

from . import iptables

import subprocess

logger = logging.getLogger(__name__)

# Set and match just the flag, ignoring other bits
_OPEN_PORT_BIT = (1 << 16)
_OPEN_PORT_FLAG = '0x%08X/0x%08X' % (
        _OPEN_PORT_BIT, _OPEN_PORT_BIT)

class InternalChain(Enum):
    FIREWALL_CONFIG = 'firewall_config'
    FIREWALL_INCOMING = 'firewall_incoming'
    NAT_INCOMING = 'nat_incoming'
    NAT_OUTGOING = 'nat_outgoing'

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
def load_modules():
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

def initialize(lan, net):
    rule = iptables.Rule(command = iptables.Command.NEW_CHAIN)

    # Create FIREWALL_CONFIG
    rule.update(table = iptables.Table.MANGLE,
            chain = InternalChain.FIREWALL_CONFIG).apply()
    rule.update(table = iptables.Table.NAT).apply()
    # Create FIREWALL_INCOMING
    rule.update(table = iptables.Table.FILTER,
            chain = InternalChain.FIREWALL_INCOMING).apply()
    # Create NAT_OUTGOING
    rule.update(table = iptables.Table.FILTER,
            chain = InternalChain.NAT_OUTGOING).apply()
    rule.update(table = iptables.Table.NAT).apply()
    # Create NAT_INCOMING
    rule.update(table = iptables.Table.FILTER,
            chain = InternalChain.NAT_INCOMING).apply()

    # FIREWALL: Accept open ports
    iptables.Rule(table = iptables.Table.FILTER,
        chain = InternalChain.FIREWALL_INCOMING,
        command = iptables.Command.APPEND,
        mark = _OPEN_PORT_FLAG,
        target = iptables.Target.ACCEPT).apply()

    # NAT: Accept established connections
    iptables.Rule(table = iptables.Table.FILTER,
        chain = InternalChain.NAT_INCOMING,
        command = iptables.Command.APPEND,
        state = [iptables.State.ESTABLISHED, iptables.State.RELATED],
        target = iptables.Target.ACCEPT).apply()

    # NAT: Forward LAN to NET
    iptables.Rule(table = iptables.Table.FILTER,
            chain = InternalChain.NAT_OUTGOING,
            command = iptables.Command.APPEND,
            packetInterface = lan,
            outputInterface = net,
            target = iptables.Target.ACCEPT).apply()

    # NAT: If outgoing to NET, masquerade as coming from this machine
    iptables.Rule(table = iptables.Table.NAT,
            chain = InternalChain.NAT_OUTGOING,
            command = iptables.Command.APPEND,
            outputInterface = net,
            target = iptables.Target.MASQUERADE).apply()

def _apply_if(rule, state):
    result = rule.copy(command = iptables.Command.CHECK).apply(check = False)
    if (result == 0) == state:
        rule.apply()

def enable_nat(enabled = True):
    if enabled:
        command = iptables.Command.PREPEND
    else:
        command = iptables.Command.DELETE
    # FORWARD (FILTER) and POSTROUTING (NAT) connect to NAT_OUTGOING
    rule = iptables.Rule(command = command,
            target = InternalChain.NAT_OUTGOING)
    _apply_if(rule.copy(table = iptables.Table.FILTER,
            chain = iptables.Chain.FORWARD), not enabled)
    _apply_if(rule.copy(table = iptables.Table.NAT,
            chain = iptables.Chain.POSTROUTING), not enabled)

    # INPUT (FILTER) connects to NAT_INCOMING
    _apply_if(iptables.Rule(table = iptables.Table.FILTER,
            chain = iptables.Chain.INPUT,
            command = command,
            target = InternalChain.NAT_INCOMING), not enabled)


def enable_firewall(enabled = True):
    if enabled:
        command = iptables.Command.PREPEND
    else:
        command = iptables.Command.DELETE
    # PREROUTING (NAT/MANGLE) connects to FIREWALL_CONFIG
    rule = iptables.Rule(chain = iptables.Chain.PREROUTING,
            command = command,
            target = InternalChain.FIREWALL_CONFIG)
    _apply_if(rule.copy(table = iptables.Table.MANGLE), not enabled)
    _apply_if(rule.copy(table = iptables.Table.NAT), not enabled)

    # INPUT (FILTER) connects to FIREWALL_INCOMING
    _apply_if(iptables.Rule(table = iptables.Table.FILTER,
            chain = iptables.Chain.INPUT,
            command = command,
            target = InternalChain.FIREWALL_INCOMING), not enabled)

def open_port(packetInterface, protocol, packetPort, targetPort = None):
    if targetPort is None:
        targetPort = packetPort

    # PREROUTING rules
    preRule = iptables.Rule(
            chain = InternalChain.FIREWALL_CONFIG,
            command = iptables.Command.APPEND,
            packetInterface = packetInterface,
            protocol = protocol,
            packetPort = packetPort)

    # Mark this packet as one we want open
    preRule.copy(
            table = iptables.Table.MANGLE,
            target = iptables.Target.MARK,
            targetMark = _OPEN_PORT_FLAG).apply()

    if packetPort != targetPort:
        # Redirect to the desired internal port
        preRule.copy(
                table = iptables.Table.NAT,
                target = iptables.Target.REDIRECT,
                targetPort = targetPort).apply()
    return

def forward_port(packetInterface, protocol, packetPort, targetAddress,
        targetPort = None):
    if targetPort is None:
        targetPort = packetPort
    # DNAT the packet to the proper recipient
    iptables.Rule(
            table = iptables.Table.NAT,
            chain = InternalChain.FIREWALL_CONFIG,
            command = iptables.Command.APPEND,
            packetInterface = packetInterface,
            protocol = protocol,
            packetPort = packetPort,
            target = iptables.Target.DNAT,
            targetAddress = targetAddress,
            targetPort = targetPort).apply()
    return

def allow_ping(packetInterface):
    # Just like open_port, but for ICMP ECHO_REQUEST packets
    iptables.Rule(
            table = iptables.Table.MANGLE,
            chain = InternalChain.FIREWALL_CONFIG,
            command = iptables.Command.APPEND,
            packetInterface = packetInterface,
            protocol = iptables.Protocol.ICMP,
            icmpType = iptables.ICMP.ECHO_REQUEST,
            target = iptables.Target.MARK,
            targetMark = _OPEN_PORT_FLAG).apply()

def set_policy(open = False):
    target = iptables.Target.ACCEPT if open else iptables.Target.DROP
    # Set default policy for input packets
    iptables.Rule(
            table = iptables.Table.FILTER,
            chain = iptables.Chain.INPUT,
            command = iptables.Command.POLICY,
            target = target).apply()

def open():
    set_policy(open = True)

def close():
    set_policy(open = False)


def clear():
    iptables.clear()
    return 0
