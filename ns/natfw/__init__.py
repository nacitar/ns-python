#!/usr/bin/env python3

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
    USER_CONFIG = 'ns_user_config'
    USER_INCOMING = 'ns_user_in'
    NAT_INCOMING = 'ns_nat_in'
    NAT_OUTGOING = 'ns_nat_out'

# Loads modules
def modprobe(module, check = True):
    logger.debug('Loading module: %s', module)
    # TODO: python 3.5+
    #child = subprocess.run(['modprobe', module], stdin = subprocess.DEVNULL,
    #        stdout = subprocess.DEVNULL, stderr = subprocess.PIPE,
    #        check = check)
    #return child.returncode
    if check:
        run = subprocess.check_call
        stderr = None
    else:
        run = subprocess.call
        stderr = subprocess.DEVNULL
    returncode = run(['modprobe', module], stdin = subprocess.DEVNULL,
            stdout = subprocess.DEVNULL, stderr = stderr)
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


# If the tables already exist, this will fail.
def install(lan, net):
    rule = iptables.Rule(command = iptables.Command.NEW_CHAIN)

    # Create USER_CONFIG
    rule.update(table = iptables.Table.MANGLE,
            chain = InternalChain.USER_CONFIG).apply()
    rule.update(table = iptables.Table.NAT).apply()
    # Create USER_INCOMING
    rule.update(table = iptables.Table.FILTER,
            chain = InternalChain.USER_INCOMING).apply()
    # Disable config
    enable_config(False)

    # Create NAT_OUTGOING
    rule.update(table = iptables.Table.FILTER,
            chain = InternalChain.NAT_OUTGOING).apply()
    rule.update(table = iptables.Table.NAT).apply()
    # Create NAT_INCOMING
    rule.update(table = iptables.Table.FILTER,
            chain = InternalChain.NAT_INCOMING).apply()
    # Disable NAT
    enable_nat(False)

    # FIREWALL: Accept open ports
    iptables.Rule(table = iptables.Table.FILTER,
        chain = InternalChain.USER_INCOMING,
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

    # INSTALL: Connect FILTER(FORWARD) and NAT(POSTROUTING) to NAT_OUTGOING
    rule = iptables.Rule(command = iptables.Command.APPEND,
            target = InternalChain.NAT_OUTGOING)
    rule.copy(table = iptables.Table.FILTER,
            chain = iptables.Chain.FORWARD).apply()
    rule.copy(table = iptables.Table.NAT,
            chain = iptables.Chain.POSTROUTING).apply()

    # INSTALL: Connect FILTER(INPUT) to NAT_INCOMING
    iptables.Rule(table = iptables.Table.FILTER,
            chain = iptables.Chain.INPUT,
            command = iptables.Command.APPEND,
            target = InternalChain.NAT_INCOMING).apply()

    # INSTALL: Connect MANGLE/NAT(PREROUTING) to CONFIG
    rule = iptables.Rule(chain = iptables.Chain.PREROUTING,
            command = iptables.Command.APPEND,
            target = InternalChain.USER_CONFIG)
    rule.copy(table = iptables.Table.MANGLE).apply()
    rule.copy(table = iptables.Table.NAT).apply()
    
    # INSTALL: Connect FILTER(INPUT) to USER_INCOMING
    iptables.Rule(table = iptables.Table.FILTER,
            chain = iptables.Chain.INPUT,
            command = iptables.Command.APPEND,
            target = InternalChain.USER_INCOMING).apply()


def _apply_if(rule, state):
    result = rule.copy(command = iptables.Command.CHECK).apply(check = False)
    if (result == 0) == state:
        rule.apply()

def enable_firewall(enabled = True):
    if enabled:
        target = iptables.Target.ACCEPT
    else:
        target = iptables.Target.DROP

    iptables.Rule(
            table = iptables.Table.FILTER,
            chain = iptables.Chain.INPUT,
            command = iptables.Command.POLICY,
            target = target).apply()

def enable_nat(enabled = True):
    if enabled:
        command = iptables.Command.DELETE
    else:
        command = iptables.Command.INSERT

    rule = iptables.Rule(command = command,
            chain = InternalChain.NAT_OUTGOING,
            target = iptables.Target.RETURN) 
    _apply_if(rule.update(table = iptables.Table.NAT), enabled)
    _apply_if(rule.update(table = iptables.Table.FILTER), enabled)
    _apply_if(rule.update(chain = InternalChain.NAT_INCOMING), enabled)

def enable_config(enabled = True):
    if enabled:
        command = iptables.Command.DELETE
    else:
        command = iptables.Command.INSERT

    rule = iptables.Rule(command = command,
            chain = InternalChain.USER_CONFIG,
            target = iptables.Target.RETURN) 
    _apply_if(rule.update(table = iptables.Table.MANGLE), enabled)
    _apply_if(rule.update(table = iptables.Table.NAT), enabled)

    _apply_if(rule.update(table = iptables.Table.FILTER,
            chain = InternalChain.USER_INCOMING), enabled)

# Enables all features
def enable(enabled = True):
    enable_firewall(enabled)
    enable_nat(enabled)
    enable_config(enabled)

def open(packetInterface = None, protocol = None, packetPort = None,
        targetPort = None, icmpType = None):
    if targetPort is None:
        targetPort = packetPort
    
    rule = iptables.Rule(
            chain = InternalChain.USER_CONFIG,
            command = iptables.Command.APPEND,
            packetInterface = packetInterface,
            protocol = protocol,
            packetPort = packetPort,
            icmpType = icmpType)

    # Mark this packet as one we want open
    rule.copy(
            table = iptables.Table.MANGLE,
            target = iptables.Target.MARK,
            targetMark = _OPEN_PORT_FLAG).apply()

    if packetPort != targetPort:
        # Redirect to the desired internal port
        rule.copy(
                table = iptables.Table.NAT,
                target = iptables.Target.REDIRECT,
                targetPort = targetPort).apply()
    return

def forward(packetInterface, protocol, packetPort, targetAddress,
        targetPort = None):
    if targetPort is None:
        targetPort = packetPort
    # DNAT the packet to the proper recipient
    iptables.Rule(
            table = iptables.Table.NAT,
            chain = InternalChain.USER_CONFIG,
            command = iptables.Command.APPEND,
            packetInterface = packetInterface,
            protocol = protocol,
            packetPort = packetPort,
            target = iptables.Target.DNAT,
            targetAddress = targetAddress,
            targetPort = targetPort).apply()
    return

def clear():
    iptables.clear()
    return 0
