#!/usr/bin/env python3

# reconsider .copy() and .update()
# IP_NF_TARGET_REDIRECT

from enum import Enum
import copy
import subprocess
import logging

logger = logging.getLogger(__name_)

class Command(Enum):
    APPEND = '-A'
    CHECK = '-C'
    DELETE = '-D'
    POLICY = '-P'
    NEW_CHAIN = '-N'
    FLUSH = '-F'
    DELETE_CHAIN = '-X'
    ZERO = '-Z'

class State(Enum):
    NEW = 'NEW'
    EXISTING = 'ESTABLISHED,RELATED'

class Target(Enum):
    ACCEPT = 'ACCEPT'
    DNAT = 'DNAT'
    DROP = 'DROP'
    MASQUERADE = 'MASQUERADE'
    REDIRECT = 'REDIRECT'
    SNAT = 'SNAT'
    MARK = 'MARK'
    RETURN = 'RETURN'

class Chain(Enum):
    PREROUTING = 'PREROUTING'
    FORWARD = 'FORWARD'
    INPUT = 'INPUT'
    OUTPUT = 'OUTPUT'
    POSTROUTING = 'POSTROUTING'

class Table(Enum):
    MANGLE = 'mangle'
    NAT = 'nat'
    FILTER = 'filter'

class Protocol(Enum):
    TCP = 'tcp'
    UDP = 'udp'
    ICMP = 'icmp'

class ICMP(Enum):
    ECHO_REQUEST = 'echo-request'
    ECHO_REPLY = 'echo-reply'

class RuleError(Exception):
    pass

class Rule(object):
    def __init__(self,
            command = None,
            table = None,
            chain =  None,
            protocol = None,
            icmpType = None,
            state = None,
            mark = None,
            packetInterface = None,
            packetSource = None,
            packetDestination = None,
            packetPort = None,
            outputInterface = None,
            target = None,
            targetAddress = None,
            targetPort = None,
            targetMark = None):
        self._command = command
        self._table = table
        self._chain = chain

        # Matching the packet protocol (required if ports are referenced)
        self._protocol = protocol
        # Matching the icmp type (if protocol is ICMP)
        self._icmpType = icmpType
        # Matching the connection state for the packet
        self._state = state
        # Matching a mark value on the packet
        self._mark = mark

        # Interface the packet arrived on
        self._packetInterface = packetInterface
        # Matching where the packet came from
        self._packetSource = packetSource
        # Matching where the packet was heading
        self._packetDestination = packetDestination
        # Matching the packet's port
        self._packetPort = packetPort

        # The output interface for the packet
        self._outputInterface = outputInterface
        # What to do with this packet: Accept, Drop, Redirect to a host
        self._target = target
        self._targetAddress = targetAddress
        self._targetPort = targetPort
        self._targetMark = targetMark

    def update(self, **kwargs):
        for key in kwargs:
            # TODO: hack
            attr_key = '_' + key
            if hasattr(self, attr_key):
                setattr(self, attr_key, kwargs[key])
            else:
                logger.error('Invalid key: %s', key)
                raise RuleError()
        return self

    def copy(self, **kwargs):
        return copy.copy(self).update(**kwargs)

    def args(self):
        if not self._command:
            logger.error('Must specify command.')
            raise RuleError()

        result = []

        chain_required = True
        has_jump_flag = True
        target_required = True
        table_required = True

        if self._command not in [Command.APPEND, Command.CHECK, Command.DELETE]:
            has_jump_flag = False
            if self._command == Command.NEW_CHAIN:
                target_required = False
                table_required = False
            elif self._command != Command.POLICY:
                chain_required = False
                target_required = False

        if self._table:
            result.extend(['-t', self._table.value])
        elif table_required:
            logger.error('Must specify table.')
            raise RuleError()

        result.append(self._command.value)

        if self._chain:
            result.append(self._chain.value)
        elif chain_required:
            logger.error('Chain required for %s command.', self._command.name)
            raise RuleError()

        if self._packetInterface:
            result.extend(['-i', self._packetInterface])

        if self._protocol:
            result.extend(['-p', self._protocol.value])

        if self._icmpType:
            if self._protocol != Protocol.ICMP:
                logger.error('Cannot specify ICMP type if not ICMP.')
                raise RuleError()
            result.extend(['--icmp-type', self._icmpType.value])

        if self._packetSource:
            result.extend(['-s', self._packetSource])

        if self._packetDestination:
            result.extend(['-d', self._packetDestination])

        if self._packetPort:
            if not self._protocol:
                logger.error('Port specification required protocol.')
                raise RuleError()
            result.extend(['--dport', str(self._packetPort)])

        if self._outputInterface:
            result.extend(['-o', self._outputInterface])

        if self._state:
            # state is deprecated
            #result.extend(['-m', 'state', '--state', self._state.value])
            result.extend(['-m', 'conntrack', '--ctstate', self._state.value])

        if self._mark:
            result.extend(['-m', 'mark', '--mark', str(self._mark)])

        # ACCEPT/DROP/MASQUERADE = NO DATA
        # DNAT = IP [PORT]
        # REDIRECT = PORT
        # SNAT = IP
        if self._target:
            if not target_required:
                logger.error('Command does not accept a target.')
                raise RuleError()

            if has_jump_flag:
                result.append('-j')
            result.append(self._target.value)

            # TODO: these must NOT be there if not required too, name?
            address_required = False
            mark_required = False
            #
            port_allowed = False
            port_required = False
            if self._target == Target.SNAT:
                result.append('--to-source')
                address_required = True
            elif self._target == Target.DNAT:
                result.append('--to-destination')
                address_required = True
                port_allowed = True
            elif self._target == Target.REDIRECT:
                result.append('--to-ports')
                port_allowed = True
                port_required = True
            elif self._target == Target.MARK:
                result.append('--set-mark')
                mark_required = True

            value = ''
            if self._targetAddress:
                if not address_required:
                    logger.error('Target cannot use an address.')
                    raise RuleError()
                value += self._targetAddress
            elif address_required:
                logger.error('Target requires an address.')
                raise RuleError()

            if self._targetPort:
                if not port_allowed:
                    logger.error('Target cannot use a port.')
                    raise RuleError()
                if value:
                    value += ':'
                value += str(self._targetPort)
            elif port_required:
                logger.error('Target requires a port.')
                raise RuleError()
            if value:
                result.append(value)

            if self._targetMark:
                if not mark_required:
                    logger.error('Target cannot use a mark.')
                    raise RuleError()
                result.append(str(self._targetMark))
            elif mark_required:
                logger.error('Target requires a mark.')
                raise RuleError()
        elif target_required:
            logger.error('Command requires a target.')
            raise RuleError()
        return result

    def apply(self, check = True):
        args = ['iptables'] + self.args()
        logger.debug('Applying rule: %s', repr(args))
        # TODO: python 3.5+
        #child = subprocess.run(args, stdin = subprocess.DEVNULL,
        #        stdout = subprocess.DEVNULL, stderr = subprocess.PIPE,
        #        check = check)
        #return child.returncode
        run = (subprocess.check_call if check else subprocess.call)
        returncode = run(args, stdin = subprocess.DEVNULL,
                stdout = subprocess.DEVNULL)
        return returncode

# Clears all rules and zeroes counters for a given chain
def flush(chain):
    logger.debug('Flushing chain: %s', chain.name())
    for table in Table:
        Rule(table = table, chain = chain,
                command = Command.FLUSH).apply()
        Rule(table = table, chain = chain,
                command = Command.ZERO).apply()

# Clears every rule, counter, custom chain, and sets ACCEPT policies.
def clear():
    logger.debug('Clearing rules')
    for table in Table:
        for chain in Chain:
            # not checking call because some chains lack certain tables
            Rule(table = table, chain = chain, command = Command.POLICY,
                target = Target.ACCEPT).apply(check = False)
        Rule(table = table, command = Command.FLUSH).apply()
        Rule(table = table, command = Command.DELETE_CHAIN).apply()
        Rule(table = table, command = Command.ZERO).apply()

#iptables_service="/etc/init.d/iptables"
#if [ -x "$iptables_service" ]; then
#    if "$iptables_service" save; then
#        echo "iptables service saved settings successfully."
#    else
#        echo "ERROR: iptables service failed to save settings."
#    fi
#fi
#
#if iptables-save > "$ipt_savefile"; then
#    echo "iptables settings were saved locally."
#else
#    echo "ERROR: iptables settings failed to save locally."
#fi

###############################################################################
#
#  FIGURE 1: Flow diagram to show when each chain's rules are applied.
#       KEY: Brackets table application in the chain:
#            [R]aw, [M]angle, [N]at, [F]ilter, [S]ecurity
#
#         _______       _______       ______
#        /  PRE  \     /       \     / POST \
# IN -->| ROUTING |-->| FORWARD |-->|ROUTING |--> OUT
#       | [R,M,N] |   | [M,F,S] |   | [M,N]  |
#        \_______/  N  \_______/     \______/
#            | Y                        ^
#            v                          |
#         _______                  ___________
#        /       \                /           \
#       |  INPUT  |              |   OUTPUT    |
#       | [M,F,S] |              | [R,M,N,F,S] |
#        \_______/                \___________/
#            |                          ^
#            |                          |
#             -----> Local Process -----
#
###############################################################################
#
#  DESCRIPTION:
#
#  When packets enter the router, iptables makes a "Routing Decision" The
#  router will decide if the packet needs to be forwarded, or if it is
#  destined for a local interface on the router.
#
#  If the router needs to forward the packet,
#  iptables will add it to the FORWARD chain.
#
#  If the packet is destined for a local interface on the router,
#  iptables will add it to the INPUT chain.
#
#  If a local process on the router is generating a
#  packet it will pass through the OUTPUT chain.
#
#  By default, each of the chains will accept any packet.
#
#  Each chain applies tables in the order: Mangle, Nat, Filter
#  However:
#  - PREROUTING and POSTROUTING chains have no FILTER table
#  - INPUT and FORWARD chains have no NAT table
#
###############################################################################
#
#  SOURCE: http://support.imagestream.com/iptables_Firewall.html
#  * changes have been made to the diagram and documentation provided here.
#
###############################################################################
