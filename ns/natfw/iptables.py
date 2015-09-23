#!/usr/bin/env python3

# reconsider .copy() and .update()
# IP_NF_TARGET_REDIRECT

from enum import Enum
import copy
import subprocess
import logging

logger = logging.getLogger(__name__)

class Command(Enum):
    INSERT = '-I'
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
    ESTABLISHED = 'ESTABLISHED'
    RELATED = 'RELATED'

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
    _KEYS = ['command', 'index', 'table', 'chain', 'protocol', 'icmpType',
            'state', 'mark', 'packetInterface', 'packetSource',
            'packetDestination', 'packetPort', 'outputInterface', 'target',
            'targetAddress', 'targetPort', 'targetMark']

    def __init__(self, **kwargs):
        # Get all defaults of None
        values = dict.fromkeys(self.__class__._KEYS)
        # Merge in specified overrides
        values.update(kwargs)
        # Actually set the attributes
        self.update(**values)

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if key in self.__class__._KEYS:
                setattr(self, key, value)
            else:
                logger.error('Invalid key: %s', key)
                raise RuleError()
        return self

    def copy(self, **kwargs):
        return copy.copy(self).update(**kwargs)

    def args(self):
        if not self.command:
            logger.error('Must specify command.')
            raise RuleError()

        result = []

        chain_required = True
        has_jump_flag = True
        target_required = True
        table_required = True

        if self.command not in [Command.APPEND, Command.INSERT,
                Command.CHECK, Command.DELETE]:
            has_jump_flag = False
            if self.command == Command.NEW_CHAIN:
                target_required = False
            elif self.command != Command.POLICY:
                chain_required = False
                target_required = False

        if self.table:
            result.extend(['-t', self.table.value])
        elif table_required:
            logger.error('Must specify table.')
            raise RuleError()

        result.append(self.command.value)

        if self.index:
            if self.command != Command.INSERT:
                logger.error('index allowed only for INSERT command.')
                raise RuleError()
            result.append(str(self.index))

        if self.chain:
            result.append(self.chain.value)
        elif chain_required:
            logger.error('Chain required for %s command.', self.command.name)
            raise RuleError()

        if self.packetInterface:
            result.extend(['-i', self.packetInterface])

        if self.protocol:
            result.extend(['-p', self.protocol.value])

        if self.icmpType:
            if self.protocol != Protocol.ICMP:
                logger.error('Cannot specify ICMP type if not ICMP.')
                raise RuleError()
            result.extend(['--icmp-type', self.icmpType.value])

        if self.packetSource:
            result.extend(['-s', self.packetSource])

        if self.packetDestination:
            result.extend(['-d', self.packetDestination])

        if self.packetPort:
            if not self.protocol:
                logger.error('Port specification required protocol.')
                raise RuleError()
            result.extend(['--dport', str(self.packetPort)])

        if self.outputInterface:
            result.extend(['-o', self.outputInterface])

        if self.state:
            # state is deprecated
            #result.extend(['-m', 'state', '--state', self.state.value])
            try:
                # Support a list of states
                value = ','.join([element.value for element in self.state])
            except:
                # Support a single state
                value = self.state.value
            result.extend(['-m', 'conntrack', '--ctstate', value])

        if self.mark:
            result.extend(['-m', 'mark', '--mark', str(self.mark)])

        # ACCEPT/DROP/MASQUERADE = NO DATA
        # DNAT = IP [PORT]
        # REDIRECT = PORT
        # SNAT = IP
        if self.target:
            if not target_required:
                logger.error('Command does not accept a target.')
                raise RuleError()

            if has_jump_flag:
                result.append('-j')
            result.append(self.target.value)

            # TODO: these must NOT be there if not required too, name?
            address_required = False
            mark_required = False
            #
            port_allowed = False
            port_required = False
            if self.target == Target.SNAT:
                result.append('--to-source')
                address_required = True
            elif self.target == Target.DNAT:
                result.append('--to-destination')
                address_required = True
                port_allowed = True
            elif self.target == Target.REDIRECT:
                result.append('--to-ports')
                port_allowed = True
                port_required = True
            elif self.target == Target.MARK:
                result.append('--set-mark')
                mark_required = True

            value = ''
            if self.targetAddress:
                if not address_required:
                    logger.error('Target cannot use an address.')
                    raise RuleError()
                value += self.targetAddress
            elif address_required:
                logger.error('Target requires an address.')
                raise RuleError()

            if self.targetPort:
                if not port_allowed:
                    logger.error('Target cannot use a port.')
                    raise RuleError()
                if value:
                    value += ':'
                value += str(self.targetPort)
            elif port_required:
                logger.error('Target requires a port.')
                raise RuleError()
            if value:
                result.append(value)

            if self.targetMark:
                if not mark_required:
                    logger.error('Target cannot use a mark.')
                    raise RuleError()
                result.append(str(self.targetMark))
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
        if check:
            run = subprocess.check_call
            stderr = None
        else:
            run = subprocess.call
            stderr = subprocess.DEVNULL
        returncode = run(args, stdin = subprocess.DEVNULL,
                stdout = subprocess.DEVNULL, stderr = stderr)
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
