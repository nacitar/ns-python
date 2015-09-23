#!/usr/bin/env python3

# NOT EVEN CLOSE TO DONE
def test_tc():

    rule = iptables.Rule(table = iptables.Table.MANGLE,
            command = iptables.Command.POSTROUTING,
            target = iptables.Target.MARK)
    # default mark
    rule.copy(targetMark = '40/0x0000ffff').apply()

    tcpRule = rule.copy(protocol = iptables.Protocol.TCP)

    # mark http and https traffic as 30, both in and out
    httpRule = tcpRule.copy(targetMark = '30/0x0000ffff')
    # Out then in
    httpRule.copy(targetInterface = net, packetPort = 80).apply()
    httpRule.copy(packetInterface = net, packetPort = 80).apply()
    # Out then in
    httpRule.copy(targetInterface = net, packetPort = 443).apply()
    httpRule.copy(packetInterface = net, packetPort = 443).apply()


