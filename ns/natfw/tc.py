#!/usr/bin/env python3

# NOT EVEN CLOSE TO DONE
def test_tc():

    rule = iptables.Rule(table = iptables.Table.MANGLE,
            command = iptables.Command.POSTROUTING,
            target = iptables.Target.MARK)

    # 40: default
    rule.copy(targetMark = '40/0x0000ffff').apply()

    packetClasses = {
        iptables.Protocol.TCP : {
            10: [22],  # SSH
            30: [80, 443, 993] },  # WWW, SSL, IMAP
        iptables.Protocol.UDP: {
            10: [53] } }  # DNS

    for protocol, marks in packetClasses:
        for mark, ports in marks:
            markRule = rule.copy(protocol = protocol,
                    targetMark = '%s/0x0000ffff' % mark)
            for port in ports:
                # outgoing
                markRule.copy(targetInterface = net, packetPort = port).apply()
                # incoming
                markRule.copy(packetInterface = net,
                        packetSourcePort = port).apply()


    # 20: outbound ack packets
    #     short ack packets in their own class in order to speed up downloads
    #     when uploads are occurring.
    iptables.Rule(table = iptables.Table.MANGLE,
            command = iptables.Command.FORWARD,
            targetInterface = net,
            protocol = iptables.Protocol.TCP,
            tcpFlagMask = [iptables.TCP.FIN, iptables.TCP.SYN,
                    iptables.TCP.RST, iptables.TCP.ACK],
            tcpFlags = iptables.TCP.ACK,
            packetLength = util.Range(0, 64),
            target = iptables.Target.MARK,
            targetMark = '20/0x0000ffff').apply()

    # - 500k or more already sent
    # - download rate > X
    # - THEN: cap the rate?

