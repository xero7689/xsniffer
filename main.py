import sys
import os

import socket
import optparse
from xsniffer import Sniffer

def main():
    parser = optparse.OptionParser("Usage -h <target host> -p <target port>")
    parser.add_option("-H", dest="tgtHost", type="string", help="specify target host")
    parser.add_option("-P", dest="tgtprtcl", default="icmp", type="string", help="specify target protocol")

    (options, args) = parser.parse_args()

    tgtHost = options.tgtHost
    tgtProtocol = options.tgtprtcl

    if tgtHost:
        if tgtProtocol == "TCP":
            proto = socket.IPPROTO_TCP
        elif tgtProtocol == "UDP":
            proto = socket.IPPROTO_UDP
        elif tgtProtocol == "ICMP":
            proto = socket.IPPROTO_ICMP

        s = Sniffer(proto)
        s.run(tgtHost)
    else:
        print(parser.usage)

if __name__ == "__main__":
    main()