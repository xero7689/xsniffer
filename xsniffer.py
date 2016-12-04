import socket
import os

from pktStruct.IP import IP_64
from pktStruct.TCP import TCP_64


class Sniffer(object):
    def __init__(self, ip_protocol):
        self.ipproto = ip_protocol

    def run(self, tgtHost):
        """
        IPV4 Sniffer

        :param tgtHost: Target Host
        :return:
        """
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.ipproto)

        for port in range(32768, 60999):
            try:
                sniffer.bind(tgtHost, port)
                print("[*] Sniffer bind at {} - {}".format(tgtHost, port))
                break
            except:
                continue

        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        while True:
            try:
                yield sniffer.recvfrom(65565)[0]
                #raw_buffer = sniffer.recvfrom(65565)[0]
                #ip_header = IP_64(raw_buffer[0:24])
                #print("{} {} -> {}".format(ip_header.protocol, ip_header.src_addr, ip_header.dst_addr))
                #if ip_header.protocol == "TCP":
                #    offset = ip_header.ihl * 4
                #    tcp_buf = raw_buffer[offset:offset + 24]
                #    try:
                #        tcp_header = TCP_64(tcp_buf)
                #   except ValueError as ve:
                #        tcp_header = TCP_64(tcp_buf.ljust(24))  # Padding to 24bit
                #        print ve
                #    print("{} -> {}".format(tcp_header.src_port, tcp_header.dst_port))
                #    print("ack: {}, seq: {}".format(tcp_header.ack_num, tcp_header.seq_num))
                #    print("ctrl: {}".format(tcp_header.control))
                #    data = raw_buffer[offset+25:]
                #    print(data)
                #    print("-*-"*20)
            except KeyboardInterrupt as ke:
                if os.name == "nt":
                    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                exit(0)

    def handle_tcp(self, buffer):
        pass