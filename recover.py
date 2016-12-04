import socket
from operator import itemgetter

from xsniffer import Sniffer
from pktStruct.IP import IP_64
from pktStruct.TCP import TCP_64

host = "192.168.0.25/24"
sniffer = Sniffer(socket.IPPROTO_TCP)

payload = {}

for raw_buffer in sniffer.run(host):
    ip_header = IP_64(raw_buffer[0:24])
    if ip_header.protocol == "TCP":
        #
        offset = ip_header.ihl * 4
        tcp_buf = raw_buffer[offset:offset + 24]
        try:
           tcp_header = TCP_64(tcp_buf)
        except ValueError as ve:
           tcp_header = TCP_64(tcp_buf.ljust(24))  # Padding to 24bit
           #print(ve)
        data = raw_buffer[offset+25:]

        #
        src_ip = ip_header.src_addr
        dst_ip = ip_header.dst_addr
        src_port = tcp_header.src_port
        dst_port = tcp_header.dst_port
        ack = tcp_header.ack_num
        seq = tcp_header.seq_num
        ctrl = tcp_header.control
        if ctrl == 49:
            if (src_ip, dst_ip, src_port) not in payload:
                payload[(src_ip, dst_ip, src_port)] = [(ack, seq, data)]
            else:
                payload[(src_ip, dst_ip, src_port)].append((ack, seq, data))
        if ctrl == 33:
            try:
                datas = sorted(payload[(src_ip, dst_ip, src_port)], key=itemgetter(1))
                dstring = "".join([data[2] for data in datas])
                print("{} {} -> {}".format(ip_header.protocol, ip_header.src_addr, ip_header.dst_addr))
                print("{} -> {}".format(tcp_header.src_port, tcp_header.dst_port))
                print(dstring)
                print("=" * 20)
            except Exception as e:
                print e
