import socket
import struct
from ctypes import *


class UDP_64(Structure):
    _fields_ = [
        ("src_port", c_uint16),
        ("dst_port", c_uint16),
        ("seq_num", c_uint32),
        ("ack_num", c_uint32),
        ("offset", c_uint8, 4),
        ("resrv", c_uint8, 3),
        ("control", c_uint16, 9),
        ("window", c_uint16),
        ("sun", c_uint16),
        ("urgptr", c_uint16)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        pass
