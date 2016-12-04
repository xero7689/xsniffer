import socket
import struct
from ctypes import *


class ICMP_64(Structure):
    _fields_ = [
        ("type", c_uint8),
        ("code", c_uint8),
        ("sum", c_uint16),
        ("unused", c_uint16),
        ("next_hop_mtu", c_uint16)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        pass
