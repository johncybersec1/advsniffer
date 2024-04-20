import socket
import os
import struct
from ctypes import *

#host to listen on
host ='192.168.0.55'

class IP(Structure):
    #the socket_buffer will be in the layout below
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(cls, socket_buffer=None):
        #copies raw_buffer[0:20] into socket_buffer
        #and intializes a new instance of the IP class
        return cls.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer=None):
        self.socket_buffer = socket_buffer

        #map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6:"TCP", 17: "UDP"}

        #from c_uint32 to human-readble form
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

        #human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except IndexError:
            self.protocol = str(self.protocol_num)

#create a raw socket
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host,0))

#we want the ip headers included in our capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

#if using windows setup promiscious mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
try:
    while True:
        #read in a single packet
        raw_buffer = sniffer.recvfrom(65535)[0]

        #create IP header from the first 20 bytes
        ip_header = IP(raw_buffer[0:20])
        print(f"Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}")

#handles CTRL C
except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
