# Nerwork-Sniffer
INTRODUCTION
In today's life networks is playing a very important role in telecommunication. without the network, almost all types of communication and service are useless. hence, this makes network concept more important for all programmers and network administrators.

To maintain and manage the security of network communication, many times network administrators or network maintainers need to find and control the traffic flowing into the network wire and also find exactly what and which types of data packets are actually flowing into the networks.

For this situation, there are many types of Networks analysing tools are available on the internet.  basically, these types of tools come on the ground to help network administrator like Wireshark and other. These tools are fast, easy and reliable to handle many types of network problems but as we know, networking concept is not that easy. so, many time these types of tools do not support our exact situation requirement and we have to find any other solution for our problem and at that time python and its socket module comes on the ground like a big boy to help network administrators.

Well, as we know python is really the very awesome language and also very powerful language. With Python, a programmer can do almost any types of programming in fastest and easiest way. hence, with python and socket module, our today project is very easy to codes if compared to other programming languages. 











ABOUT PROJECT
Our project is divided in two separate files as follow in order to keep its simplicity ->
1)	pypackets.py
The first file will be used to capture the packets on the network and pass them to the next module for extraction.
Of course, for this job we are going to use socket module. basically, socket module is the main player in our games because in python programming language socket module provides us the facility to play with network concept. so here for capturing packets, we are going to use socket.socket module.

For sniffing with socket module in python we have to create a socket.socket class object with special configuration. In simple words, we have to configure socket.socket class object to capture low-level packets from the network so that it can capture packet from low-level networks and provides us output without doing any type of changes in capture packets.
2)	pye.py
This the second file to which the first module pypackets.py passes data to be pared int the required format.
There are various types of data formats are available in networking. But for practice purpose here, we are only going to describe few important and most usable data formats. In order to understand these data formats, let's take a look at data structure diagrams.
Ethernet Frame Format
 
As you can see in ethernet frame format diagram there are more than 3 fields to extract but here, for this project we are only going to extract only 3 fields, source mac address, destination mac address and ethernal protocol type.
To extract source address, destination address, and ethernet type address, we are using struct module which can unpack network packets.
We have done the same for all the header files like ICMP header format, IP header format, TCP header format and UDP header file
FEATURES OF THE PROJECT
•	 No External Dependencies
•	 Using Custom python Script For Extracting Header
•	 Supported Header: TCP/IP, IPv4 , UDP, ICMP
•	 Fast Header Extraction
WORKING OF THE PROJECT(KALI LINUX)
 
CODE FILES
1)	pypackets.py
# import modules
import socket
import struct
import binascii
import os
import pye

# print author details on terminal
print pye.__author__

# if operating system is windows
if os.name == "nt":
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    s.bind(("YOUR_INTERFACE_IP",0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

# if operating system is linux
else:
    s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

# create loop
while True:

    # Capture packets from network
    pkt=s.recvfrom(65565)

    # extract packets with the help of pye.unpack class
    unpack=pye.unpack()

    print ("\n\n===> [+] ------------ Ethernet Header----- [+]")

    # print data on terminal
    for i in unpack.eth_header(pkt[0][0:14]).iteritems():
        a,b=i
        print "{} : {} | ".format(a,b),
    print ("\n\n===> [+] ------------ IP Header----- [+]")
    for i in unpack.ip_header(pkt[0][14:34]).iteritems():
        a,b=i
        print "{} : {} | ".format(a,b),
    print ("\n\n===> [+] ------------ TCP Header----- [+]")
    for  i in unpack.tcp_header(pkt[0][34:54]).iteritems():
        a,b=i
        print "{} : {} | ".format(a,b),



2)	pye.py
#!usr/bin/python
# Importing Modules
import socket, struct, binascii

__author__ = '''
# =========================================================================|
# ------------------------Network Packet Snifer---------------------------- 
# =========================================================================|

######################################################
  Made  By         
######################################################

==> Shubham sharma (1/18/FET/BCS/188)
==> Dawood Adim    (1/18/FET/BCS/191)
==> Rachit Chugh   (1/18/FET/BCS/194)
==> Bharat Mago    (1/18/FET/BCS/198)

######################################################

 Sniffing Data Packet Extractor
'''
__headers_support__ = """
Ethernet header Extraction
IPv4 header Extraction
Tcp header Extraction
ICMP header Extraction
UDP header Extraction

"""

class unpack:
    def __cinit__(self):
        self.data = None

    # Ethernet Header
    def eth_header(self, data):
        storeobj = data
        storeobj = struct.unpack("!6s6sH", storeobj)
        destination_mac = binascii.hexlify(storeobj[0])
        source_mac = binascii.hexlify(storeobj[1])
        eth_protocol = storeobj[2]
        data = {"Destination Mac": destination_mac,
                "Source Mac": source_mac,
                "Protocol": eth_protocol}
        return data

    # ICMP HEADER Extraction
    def icmp_header(self, data):
        icmph = struct.unpack('!BBH', data)
        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]
        data = {'ICMP Type': icmp_type,
                "Code": code,
                "CheckSum": checksum}
        return data

    # UDP Header Extraction
    def udp_header(self, data):
        storeobj = struct.unpack('!HHHH', data)
        source_port = storeobj[0]
        dest_port = storeobj[1]
        length = storeobj[2]
        checksum = storeobj[3]
        data = {"Source Port": source_port,
                "Destination Port": dest_port,
                "Length": length,
                "CheckSum": checksum}
        return data

    # IP Header Extraction
    def ip_header(self, data):
        storeobj = struct.unpack("!BBHHHBBH4s4s", data)
        _version = storeobj[0]
        _tos = storeobj[1]
        _total_length = storeobj[2]
        _identification = storeobj[3]
        _fragment_Offset = storeobj[4]
        _ttl = storeobj[5]
        _protocol = storeobj[6]
        _header_checksum = storeobj[7]
        _source_address = socket.inet_ntoa(storeobj[8])
        _destination_address = socket.inet_ntoa(storeobj[9])

        data = {'Version': _version,
                "Tos": _tos,
                "Total Length": _total_length,
                "Identification": _identification,
                "Fragment": _fragment_Offset,
                "TTL": _ttl,
                "Protocol": _protocol,
                "Header CheckSum": _header_checksum,
                "Source Address": _source_address,
                "Destination Address": _destination_address}
        return data

    # Tcp Header Extraction
    def tcp_header(self, data):
        storeobj = struct.unpack('!HHLLBBHHH', data)
        _source_port = storeobj[0]
        _destination_port = storeobj[1]
        _sequence_number = storeobj[2]
        _acknowledge_number = storeobj[3]
        _offset_reserved = storeobj[4]
        _tcp_flag = storeobj[5]
        _window = storeobj[6]
        _checksum = storeobj[7]
        _urgent_pointer = storeobj[8]
        data = {"Source Port": _source_port,
                "Destination Port": _destination_port,
                "Sequence Number": _sequence_number,
                "Acknowledge Number": _acknowledge_number,
                "Offset & Reserved": _offset_reserved,
                "Tcp Flag": _tcp_flag,
                "Window": _window,
                "CheckSum": _checksum,
                "Urgent Pointer": _urgent_pointer
                }
        return data

    # Mac Address Formating

def mac_formater(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b

def get_host(q):
    try:
        k = socket.gethostbyaddr(q)
    except:
        k = 'Unknown'
    return k













