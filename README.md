# Nerwork-Sniffer
# INTRODUCTION
In today's life networks is playing a very important role in telecommunication. without the network, almost all types of communication and service are useless. hence, this makes network concept more important for all programmers and network administrators.

To maintain and manage the security of network communication, many times network administrators or network maintainers need to find and control the traffic flowing into the network wire and also find exactly what and which types of data packets are actually flowing into the networks.

For this situation, there are many types of Networks analysing tools are available on the internet.  basically, these types of tools come on the ground to help network administrator like Wireshark and other. These tools are fast, easy and reliable to handle many types of network problems but as we know, networking concept is not that easy. so, many time these types of tools do not support our exact situation requirement and we have to find any other solution for our problem and at that time python and its socket module comes on the ground like a big boy to help network administrators.

Well, as we know python is really the very awesome language and also very powerful language. With Python, a programmer can do almost any types of programming in fastest and easiest way. hence, with python and socket module, our today project is very easy to codes if compared to other programming languages. 

# ABOUT PROJECT
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
# FEATURES OF THE PROJECT
•	 No External Dependencies
•	 Using Custom python Script For Extracting Header
•	 Supported Header: TCP/IP, IPv4 , UDP, ICMP
•	 Fast Header Extraction

 













