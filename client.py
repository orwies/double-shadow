from scapy import *
from scapy.all import Raw
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send


msg = input("enter your message: ")
# create and send a packet representing the length of the message
length_pkt = IP(dst="192.168.1.166") / UDP(dport=13337) / Raw(len(msg))
send(length_pkt)

for i in msg:
    pkt = IP(dst="192.168.1.166") / UDP(dport=ord(i) + 20003)
    send(pkt)
    
end_pkt = IP(dst="192.168.1.166") / UDP(dport=13338) / Raw("END")
send(end_pkt)