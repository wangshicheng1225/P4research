
from scapy.all import *

import networkx as nx
import time
import sys

fwd_pkt1 = IP(src = '10.0.0.1',dst = '10.0.0.2')/TCP(sport=5793,dport=80,flags = "S",options=[('MSS', 1460)])
SYNACK=sr1(fwd_pkt1,iface="h1-eth0")
fwd_pkt2 = IP(src = '10.0.0.1',dst = '10.0.0.2')/TCP(sport=5793,dport=80,flags = "A",seq=SYNACK.ack, ack=SYNACK.seq + 1)
send(fwd_pkt2)
'''
for x in range(10):
    temppkt  = Ether() / IP(dst = '192.168.0.10')/TCP(sport=5793,dport=80,flags = "S")/Raw("S"+str(x))
    sendp(temppkt, iface = "eth0")

time.sleep(2)

for y in range(10):
    temppkt = Ether() / IP(dst = '192.168.0.10')/TCP(sport=5793,dport=80,flags = "A")/Raw("A"+str(y))
    #print(temppkt)
    sendp(temppkt, iface = "eth0")
'''
