
from scapy.all import *

import networkx as nx

import sys

fwd_pkt1 = Ether() / IP(dst = '192.168.0.10')/TCP(sport=5793,dport=80)/Raw("OK")
sendp(fwd_pkt1, iface = "eth0")
