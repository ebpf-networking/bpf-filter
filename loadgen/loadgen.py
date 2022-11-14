from scapy.all import *
import time

for i in range(20):
    sendp(Ether(src="ab:cd:ef:ab:cd:ef", dst="ab:cd:ef:ab:cd:ef")/IP(src="1.2.3.4", dst="3.4.5.6")/UDP(dport=9)/b"hello")

