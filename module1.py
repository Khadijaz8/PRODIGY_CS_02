from scapy.all import *

def packet_handler(pkt):
    if pkt.haslayer(TCP):
        print(f"{pkt.sprintf('{IP:%s.%s.%s.%s}:{TCP:%s > %s}')}")

sniff(filter="tcp", prn=packet_handler)from scapy.all import *

def packet_handler(pkt):
    if pkt.haslayer(TCP):
        print(f"{pkt.sprintf('{IP:%s.%s.%s.%s}:{TCP:%s > %s}')}")

sniff(filter="tcp", prn=packet_handler)