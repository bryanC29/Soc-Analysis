import logging
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    print("This")
    if packet.haslayer(IP):
        print("THis2")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        log = f"Source: {src_ip} | Destination: {dst_ip} | Protocol: {proto}"

        print(log)

print("Starting network logger\n")
sniff(prn=packet_callback, store=0)