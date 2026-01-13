from scapy.all import TCP, sniff, TCPSession, IP
from scapy.layers.http import HTTPRequest, HTTPResponse

def packet_handling(packet):
    print("Some packet handling")

    log = ""

    if packet.haslayer(IP) and packet.haslayer(TCP):
        log += f"Source: {packet[IP].src} | Destination: {packet[IP].dst}"

    if packet.haslayer(HTTPResponse):
        log += f" | Status: {packet[HTTPResponse].Status_Code.decode()}"

    if packet.haslayer(HTTPRequest):
        log += f" | Path: {packet[HTTPRequest].Path.decode()}"

    print(log)

print("Logger starting")
sniff(prn = packet_handling, store = 0, filter = "tcp")