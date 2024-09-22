import socket

from scapy.all import *

# Define a callback function to analyze each packet
def analyze_packet(packet):
    # Ethernet Frame
    print("Ethernet Frame:")
    print(f"  Src MAC: {packet[Ether].src}")
    print(f"  Dst MAC: {packet[Ether].dst}")
    print(f"  Ethernet Type: {packet[Ether].type}")

    # IP Header
    if packet.haslayer(IP):
        print("\nIP Header:")
        print(f"  Src IP: {packet[IP].src}")
        print(f"  Dst IP: {packet[IP].dst}")
        print(f"  IP Protocol: {packet[IP].proto}")
        print(f"  TTL: {packet[IP].ttl}")

    # TCP Header
    if packet.haslayer(TCP):
        print("\nTCP Header:")
        print(f"  Src Port: {packet[TCP].sport}")
        print(f"  Dst Port: {packet[TCP].dport}")
        print(f"  Flags: {packet[TCP].flags}")
        print(f"  Seq: {packet[TCP].seq}")
        print(f"  Ack: {packet[TCP].ack}")

    # UDP Header
    elif packet.haslayer(UDP):
        print("\nUDP Header:")
        print(f"  Src Port: {packet[UDP].sport}")
        print(f"  Dst Port: {packet[UDP].dport}")
        print(f"  Len: {packet[UDP].len}")

    # ICMP Header
    elif packet.haslayer(ICMP):
        print("\nICMP Header:")
        print(f"  Type: {packet[ICMP].type}")
        print(f"  Code: {packet[ICMP].code}")
        print(f"  Seq: {packet[ICMP].seq}")

    # Packet Payload
    if packet.haslayer(Raw):
        print("\nPacket Payload:")
        print(packet[Raw].load)


    print("DONE")
# Start sniffing packets
nmae='ethanferrao.me'
sniff(prn=analyze_packet, count=10, filter=(f"dst host {nmae}  "))
print(socket.getaddrinfo(host=nmae,port=53 ))


# HTTP Filter Syntax:
#
# - tcp port 80: Filter HTTP traffic on port 80.
# - tcp[40:4] == 0x4745: Filter GET requests.
# - tcp[40:4] == 0x504f: Filter POST requests.
# - tcp[54:10] == 'Host:': Filter packets containing Host header.
