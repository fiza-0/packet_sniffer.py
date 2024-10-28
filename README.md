# packet_sniffer.py
Packet Sniffer Tool for Network Analysis
You’ve created a basic packet sniffer that captures network packets and displays relevant information.
Remember to use it ethically and responsibly.
the code i used :
from scapy.all import sniff

def packet_callback(packet):
    # Extracting relevant information from the packet
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dest_ip = packet['IP'].dst
        protocol = packet['IP'].proto
        payload = str(packet.payload)

        print(f"Source IP: {src_ip}, Destination IP: {dest_ip}, Protocol: {protocol}, Payload: {payload}")

def main():
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    # Sniff packets and call packet_callback for each packet captured
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
This repository contains a Python-based packet sniffer built with Scapy. The tool captures and analyzes network packets, providing essential details such as source and destination IP addresses, protocol type, and payload data.

Key Features:
Real-time packet capturing and analysis.
Filter packets by specific IP address.
Educational and ethical use for learning about network traffic and security.
Requirements:
Python 3.12+
Scapy library (pip install scapy)
Usage:
Install requirements using pip install -r requirements.txt.
Run the tool from the command line and specify an IP address to filter (optional).
Important:
This tool is developed strictly for educational purposes. Always ensure you have authorization before using it on any network.
