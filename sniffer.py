import scapy.all as scapy
import logging
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# ARP Table: Manually add known devices on your network (Example)
ARP_table = {
    "192.168.29.1": "00:11:22:33:44:55",  # Example router MAC address (replace with actual)
    # Add other known IPs and their corresponding MAC addresses
}

# Track connection attempts for port scan detection
scan_attempts = {}

# Create an empty list to store detected alerts
detected_alerts = []

def insert_alert(alert):
    # Append the alert to the list
    detected_alerts.append(alert)

def packet_callback(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        # Check if the IP has an expected MAC address in ARP_table
        if src_ip in ARP_table and ARP_table[src_ip] != src_mac:
            print(f"ARP Spoofing attempt detected from {src_ip} ({src_mac})!")
            alert = f"ARP Spoofing attempt detected from {src_ip} ({src_mac})"
            insert_alert(alert)

    if packet.haslayer(TCP):
        ip_src = packet[IP].src
        if ip_src not in scan_attempts:
            scan_attempts[ip_src] = 0
        scan_attempts[ip_src] += 1

        # If more than 5 connection attempts within 1 second, consider it a port scan
        if scan_attempts[ip_src] > 5:  # You can adjust the threshold here
            print(f"Port scan detected from {ip_src}!")
            alert = f"Port scan detected from {ip_src}!"
            insert_alert(alert)
            scan_attempts[ip_src] = 0  # Reset counter after detection

def start_sniffer():
    print("Starting the Sniffer...")
    scapy.sniff(prn=packet_callback, store=0, filter="ip")  # Use filter="ip" to sniff only IP packets
