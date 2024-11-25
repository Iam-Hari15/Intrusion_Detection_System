# analyze_traffic.py
from scapy.all import sniff

def analyze_packet(packet):
    # Simple analysis of packet details
    packet_details = f"Source: {packet.src}, Destination: {packet.dst}, Protocol: {packet.proto}\n"
    print(packet_details)
    
    # Save packet details to a file
    with open("traffic_analysis.log", "a") as log_file:
        log_file.write(packet_details)

# Sniff packets and call the analysis function
sniff(prn=analyze_packet, store=0)
