# attack_signatures.py

# Simple signature for port scanning - multiple connection attempts within a short time
PORT_SCAN_SIGNATURE = {
    "type": "port_scan",
    "threshold": 10,  # If more than 10 connections from the same IP in a minute
}

# Simple signature for ICMP Flood - multiple ping requests
ICMP_FLOOD_SIGNATURE = {
    "type": "icmp_flood",
    "threshold": 20,  # More than 20 ping requests in a minute
}
