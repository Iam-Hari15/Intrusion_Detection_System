#Intrusion Detection System (IDS)
#Overview
This project is an Intrusion Detection System (IDS) designed to monitor network traffic in real-time and detect suspicious activities, such as port scanning and ARP spoofing attempts. The system uses packet sniffing to identify potential intrusions and generates alerts, which are displayed on a dashboard for easy monitoring. It helps in identifying malicious network behavior and provides real-time detection of security threats.

#Features
Real-Time Network Traffic Monitoring: Monitors incoming and outgoing packets to detect abnormal activities.
Port Scanning Detection: Identifies attempts to scan ports in the network, a common indication of malicious intent.
ARP Spoofing Detection: Detects ARP spoofing attempts that can manipulate network traffic and compromise security.
Alert System: Generates alerts when suspicious activity is detected, providing real-time notifications to administrators.
Web Dashboard: A simple web interface that displays detected alerts for easy monitoring and analysis.

#Technologies Used
Python: Used for packet sniffing and intrusion detection logic.
Scapy: A Python library for packet manipulation and sniffing.
Flask: A web framework for building the alert dashboard.
HTML/CSS: Used for creating the web interface and styling the dashboard.
Socket Programming: For capturing network packets and analyzing traffic.

#Setup Instructions
Prerequisites
Python 3.6 or higher
Virtual environment (recommended)

#Installation
Clone the repository to your local machine:

git clone <repository_url>

Navigate to the project folder:

cd <project_folder>

Create and activate a virtual environment:

python3 -m venv .venv

For macOS/Linux:

source .venv/bin/activate

For Windows:

.venv\Scripts\activate

Install required dependencies:

pip install -r requirements.txt

Running the IDS
Start the packet sniffer by running the following command in your terminal:

python sniffer.py

Start the web dashboard by running the following command in another terminal:

python main.py

Open a web browser and navigate to http://127.0.0.1:5000/ to view the dashboard.

#How It Works
Packet Sniffing: The system listens to network traffic and captures incoming packets.
Intrusion Detection: It identifies suspicious activities like port scans or ARP spoofing attempts by analyzing the packets.
Alert Generation: When an intrusion is detected, an alert is generated and displayed on the web dashboard.
Web Dashboard: The web dashboard shows the list of detected alerts and helps administrators monitor and analyze the network traffic.
