from scapy.all import sniff, IP, TCP, UDP
from termcolor import colored
import pandas as pd
import time

# Configuration
SUSPICIOUS_IPS = ["192.168.1.100", "10.0.0.1"]  # Add known malicious IPs
ALERT_THRESHOLD = 10  # Number of packets from a single IP to trigger an alert
LOG_FILE = "traffic_log.csv"

# Data storage
packet_data = []

def analyze_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.sprintf("%IP.proto%")
        length = len(packet)

        # Log packet details
        packet_data.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protocol": protocol,
            "length": length
        })

        # Check for suspicious IPs
        if src_ip in SUSPICIOUS_IPS:
            print(colored(f"[!] Suspicious IP detected: {src_ip}", "red"))

        # Check for port scanning (multiple packets from the same IP)
        if len(packet_data) > ALERT_THRESHOLD:
            ip_count = {}
            for pkt in packet_data:
                ip_count[pkt["source_ip"]] = ip_count.get(pkt["source_ip"], 0) + 1
            for ip, count in ip_count.items():
                if count > ALERT_THRESHOLD:
                    print(colored(f"[!] Potential port scanning from {ip} ({count} packets)", "yellow"))

def start_sniffing():
    print(colored("[*] Starting network traffic analyzer...", "green"))
    sniff(prn=analyze_packet, store=False)

def save_logs():
    df = pd.DataFrame(packet_data)
    df.to_csv(LOG_FILE, index=False)
    print(colored(f"[*] Logs saved to {LOG_FILE}", "blue"))

if __name__ == "__main__":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print(colored("[*] Stopping analyzer...", "red"))
        save_logs()