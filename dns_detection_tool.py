#!/usr/bin/env python3
"""
DNS Detection Tool
Upgrades basic packet sniffing into active threat detection.
"""

import os
import csv
import socket
import logging
from datetime import datetime
from collections import defaultdict
import scapy.all as scapy
from scapy.layers.dns import DNSQR, DNS

# --- Configuration ---
SIGNATURES_FILE = "bad_signatures.txt"
CSV_LOG = "dns_logs.csv"
ALERT_LOG = "alerts.log"
SYSLOG_SERVER = "127.0.0.1"  # Change to your SIEM IP later, or keep localhost
SYSLOG_PORT = 514

# --- Setup Logging ---
logging.basicConfig(
    filename=ALERT_LOG,
    level=logging.INFO,
    format='%(asctime)s - [ALERT] %(message)s'
)

# --- Helper Functions ---

def load_signatures(filepath):
    """Load bad domains from text file into a set."""
    sigs = set()
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith('#'):
                    sigs.add(line)
    return sigs

def extract_dns_domain(packet):
    """Extract domain name from DNS query packet."""
    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        if dns_layer.qr == 0:  # Only process queries (not responses)
            if dns_layer.qd:
                qname = dns_layer.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                return qname
    return None

def check_signature(domain, signatures):
    """Check if domain matches any bad signature."""
    domain_lower = domain.lower()
    for sig in signatures:
        if sig in domain_lower or domain_lower in sig:
            return True, sig
    return False, None

def write_csv_log(domain, is_bad, matched_sig):
    """Append entry to CSV."""
    file_exists = os.path.isfile(CSV_LOG)
    timestamp = datetime.now().isoformat()
    
    with open(CSV_LOG, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "domain", "is_bad", "matched_signature"])
        
        writer.writerow([timestamp, domain, str(is_bad), matched_sig])

def send_syslog_alert(domain, matched_sig):
    """Send alert to syslog server (if configured)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        message = f"[DNS-ALERT] Suspicious domain detected: {domain} (Matched: {matched_sig})"
        sock.sendto(message.encode(), (SYSLOG_SERVER, SYSLOG_PORT))
        sock.close()
    except Exception as e:
        # Ignore errors if syslog server is not running (common in local dev)
        pass

def process_packet(packet, signatures):
    """Main processing logic for each packet."""
    domain = extract_dns_domain(packet)
    if not domain:
        return

    is_bad, matched = check_signature(domain, signatures)
    
    # Always log to CSV
    write_csv_log(domain, is_bad, matched)
    
    # Alert if suspicious
    if is_bad:
        print(f"⚠️  DETECTION: {domain} (Match: {matched})")
        logging.info(f"Suspicious DNS query: {domain} (Matched: {matched})")
        send_syslog_alert(domain, matched)

def main():
    print("🚀 DNS Detection Tool Started")
    print(f"📂 Loading signatures from {SIGNATURES_FILE}...")
    
    signatures = load_signatures(SIGNATURES_FILE)
    print(f"✅ Loaded {len(signatures)} signatures")
    print(f"👂 Capturing DNS traffic on UDP port 53... (Ctrl+C to stop)")
    
    # Filter: UDP port 53 (DNS)
    scapy.sniff(
        filter="udp port 53",
        prn=lambda pkt: process_packet(pkt, signatures),
        store=False,
    )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Tool stopped by user.")