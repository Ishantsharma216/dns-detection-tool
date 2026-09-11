# Network Security Monitoring Tools

Python-based network detection and traffic analysis toolkit built
with Scapy. Designed for defensive security monitoring and threat
detection research.

## Tools

### DNS Detection Tool
Captures DNS traffic in real-time, matches queries against a threat
signature list, and logs detections to CSV for SIEM ingestion.

**Features:**
- Real-time DNS query capture (UDP port 53)
- Signature-based domain matching
- CSV logging for SIEM integration
- Syslog alert forwarding
- Timestamped detection events

**MITRE ATT&CK:** T1071.004 (Application Layer Protocol: DNS)

### Packet Sniffer
TCP/UDP packet capture tool that filters traffic and saves captures
to pcap format for Wireshark analysis.

### CCTV Traffic Monitor
Monitors RTP/RTSP streams and camera traffic patterns for anomaly
detection in IoT environments.

## Installation
```bash
pip install scapy
