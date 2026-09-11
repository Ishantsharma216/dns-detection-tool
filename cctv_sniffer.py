from scapy.all import sniff, TCP, UDP, IP, wrpcap
import os

CCTV_IPS = [
    "10.0.8.3", "10.0.8.5", "10.0.8.6", "10.0.8.10", "10.0.8.11",
    "10.0.8.12", "10.0.8.18", "10.0.8.19", "10.0.8.23", "10.0.8.30",
    # ... (keep your full list)
]

def cctv_filter(packet):
    try:
        if not packet.haslayer(IP):
            return False
        is_cctv_ip = (packet[IP].src in CCTV_IPS or packet[IP].dst in CCTV_IPS)
        if is_cctv_ip:
            return True
        if packet.haslayer(TCP):
            if packet[TCP].sport in [554, 8000, 8080] or packet[TCP].dport in [554, 8000, 8080]:
                return True
        if packet.haslayer(UDP):
            if packet[UDP].sport in [554, 8000, 8080, 5004] or packet[UDP].dport in [554, 8000, 8080, 5004]:
                return True
        return False
    except Exception:
        return False

print("Starting enhanced CCTV capture (TCP + UDP)...")
print("Capturing for 2 minutes...")

try:
    packets = sniff(
        prn=lambda pkt: print(f"Captured: {pkt.summary()}"),
        filter="tcp or udp",
        timeout=120,  # Run for 2 minutes
        store=True    # Store all packets in memory
    )
    
    # Filter only CCTV-related packets before saving
    cctv_packets = [pkt for pkt in packets if cctv_filter(pkt)]
    
    output_file = "CCTV_CAPTURES/cctv_tcp_udp_capture.pcap"
    wrpcap(output_file, cctv_packets)
    print(f"\n✓ Saved {len(cctv_packets)} CCTV packets to {output_file}")
    print(f"Total packets captured: {len(packets)}")
    
except KeyboardInterrupt:
    print("\nCapture stopped by user")
except Exception as e:
    print(f"\nError: {e}")