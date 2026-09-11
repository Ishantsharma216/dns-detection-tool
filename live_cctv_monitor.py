from scapy.all import sniff, TCP, UDP, IP
import os

# 1. Define the known CCTV IPs from your Nmap scan
# (I've included the main block 10.0.8.x, 10.0.9.x, etc. from your results)
CCTV_IPS = {
    "10.0.8.3", "10.0.8.5", "10.0.8.6", "10.0.8.10", "10.0.8.11",
    "10.0.8.12", "10.0.8.18", "10.0.8.19", "10.0.8.23", "10.0.8.30",
    "10.0.8.36", "10.0.8.39", "10.0.8.40", "10.0.8.41", "10.0.8.42",
    "10.0.8.47", "10.0.8.49", "10.0.8.51", "10.0.8.52", "10.0.8.57",
    "10.0.8.62", "10.0.8.79", "10.0.8.80", "10.0.8.97", "10.0.8.98",
    "10.0.8.99", "10.0.8.100", "10.0.8.101", "10.0.8.102", "10.0.8.122",
    "10.0.8.123", "10.0.8.125", "10.0.9.103", "10.0.9.167", "10.0.10.215",
    "10.0.11.172", "10.0.11.224", "10.0.13.247", "10.0.14.119", "10.0.14.140",
    "10.0.14.244", "10.0.15.26", "10.0.15.34", "10.0.15.38", "10.0.15.39",
    "10.0.15.52", "10.0.15.151", "10.0.15.156"
}

# 2. Define common CCTV ports
CCTV_PORTS = {554, 8000, 8080, 8443, 5004, 5005}

def cctv_monitor(packet):
    """
    Only prints packets that are from/to known CCTV IPs 
    OR use known CCTV ports.
    """
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    # Check if IP is in our CCTV list
    is_cctv_ip = (src_ip in CCTV_IPS or dst_ip in CCTV_IPS)
    
    # Check if it's using a CCTV port (RTSP, Video, etc.)
    is_cctv_port = False
    port_info = ""
    
    if packet.haslayer(TCP):
        sport, dport = packet[TCP].sport, packet[TCP].dport
        if sport in CCTV_PORTS or dport in CCTV_PORTS:
            is_cctv_port = True
            port_info = f"TCP:{sport}->{dport}"
    elif packet.haslayer(UDP):
        sport, dport = packet[UDP].sport, packet[UDP].dport
        if sport in CCTV_PORTS or dport in CCTV_PORTS:
            is_cctv_port = True
            port_info = f"UDP:{sport}->{dport}"

    # Only print if it matches our criteria
    if is_cctv_ip or is_cctv_port:
        proto = "TCP" if packet.haslayer(TCP) else "UDP"
        print(f"📹 [CCTV] {src_ip} <--> {dst_ip} | {port_info}")

print("🚀 Starting LIVE CCTV Monitor...")
print(f"Monitoring {len(CCTV_IPS)} known camera IPs and ports {CCTV_PORTS}")
print("Press Ctrl+C to stop.\n")
print("-" * 60)

try:
    # Sniff only TCP and UDP, filter for CCTV ports to save resources
    # We use a BPF filter string to let the OS do the heavy lifting
    # This filters for ports 554, 8000, 8080, 5004, 5005
    sniff(
        prn=cctv_monitor,
        filter="tcp port 554 or tcp port 8000 or tcp port 8080 or udp port 5004 or udp port 5005",
        store=False,  # Do NOT save to memory, just print
        timeout=0     # Run forever
    )
except KeyboardInterrupt:
    print("\n\n⛔ Monitor stopped by user.")
except Exception as e:
    print(f"\nError: {e}")