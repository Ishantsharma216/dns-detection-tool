from scapy.all import sniff, TCP, UDP, IP, wrpcap
import os
from datetime import datetime

print("Starting RTP Video Stream Capture...")
print("This will capture ALL traffic on ports 5004/5005 (Video) for 5 minutes.")
print("Ensure someone is viewing a camera feed during this time for best results.\n")

def rtp_filter(packet):
    """
    Captures RTP video streams (ports 5004/5005) regardless of IP.
    Also captures RTSP control traffic (port 554) for context.
    """
    try:
        if not packet.haslayer(IP):
            return False
        
        # 1. Capture RTP Video Data (UDP ports 5004, 5005)
        if packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            if sport in [5004, 5005] or dport in [5004, 5005]:
                return True
        
        # 2. Capture RTSP Control (TCP/UDP port 554)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
            dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            
            if sport == 554 or dport == 554:
                return True
                
        return False
    except Exception:
        return False

def packet_callback(packet):
    """Prints a live summary of captured packets"""
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "UDP" if packet.haslayer(UDP) else "TCP"
        sport = packet[UDP].sport if packet.haslayer(UDP) else packet[TCP].sport
        dport = packet[UDP].dport if packet.haslayer(UDP) else packet[TCP].dport
        
        # Only print if it matches our filter (RTP or RTSP)
        if rtp_filter(packet):
            print(f"[CAPTURE] {src}:{sport} -> {dst}:{dport} ({proto})")

# Ensure output directory exists
output_dir = "CCTV_CAPTURES"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Configuration
duration_seconds = 300  # 5 minutes
count_limit = 5000      # Max packets to capture (safety limit)

print(f"Capturing for {duration_seconds} seconds...")
print("Press Ctrl+C to stop early.\n")

try:
    # Start sniffing
    packets = sniff(
        prn=packet_callback,
        filter="udp port 5004 or udp port 5005 or tcp port 554 or udp port 554",
        timeout=duration_seconds,
        count=count_limit,
        store=True
    )
    
    # Filter the captured packets to ensure we only save relevant ones
    final_packets = [p for p in packets if rtp_filter(p)]
    
    # Save to file with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/rtp_streams_{timestamp}.pcap"
    
    wrpcap(filename, final_packets)
    
    print(f"\n--- Capture Complete ---")
    print(f"Total packets captured: {len(packets)}")
    print(f"Relevant RTP/RTSP packets saved: {len(final_packets)}")
    print(f"File saved to: {filename}")
    
    # Quick analysis
    if len(final_packets) > 0:
        print("\n[Next Steps] Open this file in Wireshark and filter by 'rtp' or 'rtsp'.")
    else:
        print("\n[Warning] No RTP/RTSP traffic found. Cameras might be idle or using different ports.")

except KeyboardInterrupt:
    print("\n\nCapture stopped by user.")
except Exception as e:
    print(f"\nError occurred: {e}")