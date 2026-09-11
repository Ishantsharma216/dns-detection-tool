from scapy.all import sniff, IP, TCP, UDP, wrpcap

def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        # Only save if it involves the camera
        if src == "10.0.8.80" or dst == "10.0.8.80":
            print(f"Captured: {src} -> {dst}")

print("Capturing camera traffic for 30 seconds...")
print("Open your browser and go to http://10.0.8.80 while this runs.")

try:
    packets = sniff(
        prn=packet_callback,
        filter="host 10.0.8.80",
        timeout=30,
        store=True
    )
    
    # Save to file
    wrpcap("camera_login_attempt.pcap", packets)
    print(f"Saved {len(packets)} packets to camera_login_attempt.pcap")
except Exception as e:
    print(f"Error: {e}")