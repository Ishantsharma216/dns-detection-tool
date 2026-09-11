from scapy.all import sniff, IP, TCP, UDP, wrpcap
import os

# This list will store ONLY the TCP packets we find
tcp_packets = []

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Check if it is a TCP packet
        if TCP in packet:
            print(f"[+] TCP Packet: {ip_src} -> {ip_dst}")
            
            # ONLY save TCP packets to our list
            tcp_packets.append(packet)
        else:
            # If it's not TCP (e.g., UDP), we just ignore it
            pass

def main():
    print("Starting TCP-Only Packet Sniffer...")
    print("Press Ctrl+C to stop and save to 'tcp_captured.pcap'")
    
    try:
        # Sniff for 60 seconds (or remove timeout=60 to run forever)
        sniff(prn=packet_callback, store=0, timeout=60)
    except KeyboardInterrupt:
        print("\n\nSniffing stopped.")
    
    # Save the captured TCP packets to a file
    if tcp_packets:
        filename = "tcp_captured.pcap"
        wrpcap(filename, tcp_packets)
        print(f"Success! Saved {len(tcp_packets)} TCP packets to '{filename}'")
        print(f"Location: C:\\ISHANT PYTHON\\{filename}")
    else:
        print("No TCP packets were captured.")

if __name__ == "__main__":
    # Check for Admin rights (Important for Windows)
    if os.name == 'nt':
        try:
            if os.geteuid() != 0:
                print("WARNING: Please run this script as Administrator.")
                print("Right-click Command Prompt > Run as Administrator.")
        except AttributeError:
            pass
    
    main()