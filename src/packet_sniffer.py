# src/packet_sniffer.py

from scapy.all import sniff, IP, TCP, UDP
import sys
from scapy.all import get_if_list
from src.rule_engine import RuleEngine

#Rule engine global variable
engine = RuleEngine()

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")

    if TCP in packet:
        tcp_layer = packet[TCP]
        print(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")

    elif UDP in packet:
        udp_layer = packet[UDP]
        print(f"UDP Packet: {udp_layer.sport} -> {udp_layer.dport}")
    
    #Pass the packet to the rule engine for processing
    engine.process_packet(packet)

def choose_interface():
    interfaces = get_if_list()
    print("[*] Available network interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f" [{idx}]: {iface}")

    try:
        choice = int(input("Enter the number of the interface to sniff: "))
        if choice < 0 or choice >= len(interfaces):
            raise ValueError("Invalid choice")
        return interfaces[choice]
    except (ValueError, IndexError):
        print("Invalid selection.")
        sys.exit(1)

def start_sniffing(interface=None, packet_count=0):
    """
    Start sniffing packets on the given interface.
    - interface: str or None (default: all interfaces)
    - packet_count: int (0 = infinite)
    """
    print(f"[*] Starting packet capture on interface: {interface or 'ALL'}...")
    sniff(iface=interface, prn=packet_callback, count=packet_count, store=0)

if __name__ == "__main__":
    selected_interface = choose_interface()
    start_sniffing(interface=selected_interface)