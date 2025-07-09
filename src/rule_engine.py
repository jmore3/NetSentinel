# src/rule_engine.py
import time
from collections import defaultdict

class RuleEngine:
    def __init__(self):
        # Track SYN packets per IP
        self.syn_counts = defaultdict(list)  
        # Track destination ports per IP
        self.ports_scans = defaultdict(set)
        # Track total bytes sent per IP
        self.byte_count = defaultdict(int)

    def process_packet(self, packet):
        pkt_time = time.time()

        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst

            #Detect SYN flood (Many SYNs from same IP)
            if packet.haslayer("TCP"): 
                tcp_layer = packet["TCP"]
                if tcp_layer.flags == "S": # SYN flag
                    self.syn_counts[src_ip].append(pkt_time)
                    self._check_syn_flood(src_ip, pkt_time)
                #Port scan: many ports targeted from one source
                self.ports_scans[src_ip].add(tcp_layer.dport)
                self._check_port_scan(src_ip)
            if hasattr(packet, "len"):
                self.byte_count[src_ip] += packet.len
                self._check_byte_excess(src_ip)

    def _check_syn_flood(self, ip, pkt_time):
        window = 10 #seconds
        threshold = 10 #SYN packets in the window
        recent_syns = [t for t in self.syn_counts[ip] if pkt_time - t <= window]
        if len(recent_syns) >= threshold:
            print(f"[ALERT] Possible SYN flood from {ip}")
    
    def _check_port_scan(self, ip):
        threshold = 50 # Number of ports scanned
        if len(self.ports_scans[ip]) >= threshold:
            print(f"[ALERT] Possible port scan from {ip} targeting {len(self.ports_scans[ip])} ports")

    def _check_data_exfil(self, ip):
        threshold = 5 * 1024 * 1024 # 5 MB
        if self.byte_count[ip] >= threshold:
            print(f"[ALERT] Possible data exfiltration from {ip} with {self.byte_count[ip]} bytes sent")