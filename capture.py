"""
capture.py
Improved packet capture module for NetPrint project
"""

import threading
import socket
import requests
import time
import os
from scapy.all import sniff, wrpcap, IP

CAPTURE_DURATION = 10
PCAP_FILE = "temp_capture.pcap"


# ─────────────────────────────
# Resolve domain → IPs
# ─────────────────────────────
def resolve_url_to_ips(url: str) -> list:
    try:
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
        results = socket.getaddrinfo(hostname, None)
        ips = list(set([r[4][0] for r in results]))
        print(f"[Capture] IPs: {ips}")
        return ips
    except Exception as e:
        print(f"[Capture] DNS error: {e}")
        return []


# ─────────────────────────────
# Generate traffic
# ─────────────────────────────
def visit_url(url: str):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }
        print(f"[Capture] Visiting {url}")
        requests.get(url, headers=headers, timeout=5, verify=False)
    except Exception as e:
        print(f"[Capture] Request error: {e}")


# ─────────────────────────────
# Packet filter
# ─────────────────────────────
def packet_filter(target_ips):
    def _filter(pkt):
        if pkt.haslayer(IP):
            return pkt[IP].src in target_ips or pkt[IP].dst in target_ips
        return False
    return _filter


# ─────────────────────────────
# MAIN CAPTURE FUNCTION
# ─────────────────────────────
def capture_packets(url: str, duration: int = CAPTURE_DURATION) -> str:

    print(f"[Capture] Starting capture for {url}")

    target_ips = resolve_url_to_ips(url)

    # Start traffic generation
    t = threading.Thread(target=visit_url, args=(url,))
    t.start()

    time.sleep(1)

    print("[Capture] Sniffing packets...")

    try:
        packets = sniff(
            timeout=duration,
            filter=None  # (keeping None for Windows compatibility)
        )
    except Exception as e:
        print(f"[Capture] Sniff error: {e}")
        return ""

    print(f"[Capture] Packets captured: {len(packets)}")

    if len(packets) > 0:
        wrpcap(PCAP_FILE, packets)
        print(f"[Capture] Saved: {PCAP_FILE}")
    else:
        print("[Capture] No packets captured")

    return PCAP_FILE