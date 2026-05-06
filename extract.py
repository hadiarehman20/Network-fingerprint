"""
extract.py (FIXED VERSION)
Compatible with Flask + frontend dashboard
"""

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, ICMP, ARP
import statistics


def extract_features(pcap_file: str) -> dict:
    print(f"[Extract] Reading: {pcap_file}")

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[Extract] Error: {e}")
        return {}

    if not packets:
        return {}

    total_packets = len(packets)
    total_bytes = 0

    protocol_counts = {
        "TCP": 0,
        "UDP": 0,
        "DNS": 0,
        "ICMP": 0,
        "ARP": 0,
        "OTHER": 0
    }

    packet_sizes = []
    timestamps = []
    destination_ips = set()
    dns_queries = []

    for p in packets:
        size = len(p)
        packet_sizes.append(size)
        total_bytes += size

        if hasattr(p, "time"):
            timestamps.append(float(p.time))

        if p.haslayer(DNS):
            protocol_counts["DNS"] += 1
            if p.haslayer(DNSQR):
                try:
                    q = p[DNSQR].qname.decode(errors="ignore").rstrip(".")
                    if q:
                        dns_queries.append(q)
                except:
                    pass
        elif p.haslayer(TCP):
            protocol_counts["TCP"] += 1
        elif p.haslayer(UDP):
            protocol_counts["UDP"] += 1
        elif p.haslayer(ICMP):
            protocol_counts["ICMP"] += 1
        elif p.haslayer(ARP):
            protocol_counts["ARP"] += 1
        else:
            protocol_counts["OTHER"] += 1

        if p.haslayer(IP):
            destination_ips.add(p[IP].dst)

    # stats
    mean_size = round(statistics.mean(packet_sizes), 2) if packet_sizes else 0

    # protocol %
    protocol_distribution = {
        k: round((v / total_packets) * 100, 2)
        for k, v in protocol_counts.items()
    }

    # histogram
    histogram = {
        "0-100": 0,
        "101-500": 0,
        "501-1000": 0,
        "1001-1500": 0,
        "1500+": 0
    }

    for s in packet_sizes:
        if s <= 100:
            histogram["0-100"] += 1
        elif s <= 500:
            histogram["101-500"] += 1
        elif s <= 1000:
            histogram["501-1000"] += 1
        elif s <= 1500:
            histogram["1001-1500"] += 1
        else:
            histogram["1500+"] += 1

    # timeline (bytes/sec)
    timeline = {}
    for i, t in enumerate(timestamps):
        sec = int(t)
        size = packet_sizes[i] if i < len(packet_sizes) else 0
        timeline[sec] = timeline.get(sec, 0) + size

    if timeline:
        base = min(timeline.keys())
        timeline = {k - base: v for k, v in sorted(timeline.items())}

    print("[Extract] Done")

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "mean_packet_size": mean_size,
        "min_packet_size": min(packet_sizes),
        "max_packet_size": max(packet_sizes),

        "unique_ips": list(destination_ips),
        "unique_ip_count": len(destination_ips),

        "dns_queries": dns_queries[:15],
        "dns_query_count": len(dns_queries),

        "protocol_distribution": protocol_distribution,
        "packet_size_histogram": histogram,
        "bytes_per_second": list(timeline.values())
    }