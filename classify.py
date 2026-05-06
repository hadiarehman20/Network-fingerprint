"""
classify.py (FIXED)
Rule-based network behavior classification
"""

def classify_behavior(features: dict) -> tuple:

    total_bytes = features.get("total_bytes", 0)
    total_packets = features.get("total_packets", 0)
    mean_size = features.get("mean_packet_size", 0)

    unique_ips = features.get("unique_ip_count", 0)
    dns_queries = features.get("dns_query_count", 0)

    protocol_dist = features.get("protocol_distribution", {})

    tcp_pct = protocol_dist.get("TCP", 0)
    udp_pct = protocol_dist.get("UDP", 0)
    dns_pct = protocol_dist.get("DNS", 0)

    if total_packets == 0:
        return "Unknown", 0

    # ─────────────────────────────
    # STREAMING (YouTube/Netflix)
    # ─────────────────────────────
    streaming = 0
    if total_bytes > 400_000:
        streaming += 30
    if mean_size > 700:
        streaming += 25
    if tcp_pct > 60:
        streaming += 25
    if udp_pct > 20:
        streaming += 10

    # ─────────────────────────────
    # SOCIAL MEDIA
    # ─────────────────────────────
    social = 0
    if unique_ips > 8:
        social += 30
    if dns_queries > 6:
        social += 25
    if mean_size < 600:
        social += 20
    if total_packets > 90:
        social += 20

    # ─────────────────────────────
    # STATIC CONTENT
    # ─────────────────────────────
    static = 0
    if total_bytes < 120_000:
        static += 35
    if total_packets < 70:
        static += 35
    if dns_queries <= 3:
        static += 30

    # ─────────────────────────────
    # API HEAVY
    # ─────────────────────────────
    api = 0
    if mean_size < 350:
        api += 30
    if tcp_pct > 75:
        api += 30
    if total_packets > 60 and total_bytes < 250_000:
        api += 40

    scores = {
        "Streaming": streaming,
        "Social Media": social,
        "Static Content": static,
        "API-Heavy": api
    }

    label = max(scores, key=scores.get)
    confidence = scores[label]

    if confidence < 30:
        return "Unknown", 25

    confidence = min(confidence, 95)

    print(f"[Classify] {scores} → {label} ({confidence}%)")

    return label, confidence