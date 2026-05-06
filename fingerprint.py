"""
fingerprint.py (FIXED VERSION)
Creates final structured output for frontend + classification
"""

import datetime
from classify import classify_behavior


# ─────────────────────────────
# MAIN FINGERPRINT FUNCTION
# ─────────────────────────────
def build_fingerprint(url: str, features: dict) -> dict:

    print(f"[Fingerprint] Processing: {url}")

    label, confidence = classify_behavior(features)

    protocol_dist = features.get("protocol_distribution", {})

    top_protocol = (
        max(protocol_dist, key=protocol_dist.get)
        if protocol_dist else "Unknown"
    )

    fingerprint = {
        # Identity
        "site_url": url,
        "capture_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        # Traffic volume
        "total_packets": features.get("total_packets", 0),
        "total_bytes": features.get("total_bytes", 0),
        "total_bytes_human": f"{features.get('total_bytes', 0) / 1024:.2f} KB",

        # Packet stats
        "mean_packet_size": features.get("mean_packet_size", 0),
        "min_packet_size": features.get("min_packet_size", 0),
        "max_packet_size": features.get("max_packet_size", 0),

        # Protocols
        "top_protocol": top_protocol,
        "protocol_distribution": protocol_dist,

        # Network scope
        "unique_ip_count": features.get("unique_ip_count", 0),

        # DNS
        "dns_queries": features.get("dns_queries", []),
        "dns_query_count": features.get("dns_query_count", 0),

        # Classification
        "behavior_label": label,
        "confidence": confidence,

        # Visualization
        "packet_size_histogram": features.get("packet_size_histogram", {}),
        "bytes_per_second": features.get("bytes_per_second", [])
    }

    print(f"[Fingerprint] Done → {label} ({confidence}%)")

    return fingerprint


# ─────────────────────────────
# COMPARISON FUNCTION (FIXED)
# ─────────────────────────────
def build_comparison_diff(fp1: dict, fp2: dict) -> dict:

    def compare(a, b, higher_is="worse"):
        if a > b:
            winner = "site1" if higher_is == "better" else "site2"
        elif b > a:
            winner = "site2" if higher_is == "better" else "site1"
        else:
            winner = "tie"

        return {
            "site1": a,
            "site2": b,
            "winner": winner
        }

    return {
        "total_bytes": compare(fp1["total_bytes"], fp2["total_bytes"]),
        "total_packets": compare(fp1["total_packets"], fp2["total_packets"]),
        "unique_ips": compare(fp1["unique_ip_count"], fp2["unique_ip_count"]),
        "mean_packet_size": compare(fp1["mean_packet_size"], fp2["mean_packet_size"]),
        "dns_queries": compare(fp1["dns_query_count"], fp2["dns_query_count"]),
        "labels": {
            "site1": fp1["behavior_label"],
            "site2": fp2["behavior_label"]
        }
    }