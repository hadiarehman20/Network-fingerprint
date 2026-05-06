"""
app.py
------
Flask web server exposing REST API endpoints.

Routes:
  GET  /                  → serves the frontend HTML page
  POST /api/analyze       → capture + fingerprint one URL
  POST /api/compare       → capture + fingerprint two URLs side by side
  GET  /api/demo          → return a fake fingerprint (no Scapy needed, for testing)
"""

import uuid
import os
import json
import time

from flask import Flask, request, jsonify, render_template, send_from_directory

app = Flask(__name__)

# ── Try to import our own modules ──────────────────────────────────────────────
try:
    from capture import capture_packets
    from extract import extract_features
    from fingerprint import build_fingerprint, build_comparison_diff
    CAPTURE_READY = True
except ImportError as e:
    CAPTURE_READY = False
    _import_error = str(e)


# ══════════════════════════════════════════════════════════════════════════════
# Helper – build a demo fingerprint so the UI can be tested without root/Scapy
# ══════════════════════════════════════════════════════════════════════════════

def _demo_fingerprint(url: str, seed: int = 42) -> dict:
    """Return a realistic-looking fake fingerprint for UI demonstration."""
    import random
    rng = random.Random(seed)

    total_pkts = rng.randint(120, 600)
    sizes      = [rng.randint(40, 1480) for _ in range(total_pkts)]
    total_b    = sum(sizes)

    proto = {
        "HTTPS": rng.randint(40, 70),
        "TCP":   rng.randint(10, 25),
        "DNS":   rng.randint(3, 12),
        "UDP":   rng.randint(2, 10),
    }
    s = sum(proto.values())
    proto = {k: round(v / s * 100, 2) for k, v in proto.items()}

    hist = {
        "0-100":    sum(1 for x in sizes if x <= 100),
        "101-500":  sum(1 for x in sizes if 101 <= x <= 500),
        "501-1000": sum(1 for x in sizes if 501 <= x <= 1000),
        "1001-1500":sum(1 for x in sizes if 1001 <= x <= 1500),
        "1500+":    sum(1 for x in sizes if x > 1500),
    }

    bps = [rng.randint(5_000, 80_000) for _ in range(10)]

    labels = ["Streaming", "Static Content", "API-Heavy", "Social Media"]
    label  = rng.choice(labels)

    return {
        "site_url":              url,
        "capture_timestamp":     time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_packets":         total_pkts,
        "total_bytes":           total_b,
        "total_bytes_human":     _human(total_b),
        "top_protocol":          "HTTPS",
        "unique_ips":            [f"93.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}" for _ in range(rng.randint(4, 14))],
        "unique_ip_count":       rng.randint(4, 14),
        "dns_queries":           [f"cdn{i}.{url.split('//')[-1].split('/')[0]}" for i in range(rng.randint(3, 8))],
        "dns_query_count":       rng.randint(3, 8),
        "mean_packet_size":      round(sum(sizes) / len(sizes), 2),
        "min_packet_size":       min(sizes),
        "max_packet_size":       max(sizes),
        "protocol_distribution": proto,
        "packet_size_histogram": hist,
        "bytes_per_second":      bps,
        "capture_duration":      10.0,
        "behavior_label":        label,
        "confidence":            rng.randint(55, 92),
    }


def _human(num):
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


# ══════════════════════════════════════════════════════════════════════════════
# Routes
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def status():
    return jsonify({"capture_ready": CAPTURE_READY})


@app.route("/api/demo")
def demo():
    """Return a demo fingerprint (no root/Scapy required)."""
    url = request.args.get("url", "https://example.com")
    return jsonify({"fingerprint": _demo_fingerprint(url, seed=hash(url) % 9999)})


@app.route("/api/demo_compare")
def demo_compare():
    url1 = request.args.get("url1", "https://youtube.com")
    url2 = request.args.get("url2", "https://wikipedia.org")
    fp1  = _demo_fingerprint(url1, seed=hash(url1) % 9999)
    fp2  = _demo_fingerprint(url2, seed=hash(url2) % 9999)
    diff = {
        "more_bytes":         "site1" if fp1["total_bytes"] > fp2["total_bytes"] else "site2",
        "more_packets":       "site1" if fp1["total_packets"] > fp2["total_packets"] else "site2",
        "more_unique_ips":    "site1" if fp1["unique_ip_count"] > fp2["unique_ip_count"] else "site2",
        "larger_mean_packet": "site1" if fp1["mean_packet_size"] > fp2["mean_packet_size"] else "site2",
        "more_dns_queries":   "site1" if fp1["dns_query_count"] > fp2["dns_query_count"] else "site2",
        "site1_label":        fp1["behavior_label"],
        "site2_label":        fp2["behavior_label"],
    }
    return jsonify({"site1": fp1, "site2": fp2, "diff": diff})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Expects JSON body: { "url": "https://example.com" }
    Returns the network fingerprint as JSON.
    """
    data = request.get_json(force=True, silent=True) or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided."}), 400
    if not (url.startswith("http://") or url.startswith("https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    if not CAPTURE_READY:
        return jsonify({
            "error": (
                "Scapy is not installed or this system cannot capture packets. "
                "Use the /api/demo endpoint to try the UI with simulated data."
            )
        }), 503

    capture_id = str(uuid.uuid4())

    try:
        pcap_path, pkt_count = capture_packets(url, capture_id)
        features    = extract_features(pcap_path)
        fingerprint = build_fingerprint(url, features)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    finally:
        # Clean up temp pcap
        try:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)
        except Exception:
            pass

    return jsonify({"fingerprint": fingerprint})


@app.route("/api/compare", methods=["POST"])
def compare():
    """
    Expects JSON: { "url1": "...", "url2": "..." }
    Returns two fingerprints + a diff object.
    """
    data = request.get_json(force=True, silent=True) or {}
    url1 = data.get("url1", "").strip()
    url2 = data.get("url2", "").strip()

    if not url1 or not url2:
        return jsonify({"error": "Both url1 and url2 are required."}), 400

    if not CAPTURE_READY:
        return jsonify({
            "error": "Scapy not available. Use /api/demo_compare for a demonstration."
        }), 503

    results = {}
    for key, url in [("site1", url1), ("site2", url2)]:
        cid = str(uuid.uuid4())
        try:
            pcap_path, _ = capture_packets(url, cid)
            features     = extract_features(pcap_path)
            results[key] = build_fingerprint(url, features)
        except Exception as exc:
            return jsonify({"error": f"Error capturing {url}: {exc}"}), 500
        finally:
            try:
                if os.path.exists(pcap_path):
                    os.remove(pcap_path)
            except Exception:
                pass

    diff = build_comparison_diff(results["site1"], results["site2"])
    return jsonify({"site1": results["site1"], "site2": results["site2"], "diff": diff})


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "="*60)
    print("  Network Fingerprint Tool")
    print("  Open your browser at:  http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)