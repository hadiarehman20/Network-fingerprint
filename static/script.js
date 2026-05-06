// ─────────────────────────────
// MODE
// ─────────────────────────────
let mode = "single";

function setMode(m) {
    mode = m;

    document.getElementById("singleMode").style.display =
        m === "single" ? "block" : "none";

    document.getElementById("compareMode").style.display =
        m === "compare" ? "block" : "none";
}

// ─────────────────────────────
// LOADING
// ─────────────────────────────
function showLoading(state) {
    document.getElementById("loadingDiv").style.display =
        state ? "block" : "none";
}

// ─────────────────────────────
// SINGLE ANALYSIS (REAL)
// ─────────────────────────────
async function runSingle() {
    const url = document.getElementById("urlInput").value;

    showLoading(true);

    const res = await fetch("/api/demo?url=" + encodeURIComponent(url || "https://example.com"));
    const data = await res.json();

    showLoading(false);
    renderSingle(data.fingerprint);
}

// ─────────────────────────────
// RENDER SINGLE DASHBOARD
// ─────────────────────────────
function renderSingle(fp) {
    document.getElementById("resultSection").style.display = "block";

    document.getElementById("summaryGrid").innerHTML = `
    <div class="card">Packets: ${fp.total_packets}</div>
    <div class="card">Bytes: ${fp.total_bytes}</div>
    <div class="card">DNS: ${fp.dns_query_count}</div>
    <div class="card">IPs: ${fp.unique_ip_count}</div>
    <div class="card">Label: ${fp.behavior_label}</div>
  `;

    drawProtocolChart(fp.protocol_distribution);
    drawHistogram(fp.packet_size_histogram);
    drawTimeline(fp.bytes_per_second);
}

// ─────────────────────────────
// CHART 1 - PROTOCOL PIE
// ─────────────────────────────
function drawProtocolChart(data) {
    new Chart(document.getElementById("protoChart"), {
        type: "pie",
        data: {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data)
            }]
        }
    });
}

// ─────────────────────────────
// CHART 2 - HISTOGRAM
// ─────────────────────────────
function drawHistogram(data) {
    new Chart(document.getElementById("histChart"), {
        type: "bar",
        data: {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data)
            }]
        }
    });
}

// ─────────────────────────────
// CHART 3 - TIMELINE
// ─────────────────────────────
function drawTimeline(data) {
    new Chart(document.getElementById("timelineChart"), {
        type: "line",
        data: {
            labels: data.map((_, i) => i),
            datasets: [{
                data: data,
                fill: false
            }]
        }
    });
}

// ─────────────────────────────
// DEMO COMPARE (simple)
// ─────────────────────────────
async function runCompare() {
    const url1 = document.getElementById("url1Input").value || "a.com";
    const url2 = document.getElementById("url2Input").value || "b.com";

    const res = await fetch(`/api/demo_compare?url1=${url1}&url2=${url2}`);
    const data = await res.json();

    document.getElementById("compareResult").style.display = "block";

    document.getElementById("compareCards").innerHTML = `
    <div>Site 1: ${data.site1.site_url}</div>
    <div>Site 2: ${data.site2.site_url}</div>
  `;
}