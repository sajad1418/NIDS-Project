
from flask import Flask, render_template_string, jsonify, request
import sqlite3
from pathlib import Path

app = Flask(__name__)

DB_PATH = Path(__file__).resolve().parent / "data" / "nids.db"


# ==========================================
# DATABASE FUNCTIONS
# ==========================================

def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def get_dashboard_data():

    if not DB_PATH.exists():
        return {
            "total": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "sources": 0,
            "attacks": [],
            "severity": [],
            "alerts": []
        }

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM alerts")
    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE UPPER(severity) = 'HIGH'
    """)
    high = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE UPPER(severity) = 'MEDIUM'
    """)
    medium = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE UPPER(severity) = 'LOW'
    """)
    low = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(DISTINCT source_ip) FROM alerts
    """)
    sources = cursor.fetchone()[0]

    cursor.execute("""
        SELECT attack_type, COUNT(*)
        FROM alerts
        GROUP BY attack_type
    """)
    attacks = [
        {"name": row[0], "count": row[1]}
        for row in cursor.fetchall()
    ]

    severity = [
        {"name": "HIGH", "count": high},
        {"name": "MEDIUM", "count": medium},
        {"name": "LOW", "count": low}
    ]

    cursor.execute("""
        SELECT id, attack_type, source_ip, target_ip,
               detected_at, unique_ports, severity
        FROM alerts
        ORDER BY id DESC
        LIMIT 100
    """)

    alerts = [dict(row) for row in cursor.fetchall()]

    connection.close()

    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
        "sources": sources,
        "attacks": attacks,
        "severity": severity,
        "alerts": alerts
    }


# ==========================================
# DASHBOARD HTML
# ==========================================

HTML = """
<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>NIDS | Security Operations Center</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #080d18;
    color: #e5e7eb;
    font-family: Arial, sans-serif;
}

header {
    padding: 22px 30px;
    background: #101827;
    border-bottom: 1px solid #263449;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 15px;
}

header h1 {
    margin: 0;
    color: #22d3ee;
}

header p {
    color: #94a3b8;
    margin-bottom: 0;
}

.online {
    color: #22c55e;
    font-weight: bold;
}

.container {
    padding: 25px;
}

.section-title {
    color: #22d3ee;
    margin-bottom: 20px;
}

.cards {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 18px;
}

.card {
    background: #111c2e;
    padding: 22px;
    border: 1px solid #263449;
    border-radius: 12px;
}

.card h3 {
    color: #94a3b8;
    font-size: 13px;
}

.number {
    font-size: 32px;
    font-weight: bold;
    color: #22d3ee;
}

.high {
    color: #ef4444;
}

.medium {
    color: #f59e0b;
}

.low {
    color: #22c55e;
}

.charts {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-top: 25px;
}

.panel {
    background: #111c2e;
    padding: 22px;
    border: 1px solid #263449;
    border-radius: 12px;
    min-width: 0;
}

.chart-container {
    height: 260px;
    position: relative;
}

.table-panel {
    margin-top: 25px;
}

.controls {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 20px;
}

input, select {
    background: #080d18;
    color: white;
    border: 1px solid #263449;
    padding: 12px;
    border-radius: 7px;
}

table {
    width: 100%;
    border-collapse: collapse;
    min-width: 850px;
}

.table-wrap {
    overflow-x: auto;
}

th, td {
    padding: 15px;
    text-align: left;
    border-bottom: 1px solid #263449;
}

th {
    color: #94a3b8;
}

footer {
    text-align: center;
    padding: 25px;
    color: #64748b;
}

@media(max-width: 1000px) {
    .cards {
        grid-template-columns: repeat(2, 1fr);
    }
}

@media(max-width: 650px) {
    .charts {
        grid-template-columns: 1fr;
    }

    .cards {
        grid-template-columns: 1fr 1fr;
    }

    .container {
        padding: 12px;
    }
}

</style>
</head>

<body>

<header>
    <div>
        <h1>🛡 NIDS | SOC Dashboard</h1>
        <p>Network Intrusion Detection & Threat Intelligence</p>
    </div>

    <div class="online">
        ● DASHBOARD ONLINE
        <p id="lastUpdate">Waiting for data...</p>
    </div>
</header>

<div class="container">

    <h2 class="section-title">Security Overview</h2>

    <div class="cards">

        <div class="card">
            <h3>Total Alerts</h3>
            <div class="number" id="total">0</div>
        </div>

        <div class="card">
            <h3>High Severity</h3>
            <div class="number high" id="high">0</div>
        </div>

        <div class="card">
            <h3>Medium Severity</h3>
            <div class="number medium" id="medium">0</div>
        </div>

        <div class="card">
            <h3>Low Severity</h3>
            <div class="number low" id="low">0</div>
        </div>

        <div class="card">
            <h3>Unique Source IPs</h3>
            <div class="number" id="sources">0</div>
        </div>

    </div>


    <div class="charts">

        <div class="panel">
            <h3>Attack Distribution</h3>
            <div class="chart-container">
                <canvas id="attackChart"></canvas>
            </div>
        </div>

        <div class="panel">
            <h3>Severity Distribution</h3>
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
        </div>

    </div>


    <div class="panel table-panel">

        <h2 class="section-title">Live Security Alert Feed</h2>

        <div class="controls">

            <input
                type="text"
                id="search"
                placeholder="Search IP or attack..."
            >

            <select id="severityFilter">
                <option value="">All Severities</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
            </select>

        </div>

        <div class="table-wrap">

            <table>

                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Attack Type</th>
                        <th>Source IP</th>
                        <th>Target IP</th>
                        <th>Ports</th>
                        <th>Timestamp</th>
                        <th>Severity</th>
                    </tr>
                </thead>

                <tbody id="alertTable">
                    <tr>
                        <td colspan="7">Loading security alerts...</td>
                    </tr>
                </tbody>

            </table>

        </div>

    </div>

</div>

<footer>
    NIDS | Python • Scapy • Npcap • SQLite • Flask
    <br><br>
    Academic Cybersecurity Project
</footer>


<script>

let attackChart = null;
let severityChart = null;
let latestAlerts = [];

function createCharts(data) {

    if (typeof Chart === "undefined") {
        return;
    }

    const attackLabels = data.attacks.map(x => x.name);
    const attackValues = data.attacks.map(x => x.count);

    const severityLabels = data.severity.map(x => x.name);
    const severityValues = data.severity.map(x => x.count);

    if (!attackChart) {

        attackChart = new Chart(
            document.getElementById("attackChart"),
            {
                type: "doughnut",
                data: {
                    labels: attackLabels,
                    datasets: [{
                        data: attackValues,
                        backgroundColor: [
                            "#22d3ee",
                            "#8b5cf6",
                            "#f59e0b",
                            "#ef4444"
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: { color: "#e5e7eb" }
                        }
                    }
                }
            }
        );

        severityChart = new Chart(
            document.getElementById("severityChart"),
            {
                type: "bar",
                data: {
                    labels: severityLabels,
                    datasets: [{
                        label: "Alerts",
                        data: severityValues,
                        backgroundColor: [
                            "#ef4444",
                            "#f59e0b",
                            "#22c55e"
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            ticks: { color: "#e5e7eb" }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: {
                                color: "#e5e7eb",
                                precision: 0
                            }
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            }
        );

    } else {

        attackChart.data.labels = attackLabels;
        attackChart.data.datasets[0].data = attackValues;
        attackChart.update();

        severityChart.data.labels = severityLabels;
        severityChart.data.datasets[0].data = severityValues;
        severityChart.update();
    }
}


function renderAlerts() {

    const search = document.getElementById("search")
        .value.toLowerCase();

    const severity = document.getElementById("severityFilter")
        .value;

    const filtered = latestAlerts.filter(alert => {

        const text = (
            alert.attack_type + " " +
            alert.source_ip + " " +
            alert.target_ip
        ).toLowerCase();

        return text.includes(search) &&
            (!severity || alert.severity.toUpperCase() === severity);
    });

    const table = document.getElementById("alertTable");

    if (filtered.length === 0) {
        table.innerHTML =
            '<tr><td colspan="7">No matching alerts found.</td></tr>';
        return;
    }

    table.innerHTML = filtered.map(alert => {

        const level = alert.severity.toLowerCase();

        return `
            <tr>
                <td>${alert.id}</td>
                <td>${escapeHTML(alert.attack_type)}</td>
                <td>${escapeHTML(alert.source_ip)}</td>
                <td>${escapeHTML(alert.target_ip)}</td>
                <td>${alert.unique_ports ?? "-"}</td>
                <td>${escapeHTML(alert.detected_at)}</td>
                <td class="${level}">
                    ${escapeHTML(alert.severity)}
                </td>
            </tr>
        `;
    }).join("");
}


function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[char]);
}


async function updateDashboard() {

    try {

        const response = await fetch("/api/stats");

        if (!response.ok) {
            throw new Error("Dashboard API request failed");
        }

        const data = await response.json();

        document.getElementById("total").textContent = data.total;
        document.getElementById("high").textContent = data.high;
        document.getElementById("medium").textContent = data.medium;
        document.getElementById("low").textContent = data.low;
        document.getElementById("sources").textContent = data.sources;

        latestAlerts = data.alerts;

        createCharts(data);
        renderAlerts();

        document.getElementById("lastUpdate").textContent =
            "Last updated: " + new Date().toLocaleTimeString();

    } catch (error) {

        document.getElementById("lastUpdate").textContent =
            "Unable to load latest data";
        console.error(error);

    }
}


document.getElementById("search")
    .addEventListener("input", renderAlerts);

document.getElementById("severityFilter")
    .addEventListener("change", renderAlerts);


updateDashboard();
setInterval(updateDashboard, 5000);

</script>

</body>
</html>
"""


# ==========================================
# FLASK ROUTES
# ==========================================

@app.route("/")
def dashboard():
    return render_template_string(HTML)


@app.route("/api/stats")
def stats():
    return jsonify(get_dashboard_data())


@app.route("/api/alerts")
def alerts():
    return jsonify(get_dashboard_data()["alerts"])


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    print("Starting NIDS SOC Dashboard...")
    print("Dashboard: http://127.0.0.1:5000")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
