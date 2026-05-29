# ============================================
# ThreatWatch AI - Web Dashboard
# ============================================
# This creates a real webpage you can open
# in your browser to see all threats visually.
# Built with Flask - a Python web framework.
# ============================================

from flask import Flask, render_template_string
import json
import os

app = Flask(__name__)

LOG_FILE = "logs/threats.json"

# -----------------------------------------------
# HTML TEMPLATE - This is the actual webpage
# Dark theme, looks like a real security dashboard
# -----------------------------------------------
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>ThreatWatch AI - Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background-color: #0a0e1a;
            color: #e0e0e0;
            font-family: 'Courier New', monospace;
        }

        /* TOP HEADER BAR */
        .header {
            background: #0d1b2a;
            border-bottom: 2px solid #00ff88;
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            color: #00ff88;
            font-size: 22px;
            letter-spacing: 2px;
        }
        .header .status {
            color: #00ff88;
            font-size: 13px;
            animation: blink 1.5s infinite;
        }
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50%       { opacity: 0.3; }
        }

        /* STATS CARDS ROW */
        .stats-row {
            display: flex;
            gap: 20px;
            padding: 25px 30px;
        }
        .stat-card {
            flex: 1;
            background: #0d1b2a;
            border: 1px solid #1a3a5c;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        .stat-card .number {
            font-size: 40px;
            font-weight: bold;
            margin-bottom: 8px;
        }
        .stat-card .label {
            font-size: 12px;
            color: #888;
            letter-spacing: 1px;
            text-transform: uppercase;
        }
        .card-total   .number { color: #00aaff; }
        .card-blocked .number { color: #ff4444; }
        .card-alerts  .number { color: #ffaa00; }
        .card-safe    .number { color: #00ff88; }

        /* THREAT TABLE */
        .table-section {
            padding: 0 30px 30px;
        }
        .table-section h2 {
            color: #00aaff;
            font-size: 14px;
            letter-spacing: 2px;
            margin-bottom: 15px;
            text-transform: uppercase;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        th {
            background: #0d1b2a;
            color: #00aaff;
            padding: 12px 15px;
            text-align: left;
            letter-spacing: 1px;
            font-size: 11px;
            text-transform: uppercase;
            border-bottom: 1px solid #1a3a5c;
        }
        td {
            padding: 11px 15px;
            border-bottom: 1px solid #111827;
        }
        tr:hover td { background: #0d1b2a; }

        /* SEVERITY BADGES */
        .badge {
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 1px;
        }
        .badge-critical { background: #3d0000; color: #ff4444; border: 1px solid #ff4444; }
        .badge-high     { background: #2d1500; color: #ff8800; border: 1px solid #ff8800; }
        .badge-medium   { background: #2d2500; color: #ffcc00; border: 1px solid #ffcc00; }
        .badge-low      { background: #002d1a; color: #00ff88; border: 1px solid #00ff88; }

        /* ACTION BADGES */
        .action-blocked { color: #ff4444; font-weight: bold; }
        .action-alert   { color: #ffaa00; font-weight: bold; }
        .action-log     { color: #888; }

        /* SCORE BAR */
        .score-bar {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .bar-bg {
            flex: 1;
            height: 6px;
            background: #1a2a3a;
            border-radius: 3px;
            overflow: hidden;
        }
        .bar-fill {
            height: 100%;
            border-radius: 3px;
        }

        .footer {
            text-align: center;
            padding: 15px;
            color: #333;
            font-size: 11px;
            border-top: 1px solid #111827;
        }
    </style>
</head>
<body>

<!-- HEADER -->
<div class="header">
    <h1>🛡 THREATWATCH AI — AUTONOMOUS CYBER DEFENSE</h1>
    <div class="status">● LIVE MONITORING — AUTO REFRESH 5s</div>
</div>

<!-- STATS CARDS -->
<div class="stats-row">
    <div class="stat-card card-total">
        <div class="number">{{ total }}</div>
        <div class="label">Total Threats</div>
    </div>
    <div class="stat-card card-blocked">
        <div class="number">{{ blocked }}</div>
        <div class="label">IPs Blocked</div>
    </div>
    <div class="stat-card card-alerts">
        <div class="number">{{ alerts }}</div>
        <div class="label">Alerts Sent</div>
    </div>
    <div class="stat-card card-safe">
        <div class="number">{{ avg_score }}</div>
        <div class="label">Avg Risk Score</div>
    </div>
</div>

<!-- THREAT TABLE -->
<div class="table-section">
    <h2>⚡ Live Threat Feed</h2>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Timestamp</th>
                <th>IP Address</th>
                <th>Threat Type</th>
                <th>Risk Score</th>
                <th>Severity</th>
                <th>Action Taken</th>
            </tr>
        </thead>
        <tbody>
            {% for t in threats|reverse %}
            <tr>
                <td style="color:#444">{{ loop.index }}</td>
                <td style="color:#666">{{ t.timestamp }}</td>
                <td style="color:#00aaff">{{ t.ip_address }}</td>
                <td>{{ t.threat_type }}</td>
                <td>
                    <div class="score-bar">
                        <span style="min-width:30px; color:
                            {% if t.risk_score >= 90 %}#ff4444
                            {% elif t.risk_score >= 70 %}#ff8800
                            {% elif t.risk_score >= 40 %}#ffcc00
                            {% else %}#00ff88{% endif %}
                        ">{{ t.risk_score }}</span>
                        <div class="bar-bg">
                            <div class="bar-fill" style="
                                width: {{ t.risk_score }}%;
                                background:
                                    {% if t.risk_score >= 90 %}#ff4444
                                    {% elif t.risk_score >= 70 %}#ff8800
                                    {% elif t.risk_score >= 40 %}#ffcc00
                                    {% else %}#00ff88{% endif %};
                            "></div>
                        </div>
                    </div>
                </td>
                <td>
                    {% if t.risk_score >= 90 %}
                        <span class="badge badge-critical">CRITICAL</span>
                    {% elif t.risk_score >= 70 %}
                        <span class="badge badge-high">HIGH</span>
                    {% elif t.risk_score >= 40 %}
                        <span class="badge badge-medium">MEDIUM</span>
                    {% else %}
                        <span class="badge badge-low">LOW</span>
                    {% endif %}
                </td>
                <td>
                    {% if t.action_taken == "IP Blocked" %}
                        <span class="action-blocked">⛔ IP Blocked</span>
                    {% elif t.action_taken == "Alert Sent" %}
                        <span class="action-alert">⚠ Alert Sent</span>
                    {% else %}
                        <span class="action-log">📋 Logged</span>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<div class="footer">
    ThreatWatch AI v1.0 — STMU BSCYS-III — Zaynab Amjad Abbasi & Zarmeen Zawar Ghauri
</div>

</body>
</html>
"""

# -----------------------------------------------
# FLASK ROUTE - loads the dashboard page
# -----------------------------------------------
@app.route("/")
def dashboard():
    # Load threats from log file
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            threats = json.load(f)
    else:
        threats = []

    # Calculate stats for the top cards
    total   = len(threats)
    blocked = sum(1 for t in threats if t["action_taken"] == "IP Blocked")
    alerts  = sum(1 for t in threats if t["action_taken"] == "Alert Sent")
    avg_score = round(sum(t["risk_score"] for t in threats) / total) if total > 0 else 0

    return render_template_string(
        HTML_PAGE,
        threats   = threats,
        total     = total,
        blocked   = blocked,
        alerts    = alerts,
        avg_score = avg_score
    )


# -----------------------------------------------
# START THE DASHBOARD SERVER
# -----------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("  ThreatWatch AI - Dashboard Starting...")
    print("=" * 50)
    print("\n  Open your browser and go to:")
    print("  http://127.0.0.1:5000")
    print("\n  Press CTRL+C to stop the server")
    print("=" * 50)
    app.run(debug=True)