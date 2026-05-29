# ============================================
# ThreatWatch AI - Authentication System
# ============================================
# This adds a login page to the dashboard.
# Only authorised users can access the
# threat monitoring interface.
#
# Users and roles:
#   admin    → full access
#   analyst  → view only
#   monitor  → view only
# ============================================

from flask import Flask, render_template_string, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import json
import os
import datetime

app = Flask(__name__)
app.secret_key = "threatwatch_ai_secret_key_stmu_2026"

LOG_FILE = "logs/threats.json"

# -----------------------------------------------
# USER DATABASE
# Passwords are hashed — never stored as plain text
# -----------------------------------------------
USERS = {
    "admin": {
        "password": generate_password_hash("admin123"),
        "role":     "Administrator",
        "name":     "System Administrator"
    },
    "zarmeen": {
        "password": generate_password_hash("stmu2026"),
        "role":     "Security Analyst",
        "name":     "Zaynab Amjad Abbasi"
    },
    "zaynab": {
        "password": generate_password_hash("stmu2026"),
        "role":     "Security Analyst",
        "name":     "Zarmeen Zawar Ghauri"
    },
    "monitor": {
        "password": generate_password_hash("monitor123"),
        "role":     "Network Monitor",
        "name":     "Network Monitor"
    }
}

# -----------------------------------------------
# LOGIN REQUIRED DECORATOR
# Put @login_required above any route that
# needs the user to be logged in first
# -----------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# -----------------------------------------------
# HTML TEMPLATES
# -----------------------------------------------

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>ThreatWatch AI — Login</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            background: #0a0e1a;
            font-family: 'Courier New', monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-box {
            background: #0d1b2a;
            border: 1px solid #1a3a5c;
            border-radius: 12px;
            padding: 40px;
            width: 380px;
            text-align: center;
        }
        .logo {
            font-size: 40px;
            margin-bottom: 10px;
        }
        h1 {
            color: #00ff88;
            font-size: 18px;
            letter-spacing: 2px;
            margin-bottom: 6px;
        }
        .subtitle {
            color: #666;
            font-size: 11px;
            letter-spacing: 1px;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 16px;
            text-align: left;
        }
        label {
            display: block;
            color: #00aaff;
            font-size: 11px;
            letter-spacing: 1px;
            margin-bottom: 6px;
            text-transform: uppercase;
        }
        input {
            width: 100%;
            padding: 12px 14px;
            background: #0a0e1a;
            border: 1px solid #1a3a5c;
            border-radius: 6px;
            color: #e0e0e0;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            outline: none;
            transition: border-color 0.2s;
        }
        input:focus { border-color: #00aaff; }
        .btn-login {
            width: 100%;
            padding: 12px;
            background: #00aaff;
            color: #0a0e1a;
            border: none;
            border-radius: 6px;
            font-size: 13px;
            font-weight: bold;
            font-family: 'Courier New', monospace;
            letter-spacing: 2px;
            cursor: pointer;
            margin-top: 10px;
            transition: background 0.2s;
        }
        .btn-login:hover { background: #00ff88; }
        .error {
            background: #3d0000;
            border: 1px solid #ff4444;
            color: #ff4444;
            padding: 10px;
            border-radius: 6px;
            font-size: 12px;
            margin-bottom: 16px;
        }
        .footer {
            color: #333;
            font-size: 10px;
            margin-top: 24px;
        }
        .divider {
            border: none;
            border-top: 1px solid #1a3a5c;
            margin: 24px 0;
        }
        .hint {
            color: #444;
            font-size: 10px;
            margin-top: 16px;
        }
    </style>
</head>
<body>
<div class="login-box">
    <div class="logo">🛡</div>
    <h1>THREATWATCH AI</h1>
    <div class="subtitle">AUTONOMOUS CYBER DEFENSE SYSTEM</div>

    {% if error %}
    <div class="error">⛔ {{ error }}</div>
    {% endif %}

    <form method="POST" action="/login">
        <div class="form-group">
            <label>Username</label>
            <input type="text" name="username" placeholder="Enter username" required autofocus>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" placeholder="Enter password" required>
        </div>
        <button type="submit" class="btn-login">🔐 SECURE LOGIN</button>
    </form>

    <hr class="divider">
    <div class="hint">
        Demo credentials:<br>
        admin / admin123 &nbsp;|&nbsp; zaynab / stmu2026
    </div>

    <div class="footer">
        STMU BSCYS-III | CS2141 Artificial Intelligence | 2026
    </div>
</div>
</body>
</html>
"""


DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>ThreatWatch AI - Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { background:#0a0e1a; color:#e0e0e0; font-family:'Courier New',monospace; }

        .header {
            background:#0d1b2a;
            border-bottom:2px solid #00ff88;
            padding:12px 30px;
            display:flex;
            justify-content:space-between;
            align-items:center;
        }
        .header h1 { color:#00ff88; font-size:18px; letter-spacing:2px; }
        .header .right { display:flex; align-items:center; gap:20px; }
        .user-badge {
            background:#0a0e1a;
            border:1px solid #1a3a5c;
            border-radius:20px;
            padding:5px 14px;
            font-size:11px;
            color:#00aaff;
        }
        .logout-btn {
            background:transparent;
            border:1px solid #ff4444;
            color:#ff4444;
            padding:5px 14px;
            border-radius:20px;
            font-size:11px;
            cursor:pointer;
            font-family:'Courier New',monospace;
            text-decoration:none;
        }
        .logout-btn:hover { background:#3d0000; }
        .status { color:#00ff88; font-size:12px; animation:blink 1.5s infinite; }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

        .stats-row {
            display:flex; gap:20px; padding:20px 30px;
        }
        .stat-card {
            flex:1; background:#0d1b2a; border:1px solid #1a3a5c;
            border-radius:8px; padding:18px; text-align:center;
        }
        .stat-card .number { font-size:36px; font-weight:bold; margin-bottom:6px; }
        .stat-card .label  { font-size:11px; color:#888; letter-spacing:1px; text-transform:uppercase; }
        .card-total   .number { color:#00aaff; }
        .card-blocked .number { color:#ff4444; }
        .card-alerts  .number { color:#ffaa00; }
        .card-score   .number { color:#00ff88; }

        .table-section { padding:0 30px 30px; }
        .table-section h2 {
            color:#00aaff; font-size:13px; letter-spacing:2px;
            margin-bottom:12px; text-transform:uppercase;
        }
        table { width:100%; border-collapse:collapse; font-size:12px; }
        th {
            background:#0d1b2a; color:#00aaff; padding:10px 14px;
            text-align:left; letter-spacing:1px; font-size:10px;
            text-transform:uppercase; border-bottom:1px solid #1a3a5c;
        }
        td { padding:9px 14px; border-bottom:1px solid #111827; }
        tr:hover td { background:#0d1b2a; }

        .badge { padding:2px 9px; border-radius:10px; font-size:10px; font-weight:bold; letter-spacing:1px; }
        .badge-critical { background:#3d0000; color:#ff4444; border:1px solid #ff4444; }
        .badge-high     { background:#2d1500; color:#ff8800; border:1px solid #ff8800; }
        .badge-medium   { background:#2d2500; color:#ffcc00; border:1px solid #ffcc00; }
        .badge-low      { background:#002d1a; color:#00ff88; border:1px solid #00ff88; }

        .action-blocked { color:#ff4444; font-weight:bold; }
        .action-alert   { color:#ffaa00; font-weight:bold; }

        .score-bar { display:flex; align-items:center; gap:6px; }
        .bar-bg    { flex:1; height:5px; background:#1a2a3a; border-radius:3px; overflow:hidden; }
        .bar-fill  { height:100%; border-radius:3px; }

        .footer {
            text-align:center; padding:12px; color:#333;
            font-size:10px; border-top:1px solid #111827;
        }
    </style>
</head>
<body>

<div class="header">
    <h1>🛡 THREATWATCH AI — AUTONOMOUS CYBER DEFENSE</h1>
    <div class="right">
        <span class="status">● LIVE</span>
        <span class="user-badge">👤 {{ username }} | {{ role }}</span>
        <a href="/logout" class="logout-btn">⛔ Logout</a>
    </div>
</div>

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
    <div class="stat-card card-score">
        <div class="number">{{ avg_score }}</div>
        <div class="label">Avg Risk Score</div>
    </div>
</div>

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
                        <span style="min-width:28px;color:
                            {% if t.risk_score >= 90 %}#ff4444
                            {% elif t.risk_score >= 70 %}#ff8800
                            {% elif t.risk_score >= 40 %}#ffcc00
                            {% else %}#00ff88{% endif %}">{{ t.risk_score }}</span>
                        <div class="bar-bg">
                            <div class="bar-fill" style="width:{{ t.risk_score }}%;background:
                                {% if t.risk_score >= 90 %}#ff4444
                                {% elif t.risk_score >= 70 %}#ff8800
                                {% elif t.risk_score >= 40 %}#ffcc00
                                {% else %}#00ff88{% endif %};">
                            </div>
                        </div>
                    </div>
                </td>
                <td>
                    {% if t.risk_score >= 90 %}<span class="badge badge-critical">CRITICAL</span>
                    {% elif t.risk_score >= 70 %}<span class="badge badge-high">HIGH</span>
                    {% elif t.risk_score >= 40 %}<span class="badge badge-medium">MEDIUM</span>
                    {% else %}<span class="badge badge-low">LOW</span>{% endif %}
                </td>
                <td>
                    {% if t.action_taken == "IP Blocked" %}
                        <span class="action-blocked">⛔ IP Blocked</span>
                    {% elif t.action_taken == "Alert Sent" %}
                        <span class="action-alert">⚠ Alert Sent</span>
                    {% else %}
                        <span style="color:#888">📋 Logged</span>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<div class="footer">
    ThreatWatch AI v1.0 — STMU BSCYS-III — Logged in as: {{ username }} ({{ role }})
    &nbsp;|&nbsp; Auto-refresh every 5 seconds
</div>
</body>
</html>
"""


# -----------------------------------------------
# ROUTES
# -----------------------------------------------

@app.route("/")
@login_required
def dashboard():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            threats = json.load(f)
    else:
        threats = []

    total     = len(threats)
    blocked   = sum(1 for t in threats if t["action_taken"] == "IP Blocked")
    alerts    = sum(1 for t in threats if t["action_taken"] == "Alert Sent")
    avg_score = round(sum(t["risk_score"] for t in threats) / total) if total > 0 else 0

    return render_template_string(
        DASHBOARD_PAGE,
        threats   = threats,
        total     = total,
        blocked   = blocked,
        alerts    = alerts,
        avg_score = avg_score,
        username  = session.get("username"),
        role      = session.get("role")
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username in USERS and check_password_hash(USERS[username]["password"], password):
            session["username"] = username
            session["role"]     = USERS[username]["role"]
            session["name"]     = USERS[username]["name"]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password. Access denied."

    return render_template_string(LOGIN_PAGE, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -----------------------------------------------
# START SERVER
# -----------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("  ThreatWatch AI - Secure Dashboard")
    print("=" * 50)
    print("\n  Open your browser and go to:")
    print("  http://127.0.0.1:5000")
    print("\n  Login credentials:")
    print("  admin    / admin123")
    print("  zaynab  / stmu2026")
    print("  zarmeen  / stmu2026")
    print("  monitor  / monitor123")
    print("\n  Press CTRL+C to stop")
    print("=" * 50)
    app.run(debug=True)