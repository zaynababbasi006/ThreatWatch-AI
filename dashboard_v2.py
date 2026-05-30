# ============================================
# ThreatWatch AI - Dashboard V2
# ============================================
# Upgraded dashboard with:
#   - IP Scanner built into the webpage
#   - Type any IP, click scan, see results
#   - Live threat feed
#   - Login system
#   - All previous features
# ============================================

from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import json
import os
import socket
import subprocess
import datetime

app = Flask(__name__)
app.secret_key = "threatwatch_ai_v2_stmu_2026"

LOG_FILE = "logs/threats.json"

# -----------------------------------------------
# USERS
# -----------------------------------------------
USERS = {
    "admin":   {"password": generate_password_hash("admin123"),  "role": "Administrator"},
    "zarmeen": {"password": generate_password_hash("stmu2026"),  "role": "Security Analyst"},
    "zaynab":  {"password": generate_password_hash("stmu2026"),  "role": "Security Analyst"},
    "monitor": {"password": generate_password_hash("monitor123"),"role": "Network Monitor"},
}

# -----------------------------------------------
# DANGEROUS PORTS
# -----------------------------------------------
DANGEROUS_PORTS = {
    21:   {"service": "FTP",        "risk": "HIGH",     "reason": "Transmits data in plaintext"},
    22:   {"service": "SSH",        "risk": "MEDIUM",   "reason": "Brute force target"},
    23:   {"service": "Telnet",     "risk": "CRITICAL", "reason": "Completely unencrypted"},
    25:   {"service": "SMTP",       "risk": "MEDIUM",   "reason": "Spam relay possible"},
    53:   {"service": "DNS",        "risk": "MEDIUM",   "reason": "Amplification attacks"},
    80:   {"service": "HTTP",       "risk": "MEDIUM",   "reason": "Unencrypted web traffic"},
    110:  {"service": "POP3",       "risk": "HIGH",     "reason": "Plaintext passwords"},
    135:  {"service": "RPC",        "risk": "HIGH",     "reason": "Commonly exploited"},
    139:  {"service": "NetBIOS",    "risk": "HIGH",     "reason": "Windows attack vector"},
    143:  {"service": "IMAP",       "risk": "MEDIUM",   "reason": "Email vulnerability"},
    443:  {"service": "HTTPS",      "risk": "LOW",      "reason": "Encrypted — generally safe"},
    445:  {"service": "SMB",        "risk": "CRITICAL", "reason": "WannaCry/EternalBlue target!"},
    1433: {"service": "MSSQL",      "risk": "HIGH",     "reason": "Database exposed"},
    3306: {"service": "MySQL",      "risk": "HIGH",     "reason": "Database exposed"},
    3389: {"service": "RDP",        "risk": "CRITICAL", "reason": "Remote Desktop — brute force target"},
    4444: {"service": "Metasploit", "risk": "CRITICAL", "reason": "Backdoor port!"},
    5900: {"service": "VNC",        "risk": "HIGH",     "reason": "Unencrypted remote desktop"},
    6666: {"service": "Malware C2", "risk": "CRITICAL", "reason": "Malware command & control"},
    8080: {"service": "HTTP Alt",   "risk": "MEDIUM",   "reason": "Check for misconfigs"},
    8081: {"service": "HTTP Alt2",  "risk": "MEDIUM",   "reason": "Alternative HTTP port"},
    8443: {"service": "HTTPS Alt",  "risk": "LOW",      "reason": "Alternative HTTPS"},
    9200: {"service": "Elasticsearch","risk":"HIGH",    "reason": "Often no authentication"},
}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def scan_ports(ip, timeout=0.5):
    ports = list(DANGEROUS_PORTS.keys())
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def calculate_risk(open_ports):
    score = 0
    for port in open_ports:
        if port in DANGEROUS_PORTS:
            risk = DANGEROUS_PORTS[port]["risk"]
            if risk == "CRITICAL": score += 25
            elif risk == "HIGH":   score += 15
            elif risk == "MEDIUM": score += 8
            else:                  score += 2
    return min(score, 100)

def get_severity(score):
    if score >= 90: return "CRITICAL"
    elif score >= 70: return "HIGH"
    elif score >= 40: return "MEDIUM"
    else: return "LOW"

# -----------------------------------------------
# HTML TEMPLATE
# -----------------------------------------------
MAIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>ThreatWatch AI v2 - Dashboard</title>
    <meta http-equiv="refresh" content="10">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { background:#0a0e1a; color:#e0e0e0; font-family:'Courier New',monospace; }

        .header {
            background:#0d1b2a; border-bottom:2px solid #00ff88;
            padding:12px 30px; display:flex; justify-content:space-between; align-items:center;
        }
        .header h1 { color:#00ff88; font-size:18px; letter-spacing:2px; }
        .header .right { display:flex; align-items:center; gap:16px; }
        .user-badge { background:#0a0e1a; border:1px solid #1a3a5c; border-radius:20px; padding:5px 14px; font-size:11px; color:#00aaff; }
        .logout-btn { background:transparent; border:1px solid #ff4444; color:#ff4444; padding:5px 14px; border-radius:20px; font-size:11px; cursor:pointer; font-family:'Courier New',monospace; text-decoration:none; }
        .status { color:#00ff88; font-size:12px; animation:blink 1.5s infinite; }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

        /* TABS */
        .tabs { display:flex; gap:0; padding:0 30px; background:#0d1b2a; border-bottom:1px solid #1a3a5c; }
        .tab { padding:12px 24px; cursor:pointer; font-size:12px; letter-spacing:1px; color:#666; border-bottom:2px solid transparent; transition:all 0.2s; }
        .tab:hover { color:#00aaff; }
        .tab.active { color:#00ff88; border-bottom:2px solid #00ff88; }

        /* TAB CONTENT */
        .tab-content { display:none; padding:20px 30px; }
        .tab-content.active { display:block; }

        /* STATS */
        .stats-row { display:flex; gap:16px; margin-bottom:20px; }
        .stat-card { flex:1; background:#0d1b2a; border:1px solid #1a3a5c; border-radius:8px; padding:16px; text-align:center; }
        .stat-card .number { font-size:32px; font-weight:bold; margin-bottom:4px; }
        .stat-card .label { font-size:10px; color:#888; letter-spacing:1px; text-transform:uppercase; }
        .card-total .number { color:#00aaff; }
        .card-blocked .number { color:#ff4444; }
        .card-alerts .number { color:#ffaa00; }
        .card-score .number { color:#00ff88; }

        /* TABLE */
        table { width:100%; border-collapse:collapse; font-size:12px; }
        th { background:#0d1b2a; color:#00aaff; padding:10px 14px; text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid #1a3a5c; }
        td { padding:9px 14px; border-bottom:1px solid #111827; }
        tr:hover td { background:#0d1b2a; }

        .badge { padding:2px 9px; border-radius:10px; font-size:10px; font-weight:bold; }
        .badge-critical { background:#3d0000; color:#ff4444; border:1px solid #ff4444; }
        .badge-high     { background:#2d1500; color:#ff8800; border:1px solid #ff8800; }
        .badge-medium   { background:#2d2500; color:#ffcc00; border:1px solid #ffcc00; }
        .badge-low      { background:#002d1a; color:#00ff88; border:1px solid #00ff88; }

        .score-bar { display:flex; align-items:center; gap:6px; }
        .bar-bg { flex:1; height:5px; background:#1a2a3a; border-radius:3px; overflow:hidden; }
        .bar-fill { height:100%; border-radius:3px; }

        /* IP SCANNER */
        .scanner-box { background:#0d1b2a; border:1px solid #1a3a5c; border-radius:10px; padding:24px; margin-bottom:20px; }
        .scanner-box h2 { color:#00aaff; font-size:13px; letter-spacing:2px; margin-bottom:16px; text-transform:uppercase; }
        .scan-input-row { display:flex; gap:12px; align-items:center; }
        .scan-input { flex:1; padding:12px 16px; background:#0a0e1a; border:1px solid #1a3a5c; border-radius:6px; color:#e0e0e0; font-family:'Courier New',monospace; font-size:13px; outline:none; }
        .scan-input:focus { border-color:#00aaff; }
        .scan-btn { padding:12px 24px; background:#00aaff; color:#0a0e1a; border:none; border-radius:6px; font-size:12px; font-weight:bold; font-family:'Courier New',monospace; letter-spacing:1px; cursor:pointer; transition:background 0.2s; white-space:nowrap; }
        .scan-btn:hover { background:#00ff88; }
        .scan-btn:disabled { background:#1a3a5c; color:#444; cursor:not-allowed; }

        /* SCAN RESULTS */
        .scan-results { margin-top:20px; display:none; }
        .result-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
        .result-ip { font-size:18px; color:#00aaff; font-weight:bold; }
        .result-score { font-size:28px; font-weight:bold; }
        .info-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:16px; }
        .info-card { background:#0a0e1a; border:1px solid #1a3a5c; border-radius:6px; padding:12px; text-align:center; }
        .info-card .val { font-size:18px; font-weight:bold; color:#00aaff; margin-bottom:4px; }
        .info-card .lbl { font-size:10px; color:#666; text-transform:uppercase; }
        .ports-table { width:100%; border-collapse:collapse; font-size:12px; }
        .ports-table th { background:#0a0e1a; color:#00aaff; padding:8px 12px; text-align:left; font-size:10px; text-transform:uppercase; border-bottom:1px solid #1a3a5c; }
        .ports-table td { padding:8px 12px; border-bottom:1px solid #111827; }
        .risk-critical { color:#ff4444; font-weight:bold; }
        .risk-high     { color:#ff8800; font-weight:bold; }
        .risk-medium   { color:#ffcc00; }
        .risk-low      { color:#00ff88; }
        .recommendations { background:#0a0e1a; border:1px solid #1a3a5c; border-radius:6px; padding:14px; margin-top:14px; }
        .recommendations h4 { color:#00aaff; font-size:11px; letter-spacing:1px; margin-bottom:10px; text-transform:uppercase; }
        .rec-item { font-size:12px; color:#aaa; margin-bottom:6px; line-height:1.6; }
        .loading { text-align:center; padding:30px; color:#00aaff; font-size:13px; display:none; }
        .spinner { animation:spin 1s linear infinite; display:inline-block; font-size:20px; }
        @keyframes spin { 100%{transform:rotate(360deg)} }

        .section-title { color:#00aaff; font-size:13px; letter-spacing:2px; margin-bottom:12px; text-transform:uppercase; }
        .action-blocked { color:#ff4444; font-weight:bold; }
        .action-alert { color:#ffaa00; font-weight:bold; }
        .footer { text-align:center; padding:12px; color:#333; font-size:10px; border-top:1px solid #111827; margin-top:20px; }
    </style>
</head>
<body>

<!-- HEADER -->
<div class="header">
    <h1>🛡 THREATWATCH AI v2 — AUTONOMOUS CYBER DEFENSE</h1>
    <div class="right">
        <span class="status">● LIVE</span>
        <span class="user-badge">👤 {{ username }} | {{ role }}</span>
        <a href="/logout" class="logout-btn">⛔ Logout</a>
    </div>
</div>

<!-- TABS -->
<div class="tabs">
    <div class="tab active" onclick="showTab('dashboard')">📊 Dashboard</div>
    <div class="tab" onclick="showTab('scanner')">🔍 IP Scanner</div>
    <div class="tab" onclick="showTab('threats')">⚡ Threat Feed</div>
</div>

<!-- TAB 1: DASHBOARD -->
<div id="tab-dashboard" class="tab-content active">
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

    <div class="section-title">⚡ Recent Threats</div>
    <table>
        <thead>
            <tr><th>#</th><th>Timestamp</th><th>IP Address</th><th>Threat Type</th><th>Risk Score</th><th>Severity</th><th>Action</th></tr>
        </thead>
        <tbody>
            {% for t in threats[-10:]|reverse %}
            <tr>
                <td style="color:#444">{{ loop.index }}</td>
                <td style="color:#666">{{ t.timestamp }}</td>
                <td style="color:#00aaff">{{ t.ip_address }}</td>
                <td>{{ t.threat_type }}</td>
                <td>
                    <div class="score-bar">
                        <span style="min-width:28px;color:{% if t.risk_score>=90%}#ff4444{% elif t.risk_score>=70%}#ff8800{% elif t.risk_score>=40%}#ffcc00{% else %}#00ff88{% endif %}">{{ t.risk_score }}</span>
                        <div class="bar-bg"><div class="bar-fill" style="width:{{ t.risk_score }}%;background:{% if t.risk_score>=90%}#ff4444{% elif t.risk_score>=70%}#ff8800{% elif t.risk_score>=40%}#ffcc00{% else %}#00ff88{% endif %};"></div></div>
                    </div>
                </td>
                <td>
                    {% if t.risk_score>=90%}<span class="badge badge-critical">CRITICAL</span>
                    {% elif t.risk_score>=70%}<span class="badge badge-high">HIGH</span>
                    {% elif t.risk_score>=40%}<span class="badge badge-medium">MEDIUM</span>
                    {% else %}<span class="badge badge-low">LOW</span>{% endif %}
                </td>
                <td>
                    {% if t.action_taken=="IP Blocked" %}<span class="action-blocked">⛔ Blocked</span>
                    {% elif t.action_taken=="Alert Sent" %}<span class="action-alert">⚠ Alert</span>
                    {% else %}<span style="color:#888">📋 Logged</span>{% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<!-- TAB 2: IP SCANNER -->
<div id="tab-scanner" class="tab-content">
    <div class="scanner-box">
        <h2>🔍 Network IP Scanner</h2>
        <p style="color:#666;font-size:12px;margin-bottom:16px;">Enter any IP address to scan for open ports, vulnerabilities and security risks.</p>
        <div class="scan-input-row">
            <input type="text" id="scan-ip" class="scan-input" placeholder="Enter IP address e.g. 192.168.221.129" value="">
            <button class="scan-btn" id="scan-btn" onclick="startScan()">🔍 SCAN IP</button>
        </div>
        <div style="display:flex;gap:10px;margin-top:12px;flex-wrap:wrap;">
            <button onclick="quickScan('192.168.221.129')" style="padding:6px 14px;background:#0a0e1a;border:1px solid #1a3a5c;color:#00aaff;border-radius:4px;cursor:pointer;font-size:11px;font-family:'Courier New',monospace;">OWASP BWA</button>
            <button onclick="quickScan('192.168.221.128')" style="padding:6px 14px;background:#0a0e1a;border:1px solid #1a3a5c;color:#00aaff;border-radius:4px;cursor:pointer;font-size:11px;font-family:'Courier New',monospace;">Kali Linux</button>
            <button onclick="quickScan('127.0.0.1')" style="padding:6px 14px;background:#0a0e1a;border:1px solid #1a3a5c;color:#00aaff;border-radius:4px;cursor:pointer;font-size:11px;font-family:'Courier New',monospace;">Localhost</button>
        </div>
    </div>

    <div class="loading" id="loading">
        <div class="spinner">⟳</div>
        <div style="margin-top:10px">Scanning IP... checking ports... analyzing vulnerabilities...</div>
    </div>

    <div class="scan-results" id="scan-results"></div>
</div>

<!-- TAB 3: FULL THREAT FEED -->
<div id="tab-threats" class="tab-content">
    <div class="section-title">⚡ Full Threat Log ({{ total }} events)</div>
    <table>
        <thead>
            <tr><th>#</th><th>Timestamp</th><th>IP Address</th><th>Threat Type</th><th>Risk Score</th><th>Severity</th><th>Action</th></tr>
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
                        <span style="min-width:28px;color:{% if t.risk_score>=90%}#ff4444{% elif t.risk_score>=70%}#ff8800{% elif t.risk_score>=40%}#ffcc00{% else %}#00ff88{% endif %}">{{ t.risk_score }}</span>
                        <div class="bar-bg"><div class="bar-fill" style="width:{{ t.risk_score }}%;background:{% if t.risk_score>=90%}#ff4444{% elif t.risk_score>=70%}#ff8800{% elif t.risk_score>=40%}#ffcc00{% else %}#00ff88{% endif %};"></div></div>
                    </div>
                </td>
                <td>
                    {% if t.risk_score>=90%}<span class="badge badge-critical">CRITICAL</span>
                    {% elif t.risk_score>=70%}<span class="badge badge-high">HIGH</span>
                    {% elif t.risk_score>=40%}<span class="badge badge-medium">MEDIUM</span>
                    {% else %}<span class="badge badge-low">LOW</span>{% endif %}
                </td>
                <td>
                    {% if t.action_taken=="IP Blocked" %}<span class="action-blocked">⛔ Blocked</span>
                    {% elif t.action_taken=="Alert Sent" %}<span class="action-alert">⚠ Alert</span>
                    {% else %}<span style="color:#888">📋 Logged</span>{% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<div class="footer">
    ThreatWatch AI v2.0 — STMU BSCYS-III — Zarmeen Zawar Ghauri & Zaynab Amjad Abbasi | CS2141 AI
</div>

<script>
// Tab switching
function showTab(name) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    event.target.classList.add('active');
}

function quickScan(ip) {
    document.getElementById('scan-ip').value = ip;
    startScan();
}

// IP Scanner
function startScan() {
    const ip  = document.getElementById('scan-ip').value.trim();
    const btn = document.getElementById('scan-btn');

    if (!ip) { alert('Please enter an IP address!'); return; }

    btn.disabled   = true;
    btn.textContent= '⟳ Scanning...';
    document.getElementById('loading').style.display     = 'block';
    document.getElementById('scan-results').style.display= 'none';

    fetch('/scan', {
        method:  'POST',
        headers: {'Content-Type': 'application/json'},
        body:    JSON.stringify({ip: ip})
    })
    .then(r => r.json())
    .then(data => {
        btn.disabled   = false;
        btn.textContent= '🔍 SCAN IP';
        document.getElementById('loading').style.display = 'none';
        showResults(data);
    })
    .catch(err => {
        btn.disabled   = false;
        btn.textContent= '🔍 SCAN IP';
        document.getElementById('loading').style.display = 'none';
        alert('Scan failed: ' + err);
    });
}

function getRiskColor(risk) {
    if (risk === 'CRITICAL') return '#ff4444';
    if (risk === 'HIGH')     return '#ff8800';
    if (risk === 'MEDIUM')   return '#ffcc00';
    return '#00ff88';
}

function getScoreColor(score) {
    if (score >= 90) return '#ff4444';
    if (score >= 70) return '#ff8800';
    if (score >= 40) return '#ffcc00';
    return '#00ff88';
}

function showResults(data) {
    const div    = document.getElementById('scan-results');
    const color  = getScoreColor(data.risk_score);
    const ports  = data.open_ports || [];

    let portsHtml = '';
    if (ports.length > 0) {
        portsHtml = `
        <div class="section-title" style="margin-top:16px">Open Ports & Services</div>
        <table class="ports-table">
            <thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Details</th></tr></thead>
            <tbody>
                ${ports.map(p => {
                    const info  = data.port_info[p] || {service:'Unknown', risk:'LOW', reason:'Unknown'};
                    const rcolor= getRiskColor(info.risk);
                    return `<tr>
                        <td style="color:#00aaff;font-weight:bold">${p}</td>
                        <td>${info.service}</td>
                        <td style="color:${rcolor};font-weight:bold">${info.risk}</td>
                        <td style="color:#888">${info.reason}</td>
                    </tr>`;
                }).join('')}
            </tbody>
        </table>`;
    } else {
        portsHtml = '<div style="color:#00ff88;padding:12px;font-size:13px">✅ No dangerous open ports found</div>';
    }

    let recHtml = '';
    if (data.risk_score >= 70) {
        recHtml = `<div class="rec-item">🚨 HIGH RISK — Immediate action required!</div>
                   <div class="rec-item">• Close or firewall all non-essential ports immediately</div>
                   <div class="rec-item">• Check for unauthorized access or compromise</div>
                   <div class="rec-item">• Run full penetration test on this target</div>`;
    } else if (data.risk_score >= 40) {
        recHtml = `<div class="rec-item">⚠ MEDIUM RISK — Review open services</div>
                   <div class="rec-item">• Ensure all services are patched and updated</div>
                   <div class="rec-item">• Consider closing unused ports</div>`;
    } else {
        recHtml = `<div class="rec-item">✅ LOW RISK — Network looks relatively secure</div>
                   <div class="rec-item">• Continue regular monitoring</div>`;
    }

    div.innerHTML = `
        <div class="result-header">
            <div>
                <div class="result-ip">📡 ${data.ip}</div>
                <div style="color:#666;font-size:11px;margin-top:4px">Hostname: ${data.hostname} | Scanned: ${data.scanned_at}</div>
            </div>
            <div style="text-align:right">
                <div class="result-score" style="color:${color}">${data.risk_score}/100</div>
                <div style="color:${color};font-size:11px;letter-spacing:1px">${data.severity}</div>
            </div>
        </div>
        <div class="info-grid">
            <div class="info-card">
                <div class="val" style="color:${data.is_alive ? '#00ff88' : '#ff4444'}">${data.is_alive ? 'ONLINE' : 'OFFLINE'}</div>
                <div class="lbl">Host Status</div>
            </div>
            <div class="info-card">
                <div class="val">${ports.length}</div>
                <div class="lbl">Open Ports</div>
            </div>
            <div class="info-card">
                <div class="val" style="color:${color}">${data.risk_score}</div>
                <div class="lbl">Risk Score</div>
            </div>
            <div class="info-card">
                <div class="val" style="color:${color}">${data.severity}</div>
                <div class="lbl">Severity</div>
            </div>
        </div>
        ${portsHtml}
        <div class="recommendations">
            <h4>Recommendations</h4>
            ${recHtml}
        </div>
    `;
    div.style.display = 'block';
}
</script>
</body>
</html>
"""

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>ThreatWatch AI — Login</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { background:#0a0e1a; font-family:'Courier New',monospace; display:flex; justify-content:center; align-items:center; min-height:100vh; }
        .login-box { background:#0d1b2a; border:1px solid #1a3a5c; border-radius:12px; padding:40px; width:380px; text-align:center; }
        .logo { font-size:40px; margin-bottom:10px; }
        h1 { color:#00ff88; font-size:18px; letter-spacing:2px; margin-bottom:6px; }
        .subtitle { color:#666; font-size:11px; letter-spacing:1px; margin-bottom:30px; }
        .form-group { margin-bottom:16px; text-align:left; }
        label { display:block; color:#00aaff; font-size:11px; letter-spacing:1px; margin-bottom:6px; text-transform:uppercase; }
        input { width:100%; padding:12px 14px; background:#0a0e1a; border:1px solid #1a3a5c; border-radius:6px; color:#e0e0e0; font-family:'Courier New',monospace; font-size:13px; outline:none; }
        input:focus { border-color:#00aaff; }
        .btn-login { width:100%; padding:12px; background:#00aaff; color:#0a0e1a; border:none; border-radius:6px; font-size:13px; font-weight:bold; font-family:'Courier New',monospace; letter-spacing:2px; cursor:pointer; margin-top:10px; }
        .btn-login:hover { background:#00ff88; }
        .error { background:#3d0000; border:1px solid #ff4444; color:#ff4444; padding:10px; border-radius:6px; font-size:12px; margin-bottom:16px; }
        .footer { color:#333; font-size:10px; margin-top:24px; }
        hr { border:none; border-top:1px solid #1a3a5c; margin:24px 0; }
        .hint { color:#444; font-size:10px; margin-top:16px; }
    </style>
</head>
<body>
<div class="login-box">
    <div class="logo">🛡</div>
    <h1>THREATWATCH AI</h1>
    <div class="subtitle">AUTONOMOUS CYBER DEFENSE SYSTEM v2.0</div>
    {% if error %}<div class="error">⛔ {{ error }}</div>{% endif %}
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
    <hr>
    <div class="hint">admin / admin123 &nbsp;|&nbsp; zaynab / stmu2026</div>
    <div class="footer">STMU BSCYS-III | CS2141 Artificial Intelligence | 2026</div>
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
    threats = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            threats = json.load(f)
    total     = len(threats)
    blocked   = sum(1 for t in threats if t["action_taken"] == "IP Blocked")
    alerts    = sum(1 for t in threats if t["action_taken"] == "Alert Sent")
    avg_score = round(sum(t["risk_score"] for t in threats) / total) if total > 0 else 0
    return render_template_string(MAIN_PAGE, threats=threats, total=total,
                                  blocked=blocked, alerts=alerts, avg_score=avg_score,
                                  username=session.get("username"), role=session.get("role"))

@app.route("/scan", methods=["POST"])
@login_required
def scan():
    data = request.get_json()
    ip   = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "No IP provided"}), 400

    # Get hostname
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        hostname = "Unknown"

    # Ping check
    try:
        result   = subprocess.run(["ping", "-n", "1", "-w", "1000", ip],
                                   capture_output=True, text=True, timeout=5)
        is_alive = "TTL=" in result.stdout
    except:
        is_alive = False

    # Scan ports
    open_ports = scan_ports(ip)

    # Calculate risk
    risk_score = calculate_risk(open_ports)
    severity   = get_severity(risk_score)

    # Build port info
    port_info = {}
    for port in open_ports:
        if port in DANGEROUS_PORTS:
            port_info[port] = DANGEROUS_PORTS[port]
        else:
            port_info[port] = {"service": "Unknown", "risk": "LOW", "reason": "Unknown service"}

    return jsonify({
        "ip":         ip,
        "hostname":   hostname,
        "is_alive":   is_alive,
        "open_ports": open_ports,
        "port_info":  port_info,
        "risk_score": risk_score,
        "severity":   severity,
        "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            session["username"] = username
            session["role"]     = USERS[username]["role"]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."
    return render_template_string(LOGIN_PAGE, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# -----------------------------------------------
# START
# -----------------------------------------------
if __name__ == "__main__":
    print("="*50)
    print("  ThreatWatch AI v2 - Secure Dashboard")
    print("="*50)
    print("\n  Open: http://127.0.0.1:5000")
    print("  Login: admin / admin123")
    print("\n  New features:")
    print("  → IP Scanner tab (scan any IP!)")
    print("  → Full threat feed tab")
    print("  → Quick scan buttons")
    print("="*50)
    app.run(debug=True)