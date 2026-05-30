# ============================================
# ThreatWatch AI - Security Portal
# ============================================
# Public security tool where ANYONE can:
#   1. Scan any IP for vulnerabilities
#   2. Upload code/project and find security issues
# ============================================

from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import json, os, socket, subprocess, datetime, zipfile, re

app = Flask(__name__)
app.secret_key = "threatwatch_portal_stmu_2026"
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 16MB max upload

LOG_FILE    = "logs/threats.json"
UPLOAD_DIR  = "data/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# -----------------------------------------------
# USERS
# -----------------------------------------------
USERS = {
    "admin":   {"password": generate_password_hash("admin123"),  "role": "Administrator"},
    "zarmeen": {"password": generate_password_hash("stmu2026"),  "role": "Security Analyst"},
    "zaynab":  {"password": generate_password_hash("stmu2026"),  "role": "Security Analyst"},
}

# -----------------------------------------------
# DANGEROUS PORTS
# -----------------------------------------------
DANGEROUS_PORTS = {
    21:   {"service": "FTP",         "risk": "HIGH",     "reason": "Transmits data in plaintext"},
    22:   {"service": "SSH",         "risk": "MEDIUM",   "reason": "Brute force target"},
    23:   {"service": "Telnet",      "risk": "CRITICAL", "reason": "Completely unencrypted"},
    25:   {"service": "SMTP",        "risk": "MEDIUM",   "reason": "Spam relay possible"},
    80:   {"service": "HTTP",        "risk": "MEDIUM",   "reason": "Unencrypted web traffic"},
    135:  {"service": "RPC",         "risk": "HIGH",     "reason": "Commonly exploited"},
    139:  {"service": "NetBIOS",     "risk": "HIGH",     "reason": "Windows attack vector"},
    443:  {"service": "HTTPS",       "risk": "LOW",      "reason": "Encrypted — generally safe"},
    445:  {"service": "SMB",         "risk": "CRITICAL", "reason": "WannaCry/EternalBlue target!"},
    1433: {"service": "MSSQL",       "risk": "HIGH",     "reason": "Database exposed"},
    3306: {"service": "MySQL",       "risk": "HIGH",     "reason": "Database exposed"},
    3389: {"service": "RDP",         "risk": "CRITICAL", "reason": "Remote Desktop brute force target"},
    4444: {"service": "Metasploit",  "risk": "CRITICAL", "reason": "Backdoor port!"},
    5900: {"service": "VNC",         "risk": "HIGH",     "reason": "Unencrypted remote desktop"},
    6666: {"service": "Malware C2",  "risk": "CRITICAL", "reason": "Malware command & control"},
    8080: {"service": "HTTP Alt",    "risk": "MEDIUM",   "reason": "Check for misconfigs"},
    8443: {"service": "HTTPS Alt",   "risk": "LOW",      "reason": "Alternative HTTPS"},
    27017:{"service": "MongoDB",     "risk": "CRITICAL", "reason": "Often no authentication!"},
}

# -----------------------------------------------
# CODE VULNERABILITY PATTERNS
# -----------------------------------------------
VULN_PATTERNS = [
    # SQL Injection
    {"id": "SQL-01", "name": "SQL Injection",        "severity": "CRITICAL",
     "pattern": r'(SELECT|INSERT|UPDATE|DELETE).*\+.*input|query\s*\+|execute\s*\(',
     "desc": "Direct SQL query construction with user input — SQL injection possible"},
    {"id": "SQL-02", "name": "Raw SQL Query",         "severity": "HIGH",
     "pattern": r'cursor\.execute\s*\(\s*["\'].*%s|f["\'].*SELECT|f["\'].*INSERT',
     "desc": "Unparameterized SQL query detected"},

    # Hardcoded secrets
    {"id": "SEC-01", "name": "Hardcoded Password",   "severity": "CRITICAL",
     "pattern": r'password\s*=\s*["\'][^"\']{3,}["\']|passwd\s*=\s*["\']|pwd\s*=\s*["\']',
     "desc": "Hardcoded password found in source code"},
    {"id": "SEC-02", "name": "Hardcoded API Key",    "severity": "CRITICAL",
     "pattern": r'api_key\s*=\s*["\'][^"\']{8,}["\']|secret_key\s*=\s*["\']|token\s*=\s*["\'][^"\']{8,}',
     "desc": "Hardcoded API key or secret token found"},
    {"id": "SEC-03", "name": "Hardcoded IP Address", "severity": "MEDIUM",
     "pattern": r'["\'](\d{1,3}\.){3}\d{1,3}["\']',
     "desc": "Hardcoded IP address found — use config files instead"},

    # Dangerous functions
    {"id": "CMD-01", "name": "Command Injection",    "severity": "CRITICAL",
     "pattern": r'os\.system\s*\(|subprocess\.call\s*\(.*shell\s*=\s*True|eval\s*\(',
     "desc": "Dangerous system command execution with potential injection"},
    {"id": "CMD-02", "name": "Unsafe eval()",        "severity": "HIGH",
     "pattern": r'\beval\s*\(|exec\s*\(',
     "desc": "eval() or exec() can execute arbitrary code"},

    # Weak crypto
    {"id": "CRY-01", "name": "Weak Hashing (MD5)",  "severity": "HIGH",
     "pattern": r'hashlib\.md5|md5\s*\(',
     "desc": "MD5 is cryptographically broken — use SHA256 or bcrypt"},
    {"id": "CRY-02", "name": "Weak Hashing (SHA1)", "severity": "MEDIUM",
     "pattern": r'hashlib\.sha1|sha1\s*\(',
     "desc": "SHA1 is deprecated — use SHA256 or stronger"},
    {"id": "CRY-03", "name": "No Encryption",       "severity": "MEDIUM",
     "pattern": r'http://(?!localhost|127\.0\.0\.1)',
     "desc": "HTTP used instead of HTTPS — data transmitted unencrypted"},

    # Input validation
    {"id": "INP-01", "name": "No Input Validation",  "severity": "HIGH",
     "pattern": r'request\.args\.get\(|request\.form\.get\(|input\s*\(',
     "desc": "User input used without validation — sanitize all inputs"},
    {"id": "INP-02", "name": "XSS Vulnerability",   "severity": "HIGH",
     "pattern": r'innerHTML\s*=|document\.write\s*\(|\.html\s*\(',
     "desc": "Potential XSS — user data inserted directly into HTML"},

    # File security
    {"id": "FIL-01", "name": "Path Traversal",      "severity": "CRITICAL",
     "pattern": r'open\s*\(.*\+|open\s*\(.*input|open\s*\(.*request',
     "desc": "File path constructed from user input — path traversal possible"},
    {"id": "FIL-02", "name": "Unsafe File Upload",  "severity": "HIGH",
     "pattern": r'\.filename|save\s*\(|upload',
     "desc": "File upload without type validation detected"},

    # Debug/info leaks
    {"id": "DBG-01", "name": "Debug Mode On",        "severity": "MEDIUM",
     "pattern": r'debug\s*=\s*True|DEBUG\s*=\s*True',
     "desc": "Debug mode enabled — exposes stack traces in production"},
    {"id": "DBG-02", "name": "Sensitive Print",      "severity": "LOW",
     "pattern": r'print\s*\(.*password|print\s*\(.*token|print\s*\(.*secret',
     "desc": "Sensitive data being printed to console"},
]


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# -----------------------------------------------
# IP SCANNER FUNCTIONS
# -----------------------------------------------
def scan_ports(ip, timeout=0.5):
    open_ports = []
    for port in DANGEROUS_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

def get_hostname(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return "Unknown"

def calc_network_risk(open_ports):
    score = 0
    for p in open_ports:
        if p in DANGEROUS_PORTS:
            r = DANGEROUS_PORTS[p]["risk"]
            if r == "CRITICAL": score += 25
            elif r == "HIGH":   score += 15
            elif r == "MEDIUM": score += 8
            else:               score += 2
    return min(score, 100)

def get_severity(score):
    if score >= 90: return "CRITICAL"
    elif score >= 70: return "HIGH"
    elif score >= 40: return "MEDIUM"
    else: return "LOW"


# -----------------------------------------------
# CODE SCANNER FUNCTIONS
# -----------------------------------------------
def scan_code(content, filename=""):
    """Scan code content for security vulnerabilities."""
    findings = []
    lines    = content.split('\n')

    for vuln in VULN_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(vuln["pattern"], line, re.IGNORECASE):
                findings.append({
                    "id":       vuln["id"],
                    "name":     vuln["name"],
                    "severity": vuln["severity"],
                    "desc":     vuln["desc"],
                    "line":     i,
                    "code":     line.strip()[:80],
                    "file":     filename
                })

    return findings

def scan_zip_file(filepath):
    """Extract and scan all code files in a zip."""
    all_findings = []
    files_scanned = []

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            for name in zf.namelist():
                # Only scan code files
                ext = os.path.splitext(name)[1].lower()
                if ext in ['.py', '.js', '.php', '.java', '.html', '.css', '.txt', '.env', '.cfg', '.ini']:
                    try:
                        content = zf.read(name).decode('utf-8', errors='ignore')
                        findings = scan_code(content, name)
                        all_findings.extend(findings)
                        files_scanned.append(name)
                    except:
                        pass
    except Exception as e:
        return [], [], str(e)

    return all_findings, files_scanned, None

def calc_code_risk(findings):
    score = 0
    for f in findings:
        if f["severity"] == "CRITICAL": score += 25
        elif f["severity"] == "HIGH":   score += 15
        elif f["severity"] == "MEDIUM": score += 8
        else:                           score += 3
    return min(score, 100)


# -----------------------------------------------
# HTML TEMPLATE
# -----------------------------------------------
PORTAL_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>ThreatWatch AI — Security Portal</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { background:#0a0e1a; color:#e0e0e0; font-family:'Courier New',monospace; }

        .header { background:#0d1b2a; border-bottom:2px solid #00ff88; padding:14px 30px; display:flex; justify-content:space-between; align-items:center; }
        .header h1 { color:#00ff88; font-size:17px; letter-spacing:2px; }
        .header .right { display:flex; align-items:center; gap:14px; }
        .user-badge { background:#0a0e1a; border:1px solid #1a3a5c; border-radius:20px; padding:5px 14px; font-size:11px; color:#00aaff; }
        .logout-btn { background:transparent; border:1px solid #ff4444; color:#ff4444; padding:5px 14px; border-radius:20px; font-size:11px; cursor:pointer; text-decoration:none; font-family:'Courier New',monospace; }
        .status { color:#00ff88; font-size:12px; animation:blink 1.5s infinite; }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

        .tabs { display:flex; background:#0d1b2a; border-bottom:1px solid #1a3a5c; padding:0 30px; }
        .tab { padding:13px 24px; cursor:pointer; font-size:12px; letter-spacing:1px; color:#666; border-bottom:2px solid transparent; transition:all 0.2s; }
        .tab:hover { color:#00aaff; }
        .tab.active { color:#00ff88; border-bottom:2px solid #00ff88; }

        .content { padding:24px 30px; }
        .tab-pane { display:none; }
        .tab-pane.active { display:block; }

        /* STATS */
        .stats-row { display:flex; gap:16px; margin-bottom:24px; }
        .stat-card { flex:1; background:#0d1b2a; border:1px solid #1a3a5c; border-radius:8px; padding:16px; text-align:center; }
        .stat-card .num { font-size:30px; font-weight:bold; margin-bottom:4px; }
        .stat-card .lbl { font-size:10px; color:#888; text-transform:uppercase; letter-spacing:1px; }

        /* CARDS */
        .card { background:#0d1b2a; border:1px solid #1a3a5c; border-radius:10px; padding:22px; margin-bottom:20px; }
        .card h2 { color:#00aaff; font-size:13px; letter-spacing:2px; text-transform:uppercase; margin-bottom:6px; }
        .card p { color:#666; font-size:12px; margin-bottom:18px; line-height:1.6; }

        /* INPUTS */
        .input-row { display:flex; gap:12px; }
        .big-input { flex:1; padding:13px 16px; background:#0a0e1a; border:1px solid #1a3a5c; border-radius:6px; color:#e0e0e0; font-family:'Courier New',monospace; font-size:13px; outline:none; transition:border-color 0.2s; }
        .big-input:focus { border-color:#00aaff; }
        .btn { padding:13px 22px; border:none; border-radius:6px; font-size:12px; font-weight:bold; font-family:'Courier New',monospace; letter-spacing:1px; cursor:pointer; transition:all 0.2s; white-space:nowrap; }
        .btn-blue  { background:#00aaff; color:#0a0e1a; }
        .btn-blue:hover  { background:#00ff88; }
        .btn-green { background:#00ff88; color:#0a0e1a; }
        .btn-green:hover { background:#00aaff; }
        .btn:disabled { background:#1a3a5c; color:#444; cursor:not-allowed; }

        .quick-btns { display:flex; gap:8px; margin-top:10px; flex-wrap:wrap; }
        .quick-btn { padding:6px 14px; background:#0a0e1a; border:1px solid #1a3a5c; color:#00aaff; border-radius:4px; cursor:pointer; font-size:11px; font-family:'Courier New',monospace; }
        .quick-btn:hover { border-color:#00aaff; }

        /* UPLOAD */
        .upload-area { border:2px dashed #1a3a5c; border-radius:8px; padding:30px; text-align:center; cursor:pointer; transition:border-color 0.2s; margin-bottom:16px; }
        .upload-area:hover { border-color:#00aaff; }
        .upload-area input { display:none; }
        .upload-icon { font-size:36px; margin-bottom:10px; }
        .upload-text { color:#666; font-size:13px; }
        .upload-hint { color:#444; font-size:11px; margin-top:6px; }

        /* RESULTS */
        .result-box { margin-top:20px; display:none; }
        .result-header { display:flex; justify-content:space-between; align-items:center; background:#0d1b2a; border:1px solid #1a3a5c; border-radius:8px; padding:16px 20px; margin-bottom:14px; }
        .result-ip { font-size:16px; color:#00aaff; font-weight:bold; }
        .result-meta { color:#666; font-size:11px; margin-top:4px; }
        .big-score { font-size:36px; font-weight:bold; }
        .severity-label { font-size:11px; letter-spacing:2px; text-align:right; }

        .info-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:16px; }
        .info-tile { background:#0d1b2a; border:1px solid #1a3a5c; border-radius:6px; padding:12px; text-align:center; }
        .info-tile .v { font-size:20px; font-weight:bold; margin-bottom:4px; }
        .info-tile .l { font-size:10px; color:#666; text-transform:uppercase; }

        /* PORTS TABLE */
        .result-table { width:100%; border-collapse:collapse; font-size:12px; margin-bottom:14px; }
        .result-table th { background:#0a0e1a; color:#00aaff; padding:9px 14px; text-align:left; font-size:10px; text-transform:uppercase; border-bottom:1px solid #1a3a5c; }
        .result-table td { padding:9px 14px; border-bottom:1px solid #111827; }
        .result-table tr:hover td { background:#0d1b2a; }

        /* VULN CARDS */
        .vuln-card { border-radius:6px; padding:12px 14px; margin-bottom:8px; border-left:3px solid; }
        .vuln-critical { background:#1a0000; border-color:#ff4444; }
        .vuln-high     { background:#1a0d00; border-color:#ff8800; }
        .vuln-medium   { background:#1a1700; border-color:#ffcc00; }
        .vuln-low      { background:#001a0d; border-color:#00ff88; }
        .vuln-header   { display:flex; justify-content:space-between; align-items:center; margin-bottom:4px; }
        .vuln-name     { font-size:13px; font-weight:bold; }
        .vuln-id       { font-size:10px; color:#666; }
        .vuln-desc     { font-size:12px; color:#aaa; margin-bottom:6px; }
        .vuln-code     { font-size:11px; background:#0a0e1a; padding:6px 10px; border-radius:4px; color:#00aaff; font-family:'Courier New',monospace; }
        .vuln-location { font-size:10px; color:#666; margin-top:4px; }

        .rec-box { background:#0a0e1a; border:1px solid #1a3a5c; border-radius:6px; padding:14px; margin-top:14px; }
        .rec-box h4 { color:#00aaff; font-size:11px; letter-spacing:1px; text-transform:uppercase; margin-bottom:10px; }
        .rec-item { font-size:12px; color:#aaa; margin-bottom:6px; line-height:1.6; }

        /* THREAT TABLE */
        .threat-table { width:100%; border-collapse:collapse; font-size:12px; }
        .threat-table th { background:#0d1b2a; color:#00aaff; padding:10px 14px; text-align:left; font-size:10px; text-transform:uppercase; border-bottom:1px solid #1a3a5c; }
        .threat-table td { padding:9px 14px; border-bottom:1px solid #111827; }
        .badge { padding:2px 9px; border-radius:10px; font-size:10px; font-weight:bold; }
        .badge-critical { background:#3d0000; color:#ff4444; border:1px solid #ff4444; }
        .badge-high     { background:#2d1500; color:#ff8800; border:1px solid #ff8800; }
        .badge-medium   { background:#2d2500; color:#ffcc00; border:1px solid #ffcc00; }
        .badge-low      { background:#002d1a; color:#00ff88; border:1px solid #00ff88; }
        .score-bar { display:flex; align-items:center; gap:6px; }
        .bar-bg { flex:1; height:5px; background:#1a2a3a; border-radius:3px; overflow:hidden; }
        .bar-fill { height:100%; border-radius:3px; }

        .loading { text-align:center; padding:30px; display:none; }
        .spinner { font-size:24px; animation:spin 1s linear infinite; display:inline-block; }
        @keyframes spin { 100%{transform:rotate(360deg)} }
        .loading-text { color:#00aaff; font-size:13px; margin-top:10px; }

        .section-title { color:#00aaff; font-size:12px; letter-spacing:2px; text-transform:uppercase; margin-bottom:12px; }
        .footer { text-align:center; padding:14px; color:#333; font-size:10px; border-top:1px solid #111827; margin-top:10px; }
        .no-data { color:#444; font-size:13px; text-align:center; padding:30px; }
    </style>
</head>
<body>

<!-- HEADER -->
<div class="header">
    <h1>🛡 THREATWATCH AI — SECURITY PORTAL</h1>
    <div class="right">
        <span class="status">● LIVE</span>
        <span class="user-badge">👤 {{ username }} | {{ role }}</span>
        <a href="/logout" class="logout-btn">⛔ Logout</a>
    </div>
</div>

<!-- TABS -->
<div class="tabs">
    <div class="tab active"   onclick="showTab('dashboard', this)">📊 Dashboard</div>
    <div class="tab"          onclick="showTab('ipscanner', this)">🔍 IP Scanner</div>
    <div class="tab"          onclick="showTab('codescanner', this)">🧬 Code Scanner</div>
    <div class="tab"          onclick="showTab('threats', this)">⚡ Threat Log</div>
</div>

<div class="content">

<!-- TAB: DASHBOARD -->
<div id="tab-dashboard" class="tab-pane active">
    <div class="stats-row">
        <div class="stat-card"><div class="num" style="color:#00aaff">{{ total }}</div><div class="lbl">Total Threats</div></div>
        <div class="stat-card"><div class="num" style="color:#ff4444">{{ blocked }}</div><div class="lbl">IPs Blocked</div></div>
        <div class="stat-card"><div class="num" style="color:#ffaa00">{{ alerts }}</div><div class="lbl">Alerts Sent</div></div>
        <div class="stat-card"><div class="num" style="color:#00ff88">{{ avg_score }}</div><div class="lbl">Avg Risk Score</div></div>
    </div>
    <div class="section-title">⚡ Recent Threats</div>
    <table class="threat-table">
        <thead><tr><th>#</th><th>Timestamp</th><th>IP Address</th><th>Threat Type</th><th>Score</th><th>Severity</th><th>Action</th></tr></thead>
        <tbody>
        {% for t in threats[-15:]|reverse %}
        <tr>
            <td style="color:#444">{{ loop.index }}</td>
            <td style="color:#666">{{ t.timestamp }}</td>
            <td style="color:#00aaff">{{ t.ip_address }}</td>
            <td>{{ t.threat_type }}</td>
            <td><div class="score-bar"><span style="min-width:28px;color:{% if t.risk_score>=90%}#ff4444{% elif t.risk_score>=70%}#ff8800{% elif t.risk_score>=40%}#ffcc00{% else %}#00ff88{% endif %}">{{ t.risk_score }}</span><div class="bar-bg"><div class="bar-fill" style="width:{{ t.risk_score }}%;background:{% if t.risk_score>=90%}#ff4444{% elif t.risk_score>=70%}#ff8800{% elif t.risk_score>=40%}#ffcc00{% else %}#00ff88{% endif %};"></div></div></div></td>
            <td>{% if t.risk_score>=90%}<span class="badge badge-critical">CRITICAL</span>{% elif t.risk_score>=70%}<span class="badge badge-high">HIGH</span>{% elif t.risk_score>=40%}<span class="badge badge-medium">MEDIUM</span>{% else %}<span class="badge badge-low">LOW</span>{% endif %}</td>
            <td>{% if t.action_taken=="IP Blocked" %}<span style="color:#ff4444;font-weight:bold">⛔ Blocked</span>{% elif t.action_taken=="Alert Sent" %}<span style="color:#ffaa00;font-weight:bold">⚠ Alert</span>{% else %}<span style="color:#888">📋 Logged</span>{% endif %}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
</div>

<!-- TAB: IP SCANNER -->
<div id="tab-ipscanner" class="tab-pane">
    <div class="card">
        <h2>🔍 Network IP Scanner</h2>
        <p>Enter any IP address to scan for open ports, running services, and security vulnerabilities. Works on any device on your network.</p>
        <div class="input-row">
            <input type="text" id="scan-ip" class="big-input" placeholder="Enter IP address e.g. 192.168.221.129">
            <button class="btn btn-blue" id="scan-btn" onclick="startIPScan()">🔍 SCAN IP</button>
        </div>
        <div class="quick-btns">
            <button class="quick-btn" onclick="quickIP('192.168.221.129')">OWASP BWA</button>
            <button class="quick-btn" onclick="quickIP('192.168.221.128')">Kali Linux</button>
            <button class="quick-btn" onclick="quickIP('127.0.0.1')">Localhost</button>
        </div>
    </div>

    <div class="loading" id="ip-loading">
        <div class="spinner">⟳</div>
        <div class="loading-text">Scanning ports... analyzing vulnerabilities...</div>
    </div>

    <div class="result-box" id="ip-results"></div>
</div>

<!-- TAB: CODE SCANNER -->
<div id="tab-codescanner" class="tab-pane">
    <div class="card">
        <h2>🧬 AI Code Vulnerability Scanner</h2>
        <p>Upload any Python, JavaScript, PHP, or ZIP project file. The AI will scan every line of code for security vulnerabilities including SQL injection, hardcoded passwords, weak encryption, command injection, and more.</p>

        <div class="upload-area" onclick="document.getElementById('file-input').click()">
            <input type="file" id="file-input" accept=".py,.js,.php,.java,.html,.zip,.txt" onchange="handleFileSelect(this)">
            <div class="upload-icon">📁</div>
            <div class="upload-text">Click to upload file or drag & drop</div>
            <div class="upload-hint">Supports: .py .js .php .java .html .zip (max 16MB)</div>
        </div>

        <div id="file-selected" style="display:none;color:#00ff88;font-size:12px;margin-bottom:14px;padding:10px;background:#002d1a;border-radius:6px;border:1px solid #00ff88;">
            📄 <span id="file-name"></span>
        </div>

        <button class="btn btn-green" id="code-scan-btn" onclick="startCodeScan()" style="width:100%;display:none;">🧬 SCAN FOR VULNERABILITIES</button>
    </div>

    <div class="loading" id="code-loading">
        <div class="spinner">⟳</div>
        <div class="loading-text">Analyzing code... scanning for vulnerabilities...</div>
    </div>

    <div class="result-box" id="code-results"></div>
</div>

<!-- TAB: THREAT LOG -->
<div id="tab-threats" class="tab-pane">
    <div class="section-title">⚡ Full Threat Log ({{ total }} events)</div>
    {% if threats %}
    <table class="threat-table">
        <thead><tr><th>#</th><th>Timestamp</th><th>IP Address</th><th>Threat Type</th><th>Score</th><th>Severity</th><th>Action</th></tr></thead>
        <tbody>
        {% for t in threats|reverse %}
        <tr>
            <td style="color:#444">{{ loop.index }}</td>
            <td style="color:#666">{{ t.timestamp }}</td>
            <td style="color:#00aaff">{{ t.ip_address }}</td>
            <td>{{ t.threat_type }}</td>
            <td><div class="score-bar"><span style="min-width:28px;color:{% if t.risk_score>=90%}#ff4444{% elif t.risk_score>=70%}#ff8800{% elif t.risk_score>=40%}#ffcc00{% else %}#00ff88{% endif %}">{{ t.risk_score }}</span><div class="bar-bg"><div class="bar-fill" style="width:{{ t.risk_score }}%;background:{% if t.risk_score>=90%}#ff4444{% elif t.risk_score>=70%}#ff8800{% elif t.risk_score>=40%}#ffcc00{% else %}#00ff88{% endif %};"></div></div></div></td>
            <td>{% if t.risk_score>=90%}<span class="badge badge-critical">CRITICAL</span>{% elif t.risk_score>=70%}<span class="badge badge-high">HIGH</span>{% elif t.risk_score>=40%}<span class="badge badge-medium">MEDIUM</span>{% else %}<span class="badge badge-low">LOW</span>{% endif %}</td>
            <td>{% if t.action_taken=="IP Blocked" %}<span style="color:#ff4444;font-weight:bold">⛔ Blocked</span>{% elif t.action_taken=="Alert Sent" %}<span style="color:#ffaa00;font-weight:bold">⚠ Alert</span>{% else %}<span style="color:#888">📋 Logged</span>{% endif %}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="no-data">No threats logged yet. Run main.py to generate data.</div>
    {% endif %}
</div>

</div><!-- end content -->

<div class="footer">ThreatWatch AI Security Portal v2.0 — STMU BSCYS-III — Zarmeen Zawar Ghauri & Zaynab Amjad Abbasi | CS2141 Artificial Intelligence 2026</div>

<script>
// ---- TAB SWITCHING ----
function showTab(name, el) {
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    el.classList.add('active');
}

// ---- IP SCANNER ----
function quickIP(ip) {
    document.getElementById('scan-ip').value = ip;
    startIPScan();
}

function startIPScan() {
    const ip  = document.getElementById('scan-ip').value.trim();
    const btn = document.getElementById('scan-btn');
    if (!ip) { alert('Please enter an IP address!'); return; }

    btn.disabled = true; btn.textContent = '⟳ Scanning...';
    document.getElementById('ip-loading').style.display  = 'block';
    document.getElementById('ip-results').style.display  = 'none';

    fetch('/api/scan-ip', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ip})
    })
    .then(r => r.json())
    .then(data => {
        btn.disabled = false; btn.textContent = '🔍 SCAN IP';
        document.getElementById('ip-loading').style.display = 'none';
        renderIPResults(data);
    })
    .catch(e => {
        btn.disabled = false; btn.textContent = '🔍 SCAN IP';
        document.getElementById('ip-loading').style.display = 'none';
        alert('Scan error: ' + e);
    });
}

function scoreColor(s) {
    if(s>=90) return '#ff4444';
    if(s>=70) return '#ff8800';
    if(s>=40) return '#ffcc00';
    return '#00ff88';
}
function riskColor(r) {
    if(r==='CRITICAL') return '#ff4444';
    if(r==='HIGH')     return '#ff8800';
    if(r==='MEDIUM')   return '#ffcc00';
    return '#00ff88';
}

function renderIPResults(d) {
    const div   = document.getElementById('ip-results');
    const sc    = scoreColor(d.risk_score);
    const ports = d.open_ports || [];

    let portsHtml = ports.length > 0 ? `
    <div class="section-title" style="margin-top:16px">Open Ports & Services</div>
    <table class="result-table">
        <thead><tr><th>Port</th><th>Service</th><th>Risk Level</th><th>Security Issue</th></tr></thead>
        <tbody>${ports.map(p => {
            const info = d.port_info[p] || {service:'Unknown',risk:'LOW',reason:'Unknown'};
            const rc   = riskColor(info.risk);
            return `<tr>
                <td style="color:#00aaff;font-weight:bold">${p}</td>
                <td>${info.service}</td>
                <td style="color:${rc};font-weight:bold">${info.risk}</td>
                <td style="color:#888">${info.reason}</td>
            </tr>`;
        }).join('')}</tbody>
    </table>` : '<div style="color:#00ff88;padding:12px">✅ No dangerous open ports found on common ports</div>';

    let recHtml = d.risk_score >= 70
        ? `<div class="rec-item">🚨 HIGH RISK — Immediate action required!</div>
           <div class="rec-item">• Close or firewall all non-essential ports</div>
           <div class="rec-item">• Check for unauthorized access immediately</div>
           <div class="rec-item">• Run full penetration test on this system</div>`
        : d.risk_score >= 40
        ? `<div class="rec-item">⚠ MEDIUM RISK — Review open services</div>
           <div class="rec-item">• Ensure all services are patched and updated</div>
           <div class="rec-item">• Consider closing unused ports</div>`
        : `<div class="rec-item">✅ LOW RISK — Network looks relatively secure</div>
           <div class="rec-item">• Continue regular monitoring</div>`;

    div.innerHTML = `
        <div class="result-header">
            <div>
                <div class="result-ip">📡 ${d.ip}</div>
                <div class="result-meta">Hostname: ${d.hostname} &nbsp;|&nbsp; Scanned: ${d.scanned_at}</div>
            </div>
            <div>
                <div class="big-score" style="color:${sc}">${d.risk_score}/100</div>
                <div class="severity-label" style="color:${sc}">${d.severity}</div>
            </div>
        </div>
        <div class="info-grid">
            <div class="info-tile"><div class="v" style="color:${d.is_alive?'#00ff88':'#ff4444'}">${d.is_alive?'ONLINE':'OFFLINE'}</div><div class="l">Status</div></div>
            <div class="info-tile"><div class="v">${ports.length}</div><div class="l">Open Ports</div></div>
            <div class="info-tile"><div class="v" style="color:${sc}">${d.risk_score}</div><div class="l">Risk Score</div></div>
            <div class="info-tile"><div class="v" style="color:${sc}">${d.severity}</div><div class="l">Severity</div></div>
        </div>
        ${portsHtml}
        <div class="rec-box"><h4>Recommendations</h4>${recHtml}</div>
    `;
    div.style.display = 'block';
}

// ---- CODE SCANNER ----
let selectedFile = null;

function handleFileSelect(input) {
    selectedFile = input.files[0];
    if (selectedFile) {
        document.getElementById('file-name').textContent = selectedFile.name + ' (' + (selectedFile.size/1024).toFixed(1) + ' KB)';
        document.getElementById('file-selected').style.display = 'block';
        document.getElementById('code-scan-btn').style.display = 'block';
    }
}

function startCodeScan() {
    if (!selectedFile) { alert('Please select a file first!'); return; }
    const btn = document.getElementById('code-scan-btn');
    btn.disabled = true; btn.textContent = '⟳ Scanning...';
    document.getElementById('code-loading').style.display  = 'block';
    document.getElementById('code-results').style.display  = 'none';

    const formData = new FormData();
    formData.append('file', selectedFile);

    fetch('/api/scan-code', { method:'POST', body: formData })
    .then(r => r.json())
    .then(data => {
        btn.disabled = false; btn.textContent = '🧬 SCAN FOR VULNERABILITIES';
        document.getElementById('code-loading').style.display = 'none';
        renderCodeResults(data);
    })
    .catch(e => {
        btn.disabled = false; btn.textContent = '🧬 SCAN FOR VULNERABILITIES';
        document.getElementById('code-loading').style.display = 'none';
        alert('Scan error: ' + e);
    });
}

function renderCodeResults(d) {
    const div      = document.getElementById('code-results');
    const sc       = scoreColor(d.risk_score);
    const findings = d.findings || [];

    const sevCount = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
    findings.forEach(f => sevCount[f.severity] = (sevCount[f.severity]||0) + 1);

    let findingsHtml = findings.length > 0
        ? findings.map(f => `
            <div class="vuln-card vuln-${f.severity.toLowerCase()}">
                <div class="vuln-header">
                    <span class="vuln-name" style="color:${riskColor(f.severity)}">${f.name}</span>
                    <span class="vuln-id">${f.id} — ${f.severity}</span>
                </div>
                <div class="vuln-desc">${f.desc}</div>
                ${f.code ? `<div class="vuln-code">${f.code}</div>` : ''}
                <div class="vuln-location">📄 ${f.file} — Line ${f.line}</div>
            </div>`).join('')
        : '<div style="color:#00ff88;padding:16px;font-size:13px">✅ No vulnerabilities found! Code looks secure.</div>';

    div.innerHTML = `
        <div class="result-header">
            <div>
                <div class="result-ip">🧬 ${d.filename}</div>
                <div class="result-meta">Files scanned: ${d.files_scanned} &nbsp;|&nbsp; Vulnerabilities: ${findings.length}</div>
            </div>
            <div>
                <div class="big-score" style="color:${sc}">${d.risk_score}/100</div>
                <div class="severity-label" style="color:${sc}">${d.severity}</div>
            </div>
        </div>
        <div class="info-grid">
            <div class="info-tile"><div class="v" style="color:#ff4444">${sevCount.CRITICAL||0}</div><div class="l">Critical</div></div>
            <div class="info-tile"><div class="v" style="color:#ff8800">${sevCount.HIGH||0}</div><div class="l">High</div></div>
            <div class="info-tile"><div class="v" style="color:#ffcc00">${sevCount.MEDIUM||0}</div><div class="l">Medium</div></div>
            <div class="info-tile"><div class="v" style="color:#00ff88">${sevCount.LOW||0}</div><div class="l">Low</div></div>
        </div>
        <div class="section-title" style="margin-top:4px">Vulnerability Details</div>
        ${findingsHtml}
    `;
    div.style.display = 'block';
}
</script>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html><html><head><title>ThreatWatch AI Login</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0a0e1a;font-family:'Courier New',monospace;display:flex;justify-content:center;align-items:center;min-height:100vh}.box{background:#0d1b2a;border:1px solid #1a3a5c;border-radius:12px;padding:40px;width:380px;text-align:center}.logo{font-size:40px;margin-bottom:10px}h1{color:#00ff88;font-size:18px;letter-spacing:2px;margin-bottom:6px}.sub{color:#666;font-size:11px;letter-spacing:1px;margin-bottom:30px}.fg{margin-bottom:16px;text-align:left}label{display:block;color:#00aaff;font-size:11px;letter-spacing:1px;margin-bottom:6px;text-transform:uppercase}input{width:100%;padding:12px 14px;background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;color:#e0e0e0;font-family:'Courier New',monospace;font-size:13px;outline:none}input:focus{border-color:#00aaff}.btn{width:100%;padding:12px;background:#00aaff;color:#0a0e1a;border:none;border-radius:6px;font-size:13px;font-weight:bold;font-family:'Courier New',monospace;letter-spacing:2px;cursor:pointer;margin-top:10px}.btn:hover{background:#00ff88}.err{background:#3d0000;border:1px solid #ff4444;color:#ff4444;padding:10px;border-radius:6px;font-size:12px;margin-bottom:16px}hr{border:none;border-top:1px solid #1a3a5c;margin:24px 0}.hint{color:#444;font-size:10px;margin-top:12px}.footer{color:#333;font-size:10px;margin-top:20px}</style>
</head><body><div class="box">
<div class="logo">🛡</div><h1>THREATWATCH AI</h1>
<div class="sub">SECURITY PORTAL v2.0</div>
{% if error %}<div class="err">⛔ {{ error }}</div>{% endif %}
<form method="POST" action="/login">
<div class="fg"><label>Username</label><input type="text" name="username" placeholder="Enter username" required autofocus></div>
<div class="fg"><label>Password</label><input type="password" name="password" placeholder="Enter password" required></div>
<button type="submit" class="btn">🔐 SECURE LOGIN</button>
</form>
<hr><div class="hint">admin / admin123 &nbsp;|&nbsp; zaynab / stmu2026</div>
<div class="footer">STMU BSCYS-III | CS2141 Artificial Intelligence | 2026</div>
</div></body></html>
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
    return render_template_string(PORTAL_HTML, threats=threats, total=total,
                                  blocked=blocked, alerts=alerts, avg_score=avg_score,
                                  username=session.get("username"),
                                  role=session.get("role"))

@app.route("/api/scan-ip", methods=["POST"])
@login_required
def api_scan_ip():
    data = request.get_json()
    ip   = data.get("ip", "").strip()
    if not ip: return jsonify({"error": "No IP"}), 400

    hostname   = get_hostname(ip)
    try:
        result   = subprocess.run(["ping","-n","1","-w","1000",ip], capture_output=True, text=True, timeout=5)
        is_alive = "TTL=" in result.stdout
    except:
        is_alive = False

    open_ports = scan_ports(ip)
    risk_score = calc_network_risk(open_ports)
    severity   = get_severity(risk_score)
    port_info  = {p: DANGEROUS_PORTS.get(p, {"service":"Unknown","risk":"LOW","reason":"Unknown"}) for p in open_ports}

    return jsonify({
        "ip": ip, "hostname": hostname, "is_alive": is_alive,
        "open_ports": open_ports, "port_info": port_info,
        "risk_score": risk_score, "severity": severity,
        "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route("/api/scan-code", methods=["POST"])
@login_required
def api_scan_code():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    file     = request.files["file"]
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_DIR, filename)
    file.save(filepath)

    ext = os.path.splitext(filename)[1].lower()

    if ext == ".zip":
        findings, files_scanned, error = scan_zip_file(filepath)
        if error:
            return jsonify({"error": error}), 400
    else:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
        findings     = scan_code(content, filename)
        files_scanned = [filename]

    risk_score = calc_code_risk(findings)
    severity   = get_severity(risk_score)

    # Clean up uploaded file
    try: os.remove(filepath)
    except: pass

    return jsonify({
        "filename":     filename,
        "files_scanned": len(files_scanned),
        "findings":     findings,
        "risk_score":   risk_score,
        "severity":     severity,
    })

@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        if u in USERS and check_password_hash(USERS[u]["password"], p):
            session["username"] = u
            session["role"]     = USERS[u]["role"]
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template_string(LOGIN_HTML, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    print("="*55)
    print("  ThreatWatch AI — Security Portal v2.0")
    print("="*55)
    print("\n  Open: http://127.0.0.1:5000")
    print("  Login: admin/admin123 or zaynab/stmu2026")
    print("\n  Features:")
    print("  → IP Scanner: scan ANY ip on your network")
    print("  → Code Scanner: upload any file/zip")
    print("     AI finds SQL injection, weak passwords,")
    print("     backdoors, command injection & more!")
    print("="*55)
    app.run(debug=False)