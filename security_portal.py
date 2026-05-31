# ============================================
# ThreatWatch AI - Security Portal v3.0
# 5 Tabs: Dashboard, IP Scanner, Code Scanner,
#         Threat Intel, Threat Log
# ============================================

from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import json, os, socket, subprocess, datetime, zipfile, re
import vt

app = Flask(__name__)
app.secret_key = "threatwatch_v3_stmu_2026"
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

LOG_FILE   = "logs/threats.json"
UPLOAD_DIR = "data/uploads"
INTEL_LOG  = "logs/threat_intel_scans.json"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs("logs", exist_ok=True)

# !! PUT YOUR API KEY HERE !!
THREAT_INTEL_API = "543cf0e0bee9ba88218e97d3b5f6c4b21f124d39f36a944978c0b4c685ed3c52"

USERS = {
    "admin":   {"password": generate_password_hash("admin123"),  "role": "Administrator"},
    "zarmeen": {"password": generate_password_hash("stmu2026"),  "role": "Security Analyst"},
    "zaynab":  {"password": generate_password_hash("stmu2026"),  "role": "Security Analyst"},
}

DANGEROUS_PORTS = {
    21:   {"service":"FTP",        "risk":"HIGH",    "reason":"Transmits data in plaintext"},
    22:   {"service":"SSH",        "risk":"MEDIUM",  "reason":"Brute force target"},
    23:   {"service":"Telnet",     "risk":"CRITICAL","reason":"Completely unencrypted"},
    25:   {"service":"SMTP",       "risk":"MEDIUM",  "reason":"Spam relay possible"},
    80:   {"service":"HTTP",       "risk":"MEDIUM",  "reason":"Unencrypted web traffic"},
    135:  {"service":"RPC",        "risk":"HIGH",    "reason":"Commonly exploited"},
    139:  {"service":"NetBIOS",    "risk":"HIGH",    "reason":"Windows attack vector"},
    443:  {"service":"HTTPS",      "risk":"LOW",     "reason":"Encrypted — generally safe"},
    445:  {"service":"SMB",        "risk":"CRITICAL","reason":"WannaCry/EternalBlue target!"},
    1433: {"service":"MSSQL",      "risk":"HIGH",    "reason":"Database exposed"},
    3306: {"service":"MySQL",      "risk":"HIGH",    "reason":"Database exposed"},
    3389: {"service":"RDP",        "risk":"CRITICAL","reason":"Remote Desktop brute force target"},
    4444: {"service":"Metasploit", "risk":"CRITICAL","reason":"Backdoor port!"},
    5900: {"service":"VNC",        "risk":"HIGH",    "reason":"Unencrypted remote desktop"},
    6666: {"service":"Malware C2", "risk":"CRITICAL","reason":"Malware command & control"},
    8080: {"service":"HTTP Alt",   "risk":"MEDIUM",  "reason":"Check for misconfigs"},
    8443: {"service":"HTTPS Alt",  "risk":"LOW",     "reason":"Alternative HTTPS"},
    27017:{"service":"MongoDB",    "risk":"CRITICAL","reason":"Often no authentication!"},
}

VULN_PATTERNS = [
    {"id":"SQL-01","name":"SQL Injection",      "severity":"CRITICAL","pattern":r'(SELECT|INSERT|UPDATE|DELETE).*\+.*input|query\s*\+','desc':'Direct SQL with user input'},
    {"id":"SEC-01","name":"Hardcoded Password", "severity":"CRITICAL","pattern":r'password\s*=\s*["\'][^"\']{3,}["\']','desc':'Hardcoded password found'},
    {"id":"SEC-02","name":"Hardcoded API Key",  "severity":"CRITICAL","pattern":r'api_key\s*=\s*["\'][^"\']{8,}["\']','desc':'Hardcoded API key found'},
    {"id":"CMD-01","name":"Command Injection",  "severity":"CRITICAL","pattern":r'os\.system\s*\(|subprocess\.call\s*\(.*shell\s*=\s*True','desc':'Dangerous command execution'},
    {"id":"CMD-02","name":"Unsafe eval()",      "severity":"HIGH",   "pattern":r'\beval\s*\(|exec\s*\(','desc':'eval() executes arbitrary code'},
    {"id":"CRY-01","name":"Weak Hashing MD5",  "severity":"HIGH",   "pattern":r'hashlib\.md5','desc':'MD5 is cryptographically broken'},
    {"id":"CRY-02","name":"Weak Hashing SHA1", "severity":"MEDIUM", "pattern":r'hashlib\.sha1','desc':'SHA1 is deprecated'},
    {"id":"CRY-03","name":"HTTP not HTTPS",    "severity":"MEDIUM", "pattern":r'http://(?!localhost|127)','desc':'Unencrypted HTTP used'},
    {"id":"INP-01","name":"No Input Validation","severity":"HIGH",  "pattern":r'request\.args\.get\(|request\.form\.get\(','desc':'User input without validation'},
    {"id":"DBG-01","name":"Debug Mode On",     "severity":"MEDIUM", "pattern":r'debug\s*=\s*True','desc':'Debug mode in production'},
    {"id":"FIL-01","name":"Path Traversal",    "severity":"CRITICAL","pattern":r'open\s*\(.*\+|open\s*\(.*input','desc':'File path from user input'},
]

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def get_hostname(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return "Unknown"

def scan_ports(ip, timeout=0.5):
    open_ports = []
    for port in DANGEROUS_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0: open_ports.append(port)
            s.close()
        except: pass
    return open_ports

def calc_network_risk(ports):
    score = 0
    for p in ports:
        if p in DANGEROUS_PORTS:
            r = DANGEROUS_PORTS[p]["risk"]
            if r=="CRITICAL": score+=25
            elif r=="HIGH":   score+=15
            elif r=="MEDIUM": score+=8
            else:             score+=2
    return min(score, 100)

def get_severity(score):
    if score>=90: return "CRITICAL"
    elif score>=70: return "HIGH"
    elif score>=40: return "MEDIUM"
    else: return "LOW"

def get_intel_severity(malicious, total):
    if total==0: return "UNKNOWN"
    r = malicious/total
    if r>=0.5: return "CRITICAL"
    elif r>=0.2: return "HIGH"
    elif r>=0.05: return "MEDIUM"
    elif malicious>0: return "LOW"
    return "CLEAN"

def scan_code(content, filename=""):
    findings = []
    for vuln in VULN_PATTERNS:
        for i, line in enumerate(content.split('\n'), 1):
            if re.search(vuln["pattern"], line, re.IGNORECASE):
                findings.append({"id":vuln["id"],"name":vuln["name"],"severity":vuln["severity"],
                                  "desc":vuln["desc"],"line":i,"code":line.strip()[:80],"file":filename})
    return findings

def scan_zip(filepath):
    findings, files = [], []
    try:
        with zipfile.ZipFile(filepath,'r') as zf:
            for name in zf.namelist():
                if os.path.splitext(name)[1].lower() in ['.py','.js','.php','.java','.html','.txt','.env']:
                    try:
                        content = zf.read(name).decode('utf-8',errors='ignore')
                        findings.extend(scan_code(content, name))
                        files.append(name)
                    except: pass
    except Exception as e:
        return [],[],str(e)
    return findings, files, None

def calc_code_risk(findings):
    score = 0
    for f in findings:
        if f["severity"]=="CRITICAL": score+=25
        elif f["severity"]=="HIGH":   score+=15
        elif f["severity"]=="MEDIUM": score+=8
        else:                         score+=3
    return min(score, 100)

# ===============================================
# MAIN HTML PAGE
# ===============================================
PAGE = """<!DOCTYPE html>
<html>
<head>
<title>ThreatWatch AI — Security Portal v3</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e1a;color:#e0e0e0;font-family:'Courier New',monospace}
.hdr{background:#0d1b2a;border-bottom:2px solid #00ff88;padding:13px 30px;display:flex;justify-content:space-between;align-items:center}
.hdr h1{color:#00ff88;font-size:16px;letter-spacing:2px}
.hdr .r{display:flex;align-items:center;gap:12px}
.ubadge{background:#0a0e1a;border:1px solid #1a3a5c;border-radius:20px;padding:5px 13px;font-size:11px;color:#00aaff}
.lbtn{background:transparent;border:1px solid #ff4444;color:#ff4444;padding:5px 13px;border-radius:20px;font-size:11px;cursor:pointer;text-decoration:none;font-family:'Courier New',monospace}
.live{color:#00ff88;font-size:11px;animation:blink 1.5s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.tabs{display:flex;background:#0d1b2a;border-bottom:1px solid #1a3a5c;padding:0 30px;overflow-x:auto}
.tab{padding:12px 18px;cursor:pointer;font-size:11px;letter-spacing:1px;color:#555;border-bottom:2px solid transparent;white-space:nowrap}
.tab:hover{color:#00aaff}
.tab.active{color:#00ff88;border-bottom:2px solid #00ff88}
.content{padding:22px 30px}
.pane{display:none}.pane.active{display:block}
.srow{display:flex;gap:14px;margin-bottom:22px}
.sc{flex:1;background:#0d1b2a;border:1px solid #1a3a5c;border-radius:8px;padding:15px;text-align:center}
.sc .n{font-size:28px;font-weight:bold;margin-bottom:4px}
.sc .l{font-size:10px;color:#888;text-transform:uppercase;letter-spacing:1px}
.card{background:#0d1b2a;border:1px solid #1a3a5c;border-radius:10px;padding:20px;margin-bottom:18px}
.card h2{color:#00aaff;font-size:12px;letter-spacing:2px;text-transform:uppercase;margin-bottom:6px}
.card p{color:#666;font-size:12px;margin-bottom:16px;line-height:1.6}
.irow{display:flex;gap:10px}
.inp{flex:1;padding:12px 15px;background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;color:#e0e0e0;font-family:'Courier New',monospace;font-size:13px;outline:none}
.inp:focus{border-color:#00aaff}
.btn{padding:12px 20px;border:none;border-radius:6px;font-size:12px;font-weight:bold;font-family:'Courier New',monospace;cursor:pointer;white-space:nowrap}
.btn:disabled{background:#1a3a5c;color:#444;cursor:not-allowed}
.bb{background:#00aaff;color:#0a0e1a}.bb:hover{background:#00ff88}
.bg{background:#00ff88;color:#0a0e1a}.bg:hover{background:#00aaff}
.bp{background:#aa00ff;color:#fff}.bp:hover{background:#cc44ff}
.qbtns{display:flex;gap:7px;margin-top:9px;flex-wrap:wrap}
.qb{padding:5px 12px;background:#0a0e1a;border:1px solid #1a3a5c;color:#00aaff;border-radius:4px;cursor:pointer;font-size:11px;font-family:'Courier New',monospace}
.qb:hover{border-color:#00aaff}
.uarea{border:2px dashed #1a3a5c;border-radius:8px;padding:28px;text-align:center;cursor:pointer;margin-bottom:14px}
.uarea:hover{border-color:#00aaff}
.uarea input{display:none}
.rbox{margin-top:18px;display:none}
.rhdr{display:flex;justify-content:space-between;align-items:center;background:#0d1b2a;border:1px solid #1a3a5c;border-radius:8px;padding:15px 18px;margin-bottom:12px}
.rip{font-size:15px;color:#00aaff;font-weight:bold}
.rmeta{color:#666;font-size:11px;margin-top:3px}
.bscore{font-size:34px;font-weight:bold}
.igrid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}
.it{background:#0d1b2a;border:1px solid #1a3a5c;border-radius:6px;padding:11px;text-align:center}
.it .v{font-size:18px;font-weight:bold;margin-bottom:3px}
.it .l{font-size:10px;color:#666;text-transform:uppercase}
.rt{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:12px}
.rt th{background:#0a0e1a;color:#00aaff;padding:8px 12px;text-align:left;font-size:10px;text-transform:uppercase;border-bottom:1px solid #1a3a5c}
.rt td{padding:8px 12px;border-bottom:1px solid #111827}
.vc{border-radius:6px;padding:11px 13px;margin-bottom:7px;border-left:3px solid}
.vc.c{background:#1a0000;border-color:#ff4444}
.vc.h{background:#1a0d00;border-color:#ff8800}
.vc.m{background:#1a1700;border-color:#ffcc00}
.vc.l2{background:#001a0d;border-color:#00ff88}
.vh{display:flex;justify-content:space-between;margin-bottom:3px}
.vn{font-size:13px;font-weight:bold}
.vcode{font-size:11px;background:#0a0e1a;padding:5px 9px;border-radius:4px;color:#00aaff;margin-top:5px}
.vloc{font-size:10px;color:#666;margin-top:3px}
.recbox{background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;padding:13px;margin-top:12px}
.recbox h4{color:#00aaff;font-size:11px;letter-spacing:1px;text-transform:uppercase;margin-bottom:9px}
.ri{font-size:12px;color:#aaa;margin-bottom:5px;line-height:1.6}
.tt{width:100%;border-collapse:collapse;font-size:12px}
.tt th{background:#0d1b2a;color:#00aaff;padding:9px 13px;text-align:left;font-size:10px;text-transform:uppercase;border-bottom:1px solid #1a3a5c}
.tt td{padding:8px 13px;border-bottom:1px solid #111827}
.badge{padding:2px 8px;border-radius:10px;font-size:10px;font-weight:bold}
.bc{background:#3d0000;color:#ff4444;border:1px solid #ff4444}
.bh{background:#2d1500;color:#ff8800;border:1px solid #ff8800}
.bm{background:#2d2500;color:#ffcc00;border:1px solid #ffcc00}
.bl{background:#002d1a;color:#00ff88;border:1px solid #00ff88}
.sbar{display:flex;align-items:center;gap:5px}
.bbg{flex:1;height:5px;background:#1a2a3a;border-radius:3px;overflow:hidden}
.bf{height:100%;border-radius:3px}
.load{text-align:center;padding:28px;display:none}
.spin{font-size:22px;animation:spin 1s linear infinite;display:inline-block}
@keyframes spin{100%{transform:rotate(360deg)}}
.ltxt{color:#00aaff;font-size:12px;margin-top:9px}
.stitle{color:#00aaff;font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:11px}
.tbtns{display:flex;gap:9px;margin-bottom:14px}
.tbtn{flex:1;padding:9px;background:#0a0e1a;border:1px solid #1a3a5c;color:#555;border-radius:6px;cursor:pointer;font-size:11px;font-family:'Courier New',monospace;text-align:center}
.tbtn.active{border-color:#00aaff;color:#00aaff;background:#001a2d}
.vbox{background:#0d1b2a;border-radius:8px;padding:18px;text-align:center;margin-bottom:14px;border:2px solid}
.estats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}
.es{background:#0a0e1a;border:1px solid #1a3a5c;border-radius:8px;padding:12px;text-align:center}
.es .v{font-size:26px;font-weight:bold;margin-bottom:3px}
.es .l{font-size:10px;color:#666;text-transform:uppercase}
.elist{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:7px;margin-top:10px}
.ei{background:#1a0000;border:1px solid #ff4444;border-radius:6px;padding:7px 11px;font-size:11px}
.hlist .hi{background:#0d1b2a;border:1px solid #1a3a5c;border-radius:6px;padding:9px 13px;margin-bottom:7px;display:flex;justify-content:space-between;align-items:center}
.footer{text-align:center;padding:12px;color:#333;font-size:10px;border-top:1px solid #111827;margin-top:10px}
</style>
</head>
<body>
<div class="hdr">
  <h1>🛡 THREATWATCH AI — SECURITY PORTAL v3</h1>
  <div class="r">
    <span class="live">● LIVE</span>
    <span class="ubadge">👤 {{ username }} | {{ role }}</span>
    <a href="/logout" class="lbtn">⛔ Logout</a>
  </div>
</div>
<div class="tabs">
  <div class="tab active" onclick="showTab('dash',this)">📊 Dashboard</div>
  <div class="tab" onclick="showTab('ips',this)">🔍 IP Scanner</div>
  <div class="tab" onclick="showTab('code',this)">🧬 Code Scanner</div>
  <div class="tab" onclick="showTab('intel',this)">🔎 Threat Intel</div>
  <div class="tab" onclick="showTab('log',this)">⚡ Threat Log</div>
</div>
<div class="content">

<!-- DASHBOARD -->
<div id="tab-dash" class="pane active">
  <div class="srow">
    <div class="sc"><div class="n" style="color:#00aaff">{{ total }}</div><div class="l">Total Threats</div></div>
    <div class="sc"><div class="n" style="color:#ff4444">{{ blocked }}</div><div class="l">IPs Blocked</div></div>
    <div class="sc"><div class="n" style="color:#ffaa00">{{ alerts }}</div><div class="l">Alerts Sent</div></div>
    <div class="sc"><div class="n" style="color:#00ff88">{{ avg_score }}</div><div class="l">Avg Risk Score</div></div>
  </div>
  <div class="stitle">⚡ Recent Threats</div>
  <table class="tt">
    <thead><tr><th>#</th><th>Time</th><th>IP</th><th>Threat</th><th>Score</th><th>Severity</th><th>Action</th></tr></thead>
    <tbody>
    {% for t in threats[-15:]|reverse %}
    <tr>
      <td style="color:#444">{{loop.index}}</td>
      <td style="color:#666">{{t.timestamp}}</td>
      <td style="color:#00aaff">{{t.ip_address}}</td>
      <td>{{t.threat_type}}</td>
      <td><div class="sbar"><span style="min-width:26px;color:{{'#ff4444' if t.risk_score>=90 else '#ff8800' if t.risk_score>=70 else '#ffcc00' if t.risk_score>=40 else '#00ff88'}}">{{t.risk_score}}</span><div class="bbg"><div class="bf" style="width:{{t.risk_score}}%;background:{{'#ff4444' if t.risk_score>=90 else '#ff8800' if t.risk_score>=70 else '#ffcc00' if t.risk_score>=40 else '#00ff88'}};"></div></div></div></td>
      <td>{%if t.risk_score>=90%}<span class="badge bc">CRITICAL</span>{%elif t.risk_score>=70%}<span class="badge bh">HIGH</span>{%elif t.risk_score>=40%}<span class="badge bm">MEDIUM</span>{%else%}<span class="badge bl">LOW</span>{%endif%}</td>
      <td>{%if t.action_taken=="IP Blocked"%}<span style="color:#ff4444;font-weight:bold">⛔ Blocked</span>{%elif t.action_taken=="Alert Sent"%}<span style="color:#ffaa00;font-weight:bold">⚠ Alert</span>{%else%}<span style="color:#888">📋 Logged</span>{%endif%}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>

<!-- IP SCANNER -->
<div id="tab-ips" class="pane">
  <div class="card">
    <h2>🔍 Network IP Scanner</h2>
    <p>Scan any IP for open ports, services, and security vulnerabilities.</p>
    <div class="irow">
      <input type="text" id="ip-in" class="inp" placeholder="Enter IP e.g. 192.168.221.129">
      <button class="btn bb" id="ip-btn" onclick="doIPScan()">🔍 SCAN</button>
    </div>
    <div class="qbtns">
      <button class="qb" onclick="qIP('192.168.221.129')">OWASP BWA</button>
      <button class="qb" onclick="qIP('192.168.221.128')">Kali Linux</button>
      <button class="qb" onclick="qIP('127.0.0.1')">Localhost</button>
    </div>
  </div>
  <div class="load" id="ip-load"><div class="spin">⟳</div><div class="ltxt">Scanning ports...</div></div>
  <div class="rbox" id="ip-res"></div>
</div>

<!-- CODE SCANNER -->
<div id="tab-code" class="pane">
  <div class="card">
    <h2>🧬 AI Code Vulnerability Scanner</h2>
    <p>Upload any .py .js .php .java .zip file. AI scans every line for SQL injection, hardcoded passwords, weak encryption, command injection and more.</p>
    <div class="uarea" onclick="document.getElementById('fi').click()">
      <input type="file" id="fi" accept=".py,.js,.php,.java,.html,.zip,.txt" onchange="onFile(this)">
      <div style="font-size:34px;margin-bottom:9px">📁</div>
      <div style="color:#666;font-size:13px">Click to upload or drag & drop</div>
      <div style="color:#444;font-size:11px;margin-top:5px">Supports: .py .js .php .zip and more</div>
    </div>
    <div id="fsel" style="display:none;color:#00ff88;font-size:12px;margin-bottom:13px;padding:9px;background:#002d1a;border-radius:6px;border:1px solid #00ff88">📄 <span id="fn"></span></div>
    <button class="btn bg" id="code-btn" onclick="doCodeScan()" style="width:100%;display:none">🧬 SCAN FOR VULNERABILITIES</button>
  </div>
  <div class="load" id="code-load"><div class="spin">⟳</div><div class="ltxt">Analyzing code for vulnerabilities...</div></div>
  <div class="rbox" id="code-res"></div>
</div>

<!-- THREAT INTEL -->
<div id="tab-intel" class="pane">
  <div class="card">
    <h2>🔎 Threat Intelligence Scanner</h2>
    <p>Check any IP, domain, or file hash against 91 global security engines in real time.</p>
    <div class="tbtns">
      <div class="tbtn active" id="t-ip"     onclick="setType('ip')">🌐 IP Address</div>
      <div class="tbtn"        id="t-domain" onclick="setType('domain')">🔗 Domain</div>
      <div class="tbtn"        id="t-hash"   onclick="setType('hash')">🔑 File Hash</div>
    </div>
    <div class="irow">
      <input type="text" id="intel-in" class="inp" placeholder="Enter IP address e.g. 8.8.8.8">
      <button class="btn bp" id="intel-btn" onclick="doIntel()">🔎 SCAN</button>
    </div>
    <div class="qbtns" id="intel-qbtns">
      <button class="qb" onclick="qIntel('8.8.8.8')">Google DNS</button>
      <button class="qb" onclick="qIntel('1.1.1.1')">Cloudflare</button>
      <button class="qb" onclick="qIntel('malware.wicar.org','domain')">malware test</button>
    </div>
  </div>
  <div class="load" id="intel-load"><div class="spin">⟳</div><div class="ltxt">Checking 91 security engines...</div></div>
  <div class="rbox" id="intel-res"></div>
  <div id="intel-hist" style="margin-top:18px;display:none">
    <div class="stitle">Recent Scans</div>
    <div class="hlist" id="intel-hlist"></div>
  </div>
</div>

<!-- THREAT LOG -->
<div id="tab-log" class="pane">
  <div class="stitle">⚡ Full Threat Log ({{ total }} events)</div>
  <table class="tt">
    <thead><tr><th>#</th><th>Time</th><th>IP</th><th>Threat</th><th>Score</th><th>Severity</th><th>Action</th></tr></thead>
    <tbody>
    {% for t in threats|reverse %}
    <tr>
      <td style="color:#444">{{loop.index}}</td>
      <td style="color:#666">{{t.timestamp}}</td>
      <td style="color:#00aaff">{{t.ip_address}}</td>
      <td>{{t.threat_type}}</td>
      <td><div class="sbar"><span style="min-width:26px;color:{{'#ff4444' if t.risk_score>=90 else '#ff8800' if t.risk_score>=70 else '#ffcc00' if t.risk_score>=40 else '#00ff88'}}">{{t.risk_score}}</span><div class="bbg"><div class="bf" style="width:{{t.risk_score}}%;background:{{'#ff4444' if t.risk_score>=90 else '#ff8800' if t.risk_score>=70 else '#ffcc00' if t.risk_score>=40 else '#00ff88'}};"></div></div></div></td>
      <td>{%if t.risk_score>=90%}<span class="badge bc">CRITICAL</span>{%elif t.risk_score>=70%}<span class="badge bh">HIGH</span>{%elif t.risk_score>=40%}<span class="badge bm">MEDIUM</span>{%else%}<span class="badge bl">LOW</span>{%endif%}</td>
      <td>{%if t.action_taken=="IP Blocked"%}<span style="color:#ff4444;font-weight:bold">⛔ Blocked</span>{%elif t.action_taken=="Alert Sent"%}<span style="color:#ffaa00;font-weight:bold">⚠ Alert</span>{%else%}<span style="color:#888">📋 Logged</span>{%endif%}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>

</div>
<div class="footer">ThreatWatch AI Security Portal v3.0 — STMU BSCYS-III — Zarmeen Zawar Ghauri & Zaynab Amjad Abbasi | CS2141 AI 2026</div>

<script>
let itype='ip', selFile=null;

function showTab(name,el){
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  el.classList.add('active');
  if(name==='intel') loadHist();
}

function sc(s){return s>=90?'#ff4444':s>=70?'#ff8800':s>=40?'#ffcc00':'#00ff88'}
function rc(r){return r==='CRITICAL'?'#ff4444':r==='HIGH'?'#ff8800':r==='MEDIUM'?'#ffcc00':'#00ff88'}
function ic(s){const m={CRITICAL:'#ff4444',HIGH:'#ff8800',MEDIUM:'#ffcc00',LOW:'#00aaff',CLEAN:'#00ff88',UNKNOWN:'#666'};return m[s]||'#666'}

// IP SCANNER
function qIP(ip){document.getElementById('ip-in').value=ip;doIPScan();}
function doIPScan(){
  const ip=document.getElementById('ip-in').value.trim();
  const btn=document.getElementById('ip-btn');
  if(!ip){alert('Enter an IP!');return;}
  btn.disabled=true;btn.textContent='⟳ Scanning...';
  document.getElementById('ip-load').style.display='block';
  document.getElementById('ip-res').style.display='none';
  fetch('/api/scan-ip',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})})
  .then(r=>r.json()).then(d=>{
    btn.disabled=false;btn.textContent='🔍 SCAN';
    document.getElementById('ip-load').style.display='none';
    showIPRes(d);
  }).catch(e=>{btn.disabled=false;btn.textContent='🔍 SCAN';document.getElementById('ip-load').style.display='none';alert('Error: '+e);});
}
function showIPRes(d){
  const div=document.getElementById('ip-res');
  const c=sc(d.risk_score), ports=d.open_ports||[];
  let ph=ports.length>0?`<div class="stitle" style="margin-top:14px">Open Ports</div><table class="rt"><thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Issue</th></tr></thead><tbody>${ports.map(p=>{const i=d.port_info[p]||{service:'Unknown',risk:'LOW',reason:'?'};return`<tr><td style="color:#00aaff;font-weight:bold">${p}</td><td>${i.service}</td><td style="color:${rc(i.risk)};font-weight:bold">${i.risk}</td><td style="color:#888">${i.reason}</td></tr>`;}).join('')}</tbody></table>`:'<div style="color:#00ff88;padding:10px">✅ No dangerous open ports found</div>';
  let rh=d.risk_score>=70?'<div class="ri">🚨 HIGH RISK — Close non-essential ports immediately</div><div class="ri">• Check for unauthorized access now</div>':d.risk_score>=40?'<div class="ri">⚠ MEDIUM — Review open services and patch them</div>':'<div class="ri">✅ LOW RISK — Continue regular monitoring</div>';
  div.innerHTML=`<div class="rhdr"><div><div class="rip">📡 ${d.ip}</div><div class="rmeta">Hostname: ${d.hostname} | ${d.scanned_at}</div></div><div><div class="bscore" style="color:${c}">${d.risk_score}/100</div><div style="color:${c};font-size:11px;text-align:right">${d.severity}</div></div></div><div class="igrid"><div class="it"><div class="v" style="color:${d.is_alive?'#00ff88':'#ff4444'}">${d.is_alive?'ONLINE':'OFFLINE'}</div><div class="l">Status</div></div><div class="it"><div class="v">${ports.length}</div><div class="l">Open Ports</div></div><div class="it"><div class="v" style="color:${c}">${d.risk_score}</div><div class="l">Risk Score</div></div><div class="it"><div class="v" style="color:${c}">${d.severity}</div><div class="l">Severity</div></div></div>${ph}<div class="recbox"><h4>Recommendations</h4>${rh}</div>`;
  div.style.display='block';
}

// CODE SCANNER
function onFile(input){
  selFile=input.files[0];
  if(selFile){document.getElementById('fn').textContent=selFile.name+' ('+(selFile.size/1024).toFixed(1)+' KB)';document.getElementById('fsel').style.display='block';document.getElementById('code-btn').style.display='block';}
}
function doCodeScan(){
  if(!selFile){alert('Select a file!');return;}
  const btn=document.getElementById('code-btn');
  btn.disabled=true;btn.textContent='⟳ Scanning...';
  document.getElementById('code-load').style.display='block';
  document.getElementById('code-res').style.display='none';
  const fd=new FormData();fd.append('file',selFile);
  fetch('/api/scan-code',{method:'POST',body:fd})
  .then(r=>r.json()).then(d=>{
    btn.disabled=false;btn.textContent='🧬 SCAN FOR VULNERABILITIES';
    document.getElementById('code-load').style.display='none';
    showCodeRes(d);
  }).catch(e=>{btn.disabled=false;btn.textContent='🧬 SCAN FOR VULNERABILITIES';document.getElementById('code-load').style.display='none';alert('Error: '+e);});
}
function showCodeRes(d){
  const div=document.getElementById('code-res');
  const c=sc(d.risk_score), f=d.findings||[];
  const s={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  f.forEach(x=>s[x.severity]=(s[x.severity]||0)+1);
  let fh=f.length>0?f.map(x=>`<div class="vc ${x.severity==='CRITICAL'?'c':x.severity==='HIGH'?'h':x.severity==='MEDIUM'?'m':'l2'}"><div class="vh"><span class="vn" style="color:${rc(x.severity)}">${x.name}</span><span style="color:#666;font-size:10px">${x.id} — ${x.severity}</span></div><div style="font-size:12px;color:#aaa">${x.desc}</div>${x.code?`<div class="vcode">${x.code}</div>`:''}<div class="vloc">📄 ${x.file} — Line ${x.line}</div></div>`).join(''):'<div style="color:#00ff88;padding:14px;font-size:13px">✅ No vulnerabilities found! Code looks secure.</div>';
  div.innerHTML=`<div class="rhdr"><div><div class="rip">🧬 ${d.filename}</div><div class="rmeta">Files scanned: ${d.files_scanned} | Issues found: ${f.length}</div></div><div><div class="bscore" style="color:${c}">${d.risk_score}/100</div><div style="color:${c};font-size:11px;text-align:right">${d.severity}</div></div></div><div class="igrid"><div class="it"><div class="v" style="color:#ff4444">${s.CRITICAL||0}</div><div class="l">Critical</div></div><div class="it"><div class="v" style="color:#ff8800">${s.HIGH||0}</div><div class="l">High</div></div><div class="it"><div class="v" style="color:#ffcc00">${s.MEDIUM||0}</div><div class="l">Medium</div></div><div class="it"><div class="v" style="color:#00ff88">${s.LOW||0}</div><div class="l">Low</div></div></div><div class="stitle">Vulnerabilities Found</div>${fh}`;
  div.style.display='block';
}

// THREAT INTEL
function setType(t){
  itype=t;
  document.querySelectorAll('.tbtn').forEach(b=>b.classList.remove('active'));
  document.getElementById('t-'+t).classList.add('active');
  const ph={ip:'Enter IP address e.g. 8.8.8.8',domain:'Enter domain e.g. google.com',hash:'Enter MD5 or SHA256 hash'};
  document.getElementById('intel-in').placeholder=ph[t];
  const qb=document.getElementById('intel-qbtns');
  if(t==='ip') qb.innerHTML=`<button class="qb" onclick="qIntel('8.8.8.8')">Google DNS</button><button class="qb" onclick="qIntel('1.1.1.1')">Cloudflare</button><button class="qb" onclick="qIntel('192.168.221.129')">OWASP BWA</button>`;
  else if(t==='domain') qb.innerHTML=`<button class="qb" onclick="qIntel('google.com')">google.com</button><button class="qb" onclick="qIntel('malware.wicar.org')">malware test</button>`;
  else qb.innerHTML=`<button class="qb" onclick="qIntel('44d88612fea8a8f36de82e1278abb02f')">EICAR test</button>`;
}
function qIntel(v,t){if(t)setType(t);document.getElementById('intel-in').value=v;doIntel();}
function doIntel(){
  const target=document.getElementById('intel-in').value.trim();
  const btn=document.getElementById('intel-btn');
  if(!target){alert('Enter a target!');return;}
  btn.disabled=true;btn.textContent='⟳ Scanning...';
  document.getElementById('intel-load').style.display='block';
  document.getElementById('intel-res').style.display='none';
  fetch('/api/threat-intel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,type:itype})})
  .then(r=>r.json()).then(d=>{
    btn.disabled=false;btn.textContent='🔎 SCAN';
    document.getElementById('intel-load').style.display='none';
    showIntelRes(d);
    loadHist();
  }).catch(e=>{btn.disabled=false;btn.textContent='🔎 SCAN';document.getElementById('intel-load').style.display='none';alert('Error: '+e);});
}
function showIntelRes(d){
  const div=document.getElementById('intel-res');
  if(d.error){div.innerHTML=`<div style="color:#ff4444;padding:14px;background:#1a0000;border-radius:8px;border:1px solid #ff4444">❌ ${d.error}</div>`;div.style.display='block';return;}
  const c=ic(d.severity), mr=d.total>0?Math.round(d.malicious/d.total*100):0;
  let eh=d.malicious_engines&&d.malicious_engines.length>0?`<div class="stitle" style="margin-top:14px">🚨 Engines Flagging as Malicious</div><div class="elist">${d.malicious_engines.map(e=>`<div class="ei"><span style="color:#ff4444">⛔</span> <b style="color:#ff4444">${e.engine}</b><br><span style="color:#888;font-size:10px">${e.result}</span></div>`).join('')}</div>`:'';
  let ex='';
  if(d.country) ex+=`<div style="font-size:12px;color:#aaa;margin-top:7px">🌍 Country: <span style="color:#e0e0e0">${d.country}</span></div>`;
  if(d.owner)   ex+=`<div style="font-size:12px;color:#aaa">🏢 Owner: <span style="color:#e0e0e0">${d.owner}</span></div>`;
  if(d.registrar) ex+=`<div style="font-size:12px;color:#aaa">📋 Registrar: <span style="color:#e0e0e0">${d.registrar}</span></div>`;
  if(d.file_name) ex+=`<div style="font-size:12px;color:#aaa">📄 File: <span style="color:#e0e0e0">${d.file_name}</span></div>`;
  let rh=d.malicious>0?`<div class="ri">⚠ ${d.malicious} of ${d.total} engines flagged this (${mr}%)</div><div class="ri">• Do NOT interact with this target</div><div class="ri">• Block on your firewall immediately</div>`:'<div class="ri">✅ No engines flagged this as malicious</div><div class="ri">• Target appears clean based on global intelligence</div>';
  div.innerHTML=`<div class="vbox" style="border-color:${c}"><div style="font-size:30px;font-weight:bold;color:${c}">${d.severity}</div><div style="color:#aaa;font-size:13px;margin-top:5px">${d.target}</div><div style="color:#666;font-size:11px;margin-top:3px">${d.scanned_at}</div></div><div class="estats"><div class="es"><div class="v" style="color:#ff4444">${d.malicious}</div><div class="l">Malicious</div></div><div class="es"><div class="v" style="color:#ffcc00">${d.suspicious}</div><div class="l">Suspicious</div></div><div class="es"><div class="v" style="color:#00ff88">${d.harmless}</div><div class="l">Harmless</div></div><div class="es"><div class="v">${d.total}</div><div class="l">Total Engines</div></div></div>${ex}${eh}<div class="recbox" style="margin-top:12px"><h4>Analysis</h4>${rh}</div>`;
  div.style.display='block';
}
function loadHist(){
  fetch('/api/intel-history').then(r=>r.json()).then(data=>{
    if(!data.length) return;
    document.getElementById('intel-hist').style.display='block';
    document.getElementById('intel-hlist').innerHTML=data.slice(-8).reverse().map(s=>{
      const c=ic(s.severity);
      return`<div class="hi"><div><span style="color:#00aaff">${s.type.toUpperCase()}</span>: <span style="color:#e0e0e0">${s.target}</span><div style="color:#666;font-size:10px;margin-top:2px">${s.scanned_at}</div></div><div style="text-align:right"><div style="color:${c};font-weight:bold">${s.severity}</div><div style="color:#666;font-size:10px">${s.malicious}/${s.total} engines</div></div></div>`;
    }).join('');
  }).catch(()=>{});
}
</script>
</body></html>"""

LOGIN_HTML = """<!DOCTYPE html><html><head><title>ThreatWatch AI</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0a0e1a;font-family:'Courier New',monospace;display:flex;justify-content:center;align-items:center;min-height:100vh}.box{background:#0d1b2a;border:1px solid #1a3a5c;border-radius:12px;padding:40px;width:380px;text-align:center}.logo{font-size:40px;margin-bottom:10px}h1{color:#00ff88;font-size:18px;letter-spacing:2px;margin-bottom:6px}.sub{color:#666;font-size:11px;letter-spacing:1px;margin-bottom:30px}.fg{margin-bottom:16px;text-align:left}label{display:block;color:#00aaff;font-size:11px;letter-spacing:1px;margin-bottom:6px;text-transform:uppercase}input{width:100%;padding:12px 14px;background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;color:#e0e0e0;font-family:'Courier New',monospace;font-size:13px;outline:none}input:focus{border-color:#00aaff}.btn{width:100%;padding:12px;background:#00aaff;color:#0a0e1a;border:none;border-radius:6px;font-size:13px;font-weight:bold;font-family:'Courier New',monospace;letter-spacing:2px;cursor:pointer;margin-top:10px}.btn:hover{background:#00ff88}.err{background:#3d0000;border:1px solid #ff4444;color:#ff4444;padding:10px;border-radius:6px;font-size:12px;margin-bottom:16px}hr{border:none;border-top:1px solid #1a3a5c;margin:24px 0}.hint{color:#444;font-size:10px;margin-top:12px}.footer{color:#333;font-size:10px;margin-top:20px}</style>
</head><body><div class="box"><div class="logo">🛡</div><h1>THREATWATCH AI</h1><div class="sub">SECURITY PORTAL v3.0</div>
{% if error %}<div class="err">⛔ {{ error }}</div>{% endif %}
<form method="POST" action="/login"><div class="fg"><label>Username</label><input type="text" name="username" placeholder="Enter username" required autofocus></div><div class="fg"><label>Password</label><input type="password" name="password" placeholder="Enter password" required></div><button type="submit" class="btn">🔐 SECURE LOGIN</button></form>
<hr><div class="hint">admin / admin123 &nbsp;|&nbsp; zaynab / stmu2026</div><div class="footer">STMU BSCYS-III | CS2141 AI | 2026</div></div></body></html>"""

@app.route("/")
@login_required
def dashboard():
    threats=[]
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE,"r") as f: threats=json.load(f)
    total=len(threats)
    blocked=sum(1 for t in threats if t["action_taken"]=="IP Blocked")
    alerts=sum(1 for t in threats if t["action_taken"]=="Alert Sent")
    avg_score=round(sum(t["risk_score"] for t in threats)/total) if total>0 else 0
    return render_template_string(PAGE,threats=threats,total=total,blocked=blocked,
                                  alerts=alerts,avg_score=avg_score,
                                  username=session.get("username"),role=session.get("role"))

@app.route("/api/scan-ip",methods=["POST"])
@login_required
def api_scan_ip():
    data=request.get_json(); ip=data.get("ip","").strip()
    if not ip: return jsonify({"error":"No IP"}),400
    hostname=get_hostname(ip)
    try:
        r=subprocess.run(["ping","-n","1","-w","1000",ip],capture_output=True,text=True,timeout=5)
        is_alive="TTL=" in r.stdout
    except: is_alive=False
    ports=scan_ports(ip); risk=calc_network_risk(ports); sev=get_severity(risk)
    pi={p:DANGEROUS_PORTS.get(p,{"service":"Unknown","risk":"LOW","reason":"Unknown"}) for p in ports}
    return jsonify({"ip":ip,"hostname":hostname,"is_alive":is_alive,"open_ports":ports,
                    "port_info":pi,"risk_score":risk,"severity":sev,
                    "scanned_at":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

@app.route("/api/scan-code",methods=["POST"])
@login_required
def api_scan_code():
    if "file" not in request.files: return jsonify({"error":"No file"}),400
    file=request.files["file"]; fname=secure_filename(file.filename)
    fpath=os.path.join(UPLOAD_DIR,fname); file.save(fpath)
    ext=os.path.splitext(fname)[1].lower()
    if ext==".zip":
        findings,files,err=scan_zip(fpath)
        if err: return jsonify({"error":err}),400
    else:
        with open(fpath,"r",errors="ignore") as f: content=f.read()
        findings=scan_code(content,fname); files=[fname]
    risk=calc_code_risk(findings); sev=get_severity(risk)
    try: os.remove(fpath)
    except: pass
    return jsonify({"filename":fname,"files_scanned":len(files),"findings":findings,"risk_score":risk,"severity":sev})

@app.route("/api/threat-intel",methods=["POST"])
@login_required
def api_threat_intel():
    data=request.get_json(); target=data.get("target","").strip(); itype=data.get("type","ip")
    if not target: return jsonify({"error":"No target"}),400
    try:
        with vt.Client(THREAT_INTEL_API) as client:
            if itype=="ip":
                obj=client.get_object(f"/ip_addresses/{target}")
                extra={"country":getattr(obj,"country","Unknown"),"owner":getattr(obj,"as_owner","Unknown")}
            elif itype=="domain":
                obj=client.get_object(f"/domains/{target}")
                extra={"registrar":getattr(obj,"registrar","Unknown")}
            else:
                obj=client.get_object(f"/files/{target}")
                extra={"file_name":getattr(obj,"meaningful_name","Unknown"),"file_type":getattr(obj,"type_description","Unknown")}
            stats=obj.last_analysis_stats
            mal=stats.get("malicious",0); sus=stats.get("suspicious",0)
            har=stats.get("harmless",0); und=stats.get("undetected",0)
            total=mal+sus+har+und; sev=get_intel_severity(mal,total)
            engines=[]
            for eng,res in obj.last_analysis_results.items():
                if res.get("category")=="malicious":
                    engines.append({"engine":eng,"result":res.get("result","malicious")})
                if len(engines)>=20: break
            result={"target":target,"type":itype,"malicious":mal,"suspicious":sus,
                    "harmless":har,"undetected":und,"total":total,"severity":sev,
                    "malicious_engines":engines,
                    "scanned_at":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),**extra}
            existing=[]
            if os.path.exists(INTEL_LOG):
                with open(INTEL_LOG,"r") as f: existing=json.load(f)
            existing.append({"type":itype,"target":target,"malicious":mal,"suspicious":sus,
                             "total":total,"severity":sev,"scanned_at":result["scanned_at"]})
            with open(INTEL_LOG,"w") as f: json.dump(existing,f,indent=4)
            return jsonify(result)
    except vt.error.APIError as e: return jsonify({"error":f"API Error: {str(e)}"}),400
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/api/intel-history")
@login_required
def api_intel_history():
    if not os.path.exists(INTEL_LOG): return jsonify([])
    with open(INTEL_LOG,"r") as f: return jsonify(json.load(f))

@app.route("/login",methods=["GET","POST"])
def login():
    error=None
    if request.method=="POST":
        u=request.form.get("username","").strip(); p=request.form.get("password","")
        if u in USERS and check_password_hash(USERS[u]["password"],p):
            session["username"]=u; session["role"]=USERS[u]["role"]
            return redirect(url_for("dashboard"))
        error="Invalid username or password."
    return render_template_string(LOGIN_HTML,error=error)

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

if __name__=="__main__":
    print("="*55)
    print("  ThreatWatch AI — Security Portal v3.0")
    print("="*55)
    print("\n  !! Add your API key on line 23 !!")
    print("  THREAT_INTEL_API = 'your_key_here'")
    print("\n  Open: http://127.0.0.1:5000")
    print("  Login: admin/admin123 or zaynab/stmu2026")
    print("\n  5 Tabs: Dashboard | IP Scanner |")
    print("  Code Scanner | Threat Intel | Threat Log")
    print("="*55)
    app.run(debug=False)