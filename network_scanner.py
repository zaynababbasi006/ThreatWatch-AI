# ============================================
# ThreatWatch AI - Network Scanner
# ============================================
# Type any IP address and this will:
#   - Scan all open ports
#   - Identify running services
#   - Check for vulnerabilities
#   - Give a risk score
#   - Recommend actions
# ============================================

import subprocess
import socket
import datetime
import json
import os
from risk_engine import get_severity

# ============================================
# DANGEROUS PORTS DATABASE
# Ports commonly used by attackers
# ============================================
DANGEROUS_PORTS = {
    21:   {"service": "FTP",           "risk": "HIGH",   "reason": "FTP transmits data in plaintext — easy to intercept"},
    22:   {"service": "SSH",           "risk": "MEDIUM", "reason": "Brute force attacks common on SSH"},
    23:   {"service": "Telnet",        "risk": "CRITICAL","reason": "Telnet is completely unencrypted — never use"},
    25:   {"service": "SMTP",          "risk": "MEDIUM", "reason": "Can be used for spam/phishing relay"},
    53:   {"service": "DNS",           "risk": "MEDIUM", "reason": "DNS amplification attacks possible"},
    80:   {"service": "HTTP",          "risk": "MEDIUM", "reason": "Unencrypted web traffic"},
    110:  {"service": "POP3",          "risk": "HIGH",   "reason": "Email protocol — transmits passwords in plaintext"},
    135:  {"service": "RPC",           "risk": "HIGH",   "reason": "Windows RPC — commonly exploited"},
    139:  {"service": "NetBIOS",       "risk": "HIGH",   "reason": "Used in many Windows attacks"},
    143:  {"service": "IMAP",          "risk": "MEDIUM", "reason": "Email protocol vulnerability"},
    443:  {"service": "HTTPS",         "risk": "LOW",    "reason": "Encrypted web — generally safe"},
    445:  {"service": "SMB",           "risk": "CRITICAL","reason": "EternalBlue/WannaCry exploit target!"},
    1433: {"service": "MSSQL",         "risk": "HIGH",   "reason": "Database exposed to network"},
    1521: {"service": "Oracle DB",     "risk": "HIGH",   "reason": "Database exposed to network"},
    3306: {"service": "MySQL",         "risk": "HIGH",   "reason": "Database should never be public"},
    3389: {"service": "RDP",           "risk": "CRITICAL","reason": "Remote Desktop — major brute force target"},
    4444: {"service": "Metasploit",    "risk": "CRITICAL","reason": "Default Metasploit backdoor port!"},
    5900: {"service": "VNC",           "risk": "HIGH",   "reason": "Remote desktop — often unencrypted"},
    6666: {"service": "Malware C2",    "risk": "CRITICAL","reason": "Commonly used by malware command & control"},
    8080: {"service": "HTTP Alt",      "risk": "MEDIUM", "reason": "Alternative HTTP — check for misconfigs"},
    8443: {"service": "HTTPS Alt",     "risk": "LOW",    "reason": "Alternative HTTPS"},
    9200: {"service": "Elasticsearch", "risk": "HIGH",   "reason": "Often exposed without authentication"},
    27017:{"service": "MongoDB",       "risk": "CRITICAL","reason": "MongoDB often exposed without password!"},
}

# ============================================
# QUICK PORT SCANNER (no nmap needed)
# ============================================
def scan_ports_basic(ip, ports=None, timeout=1):
    """
    Scans common ports on an IP address.
    Returns list of open ports.
    """
    if ports is None:
        # Most important ports to check
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139,
                 143, 443, 445, 1433, 3306, 3389, 4444,
                 5900, 6666, 8080, 8443, 8081, 9200]

    open_ports = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass

    return open_ports


# ============================================
# GET HOSTNAME
# ============================================
def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return "Unknown"


# ============================================
# CALCULATE RISK SCORE FROM OPEN PORTS
# ============================================
def calculate_network_risk(open_ports):
    """Calculate overall risk score based on open ports."""
    score   = 0
    reasons = []

    for port in open_ports:
        if port in DANGEROUS_PORTS:
            info = DANGEROUS_PORTS[port]
            if info["risk"] == "CRITICAL":
                score += 25
                reasons.append(f"Port {port} ({info['service']}) — CRITICAL")
            elif info["risk"] == "HIGH":
                score += 15
                reasons.append(f"Port {port} ({info['service']}) — HIGH RISK")
            elif info["risk"] == "MEDIUM":
                score += 8
                reasons.append(f"Port {port} ({info['service']}) — MEDIUM")
            else:
                score += 2

    return min(score, 100), reasons


# ============================================
# FULL IP SCAN
# ============================================
def scan_ip(ip_address):
    """
    Complete network scan of an IP address.
    Shows all open ports, services, risks.
    """

    print("\n" + "="*60)
    print("  ThreatWatch AI — Network Scanner")
    print("="*60)
    print(f"  Target IP  : {ip_address}")
    print(f"  Scan Time  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Get hostname
    print(f"\n  [1/4] Resolving hostname...")
    hostname = get_hostname(ip_address)
    print(f"        Hostname: {hostname}")

    # Ping check
    print(f"\n  [2/4] Checking if host is alive...")
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "1000", ip_address],
            capture_output=True, text=True, timeout=5
        )
        is_alive = "TTL=" in result.stdout
    except:
        is_alive = False

    if is_alive:
        print(f"        ✅ Host is ALIVE and responding")
    else:
        print(f"        ⚠  Host may be offline or blocking pings")

    # Port scan
    print(f"\n  [3/4] Scanning ports (this takes 10-20 seconds)...")
    open_ports = scan_ports_basic(ip_address)

    if open_ports:
        print(f"        Found {len(open_ports)} open ports!")
    else:
        print(f"        No open ports found on common ports")

    # Risk assessment
    print(f"\n  [4/4] Analyzing vulnerabilities...")
    risk_score, risk_reasons = calculate_network_risk(open_ports)

    # ---- PRINT FULL REPORT ----
    print("\n" + "="*60)
    print("  NETWORK SCAN REPORT")
    print("="*60)
    print(f"  IP Address : {ip_address}")
    print(f"  Hostname   : {hostname}")
    print(f"  Status     : {'ONLINE' if is_alive else 'OFFLINE/FILTERED'}")
    print(f"  Open Ports : {len(open_ports)}")
    print(f"  Risk Score : {risk_score}/100")
    print(f"  Severity   : {get_severity(risk_score)}")

    if open_ports:
        print(f"\n  OPEN PORTS & SERVICES:")
        print(f"  {'Port':<8} {'Service':<20} {'Risk':<10} {'Details'}")
        print("  " + "-"*65)

        for port in open_ports:
            if port in DANGEROUS_PORTS:
                info    = DANGEROUS_PORTS[port]
                service = info["service"]
                risk    = info["risk"]
                reason  = info["reason"][:35]
            else:
                service = "Unknown"
                risk    = "LOW"
                reason  = "Unknown service"

            # Color indicator
            if risk == "CRITICAL":
                indicator = "🔴"
            elif risk == "HIGH":
                indicator = "🟠"
            elif risk == "MEDIUM":
                indicator = "🟡"
            else:
                indicator = "🟢"

            print(f"  {port:<8} {service:<20} {indicator} {risk:<8} {reason}")

    if risk_reasons:
        print(f"\n  TOP VULNERABILITIES:")
        for i, reason in enumerate(risk_reasons[:5], 1):
            print(f"  {i}. {reason}")

    # Recommendations
    print(f"\n  RECOMMENDATIONS:")
    if risk_score >= 70:
        print(f"  🚨 HIGH RISK TARGET — Immediate action required!")
        print(f"  • Close or firewall all non-essential ports")
        print(f"  • Check for unauthorized access immediately")
        print(f"  • Run full vulnerability assessment")
    elif risk_score >= 40:
        print(f"  ⚠  MEDIUM RISK — Review open services")
        print(f"  • Ensure all services are patched and updated")
        print(f"  • Consider closing unused ports")
    else:
        print(f"  ✅ LOW RISK — Network looks relatively secure")
        print(f"  • Continue regular monitoring")

    print("="*60)

    # Save result
    result = {
        "ip":         ip_address,
        "hostname":   hostname,
        "is_alive":   is_alive,
        "open_ports": open_ports,
        "risk_score": risk_score,
        "severity":   get_severity(risk_score),
        "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    save_scan(result)
    return result


def save_scan(result):
    """Save scan result to logs."""
    scan_log = "logs/network_scans.json"
    os.makedirs("logs", exist_ok=True)
    existing = []
    if os.path.exists(scan_log):
        with open(scan_log, "r") as f:
            existing = json.load(f)
    existing.append(result)
    with open(scan_log, "w") as f:
        json.dump(existing, f, indent=4)


# ============================================
# RUN
# ============================================
if __name__ == "__main__":

    print("\n" + "="*60)
    print("  ThreatWatch AI — Network Scanner")
    print("  Scans any IP for open ports & vulnerabilities")
    print("="*60)

    while True:
        print("\n  Options:")
        print("  1. Scan an IP address")
        print("  2. Scan OWASP BWA (192.168.221.129)")
        print("  3. Scan Kali Linux (192.168.221.128)")
        print("  4. Exit")

        choice = input("\n  Enter choice (1-4): ").strip()

        if choice == "1":
            ip = input("  Enter IP address: ").strip()
            scan_ip(ip)

        elif choice == "2":
            scan_ip("192.168.221.129")

        elif choice == "3":
            scan_ip("192.168.221.128")

        elif choice == "4":
            print("  Exiting Network Scanner.")
            break
        else:
            print("  Invalid choice!")