# ============================================
# ThreatWatch AI - Traffic Analyzer
# ============================================
# Analyzes network traffic patterns and
# identifies suspicious behavior in real time.
# Uses statistical analysis + ML scoring.
# ============================================

import random
import time
import datetime
import json
import os
from risk_engine import analyze_threat, get_severity
from threat_logger import log_threat

# ============================================
# TRAFFIC PROFILES
# Normal vs suspicious traffic patterns
# ============================================

NORMAL_TRAFFIC = [
    {"name": "Web Browse",    "packets": 50,   "bytes": 5000,  "port": 80,   "failed": 0},
    {"name": "HTTPS Browse",  "packets": 45,   "bytes": 4500,  "port": 443,  "failed": 0},
    {"name": "SSH Session",   "packets": 60,   "bytes": 6000,  "port": 22,   "failed": 0},
    {"name": "Email Check",   "packets": 30,   "bytes": 3000,  "port": 143,  "failed": 0},
    {"name": "DNS Lookup",    "packets": 10,   "bytes": 1000,  "port": 53,   "failed": 0},
]

ATTACK_TRAFFIC = [
    {"name": "DDoS Attack",        "packets": 9000, "bytes": 900000, "port": 80,   "failed": 0,  "threat": "DDoS Attack"},
    {"name": "Brute Force SSH",    "packets": 100,  "bytes": 10000,  "port": 22,   "failed": 50, "threat": "Brute Force Login"},
    {"name": "SQL Injection",      "packets": 200,  "bytes": 50000,  "port": 1433, "failed": 0,  "threat": "SQL Injection"},
    {"name": "Malware Beacon",     "packets": 300,  "bytes": 30000,  "port": 4444, "failed": 0,  "threat": "Malware"},
    {"name": "Port Scan",          "packets": 180,  "bytes": 18000,  "port": 9999, "failed": 0,  "threat": "Port Scan"},
    {"name": "Ransomware C2",      "packets": 400,  "bytes": 40000,  "port": 6666, "failed": 0,  "threat": "Ransomware"},
]

# ============================================
# TRAFFIC SCORING ENGINE
# ============================================
def score_traffic(packets, bytess, port, failed_logins):
    """
    Scores traffic as suspicious or normal.
    Returns score 0-100 and reason.
    """
    score   = 0
    reasons = []

    # High packet rate = possible DDoS
    if packets > 5000:
        score += 50
        reasons.append("Extremely high packet rate")
    elif packets > 1000:
        score += 30
        reasons.append("High packet rate")
    elif packets > 200:
        score += 15
        reasons.append("Elevated packet rate")

    # High byte rate
    if bytess > 500000:
        score += 25
        reasons.append("Massive data transfer")
    elif bytess > 100000:
        score += 15
        reasons.append("High data transfer")

    # Many failed logins = brute force
    if failed_logins > 30:
        score += 40
        reasons.append("Multiple failed login attempts")
    elif failed_logins > 10:
        score += 20
        reasons.append("Repeated failed logins")

    # Suspicious ports
    suspicious_ports = [4444, 6666, 9999, 8888, 1234, 31337]
    if port in suspicious_ports:
        score += 30
        reasons.append(f"Suspicious port {port}")

    return min(score, 100), reasons


def classify_traffic(score):
    """Classify traffic based on score."""
    if score >= 70:
        return "ATTACK", "🚨"
    elif score >= 40:
        return "SUSPICIOUS", "⚠️ "
    else:
        return "NORMAL", "✅"


def generate_random_ip():
    """Generate a random IP address."""
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"


# ============================================
# LIVE TRAFFIC MONITOR
# ============================================
def monitor_traffic(duration_seconds=30, log_attacks=True):
    """
    Simulates monitoring live network traffic.
    Analyzes each connection and flags threats.

    duration_seconds = how long to monitor
    log_attacks      = save detected attacks to log
    """

    print("\n" + "="*60)
    print("  ThreatWatch AI — Live Traffic Analyzer")
    print(f"  Monitoring for {duration_seconds} seconds...")
    print("  Press Ctrl+C to stop early")
    print("="*60)
    print(f"\n  {'Time':<10} {'IP':<18} {'Traffic Type':<22} {'Score':>6} {'Status'}")
    print("  " + "-"*70)

    start_time    = time.time()
    total_packets = 0
    attacks_found = 0
    normal_count  = 0

    try:
        while time.time() - start_time < duration_seconds:

            # 70% chance normal, 30% chance attack
            if random.random() < 0.7:
                traffic = random.choice(NORMAL_TRAFFIC).copy()
                # Add slight randomness
                traffic["packets"] += random.randint(-10, 10)
                traffic["bytes"]   += random.randint(-500, 500)
                is_attack = False
            else:
                traffic   = random.choice(ATTACK_TRAFFIC).copy()
                is_attack = True

            # Generate source IP
            src_ip = generate_random_ip()

            # Score the traffic
            score, reasons = score_traffic(
                traffic["packets"],
                traffic["bytes"],
                traffic["port"],
                traffic["failed"]
            )

            status, symbol = classify_traffic(score)
            now = datetime.datetime.now().strftime("%H:%M:%S")
            total_packets += traffic["packets"]

            # Print traffic line
            print(f"  {now:<10} {src_ip:<18} {traffic['name']:<22} {score:>5}  {symbol} {status}")

            # Log if attack detected
            if status == "ATTACK" and log_attacks:
                threat_type = traffic.get("threat", "Unknown")
                result      = analyze_threat(threat_type)
                log_threat(src_ip, threat_type, result["risk_score"], result["action"])
                attacks_found += 1
                if reasons:
                    print(f"  {'':>10} ↳ Reason: {', '.join(reasons[:2])}")
            else:
                normal_count += 1

            # Wait between packets
            time.sleep(random.uniform(0.3, 0.8))

    except KeyboardInterrupt:
        print("\n\n  [!] Monitoring stopped by user")

    # Summary
    elapsed = round(time.time() - start_time, 1)
    print("\n" + "="*60)
    print("  TRAFFIC ANALYSIS SUMMARY")
    print("="*60)
    print(f"  Duration        : {elapsed} seconds")
    print(f"  Total packets   : {total_packets:,}")
    print(f"  Attacks found   : {attacks_found}")
    print(f"  Normal traffic  : {normal_count}")
    if attacks_found + normal_count > 0:
        attack_rate = (attacks_found / (attacks_found + normal_count)) * 100
        print(f"  Attack rate     : {attack_rate:.1f}%")
    print("="*60)

    if attacks_found > 0:
        print(f"\n  ⚠  {attacks_found} attacks logged to dashboard!")
        print("  Run py auth.py and check http://127.0.0.1:5000")


# ============================================
# RUN
# ============================================
if __name__ == "__main__":
    print("\n" + "="*60)
    print("  ThreatWatch AI — Network Traffic Analyzer")
    print("  Statistical Analysis + ML Threat Scoring")
    print("="*60)

    # Monitor for 20 seconds
    monitor_traffic(duration_seconds=20, log_attacks=True)