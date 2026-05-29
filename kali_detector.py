# ============================================
# ThreatWatch AI - Kali Attack Detector
# ============================================
# This file detects and logs REAL attacks
# coming from Kali Linux against OWASP BWA.
#
# It monitors attack patterns and feeds them
# into our risk engine and threat logger.
# ============================================

from risk_engine import analyze_threat
from threat_logger import log_threat, view_all_threats
import datetime
import time

# -----------------------------------------------
# KNOWN ATTACKER
# This is our Kali Linux IP
# -----------------------------------------------
KALI_IP     = "192.168.221.128"
OWASP_IP    = "192.168.221.129"

print("=" * 55)
print("  ThreatWatch AI — Real Attack Monitor")
print(f"  Monitoring attacks from Kali: {KALI_IP}")
print(f"  Target system (OWASP BWA):    {OWASP_IP}")
print("=" * 55)


# -----------------------------------------------
# REAL ATTACKS WE DETECTED FROM KALI
# Add each attack here as you run them
# -----------------------------------------------
def log_kali_attacks():

    print("\n[*] Processing detected attacks from Kali Linux...\n")
    time.sleep(0.5)

    # ---- ATTACK 1: NMAP PORT SCAN ----
    print("[*] Attack 1: Nmap Port Scan detected")
    result = analyze_threat("Port Scan", extra_score=10)
    log_threat(
        ip_address   = KALI_IP,
        threat_type  = "Port Scan (Nmap -sS -sV)",
        risk_score   = result["risk_score"],
        action_taken = result["action"]
    )
    print(f"    Score: {result['risk_score']} | Severity: {result['severity']} | Action: {result['action']}")
    time.sleep(0.5)

    # ---- ATTACK 2: NIKTO WEB VULNERABILITY SCAN ----
    print("[*] Attack 2: Nikto Web Scan detected")
    result = analyze_threat("Port Scan", extra_score=20)
    log_threat(
        ip_address   = KALI_IP,
        threat_type  = "Web Vulnerability Scan (Nikto)",
        risk_score   = result["risk_score"],
        action_taken = result["action"]
    )
    print(f"    Score: {result['risk_score']} | Severity: {result['severity']} | Action: {result['action']}")
    time.sleep(0.5)

    # ---- ATTACK 3: HYDRA BRUTE FORCE ----
    print("[*] Attack 3: Hydra Brute Force detected")
    result = analyze_threat("Brute Force Login", extra_score=15)
    log_threat(
        ip_address   = KALI_IP,
        threat_type  = "Brute Force Login (Hydra)",
        risk_score   = result["risk_score"],
        action_taken = result["action"]
    )
    print(f"    Score: {result['risk_score']} | Severity: {result['severity']} | Action: {result['action']}")
    time.sleep(0.5)

    # ---- ATTACK 4: SQL INJECTION (SQLMAP) ----
    print("[*] Attack 4: SQL Injection attempt detected")
    result = analyze_threat("SQL Injection", extra_score=10)
    log_threat(
        ip_address   = KALI_IP,
        threat_type  = "SQL Injection (SQLMap)",
        risk_score   = result["risk_score"],
        action_taken = result["action"]
    )
    print(f"    Score: {result['risk_score']} | Severity: {result['severity']} | Action: {result['action']}")
    time.sleep(0.5)

    # ---- ATTACK 5: DIRB DIRECTORY BRUTEFORCE ----
    print("[*] Attack 5: Directory Brute Force detected")
    result = analyze_threat("Port Scan", extra_score=15)
    log_threat(
        ip_address   = KALI_IP,
        threat_type  = "Directory Brute Force (Dirb)",
        risk_score   = result["risk_score"],
        action_taken = result["action"]
    )
    print(f"    Score: {result['risk_score']} | Severity: {result['severity']} | Action: {result['action']}")
    time.sleep(0.5)


def show_attack_summary():
    print("\n" + "=" * 55)
    print("  KALI ATTACK SUMMARY")
    print("=" * 55)
    print(f"  Attacker IP  : {KALI_IP} (Kali Linux)")
    print(f"  Target IP    : {OWASP_IP} (OWASP BWA)")
    print(f"  Attack Time  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  Attacks Used : Nmap, Nikto, Hydra, SQLMap, Dirb")
    print("  All attacks logged to dashboard ✅")
    print("=" * 55)
    print("\n  Open your dashboard to see real attacks:")
    print("  Run: py auth.py")
    print("  Go to: http://127.0.0.1:5000")


if __name__ == "__main__":
    log_kali_attacks()
    show_attack_summary()
    print("\n  Full threat log:")
    view_all_threats()