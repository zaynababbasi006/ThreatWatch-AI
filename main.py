# ============================================
# ThreatWatch AI - Main Controller
# ============================================
# This file connects everything together.
# It uses risk_engine.py to analyze threats
# and threat_logger.py to save them.
# ============================================

from risk_engine import analyze_threat
from threat_logger import log_threat, view_all_threats


def process_threat(ip_address, threat_type, extra_score=0):
    """
    Full pipeline for one threat:
    Step 1 - Analyze it (get score, severity, action)
    Step 2 - Log it to file
    Step 3 - Print result to screen
    """

    # Step 1: Analyze the threat
    result = analyze_threat(threat_type, extra_score)

    # Step 2: Log it
    log_threat(
        ip_address  = ip_address,
        threat_type = threat_type,
        risk_score  = result["risk_score"],
        action_taken= result["action"]
    )

    # Step 3: Show result nicely
    print(f"\n{'='*45}")
    print(f"  NEW THREAT DETECTED")
    print(f"{'='*45}")
    print(f"  IP Address : {ip_address}")
    print(f"  Threat     : {threat_type}")
    print(f"  Risk Score : {result['risk_score']}/100")
    print(f"  Severity   : {result['severity']}")
    print(f"  Action     : {result['action']}")
    print(f"{'='*45}")


# -----------------------------------------------
# SIMULATE: pretend these attacks just happened
# on our network right now
# -----------------------------------------------
if __name__ == "__main__":

    print("\n*** ThreatWatch AI - Starting Monitoring ***\n")

    # Simulate attacks coming in from different IPs
    process_threat("192.168.1.105", "DDoS Attack")
    process_threat("10.0.0.44",     "Brute Force Login")
    process_threat("172.16.8.22",   "SQL Injection")
    process_threat("192.168.1.200", "Ransomware",        extra_score=5)
    process_threat("10.0.0.99",     "Port Scan")
    process_threat("192.168.1.77",  "Phishing")

    # Show summary of everything logged
    print("\n\n*** FULL THREAT LOG SUMMARY ***")
    view_all_threats()