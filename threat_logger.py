import datetime
import json
import os

# This file saves detected threats to a log file
LOG_FILE = "logs/threats.json"

def log_threat(ip_address, threat_type, risk_score, action_taken):
    """
    Saves a detected threat to our log file.
    Every threat gets: IP, type, score, action, and timestamp.
    """

    # Create the threat record
    threat = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address": ip_address,
        "threat_type": threat_type,
        "risk_score": risk_score,
        "action_taken": action_taken
    }

    # Load existing logs (or start fresh if file doesnt exist)
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            all_threats = json.load(f)
    else:
        all_threats = []

    # Add new threat and save to file
    all_threats.append(threat)
    with open(LOG_FILE, "w") as f:
        json.dump(all_threats, f, indent=4)

    print(f"[ALERT] {threat_type} from {ip_address} | Risk Score: {risk_score} | Action: {action_taken}")


def view_all_threats():
    """Shows all logged threats on screen."""
    if not os.path.exists(LOG_FILE):
        print("No threats logged yet.")
        return

    with open(LOG_FILE, "r") as f:
        all_threats = json.load(f)

    print(f"\n--- ThreatWatch AI: {len(all_threats)} threats detected ---")
    for t in all_threats:
        print(f"  [{t['timestamp']}] {t['threat_type']} from {t['ip_address']} | Score: {t['risk_score']} | {t['action_taken']}")


# TEST: simulate 3 fake threats to make sure everything works
if __name__ == "__main__":
    log_threat("192.168.1.105", "DDoS Attack",       92, "IP Blocked")
    log_threat("10.0.0.44",     "Brute Force Login", 65, "Alert Sent")
    log_threat("172.16.8.22",   "SQL Injection",     78, "IP Blocked")
    view_all_threats()