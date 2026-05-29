# ============================================
# ThreatWatch AI - Risk Scoring Engine
# ============================================
# This file looks at an attack and decides:
#   1. How dangerous is it? (risk score 0-100)
#   2. What should we do about it?
# ============================================

# Each threat type has a base danger level
THREAT_SCORES = {
    "DDoS Attack":       85,
    "Malware":           90,
    "Ransomware":        95,
    "Brute Force Login": 60,
    "SQL Injection":     75,
    "Phishing":          55,
    "Insider Threat":    70,
    "Port Scan":         40,
    "Unknown":           50
}

# Based on risk score, decide what action to take
# This matches exactly what your SRS says:
#   score >= 70  → Auto block IP
#   score >= 40  → Send alert
#   score < 40   → Just log it
def decide_action(risk_score):
    if risk_score >= 70:
        return "IP Blocked"
    elif risk_score >= 40:
        return "Alert Sent"
    else:
        return "Logged Only"

# Decide how serious the threat is (for the dashboard color)
def get_severity(risk_score):
    if risk_score >= 90:
        return "CRITICAL"
    elif risk_score >= 70:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    else:
        return "LOW"

# Main function: give it a threat type, it returns full analysis
def analyze_threat(threat_type, extra_score=0):
    """
    threat_type  = the type of attack (e.g. "DDoS Attack")
    extra_score  = bonus danger points (e.g. if attack repeated many times)
    """

    # Get base score for this threat type
    base_score = THREAT_SCORES.get(threat_type, 50)

    # Add extra points but never go above 100
    final_score = min(base_score + extra_score, 100)

    # Decide action and severity
    action   = decide_action(final_score)
    severity = get_severity(final_score)

    # Build the result
    result = {
        "threat_type": threat_type,
        "risk_score":  final_score,
        "severity":    severity,
        "action":      action
    }

    return result


# -----------------------------------------------
# TEST: analyze 4 different attack types
# -----------------------------------------------
if __name__ == "__main__":

    test_attacks = [
        "DDoS Attack",
        "Brute Force Login",
        "Ransomware",
        "Port Scan"
    ]

    print("=" * 50)
    print("  ThreatWatch AI - Risk Engine Test")
    print("=" * 50)

    for attack in test_attacks:
        result = analyze_threat(attack)
        print(f"\nThreat   : {result['threat_type']}")
        print(f"Score    : {result['risk_score']}/100")
        print(f"Severity : {result['severity']}")
        print(f"Action   : {result['action']}")
        print("-" * 30)