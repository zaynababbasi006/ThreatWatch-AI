# ============================================
# ThreatWatch AI - Threat Predictor
# ============================================
# This uses Machine Learning to analyze past
# attack patterns and predict what type of
# attack is most likely to happen next.
#
# This is predictive AI — not just detecting
# attacks but FORECASTING them before they hit.
# ============================================

from sklearn.naive_bayes import MultinomialNB
from sklearn.preprocessing import LabelEncoder
import json
import os
import numpy as np
from collections import Counter
import datetime

LOG_FILE = "logs/threats.json"

# ============================================
# STEP 1: LOAD REAL THREAT HISTORY
# ============================================
def load_threat_history():
    """Load all past threats from our log file."""
    if not os.path.exists(LOG_FILE):
        print("No threat history found. Run main.py first!")
        return []
    with open(LOG_FILE, "r") as f:
        return json.load(f)


# ============================================
# STEP 2: ANALYZE ATTACK PATTERNS
# ============================================
def analyze_patterns(threats):
    """
    Looks at threat history and finds patterns:
    - Which attacks happen most often?
    - What time of day do attacks peak?
    - Which IPs are repeat offenders?
    - What usually comes after a port scan?
    """

    if not threats:
        return None

    print("\n" + "="*55)
    print("  ATTACK PATTERN ANALYSIS")
    print("="*55)

    # Count threat types
    threat_types = [t["threat_type"].split("(")[0].strip() for t in threats]
    type_counts  = Counter(threat_types)

    print("\n  Most frequent attacks:")
    for threat, count in type_counts.most_common(5):
        bar = "█" * count
        print(f"  {threat:<30} {bar} ({count})")

    # Count by hour
    hours = []
    for t in threats:
        try:
            hour = int(t["timestamp"].split(" ")[1].split(":")[0])
            hours.append(hour)
        except:
            pass

    if hours:
        hour_counts = Counter(hours)
        peak_hour   = hour_counts.most_common(1)[0][0]
        print(f"\n  Peak attack hour: {peak_hour}:00 - {peak_hour+1}:00")

    # Repeat offender IPs
    ips = [t["ip_address"] for t in threats]
    ip_counts = Counter(ips)
    print(f"\n  Top attacker IPs:")
    for ip, count in ip_counts.most_common(3):
        print(f"  {ip:<20} → {count} attacks")

    # Average risk score
    avg = sum(t["risk_score"] for t in threats) / len(threats)
    print(f"\n  Average risk score: {avg:.1f}/100")

    # Critical threat count
    critical = sum(1 for t in threats if t["risk_score"] >= 90)
    print(f"  Critical threats:   {critical}")

    return type_counts


# ============================================
# STEP 3: PREDICT NEXT ATTACK
# ============================================
def predict_next_attack(threats):
    """
    Uses Naive Bayes classifier to predict
    what attack is most likely to come next
    based on the sequence of past attacks.
    """

    if len(threats) < 3:
        print("Need more threat history to predict.")
        return

    print("\n" + "="*55)
    print("  AI THREAT PREDICTION ENGINE")
    print("="*55)

    # Get sequence of threat types
    sequence = [t["threat_type"].split("(")[0].strip() for t in threats]

    # Encode threat types as numbers
    le = LabelEncoder()
    le.fit(sequence)
    encoded = le.transform(sequence)

    # Build training data:
    # X = current threat, y = next threat
    X = encoded[:-1].reshape(-1, 1)
    y = encoded[1:]

    # Shift values to make non-negative for MultinomialNB
    X_shifted = X - X.min()

    # Train Naive Bayes model
    model = MultinomialNB()
    model.fit(X_shifted, y)

    # Predict what comes after the LAST known attack
    last_attack    = encoded[-1]
    last_shifted   = last_attack - X.min()
    prediction_enc = model.predict([[last_shifted]])[0]
    predicted_type = le.inverse_transform([prediction_enc])[0]

    # Get confidence
    proba      = model.predict_proba([[last_shifted]])[0]
    confidence = max(proba) * 100

    # Get risk info for predicted attack
    from risk_engine import analyze_threat
    risk = analyze_threat(predicted_type)

    print(f"\n  Last detected attack : {sequence[-1]}")
    print(f"\n  🔮 PREDICTED NEXT ATTACK:")
    print(f"  Type       : {predicted_type}")
    print(f"  Confidence : {confidence:.1f}%")
    print(f"  Risk Score : {risk['risk_score']}/100")
    print(f"  Severity   : {risk['severity']}")
    print(f"  Likely Action: {risk['action']}")

    print(f"\n  ⚠  RECOMMENDATION:")
    if risk["risk_score"] >= 70:
        print(f"  Prepare firewall rules NOW — high risk attack predicted!")
    elif risk["risk_score"] >= 40:
        print(f"  Increase monitoring — medium risk attack incoming.")
    else:
        print(f"  Low risk predicted — continue normal monitoring.")

    return predicted_type, confidence


# ============================================
# STEP 4: THREAT FORECAST REPORT
# ============================================
def generate_forecast(threats):
    """Shows a full forecast of likely upcoming threats."""

    print("\n" + "="*55)
    print("  24-HOUR THREAT FORECAST")
    print("="*55)

    # Based on historical patterns suggest what to watch for
    threat_types = [t["threat_type"].split("(")[0].strip() for t in threats]
    type_counts  = Counter(threat_types)

    forecasts = []
    total = len(threats)

    for threat, count in type_counts.most_common():
        probability = (count / total) * 100
        forecasts.append((threat, probability))

    print(f"\n  {'Threat Type':<30} {'Probability':>12} {'Watch Level':>12}")
    print("  " + "-"*55)

    for threat, prob in forecasts[:6]:
        if prob >= 30:
            level = "🔴 HIGH"
        elif prob >= 15:
            level = "🟡 MEDIUM"
        else:
            level = "🟢 LOW"
        print(f"  {threat:<30} {prob:>10.1f}%  {level:>12}")

    print("\n  Forecast generated at:",
          datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


# ============================================
# RUN EVERYTHING
# ============================================
if __name__ == "__main__":

    print("\n" + "="*55)
    print("  ThreatWatch AI — Threat Predictor")
    print("  Powered by Naive Bayes ML Algorithm")
    print("="*55)

    # Load threat history
    threats = load_threat_history()

    if not threats:
        print("No data found! Run main.py first.")
    else:
        print(f"\n  Analyzing {len(threats)} historical threats...")

        # Analyze patterns
        analyze_patterns(threats)

        # Predict next attack
        predict_next_attack(threats)

        # Generate forecast
        generate_forecast(threats)

        print("\n" + "="*55)
        print("  Prediction complete!")
        print("="*55)