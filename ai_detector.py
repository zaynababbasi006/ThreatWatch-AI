# ============================================
# ThreatWatch AI - AI Detector
# ============================================
# This is the MACHINE LEARNING part of your project.
# It trains an AI model on network traffic data
# and predicts whether new traffic is an attack or not.
#
# This uses Random Forest - a popular ML algorithm
# that works like many decision trees voting together.
# ============================================

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import numpy as np

# -----------------------------------------------
# STEP 1: CREATE TRAINING DATA
# -----------------------------------------------
# In a real system this would come from real network traffic.
# For now we simulate it. Each row = one network event.
#
# Features we track for each event:
#   [packets_per_sec, bytes_per_sec, duration, failed_logins, port_number]
#
# Label (what it actually is):
#   0 = Normal traffic (safe)
#   1 = Attack (dangerous)

def create_training_data():
    """Creates simulated network traffic data for training."""

    print("Creating training data...")

    # Normal traffic samples (safe)
    # Low packets, low bytes, normal ports
    normal_traffic = [
        [50,   5000,  2.5, 0, 80],
        [45,   4500,  3.0, 0, 443],
        [60,   6000,  1.8, 0, 22],
        [30,   3000,  4.0, 0, 80],
        [55,   5500,  2.0, 0, 443],
        [40,   4000,  3.5, 0, 8080],
        [35,   3500,  2.8, 0, 80],
        [48,   4800,  1.5, 0, 443],
        [52,   5200,  3.2, 0, 22],
        [42,   4200,  2.1, 0, 80],
        [38,   3800,  4.5, 0, 443],
        [65,   6500,  1.2, 0, 80],
        [25,   2500,  5.0, 0, 443],
        [70,   7000,  0.8, 0, 22],
        [44,   4400,  3.8, 0, 80],
    ]

    # Attack traffic samples (dangerous)
    # High packets/bytes = DDoS, many failed logins = brute force
    attack_traffic = [
        [9000,  900000, 0.1, 0,  80],    # DDoS
        [8500,  850000, 0.2, 0,  443],   # DDoS
        [7000,  700000, 0.1, 0,  80],    # DDoS
        [100,   10000,  0.5, 50, 22],    # Brute Force SSH
        [80,    8000,   0.4, 45, 22],    # Brute Force SSH
        [90,    9000,   0.3, 60, 3389],  # Brute Force RDP
        [200,   50000,  0.2, 0,  1433],  # SQL Injection
        [150,   40000,  0.3, 0,  3306],  # SQL Injection
        [5000,  500000, 0.1, 0,  80],    # DDoS
        [300,   30000,  0.2, 0,  4444],  # Malware
        [250,   25000,  0.3, 0,  6666],  # Malware
        [120,   12000,  0.1, 55, 22],    # Brute Force
        [6000,  600000, 0.1, 0,  443],   # DDoS
        [180,   18000,  0.4, 0,  8888],  # Port Scan
        [400,   40000,  0.2, 0,  9999],  # Suspicious
    ]

    # Combine data and create labels
    X = np.array(normal_traffic + attack_traffic)
    y = np.array([0]*15 + [1]*15)   # 0=normal, 1=attack

    return X, y


# -----------------------------------------------
# STEP 2: TRAIN THE AI MODEL
# -----------------------------------------------
def train_model():
    """Trains the Random Forest model and shows accuracy."""

    # Get training data
    X, y = create_training_data()

    # Split into training set (80%) and testing set (20%)
    # This is how we check if the AI actually learned correctly
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Create and train the Random Forest model
    # n_estimators=100 means 100 decision trees vote together
    print("Training AI model (Random Forest)...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Test how accurate it is
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions) * 100

    print(f"\n✅ Model trained successfully!")
    print(f"   Accuracy: {accuracy:.1f}%")
    print(f"   Training samples: {len(X_train)}")
    print(f"   Testing samples:  {len(X_test)}")

    return model


# -----------------------------------------------
# STEP 3: USE THE MODEL TO DETECT ATTACKS
# -----------------------------------------------
def detect_threat(model, packets_per_sec, bytes_per_sec, duration, failed_logins, port):
    """
    Give it network traffic numbers, it tells you if it's an attack.

    packets_per_sec = how many packets per second
    bytes_per_sec   = how many bytes per second
    duration        = how long the connection lasted
    failed_logins   = number of failed login attempts
    port            = which port was used
    """

    # Put the numbers into the format the model expects
    traffic = np.array([[packets_per_sec, bytes_per_sec, duration, failed_logins, port]])

    # Ask the model: is this normal or an attack?
    prediction = model.predict(traffic)[0]

    # Get confidence percentage (how sure is the AI?)
    confidence = model.predict_proba(traffic)[0]
    confidence_pct = max(confidence) * 100

    if prediction == 1:
        result = "ATTACK DETECTED"
    else:
        result = "Normal Traffic"

    return prediction, confidence_pct, result


# -----------------------------------------------
# TEST: Run the full AI pipeline
# -----------------------------------------------
if __name__ == "__main__":

    print("=" * 50)
    print("  ThreatWatch AI - AI Detector")
    print("=" * 50)

    # Train the model
    model = train_model()

    # Now test it on new traffic it has never seen
    print("\n--- Testing AI on new network traffic ---\n")

    test_cases = [
        # (packets/s, bytes/s,   duration, failed_logins, port,  description)
        (50,    5000,   2.5, 0,  80,   "Normal web browsing"),
        (9500,  950000, 0.1, 0,  80,   "Possible DDoS attack"),
        (75,    7500,   0.5, 48, 22,   "Brute force SSH login"),
        (40,    4000,   3.0, 0,  443,  "Normal HTTPS traffic"),
        (300,   30000,  0.2, 0,  4444, "Malware connection"),
    ]

    for packets, bytess, duration, logins, port, description in test_cases:
        pred, confidence, result = detect_threat(model, packets, bytess, duration, logins, port)
        symbol = "🚨" if pred == 1 else "✅"
        print(f"{symbol} {description}")
        print(f"   Result: {result} | Confidence: {confidence:.1f}%")
        print()