
# ============================================
# ThreatWatch AI - Model Comparison
# ============================================
# This file trains 3 different AI models
# on the same network traffic data and
# compares which one is most accurate.
#
# Models we compare:
#   1. Random Forest
#   2. Support Vector Machine (SVM)
#   3. Neural Network (MLP)
#
# This is what makes your project stand out —
# you didn't just use one model, you tested
# three and picked the best one. That is
# exactly how real AI research works.
# ============================================

from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, confusion_matrix,
                             classification_report)
from sklearn.preprocessing import StandardScaler
import numpy as np
import json
import os

# -----------------------------------------------
# STEP 1: TRAINING DATA
# -----------------------------------------------
# Much bigger dataset than before — 60 samples
# Features: [packets_per_sec, bytes_per_sec, duration, failed_logins, port]
# Label: 0 = Normal, 1 = Attack

def create_dataset():
    print("Loading training dataset...")

    normal = [
        # packets/s  bytes/s   duration  failed  port
        [50,   5000,   2.5,  0,  80],
        [45,   4500,   3.0,  0,  443],
        [60,   6000,   1.8,  0,  22],
        [30,   3000,   4.0,  0,  80],
        [55,   5500,   2.0,  0,  443],
        [40,   4000,   3.5,  0,  8080],
        [35,   3500,   2.8,  0,  80],
        [48,   4800,   1.5,  0,  443],
        [52,   5200,   3.2,  0,  22],
        [42,   4200,   2.1,  0,  80],
        [38,   3800,   4.5,  0,  443],
        [65,   6500,   1.2,  0,  80],
        [25,   2500,   5.0,  0,  443],
        [70,   7000,   0.8,  0,  22],
        [44,   4400,   3.8,  0,  80],
        [58,   5800,   2.3,  0,  443],
        [33,   3300,   4.2,  0,  8080],
        [47,   4700,   1.9,  0,  80],
        [62,   6200,   2.7,  0,  443],
        [29,   2900,   3.6,  0,  22],
        [53,   5300,   1.4,  0,  80],
        [41,   4100,   2.9,  0,  443],
        [36,   3600,   3.3,  0,  80],
        [67,   6700,   1.1,  0,  443],
        [49,   4900,   2.6,  0,  22],
        [43,   4300,   3.9,  0,  80],
        [57,   5700,   1.7,  0,  443],
        [31,   3100,   4.8,  0,  8080],
        [64,   6400,   1.3,  0,  80],
        [46,   4600,   2.4,  0,  443],
    ]

    attacks = [
        # DDoS attacks — very high packets and bytes
        [9000,  900000, 0.1,  0,  80],
        [8500,  850000, 0.2,  0,  443],
        [7000,  700000, 0.1,  0,  80],
        [9500,  950000, 0.1,  0,  443],
        [8000,  800000, 0.2,  0,  80],
        [7500,  750000, 0.1,  0,  443],
        [6000,  600000, 0.1,  0,  80],
        [9200,  920000, 0.1,  0,  8080],
        # Brute force — many failed logins
        [100,   10000,  0.5,  50, 22],
        [80,    8000,   0.4,  45, 22],
        [90,    9000,   0.3,  60, 3389],
        [110,   11000,  0.6,  55, 22],
        [95,    9500,   0.4,  48, 3389],
        [85,    8500,   0.5,  52, 22],
        [105,   10500,  0.3,  58, 3389],
        [75,    7500,   0.6,  47, 22],
        # SQL Injection — medium traffic, suspicious ports
        [200,   50000,  0.2,  0,  1433],
        [150,   40000,  0.3,  0,  3306],
        [180,   45000,  0.2,  0,  1433],
        [160,   42000,  0.3,  0,  3306],
        [190,   48000,  0.2,  0,  1433],
        [170,   43000,  0.3,  0,  3306],
        # Malware — suspicious ports, high bytes
        [300,   30000,  0.2,  0,  4444],
        [250,   25000,  0.3,  0,  6666],
        [280,   28000,  0.2,  0,  4444],
        [260,   26000,  0.3,  0,  6666],
        [320,   32000,  0.2,  0,  4444],
        [240,   24000,  0.3,  0,  9999],
        [310,   31000,  0.2,  0,  6666],
        [270,   27000,  0.3,  0,  4444],
    ]

    X = np.array(normal + attacks)
    y = np.array([0]*30 + [1]*30)

    print(f"Dataset: {len(X)} samples ({len(normal)} normal, {len(attacks)} attacks)")
    return X, y


# -----------------------------------------------
# STEP 2: TRAIN AND EVALUATE ALL 3 MODELS
# -----------------------------------------------
def train_and_compare():

    X, y = create_dataset()

    # Scale the data — important for SVM and Neural Network
    # This makes all numbers on the same scale (0 to 1)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Split: 80% train, 20% test
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    # Define our 3 models
    models = {
        "Random Forest":   RandomForestClassifier(n_estimators=100, random_state=42),
        "SVM":             SVC(kernel="rbf", probability=True, random_state=42),
        "Neural Network":  MLPClassifier(hidden_layer_sizes=(64, 32),
                                         max_iter=1000, random_state=42)
    }

    results = {}

    print("\n" + "="*60)
    print("  TRAINING AND EVALUATING 3 AI MODELS")
    print("="*60)

    for name, model in models.items():
        print(f"\n Training: {name}...")

        # Train the model
        model.fit(X_train, y_train)

        # Test it
        predictions = model.predict(X_test)

        # Calculate all metrics
        accuracy  = accuracy_score(y_test, predictions)  * 100
        precision = precision_score(y_test, predictions) * 100
        recall    = recall_score(y_test, predictions)    * 100
        f1        = f1_score(y_test, predictions)        * 100

        # Cross validation — tests the model 5 times on different splits
        # This gives a more reliable accuracy score
        cv_scores = cross_val_score(model, X_scaled, y, cv=5) * 100
        cv_mean   = cv_scores.mean()

        results[name] = {
            "accuracy":   round(accuracy,  1),
            "precision":  round(precision, 1),
            "recall":     round(recall,    1),
            "f1_score":   round(f1,        1),
            "cv_mean":    round(cv_mean,   1),
            "model":      model
        }

        print(f"   ✅ Done!")
        print(f"      Accuracy  : {accuracy:.1f}%")
        print(f"      Precision : {precision:.1f}%")
        print(f"      Recall    : {recall:.1f}%")
        print(f"      F1 Score  : {f1:.1f}%")
        print(f"      CV Score  : {cv_mean:.1f}% (5-fold)")

    return results, scaler


# -----------------------------------------------
# STEP 3: PRINT FINAL COMPARISON TABLE
# -----------------------------------------------
def print_comparison(results):

    print("\n" + "="*60)
    print("  FINAL MODEL COMPARISON TABLE")
    print("="*60)
    print(f"  {'Model':<20} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'CV':>10}")
    print("  " + "-"*58)

    best_model_name = ""
    best_score = 0

    for name, r in results.items():
        print(f"  {name:<20} {r['accuracy']:>9}% {r['precision']:>9}% {r['recall']:>9}% {r['f1_score']:>9}% {r['cv_mean']:>9}%")
        if r["cv_mean"] > best_score:
            best_score      = r["cv_mean"]
            best_model_name = name

    print("  " + "-"*58)
    print(f"\n  🏆 BEST MODEL: {best_model_name} (CV Score: {best_score:.1f}%)")
    print("="*60)

    return best_model_name


# -----------------------------------------------
# STEP 4: SAVE RESULTS TO FILE
# -----------------------------------------------
def save_results(results, best_model_name):
    output = {}
    for name, r in results.items():
        output[name] = {
            "accuracy":  r["accuracy"],
            "precision": r["precision"],
            "recall":    r["recall"],
            "f1_score":  r["f1_score"],
            "cv_mean":   r["cv_mean"]
        }
    output["best_model"] = best_model_name

    os.makedirs("reports", exist_ok=True)
    with open("reports/model_comparison.json", "w") as f:
        json.dump(output, f, indent=4)

    print(f"\n  Results saved to reports/model_comparison.json")


# -----------------------------------------------
# RUN EVERYTHING
# -----------------------------------------------
if __name__ == "__main__":

    print("\n" + "="*60)
    print("  ThreatWatch AI — AI Model Comparison")
    print("  Random Forest  vs  SVM  vs  Neural Network")
    print("="*60 + "\n")

    # Train and compare all 3 models
    results, scaler = train_and_compare()

    # Print comparison table
    best = print_comparison(results)

    # Save results
    save_results(results, best)

    print("\n  What these metrics mean:")
    print("  Accuracy  = % of threats correctly identified")
    print("  Precision = when it says attack, how often it's right")
    print("  Recall    = how many real attacks it caught")
    print("  F1 Score  = balance between precision and recall")
    print("  CV Score  = accuracy tested 5 times (most reliable)\n")