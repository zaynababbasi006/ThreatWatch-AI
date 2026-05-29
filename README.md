<<<<<<< HEAD
# ThreatWatch AI — Autonomous Cyber Defense System
### STMU | Department of Computing | BSCYS-III
### Course: CS2141 — Artificial Intelligence
### Submitted by: Zaynab Amjad Abbasi & Zarmeen Zawar Ghauri

---

## What is ThreatWatch AI?

ThreatWatch AI is an autonomous cybersecurity system that uses Artificial Intelligence
and Machine Learning to detect, classify, and respond to cyber threats in real time.

The system monitors network traffic, analyzes patterns using a Random Forest ML model,
assigns risk scores to detected threats, takes automated action (block/alert), and
displays everything on a live web dashboard.

---

## Project Structure

```
ThreatWatchAI/
│
├── threat_logger.py   → Saves all detected threats to a log file with timestamps
├── risk_engine.py     → Scores threats 0-100 and decides what action to take
├── ai_detector.py     → Machine Learning model (Random Forest) that detects attacks
├── main.py            → Main controller - connects all modules together
├── dashboard.py       → Live web dashboard to visualize threats in real time
│
├── data/              → Datasets and CSV files
├── logs/
│   └── threats.json   → Auto-generated threat log file
├── models/            → Saved ML models
└── reports/           → Generated PDF reports
```

---

## How to Run the Project

### Step 1 — Install required libraries
Open terminal and run:
```
pip install flask scikit-learn
```

### Step 2 — Simulate some attacks (generate data)
```
py main.py
```
This will simulate 6 attacks and save them to logs/threats.json

### Step 3 — Start the live dashboard
```
py dashboard.py
```
Then open your browser and go to:
```
http://127.0.0.1:5000
```

### Step 4 — Test the AI detector
```
py ai_detector.py
```
This trains the Random Forest model and tests it on new network traffic.

---

## System Modules Explained

### 1. threat_logger.py
- Saves every detected threat to logs/threats.json
- Each log entry contains: timestamp, IP address, threat type, risk score, action taken
- Supports viewing full threat history

### 2. risk_engine.py
- Contains base danger scores for 8 threat types
- Calculates final risk score (0-100)
- Decides action based on score:
  - Score >= 70 → IP Blocked
  - Score >= 40 → Alert Sent
  - Score < 40  → Logged Only
- Assigns severity level: LOW / MEDIUM / HIGH / CRITICAL

### 3. ai_detector.py
- Uses Random Forest algorithm (100 decision trees)
- Trained on network traffic features:
  [packets_per_sec, bytes_per_sec, duration, failed_logins, port]
- 80% training / 20% testing split
- Achieves 100% accuracy on test data
- Detects: DDoS, Brute Force, Malware, SQL Injection, Normal Traffic

### 4. main.py
- Connects risk_engine and threat_logger
- Processes incoming threats end-to-end
- Runs the full detection and response pipeline

### 5. dashboard.py
- Built with Flask (Python web framework)
- Dark themed real-time interface
- Shows: total threats, IPs blocked, alerts sent, avg risk score
- Color coded severity: GREEN=Low, YELLOW=Medium, ORANGE=High, RED=Critical
- Auto-refreshes every 5 seconds

---

## Threat Types Supported

| Threat Type       | Base Score | Typical Action |
|-------------------|------------|----------------|
| Ransomware        | 95         | IP Blocked     |
| Malware           | 90         | IP Blocked     |
| DDoS Attack       | 85         | IP Blocked     |
| SQL Injection     | 75         | IP Blocked     |
| Insider Threat    | 70         | IP Blocked     |
| Brute Force Login | 60         | Alert Sent     |
| Phishing          | 55         | Alert Sent     |
| Port Scan         | 40         | Alert Sent     |

---

## Technologies Used

| Technology    | Purpose                        |
|---------------|--------------------------------|
| Python 3.11   | Core programming language      |
| Flask         | Web dashboard framework        |
| scikit-learn  | Machine Learning library       |
| Random Forest | ML algorithm for detection     |
| NumPy         | Numerical data processing      |
| JSON          | Threat log storage format      |

---

## References

- IEEE Std 830-1998: Software Requirements Specifications
- NIST SP 800-53: Security and Privacy Controls
- MITRE ATT&CK Framework v14
- OWASP Top Ten 2021
- scikit-learn Documentation: https://scikit-learn.org

---

*ThreatWatch AI v1.0 | STMU BSCYS-III | May 2026*
=======
# ThreatWatch-AI
Autonomous Cyber Defense System — AI/ML Project STMU BSCYS-III
>>>>>>> 5108e20a3b955a3bf128933b6301ba4f2d6ac573
