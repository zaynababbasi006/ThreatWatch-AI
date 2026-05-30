# ============================================
# ThreatWatch AI - File Scanner
# ============================================
# Upload any file and AI will analyze it for:
#   - Malware signatures
#   - Ransomware patterns
#   - Spyware indicators
#   - Suspicious code patterns
#   - File type mismatches
# ============================================

import os
import hashlib
import math
import json
import datetime
from collections import Counter

# ============================================
# KNOWN MALWARE SIGNATURES
# These are patterns found in malicious files
# ============================================
MALWARE_SIGNATURES = {
    # Ransomware keywords
    "ransomware": [
        b"your files have been encrypted",
        b"bitcoin",
        b"decrypt",
        b"ransom",
        b"pay now",
        b"YOUR_FILES_ARE_ENCRYPTED",
        b"CryptoLocker",
        b"WannaCry",
        b"NotPetya",
    ],
    # Spyware/keylogger patterns
    "spyware": [
        b"keylogger",
        b"GetAsyncKeyState",
        b"keyboard hook",
        b"screenshot",
        b"GetForegroundWindow",
        b"send_keys",
        b"capture_screen",
    ],
    # Malware/trojan patterns
    "malware": [
        b"cmd.exe /c",
        b"powershell -enc",
        b"net user add",
        b"reg add",
        b"CreateRemoteThread",
        b"VirtualAlloc",
        b"WriteProcessMemory",
        b"ShellExecute",
        b"WScript.Shell",
        b"backdoor",
    ],
    # Network attack tools
    "network_threat": [
        b"reverse_shell",
        b"bind_shell",
        b"meterpreter",
        b"metasploit",
        b"nmap",
        b"sqlmap",
        b"hydra",
    ],
    # Suspicious script patterns
    "suspicious_script": [
        b"eval(base64_decode",
        b"exec(base64",
        b"system(",
        b"passthru(",
        b"shell_exec(",
        b"base64_decode",
        b"gzinflate",
    ]
}

# ============================================
# FILE EXTENSION RISK LEVELS
# ============================================
HIGH_RISK_EXTENSIONS   = ['.exe', '.bat', '.cmd', '.com', '.scr', '.pif',
                           '.vbs', '.js', '.jar', '.ps1', '.msi']
MEDIUM_RISK_EXTENSIONS = ['.zip', '.rar', '.7z', '.doc', '.docm',
                           '.xlsm', '.pptm', '.pdf']
LOW_RISK_EXTENSIONS    = ['.txt', '.jpg', '.png', '.mp3', '.mp4',
                           '.csv', '.json']


# ============================================
# CALCULATE FILE ENTROPY
# High entropy = possibly encrypted/packed
# (ransomware encrypts files = high entropy)
# ============================================
def calculate_entropy(data):
    """
    Entropy measures randomness in data.
    Normal files: 3-6 entropy
    Encrypted/packed malware: 7-8 entropy
    """
    if not data:
        return 0

    counter   = Counter(data)
    length    = len(data)
    entropy   = 0

    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return round(entropy, 2)


# ============================================
# GET FILE HASH
# ============================================
def get_file_hash(filepath):
    """Calculate MD5 and SHA256 hash of file."""
    md5    = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        data = f.read()
        md5.update(data)
        sha256.update(data)

    return md5.hexdigest(), sha256.hexdigest()


# ============================================
# SCAN FILE FOR MALWARE
# ============================================
def scan_file(filepath):
    """
    Full AI-powered file scan.
    Returns detailed threat report.
    """

    print("\n" + "="*55)
    print("  ThreatWatch AI — File Scanner")
    print("="*55)

    # Check file exists
    if not os.path.exists(filepath):
        print(f"  ❌ File not found: {filepath}")
        return None

    filename  = os.path.basename(filepath)
    filesize  = os.path.getsize(filepath)
    extension = os.path.splitext(filename)[1].lower()

    print(f"  File     : {filename}")
    print(f"  Size     : {filesize:,} bytes ({filesize/1024:.1f} KB)")
    print(f"  Type     : {extension if extension else 'No extension'}")

    # Read file content
    with open(filepath, "rb") as f:
        content = f.read()

    # ---- ANALYSIS ----
    threats_found  = []
    risk_score     = 0
    threat_details = []

    # 1. Check file extension risk
    print("\n  [1/5] Checking file extension...")
    if extension in HIGH_RISK_EXTENSIONS:
        risk_score += 30
        threats_found.append("High-risk file extension")
        threat_details.append(f"Extension '{extension}' is commonly used by malware")
        print(f"       ⚠  HIGH RISK extension: {extension}")
    elif extension in MEDIUM_RISK_EXTENSIONS:
        risk_score += 10
        print(f"       ⚠  MEDIUM risk extension: {extension}")
    else:
        print(f"       ✅ Low risk extension: {extension}")

    # 2. Calculate entropy
    print("  [2/5] Calculating file entropy...")
    entropy = calculate_entropy(content)
    print(f"       Entropy: {entropy}/8.0")

    if entropy > 7.2:
        risk_score += 35
        threats_found.append("Extremely high entropy — possible encryption")
        threat_details.append(f"Entropy {entropy}/8.0 suggests file may be encrypted or packed (ransomware indicator)")
        print(f"       🚨 CRITICAL: Entropy {entropy} suggests encrypted/packed content!")
    elif entropy > 6.5:
        risk_score += 20
        threats_found.append("High entropy detected")
        threat_details.append(f"Entropy {entropy}/8.0 is unusually high")
        print(f"       ⚠  HIGH: Entropy {entropy} is suspicious")
    else:
        print(f"       ✅ Normal entropy range")

    # 3. Signature scanning
    print("  [3/5] Scanning for malware signatures...")
    content_lower = content.lower()
    sigs_found    = 0

    for threat_type, signatures in MALWARE_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in content_lower:
                sigs_found += 1
                risk_score += 20
                threats_found.append(f"{threat_type.upper()} signature detected")
                threat_details.append(f"Found {threat_type} pattern: '{sig.decode('utf-8', errors='ignore')}'")

    if sigs_found > 0:
        print(f"       🚨 Found {sigs_found} malware signatures!")
    else:
        print(f"       ✅ No known malware signatures found")

    # 4. File hash
    print("  [4/5] Computing file hashes...")
    md5_hash, sha256_hash = get_file_hash(filepath)
    print(f"       MD5    : {md5_hash}")
    print(f"       SHA256 : {sha256_hash[:32]}...")

    # 5. File size check
    print("  [5/5] Checking file characteristics...")
    if filesize == 0:
        risk_score += 10
        threats_found.append("Empty file — possible dropper")
        print("       ⚠  Empty file detected")
    elif filesize > 50 * 1024 * 1024:  # 50MB
        print("       ⚠  Large file — scan may take longer")
    else:
        print("       ✅ File size normal")

    # ---- FINAL VERDICT ----
    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        verdict     = "🚨 MALICIOUS"
        verdict_color = "CRITICAL"
    elif risk_score >= 40:
        verdict     = "⚠  SUSPICIOUS"
        verdict_color = "WARNING"
    elif risk_score >= 20:
        verdict     = "⚠  LOW RISK"
        verdict_color = "CAUTION"
    else:
        verdict     = "✅ CLEAN"
        verdict_color = "SAFE"

    # ---- PRINT REPORT ----
    print("\n" + "="*55)
    print("  SCAN RESULTS")
    print("="*55)
    print(f"  Verdict    : {verdict}")
    print(f"  Risk Score : {risk_score}/100")
    print(f"  Status     : {verdict_color}")
    print(f"  Threats    : {len(threats_found)} detected")

    if threat_details:
        print(f"\n  Threat Details:")
        for i, detail in enumerate(threat_details, 1):
            print(f"  {i}. {detail}")

    if risk_score >= 40:
        print(f"\n  ⚠  RECOMMENDATION: Do NOT open or execute this file!")
        print(f"  Quarantine or delete immediately.")
    else:
        print(f"\n  ✅ File appears safe to use.")

    print("="*55)

    # Build result
    result = {
        "filename":     filename,
        "filepath":     filepath,
        "filesize":     filesize,
        "extension":    extension,
        "entropy":      entropy,
        "risk_score":   risk_score,
        "verdict":      verdict_color,
        "threats":      threats_found,
        "md5":          md5_hash,
        "sha256":       sha256_hash,
        "scanned_at":   datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # Save scan result
    save_scan_result(result)

    return result


# ============================================
# SAVE SCAN RESULT
# ============================================
def save_scan_result(result):
    """Save scan result to logs."""
    scan_log = "logs/file_scans.json"
    os.makedirs("logs", exist_ok=True)

    existing = []
    if os.path.exists(scan_log):
        with open(scan_log, "r") as f:
            existing = json.load(f)

    # Don't save filepath for privacy
    save_result = {k: v for k, v in result.items() if k != "filepath"}
    existing.append(save_result)

    with open(scan_log, "w") as f:
        json.dump(existing, f, indent=4)


# ============================================
# SCAN MULTIPLE FILES IN A FOLDER
# ============================================
def scan_folder(folder_path):
    """Scan all files in a folder."""

    if not os.path.exists(folder_path):
        print(f"Folder not found: {folder_path}")
        return

    files = os.listdir(folder_path)
    print(f"\n Scanning {len(files)} files in {folder_path}...")
    print("="*55)

    results = []
    for filename in files:
        filepath = os.path.join(folder_path, filename)
        if os.path.isfile(filepath):
            result = scan_file(filepath)
            if result:
                results.append(result)

    # Summary
    clean      = sum(1 for r in results if r["risk_score"] < 20)
    suspicious = sum(1 for r in results if 20 <= r["risk_score"] < 70)
    malicious  = sum(1 for r in results if r["risk_score"] >= 70)

    print(f"\n FOLDER SCAN SUMMARY")
    print(f" Total files : {len(results)}")
    print(f" Clean       : {clean}")
    print(f" Suspicious  : {suspicious}")
    print(f" Malicious   : {malicious}")


# ============================================
# RUN — Interactive file scanner
# ============================================
if __name__ == "__main__":

    print("\n" + "="*55)
    print("  ThreatWatch AI — AI File Scanner")
    print("  Detects: Malware, Ransomware, Spyware")
    print("="*55)

    while True:
        print("\n  Options:")
        print("  1. Scan a specific file")
        print("  2. Scan a folder")
        print("  3. Create a test malware sample")
        print("  4. Exit")

        choice = input("\n  Enter choice (1-4): ").strip()

        if choice == "1":
            path = input("  Enter file path: ").strip().strip('"')
            scan_file(path)

        elif choice == "2":
            path = input("  Enter folder path: ").strip().strip('"')
            scan_folder(path)

        elif choice == "3":
            # Create a fake malware sample for testing
            test_path = "data/test_malware_sample.txt"
            os.makedirs("data", exist_ok=True)
            with open(test_path, "w") as f:
                f.write("This is a test file.\n")
                f.write("cmd.exe /c net user add hacker password123\n")
                f.write("powershell -enc base64encodedpayload\n")
                f.write("bitcoin wallet: 1A2B3C4D5E\n")
                f.write("your files have been encrypted\n")
                f.write("WannaCry ransomware test\n")
            print(f"\n  ✅ Test sample created at: {test_path}")
            print("  Now scan it with option 1!")

        elif choice == "4":
            print("  Exiting File Scanner.")
            break

        else:
            print("  Invalid choice!")