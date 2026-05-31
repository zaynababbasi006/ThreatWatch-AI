# ============================================
# ThreatWatch AI - Threat Intelligence Scanner
# ============================================
# Checks any IP, domain, URL or file hash
# against 70+ security engines in real time.
# Powered by global threat intelligence feeds.
# ============================================

import vt
import json
import os
import datetime
import hashlib

# -----------------------------------------------
# PUT YOUR API KEY HERE
# -----------------------------------------------
API_KEY = "543cf0e0bee9ba88218e97d3b5f6c4b21f124d39f36a944978c0b4c685ed3c52"

SCAN_LOG = "logs/threat_intel_scans.json"
os.makedirs("logs", exist_ok=True)


# -----------------------------------------------
# SAVE SCAN RESULT
# -----------------------------------------------
def save_scan(result):
    existing = []
    if os.path.exists(SCAN_LOG):
        with open(SCAN_LOG, "r") as f:
            existing = json.load(f)
    existing.append(result)
    with open(SCAN_LOG, "w") as f:
        json.dump(existing, f, indent=4)


def get_severity(malicious, total):
    if total == 0:
        return "UNKNOWN"
    ratio = malicious / total
    if ratio >= 0.5:   return "CRITICAL"
    elif ratio >= 0.2: return "HIGH"
    elif ratio >= 0.05:return "MEDIUM"
    elif malicious > 0:return "LOW"
    else:              return "CLEAN"


def get_color(severity):
    colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH":     "\033[93m",  # Yellow
        "MEDIUM":   "\033[33m",  # Orange
        "LOW":      "\033[96m",  # Cyan
        "CLEAN":    "\033[92m",  # Green
        "UNKNOWN":  "\033[90m",  # Gray
    }
    return colors.get(severity, "\033[0m")

RESET = "\033[0m"
BOLD  = "\033[1m"
BLUE  = "\033[94m"
GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"


# -----------------------------------------------
# SCAN IP ADDRESS
# -----------------------------------------------
def scan_ip(ip_address):
    print(f"\n{BOLD}  Scanning IP: {BLUE}{ip_address}{RESET}")
    print(f"  Checking against global threat intelligence...\n")

    try:
        with vt.Client(API_KEY) as client:
            ip_obj = client.get_object(f"/ip_addresses/{ip_address}")

            malicious  = ip_obj.last_analysis_stats.get("malicious",  0)
            suspicious = ip_obj.last_analysis_stats.get("suspicious", 0)
            harmless   = ip_obj.last_analysis_stats.get("harmless",   0)
            undetected = ip_obj.last_analysis_stats.get("undetected", 0)
            total      = malicious + suspicious + harmless + undetected

            severity = get_severity(malicious, total)
            color    = get_color(severity)

            # Get country and owner info
            country  = getattr(ip_obj, "country",           "Unknown")
            owner    = getattr(ip_obj, "as_owner",          "Unknown")
            asn      = getattr(ip_obj, "asn",               "Unknown")
            rep_score= getattr(ip_obj, "reputation",        0)

            print("="*55)
            print(f"  {BOLD}THREAT INTELLIGENCE REPORT{RESET}")
            print("="*55)
            print(f"  Target      : {BLUE}{ip_address}{RESET}")
            print(f"  Country     : {country}")
            print(f"  Owner/ISP   : {owner}")
            print(f"  ASN         : {asn}")
            print(f"  Reputation  : {rep_score}")
            print(f"\n  {BOLD}Security Engine Results:{RESET}")
            print(f"  {RED}Malicious  : {malicious}/{total}{RESET}")
            print(f"  {CYAN}Suspicious : {suspicious}/{total}{RESET}")
            print(f"  {GREEN}Harmless   : {harmless}/{total}{RESET}")
            print(f"  Undetected : {undetected}/{total}")
            print(f"\n  {BOLD}Verdict    : {color}{severity}{RESET}")

            # Show which engines flagged it
            if malicious > 0:
                print(f"\n  {RED}Engines that flagged as MALICIOUS:{RESET}")
                analysis = ip_obj.last_analysis_results
                count = 0
                for engine, result in analysis.items():
                    if result.get("category") == "malicious":
                        print(f"  ⛔ {engine}: {result.get('result', 'malicious')}")
                        count += 1
                        if count >= 10:
                            remaining = malicious - 10
                            if remaining > 0:
                                print(f"  ... and {remaining} more engines")
                            break

            print("="*55)

            # Save result
            save_scan({
                "type":       "ip",
                "target":     ip_address,
                "country":    country,
                "owner":      owner,
                "malicious":  malicious,
                "suspicious": suspicious,
                "total":      total,
                "severity":   severity,
                "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

            return severity, malicious, total

    except vt.error.APIError as e:
        print(f"  {RED}API Error: {e}{RESET}")
        return None, 0, 0
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
        return None, 0, 0


# -----------------------------------------------
# SCAN DOMAIN
# -----------------------------------------------
def scan_domain(domain):
    print(f"\n{BOLD}  Scanning Domain: {BLUE}{domain}{RESET}")
    print(f"  Checking against global threat intelligence...\n")

    try:
        with vt.Client(API_KEY) as client:
            domain_obj = client.get_object(f"/domains/{domain}")

            malicious  = domain_obj.last_analysis_stats.get("malicious",  0)
            suspicious = domain_obj.last_analysis_stats.get("suspicious", 0)
            harmless   = domain_obj.last_analysis_stats.get("harmless",   0)
            undetected = domain_obj.last_analysis_stats.get("undetected", 0)
            total      = malicious + suspicious + harmless + undetected

            severity   = get_severity(malicious, total)
            color      = get_color(severity)

            categories = getattr(domain_obj, "categories",  {})
            rep_score  = getattr(domain_obj, "reputation",  0)
            registrar  = getattr(domain_obj, "registrar",   "Unknown")

            print("="*55)
            print(f"  {BOLD}THREAT INTELLIGENCE REPORT{RESET}")
            print("="*55)
            print(f"  Target      : {BLUE}{domain}{RESET}")
            print(f"  Registrar   : {registrar}")
            print(f"  Reputation  : {rep_score}")
            if categories:
                cats = list(categories.values())[:3]
                print(f"  Categories  : {', '.join(cats)}")
            print(f"\n  {BOLD}Security Engine Results:{RESET}")
            print(f"  {RED}Malicious  : {malicious}/{total}{RESET}")
            print(f"  {CYAN}Suspicious : {suspicious}/{total}{RESET}")
            print(f"  {GREEN}Harmless   : {harmless}/{total}{RESET}")
            print(f"  Undetected : {undetected}/{total}")
            print(f"\n  {BOLD}Verdict    : {color}{severity}{RESET}")

            if malicious > 0:
                print(f"\n  {RED}Engines that flagged as MALICIOUS:{RESET}")
                analysis = domain_obj.last_analysis_results
                count    = 0
                for engine, result in analysis.items():
                    if result.get("category") == "malicious":
                        print(f"  ⛔ {engine}: {result.get('result','malicious')}")
                        count += 1
                        if count >= 10:
                            break

            print("="*55)

            save_scan({
                "type":       "domain",
                "target":     domain,
                "malicious":  malicious,
                "suspicious": suspicious,
                "total":      total,
                "severity":   severity,
                "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

            return severity, malicious, total

    except vt.error.APIError as e:
        print(f"  {RED}API Error: {e}{RESET}")
        return None, 0, 0
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
        return None, 0, 0


# -----------------------------------------------
# SCAN FILE HASH
# -----------------------------------------------
def scan_hash(file_hash):
    print(f"\n{BOLD}  Scanning Hash: {BLUE}{file_hash}{RESET}")
    print(f"  Checking against 70+ security engines...\n")

    try:
        with vt.Client(API_KEY) as client:
            file_obj = client.get_object(f"/files/{file_hash}")

            malicious  = file_obj.last_analysis_stats.get("malicious",  0)
            suspicious = file_obj.last_analysis_stats.get("suspicious", 0)
            harmless   = file_obj.last_analysis_stats.get("harmless",   0)
            undetected = file_obj.last_analysis_stats.get("undetected", 0)
            total      = malicious + suspicious + harmless + undetected

            severity   = get_severity(malicious, total)
            color      = get_color(severity)

            name       = getattr(file_obj, "meaningful_name", "Unknown")
            size       = getattr(file_obj, "size",            0)
            file_type  = getattr(file_obj, "type_description","Unknown")
            times_seen = getattr(file_obj, "times_submitted", 0)

            print("="*55)
            print(f"  {BOLD}THREAT INTELLIGENCE REPORT{RESET}")
            print("="*55)
            print(f"  Hash        : {BLUE}{file_hash[:32]}...{RESET}")
            print(f"  File Name   : {name}")
            print(f"  File Type   : {file_type}")
            print(f"  File Size   : {size:,} bytes")
            print(f"  Times Seen  : {times_seen:,} submissions")
            print(f"\n  {BOLD}Security Engine Results:{RESET}")
            print(f"  {RED}Malicious  : {malicious}/{total} engines{RESET}")
            print(f"  {CYAN}Suspicious : {suspicious}/{total} engines{RESET}")
            print(f"  {GREEN}Harmless   : {harmless}/{total} engines{RESET}")
            print(f"  Undetected : {undetected}/{total} engines")
            print(f"\n  {BOLD}Verdict    : {color}{severity}{RESET}")

            if malicious > 0:
                print(f"\n  {RED}Antivirus engines detecting as MALICIOUS:{RESET}")
                analysis = file_obj.last_analysis_results
                count    = 0
                for engine, result in analysis.items():
                    if result.get("category") == "malicious":
                        print(f"  ⛔ {engine}: {result.get('result','malicious')}")
                        count += 1
                        if count >= 15:
                            remaining = malicious - 15
                            if remaining > 0:
                                print(f"  ... and {remaining} more antivirus engines")
                            break

            print("="*55)

            save_scan({
                "type":       "hash",
                "target":     file_hash,
                "name":       name,
                "file_type":  file_type,
                "malicious":  malicious,
                "suspicious": suspicious,
                "total":      total,
                "severity":   severity,
                "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

            return severity, malicious, total

    except vt.error.APIError as e:
        print(f"  {RED}API Error: {e}{RESET}")
        return None, 0, 0
    except Exception as e:
        print(f"  {RED}Error: {e}{RESET}")
        return None, 0, 0


# -----------------------------------------------
# GET FILE HASH FROM LOCAL FILE
# -----------------------------------------------
def hash_local_file(filepath):
    """Calculate SHA256 hash of a local file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# -----------------------------------------------
# INTERACTIVE MENU
# -----------------------------------------------
def show_menu():
    while True:
        print(f"\n{BOLD}{'='*50}{RESET}")
        print(f"  {GREEN}THREATWATCH AI — Threat Intelligence{RESET}")
        print(f"{'='*50}")
        print(f"  1. Scan an IP address")
        print(f"  2. Scan a domain/website")
        print(f"  3. Scan a file hash (MD5/SHA256)")
        print(f"  4. Scan a local file")
        print(f"  5. View scan history")
        print(f"  6. Exit")
        print(f"{'='*50}")

        choice = input("  Enter choice (1-6): ").strip()

        if choice == "1":
            ip = input("  Enter IP address: ").strip()
            scan_ip(ip)

        elif choice == "2":
            domain = input("  Enter domain (e.g. google.com): ").strip()
            scan_domain(domain)

        elif choice == "3":
            h = input("  Enter MD5 or SHA256 hash: ").strip()
            scan_hash(h)

        elif choice == "4":
            path = input("  Enter file path: ").strip().strip('"')
            if os.path.exists(path):
                print(f"  Calculating hash...")
                file_hash = hash_local_file(path)
                print(f"  SHA256: {file_hash}")
                scan_hash(file_hash)
            else:
                print(f"  {RED}File not found!{RESET}")

        elif choice == "5":
            if os.path.exists(SCAN_LOG):
                with open(SCAN_LOG, "r") as f:
                    scans = json.load(f)
                print(f"\n  {'='*55}")
                print(f"  Scan History ({len(scans)} scans)")
                print(f"  {'='*55}")
                for s in reversed(scans[-10:]):
                    color = get_color(s.get("severity", "UNKNOWN"))
                    print(f"  [{s['scanned_at']}] {s['type'].upper()}: "
                          f"{BLUE}{s['target']}{RESET} → "
                          f"{color}{s.get('severity','?')}{RESET} "
                          f"({s.get('malicious',0)}/{s.get('total',0)} engines)")
            else:
                print("  No scan history yet.")

        elif choice == "6":
            print("  Exiting Threat Intelligence Scanner.")
            break

        else:
            print(f"  {RED}Invalid choice!{RESET}")


# -----------------------------------------------
# RUN
# -----------------------------------------------
if __name__ == "__main__":
    print(f"\n{'='*50}")
    print(f"  {GREEN}ThreatWatch AI{RESET}")
    print(f"  Threat Intelligence Scanner")
    print(f"  Powered by 70+ Security Engines")
    print(f"{'='*50}")

    if API_KEY == "YOUR_API_KEY_HERE":
        print(f"\n  {RED}ERROR: Please add your API key!{RESET}")
        print(f"  Open threat_intel.py and replace")
        print(f"  'YOUR_API_KEY_HERE' with your actual key")
    else:
        show_menu()