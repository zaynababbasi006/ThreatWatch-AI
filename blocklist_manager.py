# ============================================
# ThreatWatch AI - Blocklist Manager
# ============================================
# Manages the list of blocked IP addresses.
# Security analysts can:
#   - View all blocked IPs
#   - Manually block an IP
#   - Unblock a false positive
#   - See why each IP was blocked
#   - Export blocklist report
# ============================================

import json
import os
import datetime

LOG_FILE       = "logs/threats.json"
BLOCKLIST_FILE = "logs/blocklist.json"


# ============================================
# LOAD / SAVE BLOCKLIST
# ============================================
def load_blocklist():
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, "r") as f:
            return json.load(f)
    return {}


def save_blocklist(blocklist):
    os.makedirs("logs", exist_ok=True)
    with open(BLOCKLIST_FILE, "w") as f:
        json.dump(blocklist, f, indent=4)


# ============================================
# BUILD BLOCKLIST FROM THREAT LOG
# ============================================
def sync_from_threats():
    """
    Reads threats.json and automatically adds
    any IP that was blocked to the blocklist.
    """
    if not os.path.exists(LOG_FILE):
        print("No threat log found. Run main.py first!")
        return {}

    with open(LOG_FILE, "r") as f:
        threats = json.load(f)

    blocklist = load_blocklist()

    # Add all blocked IPs from threat history
    for t in threats:
        if t["action_taken"] == "IP Blocked":
            ip = t["ip_address"]
            if ip not in blocklist:
                blocklist[ip] = {
                    "blocked_at":   t["timestamp"],
                    "reason":       t["threat_type"],
                    "risk_score":   t["risk_score"],
                    "block_count":  1,
                    "status":       "ACTIVE"
                }
            else:
                # Update block count if already there
                blocklist[ip]["block_count"] += 1
                blocklist[ip]["risk_score"]   = max(
                    blocklist[ip]["risk_score"],
                    t["risk_score"]
                )

    save_blocklist(blocklist)
    return blocklist


# ============================================
# VIEW ALL BLOCKED IPs
# ============================================
def view_blocklist():
    """Display all currently blocked IPs."""

    blocklist = sync_from_threats()

    if not blocklist:
        print("  Blocklist is empty.")
        return

    active   = {ip: d for ip, d in blocklist.items() if d["status"] == "ACTIVE"}
    inactive = {ip: d for ip, d in blocklist.items() if d["status"] == "UNBLOCKED"}

    print("\n" + "="*65)
    print("  THREATWATCH AI — IP BLOCKLIST MANAGER")
    print("="*65)
    print(f"  Total blocked : {len(active)} active | {len(inactive)} unblocked")
    print("="*65)

    if active:
        print(f"\n  🔴 ACTIVE BLOCKS ({len(active)} IPs)")
        print(f"  {'IP Address':<20} {'Score':>6} {'Reason':<28} {'Blocked At'}")
        print("  " + "-"*70)
        for ip, data in active.items():
            print(f"  {ip:<20} {data['risk_score']:>5}  {data['reason'][:26]:<28} {data['blocked_at'][:16]}")

    if inactive:
        print(f"\n  🟢 PREVIOUSLY UNBLOCKED ({len(inactive)} IPs)")
        print(f"  {'IP Address':<20} {'Reason':<30} {'Status'}")
        print("  " + "-"*60)
        for ip, data in inactive.items():
            print(f"  {ip:<20} {data['reason'][:28]:<30} {data['status']}")

    print("="*65)
    return blocklist


# ============================================
# MANUALLY BLOCK AN IP
# ============================================
def block_ip(ip_address, reason="Manual block by analyst"):
    """Manually add an IP to the blocklist."""

    blocklist = load_blocklist()

    if ip_address in blocklist and blocklist[ip_address]["status"] == "ACTIVE":
        print(f"  ⚠  {ip_address} is already blocked!")
        return

    blocklist[ip_address] = {
        "blocked_at":  datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reason":      reason,
        "risk_score":  100,
        "block_count": 1,
        "status":      "ACTIVE"
    }

    save_blocklist(blocklist)
    print(f"  ⛔ {ip_address} has been BLOCKED")
    print(f"  Reason: {reason}")


# ============================================
# UNBLOCK AN IP (FALSE POSITIVE)
# ============================================
def unblock_ip(ip_address):
    """Remove an IP from the blocklist."""

    blocklist = load_blocklist()

    if ip_address not in blocklist:
        print(f"  ❌ {ip_address} is not in the blocklist!")
        return

    if blocklist[ip_address]["status"] == "UNBLOCKED":
        print(f"  ⚠  {ip_address} is already unblocked!")
        return

    blocklist[ip_address]["status"]      = "UNBLOCKED"
    blocklist[ip_address]["unblocked_at"]= datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    save_blocklist(blocklist)
    print(f"  ✅ {ip_address} has been UNBLOCKED")
    print(f"  Unblocked at: {blocklist[ip_address]['unblocked_at']}")


# ============================================
# EXPORT BLOCKLIST REPORT
# ============================================
def export_blocklist():
    """Export blocklist to a text report."""

    blocklist = sync_from_threats()
    active    = {ip: d for ip, d in blocklist.items() if d["status"] == "ACTIVE"}

    report_path = "reports/blocklist_report.txt"
    os.makedirs("reports", exist_ok=True)

    with open(report_path, "w") as f:
        f.write("="*60 + "\n")
        f.write("  THREATWATCH AI — BLOCKLIST REPORT\n")
        f.write(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Total Active Blocks: {len(active)}\n")
        f.write("="*60 + "\n\n")

        for ip, data in active.items():
            f.write(f"IP: {ip}\n")
            f.write(f"  Blocked At  : {data['blocked_at']}\n")
            f.write(f"  Reason      : {data['reason']}\n")
            f.write(f"  Risk Score  : {data['risk_score']}\n")
            f.write(f"  Block Count : {data['block_count']}\n")
            f.write(f"  Status      : {data['status']}\n\n")

    print(f"  ✅ Blocklist exported to {report_path}")
    return report_path


# ============================================
# INTERACTIVE MENU
# ============================================
def show_menu():
    """Interactive menu for managing blocklist."""

    while True:
        print("\n" + "="*45)
        print("  BLOCKLIST MANAGER — Choose an option:")
        print("="*45)
        print("  1. View all blocked IPs")
        print("  2. Block an IP manually")
        print("  3. Unblock an IP")
        print("  4. Export blocklist report")
        print("  5. Exit")
        print("="*45)

        choice = input("  Enter choice (1-5): ").strip()

        if choice == "1":
            view_blocklist()

        elif choice == "2":
            ip     = input("  Enter IP to block: ").strip()
            reason = input("  Reason (or press Enter for default): ").strip()
            if not reason:
                reason = "Manual block by analyst"
            block_ip(ip, reason)

        elif choice == "3":
            view_blocklist()
            ip = input("\n  Enter IP to unblock: ").strip()
            unblock_ip(ip)

        elif choice == "4":
            export_blocklist()

        elif choice == "5":
            print("  Exiting Blocklist Manager.")
            break

        else:
            print("  Invalid choice. Try again.")


# ============================================
# RUN
# ============================================
if __name__ == "__main__":
    print("\n" + "="*45)
    print("  ThreatWatch AI — Blocklist Manager")
    print("="*45)

    # First sync from threat log
    print("  Syncing from threat log...")
    blocklist = sync_from_threats()
    print(f"  Found {len(blocklist)} blocked IPs in history.")

    # Show interactive menu
    show_menu()