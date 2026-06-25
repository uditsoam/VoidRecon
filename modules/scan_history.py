#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Scan History Manager
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/0xSoamRecon
# ═══════════════════════════════════════════════════════════

import json, os, argparse
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

HISTORY_FILE = "history/scans.json"


def load_history():
    os.makedirs("history", exist_ok=True)
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def save_history(history):
    os.makedirs("history", exist_ok=True)
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
        return True
    except Exception as e:
        print(f"\033[91m[-] Could not save history: {e}\033[0m")
        return False


def save_scan(domain, modules_run, summary,
              report_path="", duration=0):
    history = load_history()
    scan_id = len(history) + 1

    entry = {
        "id"          : scan_id,
        "domain"      : domain,
        "timestamp"   : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration_sec": duration,
        "modules_run" : modules_run,
        "report_path" : report_path,
        "summary"     : {
            "subdomains"    : summary.get("total_subdomains", 0),
            "emails"        : summary.get("total_emails", 0),
            "open_ports"    : summary.get("total_open_ports", 0),
            "high_ports"    : summary.get("high_risk_ports", 0),
            "web_paths"     : summary.get("total_web_paths", 0),
            "juicy_paths"   : summary.get("juicy_paths", 0),
            "cves"          : len(summary.get("cves_detected", [])),
            "risk_score"    : summary.get("risk_score", "N/A"),
            "risk_grade"    : summary.get("risk_grade", "N/A"),
            "security_grade": summary.get("security_grade", "N/A")
        }
    }

    history.append(entry)
    save_history(history)
    print(f"\033[92m[+] Scan saved to history — ID: {scan_id}\033[0m")
    return scan_id


def get_history():
    return load_history()


def get_domain_history(domain):
    return [h for h in load_history() if h.get("domain") == domain]


def delete_scan(scan_id):
    history     = load_history()
    new_history = [h for h in history if h.get("id") != scan_id]
    if len(new_history) == len(history):
        print(f"\033[91m[-] Scan ID {scan_id} not found\033[0m")
        return False
    save_history(new_history)
    print(f"\033[92m[+] Scan ID {scan_id} deleted\033[0m")
    return True


def list_all_history():
    history = load_history()
    if not history:
        print(f"\033[93m[!] No scan history found\033[0m")
        return

    print(f"\n\033[96m{'═'*80}\033[0m")
    print(f"  \033[96m0xSoamRecon — Scan History ({len(history)} scans)\033[0m")
    print(f"\033[96m{'═'*80}\033[0m")
    print(f"  {'ID':<5} {'Domain':<25} {'Date':<20} {'Mods':<6} {'Ports':<7} {'Grade':<7} Score")
    print(f"  {'─'*74}")

    for scan in history:
        sid   = scan.get("id","?")
        dom   = scan.get("domain","unknown")[:24]
        ts    = scan.get("timestamp","")[:16]
        dur   = scan.get("duration_sec",0)
        mods  = len(scan.get("modules_run",[]))
        s     = scan.get("summary",{})
        ports = s.get("open_ports",0)
        grade = s.get("risk_grade","N/A")
        score = s.get("risk_score","N/A")

        gc = "\033[92m" if grade in ["A","B"] else "\033[93m" if grade=="C" else "\033[91m"

        print(
            f"  \033[96m[{sid:02}]\033[0m "
            f"\033[97m{dom:<25}\033[0m "
            f"{ts:<20} "
            f"{mods:<6} "
            f"{ports:<7} "
            f"{gc}{grade:<7}\033[0m "
            f"{score}  \033[90m({dur}s)\033[0m"
        )

    print(f"\033[96m{'═'*80}\033[0m\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="scan_history.py")
    parser.add_argument("--list",    action="store_true", help="List all history")
    parser.add_argument("--delete",  type=int, metavar="ID", help="Delete scan by ID")
    parser.add_argument("--clear",   action="store_true", help="Clear all history")
    args = parser.parse_args()

    if args.list:
        list_all_history()
    elif args.delete:
        delete_scan(args.delete)
    elif args.clear:
        confirm = input("Clear ALL history? (yes/no): ")
        if confirm.lower() == "yes":
            save_history([])
            print("\033[92m[+] History cleared\033[0m")
    else:
        list_all_history()
