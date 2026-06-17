#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   VoidRecon — JSON Aggregator Module
#   Author  : Udit Soam
#   Purpose : Merges all 9 module JSON outputs into one
#             single structured recon_report.json
# ═══════════════════════════════════════════════════════════

import json, os
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

def log_info(msg):    print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")


def load_json(filepath):
    if not os.path.exists(filepath):
        log_warn(f"File not found — skipping: {filepath}")
        return {}
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception as e:
        log_error(f"Could not read {filepath}: {e}")
        return {}


def aggregate(json_dir="output/json", domain="unknown"):
    log_info(f"Aggregating results from: {json_dir}")
    print(f"{Fore.WHITE}  {'─'*50}{Style.RESET_ALL}")

    # ── Load all module outputs ──────────────────────────────
    subdomain = load_json(f"{json_dir}/subdomain_enum.json")
    osint     = load_json(f"{json_dir}/osint_harvest.json")
    shodan    = load_json(f"{json_dir}/shodan_lookup.json")
    dns       = load_json(f"{json_dir}/dns_whois.json")
    ssl       = load_json(f"{json_dir}/ssl_checker.json")
    ports     = load_json(f"{json_dir}/port_scanner.json")
    crawler   = load_json(f"{json_dir}/web_crawler.json")
    headers   = load_json(f"{json_dir}/http_headers.json")
    screenshot= load_json(f"{json_dir}/screenshot.json")

    # ── Count findings ───────────────────────────────────────
    total_subdomains  = len(subdomain.get("subdomains", []))
    total_emails      = osint.get("total_emails", 0)
    total_hosts       = osint.get("total_hosts", 0)
    total_ports       = ports.get("total_open", 0)
    total_paths       = crawler.get("total_found", 0)
    total_certs       = ssl.get("total_certs", 0)
    total_shodan      = shodan.get("total", 0)
    juicy_paths       = crawler.get("juicy_paths", 0)
    missing_headers   = len(
        headers.get("header_analysis", {})
               .get("missing_security", [])
    )
    security_grade    = headers.get("security_grade", "N/A")
    cve_list          = shodan.get("cve_summary", [])
    high_ports        = ports.get("risk_summary", {}).get("high", 0)

    # ── Print summary ────────────────────────────────────────
    log_success(f"Subdomains found     : {total_subdomains}")
    log_success(f"Emails harvested     : {total_emails}")
    log_success(f"Open ports           : {total_ports} ({high_ports} HIGH risk)")
    log_success(f"Web paths found      : {total_paths} ({juicy_paths} juicy)")
    log_success(f"SSL certificates     : {total_certs}")
    log_success(f"Shodan results       : {total_shodan}")
    log_success(f"Security grade       : {security_grade}")
    log_success(f"Missing sec headers  : {missing_headers}")

    if cve_list:
        log_warn(f"CVEs detected        : {cve_list}")

    # ── Build merged report object ───────────────────────────
    merged = {
        "meta": {
            "tool"       : "VoidRecon",
            "version"    : "1.0",
            "author"     : "Udit Soam",
            "domain"     : domain,
            "timestamp"  : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "github"     : "https://github.com/uditsoam/VoidRecon"
        },
        "summary": {
            "total_subdomains"  : total_subdomains,
            "total_emails"      : total_emails,
            "total_open_ports"  : total_ports,
            "high_risk_ports"   : high_ports,
            "total_web_paths"   : total_paths,
            "juicy_paths"       : juicy_paths,
            "total_certs"       : total_certs,
            "shodan_results"    : total_shodan,
            "cves_detected"     : cve_list,
            "security_grade"    : security_grade,
            "missing_headers"   : missing_headers
        },
        "subdomains"     : subdomain.get("subdomains", []),
        "emails"         : osint.get("emails", []),
        "hosts"          : osint.get("hosts", []),
        "dns_records"    : dns.get("dns_records", {}),
        "whois"          : dns.get("whois", {}),
        "open_ports"     : ports.get("open_ports", []),
        "web_paths"      : crawler.get("results", []),
        "http_headers"   : headers.get("header_analysis", {}),
        "ssl_certs"      : ssl.get("cert_history", []),
        "live_ssl"       : ssl.get("live_ssl", {}),
        "shodan"         : shodan.get("results", []),
        "screenshots"    : screenshot.get("captured", []),
        "live_urls"      : screenshot.get("live_urls", [])
    }

    # ── Save merged JSON ─────────────────────────────────────
    out_path = os.path.join(json_dir, "recon_report.json")
    with open(out_path, "w") as f:
        json.dump(merged, f, indent=2)

    print(f"{Fore.WHITE}  {'─'*50}{Style.RESET_ALL}")
    log_success(f"Merged report saved → {out_path}")
    return merged


if __name__ == "__main__":
    import sys
    domain  = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    result  = aggregate("output/json", domain)
    print(f"\n{Fore.GREEN}  Aggregation complete.{Style.RESET_ALL}")
