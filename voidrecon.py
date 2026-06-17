#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   VoidRecon — Main Orchestrator
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/VoidRecon
#
#   Usage:
#     python3 voidrecon.py -u target.com
#     python3 voidrecon.py -u target.com --passive-only
#     python3 voidrecon.py -u target.com --skip screenshots
#     python3 voidrecon.py -u target.com --speed T3
#     python3 voidrecon.py --help
# ═══════════════════════════════════════════════════════════

import argparse, os, sys, time
from datetime import datetime
from colorama import Fore, Back, Style, init
init(autoreset=True)

BANNER = """
\033[96m
 ██╗   ██╗ ██████╗ ██╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██║   ██║██╔═══██╗██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║   ██║██║   ██║██║██║  ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║██║  ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝██║██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
   ╚═══╝   ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
\033[97m         Automated Red Team Reconnaissance Framework\033[0m
\033[93m         Author : Udit Soam  |  v1.0  |  2026\033[0m
\033[96m         GitHub : https://github.com/uditsoam/VoidRecon\033[0m
\033[91m         WARNING: Use only on authorized targets!\033[0m
"""

def banner(): print(BANNER)

def log_info(msg):    print(f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}")
def log_success(msg): print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")
def log_warn(msg):    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")
def log_error(msg):   print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")
def log_phase(msg):   print(f"\n{Fore.WHITE}{Back.BLUE} {msg} {Style.RESET_ALL}\n")
def log_skip(msg):    print(f"{Fore.WHITE}[~] SKIPPED: {msg}{Style.RESET_ALL}")
def divider():        print(f"{Fore.WHITE}{'═'*65}{Style.RESET_ALL}")


def get_args():
    parser = argparse.ArgumentParser(
        prog="voidrecon.py",
        description="VoidRecon — Automated Red Team Reconnaissance Framework",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 voidrecon.py -u target.com
  python3 voidrecon.py -u target.com --passive-only
  python3 voidrecon.py -u target.com --skip screenshots,nikto
  python3 voidrecon.py -u target.com --speed T3 --top-ports 500
  python3 voidrecon.py -u target.com --https --threads 100
  python3 voidrecon.py -u 192.168.1.1 --ip-mode

Modules:
  Passive : subdomain_enum, osint, shodan, dns, ssl
  Active  : port_scanner, web_crawler, http_headers, screenshots
        """
    )
    parser.add_argument("-u", "--url",
        required=True,
        help="Target domain or IP (e.g. target.com)"
    )
    parser.add_argument("-o", "--output",
        default="output",
        help="Output base directory (default: output)"
    )
    parser.add_argument("--passive-only",
        action="store_true",
        help="Run passive recon only — no direct target contact"
    )
    parser.add_argument("--skip",
        default="",
        help="Comma-separated modules to skip\n"
             "(e.g. --skip screenshots,nikto,shodan)"
    )
    parser.add_argument("--speed",
        default="T4",
        choices=["T1","T2","T3","T4","T5"],
        help="Nmap scan speed (default: T4)"
    )
    parser.add_argument("--top-ports",
        type=int, default=1000,
        help="Nmap top ports to scan (default: 1000)"
    )
    parser.add_argument("--threads",
        type=int, default=50,
        help="Threads for web crawling (default: 50)"
    )
    parser.add_argument("--https",
        action="store_true",
        help="Force HTTPS for web modules"
    )
    parser.add_argument("--ip-mode",
        action="store_true",
        help="Target is an IP address"
    )
    parser.add_argument("--nikto",
        action="store_true",
        help="Enable Nikto scan in http_headers module (slower)"
    )
    parser.add_argument("--no-banner",
        action="store_true",
        help="Suppress banner"
    )
    return parser.parse_args()


def run_module(name, func, skip_list):
    if name in skip_list:
        log_skip(f"{name}")
        return {}
    log_info(f"Starting module: {name}")
    start = time.time()
    try:
        result = func()
        elapsed = round(time.time() - start, 1)
        log_success(f"{name} done in {elapsed}s")
        return result
    except Exception as e:
        log_error(f"{name} failed: {e}")
        return {}


def print_final_summary(merged, domain, elapsed_total):
    divider()
    print(f"""
{Fore.CYAN}  ██╗   ██╗ ██████╗ ██╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██║   ██║██╔═══██╗██║██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ╚██╗ ██╔╝██║   ██║██║██║  ██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
   ╚████╔╝ ╚██████╔╝██║██████╔╝    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ╚═══╝   ╚═════╝ ╚═╝╚═════╝     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
                                    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Style.RESET_ALL}""")

    s = merged.get("summary", {})
    divider()
    print(f"  {Fore.WHITE}TARGET{Style.RESET_ALL}            : {Fore.GREEN}{domain}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}SCAN COMPLETED{Style.RESET_ALL}    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {Fore.WHITE}TOTAL TIME{Style.RESET_ALL}        : {elapsed_total}s")
    divider()
    print(f"  {Fore.CYAN}SUBDOMAINS{Style.RESET_ALL}         : {Fore.YELLOW}{s.get('total_subdomains',0)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}EMAILS FOUND{Style.RESET_ALL}       : {Fore.YELLOW}{s.get('total_emails',0)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}OPEN PORTS{Style.RESET_ALL}         : {Fore.YELLOW}{s.get('total_open_ports',0)}{Style.RESET_ALL}  "
          f"({Fore.RED}{s.get('high_risk_ports',0)} HIGH RISK{Style.RESET_ALL})")
    print(f"  {Fore.CYAN}WEB PATHS{Style.RESET_ALL}          : {Fore.YELLOW}{s.get('total_web_paths',0)}{Style.RESET_ALL}  "
          f"({Fore.RED}{s.get('juicy_paths',0)} JUICY{Style.RESET_ALL})")
    print(f"  {Fore.CYAN}SSL CERTS{Style.RESET_ALL}          : {Fore.YELLOW}{s.get('total_certs',0)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}SHODAN RESULTS{Style.RESET_ALL}     : {Fore.YELLOW}{s.get('shodan_results',0)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}SECURITY GRADE{Style.RESET_ALL}     : {Fore.RED}{s.get('security_grade','N/A')}{Style.RESET_ALL}")

    cves = s.get("cves_detected", [])
    if cves:
        print(f"\n  {Fore.RED}[!!!] CVEs DETECTED: {cves}{Style.RESET_ALL}")

    divider()


def main():
    args     = get_args()
    skip     = [s.strip() for s in args.skip.split(",") if s.strip()]
    json_dir = os.path.join(args.output, "json")

    os.makedirs(json_dir, exist_ok=True)
    os.makedirs(os.path.join(args.output, "screenshots"), exist_ok=True)
    os.makedirs(os.path.join(args.output, "reports"), exist_ok=True)

    if not args.no_banner:
        banner()

    divider()
    log_info(f"Target        : {args.url}")
    log_info(f"Mode          : {'PASSIVE ONLY' if args.passive_only else 'FULL SCAN'}")
    log_info(f"Output        : {args.output}")
    log_info(f"Speed         : {args.speed}")
    log_info(f"Skipping      : {skip if skip else 'None'}")
    log_info(f"Started       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    divider()

    # ── Import all modules ───────────────────────────────────
    from modules import (
        subdomain_enum, osint_harvest, shodan_lookup,
        dns_whois, ssl_checker, port_scanner,
        web_crawler, http_headers, screenshot
    )
    from aggregator.merge import aggregate

    start_time = time.time()

    # ══════════════════════════════════════════════════════════
    # PHASE 1 — PASSIVE RECON
    # ══════════════════════════════════════════════════════════
    log_phase("PHASE 1 — PASSIVE RECONNAISSANCE")

    run_module("subdomain_enum", lambda: subdomain_enum.run(
        domain=args.url, output_dir=json_dir,
        passive_only=args.passive_only
    ), skip)

    run_module("osint", lambda: osint_harvest.run(
        domain=args.url, output_dir=json_dir
    ), skip)

    run_module("shodan", lambda: shodan_lookup.run(
        domain=args.url, output_dir=json_dir,
        ip_mode=args.ip_mode
    ), skip)

    run_module("dns", lambda: dns_whois.run(
        domain=args.url, output_dir=json_dir
    ), skip)

    run_module("ssl", lambda: ssl_checker.run(
        domain=args.url, output_dir=json_dir
    ), skip)

    # ══════════════════════════════════════════════════════════
    # PHASE 2 — ACTIVE RECON (skip if passive-only)
    # ══════════════════════════════════════════════════════════
    if not args.passive_only:
        log_phase("PHASE 2 — ACTIVE RECONNAISSANCE")

        run_module("port_scanner", lambda: port_scanner.run(
            target=args.url, output_dir=json_dir,
            top_ports=args.top_ports, speed=args.speed
        ), skip)

        run_module("web_crawler", lambda: web_crawler.run(
            domain=args.url, output_dir=json_dir,
            threads=args.threads, https=args.https
        ), skip)

        run_module("http_headers", lambda: http_headers.run(
            domain=args.url, output_dir=json_dir,
            https=args.https, run_nikto_scan=args.nikto
        ), skip)

        run_module("screenshots", lambda: screenshot.run(
            domain=args.url, output_dir=args.output,
            subdomains_json=f"{json_dir}/subdomain_enum.json"
        ), skip)

    else:
        log_warn("Passive-only mode — skipping all active modules")

    # ══════════════════════════════════════════════════════════
    # PHASE 3 — AGGREGATE
    # ══════════════════════════════════════════════════════════
    log_phase("PHASE 3 — AGGREGATING RESULTS")
    merged = aggregate(json_dir=json_dir, domain=args.url)

    # ══════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ══════════════════════════════════════════════════════════
    elapsed = round(time.time() - start_time, 1)
    print_final_summary(merged, args.url, elapsed)

    log_success(f"All results saved in: {args.output}/")
    log_success(f"JSON report        : {json_dir}/recon_report.json")
    log_warn("PDF report         : Run Phase 5 to generate PDF")


if __name__ == "__main__":
    main()
