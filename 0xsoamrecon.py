#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   0xSoamRecon — Automated Red Team Reconnaissance Tool
#   Author  : Udit Soam
#   GitHub  : https://github.com/uditsoam/0xSoamRecon
# ═══════════════════════════════════════════════════════════

import os, sys, time, yaml, argparse
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

# ── ANSI shortcuts ───────────────────────────────────────────
CY  = "\033[96m"   # cyan
GR  = "\033[92m"   # green
YL  = "\033[93m"   # yellow
RD  = "\033[91m"   # red
WH  = "\033[97m"   # white
DM  = "\033[90m"   # dim
MG  = "\033[95m"   # magenta
BL  = "\033[94m"   # blue
RS  = "\033[0m"    # reset
BLD = "\033[1m"    # bold

BANNER = f"""
{CY}
  ██████╗ ██╗  ██╗    ███████╗ ██████╗  █████╗ ███╗   ███╗
 ██╔═████╗╚██╗██╔╝    ██╔════╝██╔═══██╗██╔══██╗████╗ ████║
 ██║██╔██║ ╚███╔╝     ███████╗██║   ██║███████║██╔████╔██║
 ████╔╝██║ ██╔██╗     ╚════██║██║   ██║██╔══██║██║╚██╔╝██║
 ╚██████╔╝██╔╝ ██╗    ███████║╚██████╔╝██║  ██║██║ ╚═╝ ██║
  ╚═════╝ ╚═╝  ╚═╝    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝
{RS}{YL}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RS}
{WH}  ┌─────────────────────────────────────────────────────┐{RS}
{WH}  │  {CY}Red Team Reconnaissance Framework  {YL}v2.0{WH}          │{RS}
{WH}  │  {GR}Author : Udit Soam{WH}                                │{RS}
{WH}  │  {BL}GitHub : github.com/uditsoam/0xSoamRecon{WH}          │{RS}
{WH}  │  {RD}WARNING: Authorized targets only!{WH}                 │{RS}
{WH}  └─────────────────────────────────────────────────────┘{RS}
"""

# ── Module definitions ───────────────────────────────────────
GROUPS = [
    {
        "id"    : 1,
        "name"  : "PASSIVE INTELLIGENCE",
        "color" : CY,
        "icon"  : "👁 ",
        "desc"  : "No direct contact with target — safe & stealthy",
        "modules": [
            {"id":1,  "name":"Subdomain Enumeration",   "tool":"Amass + Subfinder", "desc":"Find all subdomains of target",               "file":"subdomain_enum" },
            {"id":2,  "name":"OSINT Harvesting",        "tool":"theHarvester",      "desc":"Emails, names from public OSINT sources",     "file":"osint_harvest"  },
            {"id":3,  "name":"Shodan Intelligence",     "tool":"Shodan API",        "desc":"Exposed services, banners, CVEs via Shodan",  "file":"shodan_lookup"  },
            {"id":4,  "name":"DNS & Whois Analysis",    "tool":"dig + whois",       "desc":"DNS records, registrar, org details",         "file":"dns_whois"      },
            {"id":5,  "name":"SSL Certificate History", "tool":"crt.sh",            "desc":"SSL cert history, alternative domains",       "file":"ssl_checker"    },
        ]
    },
    {
        "id"    : 2,
        "name"  : "ACTIVE RECONNAISSANCE",
        "color" : GR,
        "icon"  : "⚡",
        "desc"  : "Direct contact with target — may leave logs",
        "modules": [
            {"id":6,  "name":"Port Scanner",            "tool":"Nmap",              "desc":"Open ports, services, version detection",     "file":"port_scanner"   },
            {"id":7,  "name":"Web Directory Crawler",   "tool":"Gobuster + ffuf",   "desc":"Hidden dirs, admin panels, backup files",     "file":"web_crawler"    },
            {"id":8,  "name":"HTTP Header Analysis",    "tool":"curl + Nikto",      "desc":"Security headers, misconfigs, server info",   "file":"http_headers"   },
            {"id":9,  "name":"Web Screenshots",         "tool":"EyeWitness",        "desc":"Visual screenshots of all web assets",        "file":"screenshot"     },
        ]
    },
    {
        "id"    : 3,
        "name"  : "ADVANCED INTELLIGENCE",
        "color" : YL,
        "icon"  : "🔬",
        "desc"  : "Deep recon — API keys needed for best results",
        "modules": [
            {"id":10, "name":"Tech Stack Fingerprint",  "tool":"WhatWeb",           "desc":"CMS, framework, CDN, JS library detection",   "file":"tech_stack"     },
            {"id":11, "name":"Subdomain Takeover",      "tool":"DNS + HTTP",        "desc":"Find vulnerable unclaimed subdomains",         "file":"takeover_check" },
            {"id":12, "name":"GitHub Dorking",          "tool":"GitHub API",        "desc":"Leaked secrets, API keys, configs in repos",  "file":"github_dork"    },
            {"id":13, "name":"Wayback Machine URLs",    "tool":"archive.org",       "desc":"Historical URLs, deleted pages, endpoints",   "file":"wayback"        },
        ]
    },
    {
        "id"    : 4,
        "name"  : "OSINT EXTRAS",
        "color" : MG,
        "icon"  : "🕵",
        "desc"  : "Additional intelligence gathering modules",
        "modules": [
            {"id":14, "name":"Email Breach Check",      "tool":"HaveIBeenPwned",    "desc":"Check emails against breach databases",       "file":"email_breach"   },
            {"id":15, "name":"CVE Auto Lookup",         "tool":"NVD API",           "desc":"Match service versions to known CVEs",        "file":"cve_lookup"     },
            {"id":16, "name":"Google Dork Generator",   "tool":"Auto Generate",     "desc":"100+ dorks across 8 categories",              "file":"dork_generator" },
        ]
    },
]

REPORT_MODULES = [
    {"id":17, "name":"Risk Score Calculator",  "tool":"0-100 Scoring",    "desc":"Calculate overall risk score with grade"    },
    {"id":18, "name":"Recommendations Engine", "tool":"Auto Suggestions",  "desc":"Prioritized remediation recommendations"    },
    {"id":19, "name":"PDF + HTML Report",      "tool":"WeasyPrint",        "desc":"Professional pentest-grade PDF report"      },
    {"id":20, "name":"Scan History Log",       "tool":"Local JSON DB",     "desc":"Save and compare scans over time"           },
]

ALL_MODULES = {}
for g in GROUPS:
    for m in g["modules"]:
        ALL_MODULES[m["id"]] = {**m, "group_id": g["id"], "group_name": g["name"], "group_color": g["color"]}
for m in REPORT_MODULES:
    ALL_MODULES[m["id"]] = {**m, "group_id": 5, "group_name": "REPORT & ANALYSIS", "group_color": BL}


# ── Helpers ──────────────────────────────────────────────────
def clr():
    os.system("clear")

def div(char="═", n=64, color=WH):
    print(f"{color}{char*n}{RS}")

def hdr(title, subtitle=""):
    div()
    print(f"{WH}  {title}{RS}")
    if subtitle:
        print(f"{DM}  {subtitle}{RS}")
    div("─", 64, DM)

def inp(prompt):
    try:
        return input(f"\n{YL}  ❯ {prompt}: {RS}").strip().upper()
    except KeyboardInterrupt:
        print(f"\n{YL}  Exiting...{RS}")
        sys.exit(0)

def load_config():
    try:
        with open("config/config.yaml") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}

def save_config(cfg):
    try:
        with open("config/config.yaml", "w") as f:
            yaml.dump(cfg, f, default_flow_style=False)
    except Exception:
        pass

def needs_setup():
    cfg = load_config()
    k   = cfg.get("shodan", {}).get("api_key", "")
    return not k or k == "USER_SHODAN_KEY"


# ── First time setup ─────────────────────────────────────────
def setup_wizard():
    cfg     = load_config()
    changed = False
    clr()
    print(BANNER)
    hdr("API KEY SETUP WIZARD", "All keys are FREE — press ENTER to skip any")
    print(f"""
{WH}  These keys unlock specific modules:{RS}
  {CY}Shodan API{RS}       → Module 03 — Internet exposure intel
  {CY}GitHub Token{RS}     → Module 12 — GitHub secret scanning
  {CY}HIBP Key{RS}         → Module 14 — Email breach checking
  {CY}NVD API Key{RS}      → Module 15 — CVE auto lookup
""")

    keys = [
        ("Shodan API Key",     "shodan",        "api_key", "USER_SHODAN_KEY",   "shodan.io"),
        ("GitHub Token",       "github",        "token",   "USER_GITHUB_TOKEN", "github.com/settings/tokens"),
        ("HaveIBeenPwned Key", "haveibeenpwned","api_key", "USER_HIBP_KEY",     "haveibeenpwned.com/API"),
        ("NVD API Key",        "nvd",           "api_key", "USER_NVD_KEY",      "nvd.nist.gov/developers"),
    ]

    for label, sec, field, ph, url in keys:
        cur = cfg.get(sec, {}).get(field, "")
        if not cur or cur == ph:
            div("─", 64, DM)
            print(f"  {CY}{label}{RS}")
            print(f"  {DM}Get free: {url}{RS}")
            try:
                val = input(f"  Enter key (ENTER to skip): ").strip()
            except KeyboardInterrupt:
                sys.exit(0)
            if val:
                if sec not in cfg: cfg[sec] = {}
                cfg[sec][field] = val
                changed = True
                print(f"  {GR}✅ Saved{RS}")
            else:
                print(f"  {DM}⏭  Skipped{RS}")

    if changed:
        save_config(cfg)
        print(f"\n  {GR}✅ Config saved → config/config.yaml{RS}")

    div()
    try:
        input(f"\n  {WH}Press ENTER to continue...{RS}")
    except KeyboardInterrupt:
        sys.exit(0)


# ── Group overview screen ────────────────────────────────────
def show_groups_overview(domain, selections):
    clr()
    print(BANNER)
    hdr(f"MODULE GROUPS — {domain}", "Select modules from each group then review & run")
    print()

    for grp in GROUPS:
        sel_count = len(selections.get(grp["id"], set()))
        total     = len(grp["modules"])
        color     = grp["color"]
        bar_filled = "█" * sel_count
        bar_empty  = "░" * (total - sel_count)
        status    = f"{GR}[{bar_filled}{DM}{bar_empty}{GR}] {sel_count}/{total}{RS}"

        print(
            f"  {color}[{grp['id']}]{RS}  "
            f"{WH}{grp['icon']}  {grp['name']:<28}{RS}"
            f"  {status}"
        )
        print(f"       {DM}{grp['desc']}{RS}")
        print()

    total_sel = sum(len(v) for v in selections.values())
    div("─", 64, DM)
    print(f"""
  {YL}[1-4]{RS}  Enter group number to select modules
  {GR}[R]{RS}    Review & edit final selection
  {GR}[RUN]{RS}  Skip to run with current selection
  {RD}[EXIT]{RS} Quit
""")
    div("─", 64, DM)
    print(f"  {WH}Total modules selected: {GR}{total_sel}{RS}")


# ── Single group selection screen ────────────────────────────
def show_group_screen(grp, selected_ids):
    clr()
    print(BANNER)
    color = grp["color"]

    hdr(
        f"GROUP {grp['id']} — {grp['icon']}  {grp['name']}",
        grp["desc"]
    )

    print(f"\n  {'NUM':<6} {'MODULE NAME':<28} {'TOOL':<22} {'STATUS'}{RS}")
    div("─", 64, DM)

    for mod in grp["modules"]:
        mid    = mod["id"]
        is_on  = mid in selected_ids
        status = f"{GR}● ON {RS}" if is_on else f"{DM}○ OFF{RS}"
        num    = f"{color}[{mid:02d}]{RS}"
        name   = f"{WH}{mod['name']}{RS}" if is_on else f"{DM}{mod['name']}{RS}"
        tool   = f"{BL}{mod['tool']}{RS}"

        print(f"  {num}  {name:<37} {tool:<31} {status}")
        print(f"        {DM}└─ {mod['desc']}{RS}\n")

    div("─", 64, DM)

    sel_count = len(selected_ids)
    total     = len(grp["modules"])

    print(f"""
  {YL}[01-{grp['modules'][-1]['id']:02d}]{RS}  Type number(s) to toggle  {DM}e.g: 1  or  1,3{RS}
  {GR}[A]{RS}      Select ALL modules in this group
  {RD}[N]{RS}      Deselect ALL modules in this group
  {WH}[ENTER]{RS}  Confirm & continue to next group
  {CY}[B]{RS}      Back to groups overview
""")
    div("─", 64, DM)
    print(f"  {WH}Selected: {GR}{sel_count}{RS}{WH}/{total}{RS} in this group")


# ── Review screen ─────────────────────────────────────────────
def show_review_screen(selections, domain):
    clr()
    print(BANNER)

    all_selected = set()
    for v in selections.values():
        all_selected.update(v)

    hdr(
        f"FINAL REVIEW — {domain}",
        "Add or remove modules before running"
    )

    if not all_selected:
        print(f"\n  {RD}No modules selected!{RS}\n")
    else:
        for grp in GROUPS:
            grp_sel = [m for m in grp["modules"] if m["id"] in all_selected]
            if grp_sel:
                color = grp["color"]
                print(f"\n  {color}{grp['icon']}  {grp['name']}{RS}")
                div("─", 64, DM)
                for mod in grp_sel:
                    print(
                        f"  {GR}✅{RS}  "
                        f"{WH}[{mod['id']:02d}]{RS}  "
                        f"{mod['name']:<28}  "
                        f"{DM}{mod['tool']}{RS}"
                    )

        # Report modules always included
        print(f"\n  {BL}📊  REPORT & ANALYSIS{RS}  {DM}(always included){RS}")
        div("─", 64, DM)
        for m in REPORT_MODULES:
            print(f"  {GR}✅{RS}  {WH}[{m['id']:02d}]{RS}  {m['name']:<28}  {DM}{m['tool']}{RS}")

    passive  = len([s for s in all_selected if ALL_MODULES.get(s,{}).get("group_id") == 1])
    active_c = len([s for s in all_selected if ALL_MODULES.get(s,{}).get("group_id") == 2])
    advanced = len([s for s in all_selected if ALL_MODULES.get(s,{}).get("group_id") in [3,4]])
    est_min  = int((passive*1.5) + (active_c*3) + (advanced*2))
    est_max  = int(est_min * 1.8)

    print(f"\n  {YL}Estimated time: {est_min}-{est_max} minutes{RS}")

    div("─", 64, DM)
    print(f"""
  {YL}[01-16]{RS}  Toggle a module ON/OFF by number
  {CY}[1-4]{RS}    Go back and edit a group
  {GR}[RUN]{RS}    Confirm and start scan
  {RD}[CLEAR]{RS}  Remove all selections
""")
    div("─", 64, DM)
    print(f"  {WH}Total: {GR}{len(all_selected)}{RS}{WH} modules + 4 report modules{RS}")

    return all_selected


# ── Main wizard flow ─────────────────────────────────────────
def wizard(domain):
    selections = {g["id"]: set() for g in GROUPS}
    grp_map    = {g["id"]: g for g in GROUPS}
    mod_to_grp = {}
    for g in GROUPS:
        for m in g["modules"]:
            mod_to_grp[m["id"]] = g["id"]

    state = "OVERVIEW"  # states: OVERVIEW, GROUP_n, REVIEW

    while True:

        # ── OVERVIEW ─────────────────────────────────────────
        if state == "OVERVIEW":
            show_groups_overview(domain, selections)
            cmd = inp("Enter group number, R to review, or RUN")

            if cmd in ["1","2","3","4"]:
                state = f"GROUP_{cmd}"

            elif cmd == "R" or cmd == "REVIEW":
                state = "REVIEW"

            elif cmd == "RUN":
                all_sel = set()
                for v in selections.values():
                    all_sel.update(v)
                all_sel.update([17,18,19,20])
                return sorted(list(all_sel))

            elif cmd == "EXIT":
                print(f"\n{YL}  Goodbye!{RS}")
                sys.exit(0)

        # ── GROUP SCREEN ─────────────────────────────────────
        elif state.startswith("GROUP_"):
            gid     = int(state.split("_")[1])
            grp     = grp_map[gid]
            mod_ids = [m["id"] for m in grp["modules"]]

            show_group_screen(grp, selections[gid])
            cmd = inp(f"Select modules for {grp['name']}")

            if not cmd:
                # ENTER — confirm, go to next group or overview
                next_gid = gid + 1
                if next_gid <= 4:
                    state = f"GROUP_{next_gid}"
                else:
                    state = "REVIEW"

            elif cmd == "B":
                state = "OVERVIEW"

            elif cmd == "A":
                selections[gid] = set(mod_ids)
                print(f"\n  {GR}✅ All {len(mod_ids)} modules selected{RS}")
                time.sleep(0.7)

            elif cmd == "N":
                selections[gid] = set()
                print(f"\n  {DM}  All modules deselected{RS}")
                time.sleep(0.7)

            elif cmd == "EXIT":
                print(f"\n{YL}  Goodbye!{RS}")
                sys.exit(0)

            else:
                # Parse numbers
                try:
                    nums = [int(x.strip()) for x in cmd.split(",") if x.strip().isdigit()]
                    for num in nums:
                        if num in mod_ids:
                            if num in selections[gid]:
                                selections[gid].discard(num)
                                mod_name = next(m["name"] for m in grp["modules"] if m["id"] == num)
                                print(f"\n  {RD}[-] {num:02d} — {mod_name} → OFF{RS}")
                            else:
                                selections[gid].add(num)
                                mod_name = next(m["name"] for m in grp["modules"] if m["id"] == num)
                                print(f"\n  {GR}[+] {num:02d} — {mod_name} → ON{RS}")
                        else:
                            print(f"\n  {RD}[!] {num} not in this group{RS}")
                    time.sleep(0.8)
                except ValueError:
                    print(f"\n  {RD}Invalid — enter numbers like: 1 or 1,3{RS}")
                    time.sleep(0.8)

        # ── REVIEW SCREEN ─────────────────────────────────────
        elif state == "REVIEW":
            all_sel = show_review_screen(selections, domain)
            cmd     = inp("RUN to start, number to toggle, 1-4 to edit group")

            if cmd == "RUN":
                if not all_sel:
                    print(f"\n  {RD}No modules selected — go back and select some{RS}")
                    time.sleep(1.2)
                else:
                    final = set(all_sel)
                    final.update([17,18,19,20])
                    return sorted(list(final))

            elif cmd == "CLEAR":
                for gid in selections:
                    selections[gid] = set()
                print(f"\n  {YL}All selections cleared{RS}")
                time.sleep(0.8)

            elif cmd in ["1","2","3","4"]:
                state = f"GROUP_{cmd}"

            elif cmd == "EXIT":
                print(f"\n{YL}  Goodbye!{RS}")
                sys.exit(0)

            elif cmd.replace(",","").replace(" ","").isdigit():
                # Toggle individual modules
                try:
                    nums = [int(x.strip()) for x in cmd.split(",") if x.strip().isdigit()]
                    for num in nums:
                        if 1 <= num <= 16:
                            gid = mod_to_grp.get(num)
                            if gid:
                                if num in selections[gid]:
                                    selections[gid].discard(num)
                                    print(f"\n  {RD}[-] Module {num:02d} — {ALL_MODULES[num]['name']} → OFF{RS}")
                                else:
                                    selections[gid].add(num)
                                    print(f"\n  {GR}[+] Module {num:02d} — {ALL_MODULES[num]['name']} → ON{RS}")
                        else:
                            print(f"\n  {RD}[!] Invalid module: {num} (1-16 only){RS}")
                    time.sleep(0.8)
                except ValueError:
                    pass


# ── Scan confirmation ─────────────────────────────────────────
def confirm_screen(selected, domain, args):
    clr()
    print(BANNER)
    hdr(f"READY TO SCAN — {domain}", "Final confirmation before execution")

    print(f"\n  {CY}Target    :{RS} {GR}{domain}{RS}")
    print(f"  {CY}Output    :{RS} {args.output}")
    print(f"  {CY}Nmap Speed:{RS} {args.speed}")
    print(f"  {CY}Modules   :{RS} {GR}{len(selected)}{RS} total\n")

    for grp in GROUPS:
        grp_mods = [ALL_MODULES[s] for s in selected if ALL_MODULES.get(s,{}).get("group_id") == grp["id"]]
        if grp_mods:
            print(f"  {grp['color']}{grp['icon']}  {grp['name']}{RS}")
            for m in grp_mods:
                print(f"    {GR}✅{RS}  {m['name']}")
            print()

    report_sel = [ALL_MODULES[s] for s in selected if ALL_MODULES.get(s,{}).get("group_id") == 5]
    if report_sel:
        print(f"  {BL}📊  REPORT & ANALYSIS{RS}")
        for m in report_sel:
            print(f"    {GR}✅{RS}  {m['name']}")
        print()

    passive  = len([s for s in selected if ALL_MODULES.get(s,{}).get("group_id") == 1])
    active_c = len([s for s in selected if ALL_MODULES.get(s,{}).get("group_id") == 2])
    advanced = len([s for s in selected if ALL_MODULES.get(s,{}).get("group_id") in [3,4]])
    est_min  = int((passive*1.5) + (active_c*3) + (advanced*2))
    est_max  = int(est_min * 1.8)

    print(f"  {YL}Estimated scan time: {est_min}–{est_max} minutes{RS}\n")
    div()

    try:
        ans = input(f"\n  {GR}Start scan? (Y/n): {RS}").strip().lower()
    except KeyboardInterrupt:
        sys.exit(0)
    return ans in ["", "y", "yes"]


# ── Logging ───────────────────────────────────────────────────
def log_i(m):  print(f"{CY}[*] {m}{RS}")
def log_s(m):  print(f"{GR}[+] {m}{RS}")
def log_w(m):  print(f"{YL}[!] {m}{RS}")
def log_e(m):  print(f"{RD}[-] {m}{RS}")
def log_ph(m): print(f"\n{WH}\033[44m {m} \033[0m\n")


def run_mod(name, func):
    log_i(f"Running: {name}")
    t = time.time()
    try:
        r = func()
        log_s(f"{name} — done in {round(time.time()-t,1)}s")
        return r or {}
    except Exception as e:
        log_e(f"{name} failed: {e}")
        return {}


# ── Final summary ─────────────────────────────────────────────
def final_summary(merged, domain, elapsed, selected):
    s = merged.get("summary", {})
    clr()
    print(BANNER)
    div()
    print(f"{GR}  ✅  SCAN COMPLETE{RS}")
    div("─", 64, DM)
    print(f"  {CY}Target{RS}         : {GR}{domain}{RS}")
    print(f"  {CY}Completed{RS}      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {CY}Total Time{RS}     : {elapsed}s")
    print(f"  {CY}Modules Run{RS}    : {len(selected)}/20")
    div("─", 64, DM)
    print(f"  {CY}Subdomains{RS}     : {YL}{s.get('total_subdomains',0)}{RS}")
    print(f"  {CY}Emails{RS}         : {YL}{s.get('total_emails',0)}{RS}")
    print(f"  {CY}Open Ports{RS}     : {YL}{s.get('total_open_ports',0)}{RS}  {RD}({s.get('high_risk_ports',0)} HIGH){RS}")
    print(f"  {CY}Web Paths{RS}      : {YL}{s.get('total_web_paths',0)}{RS}  {RD}({s.get('juicy_paths',0)} JUICY){RS}")
    print(f"  {CY}SSL Certs{RS}      : {YL}{s.get('total_certs',0)}{RS}")
    print(f"  {CY}Shodan{RS}         : {YL}{s.get('shodan_results',0)}{RS}")

    g  = s.get("security_grade","N/A")
    gc = GR if g in ["A","B"] else YL if g=="C" else RD
    print(f"  {CY}Security Grade{RS} : {gc}{g}{RS}")

    rs_val = s.get("risk_score","N/A")
    rg_val = s.get("risk_grade","N/A")
    if rs_val != "N/A":
        try:
            rc = GR if int(str(rs_val))>=75 else YL if int(str(rs_val))>=50 else RD
            print(f"  {CY}Risk Score{RS}     : {rc}{rs_val}/100  (Grade: {rg_val}){RS}")
        except Exception:
            pass

    cves = s.get("cves_detected",[])
    if cves:
        print(f"\n  {RD}[!!!] CVEs DETECTED: {cves}{RS}")

    div("─", 64, DM)
    print(f"  {GR}PDF Report  → output/reports/{RS}")
    print(f"  {GR}JSON Data   → output/json/recon_report.json{RS}")
    print(f"  {GR}History     → python3 0xsoamrecon.py --history{RS}")
    div()


# ── Args ──────────────────────────────────────────────────────
def get_args():
    p = argparse.ArgumentParser(
        prog="0xsoamrecon.py",
        description="0xSoamRecon — Red Team Reconnaissance Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 0xsoamrecon.py -u target.com
  python3 0xsoamrecon.py -u target.com --speed T3
  python3 0xsoamrecon.py -u target.com --no-interactive
  python3 0xsoamrecon.py --history

Safe test targets:
  testphp.vulnweb.com    Acunetix vulnerable lab
  scanme.nmap.org        Official Nmap test server
        """
    )
    p.add_argument("-u","--url",          default=None,     help="Target domain or IP")
    p.add_argument("-o","--output",       default="output", help="Output directory (default: output)")
    p.add_argument("--speed",             default="T4",     choices=["T1","T2","T3","T4","T5"])
    p.add_argument("--top-ports",         type=int, default=1000)
    p.add_argument("--threads",           type=int, default=50)
    p.add_argument("--https",             action="store_true")
    p.add_argument("--no-interactive",    action="store_true", help="Run standard scan without wizard")
    p.add_argument("--history",           action="store_true", help="Show scan history and exit")
    p.add_argument("--no-banner",         action="store_true")
    return p.parse_args()


# ── Main ──────────────────────────────────────────────────────
def main():
    args = get_args()

    if not args.no_banner:
        clr()
        print(BANNER)

    if args.history:
        from modules.scan_history import list_all_history
        list_all_history()
        sys.exit(0)

    if needs_setup():
        print(f"  {YL}[!] API keys not configured.{RS}")
        try:
            go = input(f"  Run setup wizard? (Y/n): ").strip().lower()
        except KeyboardInterrupt:
            sys.exit(0)
        if go in ["","y","yes"]:
            setup_wizard()

    # Get target
    if not args.url:
        clr()
        print(BANNER)
        print(f"\n  {CY}0xSoamRecon — Red Team Reconnaissance{RS}")
        print(f"  {DM}github.com/uditsoam/0xSoamRecon{RS}\n")
        div("─", 64, DM)
        try:
            domain = input(f"\n  {YL}❯ Enter target domain or IP: {RS}").strip()
        except KeyboardInterrupt:
            sys.exit(0)
        if not domain:
            log_e("No target — exiting")
            sys.exit(1)
    else:
        domain = args.url

    domain = domain.replace("http://","").replace("https://","").rstrip("/")

    # Dirs
    json_dir   = os.path.join(args.output, "json")
    report_dir = os.path.join(args.output, "reports")
    for d in [json_dir, report_dir, os.path.join(args.output,"screenshots"), "history"]:
        os.makedirs(d, exist_ok=True)

    # Select modules
    if args.no_interactive:
        selected = [1,2,3,4,5,6,7,8,9,17,18,19,20]
        log_i(f"Standard scan — {len(selected)} modules")
    else:
        selected = wizard(domain)
        if not selected:
            log_w("Nothing selected — exiting")
            sys.exit(0)
        if not confirm_screen(selected, domain, args):
            log_w("Cancelled")
            sys.exit(0)

    # Imports
    from modules import (
        subdomain_enum, osint_harvest, shodan_lookup,
        dns_whois, ssl_checker, port_scanner,
        web_crawler, http_headers, screenshot,
        tech_stack, takeover_check, github_dork,
        wayback, email_breach, cve_lookup,
        dork_generator, scan_history
    )
    from aggregator.merge import aggregate
    from reporter.report_generator import generate_report

    t0 = time.time()
    clr()
    print(BANNER)
    div()
    log_i(f"Target  : {GR}{domain}{RS}")
    log_i(f"Modules : {len(selected)} selected")
    log_i(f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    div()
    print()

    # Run modules
    if any(m in selected for m in [1,2,3,4,5]):
        log_ph("GROUP 1 — PASSIVE INTELLIGENCE")
        if 1 in selected: run_mod("Subdomain Enumeration",  lambda: subdomain_enum.run(domain=domain, output_dir=json_dir))
        if 2 in selected: run_mod("OSINT Harvesting",       lambda: osint_harvest.run(domain=domain, output_dir=json_dir))
        if 3 in selected: run_mod("Shodan Intelligence",    lambda: shodan_lookup.run(domain=domain, output_dir=json_dir))
        if 4 in selected: run_mod("DNS & Whois Analysis",   lambda: dns_whois.run(domain=domain, output_dir=json_dir))
        if 5 in selected: run_mod("SSL Certificate History",lambda: ssl_checker.run(domain=domain, output_dir=json_dir))

    if any(m in selected for m in [6,7,8,9]):
        log_ph("GROUP 2 — ACTIVE RECONNAISSANCE")
        if 6 in selected: run_mod("Port Scanner",           lambda: port_scanner.run(target=domain, output_dir=json_dir, top_ports=args.top_ports, speed=args.speed))
        if 7 in selected: run_mod("Web Directory Crawler",  lambda: web_crawler.run(domain=domain, output_dir=json_dir, threads=args.threads, https=args.https))
        if 8 in selected: run_mod("HTTP Header Analysis",   lambda: http_headers.run(domain=domain, output_dir=json_dir, https=args.https))
        if 9 in selected: run_mod("Web Screenshots",        lambda: screenshot.run(domain=domain, output_dir=args.output, subdomains_json=f"{json_dir}/subdomain_enum.json"))

    if any(m in selected for m in [10,11,12,13]):
        log_ph("GROUP 3 — ADVANCED INTELLIGENCE")
        if 10 in selected: run_mod("Tech Stack Fingerprint", lambda: tech_stack.run(domain=domain, output_dir=json_dir))
        if 11 in selected: run_mod("Subdomain Takeover",     lambda: takeover_check.run(domain=domain, output_dir=json_dir))
        if 12 in selected: run_mod("GitHub Dorking",         lambda: github_dork.run(domain=domain, output_dir=json_dir))
        if 13 in selected: run_mod("Wayback Machine URLs",   lambda: wayback.run(domain=domain, output_dir=json_dir))

    if any(m in selected for m in [14,15,16]):
        log_ph("GROUP 4 — OSINT EXTRAS")
        if 14 in selected: run_mod("Email Breach Check",     lambda: email_breach.run(domain=domain, output_dir=json_dir))
        if 15 in selected: run_mod("CVE Auto Lookup",        lambda: cve_lookup.run(domain=domain, output_dir=json_dir))
        if 16 in selected: run_mod("Google Dork Generator",  lambda: dork_generator.run(domain=domain, output_dir=json_dir))

    log_ph("GROUP 5 — REPORT & ANALYSIS")
    log_i("Aggregating results...")
    merged = aggregate(json_dir=json_dir, domain=domain)

    if 19 in selected:
        run_mod("PDF + HTML Report", lambda: generate_report(
            json_path=f"{json_dir}/recon_report.json", output_dir=report_dir))

    if 20 in selected:
        elapsed = round(time.time()-t0, 1)
        scan_history.save_scan(
            domain      = domain,
            modules_run = [ALL_MODULES[s]["name"] for s in selected if s in ALL_MODULES],
            summary     = merged.get("summary",{}),
            report_path = report_dir,
            duration    = elapsed)

    final_summary(merged, domain, round(time.time()-t0,1), selected)


if __name__ == "__main__":
    main()
