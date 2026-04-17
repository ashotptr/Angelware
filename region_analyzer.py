#!/usr/bin/env python3
"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Multi-Region Honeypot Data Analyser
 Environment: ISOLATED VM LAB ONLY
====================================================

Source: JHU HotSoS '24 §4 — Data Collection and Analysis of Bot Interactions

Implements ALL quantitative analyses from the paper that are absent from
generate_graphs.py (which covers DPI, persistence, and IDS accuracy only):

  1. Wordlist proportion matching
       Paper Table 2 — what % of observed credentials appear in
       rockyou.txt, sqlmap.txt, nmap.lst, john.lst, metasploit wordlists.
       Without the actual wordlists, we compute a simulated match using
       known-weak password sets, with a hook to load real wordlist files.

  2. Country-level IP attribution tables
       Paper Tables 1, 5, 6 — top 5 source countries per service per region.
       Driven by geoip_sim.py lookups on logged IPs.

  3. Per-service daily traffic graphs
       Paper Figures 2, 4, 5 — daily connection count vs IP count for
       SSH, Apache, and RDP across simulated EA / WE / EUS regions.

  4. Hourly temporal analysis
       Paper Figure 3 — hourly attack distribution per region.

Usage
─────
  python3 region_analyzer.py --cowrie /path/to/cowrie.json
  python3 region_analyzer.py --honeypot /path/to/honeypot.json
  python3 region_analyzer.py --simulate           # generate synthetic data
  python3 region_analyzer.py --all --out ./graphs/
"""

import argparse
import datetime
import json
import math
import os
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    PLT_OK = True
except ImportError:
    PLT_OK = False
    print("[REGION] matplotlib not installed — pip3 install matplotlib")

try:
    import geoip_sim
    GEO_OK = True
except ImportError:
    GEO_OK = False
    print("[REGION] geoip_sim.py not found — using built-in country heuristics")

# ── Output dir ────────────────────────────────────────────────
DEFAULT_OUT = Path("./graphs")

# ── Regions (mirroring the paper's three deployment zones) ────
REGIONS = ["East Asia (EA)", "West Europe (WE)", "East US (EUS)"]
REGION_SHORT = ["EA", "WE", "EUS"]

# ── Known weak passwords (subset of rockyou.txt top entries) ──
# Used when actual wordlist files are not available.
ROCKYOU_SAMPLE = {
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "123123", "admin", "letmein", "monkey", "master",
    "login", "dragon", "654321", "shadow", "1234",
    "superman", "michael", "football", "baseball", "iloveyou",
    "sunshine", "princess", "welcome", "passw0rd", "password1",
    "password123", "admin123", "root", "toor", "test",
    "guest", "user", "default", "raspberry", "ubnt",
    "345gs5662d34", "3245gs5662d34",   # observed in paper Table 3
}

SQLMAP_SAMPLE = {
    "admin", "123456", "password", "12345", "test", "root",
    "toor", "1234", "qwerty", "abc123", "pass", "changeme",
    "345gs5662d34", "3245gs5662d34", "admin123", "letmein",
}

NMAP_SAMPLE = {
    "admin", "root", "password", "test", "user",
    "1234", "12345", "123456", "ubnt", "admin1",
}

JOHN_SAMPLE = {
    "password", "123456", "abc123", "qwerty", "letmein",
    "admin", "welcome", "monkey", "dragon", "password1",
}

METASPLOIT_SAMPLE = {
    "admin", "root", "password", "pass", "123456",
    "1234", "admin123", "test", "user", "default",
}

WORDLISTS = {
    "rockyou.txt":  ROCKYOU_SAMPLE,
    "sqlmap.txt":   SQLMAP_SAMPLE,
    "nmap.lst":     NMAP_SAMPLE,
    "john.lst":     JOHN_SAMPLE,
    "metasploit":   METASPLOIT_SAMPLE,
}

WORDLIST_FILES = {
    "rockyou.txt": "/usr/share/wordlists/rockyou.txt",
    "sqlmap.txt":  "/usr/share/sqlmap/data/txt/wordlist.txt",
}


# ══════════════════════════════════════════════════════════════
#  WORDLIST LOADER
# ══════════════════════════════════════════════════════════════

def _load_wordlist(name: str, filepath: str, limit: int = 100_000) -> set:
    """Load a real wordlist file if available, else return the sample set."""
    if os.path.exists(filepath):
        words = set()
        with open(filepath, errors="replace") as f:
            for i, line in enumerate(f):
                if i >= limit:
                    break
                words.add(line.strip().lower())
        print(f"[REGION] Loaded {len(words):,} entries from {filepath}")
        return words
    return WORDLISTS.get(name, set())


# ══════════════════════════════════════════════════════════════
#  1. WORDLIST PROPORTION MATCHING  (Paper Table 2)
# ══════════════════════════════════════════════════════════════

def wordlist_proportion_match(
    accounts: list,
    passwords: list,
) -> dict:
    """
    Compute the proportion of observed credentials that appear in each
    standard attack wordlist.  Mirrors Table 2 of the paper.

    Paper result:
      rockyou.txt   account=37.9%  password=49.7%
      nmap.lst      account= 8.3%  password= 7.0%
      john.lst      account= 9.4%  password= 6.7%
      metasploit    account= 1.2%  password= 2.5%
      sqlmap.txt    account=41.7%  password=46.3%

    Args:
      accounts  : list of usernames observed in login attempts
      passwords : list of passwords observed

    Returns: { wordlist_name: { "account_pct": float, "password_pct": float } }
    """
    wl_data = {}
    for wl_name, filepath in WORDLIST_FILES.items():
        wl_data[wl_name] = _load_wordlist(wl_name, filepath)
    for wl_name, sample in WORDLISTS.items():
        if wl_name not in wl_data:
            wl_data[wl_name] = sample

    acct_set = {a.lower().strip() for a in accounts if a}
    pass_set  = {p.lower().strip() for p in passwords if p}
    n_acct    = max(len(acct_set), 1)
    n_pass    = max(len(pass_set), 1)

    results = {}
    print("\n=== Wordlist Proportion Match (Paper Table 2) ===")
    print(f"  Observed unique accounts:  {n_acct}")
    print(f"  Observed unique passwords: {n_pass}")
    print(f"\n  {'Wordlist':<15} {'Account (%)':>12} {'Password (%)':>13}")
    print("  " + "─" * 42)
    for wl_name, wl_set in wl_data.items():
        acct_match = len(acct_set & wl_set)
        pass_match = len(pass_set & wl_set)
        acct_pct   = round(100.0 * acct_match / n_acct, 1)
        pass_pct   = round(100.0 * pass_match / n_pass,  1)
        results[wl_name] = {
            "account_pct":     acct_pct,
            "password_pct":    pass_pct,
            "account_matches": acct_match,
            "password_matches": pass_match,
        }
        print(f"  {wl_name:<15} {acct_pct:>11.1f}%  {pass_pct:>11.1f}%")

    # Security implication (verbatim from paper §4.2.3)
    print(
        "\n  Implication: substantial match with well-known wordlists signals"
        " that bots frequently exploit weak/default passwords."
        " This underscores the need for stringent password policies."
    )
    return results


# ══════════════════════════════════════════════════════════════
#  2. COUNTRY ATTRIBUTION TABLES  (Paper Tables 1, 5, 6)
# ══════════════════════════════════════════════════════════════

def _ip_to_country(ip: str) -> str:
    """Resolve an IP to a 2-letter country code."""
    if GEO_OK:
        try:
            return geoip_sim.lookup(ip).get("country", "XX")
        except Exception:
            pass
    # Minimal deterministic fallback based on first octet (for lab IPs)
    try:
        first = int(ip.split(".")[0])
    except Exception:
        return "XX"
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        return "AM"   # Lab = Armenia
    # Use hash for unknown IPs
    _COUNTRY_LIST = ["US", "CN", "KR", "SG", "RU", "DE", "GB", "FR", "IN", "BR"]
    return _COUNTRY_LIST[hash(ip) % len(_COUNTRY_LIST)]


def country_attribution_table(
    service_logs: dict,
    top_n: int = 5,
) -> dict:
    """
    Build top-N source country tables per service per (simulated) region.
    Mirrors Paper Tables 1 (SSH), 5 (Apache), 6 (RDP).

    Args:
      service_logs : { service_name: [{"remote_ip": ..., ...}] }

    Returns: { service: { region: [(country, count), …] } }
    """
    results = {}
    for service, events in service_logs.items():
        results[service] = {}
        print(f"\n=== Top {top_n} Countries — {service} (Paper Tables 1/5/6) ===")
        header = f"  {'Country':<10}" + "".join(
            f"  {r:>18}" for r in REGION_SHORT
        )
        print(header)
        print("  " + "─" * (10 + 22 * len(REGION_SHORT)))

        # Simulate regional distribution by seeding region offset
        for r_idx, region in enumerate(REGION_SHORT):
            rng = random.Random(hash(service + region))
            ip_list = [e["remote_ip"] for e in events]
            # Introduce region-specific perturbation (mirrors paper's EA/WE/EUS diffs)
            # EA sees more CN/KR, WE sees more RU/DE/GB, EUS sees more US
            region_weight = {
                "EA":  {"CN": 3.0, "KR": 2.5, "US": 1.0, "RU": 0.8},
                "WE":  {"RU": 2.0, "DE": 1.8, "GB": 1.6, "CN": 1.5, "US": 0.9},
                "EUS": {"US": 0.5, "CN": 2.0, "KR": 1.8, "RU": 1.5},
            }.get(region, {})
            counts: Counter = Counter()
            for ip in ip_list:
                cc = _ip_to_country(ip)
                w  = region_weight.get(cc, 1.0)
                counts[cc] += max(1, int(w * rng.uniform(0.8, 1.2)))
            top = counts.most_common(top_n)
            results[service][region] = top

        # Print side-by-side like the paper
        all_countries = list({cc for r in REGION_SHORT
                               for cc, _ in results[service].get(r, [])})[:top_n]
        for rank in range(top_n):
            row = f"  {rank + 1:<3}  "
            for region in REGION_SHORT:
                top = results[service].get(region, [])
                if rank < len(top):
                    cc, n = top[rank]
                    row += f"  {cc:<6} {n:>8}   "
                else:
                    row += f"  {'':>16}   "
            print(row)

    return results


# ══════════════════════════════════════════════════════════════
#  3. DAILY TRAFFIC GRAPHS  (Paper Figures 2, 4, 5)
# ══════════════════════════════════════════════════════════════

def _simulate_daily_traffic(
    service: str,
    n_days: int = 20,
    base_connections: int = 1000,
    base_ips: int = 40,
) -> dict:
    """
    Produce synthetic daily log count + unique IP count per region
    that statistically resembles the paper's Figure 2/4/5 data.
    """
    rng = random.Random(hash(service))
    data = {}
    for r_idx, region in enumerate(REGION_SHORT):
        multiplier = [1.8, 0.9, 0.7][r_idx]   # EA > WE > EUS (paper observation)
        logs = []
        ips  = []
        for day in range(n_days):
            # Occasional spikes (botnet campaigns, paper §4.2.1)
            spike = 5.0 if rng.random() < 0.15 else 1.0
            daily_logs = int(base_connections * multiplier * spike
                             * rng.uniform(0.6, 1.4))
            # Spikes have fewer IPs relative to log count (brute-force)
            ip_ratio = 0.02 if spike > 1 else 0.15
            daily_ips = max(1, int(daily_logs * ip_ratio * rng.uniform(0.8, 1.2)))
            logs.append(daily_logs)
            ips.append(daily_ips)
        data[region] = {"logs": logs, "ips": ips}
    return data


def plot_daily_traffic(
    service: str,
    traffic_data: dict = None,
    n_days: int = 20,
    start_date: str = "2023-10-24",
    out_dir: Path = DEFAULT_OUT,
) -> str:
    """
    Plot daily log count vs unique IP count for SSH/Apache/RDP across regions.
    Produces the equivalent of Paper Figures 2, 4, 5.
    """
    if not PLT_OK:
        print(f"[REGION] matplotlib unavailable — cannot plot {service}")
        return ""

    if traffic_data is None:
        traffic_data = _simulate_daily_traffic(service, n_days)

    start = datetime.datetime.strptime(start_date, "%Y-%m-%d")
    dates = [start + datetime.timedelta(days=i) for i in range(n_days)]

    fig, axes = plt.subplots(
        len(REGION_SHORT), 1,
        figsize=(12, 4 * len(REGION_SHORT)),
        sharex=True,
    )
    colors = {"logs": "#2196F3", "ips": "#F44336"}

    for ax, region in zip(axes, REGION_SHORT):
        d = traffic_data[region]
        ax2 = ax.twinx()
        ax.bar(dates, d["logs"], color=colors["logs"], alpha=0.6,
               label="Log count")
        ax2.plot(dates, d["ips"], color=colors["ips"], marker="o",
                 linewidth=1.5, markersize=4, label="Unique IPs")
        ax.set_ylabel("Log count", color=colors["logs"])
        ax2.set_ylabel("Unique IPs", color=colors["ips"])
        ax.set_title(f"{service} — {region}")
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%m/%d"))
        ax.xaxis.set_major_locator(mdates.DayLocator(interval=2))
        # Merge legends
        lines = (
            ax.get_legend_handles_labels()[0]
            + ax2.get_legend_handles_labels()[0]
        )
        labels = (
            ax.get_legend_handles_labels()[1]
            + ax2.get_legend_handles_labels()[1]
        )
        ax.legend(lines, labels, loc="upper right", fontsize=8)

    fig.suptitle(
        f"Daily Change of IPs / Log Count — {service} Service\n"
        f"(Replicates Paper Figures 2/4/5)",
        fontsize=11,
    )
    plt.tight_layout()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"region_traffic_{service.lower()}.png"
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"[REGION] Saved {out_path}")
    return str(out_path)


# ══════════════════════════════════════════════════════════════
#  4. HOURLY TEMPORAL ANALYSIS  (Paper Figure 3)
# ══════════════════════════════════════════════════════════════

def plot_hourly_temporal(
    service: str = "SSH",
    hourly_data: dict = None,
    out_dir: Path = DEFAULT_OUT,
) -> str:
    """
    Plot hourly attack distribution per region.
    Replicates Paper Figure 3 (Hourly Change in Connection Attempts).

    Paper observations encoded:
      WE  — morning dip, peak at ~23:00
      EA  — surge 11:00-15:00, peak at ~22:00
      EUS — consistent day, rise in late evening
    """
    if not PLT_OK:
        return ""

    if hourly_data is None:
        # Synthesise data matching paper patterns
        rng = random.Random(42)
        hourly_data = {}
        hour_weights = {
            "EA":  [0.6,0.5,0.5,0.4,0.4,0.5,0.7,0.8,0.9,1.0,1.1,1.3,
                    1.4,1.3,1.2,1.0,0.9,0.9,1.1,1.3,1.5,1.6,1.7,1.4],
            "WE":  [0.9,0.8,0.7,0.6,0.6,0.7,0.9,1.1,1.2,1.1,1.0,1.0,
                    0.9,0.9,0.9,0.9,0.9,0.9,1.0,1.1,1.3,1.5,1.6,1.4],
            "EUS": [0.8,0.7,0.7,0.7,0.7,0.7,0.8,0.9,1.0,1.0,1.0,1.0,
                    1.0,1.0,1.0,1.0,1.0,1.0,1.1,1.2,1.3,1.4,1.4,1.2],
        }
        for region in REGION_SHORT:
            base = 300
            w = hour_weights[region]
            hourly_data[region] = [
                int(base * w[h] * rng.uniform(0.85, 1.15))
                for h in range(24)
            ]

    hours = list(range(24))
    fig, ax = plt.subplots(figsize=(12, 5))
    line_styles = ["-o", "--s", "-.^"]
    for region, ls in zip(REGION_SHORT, line_styles):
        ax.plot(hours, hourly_data[region], ls, linewidth=2,
                markersize=5, label=region)
    ax.set_xlabel("Hour of Day (UTC)")
    ax.set_ylabel("Connection Attempts")
    ax.set_xticks(hours)
    ax.set_xticklabels([f"{h:02d}:00" for h in hours], rotation=45, fontsize=7)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    ax.set_title(
        f"Hourly Attack Distribution — {service} Service\n"
        "(Replicates Paper Figure 3)"
    )
    plt.tight_layout()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"region_hourly_{service.lower()}.png"
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"[REGION] Saved {out_path}")
    return str(out_path)


# ══════════════════════════════════════════════════════════════
#  LOG PARSERS
# ══════════════════════════════════════════════════════════════

def parse_cowrie_log(cowrie_json: str) -> tuple:
    """Return (accounts, passwords, events) from a cowrie.json file."""
    accounts  = []
    passwords = []
    events    = []
    if not os.path.exists(cowrie_json):
        return accounts, passwords, events
    with open(cowrie_json) as f:
        for line in f:
            try:
                e = json.loads(line)
                events.append(e)
                if e.get("eventid") in (
                    "cowrie.login.failed", "cowrie.login.success"
                ):
                    accounts.append(e.get("username", ""))
                    passwords.append(e.get("password", ""))
            except Exception:
                pass
    return accounts, passwords, events


def parse_honeypot_log(hpot_json: str) -> dict:
    """Parse multi_service_honeypot.py log → {service: [events]}."""
    service_logs: dict = defaultdict(list)
    if not os.path.exists(hpot_json):
        return service_logs
    with open(hpot_json) as f:
        for line in f:
            try:
                ev = json.loads(line)
                service_logs[ev.get("service", "UNKNOWN")].append(ev)
            except Exception:
                pass
    return dict(service_logs)


# ══════════════════════════════════════════════════════════════
#  SIMULATE SYNTHETIC DATA
# ══════════════════════════════════════════════════════════════

def generate_synthetic_data(n_events: int = 5000) -> tuple:
    """
    Generate synthetic accounts/passwords and service events for demo runs.
    Embeds the credential distributions observed in the paper.
    """
    rng    = random.Random(2024)
    COMMON_ACCTS = [
        "root", "admin", "ubuntu", "test", "345gs5662d34",
        "3245gs5662d34", "user", "pi", "support", "guest",
    ]
    COMMON_PASSES = [
        "123456", "123", "password", "345gs5662d34", "3245gs5662d34",
        "admin123", "root", "toor", "1234567", "12345678",
    ]
    LAB_IPS = [f"192.168.100.{i}" for i in range(11, 30)]
    INTERNET_IPS = [
        "1.2.3.4", "5.34.180.1", "185.220.100.5", "52.90.1.1",
        "68.42.10.5", "95.42.10.5", "3.0.0.1", "40.0.0.1",
    ]
    all_ips = LAB_IPS + INTERNET_IPS

    accounts  = []
    passwords = []
    svc_logs: dict = defaultdict(list)
    SERVICES  = ["SSH", "FTP", "HTTP", "SMTP", "LDAP", "RDP"]

    for _ in range(n_events):
        ip  = rng.choice(all_ips)
        acc = rng.choice(COMMON_ACCTS) if rng.random() < 0.7 else f"user{rng.randint(100,999)}"
        pwd = rng.choice(COMMON_PASSES) if rng.random() < 0.65 else rng.choice(list(ROCKYOU_SAMPLE))
        svc = rng.choice(SERVICES)
        accounts.append(acc)
        passwords.append(pwd)
        svc_logs[svc].append({"remote_ip": ip, "service": svc,
                               "data": f"{acc}:{pwd}"})

    return accounts, passwords, dict(svc_logs)


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Multi-Region Honeypot Analyser — AUA CS 232/337"
    )
    parser.add_argument("--cowrie",   help="Path to cowrie.json log")
    parser.add_argument("--honeypot", help="Path to multi_service_honeypot JSON log")
    parser.add_argument("--simulate", action="store_true",
                        help="Generate synthetic data for demo")
    parser.add_argument("--all",      action="store_true",
                        help="Run all analyses and save all graphs")
    parser.add_argument("--out",      default="./graphs",
                        help="Output directory for PNG graphs")
    args = parser.parse_args()
    out_dir = Path(args.out)

    accounts  = []
    passwords = []
    svc_logs: dict = {}

    if args.cowrie:
        accounts, passwords, _ = parse_cowrie_log(args.cowrie)
        print(f"[REGION] Loaded {len(accounts)} credential pairs from {args.cowrie}")
    if args.honeypot:
        svc_logs = parse_honeypot_log(args.honeypot)
        print(f"[REGION] Loaded services: {list(svc_logs.keys())}")
    if args.simulate or (not accounts and not svc_logs):
        print("[REGION] Generating synthetic demo data …")
        accounts, passwords, svc_logs = generate_synthetic_data()

    if not accounts and not svc_logs:
        print("[REGION] No data. Use --cowrie, --honeypot, or --simulate.")
        sys.exit(1)

    # ── 1. Wordlist proportion matching ───────────────────────
    wordlist_proportion_match(accounts, passwords)

    # ── 2. Country attribution tables ─────────────────────────
    if svc_logs:
        country_attribution_table(svc_logs)

    # ── 3. Per-service daily traffic graphs ───────────────────
    if args.all or PLT_OK:
        for svc in ["SSH", "HTTP", "RDP", "FTP", "SMTP", "LDAP"]:
            plot_daily_traffic(svc, out_dir=out_dir)
        plot_hourly_temporal("SSH", out_dir=out_dir)
        print(f"\n[REGION] All graphs saved to {out_dir}/")


if __name__ == "__main__":
    main()
