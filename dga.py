"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Domain Generation Algorithm (DGA)
 Environment: ISOLATED VM LAB ONLY
====================================================

Enhanced version of the original dga.py.
Now integrates the full research-resource feature set:

Original capabilities (preserved):
  • SHA-256 time-seeded daily domain generation
  • Shannon entropy analysis
  • NXDOMAIN burst simulation

New capabilities (from gap analysis):
  • 21 DGA algorithm types via dga_variants.py
  • Weekly seed mode (Mirai.Nomi style)
  • Hex-only domain body format [a-f0-9]{10}
  • Exotic TLD pool (DDNS, OpenNIC, ccTLDs)
  • PSL-aware entropy (full subdomain, not just first label)
  • Multi-mode DGA (DDNS subdomain + standard)
  • ML-based domain classification
  • YARA rule generation for generated domains
  • Per-type analysis output

Key teaching point: IDS detects DGA via:
  1) Burst of NXDOMAIN responses (≥10 in 30s → Engine 3 HIGH)
  2) High Shannon entropy in domain labels (H > 3.8 → Engine 3 MED)
  3) DNS TTL anomalies (very low TTL → Engine 3 advanced)
  4) ML feature vector classification (16 features)
  5) Family matching (Ranbyus/Necurs/Dyre signatures)
"""

import hashlib
import time
import math
import socket
from datetime import datetime
from typing import List, Optional

# ── TLD pools (gap items 31, 32, 58) ──────────────────────────
STANDARD_TLDS = [".com", ".net", ".org", ".xyz", ".info"]

EXOTIC_TLDS   = [".ga", ".im", ".sc", ".xxx", ".tw", ".pro",
                 ".mn", ".me", ".su", ".bit", ".pw", ".cc"]

DDNS_TLDS     = [".duckdns.org", ".chickenkiller.com", ".accesscam.org",
                 ".casacam.net", ".ddnsfree.com", ".mooo.com",
                 ".strangled.net", ".ignorelist.com", ".dontargetme.nl",
                 ".ddns.net", ".dyndns.org"]

OPENNIC_TLDS  = [".geek", ".oss", ".session.geek", ".session.oss"]

ALL_TLDS      = STANDARD_TLDS + EXOTIC_TLDS + DDNS_TLDS + OPENNIC_TLDS


# ── PSL-aware subdomain extractor (gap item 74, 84) ───────────
try:
    from publicsuffixlist import PublicSuffixList as _PSL
    _psl = _PSL()
    def _strip_psl(domain: str) -> str:
        vps = _psl.publicsuffix(domain)
        if vps and domain.endswith("." + vps):
            return domain[:-(len(vps) + 1)]
        return domain.split(".")[0]
except ImportError:
    def _strip_psl(domain: str) -> str:
        parts = domain.rstrip(".").split(".")
        return ".".join(parts[:-1]) if len(parts) > 1 else domain


# ═══════════════════════════════════════════════════════════════
#  DAILY / WEEKLY DOMAIN GENERATION  (original + enhanced)
# ═══════════════════════════════════════════════════════════════

def generate_daily_domains(date_seed: str = None,
                           count: int = 50,
                           tlds: list = None,
                           hex_mode: bool = False) -> List[str]:
    """
    Generate `count` pseudo-random domain names for a given date.
    Both bot and botmaster use the same seed, so their lists stay in sync.

    Args:
        date_seed : YYYY-MM-DD string (defaults to today)
        count     : number of domains to generate
        tlds      : TLD rotation list (defaults to STANDARD_TLDS)
        hex_mode  : if True, produce [a-f0-9]{10} body (Mirai.Nomi style, gap 27)

    Returns:
        List of domain names
    """
    if date_seed is None:
        date_seed = datetime.now().strftime("%Y-%m-%d")

    if tlds is None:
        tlds = STANDARD_TLDS

    domains = []
    for i in range(count):
        seed_str = f"{date_seed}-{i}"
        h        = hashlib.sha256(seed_str.encode()).hexdigest()
        raw      = h[:16]

        if hex_mode:
            # [a-f0-9]{10} — Mirai.Nomi format (gap item 27)
            domain_body = h[:10]
        else:
            # Alpha-only body (original format)
            domain_body = "".join(
                chr(ord("a") + (int(c, 16) % 26)) for c in raw[:10])

        tld = tlds[i % len(tlds)]
        domains.append(domain_body + tld)

    return domains


def generate_weekly_domains(week_offset: int = 0,
                            count: int = 50,
                            tlds: list = None,
                            hex_mode: bool = True) -> List[str]:
    """
    Generate domains using a weekly seed (gap item 25).
    Seed changes every 7 days (604800 seconds), not daily.
    Used by Mirai.Nomi via NTP timestamp.
    """
    ts   = int(time.time()) + week_offset * 604800
    seed = str(ts // 604800)
    tlds = tlds or (DDNS_TLDS + OPENNIC_TLDS + STANDARD_TLDS)
    return generate_daily_domains(date_seed=seed, count=count,
                                  tlds=tlds, hex_mode=hex_mode)


def generate_ddns_subdomain_domains(count: int = 20,
                                    provider: str = ".ddns.net") -> List[str]:
    """
    Symmi / Kraken pattern: random subdomains under a DDNS provider (gap 79).
    Zero registration cost; hard to sinkhole because the provider is legitimate.
    """
    import random, string
    rng = random.Random(int(time.time()) // 86400)
    return [
        "".join(rng.choice(string.ascii_lowercase + string.digits)
                for _ in range(rng.randint(8, 14))) + provider
        for _ in range(count)
    ]


# ═══════════════════════════════════════════════════════════════
#  ENTROPY  (gap item 84: PSL-aware full subdomain)
# ═══════════════════════════════════════════════════════════════

def shannon_entropy(domain: str, psl_aware: bool = True) -> float:
    """
    Compute Shannon entropy H(X) = -sum P(x_i) * log2 P(x_i)
    for the character distribution of a domain name.

    If psl_aware=True (default), strips the public suffix before
    computing entropy so multi-part TLDs (.co.uk, .github.io) do not
    dilute the analysis. This is gap item 84.

    DGA domains typically score > 3.8 bits/char.
    Natural language domains typically score < 3.5 bits/char.
    """
    import re
    if psl_aware:
        name = _strip_psl(domain.lower().rstrip("."))
    else:
        name = domain.split(".")[0]  # original naive approach

    clean = re.sub(r"\.", "", name)
    if not clean:
        return 0.0
    freq   = {}
    for c in clean:
        freq[c] = freq.get(c, 0) + 1
    length  = len(clean)
    entropy = 0.0
    for cnt in freq.values():
        p = cnt / length
        entropy -= p * math.log2(p)
    return entropy


# ═══════════════════════════════════════════════════════════════
#  BOT C2 SEARCH  (original, preserved)
# ═══════════════════════════════════════════════════════════════

def bot_c2_search(domains: List[str],
                  known_c2_ip: str = "192.168.100.10") -> Optional[str]:
    """
    Simulate the bot iterating through DGA domains trying to
    resolve one. In the real botnet, the botmaster registers one
    of these domains. In the lab, we detect the resolution *attempt*.

    Returns the first successfully resolved domain (or None).
    """
    print(f"[DGA] Searching {len(domains)} domains for C2 rendezvous...")
    for domain in domains:
        try:
            ip = socket.gethostbyname(domain)
            print(f"[DGA] FOUND C2 at {domain} -> {ip}")
            return domain
        except socket.gaierror:
            print(f"[DGA] NXDOMAIN: {domain}  entropy={shannon_entropy(domain):.2f}")
            time.sleep(0.2)
    return None


# ═══════════════════════════════════════════════════════════════
#  ANALYSIS  (original + extended with new features)
# ═══════════════════════════════════════════════════════════════

def analyze_domains(domains: List[str], show_ml: bool = False):
    """
    Show entropy analysis for a batch of generated domains.
    If show_ml=True, also shows ML classification (requires training).
    """
    print(f"\n{'Domain':<30} {'Entropy':>12} {'Classification':>18} {'Family':>15}")
    print("-" * 80)

    ml_det = None
    if show_ml:
        try:
            from dga_ml_detector import DGAMLDetector
            ml_det = DGAMLDetector(model="gbt")
            ml_det.load()
        except Exception:
            pass

    from ids_detector_dga_patch import DGAFamilyClassifier
    cls = DGAFamilyClassifier()

    for d in domains:
        e      = shannon_entropy(d)
        label  = "LIKELY DGA" if e > 3.8 else "natural"
        family = cls.classify(d)
        fam_s  = family["family"] if family else "—"

        ml_s   = ""
        if ml_det:
            try:
                r   = ml_det.predict(d)
                ml_s = f" [ML: {r['probability']:.2f}]"
            except Exception:
                pass

        print(f"{d:<30} {e:>12.4f} {label + ml_s:>18} {fam_s:>15}")


# ═══════════════════════════════════════════════════════════════
#  MULTI-TYPE DEMO  (all 21 DGA algorithms)
# ═══════════════════════════════════════════════════════════════

def demo_all_types(count_per_type: int = 3):
    """
    Generate sample domains from all 21 DGA types and display
    their entropy and family classification.
    """
    from dga_variants import ALL_DGA_TYPES

    print(f"\n{'='*80}")
    print(f" DGA Variants Demo — {len(ALL_DGA_TYPES)} algorithm types")
    print(f"{'='*80}")
    print(f"{'Type':<20} {'Sample Domain':<38} {'Entropy':>8}")
    print("-" * 70)
    for name, fn in ALL_DGA_TYPES.items():
        try:
            samples = fn(count=count_per_type)
            for s in samples[:1]:
                e = shannon_entropy(s)
                print(f"{name:<20} {s:<38} {e:>8.4f}")
        except Exception as e_:
            print(f"{name:<20} ERROR: {e_}")


# ═══════════════════════════════════════════════════════════════
#  YARA GENERATION  (gap item 51, 52)
# ═══════════════════════════════════════════════════════════════

def generate_yara_for_session(output_path: str = "/tmp/dga_rules.yar"):
    """Generate YARA rules for all DGA variants and save to file."""
    from dga_variants import generate_all_yara_rules
    return generate_all_yara_rules(output_path=output_path)


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    mode     = sys.argv[1] if len(sys.argv) > 1 else "demo"
    today    = datetime.now().strftime("%Y-%m-%d")

    if mode == "demo":
        print("=" * 60)
        print(" DGA Module — AUA Botnet Research Lab")
        print("=" * 60)
        print(f"\nGenerating domains (daily seed: {today})\n")

        # Standard alpha domains
        print("[Mode: alpha, standard TLDs]")
        domains = generate_daily_domains(date_seed=today, count=10)
        analyze_domains(domains)

        # Hex mode (Mirai.Nomi style, gap 27)
        print("\n[Mode: hex, DDNS+OpenNIC TLDs — Mirai.Nomi style]")
        hex_doms = generate_daily_domains(
            date_seed=today, count=10,
            tlds=DDNS_TLDS + OPENNIC_TLDS, hex_mode=True)
        analyze_domains(hex_doms)

        # Weekly seed
        print("\n[Mode: weekly seed, gap 25]")
        weekly = generate_weekly_domains(count=5)
        analyze_domains(weekly)

        # DDNS subdomains
        print("\n[Mode: DDNS subdomain (Symmi pattern), gap 79]")
        ddns = generate_ddns_subdomain_domains(5)
        analyze_domains(ddns)

        print("\nLaunching C2 search simulation (NXDOMAIN burst = IDS signal)...")
        bot_c2_search(domains[:5])

    elif mode == "all-types":
        demo_all_types()

    elif mode == "yara":
        path = sys.argv[2] if len(sys.argv) > 2 else "/tmp/dga_rules.yar"
        generate_yara_for_session(path)

    elif mode == "dataset":
        from dga_variants import generate_labeled_dataset
        rows = generate_labeled_dataset(100, "/tmp/dga_dataset.csv")
        print(f"Generated {len(rows)} labeled domains → /tmp/dga_dataset.csv")

    elif mode == "weekly":
        print("Weekly seed domains (Mirai.Nomi style):")
        domains = generate_weekly_domains(count=17)
        for d in domains:
            print(f"  {d}")

    else:
        print("Usage: python3 dga.py [demo|all-types|yara|dataset|weekly]")
