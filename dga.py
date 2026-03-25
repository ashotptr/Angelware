"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Domain Generation Algorithm (DGA)
 Environment: ISOLATED VM LAB ONLY
====================================================

DGA generates pseudo-random domain names from a
time-based seed. The bot iterates through these
domains trying to resolve one until it finds the
C2 rendezvous point registered by the botmaster.

This creates a "moving target" — blocking one domain
is futile because the list rotates daily.

Key teaching point: IDS detects DGA via:
  1) Burst of NXDOMAIN responses
  2) High Shannon entropy in domain names
"""

import hashlib
import time
import math
import socket
from datetime import datetime


def generate_daily_domains(date_seed: str = None, count: int = 50,
                            tlds: list = None) -> list[str]:
    """
    Generate `count` pseudo-random domain names for a given date.
    Both bot and botmaster use the same seed, so their lists stay in sync.

    Args:
        date_seed: YYYY-MM-DD string (defaults to today)
        count:     number of domains to generate
        tlds:      TLD rotation list

    Returns:
        List of domain names
    """
    if date_seed is None:
        date_seed = datetime.now().strftime("%Y-%m-%d")

    if tlds is None:
        tlds = [".com", ".net", ".org", ".xyz", ".info"]

    domains = []
    for i in range(count):
        # Seed = date + iteration index
        seed_str = f"{date_seed}-{i}"
        h = hashlib.sha256(seed_str.encode()).hexdigest()
        # Take first 12 chars of hex hash, convert to alpha-only domain name
        raw = h[:16]
        domain_body = ''.join(chr(ord('a') + (int(c, 16) % 26)) for c in raw[:10])
        tld = tlds[i % len(tlds)]
        domains.append(domain_body + tld)

    return domains


def shannon_entropy(domain: str) -> float:
    """
    Compute Shannon entropy H(X) = -sum P(x_i) * log2(P(x_i))
    for the character distribution of a domain name.

    DGA domains typically score > 4.0 bits/char.
    Natural language domains typically score < 3.5 bits/char.
    """
    name = domain.split(".")[0]  # strip TLD for analysis
    if not name:
        return 0.0
    freq = {}
    for c in name:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(name)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def bot_c2_search(domains: list[str], known_c2_ip: str = "192.168.100.10") -> str | None:
    """
    Simulate the bot iterating through DGA domains trying to
    resolve one. In the real botnet, the botmaster registers one
    of these domains. In the lab, we detect the resolution *attempt*.

    Returns the first successfully resolved domain (or None).
    """
    print(f"[DGA] Searching {len(domains)} domains for C2 rendezvous...")
    for domain in domains:
        try:
            # In lab: these will all fail (NXDOMAIN) — that burst IS the detection signal
            ip = socket.gethostbyname(domain)
            print(f"[DGA] FOUND C2 at {domain} -> {ip}")
            return domain
        except socket.gaierror:
            # NXDOMAIN — expected for all non-registered domains
            print(f"[DGA] NXDOMAIN: {domain}  entropy={shannon_entropy(domain):.2f}")
            time.sleep(0.2)  # small delay between queries
    return None


def analyze_domains(domains: list[str]):
    """Show entropy analysis for a batch of generated domains."""
    print(f"\n{'Domain':<25} {'Entropy (bits/char)':>20} {'Classification':>20}")
    print("-" * 68)
    for d in domains:
        e = shannon_entropy(d)
        cls = "LIKELY DGA" if e > 3.8 else "natural"
        print(f"{d:<25} {e:>20.4f} {cls:>20}")


if __name__ == "__main__":
    print("=" * 60)
    print(" DGA Module - AUA Botnet Research Lab")
    print("=" * 60)

    today = datetime.now().strftime("%Y-%m-%d")
    print(f"\nGenerating domains for seed: {today}\n")
    domains = generate_daily_domains(date_seed=today, count=20)
    analyze_domains(domains)

    print(f"\n\nLaunching C2 search simulation (expect NXDOMAIN burst)...")
    print("(This is exactly what the IDS detector watches for)\n")
    bot_c2_search(domains[:10])
