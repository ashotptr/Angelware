"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Breach Dump Generator
 Environment: ISOLATED VM LAB ONLY
====================================================

Generates the required breach_dump.txt file that the following
modules depend on but which is intentionally NOT committed to
the repository (it's .gitignored):

  cred_stuffing.py       --creds-file breach_dump.txt
  breach_dump_enricher.py --input breach_dump.txt
  account_enum_sim.py    (reads BREACH_DUMP path)

The generated file uses the standard email:password format
used by Collection #1-style combo lists.

Design:
  - 250+ credential pairs (well above the --max 50 default)
  - Only 3 of them match the fake_portal.py USERS database
    (alice@example.com, bob@example.com, admin@example.com)
    so the hit rate is ~1.2% — realistic for credential stuffing
    and enough to trigger Engine 2, Engine 5 unknowns spike, etc.
  - Password patterns mirror real breach characteristics:
    simple words, word+year, company variants, common bases
  - Email domains: mix of corporate and consumer to allow
    domain-concentration clustering to detect them
  - Some sequential usernames (user001, user002…) to trigger
    Engine 10 sequential pattern detection

Usage:
  python3 breach_dump_generator.py            # writes ./breach_dump.txt
  python3 breach_dump_generator.py --out /tmp/breach_dump.txt
  python3 breach_dump_generator.py --count 500
  python3 breach_dump_generator.py --check     # verify counts / patterns
====================================================
"""

import argparse
import os
import random
import string
from datetime import datetime
from typing import List, Tuple


# ── Known-good credentials (must match fake_portal.py USERS) ──
VALID_CREDS = [
    ("alice@example.com",  "correct_password_1"),
    ("bob@example.com",    "correct_password_2"),
    ("admin@example.com",  "securePass123!"),
]

# ── Common password patterns (realistic breach characteristics)
# Mirrors what breach_dump_enricher.py expects for reuse scoring.
COMMON_WORDS = [
    "password", "letmein", "sunshine", "monkey", "dragon",
    "football", "baseball", "shadow", "master", "welcome",
    "login", "admin", "root", "qwerty", "abc123",
    "iloveyou", "michael", "princess", "superman", "batman",
]

YEAR_SUFFIXES = ["2019", "2020", "2021", "2022", "2023", "2024", "25", "1"]
NUMBER_SUFFIXES = ["1", "12", "123", "1234", "!", "!1", "@123"]

FIRST_NAMES = [
    "john", "jane", "mike", "sarah", "david", "emily", "chris",
    "laura", "ryan", "anna", "james", "lisa", "mark", "karen",
    "steve", "helen", "paul", "mary", "kevin", "linda",
    "thomas", "barbara", "charles", "jessica", "daniel",
]

LAST_NAMES = [
    "smith", "jones", "brown", "taylor", "wilson", "davis",
    "miller", "moore", "anderson", "jackson", "white", "harris",
    "martin", "garcia", "thompson", "robinson", "clark", "lewis",
    "lee", "walker",
]

# Email domain pools — mix triggers domain-clustering detections
CORPORATE_DOMAINS = [
    "corporate.com", "techcorp.io", "bigfirm.net", "enterprise.org",
    "globalcorp.com", "solutions.biz", "systems.com", "infotech.net",
]
CONSUMER_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "protonmail.com", "aol.com", "live.com",
]
# Single-domain concentration for clustering trigger
SINGLE_DOMAIN = "corporate.com"


def _random_password() -> str:
    """Generate a realistic breach-style password."""
    choice = random.randint(0, 5)
    if choice == 0:
        return random.choice(COMMON_WORDS)
    elif choice == 1:
        return random.choice(COMMON_WORDS) + random.choice(YEAR_SUFFIXES)
    elif choice == 2:
        return random.choice(FIRST_NAMES).capitalize() + random.choice(YEAR_SUFFIXES)
    elif choice == 3:
        name = random.choice(FIRST_NAMES)
        return name + random.choice(NUMBER_SUFFIXES)
    elif choice == 4:
        # Word+Word pattern (linkedin-style "CompanyName2021")
        w1 = random.choice(COMMON_WORDS).capitalize()
        return w1 + random.choice(YEAR_SUFFIXES)
    else:
        # Short random string (stealer-log style)
        length = random.randint(6, 10)
        chars  = string.ascii_lowercase + string.digits
        return "".join(random.choices(chars, k=length))


def _gen_sequential_block(n: int = 40) -> List[Tuple[str, str]]:
    """
    Sequential usernames: user001@corporate.com … user040@corporate.com
    Triggers Engine 10 sequential username pattern detection.
    """
    entries = []
    base    = random.randint(100, 500)
    for i in range(n):
        email = f"user{base + i:03d}@{SINGLE_DOMAIN}"
        pwd   = _random_password()
        entries.append((email, pwd))
    return entries


def _gen_domain_concentration_block(n: int = 60) -> List[Tuple[str, str]]:
    """
    ~60 entries all from @corporate.com.
    When combined with gen_sequential_block they push domain
    concentration above the Engine 10 threshold (70%).
    """
    entries = []
    for _ in range(n):
        local = random.choice(FIRST_NAMES) + str(random.randint(1, 999))
        email = f"{local}@{SINGLE_DOMAIN}"
        pwd   = _random_password()
        entries.append((email, pwd))
    return entries


def _gen_organic_block(n: int = 120) -> List[Tuple[str, str]]:
    """
    Organic-looking entries across mixed domains.
    These mimic a realistic multi-source breach dump.
    """
    entries = []
    all_domains = CORPORATE_DOMAINS + CONSUMER_DOMAINS
    for _ in range(n):
        first  = random.choice(FIRST_NAMES)
        last   = random.choice(LAST_NAMES)
        sep    = random.choice([".", "_", ""])
        num    = str(random.randint(1, 9999)) if random.random() < 0.4 else ""
        local  = first + sep + last + num
        domain = random.choice(all_domains)
        email  = f"{local}@{domain}"
        pwd    = _random_password()
        entries.append((email, pwd))
    return entries


def generate_breach_dump(count: int = 250) -> List[Tuple[str, str]]:
    """
    Build the full breach dump with realistic structure.

    Structure:
      3   valid credentials (match fake_portal.py USERS)
      40  sequential usernames (triggers Engine 10)
      60  domain-concentrated entries (triggers Engine 10)
      147+ organic mixed entries (realistic noise)
    """
    entries: List[Tuple[str, str]] = []

    # Valid hits (sparse — realistic ~1.2% hit rate)
    entries.extend(VALID_CREDS)

    # Sequential block
    entries.extend(_gen_sequential_block(40))

    # Domain concentration block
    entries.extend(_gen_domain_concentration_block(60))

    # Organic remainder
    remainder = max(0, count - len(entries))
    entries.extend(_gen_organic_block(remainder))

    # Shuffle so valid creds aren't at predictable positions
    non_valid = entries[3:]
    random.shuffle(non_valid)
    entries = entries[:3] + non_valid

    # De-duplicate emails (keep first occurrence)
    seen  = set()
    dedup = []
    for email, pwd in entries:
        if email.lower() not in seen:
            seen.add(email.lower())
            dedup.append((email, pwd))

    return dedup


def write_breach_dump(path: str, count: int = 250) -> None:
    """Write the breach dump to path in email:password format."""
    entries = generate_breach_dump(count)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    with open(path, "w") as fh:
        for email, pwd in entries:
            fh.write(f"{email}:{pwd}\n")

    # Stats
    domain_counts: dict = {}
    for email, _ in entries:
        domain = email.split("@")[-1] if "@" in email else "unknown"
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
    top_domain = max(domain_counts, key=domain_counts.get)
    top_pct    = 100 * domain_counts[top_domain] / len(entries)

    valid_count = sum(
        1 for e, p in entries
        if any(e == v and p == q for v, q in VALID_CREDS)
    )

    print(f"[generator] Wrote {len(entries)} credentials → {path}")
    print(f"  Valid hits:        {valid_count} / {len(entries)} "
          f"({100*valid_count/len(entries):.1f}% — realistic stuffing hit rate)")
    print(f"  Top domain:        @{top_domain} "
          f"({domain_counts[top_domain]} = {top_pct:.0f}%)")
    print(f"  Total domains:     {len(domain_counts)}")
    print(f"\n  Teaching notes:")
    print(f"    Engine 10 domain concentration threshold: 70%")
    print(f"    Top domain at {top_pct:.0f}% → "
          f"{'TRIGGERS' if top_pct >= 70 else 'does not trigger'} Engine 10")
    print(f"\n  Next steps:")
    print(f"    python3 account_enum_sim.py      # pre-filter to confirmed accounts")
    print(f"    python3 breach_dump_enricher.py --input {path}")
    print(f"    python3 cred_stuffing.py --creds-file {path} --mode bot")


def verify_breach_dump(path: str) -> None:
    """Load and report statistics on an existing breach dump."""
    if not os.path.isfile(path):
        print(f"[verify] File not found: {path}")
        return

    entries = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if ":" in line:
                email, _, pwd = line.partition(":")
                entries.append((email.strip(), pwd.strip()))

    valid_pairs = {e: p for e, p in VALID_CREDS}
    hits = [(e, p) for e, p in entries if valid_pairs.get(e) == p]

    domain_counts: dict = {}
    for email, _ in entries:
        domain = email.split("@")[-1] if "@" in email else "unknown"
        domain_counts[domain] = domain_counts.get(domain, 0) + 1

    print(f"[verify] {path}")
    print(f"  Total entries: {len(entries)}")
    print(f"  Valid creds:   {len(hits)} ({', '.join(e for e, _ in hits)})")
    print(f"  Domains:       {len(domain_counts)}")
    top5 = sorted(domain_counts.items(), key=lambda x: -x[1])[:5]
    for domain, count in top5:
        pct = 100 * count / len(entries)
        print(f"    @{domain:<30s} {count:4d} ({pct:.0f}%)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Breach Dump Generator — AUA Botnet Research Lab"
    )
    parser.add_argument("--out",   default="breach_dump.txt",
                        help="Output file path (default: ./breach_dump.txt)")
    parser.add_argument("--count", type=int, default=250,
                        help="Total credential pairs to generate (default: 250)")
    parser.add_argument("--check", action="store_true",
                        help="Verify an existing breach_dump.txt instead of generating")
    parser.add_argument("--seed",  type=int, default=None,
                        help="Random seed for reproducible output")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if args.check:
        verify_breach_dump(args.out)
    else:
        write_breach_dump(args.out, args.count)
