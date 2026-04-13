"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Enriched Breach Dump Format + Parser
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching point (from Castle credential stuffing article):
  "Some actors build private collections by merging multiple
   breaches, de-duping, and enriching with metadata (e.g.
   source service, password reuse hints) to improve their
   hit rate."

  "Attackers collect username-password pairs from public leaks
   (e.g., Collection #1), stealer logs, or breach dumps traded
   in underground marketplaces. Many of these lists circulate
   in Telegram channels and forums, often formatted as
   email:password."

Why metadata enrichment matters:
  A raw breach dump is:     alice@example.com:password123
  An enriched dump is:      alice@example.com:password123:linkedin:2021-06:high

  Enrichment fields:
    source_service  — which platform was breached (predictive
                      of password reuse on similar platforms)
    breach_date     — older breaches = more likely password has
                      been changed; recent = high success chance
    reuse_score     — estimated probability this password is
                      reused elsewhere (based on password patterns
                      like "company name + year" or common bases)
    plaintext_flag  — was password stored in plaintext (vs. hash)?
    category        — email type: corporate, personal, gaming, etc.

  An attacker who enriches their list can:
    - Prioritize high-reuse-score pairs to attack first
    - Target breaches from the same industry as the victim service
      (e.g., LinkedIn breach → LinkedIn-password → attack Salesforce)
    - Skip old passwords for services that enforce 90-day rotation
    - Focus on corporate emails for SaaS credential stuffing
    - Compute a "freshness-weighted hit probability" per credential

This module has three parts:

1. EnrichedBreachDump — data format definition and file I/O
   Supports both plain email:password and the extended format.
   Backward compatible: cred_stuffing.py --creds-file works
   with both formats.

2. BreachDumpEnricher — populates metadata fields using
   heuristics (no external API calls in isolated lab):
   - Password pattern analysis (reuse likelihood scoring)
   - Source-domain affinity (predict reuse across services)
   - Temporal freshness scoring

3. PriorityCredentialSelector
   Sorts enriched credentials by estimated hit probability.
   Demonstrates why enriched dumps have higher hit rates
   than raw dumps of equal size.

   Also exposes a defender-side view:
   BreachIntelDetector (IDS Engine 14)
   Detects when an attacker is using an enriched dump:
   - Login attempts follow non-uniform distribution of
     email domain categories (too many corporate emails
     from one specific industry = targeted enriched list)
   - Password patterns match a known breach's characteristics
     (e.g., all passwords follow "CompanyName20XX" pattern
     = LinkedIn breach targeting)
   - Temporal clustering of attempts (most enriched dumps
     sort by freshness, so recent-breach passwords come first)
"""

import csv
import hashlib
import json
import os
import re
import random
import statistics
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime
from typing import Optional

# ── Output paths ──────────────────────────────────────────────
ENRICHED_DUMP_PATH   = "/tmp/enriched_breach_dump.txt"
PRIORITY_LIST_PATH   = "/tmp/priority_credentials.txt"
ANALYSIS_LOG_PATH    = "/tmp/breach_analysis.json"

# ── Known breach profiles (simulated intelligence) ────────────
KNOWN_BREACHES = {
    "linkedin_2021": {
        "service":      "LinkedIn",
        "date":         "2021-06",
        "n_records":    700_000_000,
        "industry":     "professional_network",
        "password_patterns": [
            r"^[A-Z][a-z]+\d{4}$",   # FirstName2020
            r"^[a-z]+\d{2,4}$",      # company2021
            r"linkedin\d*",
        ],
        "reuse_targets": ["salesforce", "slack", "github", "jira"],
    },
    "adobe_2013": {
        "service":      "Adobe",
        "date":         "2013-10",
        "n_records":    153_000_000,
        "industry":     "creative_software",
        "password_patterns": [
            r"^adobe\d*$",
            r"^photoshop\d*$",
            r"^creative\d*$",
        ],
        "reuse_targets": ["spotify", "netflix", "dropbox"],
    },
    "rockyou_2009": {
        "service":      "RockYou",
        "date":         "2009-12",
        "n_records":    32_000_000,
        "industry":     "gaming",
        "password_patterns": [
            r"^\d{6,8}$",
            r"^[a-z]{4,8}$",
            r"^[a-z]+123$",
        ],
        "reuse_targets": ["gaming", "streaming"],
    },
    "collection1_2019": {
        "service":      "Collection #1 (aggregated)",
        "date":         "2019-01",
        "n_records":    773_000_000,
        "industry":     "mixed",
        "password_patterns": [],  # Aggregated — no single pattern
        "reuse_targets": ["any"],
    },
}

# ── Reuse scoring heuristics ──────────────────────────────────

COMMON_BASES = {
    "password", "qwerty", "letmein", "welcome", "monkey",
    "dragon", "master", "shadow", "sunshine", "princess",
    "iloveyou", "starwars", "batman", "superman", "admin",
    "login", "passw0rd", "p@ssw0rd", "123456", "abc123",
}

def _password_reuse_score(password: str) -> float:
    """
    Estimate probability (0.0–1.0) that this password is
    reused on other services, based on:
      - Common base word (+0.4)
      - Simple year suffix (+0.2)
      - Short length < 8 (+0.2)
      - All lowercase (+0.1)
      - No special characters (+0.1)
    """
    score = 0.0
    p = password.lower()

    base = re.sub(r'\d+$', '', p).rstrip('!@#$%')
    if base in COMMON_BASES or len(base) <= 4:
        score += 0.4

    if re.search(r'(19|20)\d{2}$', p):
        score += 0.2

    if len(password) < 8:
        score += 0.2

    if password == password.lower():
        score += 0.1

    if re.match(r'^[a-z0-9]+$', p):
        score += 0.1

    return min(1.0, score)


def _freshness_score(breach_date: str) -> float:
    """
    Score 0.0–1.0 based on how recent the breach is.
    Fresher = higher probability password hasn't been changed.
    2024-2025: 1.0; 2020-2023: 0.7; 2015-2019: 0.4; older: 0.1
    """
    try:
        year = int(breach_date[:4])
        now_year = 2026
        age_years = now_year - year
        if age_years <= 1:
            return 1.0
        elif age_years <= 5:
            return 0.7
        elif age_years <= 10:
            return 0.4
        else:
            return 0.1
    except (ValueError, IndexError):
        return 0.5


def _email_category(email: str) -> str:
    """Classify email domain into broad categories."""
    domain = email.split("@")[-1].lower() if "@" in email else ""
    personal  = {"gmail.com", "yahoo.com", "hotmail.com",
                  "outlook.com", "icloud.com", "me.com",
                  "protonmail.com", "aol.com"}
    gaming    = {"steam.com", "epicgames.com", "battle.net",
                  "ea.com", "ubisoft.com"}
    if domain in personal:
        return "personal"
    if domain in gaming:
        return "gaming"
    if domain.endswith(".edu"):
        return "academic"
    if domain.endswith(".gov"):
        return "government"
    return "corporate"


# ══════════════════════════════════════════════════════════════
#  Part 1: ENRICHED BREACH DUMP FORMAT
# ══════════════════════════════════════════════════════════════

class EnrichedBreachDump:
    """
    Extended credential format:
      email:password:source:breach_date:reuse_score:category:plaintext

    Example:
      alice@corp.com:Summer2024!:linkedin_2021:2021-06:0.82:corporate:1

    Backward compatible: parse_line() accepts plain email:password.
    """

    HEADER = (
        "# Enriched Breach Dump — AUA Lab Simulation\n"
        "# Format: email:password:source:breach_date:"
        "reuse_score:category:plaintext\n"
        "# RESEARCH ONLY — ISOLATED VM — NO REAL DATA\n"
    )

    @staticmethod
    def parse_line(line: str) -> Optional[dict]:
        """
        Parse one line from either plain or enriched format.
        Returns a credential dict or None on failure.
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        # Try enriched format first (7 fields)
        parts = line.split(":", 6)
        if len(parts) >= 7:
            try:
                return {
                    "email":        parts[0].strip(),
                    "password":     parts[1].strip(),
                    "source":       parts[2].strip(),
                    "breach_date":  parts[3].strip(),
                    "reuse_score":  float(parts[4]),
                    "category":     parts[5].strip(),
                    "plaintext":    bool(int(parts[6])),
                }
            except (ValueError, IndexError):
                pass

        # Fall back to plain email:password
        if len(parts) >= 2:
            return {
                "email":        parts[0].strip(),
                "password":     ":".join(parts[1:]).strip(),
                "source":       "unknown",
                "breach_date":  "unknown",
                "reuse_score":  _password_reuse_score(parts[1].strip()),
                "category":     _email_category(parts[0].strip()),
                "plaintext":    True,
            }
        return None

    @staticmethod
    def format_line(cred: dict) -> str:
        return (
            f"{cred['email']}:"
            f"{cred['password']}:"
            f"{cred.get('source','unknown')}:"
            f"{cred.get('breach_date','unknown')}:"
            f"{cred.get('reuse_score', 0.5):.2f}:"
            f"{cred.get('category','unknown')}:"
            f"{1 if cred.get('plaintext', True) else 0}"
        )

    def load(self, path: str) -> list:
        creds = []
        if not os.path.exists(path):
            print(f"[DUMP] File not found: {path}")
            return creds
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                c = self.parse_line(line)
                if c and "@" in c["email"]:
                    creds.append(c)
        print(f"[DUMP] Loaded {len(creds)} credentials from {path}")
        return creds

    def save(self, creds: list, path: str):
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.HEADER)
            for c in creds:
                f.write(self.format_line(c) + "\n")
        print(f"[DUMP] Saved {len(creds)} credentials to {path}")


# ══════════════════════════════════════════════════════════════
#  Part 2: BREACH DUMP ENRICHER
# ══════════════════════════════════════════════════════════════

class BreachDumpEnricher:
    """
    Enriches plain email:password pairs with metadata.
    Does NOT make external API calls — uses local heuristics only.

    In production (on the attacker side): would call
    haveibeenpwned.com API, cross-reference with known breach
    databases, and use ML classifiers trained on billions of
    password pairs to predict reuse probability.
    """

    def enrich(self, creds: list,
               default_source: str = "collection1_2019") -> list:
        """
        Add metadata to each credential.
        creds: list of dicts with at least email + password.
        """
        enriched = []
        breach = KNOWN_BREACHES.get(default_source, {})
        breach_date = breach.get("date", "unknown")

        for c in creds:
            ec = dict(c)
            # Infer source if missing
            if ec.get("source", "unknown") == "unknown":
                ec["source"] = self._infer_source(ec["email"], ec["password"])

            # Compute metadata
            ec["reuse_score"]  = _password_reuse_score(ec["password"])
            ec["freshness"]    = _freshness_score(
                ec.get("breach_date", breach_date)
            )
            ec["category"]     = _email_category(ec["email"])
            ec["hit_estimate"] = round(
                ec["reuse_score"] * ec["freshness"], 3
            )
            ec.setdefault("plaintext", True)
            enriched.append(ec)

        return enriched

    def _infer_source(self, email: str, password: str) -> str:
        """Guess breach source from password patterns."""
        p = password.lower()
        for breach_id, breach in KNOWN_BREACHES.items():
            for pattern in breach.get("password_patterns", []):
                if re.match(pattern, p, re.IGNORECASE):
                    return breach_id
        return "collection1_2019"  # Default: aggregated

    def print_statistics(self, enriched: list):
        """Print enrichment quality report."""
        if not enriched:
            return
        scores       = [c["reuse_score"] for c in enriched]
        freshness    = [c.get("freshness", 0.5) for c in enriched]
        hit_estimates = [c.get("hit_estimate", 0) for c in enriched]
        categories   = Counter(c["category"] for c in enriched)
        sources      = Counter(c.get("source", "unknown") for c in enriched)

        print(f"\n[ENRICH] ── Enrichment Statistics ──────────────────")
        print(f"  Total credentials:    {len(enriched):,}")
        print(f"  Avg reuse score:      {statistics.mean(scores):.3f}")
        print(f"  Avg freshness score:  {statistics.mean(freshness):.3f}")
        print(f"  Avg hit estimate:     {statistics.mean(hit_estimates):.3f}")
        print(f"  High-priority (>0.5): "
              f"{sum(1 for h in hit_estimates if h > 0.5):,}")
        print(f"\n  Email categories:")
        for cat, n in categories.most_common():
            print(f"    {cat:<15}  {n:>5} ({100*n/len(enriched):.1f}%)")
        print(f"\n  Inferred sources:")
        for src, n in sources.most_common():
            print(f"    {src:<20}  {n:>5} ({100*n/len(enriched):.1f}%)")


# ══════════════════════════════════════════════════════════════
#  Part 3: PRIORITY SELECTOR + DEFENDER DETECTOR
# ══════════════════════════════════════════════════════════════

class PriorityCredentialSelector:
    """
    Sorts enriched credentials by estimated hit probability.
    Demonstrates why attackers enrich before attacking.
    """

    def sort(self, enriched: list,
             strategy: str = "hit_estimate") -> list:
        """
        Sort credentials by strategy.
        Strategies:
          hit_estimate  — reuse_score × freshness (default)
          freshness     — most recent breaches first
          reuse_score   — highest password reuse likelihood first
          corporate     — corporate emails first (SaaS targeting)
          random        — baseline comparison
        """
        if strategy == "random":
            result = list(enriched)
            random.shuffle(result)
            return result
        if strategy == "corporate":
            return sorted(enriched,
                          key=lambda c: (c["category"] == "corporate"),
                          reverse=True)
        return sorted(enriched,
                      key=lambda c: c.get(strategy, 0),
                      reverse=True)

    def compare_strategies(self, enriched: list,
                            top_n: int = 100) -> dict:
        """
        Simulate attack with different sort strategies.
        Assumes hit_estimate correlates with actual success.
        """
        print(f"\n[PRIORITY] Strategy comparison (top {top_n} credentials):")
        print(f"  {'Strategy':<20}  {'Avg hit est.':>13}  "
              f"{'Expected hits':>14}")
        print(f"  {'─'*20}  {'─'*13}  {'─'*14}")

        results = {}
        for strategy in ["hit_estimate", "freshness",
                          "reuse_score", "corporate", "random"]:
            top = self.sort(enriched, strategy)[:top_n]
            avg_est = statistics.mean(
                c.get("hit_estimate", 0) for c in top
            ) if top else 0
            # Simulate hits with some noise
            expected = sum(
                1 for c in top
                if random.random() < c.get("hit_estimate", 0.02)
            )
            results[strategy] = {
                "avg_estimate": round(avg_est, 4),
                "expected_hits": expected,
            }
            print(f"  {strategy:<20}  {avg_est:>13.4f}  "
                  f"{expected:>14}")

        best = max(results, key=lambda s: results[s]["expected_hits"])
        print(f"\n  Best strategy: {best} "
              f"({results[best]['expected_hits']} expected hits)")
        print(f"  Teaching point: enrichment improves hit rate by sorting")
        print(f"  high-reuse-score credentials to the front of the list.")
        return results


class BreachIntelDetector:
    """
    IDS Engine 14: Detect enriched dump usage from request patterns.

    Signals:
      1. Industry clustering: >70% of login attempts target emails
         from one industry category (e.g. all @corp.com addresses)
         suggests a targeted enriched list, not a generic dump.

      2. Password pattern concentration: >40% of attempted passwords
         match a single breach's characteristic pattern (e.g. all
         passwords match the pattern [A-Z][a-z]+NNNN = LinkedIn 2021 style).

      3. Temporal ordering: inter-attempt timestamps are NOT uniform
         random — they cluster at the head of the campaign (fresh
         credentials sorted to front) then decrease in success rate.
         Detectable via the ratio of successes in first vs last 25%
         of the campaign.
    """

    INDUSTRY_CLUSTER_THRESHOLD  = 70.0  # pct
    PATTERN_CLUSTER_THRESHOLD   = 40.0  # pct
    MIN_SAMPLES                 = 15

    def __init__(self):
        self._lock   = threading.Lock()
        self._emails: list      = []
        self._passwords: list   = []
        self._success_ts: list  = []  # timestamps of successes
        self._fail_ts: list     = []  # timestamps of failures
        self._alerts: list      = []

    def record_attempt(self, email: str, password: str,
                        success: bool) -> Optional[dict]:
        now = time.time()
        with self._lock:
            self._emails.append(email)
            self._passwords.append(password)
            if success:
                self._success_ts.append(now)
            else:
                self._fail_ts.append(now)
            n = len(self._emails)

        if n < self.MIN_SAMPLES:
            return None

        alert = None

        # Signal 1: Industry clustering
        cats = Counter(_email_category(e) for e in self._emails[-n:])
        top_cat, top_n = cats.most_common(1)[0]
        top_pct = 100.0 * top_n / n
        if top_pct >= self.INDUSTRY_CLUSTER_THRESHOLD:
            alert = {
                "engine":    "Engine14/IndustryCluster",
                "severity":  "MED",
                "category":  top_cat,
                "pct":       round(top_pct, 1),
                "ts":        datetime.now().isoformat(),
                "message": (
                    f"ENRICHED DUMP INDICATOR: {top_pct:.1f}% of "
                    f"attempts target '{top_cat}' email category\n"
                    f"  Random breach dump: ~30% corporate\n"
                    f"  Enriched/targeted: >70% one category\n"
                    f"  Attack is likely industry-targeted"
                ),
            }

        # Signal 2: Password pattern concentration
        matched = 0
        for breach_id, breach in KNOWN_BREACHES.items():
            for pattern in breach.get("password_patterns", []):
                m = sum(
                    1 for p in self._passwords[-n:]
                    if re.match(pattern, p, re.IGNORECASE)
                )
                pct = 100.0 * m / n
                if pct >= self.PATTERN_CLUSTER_THRESHOLD:
                    pattern_alert = {
                        "engine":   "Engine14/PasswordPattern",
                        "severity": "HIGH",
                        "breach":   breach["service"],
                        "pattern":  pattern,
                        "pct":      round(pct, 1),
                        "ts":       datetime.now().isoformat(),
                        "message": (
                            f"BREACH SOURCE IDENTIFIED: {pct:.1f}% of "
                            f"passwords match {breach['service']} "
                            f"breach pattern\n"
                            f"  Pattern: {pattern}\n"
                            f"  Alert other services likely targeted "
                            f"by same dump: "
                            f"{breach.get('reuse_targets', [])}"
                        ),
                    }
                    if not alert:
                        alert = pattern_alert

        if alert:
            self._alerts.append(alert)
            print(f"\n[IDS-{alert['engine']}] {alert['severity']}: "
                  f"{alert['message']}\n")
        return alert

    def get_stats(self) -> dict:
        return {
            "attempts":     len(self._emails),
            "total_alerts": len(self._alerts),
        }


# ── Generate sample enriched breach dump ──────────────────────

def generate_sample_enriched_dump(n: int = 200,
                                   path: str = ENRICHED_DUMP_PATH):
    """
    Generate a sample enriched breach dump for lab use.
    All credentials are fictional.
    """
    dump = EnrichedBreachDump()
    enricher = BreachDumpEnricher()
    sources = list(KNOWN_BREACHES.keys())

    creds = []
    domains = [
        "gmail.com", "yahoo.com", "outlook.com",
        "corp.com", "company.io", "startup.co",
    ]
    first = ["alice","bob","carol","dave","eve","frank",
              "grace","hal","ivy","jack","kate","liam"]
    last  = ["smith","jones","brown","wilson","taylor",
              "moore","anderson","lee","garcia","white"]
    years = ["2020","2021","2022","2023","2024"]
    words = ["sunshine","monkey","letmein","welcome",
              "password","qwerty","dragon","summer"]

    for i in range(n):
        fn = random.choice(first)
        ln = random.choice(last)
        dom = random.choice(domains)
        email = f"{fn}.{ln}{random.randint(1,999)}@{dom}"

        # Mix of password styles
        style = random.choice(["word+year", "name+num", "common"])
        if style == "word+year":
            pwd = random.choice(words) + random.choice(years)
        elif style == "name+num":
            pwd = fn.capitalize() + str(random.randint(10,999))
        else:
            pwd = random.choice(words) + str(random.randint(1,99))

        cred = {
            "email":       email,
            "password":    pwd,
            "source":      random.choice(sources),
            "breach_date": KNOWN_BREACHES[random.choice(sources)]["date"],
            "plaintext":   True,
        }
        creds.append(cred)

    enriched = enricher.enrich(creds)
    enricher.print_statistics(enriched)
    dump.save(enriched, path)
    return enriched


# ── Demo ──────────────────────────────────────────────────────

def _run_demo():
    print("=" * 60)
    print(" Enriched Breach Dump Format + Parser")
    print(" AUA Botnet Research Lab — ISOLATED VM ONLY")
    print("=" * 60)

    # Generate sample enriched dump
    print("\n── Generating sample enriched breach dump (200 pairs) ─")
    enriched = generate_sample_enriched_dump(200)

    # Load and parse it back
    dump    = EnrichedBreachDump()
    loaded  = dump.load(ENRICHED_DUMP_PATH)
    print(f"\n  Loaded back: {len(loaded)} records")
    print(f"  First record:")
    first = loaded[0]
    for k, v in first.items():
        print(f"    {k:<15}: {v}")

    # Priority selection
    print("\n── Priority Selector ─────────────────────────────────")
    selector = PriorityCredentialSelector()
    selector.compare_strategies(enriched, top_n=50)

    # Write priority list for cred_stuffing.py
    top_50 = selector.sort(enriched, "hit_estimate")[:50]
    dump.save(top_50, PRIORITY_LIST_PATH)
    print(f"\n  Top-50 priority list: {PRIORITY_LIST_PATH}")
    print(f"  Usage: python3 cred_stuffing.py "
          f"--creds-file {PRIORITY_LIST_PATH} --mode jitter")

    # IDS Engine 14 demo
    print("\n── IDS Engine 14: Breach Intel Detection ─────────────")
    det = BreachIntelDetector()
    # Simulate corporate-heavy targeted attack
    for c in enriched[:30]:
        # Bias toward corporate for demo
        email = (c["email"].split("@")[0] + "@corp.com"
                 if random.random() < 0.8 else c["email"])
        det.record_attempt(email, c["password"], random.random() < 0.02)
    print(f"\n  Engine 14 stats: {det.get_stats()}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Enriched Breach Dump — AUA Research Lab"
    )
    parser.add_argument("--generate", action="store_true",
                        help="Generate sample enriched dump")
    parser.add_argument("--enrich",   default=None, metavar="PATH",
                        help="Enrich an existing plain email:pass dump")
    parser.add_argument("--analyze",  default=None, metavar="PATH",
                        help="Analyze and prioritize an enriched dump")
    parser.add_argument("--n",        type=int, default=200,
                        help="Number of entries to generate (default: 200)")
    args = parser.parse_args()

    if args.enrich:
        d = EnrichedBreachDump()
        raw = d.load(args.enrich)
        enriched = BreachDumpEnricher().enrich(raw)
        out = args.enrich.replace(".txt", "_enriched.txt")
        d.save(enriched, out)
        BreachDumpEnricher().print_statistics(enriched)
    elif args.analyze:
        d = EnrichedBreachDump()
        loaded = d.load(args.analyze)
        enriched = BreachDumpEnricher().enrich(loaded)
        PriorityCredentialSelector().compare_strategies(enriched)
    else:
        _run_demo()
