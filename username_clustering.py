"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Username / Email Clustering Detector
 Environment: ISOLATED VM LAB ONLY
====================================================

Detects two credential stuffing signals the other engines miss:

  1. Domain concentration — a bulk breach dump for one service
     (e.g. LinkedIn) contains mostly @company-domain.com addresses.
     Legitimate logins come from diverse mail providers.
     Signal: >DOMAIN_CONC_THRESH% of attempts share one @domain.

  2. Sequential username patterns — some attackers brute-force with
     generated lists: user001, user002... or john1, john2...
     Signal: >SEQ_PATT_THRESH% of usernames match a numeric-suffix
     pattern with the same base string.

  3. Common prefix clustering — many usernames sharing the same
     short prefix (e.g. "test", "admin", "user") at rates far
     exceeding legitimate traffic.

Article mapping (Castle credential stuffing blog):
  "Clustering around similar usernames: high volumes of login
   attempts targeting similar email patterns (e.g. many @gmail.com
   addresses or usernames with incremental numbers) suggest
   automation using generic breach data or brute-force permutations."

Usage (standalone):
  from username_clustering import EmailClusteringTracker
  tracker = EmailClusteringTracker()
  tracker.add("user001@example.com")
  tracker.add("user002@example.com")
  result = tracker.analyze()
  if result["anomalous"]:
      print(result["alerts"])

Integration:
  fake_portal.py calls tracker.add(email) on every /login POST.
  ids_detector.py Engine 5 polls /stats/advanced which includes
  tracker.analyze() output under key "username_clustering".
"""

import re
import threading
import time
from collections import Counter, defaultdict
from typing import Optional

# ── Configuration ─────────────────────────────────────────────
DOMAIN_CONC_THRESH  = 60.0   # % — alert if one @domain > this share
SEQ_PATT_THRESH     = 20.0   # % — alert if sequential pattern > this share
PREFIX_CONC_THRESH  = 40.0   # % — alert if common short prefix > this share
MIN_SAMPLES         = 10     # minimum attempts before alerting
PREFIX_LEN          = 4      # length of username prefix to check
SEQ_MIN_GROUP       = 3      # minimum sequential runs to count as pattern

# Pattern: ends with 1–4 digits (user001, john5, test_12)
_NUMERIC_SUFFIX_RE  = re.compile(r'^(.+?)(\d{1,4})$')
# Common bot-generated username bases
_COMMON_BASES = {"user", "test", "admin", "guest", "info", "mail",
                 "support", "service", "contact", "no-reply", "noreply",
                 "postmaster", "webmaster", "root", "dev"}


def _parse_email(email: str):
    """Split email into (local_part, domain). Returns (None, None) on failure."""
    parts = email.lower().strip().split("@", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return None, None


def _numeric_base(local: str) -> Optional[str]:
    """
    If local matches a numeric-suffix pattern, return the base string.
    E.g. "user042" → "user", "john5" → "john".  Else None.
    """
    m = _NUMERIC_SUFFIX_RE.match(local)
    if m:
        return m.group(1)
    return None


def _detect_sequential_runs(nums_by_base: dict) -> dict:
    """
    For each base string, check if the numeric suffixes form a
    sequential run (e.g. 1,2,3,4 or 100,101,102).
    Returns {base: run_length} for bases with run ≥ SEQ_MIN_GROUP.
    """
    results = {}
    for base, nums in nums_by_base.items():
        sorted_nums = sorted(set(nums))
        if len(sorted_nums) < SEQ_MIN_GROUP:
            continue
        # Find longest consecutive run
        best_run = 1
        cur_run  = 1
        for i in range(1, len(sorted_nums)):
            if sorted_nums[i] - sorted_nums[i-1] == 1:
                cur_run += 1
                best_run = max(best_run, cur_run)
            else:
                cur_run = 1
        if best_run >= SEQ_MIN_GROUP:
            results[base] = best_run
    return results


class EmailClusteringTracker:
    """
    Rolling window tracker for email clustering signals.

    Thread-safe.  Call add(email) on each login attempt.
    Call analyze() to get current clustering statistics and alerts.
    """

    def __init__(self, window_sec: float = 300.0):
        self.window_sec = window_sec
        self._lock = threading.Lock()
        # (timestamp, email) entries in rolling window
        self._entries: list = []
        # Cumulative counters (never reset — for lifetime stats)
        self._total_seen = 0

    def add(self, email: str, ts: float = None):
        """Record one login attempt for this email."""
        if ts is None:
            ts = time.time()
        with self._lock:
            self._entries.append((ts, email.lower().strip()))
            self._total_seen += 1

    def _prune(self, now: float):
        """Remove entries outside the rolling window (must hold lock)."""
        cutoff = now - self.window_sec
        self._entries = [(ts, e) for ts, e in self._entries if ts > cutoff]

    def analyze(self) -> dict:
        """
        Analyze current window for clustering patterns.

        Returns:
          {
            n_samples       : int,
            anomalous       : bool,
            alerts          : list[str],
            domain_stats    : {domain: {count, pct}},
            top_domain      : str,
            top_domain_pct  : float,
            seq_patterns    : {base: run_length},
            prefix_stats    : {prefix: {count, pct}},
            common_bases    : {base: count},
          }
        """
        now = time.time()
        with self._lock:
            self._prune(now)
            entries = list(self._entries)

        n = len(entries)
        alerts = []

        if n < MIN_SAMPLES:
            return dict(n_samples=n, anomalous=False, alerts=[],
                        domain_stats={}, top_domain="", top_domain_pct=0.0,
                        seq_patterns={}, prefix_stats={}, common_bases={})

        # ── Parse all emails ─────────────────────────────────────────
        domains   = Counter()
        prefixes  = Counter()
        bases_num: dict = defaultdict(list)   # base → list of numeric suffixes
        common_base_hits = Counter()

        for _, email in entries:
            local, domain = _parse_email(email)
            if domain:
                domains[domain] += 1
            if local:
                # Short prefix
                prefixes[local[:PREFIX_LEN]] += 1
                # Numeric suffix base detection
                base = _numeric_base(local)
                if base:
                    try:
                        suffix = int(_NUMERIC_SUFFIX_RE.match(local).group(2))
                        bases_num[base].append(suffix)
                    except Exception:
                        pass
                # Common bot-generated base check
                clean_base = local.rstrip("0123456789").rstrip("_-.")
                if clean_base in _COMMON_BASES:
                    common_base_hits[clean_base] += 1

        # ── Domain concentration ──────────────────────────────────────
        domain_stats  = {}
        top_domain    = ""
        top_domain_pct = 0.0
        if domains:
            top_domain, top_count = domains.most_common(1)[0]
            top_domain_pct = 100.0 * top_count / n
            for d, c in domains.most_common(10):
                domain_stats[d] = {"count": c, "pct": round(100.0 * c / n, 1)}
            if top_domain_pct >= DOMAIN_CONC_THRESH:
                alerts.append(
                    f"DOMAIN CONCENTRATION: {top_domain_pct:.1f}% of attempts "
                    f"target @{top_domain} ({top_count}/{n}) — "
                    f"breach dump from one service (threshold: {DOMAIN_CONC_THRESH}%)"
                )

        # ── Sequential username patterns ──────────────────────────────
        seq_patterns = _detect_sequential_runs(bases_num)
        seq_count    = sum(seq_patterns.values())
        seq_pct      = 100.0 * seq_count / n if n else 0
        if seq_pct >= SEQ_PATT_THRESH:
            examples = [f"{b}N (run={r})" for b, r in
                        list(seq_patterns.items())[:3]]
            alerts.append(
                f"SEQUENTIAL USERNAME PATTERN: {seq_pct:.1f}% of usernames "
                f"follow incremental numbering — brute-force enumeration "
                f"({', '.join(examples)}) (threshold: {SEQ_PATT_THRESH}%)"
            )

        # ── Short prefix concentration ────────────────────────────────
        prefix_stats = {}
        if prefixes:
            top_prefix, top_p_count = prefixes.most_common(1)[0]
            top_prefix_pct = 100.0 * top_p_count / n
            for p, c in prefixes.most_common(8):
                prefix_stats[p] = {"count": c, "pct": round(100.0 * c / n, 1)}
            if top_prefix_pct >= PREFIX_CONC_THRESH:
                alerts.append(
                    f"PREFIX CONCENTRATION: {top_prefix_pct:.1f}% of usernames "
                    f"start with '{top_prefix}' — "
                    f"dictionary or permutation list (threshold: {PREFIX_CONC_THRESH}%)"
                )

        # ── Common bot base strings ───────────────────────────────────
        if common_base_hits:
            total_common = sum(common_base_hits.values())
            common_pct   = 100.0 * total_common / n
            if common_pct >= 20.0:
                top_common = common_base_hits.most_common(3)
                alerts.append(
                    f"COMMON-BASE USERNAMES: {common_pct:.1f}% use generic bases "
                    f"({', '.join(f'{b}({c})' for b,c in top_common)}) — "
                    f"automated list, not organic user base"
                )

        return dict(
            n_samples       = n,
            anomalous       = len(alerts) > 0,
            alerts          = alerts,
            domain_stats    = domain_stats,
            top_domain      = top_domain,
            top_domain_pct  = round(top_domain_pct, 1),
            seq_patterns    = seq_patterns,
            prefix_stats    = prefix_stats,
            common_bases    = dict(common_base_hits.most_common(10)),
        )

    def reset(self):
        """Clear all tracking state (call between test runs)."""
        with self._lock:
            self._entries.clear()
            self._total_seen = 0

    def stats_for_api(self) -> dict:
        """Compact dict for /stats/advanced endpoint."""
        r = self.analyze()
        return {
            "n_samples_in_window": r["n_samples"],
            "anomalous":           r["anomalous"],
            "alerts":              r["alerts"],
            "top_domain":          r["top_domain"],
            "top_domain_pct":      r["top_domain_pct"],
            "sequential_patterns": r["seq_patterns"],
        }


# ── Singleton for fake_portal.py ──────────────────────────────
_tracker = EmailClusteringTracker()


def get_tracker() -> EmailClusteringTracker:
    return _tracker


if __name__ == "__main__":
    print("Username Clustering Detector — self-test\n")
    t = EmailClusteringTracker()

    print("--- Test 1: domain concentration ---")
    for i in range(80):
        t.add(f"victim{i:03d}@corporate.com")
    for i in range(20):
        t.add(f"user{i}@gmail.com")
    r = t.analyze()
    print(f"  n={r['n_samples']}, anomalous={r['anomalous']}")
    for a in r["alerts"]:
        print(f"  ⚠  {a}")

    t.reset()
    print("\n--- Test 2: sequential pattern ---")
    for i in range(50):
        t.add(f"user{i:03d}@example.com")
    r = t.analyze()
    for a in r["alerts"]:
        print(f"  ⚠  {a}")

    t.reset()
    print("\n--- Test 3: legitimate traffic ---")
    import random, string
    first_names = ["alice","bob","carol","dave","eve","frank","grace","hal"]
    domains = ["gmail.com","yahoo.com","outlook.com","icloud.com","hotmail.com"]
    for _ in range(30):
        name   = random.choice(first_names) + str(random.randint(1, 9999))
        domain = random.choice(domains)
        t.add(f"{name}@{domain}")
    r = t.analyze()
    print(f"  n={r['n_samples']}, anomalous={r['anomalous']} (should be False)")
    print(f"  Top domain: {r['top_domain']} ({r['top_domain_pct']}%)")
