"""
====================================================
 Angelware — Domain Whitelist + Detection Scorer
 Ported/adapted from: C2Detective (martinkubecka)
====================================================

Two lightweight but important missing pieces:

1. Domain Whitelist
   ─────────────────
   C2Detective has config/domain_whitelist.txt + tldextract-based
   matching so that known-legitimate domains (cloudflare.net,
   microsoft.com) are excluded from all DNS-based detections.

   Angelware's Engine 3 had no whitelist mechanism.

   DomainWhitelist — load from file, match with tldextract, expose
   a simple is_whitelisted(domain) API for use across all detectors.

2. Aggregate Detection Scorer
   ───────────────────────────
   C2Detective counts how many detection checks fired out of the total
   possible and produces a colour-coded verdict:
     - Green:  nothing detected
     - Yellow: < 50% of indicators triggered
     - Red:    ≥ 50% of indicators triggered

   Angelware's IDS wrote per-engine HIGH/MED labels to a log file but
   produced no aggregate session-level score.

   DetectionScorer — register checks as they fire, compute the final
   score, produce a structured summary, and optionally colour-code for
   terminal output.

Usage:
    whitelist = DomainWhitelist("config/domain_whitelist.txt")
    if whitelist.is_whitelisted("cdn.cloudflare.net"):
        ...  # skip

    scorer = DetectionScorer(total_checks=11)
    scorer.record("Tor relay traffic",      fired=True,  severity="HIGH")
    scorer.record("DNS Tunneling",          fired=False, severity="HIGH")
    scorer.record("Crypto domains",         fired=True,  severity="MED")
    summary = scorer.summary()
    scorer.print_verdict()
"""

import os
import time
from typing import Dict, List, Optional, Set, Tuple

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

_HERE = os.path.dirname(os.path.realpath(__file__))

DEFAULT_WHITELIST_PATH = os.path.join(_HERE, "config", "domain_whitelist.txt")

# ANSI colours for terminal output
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_GREEN  = "\033[92m"
_RESET  = "\033[0m"


def _ts() -> str:
    return time.strftime("%H:%M:%S")


# ═══════════════════════════════════════════════════════════════════════════════
#  DOMAIN WHITELIST
# ═══════════════════════════════════════════════════════════════════════════════

class DomainWhitelist:
    """
    Load a domain whitelist from a plain-text file (one entry per line)
    and provide tldextract-based matching so that *.cloudflare.net
    and cloudflare.net both match against a 'cloudflare.net' entry.

    File format — one domain per line, blank lines and # comments ignored:
      cloudflare.net
      microsoft.com
      # add more entries here
    """

    def __init__(self, path: str = DEFAULT_WHITELIST_PATH):
        self.path    = path
        self._entries: Set[str] = set()
        self._domain_names: Set[str] = set()   # extracted domain-only parts
        self._load()

    # ------------------------------------------------------------------
    def _load(self):
        if not os.path.exists(self.path):
            print(f"[{_ts()}] [WARNING] Domain whitelist not found: {self.path}")
            return
        with open(self.path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    self._entries.add(line.lower())
                    # Pre-extract domain name for fast matching
                    if _HAS_TLDEXTRACT:
                        ex = tldextract.extract(line)
                        if ex.domain:
                            self._domain_names.add(ex.domain.lower())
                    else:
                        # Fallback: use second-to-last label
                        parts = line.split(".")
                        if len(parts) >= 2:
                            self._domain_names.add(parts[-2].lower())
        print(f"[{_ts()}] [INFO] Domain whitelist loaded — "
              f"{len(self._entries)} entries from {self.path}")

    # ------------------------------------------------------------------
    def is_whitelisted(self, domain: str) -> bool:
        """
        Returns True if `domain` or any parent of it matches a whitelist entry.
        Uses tldextract when available for robust eTLD+1 comparison.
        """
        domain = domain.lower().rstrip(".")
        if domain in self._entries:
            return True

        if _HAS_TLDEXTRACT:
            ex = tldextract.extract(domain)
            if ex.domain and ex.domain.lower() in self._domain_names:
                return True
        else:
            parts = domain.split(".")
            if len(parts) >= 2 and parts[-2] in self._domain_names:
                return True

        return False

    # ------------------------------------------------------------------
    def filter_domains(self, domains: List[str]) -> List[str]:
        """Return domains that are NOT on the whitelist."""
        return [d for d in domains if not self.is_whitelisted(d)]

    # ------------------------------------------------------------------
    def add(self, domain: str):
        """Add a domain at runtime (does NOT write back to the file)."""
        domain = domain.lower().strip()
        self._entries.add(domain)
        if _HAS_TLDEXTRACT:
            ex = tldextract.extract(domain)
            if ex.domain:
                self._domain_names.add(ex.domain.lower())

    # ------------------------------------------------------------------
    def save(self):
        """Write the current whitelist back to the file."""
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as fh:
            for entry in sorted(self._entries):
                fh.write(entry + "\n")
        print(f"[{_ts()}] [INFO] Whitelist saved — {len(self._entries)} entries")

    # ------------------------------------------------------------------
    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, domain: str) -> bool:
        return self.is_whitelisted(domain)


# ═══════════════════════════════════════════════════════════════════════════════
#  DETECTION SCORER
# ═══════════════════════════════════════════════════════════════════════════════

class DetectionScorer:
    """
    Aggregate scoring across all C2 detection checks.

    Mirrors C2Detective's indicator counting and verdict system.

    Usage:
        scorer = DetectionScorer(total_checks=11)
        scorer.record("Excessive beaconing frequency", fired=True,  severity="MED")
        scorer.record("Long connections",              fired=False, severity="MED")
        scorer.record("Tor relay traffic",             fired=True,  severity="HIGH")
        # …
        summary = scorer.summary()
        scorer.print_verdict()
    """

    # Standard C2Detective check set — extend as needed
    STANDARD_CHECKS = [
        "Excessive beaconing frequency",
        "Long TCP connections",
        "Unusual HTTP body size",
        "Malicious C2 TLS certificate values",
        "Malicious JA3 TLS fingerprints",
        "DGA domain names",
        "DNS Tunneling",
        "Tor relay traffic",
        "Tor exit node traffic",
        "Crypto/cryptojacking domains",
        # C2Hunter / C2 Threat Feed checks (each counts as one)
        "Confirmed C2 IP addresses (threat feed)",
        "Confirmed C2 domain names (threat feed)",
        "Confirmed C2 URLs (threat feed)",
        "Potential C2 IP addresses (threat feed)",
    ]

    def __init__(self, total_checks: Optional[int] = None):
        self.total_checks: int = total_checks or len(self.STANDARD_CHECKS)
        self._records: List[Dict] = []

    # ------------------------------------------------------------------
    def record(
        self,
        check_name: str,
        fired: bool,
        severity: str = "MED",
        detail: Optional[str] = None,
    ):
        """Register the result of one detection check."""
        self._records.append({
            "check":    check_name,
            "fired":    fired,
            "severity": severity.upper(),
            "detail":   detail or "",
        })

    # ------------------------------------------------------------------
    @property
    def fired_count(self) -> int:
        return sum(1 for r in self._records if r["fired"])

    @property
    def total_registered(self) -> int:
        return len(self._records)

    # ------------------------------------------------------------------
    def summary(self) -> Dict:
        fired     = self.fired_count
        total     = self.total_checks
        pct       = round(fired / total * 100, 1) if total else 0
        verdict   = "CLEAN"
        if fired > 0:
            verdict = "POTENTIAL C2" if fired < total / 2 else "LIKELY C2"

        return {
            "fired":           fired,
            "total_checks":    total,
            "score_pct":       pct,
            "verdict":         verdict,
            "checks":          self._records,
        }

    # ------------------------------------------------------------------
    def print_verdict(self, use_colour: bool = True):
        """Print a formatted verdict to stdout."""
        s     = self.summary()
        fired = s["fired"]
        total = s["total_checks"]

        if fired == 0:
            colour = _GREEN if use_colour else ""
        elif fired < total / 2:
            colour = _YELLOW if use_colour else ""
        else:
            colour = _RED if use_colour else ""
        reset = _RESET if use_colour else ""

        bar = "─" * 60
        print(f"\n{bar}")
        print(f"[{_ts()}] [VERDICT] {colour}{s['verdict']}{reset}  "
              f"[{fired}/{total} indicators triggered]")
        print(bar)

        for r in self._records:
            icon  = "✓" if r["fired"] else "·"
            sev   = f"[{r['severity']}]" if r["fired"] else "     "
            clr   = (colour if r["fired"] else "") if use_colour else ""
            print(f"  {clr}{icon} {sev:8} {r['check']}{reset}"
                  + (f"  — {r['detail']}" if r["detail"] else ""))

        print(bar + "\n")

    # ------------------------------------------------------------------
    def to_dict(self) -> Dict:
        """Serialise for inclusion in JSON output or HTML report."""
        return self.summary()


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI for whitelist management
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        prog="detection_scorer",
        description="Domain whitelist management — Angelware add-on"
    )
    ap.add_argument("--list-whitelist",  action="store_true")
    ap.add_argument("--add-whitelist",   metavar="DOMAIN")
    ap.add_argument("--check-domain",    metavar="DOMAIN")
    ap.add_argument("--whitelist",       default=DEFAULT_WHITELIST_PATH)
    ap.add_argument("--demo-score",      action="store_true",
                    help="Run a demo scoring session")
    args = ap.parse_args()

    wl = DomainWhitelist(args.whitelist)

    if args.list_whitelist:
        for d in sorted(wl._entries):
            print(f"  {d}")

    if args.add_whitelist:
        wl.add(args.add_whitelist)
        wl.save()

    if args.check_domain:
        result = wl.is_whitelisted(args.check_domain)
        print(f"  {args.check_domain}  →  {'WHITELISTED' if result else 'not whitelisted'}")

    if args.demo_score:
        scorer = DetectionScorer(total_checks=11)
        scorer.record("Excessive beaconing frequency", True,  "MED",  "3 connections > 10% threshold")
        scorer.record("Long TCP connections",          False, "MED")
        scorer.record("Unusual HTTP body size",        False, "MED")
        scorer.record("Malicious C2 TLS cert values",  True,  "HIGH", "Cobalt Strike serialNumber match")
        scorer.record("Malicious JA3 fingerprints",    True,  "HIGH", "2 matches")
        scorer.record("DGA domain names",              False, "HIGH")
        scorer.record("DNS Tunneling",                 True,  "HIGH", "evil.com — 12 unique long subdomains")
        scorer.record("Tor relay traffic",             False, "MED")
        scorer.record("Tor exit node traffic",         False, "MED")
        scorer.record("Crypto/cryptojacking domains",  False, "MED")
        scorer.record("C2 threat feed matches",        True,  "HIGH", "185.220.101.50 in Feodo Tracker")
        scorer.print_verdict()
