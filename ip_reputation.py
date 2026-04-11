"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: IP Reputation & Proxy Detection Module
 Environment: ISOLATED VM LAB ONLY
====================================================

Scores inbound IP addresses and request headers for
indicators of proxy/VPN use, distributed attack
infrastructure, and bot-like header patterns.

Used by:
  fake_portal.py  — scores each /login request
  ids_detector.py — Engine 6 fingerprint correlation

Article mapping (Castle credential stuffing blog):
  "Proxy and VPN usage: high usage of known proxy networks"
  "Unfamiliar geographies"
  "Fingerprint reuse: same browser characteristics appearing
   across many sessions, suggesting automation or anti-detect
   tools."
  "Uniform TLS or header signatures"
  "Session linking: by linking sessions over time using TLS
   fingerprints and device traits, you can detect distributed
   attacks that wouldn't trigger individual alerts."

In production this module would call an external IP-reputation
API (e.g. IPQualityScore, ipinfo.io, MaxMind GeoIP/ASN).
Here we implement the same logic on in-lab traffic using
proxy-indicator heuristics and header fingerprinting.
"""

import hashlib
import ipaddress
import re
import time
import threading
from collections import defaultdict
from typing import Optional

# ── Known proxy / datacenter subnet ranges (simulated) ───────
# In production: replace with MaxMind ASN database or
# ipinfo.io /ranges endpoint.
# In lab: bot VMs are in 192.168.100.11-12; we treat the bot
# subnet as "datacenter" for demonstration purposes.
DATACENTER_SUBNETS = [
    "192.168.100.10/31",   # C2 + bot1 (lab: datacenter-like)
    "192.168.100.12/32",   # bot2 explicit
    "10.0.0.0/8",          # RFC1918 generic (spoofed X-Forwarded-For)
    "172.16.0.0/12",       # RFC1918 (spoofed)
]

# IPs whose X-Forwarded-For has cycled through this many /24 subnets
# within PROXY_POOL_WINDOW_SEC are flagged as using a proxy pool.
PROXY_POOL_SUBNET_THRESHOLD = 3
PROXY_POOL_WINDOW_SEC       = 120   # seconds

# ── Suspicious User-Agent substrings ─────────────────────────
# Real bots often expose toolchain strings in their UA.
SUSPICIOUS_UA_PATTERNS = [
    r"python[-/]",
    r"curl/",
    r"wget/",
    r"go-http-client",
    r"java/",
    r"libwww",
    r"jakarta",
    r"httpie",
    r"scrapy",
    r"mechanize",
    r"aiohttp",
    r"requests/",
    r"okhttp",
    r"openbullet",
    r"silverbullet",
    r"research/",              # cred_stuffing.py default UA
]
_SUSPICIOUS_UA_RE = re.compile(
    "|".join(SUSPICIOUS_UA_PATTERNS), re.IGNORECASE
)


# ── Browser fingerprint helpers ───────────────────────────────

def fingerprint_headers(headers: dict) -> str:
    """
    Derive a lightweight browser fingerprint from HTTP headers.

    Combines: User-Agent + Accept + Accept-Language + Accept-Encoding
    into a SHA-256 hash (first 12 hex chars used as fingerprint ID).

    Real anti-bot systems use TLS JA3 + canvas/WebGL fingerprints.
    At the HTTP layer this is the best proxy available without TLS
    interception.

    Key property: a bot config that doesn't rotate headers will
    produce the same fingerprint even when rotating proxy IPs —
    exactly what Engine 6 exploits to link distributed requests.
    """
    ua   = headers.get("User-Agent",       "")
    acc  = headers.get("Accept",           "")
    lang = headers.get("Accept-Language",  "")
    enc  = headers.get("Accept-Encoding",  "")
    raw  = f"{ua}|{acc}|{lang}|{enc}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def is_suspicious_ua(ua: str) -> bool:
    """Return True if User-Agent matches a known bot/tool pattern."""
    if not ua:
        return True   # missing UA is itself suspicious
    return bool(_SUSPICIOUS_UA_RE.search(ua))


def _in_datacenter(ip: str) -> bool:
    """True if the IP falls within a known datacenter/hosting subnet."""
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in DATACENTER_SUBNETS:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


# ── IP scoring ────────────────────────────────────────────────

class IPReputationScorer:
    """
    Per-session IP reputation tracker.

    Score bands:
       0–24   CLEAN      — normal residential traffic
      25–49   SUSPECT    — some bot indicators present
      50–74   LIKELY_BOT — strong indicators; consider CAPTCHA
      75–100  BOT        — block or tarpit immediately

    Scoring components (additive):
      +15  datacenter / known hosting subnet
      +20  suspicious User-Agent string (tool fingerprint)
      +15  missing Accept-Language header (common in scripts)
      +10  Chrome UA without Sec-Ch-Ua header (impersonation)
      +25  same fingerprint seen from ≥3 IPs in 5 minutes
      +20  X-Forwarded-For cycling through ≥3 /24 subnets
    """

    SCORE_DATACENTER    = 15
    SCORE_SUSPICIOUS_UA = 20
    SCORE_NO_LANG       = 15
    SCORE_UA_INCONSIST  = 10
    SCORE_FP_MULTIIP    = 25
    SCORE_XFWD_CYCLING  = 20

    BAND_CLEAN      = 25
    BAND_SUSPECT    = 50
    BAND_LIKELY_BOT = 75

    def __init__(self):
        self._lock = threading.Lock()

        # fingerprint → set of source IPs that used it
        self._fp_to_ips: dict = defaultdict(set)
        # fingerprint → first-seen timestamp
        self._fp_first_seen: dict = {}
        # source_ip → list of (timestamp, /24 subnet) from X-Fwd headers
        self._xfwd_subnets: dict = defaultdict(list)
        # source_ip → cumulative score (persists across requests)
        self._ip_scores: dict = defaultdict(int)

    # ── Public API ─────────────────────────────────────────────

    def score(self, src_ip: str, headers: dict) -> dict:
        """
        Score a single request.

        Returns:
          {
            "score":       int,       # 0–100
            "band":        str,       # CLEAN / SUSPECT / LIKELY_BOT / BOT
            "reasons":     list[str], # human-readable reasons
            "fingerprint": str,       # 12-char hex fingerprint ID
            "src_ip":      str,
          }
        """
        reasons = []
        delta   = 0
        fp      = fingerprint_headers(headers)
        now     = time.time()

        with self._lock:
            # 1. Datacenter IP check
            if _in_datacenter(src_ip):
                delta += self.SCORE_DATACENTER
                reasons.append(f"datacenter subnet (+{self.SCORE_DATACENTER})")

            # 2. Suspicious UA
            ua = headers.get("User-Agent", "")
            if is_suspicious_ua(ua):
                delta += self.SCORE_SUSPICIOUS_UA
                reasons.append(
                    f"suspicious UA: '{ua[:60]}' (+{self.SCORE_SUSPICIOUS_UA})"
                )

            # 3. Missing Accept-Language
            if not headers.get("Accept-Language"):
                delta += self.SCORE_NO_LANG
                reasons.append(
                    f"no Accept-Language header (+{self.SCORE_NO_LANG})"
                )

            # 4. UA inconsistency: claims Chrome but no Sec-Ch-Ua
            if "Chrome" in ua and not headers.get("Sec-Ch-Ua"):
                delta += self.SCORE_UA_INCONSIST
                reasons.append(
                    f"Chrome UA without Sec-Ch-Ua (+{self.SCORE_UA_INCONSIST})"
                )

            # 5. Cross-IP fingerprint reuse
            self._fp_to_ips[fp].add(src_ip)
            if fp not in self._fp_first_seen:
                self._fp_first_seen[fp] = now
            age   = now - self._fp_first_seen[fp]
            n_ips = len(self._fp_to_ips[fp])
            if n_ips >= 3 and age <= 300:   # 5-minute window
                delta += self.SCORE_FP_MULTIIP
                reasons.append(
                    f"fingerprint {fp} seen from {n_ips} IPs "
                    f"in {age:.0f}s (+{self.SCORE_FP_MULTIIP})"
                )

            # 6. X-Forwarded-For subnet cycling (proxy pool indicator)
            xfwd = (headers.get("X-Forwarded-For")
                    or headers.get("X-Real-IP") or "")
            if xfwd:
                try:
                    xfwd_ip  = xfwd.split(",")[0].strip()
                    subnet24 = ".".join(xfwd_ip.split(".")[:3])
                    self._xfwd_subnets[src_ip].append((now, subnet24))
                    # Prune old entries
                    cutoff = now - PROXY_POOL_WINDOW_SEC
                    self._xfwd_subnets[src_ip] = [
                        (t, s) for t, s in self._xfwd_subnets[src_ip]
                        if t >= cutoff
                    ]
                    distinct = {s for _, s in self._xfwd_subnets[src_ip]}
                    if len(distinct) >= PROXY_POOL_SUBNET_THRESHOLD:
                        delta += self.SCORE_XFWD_CYCLING
                        reasons.append(
                            f"X-Forwarded-For cycling {len(distinct)} "
                            f"/24 subnets in {PROXY_POOL_WINDOW_SEC}s "
                            f"(+{self.SCORE_XFWD_CYCLING})"
                        )
                except Exception:
                    pass

            # Accumulate and clamp to 100
            self._ip_scores[src_ip] += delta
            score = min(100, self._ip_scores[src_ip])

        band = self._band(score)
        return {
            "score":       score,
            "band":        band,
            "reasons":     reasons,
            "fingerprint": fp,
            "src_ip":      src_ip,
        }

    def get_multiip_fingerprints(self, min_ips: int = 3,
                                  max_age_sec: float = 300) -> list:
        """
        Return all fingerprints seen from >= min_ips distinct IPs within
        the last max_age_sec seconds.  Consumed by IDS Engine 6.
        """
        now = time.time()
        results = []
        with self._lock:
            for fp, ips in self._fp_to_ips.items():
                age = now - self._fp_first_seen.get(fp, now)
                if len(ips) >= min_ips and age <= max_age_sec:
                    results.append({
                        "fingerprint": fp,
                        "ips":         list(ips),
                        "n_ips":       len(ips),
                        "age_sec":     round(age, 1),
                    })
        return results

    def reset(self):
        """Clear all state (call between measurement windows)."""
        with self._lock:
            self._fp_to_ips.clear()
            self._fp_first_seen.clear()
            self._xfwd_subnets.clear()
            self._ip_scores.clear()

    @staticmethod
    def _band(score: int) -> str:
        if score < IPReputationScorer.BAND_CLEAN:
            return "CLEAN"
        if score < IPReputationScorer.BAND_SUSPECT:
            return "SUSPECT"
        if score < IPReputationScorer.BAND_LIKELY_BOT:
            return "LIKELY_BOT"
        return "BOT"


# ── Module-level singleton (shared by portal + IDS) ──────────
_scorer = IPReputationScorer()

def score_request(src_ip: str, headers: dict) -> dict:
    """Convenience wrapper around the module-level scorer."""
    return _scorer.score(src_ip, headers)

def get_multiip_fingerprints(min_ips: int = 3) -> list:
    """Return fingerprints seen from >= min_ips IPs recently."""
    return _scorer.get_multiip_fingerprints(min_ips=min_ips)

def reset_scorer():
    """Reset all state (call between test runs)."""
    _scorer.reset()


# ── CLI ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print(" IP Reputation Scorer — AUA Botnet Research Lab")
    print(" ISOLATED ENVIRONMENT ONLY")
    print("=" * 60)

    bot_headers = {
        "User-Agent": "python-requests/2.31.0",
        "Accept":     "*/*",
        # No Accept-Language, no Accept-Encoding — typical urllib/requests
    }
    browser_headers = {
        "User-Agent":      ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0.0.0 Safari/537.36"),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Ch-Ua":       '"Not_A Brand";v="8", "Chromium";v="120"',
    }

    print("\n[DEMO] Scoring bot-like request from 192.168.100.11:")
    r1 = score_request("192.168.100.11", bot_headers)
    print(f"  Score: {r1['score']}  Band: {r1['band']}")
    for reason in r1["reasons"]:
        print(f"  • {reason}")
    print(f"  Fingerprint: {r1['fingerprint']}")

    print("\n[DEMO] Scoring browser-like request from 192.168.100.50:")
    r2 = score_request("192.168.100.50", browser_headers)
    print(f"  Score: {r2['score']}  Band: {r2['band']}")
    for reason in r2["reasons"]:
        print(f"  • {reason}")
    print(f"  Fingerprint: {r2['fingerprint']}")

    print("\n[DEMO] Simulating same fingerprint from 4 different IPs (proxy pool)...")
    for i, ip in enumerate(["10.0.0.1", "10.0.1.2", "10.0.2.3", "10.0.3.4"]):
        r = score_request(ip, bot_headers)
        print(f"  {ip}: score={r['score']} band={r['band']}")
    multi = get_multiip_fingerprints(min_ips=3)
    print(f"\n  Multi-IP fingerprints (≥3 IPs): {multi}")
    print("\n  → IDS Engine 6 would fire a DISTRIBUTED BOT FINGERPRINT alert.")
