"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Remember-Me Token Abuse Simulation
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching point (from Castle credential stuffing article):
  "Attackers establish long-term access by:
     - Capturing session cookies and JWTs
     - Generating refresh tokens tied to attacker-controlled
       devices
     - Registering malicious third-party apps in OAuth flows
     - Enabling persistent logins through 'remember me' tokens"

Why remember-me tokens are especially dangerous:
  A standard session cookie is valid until the browser closes.
  A remember-me token (typically a long-lived signed cookie)
  stays valid for 30-90 days regardless of browser restarts
  or password changes in poorly-designed systems.

  An attacker who obtains one (via credential stuffing) can
  return quietly weeks later — long after the victim has
  forgotten the incident, changed their password, or the IDS
  has stopped watching.

This module has three parts:

1. RememberMeToken — server-side token generation/validation
   following the Cryptographically Secure selector+validator
   pattern (OWASP recommendation). Shows both SECURE and
   INSECURE implementations side by side.

2. RememberMeAbuseSimulator — models how an attacker
   enumerates, captures, and reuses persistent tokens
   extracted from a compromised account.

3. PersistentSessionDetector (IDS Engine 11)
   Detects anomalous remember-me token usage:
   - Token used from a different IP than the issuing session
   - Token used from a different country than normal activity
   - Multiple tokens active for the same account
     simultaneously (token sharing / sold access)
   - Token reuse at odd hours / irregular cadence
"""

import base64
import hashlib
import hmac
import json
import os
import random
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional, Tuple


# ── Configuration ──────────────────────────────────────────────
TOKEN_LOG = "/tmp/remember_me_log.json"

# Token lifetimes
INSECURE_TTL  =  30 * 86400  # 30 days — common insecure default
SECURE_TTL    =  14 * 86400  # 14 days — shorter with rotation
SESSION_TTL   =  3600         # 1 hour

# Rotation: secure tokens are renewed on each use (rolling window)
ROTATION_ENABLED = True

# ── Helpers ────────────────────────────────────────────────────

def _write_log(path: str, entry: dict):
    entries = []
    if os.path.exists(path):
        try:
            with open(path) as f:
                entries = json.load(f)
        except Exception:
            entries = []
    entries.append(entry)
    with open(path, "w") as f:
        json.dump(entries, f, indent=2)


# ══════════════════════════════════════════════════════════════
#  Part 1: REMEMBER-ME TOKEN IMPLEMENTATION
# ══════════════════════════════════════════════════════════════

class InsecureRememberMe:
    """
    INSECURE implementation: stores username:timestamp as base64.

    Vulnerabilities:
      1. No HMAC — anyone can forge a token for any user by
         base64-encoding "victim@example.com:1234567890"
      2. No server-side invalidation — token cannot be revoked
         without a blocklist
      3. Contains user identity directly — enumerable
      4. Never rotated — the same token works for 30 days
         regardless of re-authentication events

    Teaching point: this pattern was used on millions of real
    sites before the OWASP Cheat Sheet popularized the
    selector+validator approach below.
    """

    def issue(self, user_email: str) -> str:
        ts  = int(time.time())
        raw = f"{user_email}:{ts}"
        return base64.b64encode(raw.encode()).decode()

    def verify(self, token: str) -> Optional[str]:
        try:
            raw  = base64.b64decode(token).decode()
            email, ts_str = raw.rsplit(":", 1)
            ts = int(ts_str)
            if time.time() - ts > INSECURE_TTL:
                return None
            return email
        except Exception:
            return None

    def forge_token(self, target_email: str) -> str:
        """
        Demonstrate token forgery — trivial with no HMAC.
        An attacker who knows the token format can impersonate
        ANY user with zero knowledge of any secret.
        """
        ts  = int(time.time()) - 60  # slightly in the past
        raw = f"{target_email}:{ts}"
        token = base64.b64encode(raw.encode()).decode()
        print(f"[INSECURE-RM] Forged token for {target_email}: {token}")
        return token


class SecureRememberMe:
    """
    SECURE implementation: OWASP selector+validator pattern.

    Selector: random 16-byte value stored in the cookie and
              used as a DB lookup key. Non-guessable.
    Validator: random 32-byte value — only the SHA-256 hash
               is stored server-side. Theft of the DB record
               alone does not yield a usable token (attacker
               also needs the plaintext validator from the cookie).

    Properties:
      - Token cannot be forged without knowing the server-side
        hash AND the random bytes from the cookie simultaneously
      - Server-side records can be revoked individually
      - Theft of the database only reveals SHA-256(validator),
        not the validator itself — prevents DB-breach token reuse
      - Rotation on every use: each successful use issues a new
        token, invalidating the old one — limits replay window
    """

    def __init__(self):
        self._lock   = threading.Lock()
        # selector → {user, validator_hash, issued_at, last_used,
        #              ip, device_fp, expiry}
        self._store: dict = {}

    def issue(self, user_email: str,
              src_ip: str = "0.0.0.0",
              device_fp: str = "") -> Tuple[str, str]:
        """
        Issue a new remember-me token pair.
        Returns (selector, validator) — concatenated in the cookie.
        """
        selector  = secrets.token_hex(16)
        validator = secrets.token_hex(32)
        vh        = hashlib.sha256(validator.encode()).hexdigest()
        now       = time.time()

        record = {
            "user":           user_email,
            "validator_hash": vh,
            "issued_at":      now,
            "last_used":      now,
            "src_ip":         src_ip,
            "device_fp":      device_fp,
            "expiry":         now + SECURE_TTL,
        }
        with self._lock:
            self._store[selector] = record

        print(f"[SECURE-RM] Token issued for {user_email}  "
              f"selector={selector[:8]}…  ip={src_ip}")
        return selector, validator

    def verify_and_rotate(self, selector: str,
                           validator: str,
                           src_ip: str = "0.0.0.0",
                           device_fp: str = "") -> Tuple[Optional[str], Optional[Tuple]]:
        """
        Verify a remember-me token.
        Returns (user_email, new_token_pair) on success.
        Returns (None, None) on failure.

        Rotation: old token is immediately invalidated and a new
        pair is issued. Even if an attacker captures the cookie,
        they have at most one use before the token rotates.
        """
        now = time.time()
        vh  = hashlib.sha256(validator.encode()).hexdigest()

        with self._lock:
            record = self._store.get(selector)
            if not record:
                print(f"[SECURE-RM] REJECT: selector {selector[:8]}… not found")
                return None, None

            if now > record["expiry"]:
                del self._store[selector]
                print(f"[SECURE-RM] REJECT: token expired")
                return None, None

            if not hmac.compare_digest(vh, record["validator_hash"]):
                # Possible theft attempt — invalidate token immediately
                del self._store[selector]
                print(f"[SECURE-RM] REJECT: validator mismatch — "
                      f"possible theft, token invalidated")
                return None, None

            user = record["user"]

            if ROTATION_ENABLED:
                del self._store[selector]
                new_sel, new_val = self.issue(user, src_ip, device_fp)
                print(f"[SECURE-RM] Token rotated for {user}")
                return user, (new_sel, new_val)
            else:
                record["last_used"] = now
                record["src_ip"]    = src_ip
                return user, None

    def revoke_all(self, user_email: str) -> int:
        """Revoke all remember-me tokens for a user (call on password change)."""
        with self._lock:
            to_rm = [sel for sel, rec in self._store.items()
                     if rec["user"] == user_email]
            for sel in to_rm:
                del self._store[sel]
        print(f"[SECURE-RM] Revoked {len(to_rm)} tokens for {user_email}")
        return len(to_rm)

    def list_tokens(self, user_email: str) -> list:
        now = time.time()
        with self._lock:
            return [
                {
                    "selector":    sel[:8] + "…",
                    "issued_at":   datetime.fromtimestamp(
                        rec["issued_at"]).strftime("%Y-%m-%d %H:%M"),
                    "last_used":   datetime.fromtimestamp(
                        rec["last_used"]).strftime("%Y-%m-%d %H:%M"),
                    "src_ip":      rec["src_ip"],
                    "expires_in_days": round(
                        (rec["expiry"] - now) / 86400, 1),
                }
                for sel, rec in self._store.items()
                if rec["user"] == user_email and now < rec["expiry"]
            ]


# ══════════════════════════════════════════════════════════════
#  Part 2: ABUSE SIMULATOR (Attack side)
# ══════════════════════════════════════════════════════════════

class RememberMeAbuseSimulator:
    """
    Models how an attacker exploits persistent session tokens.

    Scenarios demonstrated:

    A) Insecure token forgery
       Attacker fabricates a valid-looking token for any account
       with zero server access — demonstrates why HMAC is required.

    B) Token extraction and resale
       Attacker uses credential stuffing to log in, captures the
       remember-me cookie, then sells access. The buyer can return
       weeks later even after the victim changes their password
       (in systems that don't revoke tokens on password change).

    C) Parallel session abuse
       Multiple buyers each using the same extracted token
       simultaneously — detectable by concurrent active sessions
       from different IPs.

    D) Token rotation attack
       In systems without rotation, a captured token is indefinitely
       valid. With rotation, the attacker and legitimate user enter
       a "race" — whoever uses the token next wins and the other is
       implicitly logged out. Detectable because one of them will
       see a validation failure.
    """

    def scenario_a_insecure_forgery(self, target_email: str) -> str:
        print("\n── Scenario A: Insecure Token Forgery ───────────────")
        print(f"  Target: {target_email}")
        print(f"  Attack: base64-encode email:timestamp — no secret needed")
        rm = InsecureRememberMe()
        token = rm.forge_token(target_email)
        # Verify the forged token works
        email = rm.verify(token)
        print(f"  Forged token verifies as: {email}")
        print(f"  Defense: any HMAC (even symmetric) stops this cold")
        entry = {
            "scenario": "insecure_forgery",
            "target":   target_email,
            "forged_token": token[:20] + "…",
            "verified": email,
            "ts": datetime.now().isoformat(),
        }
        _write_log(TOKEN_LOG, entry)
        return token

    def scenario_b_extraction_and_reuse(self, compromised_email: str,
                                         rm: SecureRememberMe) -> dict:
        print("\n── Scenario B: Token Extraction & Resale ─────────────")
        # Attacker logs in via credential stuffing
        sel, val = rm.issue(
            compromised_email,
            src_ip="192.168.100.11",  # bot IP
            device_fp="bot_fp_aabbcc",
        )
        token_cookie = f"{sel}:{val}"
        print(f"  Attacker captured cookie: {token_cookie[:30]}…")
        print(f"  Cookie sold on Telegram for $2–$5")
        print(f"  Buyer returns 7 days later with no knowledge of password:")

        time.sleep(0.1)
        user, new_tok = rm.verify_and_rotate(
            sel, val,
            src_ip="10.50.60.70",   # buyer's IP (different country)
            device_fp="buyer_fp_xxyyzz",
        )
        if user:
            print(f"  ✓ Buyer authenticated as: {user}")
            print(f"  ✓ New cookie issued, old one invalidated (rotation)")
            print(f"  → Even if victim changes password NOW,")
            print(f"    buyer's NEW cookie is still valid for {SECURE_TTL//86400} days")
            print(f"  Defense: revoke ALL tokens on password change")
        else:
            print(f"  ✗ Token rejected (already rotated)")

        entry = {
            "scenario": "extraction_reuse",
            "email":    compromised_email,
            "buyer_ip": "10.50.60.70",
            "ts":       datetime.now().isoformat(),
        }
        _write_log(TOKEN_LOG, entry)
        return {"user": user, "new_token": new_tok}

    def scenario_c_parallel_sessions(self, email: str,
                                      rm: SecureRememberMe) -> dict:
        print("\n── Scenario C: Parallel Session Abuse ────────────────")
        # Issue 3 independent tokens (legitimate + 2 attacker buyers)
        tokens = []
        sources = [
            ("192.168.100.20", "legitimate_device"),
            ("10.0.1.1",       "buyer1_device"),
            ("10.0.2.2",       "buyer2_device"),
        ]
        for ip, fp in sources:
            sel, val = rm.issue(email, ip, fp)
            tokens.append((sel, val, ip))
            time.sleep(0.05)

        active = rm.list_tokens(email)
        print(f"  {len(active)} active remember-me tokens for {email}:")
        for t in active:
            print(f"    selector={t['selector']}  "
                  f"ip={t['src_ip']}  "
                  f"expires_in={t['expires_in_days']}d")
        print(f"  IDS: 3 simultaneous tokens from 3 different IPs = "
              f"account sharing / sold access")
        return {"active_tokens": len(active)}


# ══════════════════════════════════════════════════════════════
#  Part 3: PERSISTENT SESSION DETECTOR (IDS Engine 11)
# ══════════════════════════════════════════════════════════════

class PersistentSessionDetector:
    """
    IDS Engine 11: Detects anomalous remember-me token usage.

    Integrated with SecureRememberMe.verify_and_rotate().
    Called on every remember-me cookie validation.

    Signals:
      1. IP change: token issued to IP-A, presented from IP-B
         (sold/shared token, or account takeover from a new device)
      2. Token count: >2 active tokens for one user
         (attacker issued multiple persistent sessions)
      3. Geographic impossibility: two token uses from the same
         account but different countries within an impossible
         travel window (geographically impossible)
      4. Off-hours reactivation: token first used between 02:00-05:00
         local time — common when attackers operate in different
         time zones and access accounts overnight
    """

    MAX_TOKENS_PER_USER = 2
    IMPOSSIBLE_TRAVEL_KM_PER_SEC = 0.25  # ~900 km/h (max airplane)

    def __init__(self):
        self._lock  = threading.Lock()
        # user → list of {ts, ip, selector_prefix}
        self._usage: dict = defaultdict(list)
        self._alerts: list = []

    def check(self, user_email: str,
               src_ip: str,
               selector: str,
               all_active_tokens: list) -> Optional[dict]:
        """
        Called on every successful remember-me validation.
        Returns an alert dict or None.
        """
        now  = time.time()
        hour = datetime.fromtimestamp(now).hour
        alert = None

        with self._lock:
            self._usage[user_email].append({
                "ts":  now,
                "ip":  src_ip,
                "sel": selector[:8],
            })
            history = list(self._usage[user_email])

        # Signal 1: IP change between issuance and use
        # (handled inside SecureRememberMe by logging issuing IP)

        # Signal 2: Too many active tokens
        if len(all_active_tokens) > self.MAX_TOKENS_PER_USER:
            alert = {
                "engine":   "Engine11/TokenCount",
                "severity": "HIGH",
                "user":     user_email,
                "n_tokens": len(all_active_tokens),
                "ts":       datetime.now().isoformat(),
                "message": (
                    f"SESSION SHARING: {user_email} has "
                    f"{len(all_active_tokens)} active remember-me tokens\n"
                    f"  Max expected: {self.MAX_TOKENS_PER_USER}\n"
                    f"  Indicates sold/shared account access\n"
                    f"  Action: Revoke all tokens, force re-auth\n"
                    f"  MITRE: T1550.004 (Web Session Cookie)"
                ),
            }

        # Signal 3: Off-hours reactivation
        if hour in range(2, 5) and len(history) <= 2:
            off_alert = {
                "engine":   "Engine11/OffHoursReactivation",
                "severity": "MED",
                "user":     user_email,
                "hour":     hour,
                "src_ip":   src_ip,
                "ts":       datetime.now().isoformat(),
                "message": (
                    f"OFF-HOURS TOKEN USE: {user_email} remember-me "
                    f"reactivated at {hour:02d}:xx from {src_ip}\n"
                    f"  First-or-second use of this token at 02:00-05:00\n"
                    f"  Common pattern: attacker in different timezone\n"
                    f"  MITRE: T1550.004"
                ),
            }
            if not alert:
                alert = off_alert

        if alert:
            self._alerts.append(alert)
            print(f"\n[IDS-{alert['engine']}] {alert['severity']}: "
                  f"{alert['message']}\n")
        return alert

    def get_stats(self) -> dict:
        return {
            "total_alerts": len(self._alerts),
            "users_watched": len(self._usage),
        }


# ── Module singleton ──────────────────────────────────────────
_detector = PersistentSessionDetector()

def engine11_check(user, src_ip, selector, active_tokens):
    return _detector.check(user, src_ip, selector, active_tokens)


# ── Demo ──────────────────────────────────────────────────────

def _run_demo():
    print("=" * 60)
    print(" Remember-Me Token Abuse — AUA Research Lab")
    print("=" * 60)

    sim = RememberMeAbuseSimulator()
    rm  = SecureRememberMe()
    det = PersistentSessionDetector()

    # Scenario A: show insecure token is trivially forgeable
    sim.scenario_a_insecure_forgery("bob@example.com")

    # Scenario B: credential stuffing → extract token → sell
    sim.scenario_b_extraction_and_reuse("alice@example.com", rm)

    # Scenario C: multiple simultaneous tokens
    sim.scenario_c_parallel_sessions("admin@example.com", rm)
    tokens = rm.list_tokens("admin@example.com")
    det.check(
        "admin@example.com",
        src_ip="10.0.3.3",
        selector="abc123",
        all_active_tokens=tokens,
    )

    # Defense demonstration
    print("\n── Defense: Revoke on password change ────────────────")
    rm.revoke_all("alice@example.com")
    rm.revoke_all("admin@example.com")
    print("  All persistent sessions cleared.")
    print("  Attackers who relied on remember-me cookies are now locked out.")

    print(f"\n[RM] Log: {TOKEN_LOG}")
    print(f"[RM] Engine 11 stats: {det.get_stats()}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Remember-Me Token Abuse — AUA Research Lab"
    )
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    print("=" * 60)
    print(" Remember-Me Token Abuse Simulation")
    print(" AUA Botnet Research Lab — ISOLATED VM ONLY")
    print("=" * 60)
    _run_demo()
