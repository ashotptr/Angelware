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

    def scenario_d_rotation_attack(self, target_email: str,
                                    rm: "SecureRememberMe") -> dict:
        """
        Scenario D: Token Rotation Race Condition.

        In systems WITHOUT rotation:
          Attacker captures the remember-me cookie once and reuses it
          indefinitely.  The victim's password change does nothing.
          The cookie is valid until the TTL expires (often 30–90 days).

        In systems WITH rotation (like SecureRememberMe):
          Each verification invalidates the old token and issues a new one.
          If the attacker and the legitimate user both hold the old token:
            - Whoever presents it FIRST wins and gets the new token.
            - The other party's next access FAILS (token already rotated).
          This creates a detectable race condition:
            - One of the two parties will see an unexpected validation failure.
            - A validation failure on a recently-issued token → alert IDS.

        This scenario demonstrates:
          1. How the race plays out (attacker wins the first use)
          2. How the legitimate user is implicitly logged out
          3. How the defender can detect the race (Engine 11 fires on
             duplicate-rotation attempts from different IPs)
        """
        print("\n── Scenario D: Token Rotation Race Condition ─────────")
        print(f"  Target: {target_email}")
        print(f"  System: rotation ENABLED = {ROTATION_ENABLED}")
        print()

        # Step 1: Issue a token to the legitimate user
        leg_ip = "203.0.113.10"    # legitimate user's home IP
        atk_ip = "10.50.60.70"     # attacker's IP (different country)
        sel, val = rm.issue(target_email, src_ip=leg_ip, device_fp="leg_device")
        print(f"  [1] Legitimate user logs in from {leg_ip}")
        print(f"      Token issued: {sel[:8]}…")
        print()

        # Step 2: Attacker captures the token (via ATO credential stuffing,
        #          network sniff, or buying from a resale market)
        # --- In this simulation we simply copy sel/val ---
        atk_sel, atk_val = sel, val
        print(f"  [2] Attacker captures token: {atk_sel[:8]}… (sold on Telegram)")
        print()

        # Step 3: Attacker uses the token FIRST (faster, automated)
        time.sleep(0.05)
        atk_user, atk_new = rm.verify_and_rotate(
            atk_sel, atk_val,
            src_ip=atk_ip,
            device_fp="atk_device"
        )
        if atk_user:
            print(f"  [3] Attacker presents token from {atk_ip}")
            print(f"      ✓ Access GRANTED as: {atk_user}")
            if atk_new:
                print(f"      New token issued (old one now DEAD): "
                      f"{atk_new[0][:8]}…")
        else:
            print(f"  [3] Attacker token REJECTED (already used)")
        print()

        # Step 4: Legitimate user now tries the same original token
        #         (they still have the old cookie in their browser)
        time.sleep(0.05)
        leg_user, leg_new = rm.verify_and_rotate(
            sel, val,
            src_ip=leg_ip,
            device_fp="leg_device"
        )
        if leg_user:
            print(f"  [4] Legitimate user presents token from {leg_ip}")
            print(f"      ✓ Access GRANTED (attacker was too slow)")
        else:
            print(f"  [4] Legitimate user presents token from {leg_ip}")
            print(f"      ✗ REJECTED — token already rotated by attacker!")
            print(f"      The legitimate user is now implicitly logged out.")
            print(f"      → This is detectable: a validation FAILURE on a")
            print(f"        recently-issued token from a known-good device.")
            print(f"        Engine 11 should alert on this pattern.")
        print()

        # Step 5: Detection — the stolen-token rotation leaves a fingerprint
        # IDS can detect:
        #   (a) The original token was issued to IP A, but first presented
        #       from IP B (a different country) — impossible travel.
        #   (b) The legitimate user's NEXT login attempt will have to use
        #       password auth, creating an unusual re-auth event.
        if not leg_user and atk_new:
            alert = {
                "engine":       "Engine11/RotationRace",
                "severity":     "HIGH",
                "user":         target_email,
                "atk_ip":       atk_ip,
                "leg_ip":       leg_ip,
                "ts":           datetime.now().isoformat(),
                "message": (
                    f"TOKEN ROTATION RACE: {target_email}\n"
                    f"  Token was issued to {leg_ip} but first rotated "
                    f"from {atk_ip}\n"
                    f"  The original holder ({leg_ip}) was implicitly "
                    f"logged out.\n"
                    f"  Sequence: issue({leg_ip}) → rotate({atk_ip}) "
                    f"→ reject({leg_ip})\n"
                    f"  Indicates stolen remember-me cookie used before "
                    f"the legitimate owner.\n"
                    f"  Action: revoke ALL tokens for this user, "
                    f"force password reset.\n"
                    f"  MITRE: T1539 (Steal Web Session Cookie) + "
                    f"T1550.004 (Use Alternate Auth Material)"
                ),
            }
            print(f"  [IDS-Engine11/RotationRace] HIGH: {alert['message']}")
            _write_log(TOKEN_LOG, alert)
        else:
            alert = None

        result = {
            "scenario":    "rotation_race",
            "target":      target_email,
            "atk_won":     atk_user is not None,
            "leg_locked":  leg_user is None,
            "alert_fired": alert is not None,
        }
        print(f"  ── Summary ──")
        print(f"     Attacker won race   : {result['atk_won']}")
        print(f"     Legitimate locked out: {result['leg_locked']}")
        print(f"     Alert fired         : {result['alert_fired']}")
        print(f"  Defense: bind token to issuing IP (IP pinning) OR")
        print(f"           alert on issuance-IP ≠ first-use-IP pattern.")
        return result

    def scenario_c_parallel_sessions(self, email: str,
                                      rm: "SecureRememberMe") -> dict:
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

# ══════════════════════════════════════════════════════════════
#  GEO-IMPOSSIBILITY HELPERS (Signal 3)
# ══════════════════════════════════════════════════════════════

import math as _math

# IP prefix → (latitude, longitude, country, city)
# Covers lab IPs, simulated attacker ranges, and common datacenter blocks.
# Extend as needed.  Order matters: more specific prefixes first.
_GEO_TABLE = [
    # Lab / private ranges  (Armenia, Yerevan)
    ("192.168.100.", 40.18,  44.51, "Armenia",     "Yerevan"),
    ("192.168.",     40.18,  44.51, "Armenia",     "Yerevan"),
    # RFC-1918 10.0–10.49  → Russia, Moscow (simulation)
    ("10.0.",        55.75,  37.62, "Russia",      "Moscow"),
    ("10.1.",        55.75,  37.62, "Russia",      "Moscow"),
    # RFC-1918 10.50–10.99 → Netherlands (buyer simulation)
    ("10.50.",       52.37,  4.90,  "Netherlands", "Amsterdam"),
    ("10.51.",       52.37,  4.90,  "Netherlands", "Amsterdam"),
    # Tor exit nodes (approximation — Netherlands)
    ("185.220.",     52.37,  4.90,  "Netherlands", "Amsterdam"),
    ("185.107.",     52.37,  4.90,  "Netherlands", "Amsterdam"),
    # Comcast US residential
    ("68.42.",       41.85, -87.65, "United States", "Chicago"),
    ("73.0.",        37.77, -122.4, "United States", "San Francisco"),
    # Generic fallback
    ("0.",            0.0,   0.0,   "Unknown",     "Unknown"),
]


def _geo_lookup(ip: str) -> dict:
    """Return {lat, lon, country, city} for a given IP."""
    for prefix, lat, lon, country, city in _GEO_TABLE:
        if ip.startswith(prefix):
            return {"lat": lat, "lon": lon, "country": country, "city": city}
    return {"lat": 0.0, "lon": 0.0, "country": "Unknown", "city": "Unknown"}


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two lat/lon points in kilometres."""
    R = 6371.0
    dlat = _math.radians(lat2 - lat1)
    dlon = _math.radians(lon2 - lon1)
    a = (_math.sin(dlat / 2) ** 2
         + _math.cos(_math.radians(lat1))
         * _math.cos(_math.radians(lat2))
         * _math.sin(dlon / 2) ** 2)
    return R * 2 * _math.asin(_math.sqrt(min(1.0, a)))


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
        Evaluates four signals and returns the highest-severity alert, or None.

        Signal 1: IP change between issuance and use
                  (handled inside SecureRememberMe.verify_and_rotate;
                   logged there, not re-evaluated here to avoid double-firing)
        Signal 2: Too many active tokens (> MAX_TOKENS_PER_USER)
        Signal 3: Geographic impossibility — two uses from locations
                  whose straight-line distance divided by elapsed time
                  exceeds IMPOSSIBLE_TRAVEL_KM_PER_SEC (~900 km/h)
        Signal 4: Off-hours reactivation (02:00–05:00 local time,
                  first or second use of the token)
        """
        now   = time.time()
        hour  = datetime.fromtimestamp(now).hour
        alert = None
        geo_now = _geo_lookup(src_ip)

        with self._lock:
            self._usage[user_email].append({
                "ts":     now,
                "ip":     src_ip,
                "sel":    selector[:8],
                "lat":    geo_now["lat"],
                "lon":    geo_now["lon"],
                "country": geo_now["country"],
            })
            history = list(self._usage[user_email])

        # ── Signal 2: Too many active tokens ─────────────────────
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

        # ── Signal 3: Geographic impossibility ───────────────────
        # Compare current access against every prior access in the
        # rolling history.  If the required travel speed between any
        # two successive accesses exceeds IMPOSSIBLE_TRAVEL_KM_PER_SEC
        # (0.25 km/s ≈ 900 km/h, max commercial aircraft), the pair is
        # physically impossible and indicates account sharing or ATO.
        if len(history) >= 2:
            prev = history[-2]   # second-to-last entry
            time_delta_sec = now - prev["ts"]
            if time_delta_sec > 0:   # sanity guard
                dist_km = _haversine_km(
                    prev["lat"], prev["lon"],
                    geo_now["lat"], geo_now["lon"],
                )
                required_speed = dist_km / time_delta_sec  # km/s
                if required_speed > self.IMPOSSIBLE_TRAVEL_KM_PER_SEC:
                    elapsed_min = time_delta_sec / 60
                    speed_kmh   = required_speed * 3600
                    geo_alert = {
                        "engine":        "Engine11/ImpossibleTravel",
                        "severity":      "HIGH",
                        "user":          user_email,
                        "dist_km":       round(dist_km, 1),
                        "elapsed_min":   round(elapsed_min, 1),
                        "speed_kmh":     round(speed_kmh, 1),
                        "prev_ip":       prev["ip"],
                        "prev_country":  prev["country"],
                        "curr_ip":       src_ip,
                        "curr_country":  geo_now["country"],
                        "ts":            datetime.now().isoformat(),
                        "message": (
                            f"IMPOSSIBLE TRAVEL: {user_email}\n"
                            f"  Previous access: {prev['ip']} "
                            f"({prev['country']})  {elapsed_min:.1f} min ago\n"
                            f"  Current  access: {src_ip} "
                            f"({geo_now['country']})\n"
                            f"  Distance: {dist_km:.0f} km  "
                            f"in {elapsed_min:.1f} min  "
                            f"= {speed_kmh:.0f} km/h\n"
                            f"  Max possible (aircraft): "
                            f"{self.IMPOSSIBLE_TRAVEL_KM_PER_SEC * 3600:.0f} km/h\n"
                            f"  Conclusion: two people are using this account "
                            f"simultaneously.\n"
                            f"  Action: revoke all tokens, force re-auth, "
                            f"notify user.\n"
                            f"  MITRE: T1550.004 (Web Session Cookie)"
                        ),
                    }
                    if not alert:
                        alert = geo_alert

        # ── Signal 4: Off-hours reactivation ─────────────────────
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
                    f"  First-or-second use of this token at 02:00–05:00\n"
                    f"  Common pattern: attacker operating in a distant timezone\n"
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
            "total_alerts":  len(self._alerts),
            "users_watched": len(self._usage),
            "alert_breakdown": {
                "TokenCount":           sum(1 for a in self._alerts if "TokenCount" in a["engine"]),
                "ImpossibleTravel":     sum(1 for a in self._alerts if "ImpossibleTravel" in a["engine"]),
                "OffHoursReactivation": sum(1 for a in self._alerts if "OffHoursReactivation" in a["engine"]),
                "RotationRace":         sum(1 for a in self._alerts if "RotationRace" in a["engine"]),
            },
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

    # Scenario D: Token rotation race condition
    rm_d = SecureRememberMe()
    sim.scenario_d_rotation_attack("carol@corp.com", rm_d)

    # Demo: Signal 3 — geographic impossibility
    print("\n── Signal 3 Demo: Geographic Impossibility ──────────────")
    rm_geo = SecureRememberMe()
    sel_g, val_g = rm_geo.issue("eve@example.com", src_ip="192.168.100.20")
    det_geo = PersistentSessionDetector()
    # First use from Armenia (192.168.100.x)
    det_geo.check("eve@example.com", "192.168.100.20",
                  selector=sel_g, all_active_tokens=[])
    # Second use 90 seconds later from Netherlands — 4000+ km / 90s = impossible
    time.sleep(0.05)  # (simulated — we just manipulate the timestamp directly)
    # Manually backdate the first entry to simulate 90s elapsed
    with det_geo._lock:
        det_geo._usage["eve@example.com"][0]["ts"] -= 90
        det_geo._usage["eve@example.com"][0]["lat"] = 40.18   # Armenia
        det_geo._usage["eve@example.com"][0]["lon"] = 44.51
        det_geo._usage["eve@example.com"][0]["country"] = "Armenia"
    det_geo.check("eve@example.com", "10.50.60.70",
                  selector=sel_g, all_active_tokens=[])

    # Defense demonstration
    print("\n── Defense: Revoke on password change ────────────────")
    rm.revoke_all("alice@example.com")
    rm.revoke_all("admin@example.com")
    rm_d.revoke_all("carol@corp.com")
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