"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: TOTP Step-Up 2FA (RFC 6238)
 Environment: ISOLATED VM LAB ONLY
====================================================

Pure-Python TOTP implementation (RFC 6238) — no external deps.
Provides step-up authentication triggered by IP reputation score.

Article mapping (Castle credential stuffing blog):
  "Use risk-based authentication to step up to 2FA or email
   verification when the session looks new, untrusted, or unusual."

How step-up 2FA stops credential stuffing:
  A credential stuffer has the correct password but does NOT have
  access to the victim's TOTP device.  Even a 100% hit rate on
  credential testing becomes useless if 2FA is required for
  elevated-risk sessions.

  Trigger thresholds (configurable):
    ip_reputation SUSPECT (score ≥ 25)  → require TOTP on login
    ip_reputation LIKELY_BOT (≥ 50)     → require TOTP always
    ip_reputation BOT (≥ 75)            → hard block (no TOTP offered)

Lab demonstration:
  cred_stuffing.py mode=bot will hit the 2FA wall because it uses
  urllib, which gets SUSPECT/LIKELY_BOT from ip_reputation.
  Human sessions (realistic UA + residential IP) are scored CLEAN
  and get no friction.

TOTP algorithm (RFC 6238):
  1. secret = base32-encoded random bytes (per-user, server-stored)
  2. T = floor(unix_timestamp / 30)          # 30-second time step
  3. HMAC-SHA1(secret, T as 8-byte big-endian)
  4. offset = last 4 bits of HMAC
  5. code = HMAC[offset:offset+4] & 0x7FFFFFFF  mod 10^6

Usage:
  from totp_2fa import TOTPManager, verify_totp, generate_secret

  # Server-side: generate and store secret per user at enrolment
  secret = generate_secret()
  uri    = get_provisioning_uri(secret, "alice@example.com", "MyApp")
  # → show uri as QR code for Google Authenticator / Authy

  # At login time:
  ok = verify_totp(secret, user_submitted_code, window=1)

  # Or use the full manager:
  mgr = TOTPManager()
  mgr.enrol("alice@example.com")
  ok, msg = mgr.verify("alice@example.com", "123456")
"""

import base64
import hashlib
import hmac
import os
import struct
import threading
import time
from typing import Optional, Tuple


# ── Core TOTP functions (RFC 6238) ────────────────────────────

def generate_secret(n_bytes: int = 20) -> str:
    """
    Generate a random TOTP secret.
    Returns URL-safe base32 string (no padding) suitable for QR codes.
    """
    raw = os.urandom(n_bytes)
    return base64.b32encode(raw).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> int:
    """
    HOTP (RFC 4226): HMAC-SHA1 of counter, then dynamic truncation.
    Returns a 6-digit integer.
    """
    # Pad base32 to multiple of 8
    pad    = (-len(secret_b32)) % 8
    secret = base64.b32decode(secret_b32 + "=" * pad, casefold=True)
    msg    = struct.pack(">Q", counter)
    h      = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code   = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return code % 1_000_000


def get_totp(secret_b32: str, timestamp: float = None,
             step: int = 30) -> str:
    """
    Compute the current TOTP code.
    Returns a zero-padded 6-digit string (e.g. "042891").
    """
    if timestamp is None:
        timestamp = time.time()
    counter = int(timestamp) // step
    return f"{_hotp(secret_b32, counter):06d}"


def verify_totp(secret_b32: str, code: str,
                window: int = 1,
                step: int = 30) -> bool:
    """
    Verify a TOTP code with ±window tolerance (handles clock skew).

    window=1 accepts codes from one step before and after current time.
    RFC 6238 recommends window ≤ 1 for security.
    """
    try:
        code_int = int(code.strip())
    except (TypeError, ValueError):
        return False
    now     = time.time()
    counter = int(now) // step
    for delta in range(-window, window + 1):
        if _hotp(secret_b32, counter + delta) == code_int:
            return True
    return False


def get_provisioning_uri(secret_b32: str,
                         email: str,
                         issuer: str = "AUA-Lab") -> str:
    """
    Return an otpauth:// URI for QR code enrolment.
    Compatible with Google Authenticator, Authy, and 1Password.
    """
    from urllib.parse import quote
    return (
        f"otpauth://totp/{quote(issuer)}:{quote(email)}"
        f"?secret={secret_b32}&issuer={quote(issuer)}&algorithm=SHA1"
        f"&digits=6&period=30"
    )


# ── Risk-threshold helpers ────────────────────────────────────

# Maps ip_reputation band → 2FA policy
# CLEAN     → no 2FA required
# SUSPECT   → 2FA required for new sessions (step-up)
# LIKELY_BOT → 2FA required always
# BOT       → hard block; do not offer 2FA (attacker cannot solve it anyway
#              but revealing detection lets them tune their traffic)
TWOFACTOR_POLICY = {
    "CLEAN":      "none",
    "SUSPECT":    "step_up",
    "LIKELY_BOT": "required",
    "BOT":        "block",
    "HIGH_RISK":  "block",   # geoip_sim band
}


def requires_2fa(rep_band: str,
                 session_is_new: bool = True) -> str:
    """
    Given a reputation band, return the 2FA policy:
      "none"      — proceed normally
      "step_up"   — ask for TOTP if session is new
      "required"  — ask for TOTP regardless
      "block"     — reject without explanation
    """
    policy = TWOFACTOR_POLICY.get(rep_band, "step_up")
    if policy == "step_up" and not session_is_new:
        return "none"
    return policy


# ── Server-side TOTP manager ──────────────────────────────────

class TOTPManager:
    """
    Manages TOTP secrets for all users.

    In production: secrets are stored in a database, encrypted at rest.
    In lab: in-memory dict (resets on restart — re-enrol on each lab session).

    Thread-safe.
    """

    def __init__(self):
        self._secrets: dict = {}   # email → secret_b32
        self._lock = threading.Lock()

        # Rate-limit: block IP after N failed TOTP attempts
        self._fail_counts: dict = {}  # (email, ip) → count
        self._fail_lock  = threading.Lock()
        self.MAX_FAILS   = 5

    def enrol(self, email: str,
              secret: str = None) -> str:
        """
        Enrol a user with a new or provided secret.
        Returns the secret (to show as QR code / URI).
        """
        if secret is None:
            secret = generate_secret()
        with self._lock:
            self._secrets[email] = secret
        return secret

    def get_uri(self, email: str,
                issuer: str = "MyApp") -> Optional[str]:
        """Return the otpauth:// provisioning URI for a user."""
        with self._lock:
            secret = self._secrets.get(email)
        if not secret:
            return None
        return get_provisioning_uri(secret, email, issuer)

    def is_enrolled(self, email: str) -> bool:
        with self._lock:
            return email in self._secrets

    def verify(self, email: str, code: str,
               src_ip: str = "?",
               window: int = 1) -> Tuple[bool, str]:
        """
        Verify a TOTP code for a user.

        Returns (ok: bool, message: str).
        Rate-limits failed attempts per (email, ip) pair.
        """
        fail_key = (email, src_ip)
        with self._fail_lock:
            fails = self._fail_counts.get(fail_key, 0)
            if fails >= self.MAX_FAILS:
                return False, "Too many failed 2FA attempts. Account temporarily locked."

        with self._lock:
            secret = self._secrets.get(email)
        if secret is None:
            return False, "User not enrolled in 2FA."

        ok = verify_totp(secret, code, window=window)

        with self._fail_lock:
            if ok:
                self._fail_counts.pop(fail_key, None)
            else:
                self._fail_counts[fail_key] = fails + 1

        if ok:
            return True, "2FA verified."
        remaining = max(0, self.MAX_FAILS - self._fail_counts.get(fail_key, 0))
        return False, f"Invalid 2FA code. {remaining} attempt(s) remaining."

    def unenrol(self, email: str):
        with self._lock:
            self._secrets.pop(email, None)

    def status(self) -> dict:
        with self._lock:
            return {
                "enrolled_users": list(self._secrets.keys()),
                "n_enrolled": len(self._secrets),
            }


# ── Singleton manager (shared by fake_portal.py) ─────────────
_manager = TOTPManager()


def get_manager() -> TOTPManager:
    return _manager


# ── CLI demo ──────────────────────────────────────────────────

if __name__ == "__main__":
    print("TOTP 2FA Module — RFC 6238 self-test\n")

    secret = generate_secret()
    print(f"  Generated secret : {secret}")

    code = get_totp(secret)
    print(f"  Current TOTP code: {code}")
    print(f"  Verify code      : {verify_totp(secret, code)} (should be True)")
    print(f"  Verify wrong     : {verify_totp(secret, '000000')} (should be False)")

    uri = get_provisioning_uri(secret, "alice@example.com", "AUA-Lab")
    print(f"\n  Provisioning URI (scan with Authenticator app):")
    print(f"  {uri}")

    print("\n--- Manager demo ---")
    mgr = TOTPManager()
    sec = mgr.enrol("alice@example.com")
    code = get_totp(sec)
    ok, msg = mgr.verify("alice@example.com", code, src_ip="192.168.100.11")
    print(f"  alice verify correct : {ok}  [{msg}]")
    ok, msg = mgr.verify("alice@example.com", "000000", src_ip="192.168.100.11")
    print(f"  alice verify wrong   : {ok}  [{msg}]")

    print("\n--- Risk-based 2FA policy ---")
    for band in ["CLEAN", "SUSPECT", "LIKELY_BOT", "BOT"]:
        policy = requires_2fa(band, session_is_new=True)
        print(f"  {band:<12} → {policy}")
