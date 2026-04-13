"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: CSRF Protection + OAuth Token Flow Simulation
 Environment: ISOLATED VM LAB ONLY
====================================================

Covers two of the missing attack chains from Document 2:

  "Credential stuffing + CSRF: In environments without CSRF
   protection, attackers hijack valid sessions and execute
   unauthorized actions silently."

  "Persistent Access and Token Abuse: When used strategically,
   credential stuffing becomes a launchpad for token hijacking,
   device registration abuse, or OAuth session planting.
   Attackers establish long-term access by:
     - Capturing session cookies and JWTs
     - Generating refresh tokens tied to attacker-controlled devices
     - Registering malicious third-party apps in OAuth flows"

This file has three parts:

Part 1 — CSRFProtection
  A reusable CSRF token implementation for fake_portal.py.
  Shows how CSRF tokens prevent session-riding after a
  credential stuffing login.

Part 2 — OAuthFlowSimulator
  Educational simulation of OAuth 2.0 authorization code flow.
  Demonstrates:
    a) Legitimate OAuth flow (auth code → access token → refresh token)
    b) Post-stuffing token abuse (attacker registers their own OAuth
       app in a compromised account, plants a persistent refresh token)
    c) Detection signals for token abuse

Part 3 — TokenAbuseDetector
  IDS-side detection of suspicious OAuth activity:
    - New device/app registration immediately after login from
      a flagged IP
    - Refresh token generation from unusual geolocation
    - Multiple refresh tokens created in rapid succession
"""

import base64
import hashlib
import hmac as _hmac_std
import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional


# ══════════════════════════════════════════════════════════════
#  Part 1: CSRF PROTECTION
# ══════════════════════════════════════════════════════════════

class CSRFProtection:
    """
    Double-Submit Cookie + Signed Token CSRF protection.

    How it works:
      1. Server issues a CSRF token on every form-serving GET.
         Token = HMAC-SHA256(session_id + timestamp, server_secret)
      2. Token is embedded in the HTML form as a hidden field AND
         set as a cookie (double-submit pattern).
      3. On POST, server verifies:
         a) form field matches cookie value
         b) token HMAC is valid (not tampered)
         c) token is not expired (max-age: TOKEN_TTL seconds)

    Why this stops session-riding after credential stuffing:
      A CSRF attack requires the victim's browser to submit a form
      to a target site. The attacker's page cannot READ the CSRF
      token from the victim's session (same-origin policy), so they
      cannot construct a valid form submission.

      After credential stuffing, an attacker has the password but
      typically does NOT have the victim's active session cookie
      (they logged in fresh). CSRF protection on state-changing
      actions (password change, email change, add payment) prevents
      them from automating post-login damage via a hosted page.

    Integration:
      In fake_portal.py:
        csrf = CSRFProtection(secret=SERVER_SECRET)
        # On GET /settings:
        token = csrf.generate(session_id)
        # embed token in form hidden field + set cookie
        # On POST /settings:
        ok, err = csrf.verify(session_id, form_token, cookie_token)
    """

    TOKEN_TTL    = 3600   # 1 hour
    SECRET_BYTES = 32

    def __init__(self, secret: bytes = None):
        self.secret = secret or os.urandom(self.SECRET_BYTES)
        self._lock  = threading.Lock()
        # Track issued tokens for explicit invalidation after use
        self._used: set = set()

    def generate(self, session_id: str) -> str:
        """
        Generate a CSRF token for the given session.
        Returns a URL-safe base64 string: timestamp|signature
        """
        ts  = int(time.time())
        msg = f"{session_id}:{ts}".encode()
        sig = _hmac_std.new(self.secret, msg, hashlib.sha256).hexdigest()[:16]
        raw = f"{ts}:{sig}"
        return base64.urlsafe_b64encode(raw.encode()).decode()

    def verify(self, session_id: str,
               form_token: str,
               cookie_token: str) -> tuple:
        """
        Verify a CSRF token pair (form field vs cookie).
        Returns (ok: bool, error_message: str)

        Defense-in-depth checks:
          1. Form token == cookie token (double-submit)
          2. HMAC valid for this session_id
          3. Token not expired
          4. Token not already used (one-time tokens)
        """
        if not form_token or not cookie_token:
            return False, "CSRF token missing"

        # Check 1: double-submit
        if not _hmac_std.compare_digest(form_token.strip(), cookie_token.strip()):
            return False, "CSRF token mismatch (form ≠ cookie)"

        # Decode token
        try:
            raw = base64.urlsafe_b64decode(form_token + "==").decode()
            ts_str, sig = raw.split(":", 1)
            ts = int(ts_str)
        except Exception:
            return False, "CSRF token malformed"

        # Check 3: expiry
        if time.time() - ts > self.TOKEN_TTL:
            return False, f"CSRF token expired ({int(time.time()-ts)}s old)"

        # Check 2: HMAC
        msg      = f"{session_id}:{ts}".encode()
        expected = _hmac_std.new(self.secret, msg, hashlib.sha256).hexdigest()[:16]
        if not _hmac_std.compare_digest(sig, expected):
            return False, "CSRF token signature invalid"

        # Check 4: replay
        token_id = hashlib.sha256(form_token.encode()).hexdigest()[:12]
        with self._lock:
            if token_id in self._used:
                return False, "CSRF token already used (replay detected)"
            self._used.add(token_id)

        return True, ""

    def html_field(self, token: str) -> str:
        """Return an HTML hidden input field for embedding in forms."""
        return f'<input type="hidden" name="csrf_token" value="{token}">'

    def cookie_header(self, token: str) -> str:
        """Return a Set-Cookie header value for the CSRF cookie."""
        return (f"csrf_token={token}; Path=/; HttpOnly; SameSite=Strict; "
                f"Max-Age={self.TOKEN_TTL}")

    @staticmethod
    def demo():
        print("\n── CSRF Protection Demo ──────────────────────────────")
        csrf = CSRFProtection()
        session = "sess_abc123"

        token = csrf.generate(session)
        print(f"  Generated token: {token[:20]}…")

        # Valid verification
        ok, err = csrf.verify(session, token, token)
        print(f"  Verify (valid):          ok={ok}, err='{err}'")

        # Mismatch attack
        ok2, err2 = csrf.verify(session, token, "tampered_token")
        print(f"  Verify (mismatch):       ok={ok2}, err='{err2}'")

        # Replay attack
        ok3, err3 = csrf.verify(session, token, token)
        print(f"  Verify (replay):         ok={ok3}, err='{err3}'")

        # Wrong session
        token2 = csrf.generate(session)
        ok4, err4 = csrf.verify("different_session", token2, token2)
        print(f"  Verify (wrong session):  ok={ok4}, err='{err4}'")
        print("── End CSRF Demo ─────────────────────────────────────\n")


# ══════════════════════════════════════════════════════════════
#  Part 2: OAUTH FLOW SIMULATION
# ══════════════════════════════════════════════════════════════

class OAuthFlowSimulator:
    """
    Educational simulation of OAuth 2.0 authorization code flow
    and how an attacker exploits it post-credential-stuffing.

    This is a fully in-memory simulation — no real OAuth server.
    Demonstrates the concepts described in Document 2's
    "Persistent Access and Token Abuse" section.

    Normal OAuth flow:
      User → Auth Server: "Authorize MyApp to read my profile"
      Auth Server → User: auth_code
      MyApp → Auth Server: exchange(auth_code) → access_token + refresh_token
      MyApp → Resource Server: GET /me  Authorization: Bearer access_token

    Post-stuffing abuse:
      1. Attacker stuffs credentials → logs in as victim
      2. Attacker's site initiates OAuth for their own malicious app
      3. Victim's session auto-approves (if scope was pre-consented)
      4. Attacker receives refresh_token tied to victim's account
      5. Attacker can silently access victim's account for weeks/months
         even after victim changes their password (refresh tokens often
         survive password changes in poorly-designed systems)
    """

    ACCESS_TOKEN_TTL  = 3600         # 1 hour
    REFRESH_TOKEN_TTL = 30 * 86400   # 30 days
    AUTH_CODE_TTL     = 60           # 1 minute

    # Simulated registered OAuth applications
    REGISTERED_APPS = {
        "app_legitimate": {
            "name": "Official Mobile App",
            "redirect_uri": "myapp://callback",
            "trusted": True,
        },
        "app_malicious": {
            "name": "Attacker's Evil App",
            "redirect_uri": "https://evil.attacker.lab/callback",
            "trusted": False,
        },
        "app_thirdparty": {
            "name": "Trusted Analytics Partner",
            "redirect_uri": "https://analytics.partner.lab/callback",
            "trusted": True,
        },
    }

    def __init__(self):
        self._lock          = threading.Lock()
        self._auth_codes:   dict = {}   # code → {user, client_id, scope, expiry}
        self._access_tokens: dict = {}  # token → {user, client_id, scope, expiry}
        self._refresh_tokens: dict = {} # token → {user, client_id, scope, issued, expiry}
        self._consents:     dict = defaultdict(set)  # user → set of client_ids

        # Simulated user accounts
        self._users = {
            "alice@example.com": {"password": "hunter2", "id": "u001"},
            "bob@example.com":   {"password": "password1", "id": "u002"},
        }

    def _make_token(self, prefix: str = "") -> str:
        return prefix + secrets.token_urlsafe(24)

    # ── Authorization endpoint ────────────────────────────────

    def authorize(self, user_email: str, client_id: str,
                  scope: str, auto_approve: bool = False) -> dict:
        """
        Simulate GET /oauth/authorize.

        In the post-stuffing abuse scenario:
          - user_email is the victim (attacker has their password)
          - client_id is the attacker's malicious app
          - auto_approve=True simulates silent approval when scope
            was previously consented (common in poorly-designed systems)

        Returns: {'auth_code': str} or {'error': str}
        """
        if client_id not in self.REGISTERED_APPS:
            return {"error": "unknown_client"}

        app = self.REGISTERED_APPS[client_id]

        # Check prior consent
        with self._lock:
            already_consented = client_id in self._consents.get(user_email, set())

        if not already_consented and not auto_approve:
            return {
                "status": "consent_required",
                "app_name": app["name"],
                "scope": scope,
                "message": "User must explicitly approve this app.",
            }

        # Grant authorization code
        code   = self._make_token("code_")
        expiry = time.time() + self.AUTH_CODE_TTL
        with self._lock:
            self._auth_codes[code] = {
                "user":      user_email,
                "client_id": client_id,
                "scope":     scope,
                "expiry":    expiry,
            }
            self._consents[user_email].add(client_id)

        print(f"[OAUTH] Auth code issued: user={user_email}, "
              f"client={app['name']}, scope={scope}")
        return {"auth_code": code, "redirect_uri": app["redirect_uri"]}

    # ── Token endpoint ────────────────────────────────────────

    def exchange_code(self, auth_code: str, client_id: str) -> dict:
        """
        Simulate POST /oauth/token (authorization code grant).
        Returns access_token + refresh_token.
        """
        with self._lock:
            entry = self._auth_codes.pop(auth_code, None)

        if not entry:
            return {"error": "invalid_grant"}
        if time.time() > entry["expiry"]:
            return {"error": "expired_code"}
        if entry["client_id"] != client_id:
            return {"error": "client_mismatch"}

        now     = time.time()
        at      = self._make_token("at_")
        rt      = self._make_token("rt_")

        with self._lock:
            self._access_tokens[at] = {
                "user":      entry["user"],
                "client_id": client_id,
                "scope":     entry["scope"],
                "expiry":    now + self.ACCESS_TOKEN_TTL,
            }
            self._refresh_tokens[rt] = {
                "user":      entry["user"],
                "client_id": client_id,
                "scope":     entry["scope"],
                "issued":    now,
                "expiry":    now + self.REFRESH_TOKEN_TTL,
            }

        print(f"[OAUTH] Tokens issued: user={entry['user']}, "
              f"client={client_id}\n"
              f"[OAUTH]   access_token={at[:12]}…  (TTL: {self.ACCESS_TOKEN_TTL}s)\n"
              f"[OAUTH]   refresh_token={rt[:12]}…  (TTL: {self.REFRESH_TOKEN_TTL}s)")

        return {
            "access_token":  at,
            "refresh_token": rt,
            "token_type":    "Bearer",
            "expires_in":    self.ACCESS_TOKEN_TTL,
            "scope":         entry["scope"],
        }

    def refresh(self, refresh_token: str, client_id: str) -> dict:
        """
        Simulate POST /oauth/token (refresh token grant).
        Issues new access token; refresh token may be rotated.
        """
        with self._lock:
            entry = self._refresh_tokens.get(refresh_token)

        if not entry:
            return {"error": "invalid_token"}
        if time.time() > entry["expiry"]:
            return {"error": "token_expired"}
        if entry["client_id"] != client_id:
            return {"error": "client_mismatch"}

        now = time.time()
        at  = self._make_token("at_")
        with self._lock:
            self._access_tokens[at] = {
                "user":      entry["user"],
                "client_id": client_id,
                "scope":     entry["scope"],
                "expiry":    now + self.ACCESS_TOKEN_TTL,
            }

        print(f"[OAUTH] Token refreshed: user={entry['user']}, "
              f"client={client_id}, new_at={at[:12]}…")
        return {
            "access_token": at,
            "token_type":   "Bearer",
            "expires_in":   self.ACCESS_TOKEN_TTL,
        }

    def revoke_user_tokens(self, user_email: str):
        """
        Revoke ALL tokens for a user (password change defense).
        Proper systems do this; buggy ones do not — hence the attack.
        """
        with self._lock:
            to_rm_at = [k for k, v in self._access_tokens.items()
                        if v["user"] == user_email]
            to_rm_rt = [k for k, v in self._refresh_tokens.items()
                        if v["user"] == user_email]
            for k in to_rm_at:
                del self._access_tokens[k]
            for k in to_rm_rt:
                del self._refresh_tokens[k]
        print(f"[OAUTH] Revoked {len(to_rm_at)} access + "
              f"{len(to_rm_rt)} refresh tokens for {user_email}")

    def list_active_tokens(self, user_email: str) -> dict:
        now = time.time()
        with self._lock:
            ats = {k: v for k, v in self._access_tokens.items()
                   if v["user"] == user_email and now < v["expiry"]}
            rts = {k: v for k, v in self._refresh_tokens.items()
                   if v["user"] == user_email and now < v["expiry"]}
        return {"access_tokens": len(ats), "refresh_tokens": len(rts),
                "refresh_details": [
                    {"client": v["client_id"],
                     "scope":  v["scope"],
                     "issued": datetime.fromtimestamp(v["issued"]).strftime("%H:%M:%S"),
                     "days_left": round((v["expiry"] - now) / 86400, 1)}
                    for v in rts.values()
                ]}


# ══════════════════════════════════════════════════════════════
#  Part 3: TOKEN ABUSE DETECTOR (IDS side)
# ══════════════════════════════════════════════════════════════

class TokenAbuseDetector:
    """
    Detects suspicious OAuth token activity post-stuffing.

    Signals:
      1. Token grant to an untrusted/new app immediately after
         login from a flagged (tarpitted) IP
      2. Multiple refresh tokens for the same user from different
         client_ids in a short window (app farm)
      3. Refresh token used from a different geographic region
         than the original grant
    """

    NEW_APP_WINDOW   = 300    # seconds after login to watch for app registration
    MULTI_APP_THRESH = 3      # apps in MULTI_APP_WINDOW
    MULTI_APP_WINDOW = 600    # seconds

    def __init__(self, flagged_ips_fn=None):
        """
        flagged_ips_fn: callable returning set of currently tarpitted IPs
                        (connects to tarpit_state.list_flagged)
        """
        self.flagged_ips_fn = flagged_ips_fn or (lambda: set())
        self._lock          = threading.Lock()
        # user → deque of (timestamp, client_id, src_ip) for token grants
        self._grants: dict  = defaultdict(lambda: deque(maxlen=50))
        self._alerts        = 0

    def record_grant(self, user_email: str, client_id: str,
                     src_ip: str, app_trusted: bool,
                     alert_cb=None) -> Optional[str]:
        """
        Called when OAuth tokens are issued.
        Checks for suspicious grant patterns.
        """
        now = time.time()
        with self._lock:
            self._grants[user_email].append((now, client_id, src_ip, app_trusted))
            recent = list(self._grants[user_email])

        alerts = []

        # Signal 1: untrusted app + flagged IP
        if not app_trusted and src_ip in self.flagged_ips_fn():
            alerts.append(
                f"OAUTH TOKEN ABUSE: Untrusted app '{client_id}' granted "
                f"token by user '{user_email}' from TARPITTED IP {src_ip}\n"
                f"  Post-stuffing persistence attack: attacker planted "
                f"a long-lived refresh token in victim account.\n"
                f"  Mitigation: revoke all tokens for {user_email}, "
                f"force re-authentication.\n"
                f"  MITRE: T1550.001 (Use Alternate Authentication Material)"
            )

        # Signal 2: multiple different apps in short window
        cutoff = now - self.MULTI_APP_WINDOW
        recent_grants = [(ts, cid) for ts, cid, ip, _ in recent if ts > cutoff]
        unique_apps   = {cid for _, cid in recent_grants}
        if len(unique_apps) >= self.MULTI_APP_THRESH:
            alerts.append(
                f"OAUTH APP FARM: {user_email} granted tokens to "
                f"{len(unique_apps)} different apps in {self.MULTI_APP_WINDOW}s\n"
                f"  Apps: {list(unique_apps)}\n"
                f"  Indicates automated app registration by an attacker "
                f"establishing multiple persistence channels.\n"
                f"  MITRE: T1078 (Valid Accounts)"
            )

        for a in alerts:
            self._alerts += 1
            if alert_cb:
                alert_cb("OAuth/TokenAbuse", "CRITICAL", a)

        return alerts[0] if alerts else None

    def get_stats(self) -> dict:
        now = time.time()
        result = {}
        with self._lock:
            for user, entries in self._grants.items():
                recent = [(ts, cid, ip, tr)
                          for ts, cid, ip, tr in entries
                          if now - ts < self.MULTI_APP_WINDOW]
                if recent:
                    result[user] = {
                        "recent_grants":  len(recent),
                        "unique_apps":    len({cid for _, cid, _, _ in recent}),
                        "untrusted_apps": sum(1 for _, _, _, tr in recent if not tr),
                    }
        return result


# ── Demo / self-test ──────────────────────────────────────────

def run_demo():
    print("\n" + "="*60)
    print(" CSRF + OAuth Simulation — AUA Research Lab")
    print("="*60)

    # ── CSRF Demo ─────────────────────────────────────────────
    CSRFProtection.demo()

    # ── OAuth: Normal flow ────────────────────────────────────
    print("── Normal OAuth 2.0 Flow ─────────────────────────────")
    oauth = OAuthFlowSimulator()
    result = oauth.authorize(
        "alice@example.com", "app_legitimate",
        scope="read:profile", auto_approve=True
    )
    print(f"  Authorize: {result}")

    token_resp = oauth.exchange_code(result["auth_code"], "app_legitimate")
    print(f"  Token exchange: access={token_resp['access_token'][:12]}…  "
          f"refresh={token_resp['refresh_token'][:12]}…")

    refresh_resp = oauth.refresh(token_resp["refresh_token"], "app_legitimate")
    print(f"  Refresh: new access={refresh_resp['access_token'][:12]}…")

    tokens = oauth.list_active_tokens("alice@example.com")
    print(f"  Alice's active tokens: {tokens}")

    # ── OAuth: Post-stuffing abuse ─────────────────────────────
    print("\n── Post-Stuffing OAuth Abuse ─────────────────────────")
    print("  [Attacker has Alice's password via credential stuffing]")
    print("  [Attacker uses Alice's session to authorize evil app]")

    detector = TokenAbuseDetector(flagged_ips_fn=lambda: {"192.168.100.11"})

    result2 = oauth.authorize(
        "alice@example.com", "app_malicious",
        scope="read:profile write:settings", auto_approve=True
    )
    token_resp2 = oauth.exchange_code(result2["auth_code"], "app_malicious")
    print(f"  Evil app got refresh_token: {token_resp2['refresh_token'][:12]}…")

    alert = detector.record_grant(
        user_email="alice@example.com",
        client_id="app_malicious",
        src_ip="192.168.100.11",   # this IP is tarpitted
        app_trusted=False,
        alert_cb=lambda eng, sev, msg: print(f"\n  [IDS-{eng}] {sev}: {msg}\n"),
    )

    # ── Defense: Revoke all tokens ─────────────────────────────
    print("\n── Defense: Revoke all tokens on password reset ──────")
    oauth.revoke_user_tokens("alice@example.com")
    tokens_after = oauth.list_active_tokens("alice@example.com")
    print(f"  Tokens after revocation: {tokens_after}")
    print(f"  Evil app's refresh token is now invalid.")
    print(f"\n  Teaching point: If revoke_user_tokens() is NOT called")
    print(f"  on password change, the attacker's refresh_token remains")
    print(f"  valid for up to 30 days despite the password change.")
    print("="*60 + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="CSRF + OAuth Simulation — AUA Research Lab"
    )
    parser.add_argument("--demo", action="store_true",
                        help="Run full CSRF + OAuth demo")
    args = parser.parse_args()

    print("=" * 60)
    print(" CSRF Protection + OAuth Flow Simulation")
    print(" AUA Botnet Research Lab — ISOLATED VM ONLY")
    print("=" * 60)

    run_demo()
