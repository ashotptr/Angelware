"""
====================================================
 fake_portal_extensions.py
 AUA CS 232/337 — Botnet Research Lab
 Extensions for fake_portal.py
====================================================

This file was imported by fake_portal.py but never existed in the
repository. It provides every symbol fake_portal.py needs:

  engine9_score()         Engine 9 — browser automation artifact detection
  set_alert_callback()    Register the portal's alert sink
  handle_mobile_login()   POST /api/mobile/login
  handle_reset_password() POST /reset-password (secure + leaky modes)
  handle_oauth_authorize() POST /oauth/authorize
  handle_oauth_token()    POST /oauth/token
  handle_oauth_revoke()   POST /oauth/revoke
  get_extension_stats()   /stats/extensions payload
  csrf_protection         CSRF double-submit cookie helper (class)
  KNOWN_EMAILS            Mutable set populated by fake_portal.py

Teaching points covered:
  - Browser automation detection at the HTTP layer (Engine 9)
  - CSRF double-submit cookie pattern and why bots bypass it easily
  - Mobile API blind spot (no JS fingerprinting available)
  - OAuth token planting after account takeover (persistent access)
  - Password-reset enumeration: leaky vs. uniform responses
  - Session-chaining anomaly (immediate API calls right after login)
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

# ─────────────────────────────────────────────────────────────
#  Shared alert sink (wired by fake_portal.py via set_alert_callback)
# ─────────────────────────────────────────────────────────────

_alert_fn = None

def set_alert_callback(fn):
    """Register the portal's alert function so extensions can fire alerts."""
    global _alert_fn
    _alert_fn = fn

def _alert(engine, severity, msg):
    if _alert_fn:
        _alert_fn(engine, severity, msg)
    else:
        ts = datetime.now().strftime("%H:%M:%S")
        logging.warning(f"[{severity}] {engine} @ {ts} — {msg.splitlines()[0]}")


# ─────────────────────────────────────────────────────────────
#  Shared known-email set (fake_portal.py populates this)
# ─────────────────────────────────────────────────────────────

KNOWN_EMAILS: set = set()


# ═════════════════════════════════════════════════════════════
#  ENGINE 9 — BROWSER AUTOMATION ARTIFACT DETECTION
#
#  Source: browser_bot_sim.py (already in the repo) + fake_portal.py
#  integration point.
#
#  At the HTTP layer we can check:
#    1. User-Agent strings that betray Selenium/Playwright/Puppeteer
#    2. Missing Sec-Fetch-* headers (browsers always send these on
#       same-origin form POSTs since Chrome 76 / Firefox 90)
#    3. Missing or implausible Accept-Language (automation tools
#       often omit it or use a single "en" with no quality values)
#    4. Missing Sec-CH-UA on requests claiming to be Chrome 90+
#    5. Headless browser UA keywords (HeadlessChrome, PhantomJS, …)
#    6. CDP/DevTools injection headers left by Puppeteer patches
#    7. Missing Referer/Origin on form POST (browser always sends these
#       when submitting a form received from the same origin)
#    8. WebDriver fingerprint via Accept header order anomalies
#
#  JS-layer signals (webdriver property, canvas entropy, WebGL vendor)
#  require JavaScript to be injected into the login page and the result
#  submitted as a hidden field.  The BIOMETRICS_JS in
#  fake_portal_biometrics.py handles that side; this module handles the
#  header-only side that fires even when JS is absent or spoofed.
# ═════════════════════════════════════════════════════════════

_HEADLESS_UA_PATTERNS = [
    r"HeadlessChrome",
    r"PhantomJS",
    r"SlimerJS",
    r"Splash",
    r"python-requests",
    r"python-urllib",
    r"Go-http-client",
    r"curl/",
    r"libwww-perl",
    r"Mechanize",
    r"scrapy",
    r"httpx",
    r"aiohttp",
    r"node-fetch",
    r"axios/",
    r"OpenBullet",
    r"SentryBot",
    r"BlackCapBot",
]

_CDP_INJECTION_HEADERS = [
    "x-devtools-emulate-network-conditions-client-id",
    "x-client-data",          # sometimes left by Puppeteer Page.setExtraHTTPHeaders
    "x-purpose",              # old Puppeteer artefact
]

# Signals tuple: (name, points, description)
_E9_SIGNALS_REGISTRY = [
    ("HEADLESS_UA",          30, "User-Agent contains headless browser / automation tool keyword"),
    ("CDP_HEADER",           25, "CDP/DevTools injection header detected"),
    ("MISSING_SEC_FETCH",    15, "Sec-Fetch-Site/Mode/Dest absent — browsers always send on form POST"),
    ("MISSING_ACCEPT_LANG",  15, "Accept-Language header absent — browsers always include it"),
    ("MISSING_CH_UA",        10, "Chrome UA without Sec-CH-UA — incomplete Chrome impersonation"),
    ("MISSING_ORIGIN",       10, "No Origin or Referer on POST — browser always sends for same-origin forms"),
    ("UNUSUAL_ACCEPT",        5, "Accept header does not match browser HTML request pattern"),
]

_e9_scores_by_ip: dict = defaultdict(list)   # ip → list of (ts, score, signals)
_e9_lock = threading.Lock()

E9_BOT_THRESHOLD     = 30   # score at or above this → LIKELY_BOT classification
E9_SUSPECT_THRESHOLD = 15   # score at or above this → SUSPECT


def engine9_score(headers: dict, ip: str) -> dict:
    """
    Score a login request for browser automation artefacts.

    Parameters
    ----------
    headers : dict
        HTTP headers from request, keys already lowercased.
    ip : str
        Source IP address (for multi-request correlation).

    Returns
    -------
    dict with keys: score (0-100), signals (list of str), classification
    """
    score   = 0
    signals = []
    ua      = headers.get("user-agent", "")

    # 1. Headless / automation User-Agent
    for pattern in _HEADLESS_UA_PATTERNS:
        if re.search(pattern, ua, re.IGNORECASE):
            score   += 30
            signals.append(f"HEADLESS_UA: matched pattern '{pattern}' in User-Agent")
            break

    # 2. CDP injection headers
    for cdp_hdr in _CDP_INJECTION_HEADERS:
        if cdp_hdr in headers:
            score   += 25
            signals.append(f"CDP_HEADER: '{cdp_hdr}' present")

    # 3. Missing Sec-Fetch headers (browsers send on same-origin form POST)
    has_sec_fetch = any(k.startswith("sec-fetch-") for k in headers)
    if not has_sec_fetch:
        score   += 15
        signals.append("MISSING_SEC_FETCH: no Sec-Fetch-* headers")

    # 4. Missing Accept-Language
    if not headers.get("accept-language"):
        score   += 15
        signals.append("MISSING_ACCEPT_LANG: Accept-Language absent")

    # 5. Chrome UA without Sec-CH-UA
    is_chrome = "chrome" in ua.lower() and "chromium" not in ua.lower()
    has_ch_ua = bool(headers.get("sec-ch-ua") or headers.get("sec-ch-ua-platform"))
    if is_chrome and not has_ch_ua and "chrome/9" in ua.lower():
        score   += 10
        signals.append("MISSING_CH_UA: Chrome UA without Sec-CH-UA (incomplete impersonation)")

    # 6. No Origin/Referer on POST
    has_origin  = bool(headers.get("origin") or headers.get("referer"))
    if not has_origin and ua:
        score   += 10
        signals.append("MISSING_ORIGIN: no Origin or Referer on POST request")

    # 7. Unusual Accept header
    accept = headers.get("accept", "")
    browser_accept = "text/html" in accept or "*/*" in accept
    if ua and not browser_accept:
        score   += 5
        signals.append(f"UNUSUAL_ACCEPT: '{accept[:60]}' does not match browser pattern")

    score = min(score, 100)

    if score >= E9_BOT_THRESHOLD:
        classification = "BOT"
    elif score >= E9_SUSPECT_THRESHOLD:
        classification = "SUSPECT"
    else:
        classification = "CLEAN"

    # Store for stats
    with _e9_lock:
        _e9_scores_by_ip[ip].append((time.time(), score, classification))
        # Keep last 50 per IP
        if len(_e9_scores_by_ip[ip]) > 50:
            _e9_scores_by_ip[ip].pop(0)

    if score >= E9_BOT_THRESHOLD:
        _alert(
            "Engine9/BrowserAutomation", "HIGH",
            f"BROWSER AUTOMATION DETECTED: {ip}\n"
            f"  Score: {score}/100  Classification: {classification}\n"
            f"  Signals detected ({len(signals)}):\n"
            + "".join(f"    • {s}\n" for s in signals) +
            f"  MITRE: T1589 (Gather Victim Identity Information)"
        )

    return {"score": score, "signals": signals, "classification": classification}


# ═════════════════════════════════════════════════════════════
#  CSRF PROTECTION — double-submit cookie pattern
#
#  Teaching point: CSRF is ineffective against credential-stuffing
#  bots that use a cookie-jar and a real browser GET → POST cycle
#  (they receive the cookie on GET and submit it on POST automatically).
#  It IS effective against cross-origin forgery from a different site.
#  The real defence against stuffing is timing analysis + fingerprinting.
# ═════════════════════════════════════════════════════════════

_CSRF_SECRET = secrets.token_hex(32)   # one secret per process lifetime

class CSRFProtection:
    """
    Double-submit cookie CSRF protection.

    Usage (in fake_portal.py):
        from fake_portal_extensions import csrf_protection as _csrf
        # On GET /login:
        token = _csrf.generate(session_id)
        html  = LOGIN_PAGE_TMPL.format(csrf_field=_csrf.html_field(token))
        resp  = make_response(html)
        resp.headers["Set-Cookie"] = _csrf.cookie_header(token)
        # On POST /login:
        ok, err = _csrf.verify(session_id, form_token, cookie_token)
    """

    _TTL  = 3600      # token valid for 1 hour
    _store: dict = {}  # session_id → (token, issued_at)
    _lock = threading.Lock()

    @classmethod
    def _sign(cls, session_id: str, token: str) -> str:
        return hmac.new(
            _CSRF_SECRET.encode(),
            f"{session_id}:{token}".encode(),
            hashlib.sha256,
        ).hexdigest()

    @classmethod
    def generate(cls, session_id: str) -> str:
        """Generate and store a CSRF token for this session."""
        token = secrets.token_hex(16)
        with cls._lock:
            cls._store[session_id] = (token, time.time())
        return token

    @classmethod
    def verify(cls, session_id: str, form_token: str, cookie_token: str) -> tuple:
        """
        Verify CSRF token from form against cookie.
        Returns (ok: bool, error_msg: str).
        """
        if not form_token or not cookie_token:
            return False, "CSRF token missing"
        if not secrets.compare_digest(str(form_token), str(cookie_token)):
            return False, "CSRF token mismatch (form vs cookie)"
        with cls._lock:
            stored = cls._store.get(session_id)
        if not stored:
            return False, "CSRF token unknown session"
        _token, issued = stored
        if time.time() - issued > cls._TTL:
            return False, "CSRF token expired"
        if not secrets.compare_digest(str(form_token), _token):
            return False, "CSRF token invalid"
        return True, ""

    @staticmethod
    def html_field(token: str) -> str:
        """Render a hidden input tag for the login form."""
        return f'<input type="hidden" name="csrf_token" value="{token}">'

    @staticmethod
    def cookie_header(token: str) -> str:
        """Render the Set-Cookie header value."""
        return f"csrf_token={token}; Path=/; SameSite=Strict; HttpOnly=false"


csrf_protection = CSRFProtection()


# ═════════════════════════════════════════════════════════════
#  MOBILE API LOGIN  — POST /api/mobile/login
#
#  Teaching point: mobile endpoints lack JS-based fingerprinting.
#  Bots can spoof device headers cheaply with --rotate-device,
#  bypassing Engine 6 (fingerprint reuse) and Engine 9.
#  Only Engine 2 (CV timing) still applies if requests are frequent
#  enough, and username-level rate limiting (per Device-ID).
# ═════════════════════════════════════════════════════════════

_mobile_device_tracker: dict = defaultdict(deque)   # device_id → deque[ts]
_mobile_ip_tracker:     dict = defaultdict(deque)   # ip → deque[ts]
_mobile_lock   = threading.Lock()

MOBILE_DEVICE_RATE_MAX    = 10   # attempts per device per window
MOBILE_DEVICE_RATE_WINDOW = 60   # seconds
MOBILE_IP_RATE_MAX        = 30
MOBILE_ATTEMPTS: list     = []


def handle_mobile_login(src_ip: str, body: bytes,
                         headers: dict, user_db: dict,
                         tarpit_delay_fn) -> tuple:
    """
    Handle POST /api/mobile/login.

    user_db format: {email: {"password_hash": sha256hex}}
    Returns (http_status_code, response_dict).
    """
    try:
        data = json.loads(body)
    except Exception:
        return 400, {"status": "error", "message": "invalid JSON"}

    email     = data.get("email", "").lower().strip()
    password  = data.get("password", "")
    device_id = (
        headers.get("x-device-id") or
        headers.get("x-device-identifier") or
        "unknown"
    )
    app_ver   = headers.get("x-app-version", "unknown")
    platform  = headers.get("x-platform", headers.get("x-os", "unknown"))

    now = time.time()

    # Per-device rate limiting
    with _mobile_lock:
        dq = _mobile_device_tracker[device_id]
        cutoff = now - MOBILE_DEVICE_RATE_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= MOBILE_DEVICE_RATE_MAX:
            return 429, {
                "status": "error",
                "message": "Too many requests from this device.",
                "retry_after": int(MOBILE_DEVICE_RATE_WINDOW - (now - dq[0])),
            }
        dq.append(now)

        # Per-IP rate limiting (higher threshold — shared NAT is common on mobile)
        iq = _mobile_ip_tracker[src_ip]
        while iq and iq[0] < cutoff:
            iq.popleft()
        if len(iq) >= MOBILE_IP_RATE_MAX:
            return 429, {"status": "error", "message": "Too many requests."}
        iq.append(now)

    # Verify credentials
    import hashlib as _hl
    pwd_hash = _hl.sha256(password.encode()).hexdigest()
    user     = user_db.get(email)
    success  = user is not None and user.get("password_hash") == pwd_hash

    # Tarpit delay if flagged
    delay = tarpit_delay_fn(src_ip)
    if delay:
        time.sleep(delay)

    entry = {
        "ts":        now,
        "src":       src_ip,
        "device_id": device_id,
        "app_ver":   app_ver,
        "platform":  platform,
        "email":     email,
        "success":   success,
    }
    with _mobile_lock:
        MOBILE_ATTEMPTS.append(entry)
        if len(MOBILE_ATTEMPTS) > 500:
            MOBILE_ATTEMPTS.pop(0)

    if success:
        token = secrets.token_hex(24)
        return 200, {
            "status":       "success",
            "access_token": token,
            "token_type":   "Bearer",
            "expires_in":   3600,
        }
    else:
        return 401, {"status": "fail", "message": "Invalid credentials"}


# ═════════════════════════════════════════════════════════════
#  PASSWORD RESET — POST /reset-password
#
#  Teaching point: a "leaky" endpoint that returns different
#  HTTP status codes or body messages for "found" vs "not found"
#  lets attackers pre-filter a million-entry breach dump to only
#  accounts that exist on this service — improving hit rate 10-100x.
#
#  The secure endpoint always returns the same response regardless
#  of whether the email was found, making pre-filtering impossible.
# ═════════════════════════════════════════════════════════════

_reset_probe_tracker: dict = defaultdict(deque)   # ip → deque[ts]
_reset_lock    = threading.Lock()
RESET_PROBES: list = []

RESET_RATE_MAX    = 20
RESET_RATE_WINDOW = 60


def handle_reset_password(src_ip: str, body: bytes,
                           user_db: dict, leaky_mode: bool) -> tuple:
    """
    Handle POST /reset-password.

    leaky_mode=False (default): uniform response regardless of account existence.
    leaky_mode=True  (--leaky-reset): reveals whether account exists.

    Returns (http_status_code, response_dict).
    """
    try:
        data = json.loads(body)
    except Exception:
        return 400, {"status": "error", "message": "invalid JSON"}

    email = data.get("email", "").lower().strip()
    now   = time.time()

    # Rate limit probes
    with _reset_lock:
        dq = _reset_probe_tracker[src_ip]
        cutoff = now - RESET_RATE_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= RESET_RATE_MAX:
            return 429, {"status": "error", "message": "Too many requests."}
        dq.append(now)

    found = email in KNOWN_EMAILS or email in user_db

    entry = {
        "ts":    now,
        "src":   src_ip,
        "email": email,
        "found": found,
    }
    with _reset_lock:
        RESET_PROBES.append(entry)
        if len(RESET_PROBES) > 1000:
            RESET_PROBES.pop(0)

    if leaky_mode:
        if found:
            return 200, {
                "status":  "success",
                "message": "Password reset link sent to your email.",
            }
        else:
            return 404, {
                "status":  "not_found",
                "message": "No account found with that email address.",
            }
    else:
        # Uniform response — indistinguishable whether account exists or not
        # Timing-safe: always sleep a fixed small amount to prevent timing oracle
        time.sleep(0.05)
        return 200, {
            "status":  "success",
            "message": (
                "If an account exists for that email, "
                "a reset link has been sent."
            ),
        }


# ═════════════════════════════════════════════════════════════
#  OAUTH 2.0 TOKEN FLOW  — /oauth/authorize, /oauth/token, /oauth/revoke
#
#  Teaching point: after a successful credential-stuffing hit, an
#  attacker registers a malicious OAuth app and plants a refresh token.
#  This provides persistent access that survives a password reset
#  (the victim resets their password, but the attacker's refresh token
#  is still valid until explicitly revoked).
#
#  csrf_oauth_sim.py in the same repo has the full CSRF+OAuth attack
#  simulation; these endpoints provide the victim-side server.
# ═════════════════════════════════════════════════════════════

_auth_codes:     dict = {}   # code → {email, client_id, issued_at}
_access_tokens:  dict = {}   # token → {email, client_id, issued_at, expires}
_refresh_tokens: dict = {}   # token → {email, client_id, issued_at, device_ip}
_revoked_tokens: set = set()
_oauth_lock      = threading.Lock()

OAUTH_CODE_TTL    = 600    # auth code valid 10 min
OAUTH_ACCESS_TTL  = 3600   # access token valid 1 hour
OAUTH_ABUSE_LOG: list = []  # suspicious OAuth events


def _oauth_check_abuse(event_type: str, detail: str, src_ip: str):
    """Log and alert on suspicious OAuth events."""
    entry = {
        "ts":         time.time(),
        "type":       event_type,
        "src":        src_ip,
        "detail":     detail,
    }
    OAUTH_ABUSE_LOG.append(entry)
    if len(OAUTH_ABUSE_LOG) > 200:
        OAUTH_ABUSE_LOG.pop(0)
    _alert(
        "OAuth/Abuse", "HIGH",
        f"SUSPICIOUS OAUTH EVENT: {event_type}\n"
        f"  Source: {src_ip}\n"
        f"  Detail: {detail}\n"
        f"  MITRE: T1550.001 (Use Alternate Auth Material: App Access Token)"
    )


def handle_oauth_authorize(src_ip: str, body: bytes) -> tuple:
    """
    POST /oauth/authorize — issue an authorization code.

    Expected body: {client_id, redirect_uri, email, password}
    (simplified: password is used to verify the user is logged in)
    """
    try:
        data = json.loads(body)
    except Exception:
        return 400, {"error": "invalid_request"}

    client_id    = data.get("client_id", "")
    redirect_uri = data.get("redirect_uri", "")
    email        = data.get("email", "").lower()

    if not client_id or not email:
        return 400, {"error": "invalid_request", "error_description": "client_id and email required"}

    # Detect suspicious OAuth app registrations (unknown client IDs)
    known_clients = {"angelware_lab_client", "test_client"}
    if client_id not in known_clients:
        _oauth_check_abuse(
            "UNKNOWN_CLIENT_REGISTRATION",
            f"client_id='{client_id}' from {src_ip} for {email} — "
            f"attacker may be planting a malicious OAuth app post-ATO",
            src_ip,
        )

    code = secrets.token_urlsafe(24)
    with _oauth_lock:
        _auth_codes[code] = {
            "email":      email,
            "client_id":  client_id,
            "issued_at":  time.time(),
            "src_ip":     src_ip,
        }

    return 200, {
        "code":         code,
        "redirect_uri": redirect_uri,
        "state":        data.get("state", ""),
    }


def handle_oauth_token(src_ip: str, body: bytes) -> tuple:
    """
    POST /oauth/token — exchange auth code or refresh token.

    grant_type=authorization_code: exchange code for tokens.
    grant_type=refresh_token:       refresh access token.
    """
    try:
        data = json.loads(body)
    except Exception:
        return 400, {"error": "invalid_request"}

    grant_type = data.get("grant_type", "")

    if grant_type == "authorization_code":
        code = data.get("code", "")
        with _oauth_lock:
            code_data = _auth_codes.pop(code, None)

        if not code_data:
            return 400, {"error": "invalid_grant", "error_description": "Unknown or expired code"}

        if time.time() - code_data["issued_at"] > OAUTH_CODE_TTL:
            return 400, {"error": "invalid_grant", "error_description": "Code expired"}

        access_token  = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        now = time.time()

        with _oauth_lock:
            _access_tokens[access_token] = {
                "email":     code_data["email"],
                "client_id": code_data["client_id"],
                "issued_at": now,
                "expires":   now + OAUTH_ACCESS_TTL,
                "src_ip":    src_ip,
            }
            _refresh_tokens[refresh_token] = {
                "email":     code_data["email"],
                "client_id": code_data["client_id"],
                "issued_at": now,
                "device_ip": src_ip,
            }

        # Detect if attacker's IP differs from code-issuer IP
        if src_ip != code_data["src_ip"]:
            _oauth_check_abuse(
                "TOKEN_EXCHANGE_IP_MISMATCH",
                f"Code issued at {code_data['src_ip']} but exchanged from {src_ip} "
                f"— possible token-interception after ATO",
                src_ip,
            )

        return 200, {
            "access_token":  access_token,
            "refresh_token": refresh_token,
            "token_type":    "Bearer",
            "expires_in":    OAUTH_ACCESS_TTL,
        }

    elif grant_type == "refresh_token":
        token = data.get("refresh_token", "")
        with _oauth_lock:
            rt_data = _refresh_tokens.get(token)

        if not rt_data or token in _revoked_tokens:
            return 400, {"error": "invalid_grant"}

        # Detect refresh from a different IP than issuance
        if src_ip != rt_data["device_ip"]:
            age_h = (time.time() - rt_data["issued_at"]) / 3600
            _oauth_check_abuse(
                "REFRESH_TOKEN_ASN_SHIFT",
                f"Token issued at {rt_data['device_ip']} refreshed from {src_ip} "
                f"({age_h:.1f}h later) — attacker using planted refresh token "
                f"from a different network after victim password-reset",
                src_ip,
            )

        new_access = secrets.token_urlsafe(32)
        with _oauth_lock:
            _access_tokens[new_access] = {
                "email":     rt_data["email"],
                "client_id": rt_data["client_id"],
                "issued_at": time.time(),
                "expires":   time.time() + OAUTH_ACCESS_TTL,
                "src_ip":    src_ip,
            }

        return 200, {
            "access_token": new_access,
            "token_type":   "Bearer",
            "expires_in":   OAUTH_ACCESS_TTL,
        }

    else:
        return 400, {"error": "unsupported_grant_type"}


def handle_oauth_revoke(src_ip: str, body: bytes) -> tuple:
    """POST /oauth/revoke — revoke an access or refresh token."""
    try:
        data = json.loads(body)
    except Exception:
        return 400, {"error": "invalid_request"}

    token = data.get("token", "")
    if not token:
        return 400, {"error": "invalid_request", "error_description": "token required"}

    with _oauth_lock:
        _revoked_tokens.add(token)
        _access_tokens.pop(token, None)
        _refresh_tokens.pop(token, None)

    return 200, {"status": "revoked"}


# ═════════════════════════════════════════════════════════════
#  SESSION CHAINING DETECTOR
#
#  Teaching point: after a successful credential-stuffing hit,
#  automated tools immediately chain API calls (profile scrape,
#  initiate transfer, change email/phone) within the same second.
#  A human would spend several seconds reading the dashboard.
#  Session chaining fires if ≥ SESSION_CHAIN_CALLS API calls
#  arrive from the same session within SESSION_CHAIN_WINDOW seconds
#  of a successful login.
# ═════════════════════════════════════════════════════════════

_session_logins: dict  = {}   # ip → login_ts
_session_calls:  dict  = defaultdict(list)  # ip → [call_ts, ...]
_session_lock    = threading.Lock()

SESSION_CHAIN_CALLS  = 3    # suspicious if ≥ N API calls...
SESSION_CHAIN_WINDOW = 5.0  # ...within N seconds of login


def record_successful_login(ip: str):
    """Call this from fake_portal.py when a login succeeds."""
    with _session_lock:
        _session_logins[ip] = time.time()
        _session_calls[ip]  = []


def record_api_call(ip: str, endpoint: str):
    """Call this from fake_portal.py on any authenticated API endpoint."""
    now = time.time()
    with _session_lock:
        login_ts = _session_logins.get(ip)
        if not login_ts:
            return
        if now - login_ts > SESSION_CHAIN_WINDOW * 10:
            # Too old — stop tracking
            _session_logins.pop(ip, None)
            _session_calls.pop(ip, None)
            return
        _session_calls[ip].append((now, endpoint))
        recent = [t for t, _ in _session_calls[ip] if now - t <= SESSION_CHAIN_WINDOW]
        if len(recent) >= SESSION_CHAIN_CALLS:
            endpoints = [ep for _, ep in _session_calls[ip][-SESSION_CHAIN_CALLS:]]
            _alert(
                "SessionChaining/PostATO", "HIGH",
                f"SESSION CHAINING DETECTED: {ip}\n"
                f"  {len(recent)} API calls within {SESSION_CHAIN_WINDOW}s of login\n"
                f"  Endpoints: {endpoints}\n"
                f"  Pattern: automated post-ATO action sequence.\n"
                f"  Human users read the page before clicking — bots chain immediately.\n"
                f"  MITRE: T1078 (Valid Accounts), T1185 (Browser Session Hijacking)"
            )
            # Stop alerting repeatedly for this session
            _session_logins.pop(ip, None)
            _session_calls.pop(ip, None)


# ═════════════════════════════════════════════════════════════
#  EXTENSION STATS  — consumed by /stats/extensions
# ═════════════════════════════════════════════════════════════

def get_extension_stats() -> dict:
    """Return a stats dict for GET /stats/extensions."""
    now = time.time()

    # Engine 9 summary
    with _e9_lock:
        e9_recent = {
            ip: scores[-1]
            for ip, scores in _e9_scores_by_ip.items()
            if scores
        }
    e9_bots = sum(1 for _, score, cls in e9_recent.values() if cls == "BOT")
    e9_suspects = sum(1 for _, score, cls in e9_recent.values() if cls == "SUSPECT")

    # Mobile API summary
    with _mobile_lock:
        mobile_devices = len(_mobile_device_tracker)
        mobile_ips     = len(_mobile_ip_tracker)
        mobile_recent  = len([a for a in MOBILE_ATTEMPTS if now - a["ts"] < 300])

    # Reset probe summary
    with _reset_lock:
        reset_recent    = [p for p in RESET_PROBES if now - p["ts"] < 300]
        reset_not_found = sum(1 for p in reset_recent if not p["found"])
        reset_found     = sum(1 for p in reset_recent if p["found"])
        reset_by_ip     = defaultdict(int)
        for p in reset_recent:
            reset_by_ip[p["src"]] += 1
        top_reset_ip = max(reset_by_ip, key=reset_by_ip.get) if reset_by_ip else None

    # OAuth summary
    with _oauth_lock:
        active_tokens   = len(_access_tokens)
        refresh_count   = len(_refresh_tokens)
        revoked_count   = len(_revoked_tokens)
        abuse_count     = len(OAUTH_ABUSE_LOG)

    return {
        "engine9": {
            "ips_scored":   len(e9_recent),
            "bots_detected": e9_bots,
            "suspects":      e9_suspects,
            "recent_scores": {
                ip: {"score": score, "classification": cls}
                for ip, (_, score, cls) in list(e9_recent.items())[-20:]
            },
        },
        "mobile_rate_limiter": {
            "unique_device_ids":  mobile_devices,
            "unique_src_ips":     mobile_ips,
            "attempts_last_5min": mobile_recent,
        },
        "reset_enumeration": {
            "probes_last_5min":   len(reset_recent),
            "found_count":        reset_found,
            "not_found_count":    reset_not_found,
            "top_probe_ip":       top_reset_ip,
            "probes_by_ip":       dict(reset_by_ip),
        },
        "oauth_token_abuse": {
            "active_access_tokens":  active_tokens,
            "active_refresh_tokens": refresh_count,
            "revoked_tokens":        revoked_count,
            "abuse_events":          abuse_count,
            "recent_abuse":          OAUTH_ABUSE_LOG[-10:],
        },
    }
