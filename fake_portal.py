"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Dummy Login Portal (Credential Stuffing Target)
 Run on victim VM: sudo python3 fake_portal.py
 Environment: ISOLATED VM LAB ONLY
====================================================

A minimal Flask web app that acts as the credential stuffing
target for the lab. The IDS behavioral engine monitors POST
requests to /login to detect stuffing via CV-based timing analysis.

TARPIT INTEGRATION:
  When ids_detector.py Engine 2 flags an IP (CV < 0.15),
  it writes that IP to tarpit_state.json. This portal
  reads that file on every /login request:

  Flagged IP  -> response delayed by 8 +/- 2 seconds
  Normal IP   -> response in <200ms (unchanged)

GRAPH 3 DETECTION PROXY:
  collect_graph23_data.py uses GET /tarpit/status to measure
  whether the IDS fired during a jitter-level sweep.
    total_delayed     -- increments when a /login response is delayed
    total_flag_events -- increments the instant tarpit_state.flag()
                         is called (race-condition-free)

ORIGINAL DEFENSES:
  1.  Unknown-account tracking
  2.  Per-username rate limiting
  3.  IP reputation scoring (ip_reputation.py)
  4.  Progressive CAPTCHA (math challenge)
  5.  Hard block (429) after tarpit + persistence
  6.  Breach credential detection (HIBP simulation)
  7.  /stats/advanced endpoint (consumed by IDS Engine 5)
  8.  Sec-Fetch / browser security header scoring
  9.  Email clustering tracking (username_clustering.py)
  10. Risk-based step-up 2FA via TOTP (totp_2fa.py)

NEW DEFENSES (fake_portal_extensions.py):
  11. Engine 9: Browser automation artifact detection on every /login
  12. CSRF token on /login GET + verified on POST
  13. POST /reset-password — secure (uniform) or leaky (--leaky-reset) demo
  14. POST /api/mobile/login — dedicated mobile endpoint with Device-ID
      rate limiting; demonstrates the mobile API blind-spot
  15. GET/POST /oauth/* — OAuth 2.0 flow + token abuse detection
  16. Session chaining detector (immediate API calls post-login)
  17. Extended /stats/advanced fields for all new signals

ENDPOINTS:
  GET  /                    Login form
  GET  /login               Login form
  POST /login               Credential attempt (all defenses apply)
  GET  /attempts            Full attempt log + tarpit summary
  POST /attempts/reset      Clear log between test runs
  GET  /tarpit/status       Race-free flag counter for Graph 3
  POST /tarpit/flag         Manual flag an IP
  POST /tarpit/unflag       Manual unflag an IP
  GET  /stats/advanced      All IDS Engine 5 signals
  GET  /2fa/status          Step-up 2FA enrolment admin
  GET  /clustering/status   Username clustering analysis admin
  POST /reset-password      Password reset (secure/leaky demo)
  POST /api/mobile/login    Mobile API endpoint
  GET  /oauth/authorize     OAuth authorization code
  POST /oauth/token         OAuth token exchange / refresh
  POST /oauth/revoke        Token revocation
  GET  /stats/extensions    New-module stats (Engine 9, OAuth, etc.)
"""

import time
import json
import random
import logging
import threading
from datetime import datetime
from collections import defaultdict, deque
from flask import Flask, request, jsonify, render_template_string

# ── Tarpit integration ────────────────────────────────────────
try:
    import tarpit_state
    TARPIT_ENABLED = True
except ImportError:
    TARPIT_ENABLED = False
    print("[PORTAL] WARNING: tarpit_state.py not found -- tarpit disabled")

# ── IP reputation scoring ─────────────────────────────────────
try:
    import ip_reputation
    REPUTATION_ENABLED = True
except ImportError:
    REPUTATION_ENABLED = False
    print("[PORTAL] WARNING: ip_reputation.py not found -- scoring disabled")

# ── Step-up 2FA via TOTP ──────────────────────────────────────
try:
    import totp_2fa
    TOTP_ENABLED = True
    _totp_mgr    = totp_2fa.get_manager()
    print("[PORTAL] Step-up 2FA: ENABLED (totp_2fa.py)")
except ImportError:
    TOTP_ENABLED = False
    _totp_mgr    = None
    print("[PORTAL] INFO: totp_2fa.py not found -- step-up 2FA disabled")

# ── Email clustering tracking ─────────────────────────────────
try:
    import username_clustering as _uc_module
    CLUSTERING_ENABLED = True
    _email_tracker     = _uc_module.get_tracker()
    print("[PORTAL] Username clustering: ENABLED (username_clustering.py)")
except ImportError:
    CLUSTERING_ENABLED = False
    _email_tracker     = None
    print("[PORTAL] INFO: username_clustering.py not found -- clustering disabled")

# ── New extensions (Engine 9, CSRF, mobile, OAuth, etc.) ─────
try:
    from fake_portal_extensions import (
        engine9_score,
        set_alert_callback    as _ext_set_alert,
        handle_mobile_login   as _ext_mobile_login,
        handle_reset_password as _ext_reset_password,
        handle_oauth_authorize as _ext_oauth_authorize,
        handle_oauth_token    as _ext_oauth_token,
        handle_oauth_revoke   as _ext_oauth_revoke,
        get_extension_stats   as _ext_stats,
        csrf_protection       as _csrf,
        KNOWN_EMAILS          as _ext_known_emails,
    )
    EXTENSIONS_ENABLED = True
    print("[PORTAL] Extensions: ENABLED (fake_portal_extensions.py)")
    print("[PORTAL]   Engine 9 (browser automation), CSRF, mobile API,")
    print("[PORTAL]   /reset-password, /oauth/*, session chaining")
except ImportError as _ext_err:
    EXTENSIONS_ENABLED = False
    print(f"[PORTAL] INFO: fake_portal_extensions.py not found -- "
          f"new defenses disabled ({_ext_err})")

    # Stub functions so routes below don't need if-guards
    def engine9_score(h, ip):          return {"score": 0, "signals": [], "classification": "CLEAN"}
    def _ext_set_alert(fn):            pass
    def _ext_mobile_login(*a, **kw):   return 501, {"status": "error", "message": "extensions not loaded"}
    def _ext_reset_password(*a, **kw): return 501, {"status": "error", "message": "extensions not loaded"}
    def _ext_oauth_authorize(*a, **kw):return 501, {"error": "not_implemented"}
    def _ext_oauth_token(*a, **kw):    return 501, {"error": "not_implemented"}
    def _ext_oauth_revoke(*a, **kw):   return 501, {"error": "not_implemented"}
    def _ext_stats():                  return {}
    class _csrf:
        @staticmethod
        def generate(s):               return ""
        @staticmethod
        def verify(s, a, b):           return True, ""
        @staticmethod
        def html_field(t):             return ""
        @staticmethod
        def cookie_header(t):          return ""
    _ext_known_emails = set()


app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="[PORTAL %(asctime)s] %(message)s",
    datefmt="%H:%M:%S"
)

# ── Fake user database ────────────────────────────────────────
USERS = {
    "alice@example.com":  "correct_password_1",
    "bob@example.com":    "correct_password_2",
    "admin@example.com":  "securePass123!",
}

# Populate extension's known-email set for secure reset endpoint
_ext_known_emails.update(USERS.keys())

# ── Pre-enrol fake users in 2FA ───────────────────────────────
if TOTP_ENABLED:
    for _u in USERS:
        _sec = _totp_mgr.enrol(_u)
        print(f"[PORTAL]  2FA enrolled: {_u}  "
              f"({_totp_mgr.get_uri(_u, 'MyApp')[:72]}...)")

# ── Known-breached password list (HIBP simulation, 35 entries) ─
BREACHED_PASSWORDS = {
    "password", "password123", "123456", "12345678", "qwerty",
    "abc123", "monkey", "1234567", "letmein", "trustno1",
    "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123",
    "654321", "superman", "qazwsx", "michael", "football",
    "password1", "admin", "admin123", "root", "toor",
    "test", "test123", "user", "guest", "welcome",
}

# ── Attempt log (in-memory) ───────────────────────────────────
attempt_log  = []
tarpit_stats = {
    "total_delayed":       0,
    "total_delay_seconds": 0.0,
    "total_flag_events":   0,
}
_stats_lock = threading.Lock()

# ── Per-username rate limiting ────────────────────────────────
USERNAME_RATE_WINDOW = 60
USERNAME_RATE_MAX    = 5
_username_attempts: dict = defaultdict(lambda: deque())
_username_lock = threading.Lock()

# ── Progressive CAPTCHA state ─────────────────────────────────
CAPTCHA_FAIL_THRESHOLD = 3
CAPTCHA_TTL            = 120
_captcha_state: dict = {}
_captcha_lock = threading.Lock()

# ── Hard block escalation ─────────────────────────────────────
N_BEFORE_BLOCK     = 10
_post_tarpit_fails = defaultdict(int)

# ── Unknown account tracking ──────────────────────────────────
_unknown_acct_counts: dict = defaultdict(int)
_unknown_acct_total        = 0

# ── Off-hours tracking ────────────────────────────────────────
_hourly_counts: dict = defaultdict(int)

# ── Reputation snapshot ───────────────────────────────────────
_rep_scores: dict = {}

# ── Breach credential hit counter ────────────────────────────
_breached_cred_hits = 0

# ── Step-up 2FA reputation threshold ─────────────────────────
TWOFACTOR_SCORE_THRESHOLD = 25

# ── Leaky reset mode flag (set via --leaky-reset CLI arg) ─────
_LEAKY_RESET_MODE = False


# ── HTML pages ────────────────────────────────────────────────

LOGIN_PAGE_TMPL = """
<!DOCTYPE html>
<html>
<head><title>MyApp Login</title>
<style>
  body {{ font-family: Arial; max-width: 400px; margin: 100px auto; }}
  input {{ width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }}
  button {{ width: 100%; padding: 10px; background: #2980B9; color: white;
            border: none; cursor: pointer; }}
  .note {{ font-size: 11px; color: #888; margin-top: 12px; }}
</style>
</head>
<body>
  <h2>Login to MyApp</h2>
  <form method="POST" action="/login">
    <input type="email"    name="email"    placeholder="Email"    required>
    <input type="password" name="password" placeholder="Password" required>
    {csrf_field}
    <button type="submit">Login</button>
  </form>
  <p class="note">AUA CS 232/337 Lab Portal — isolated environment</p>
</body>
</html>
"""


# ── Helpers ───────────────────────────────────────────────────

def _make_captcha() -> dict:
    a  = random.randint(2, 20)
    b  = random.randint(2, 20)
    op = random.choice(["+", "-", "*"])
    answer = a + b if op == "+" else (a - b if op == "-" else a * b)
    return {"question": f"What is {a} {op} {b}?", "answer": answer}


def _check_username_rate_limit(email: str) -> bool:
    """Returns True if this email is rate-limited (should block)."""
    now    = time.time()
    cutoff = now - USERNAME_RATE_WINDOW
    with _username_lock:
        dq = _username_attempts[email]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= USERNAME_RATE_MAX:
            return True
        dq.append(now)
        return False


def _apply_sec_fetch_check(headers: dict, rep_score: int) -> tuple:
    """
    Returns (effective_score, sec_fetch_info_dict).
    Adds Sec-Fetch header anomaly penalty on top of ip_reputation
    score, used as input to risk-based 2FA gate.
    """
    if REPUTATION_ENABLED:
        try:
            info = ip_reputation.check_sec_fetch_headers(headers)
        except AttributeError:
            info = {"score_penalty": 0, "reasons": [],
                    "missing_sec_fetch": False, "missing_sec_ch_ua": False,
                    "missing_origin": False}
    else:
        ua       = headers.get("User-Agent", "")
        has_sec  = any(k.startswith("Sec-Fetch-") for k in headers)
        is_chrome = "Chrome" in ua or "Chromium" in ua
        has_ch_ua = "Sec-Ch-Ua" in headers or "sec-ch-ua" in headers
        penalty   = (
            (15 if not has_sec else 0) +
            (10 if is_chrome and not has_ch_ua else 0) +
            (10 if not (headers.get("Origin") or headers.get("Referer")) and ua else 0)
        )
        info = {
            "score_penalty":     penalty,
            "reasons":           [],
            "missing_sec_fetch": not has_sec,
            "missing_sec_ch_ua": is_chrome and not has_ch_ua,
            "missing_origin":    False,
        }

    if info["score_penalty"] >= 25:
        logging.warning(
            f"SEC-FETCH-ANOMALY | penalty={info['score_penalty']} | "
            f"{info.get('reasons', [])}"
        )
    return min(100, rep_score + info["score_penalty"]), info


def _step_up_2fa(email: str, src_ip: str,
                  effective_rep_score: int,
                  form_data: dict):
    """
    Risk-based step-up 2FA gate.

    Returns (blocked: bool, flask_response_tuple | None).
      blocked=True  -- return the response immediately
      blocked=False -- continue to credential check

    Policy (from totp_2fa.requires_2fa):
      CLEAN (score < 25)      -- no 2FA
      SUSPECT (25-49)         -- TOTP required for new sessions
      LIKELY_BOT (50-74)      -- TOTP required always
      BOT (75+)               -- handled silently by N_BEFORE_BLOCK;
                                 do not reveal detection via 2FA hint
    """
    if not TOTP_ENABLED:
        return False, None

    if effective_rep_score < 25:
        band = "CLEAN"
    elif effective_rep_score < 50:
        band = "SUSPECT"
    elif effective_rep_score < 75:
        band = "LIKELY_BOT"
    else:
        return False, None   # BOT band: let hard-block handle it

    policy = totp_2fa.requires_2fa(band, session_is_new=True)
    if policy == "none":
        return False, None

    totp_code = (
        form_data.get("totp_code") or
        form_data.get("otp") or
        form_data.get("mfa_code")
    )

    if totp_code is None:
        return True, (jsonify({
            "status":   "2fa_required",
            "message":  (
                "Step-up authentication required for this session. "
                "Submit your 6-digit authenticator code in field 'totp_code'."
            ),
            "trigger":  band,
            "enrolled": _totp_mgr.is_enrolled(email or ""),
        }), 403)

    if not _totp_mgr.is_enrolled(email or ""):
        if email:
            sec     = _totp_mgr.enrol(email)
            current = totp_2fa.get_totp(sec)
            logging.warning(
                f"2FA-AUTO-ENROL | {email} | current code: {current} "
                f"(lab demo -- store secret at signup in production)"
            )
        return False, None

    ok, msg = _totp_mgr.verify(email, totp_code, src_ip=src_ip)
    if ok:
        logging.info(f"2FA-OK  | src={src_ip} email={email}")
        return False, None

    logging.warning(f"2FA-FAIL | src={src_ip} email={email} | {msg}")
    return True, (jsonify({"status": "2fa_failed", "message": msg}), 403)


def _portal_alert(engine: str, severity: str, msg: str):
    """
    Internal alert callback: logs to portal stdout.
    Passed to fake_portal_extensions so new detectors can
    emit alerts through the same channel.
    """
    ts = datetime.now().strftime("%H:%M:%S")
    logging.warning(f"ALERT [{severity}] {engine} @ {ts} — {msg.splitlines()[0]}")


# Wire alert callback into extensions
_ext_set_alert(_portal_alert)


# ══════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return _render_login_page()


@app.route("/login", methods=["GET", "POST"])
def login():
    global _unknown_acct_total, _breached_cred_hits

    if request.method == "GET":
        return _render_login_page()

    # ── Parse request body ────────────────────────────────────
    if request.is_json:
        data           = request.get_json() or {}
        email          = data.get("email", "")
        password       = data.get("password", "")
        captcha_answer = data.get("captcha_answer")
        csrf_form      = data.get("csrf_token", "")
    else:
        data           = request.form.to_dict()
        email          = request.form.get("email", "")
        password       = request.form.get("password", "")
        captcha_answer = request.form.get("captcha_answer")
        csrf_form      = request.form.get("csrf_token", "")

    timestamp = time.time()
    src_ip    = request.remote_addr
    headers   = dict(request.headers)
    hour      = datetime.now().hour

    # ── CSRF verification (new) ───────────────────────────────
    # Skip for JSON API callers (bots / cred_stuffing.py) which
    # have no session — this mirrors real portal behaviour where
    # machine-to-machine clients use API tokens, not CSRF tokens.
    # HTML form submissions (from a browser GET) must supply it.
    if not request.is_json and EXTENSIONS_ENABLED:
        csrf_cookie = request.cookies.get("csrf_token", "")
        session_id  = src_ip   # simplified: use IP as session proxy in lab
        ok, err     = _csrf.verify(session_id, csrf_form, csrf_cookie)
        if not ok and csrf_form:
            # Only hard-reject if a token was supplied but is wrong.
            # Missing token (e.g. bot with no cookie jar) falls through
            # and is caught by Engine 9 + IP reputation instead.
            logging.warning(f"CSRF-FAIL | src={src_ip} | {err}")
            return jsonify({"status": "error", "message": "Session expired. Please reload."}), 403

    # ── Off-hours tracking ────────────────────────────────────
    with _stats_lock:
        _hourly_counts[hour] += 1

    # ── IP reputation scoring ─────────────────────────────────
    rep = {}
    if REPUTATION_ENABLED:
        rep = ip_reputation.score_request(src_ip, headers)
        with _stats_lock:
            _rep_scores[src_ip] = rep

    # ── Sec-Fetch anomaly check → effective reputation score ──
    rep_score_raw          = rep.get("score", 0) if REPUTATION_ENABLED else 0
    effective_rep, sf_info = _apply_sec_fetch_check(headers, rep_score_raw)

    # ── Engine 9: browser automation artifact detection (new) ─
    if EXTENSIONS_ENABLED:
        _lc_headers = {k.lower(): v for k, v in headers.items()}
        e9_result   = engine9_score(_lc_headers, src_ip)
        if e9_result["score"] > 0:
            logging.info(
                f"ENGINE9 | src={src_ip} | score={e9_result['score']} | "
                f"class={e9_result['classification']} | "
                f"signals={len(e9_result['signals'])}"
            )

    # ── Email clustering tracking ─────────────────────────────
    if CLUSTERING_ENABLED and email and _email_tracker:
        _email_tracker.add(email)

    # ── Per-username rate limiting ────────────────────────────
    if email and _check_username_rate_limit(email):
        logging.warning(
            f"RATE-LIMITED | src={src_ip} | email={email} | "
            f">{USERNAME_RATE_MAX} attempts in {USERNAME_RATE_WINDOW}s"
        )
        return jsonify({
            "status":  "error",
            "message": "Too many login attempts for this account. Try again later.",
        }), 429

    # ── Step-up 2FA check ─────────────────────────────────────
    if TOTP_ENABLED and email:
        _blocked, _2fa_resp = _step_up_2fa(email, src_ip, effective_rep, data)
        if _blocked:
            return _2fa_resp

    # ── Unknown account detection ─────────────────────────────
    email_known = email in USERS
    if not email_known:
        with _stats_lock:
            _unknown_acct_counts[src_ip] += 1
            _unknown_acct_total          += 1

    # ── Breach credential detection ───────────────────────────
    is_breached = password in BREACHED_PASSWORDS
    if is_breached:
        with _stats_lock:
            _breached_cred_hits += 1
        logging.warning(
            f"BREACHED-CRED | src={src_ip} | email={email} | "
            f"password in HIBP simulation list"
        )

    # ── Progressive CAPTCHA ───────────────────────────────────
    with _captcha_lock:
        state = _captcha_state.setdefault(src_ip, {
            "fails": 0, "challenge": None,
            "issued_at": 0, "solved": False
        })
        needs_challenge = (
            state["fails"] >= CAPTCHA_FAIL_THRESHOLD
            and not state["solved"]
        )
        if needs_challenge:
            now_c = time.time()
            if state["challenge"] is None or now_c - state["issued_at"] > CAPTCHA_TTL:
                state["challenge"] = _make_captcha()
                state["issued_at"] = now_c
            expected = state["challenge"]["answer"]
            if captcha_answer is None:
                return jsonify({
                    "status":           "captcha_required",
                    "captcha_question": state["challenge"]["question"],
                    "message": (
                        "Security check required. "
                        "Submit 'captcha_answer' with your next login request."
                    ),
                }), 403
            try:
                submitted = int(captcha_answer)
            except (TypeError, ValueError):
                submitted = None
            if submitted == expected:
                state["solved"] = True
                logging.info(f"CAPTCHA SOLVED | src={src_ip}")
            else:
                return jsonify({
                    "status":  "captcha_failed",
                    "message": "Incorrect security answer.",
                }), 403

    # ── Hard block after tarpit + persistence ─────────────────
    already_tarpitted = TARPIT_ENABLED and tarpit_state.is_flagged(src_ip)
    if already_tarpitted:
        _post_tarpit_fails[src_ip] += 1
        if _post_tarpit_fails[src_ip] >= N_BEFORE_BLOCK:
            logging.warning(
                f"HARD-BLOCK | src={src_ip} | "
                f"{_post_tarpit_fails[src_ip]} attempts after tarpit detection"
            )
            return jsonify({"status": "error", "message": "Too many requests."}), 429

    # ── Check credentials ─────────────────────────────────────
    success = USERS.get(email) == password

    # ── Tarpit delay ──────────────────────────────────────────
    tarpitted      = False
    tarpit_delay_s = 0.0

    if TARPIT_ENABLED and tarpit_state.is_flagged(src_ip):
        tarpit_delay_s = tarpit_state.tarpit_delay()
        tarpitted      = True
        logging.warning(
            f"TARPIT  | src={src_ip} | delaying {tarpit_delay_s:.1f}s "
            f"(bot detected by IDS Engine 2)"
        )
        time.sleep(tarpit_delay_s)
        with _stats_lock:
            tarpit_stats["total_delayed"]       += 1
            tarpit_stats["total_delay_seconds"] += tarpit_delay_s
    else:
        time.sleep(0.1)

    # ── Sync flag count from tarpit_state file ────────────────
    if TARPIT_ENABLED:
        try:
            file_count = tarpit_state.get_flag_count()
            with _stats_lock:
                if file_count > tarpit_stats["total_flag_events"]:
                    tarpit_stats["total_flag_events"] = file_count
        except Exception:
            pass

    # ── Update CAPTCHA failure counter ────────────────────────
    if not success:
        with _captcha_lock:
            st = _captcha_state.setdefault(src_ip, {
                "fails": 0, "challenge": None, "issued_at": 0, "solved": False
            })
            st["fails"] += 1
    else:
        with _captcha_lock:
            _captcha_state.pop(src_ip, None)
        _post_tarpit_fails.pop(src_ip, None)

    # ── Log attempt ───────────────────────────────────────────
    entry = {
        "ts":                timestamp,
        "src":               src_ip,
        "email":             email,
        "success":           success,
        "tarpitted":         tarpitted,
        "tarpit_delay":      round(tarpit_delay_s, 2),
        "dt":                datetime.now().isoformat(),
        "email_known":       email_known,
        "is_breached":       is_breached,
        "rep_score":         rep.get("score", 0),
        "rep_band":          rep.get("band", "UNKNOWN"),
        "effective_rep":     effective_rep,
        "fingerprint":       rep.get("fingerprint", ""),
        "sec_fetch_penalty": sf_info.get("score_penalty", 0),
    }
    with _stats_lock:
        attempt_log.append(entry)

    logging.info(
        f"LOGIN   | src={src_ip} | email={email} | "
        f"success={success} | tarpitted={tarpitted} | "
        f"rep={rep.get('band','?')} | eff_rep={effective_rep}"
    )

    if success:
        return jsonify({"status": "success", "message": "Welcome!"})
    else:
        return jsonify({"status": "fail", "message": "Invalid credentials"}), 401


# ── /reset-password (new) ─────────────────────────────────────

@app.route("/reset-password", methods=["POST"])
def reset_password():
    """
    Password reset endpoint.

    Default: SECURE — uniform response regardless of account existence.
    With _LEAKY_RESET_MODE=True (--leaky-reset flag): reveals existence.

    Teaches: difference between leaky and secure reset implementations,
    and why pre-filtering via reset probing boosts stuffing hit rates.
    IDS EnumerationDetector monitors this endpoint.
    """
    src_ip = request.remote_addr
    body   = request.get_data()
    status, body_dict = _ext_reset_password(
        src_ip=src_ip,
        body=body,
        user_db=USERS,
        leaky_mode=_LEAKY_RESET_MODE,
    )
    return jsonify(body_dict), status


# ── /api/mobile/login (new) ───────────────────────────────────

@app.route("/api/mobile/login", methods=["POST"])
def mobile_login():
    """
    Mobile API login endpoint.

    Teaches: mobile endpoints often lack the JS-based fingerprinting
    and CAPTCHA of web portals. Rate limited per Device-ID (not just IP).
    IDS Engine 2 (CV timing) still applies if requests are logged.
    """
    src_ip = request.remote_addr
    body   = request.get_data()

    # Build a lowercase header dict for extensions
    lc_headers = {k.lower(): v for k, v in request.headers.items()}

    def _tarpit_delay(ip: str) -> float:
        if TARPIT_ENABLED and tarpit_state.is_flagged(ip):
            return tarpit_state.tarpit_delay()
        return 0.0

    # Build a hashed user_db compatible format
    import hashlib as _hl
    hashed_db = {
        email: {"password_hash": _hl.sha256(pwd.encode()).hexdigest()}
        for email, pwd in USERS.items()
    }

    status, body_dict = _ext_mobile_login(
        src_ip=src_ip,
        body=body,
        headers=lc_headers,
        user_db=hashed_db,
        tarpit_delay_fn=_tarpit_delay,
    )
    return jsonify(body_dict), status


# ── /oauth/* (new) ────────────────────────────────────────────

@app.route("/oauth/authorize", methods=["POST"])
def oauth_authorize():
    """
    OAuth 2.0 authorization code endpoint.
    Teaches: post-stuffing token planting and OAuth app farm detection.
    """
    status, body_dict = _ext_oauth_authorize(request.remote_addr, request.get_data())
    return jsonify(body_dict), status


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    """OAuth 2.0 token exchange / refresh endpoint."""
    status, body_dict = _ext_oauth_token(request.remote_addr, request.get_data())
    return jsonify(body_dict), status


@app.route("/oauth/revoke", methods=["POST"])
def oauth_revoke():
    """
    Token revocation endpoint.
    Teaches: why revoking ALL tokens on password change is essential
    to stop an attacker's planted refresh token from persisting.
    """
    status, body_dict = _ext_oauth_revoke(request.remote_addr, request.get_data())
    return jsonify(body_dict), status


# ── /attempts (original) ──────────────────────────────────────

@app.route("/attempts")
def view_attempts():
    with _stats_lock:
        recent         = list(attempt_log[-200:])
        tarpitted_log  = [e for e in attempt_log if e.get("tarpitted")]
        total          = len(attempt_log)
        success_count  = sum(1 for a in attempt_log if a["success"])
        fail_count     = sum(1 for a in attempt_log if not a["success"])
        ts_delayed     = tarpit_stats["total_delayed"]
        ts_delay_sec   = round(tarpit_stats["total_delay_seconds"], 1)
        ts_flag_events = tarpit_stats["total_flag_events"]
        recent_tp      = tarpitted_log[-50:]

    flagged_ips = tarpit_state.list_flagged() if TARPIT_ENABLED else []

    return jsonify({
        "total_attempts": total,
        "recent":         recent,
        "success_count":  success_count,
        "fail_count":     fail_count,
        "tarpit": {
            "enabled":           TARPIT_ENABLED,
            "currently_flagged": flagged_ips,
            "total_delayed":     ts_delayed,
            "total_delay_sec":   ts_delay_sec,
            "total_flag_events": ts_flag_events,
            "recent_tarpitted":  recent_tp,
        },
    })

# ── /stats/advanced (extended) ────────────────────────────────

@app.route("/stats/advanced")
def advanced_stats():
    """
    Extended statistics endpoint consumed by IDS Engine 5.

    Original fields:
      total_attempts, success_rate_pct, unknown_acct_pct,
      off_hours_pct, breached_cred_hits, per_ip_unknowns,
      reputation_scores, captcha_active, hard_blocked_ips,
      hourly_distribution, total_flag_events

    New fields (from extensions):
      username_clustering    — domain/sequential/prefix clustering alerts
      totp_enabled           — whether step-up 2FA is active
      sec_fetch_penalty_avg  — avg Sec-Fetch anomaly penalty (Engine 9 proxy)
      engine9_scores         — per-IP browser automation scores
      mobile_rate_limiter    — device count / IP count
      reset_enumeration      — per-IP reset probe stats
      oauth_token_abuse      — suspicious OAuth grant stats
    """
    with _stats_lock:
        total          = len(attempt_log)
        success_count  = sum(1 for a in attempt_log if a["success"])
        unknown_count  = sum(1 for a in attempt_log if not a.get("email_known", True))
        breached_count = _breached_cred_hits
        off_hours      = sum(
            cnt for h, cnt in _hourly_counts.items() if h < 8 or h >= 22
        )
        total_counted  = sum(_hourly_counts.values())
        per_ip_unknowns = dict(_unknown_acct_counts)
        rep_snap        = dict(_rep_scores)
        hourly_snap     = dict(_hourly_counts)
        ts_flag_events  = tarpit_stats["total_flag_events"]
        recent          = attempt_log[-200:] if attempt_log else []
        sfp_values      = [a.get("sec_fetch_penalty", 0) for a in recent]
        sfp_avg         = round(sum(sfp_values) / max(1, len(sfp_values)), 1)

    with _captcha_lock:
        captcha_active = {
            ip: {
                "fails":    s.get("fails", 0),
                "solved":   s.get("solved", False),
                "question": (s.get("challenge") or {}).get("question", ""),
            }
            for ip, s in _captcha_state.items()
            if s.get("fails", 0) >= CAPTCHA_FAIL_THRESHOLD
        }

    hard_blocked = {
        ip: count for ip, count in _post_tarpit_fails.items()
        if count >= N_BEFORE_BLOCK
    }

    clustering_stats = {}
    if CLUSTERING_ENABLED and _email_tracker:
        clustering_stats = _email_tracker.stats_for_api()

    # Extension stats (Engine 9, mobile, reset, OAuth)
    ext_stats = _ext_stats() if EXTENSIONS_ENABLED else {}

    return jsonify({
        # ── Original fields ───────────────────────────────────
        "total_attempts":        total,
        "success_count":         success_count,
        "fail_count":            total - success_count,
        "success_rate_pct":      round(success_count / max(1, total) * 100, 2),
        "unknown_acct_count":    unknown_count,
        "unknown_acct_pct":      round(unknown_count / max(1, total) * 100, 2),
        "off_hours_count":       off_hours,
        "off_hours_pct":         round(off_hours / max(1, total_counted) * 100, 2),
        "breached_cred_hits":    breached_count,
        "per_ip_unknowns":       per_ip_unknowns,
        "reputation_scores":     rep_snap,
        "captcha_active":        captcha_active,
        "hard_blocked_ips":      hard_blocked,
        "hourly_distribution":   hourly_snap,
        "total_flag_events":     ts_flag_events,
        "tarpit_enabled":        TARPIT_ENABLED,
        "reputation_enabled":    REPUTATION_ENABLED,
        # ── Original new fields (patch 1) ─────────────────────
        "username_clustering":   clustering_stats,
        "totp_enabled":          TOTP_ENABLED,
        "totp_enrolled":         _totp_mgr.status() if TOTP_ENABLED and _totp_mgr else {},
        "sec_fetch_penalty_avg": sfp_avg,
        # ── New extension fields ──────────────────────────────
        "extensions_enabled":    EXTENSIONS_ENABLED,
        "leaky_reset_mode":      _LEAKY_RESET_MODE,
        **ext_stats,
    })


# ── /attempts/reset (original) ────────────────────────────────

@app.route("/attempts/reset", methods=["POST"])
def reset_attempts():
    """
    Reset all in-memory state between test runs.
    Used by collect_graph23_data.py between jitter-level sweeps.
    Optional JSON body: {"clear_tarpit": true}
    """
    global _unknown_acct_total, _breached_cred_hits
    data = request.get_json(silent=True) or {}

    with _stats_lock:
        attempt_log.clear()
        tarpit_stats["total_delayed"]       = 0
        tarpit_stats["total_delay_seconds"] = 0.0
        tarpit_stats["total_flag_events"]   = 0
        _unknown_acct_counts.clear()
        _unknown_acct_total  = 0
        _breached_cred_hits  = 0
        _hourly_counts.clear()
        _rep_scores.clear()

    _post_tarpit_fails.clear()

    with _captcha_lock:
        _captcha_state.clear()
    with _username_lock:
        _username_attempts.clear()

    if REPUTATION_ENABLED:
        ip_reputation.reset_scorer()
    if CLUSTERING_ENABLED and _email_tracker:
        _email_tracker.reset()

    clear_tarpit = data.get("clear_tarpit", False)
    if clear_tarpit and TARPIT_ENABLED:
        tarpit_state.clear_all()
        logging.info("RESET    | attempt log, tarpit stats, and tarpit flags cleared")
    else:
        logging.info("RESET    | attempt log and tarpit stats cleared")

    return jsonify({"status": "reset", "cleared_tarpit": clear_tarpit})


# ── /stats/extensions (new — quick debug) ────────────────────

@app.route("/stats/extensions")
def extension_stats():
    """
    Compact view of just the new-module stats.
    Useful for quickly inspecting Engine 9, OAuth, mobile, reset signals
    without parsing the full /stats/advanced payload.
    """
    return jsonify(_ext_stats() if EXTENSIONS_ENABLED else
                   {"error": "extensions not loaded"})


# ── Tarpit admin endpoints (original) ────────────────────────

@app.route("/tarpit/flag", methods=["POST"])
def tarpit_flag():
    if not TARPIT_ENABLED:
        return jsonify({"error": "tarpit disabled"}), 503
    data = request.get_json() or {}
    ip   = data.get("ip", "")
    if not ip:
        return jsonify({"error": "no ip"}), 400
    tarpit_state.flag(ip)
    with _stats_lock:
        tarpit_stats["total_flag_events"] += 1
    return jsonify({"status": "flagged", "ip": ip})


@app.route("/tarpit/unflag", methods=["POST"])
def tarpit_unflag():
    if not TARPIT_ENABLED:
        return jsonify({"error": "tarpit disabled"}), 503
    data = request.get_json() or {}
    ip   = data.get("ip", "")
    tarpit_state.unflag(ip)
    return jsonify({"status": "unflagged", "ip": ip})


@app.route("/tarpit/status")
def tarpit_status():
    """
    Current tarpit state.
    stats.total_flag_events is the race-free Graph 3 TPR counter —
    it increments the instant tarpit_state.flag() is called by IDS
    Engine 2, before the portal has served any delayed response.
    """
    flagged = tarpit_state.list_flagged() if TARPIT_ENABLED else []

    if TARPIT_ENABLED:
        try:
            file_count = tarpit_state.get_flag_count()
            with _stats_lock:
                if file_count > tarpit_stats["total_flag_events"]:
                    tarpit_stats["total_flag_events"] = file_count
        except Exception:
            pass

    with _stats_lock:
        stats_snapshot = dict(tarpit_stats)

    return jsonify({
        "enabled":   TARPIT_ENABLED,
        "flagged":   flagged,
        "stats":     stats_snapshot,
        "ttl_sec":   tarpit_state.TTL_SECONDS  if TARPIT_ENABLED else None,
        "delay_sec": tarpit_state.TARPIT_DELAY if TARPIT_ENABLED else None,
    })


# ── Admin / debug endpoints (original) ───────────────────────

@app.route("/2fa/status", methods=["GET"])
def twofactor_status():
    """Admin: show 2FA enrolment and policy map."""
    if not TOTP_ENABLED:
        return jsonify({"enabled": False, "message": "totp_2fa.py not loaded"})
    return jsonify({
        "enabled":         True,
        "enrolments":      _totp_mgr.status(),
        "score_threshold": TWOFACTOR_SCORE_THRESHOLD,
        "policy_map":      totp_2fa.TWOFACTOR_POLICY,
    })


@app.route("/clustering/status", methods=["GET"])
def clustering_status():
    """Admin: current username clustering analysis."""
    if not CLUSTERING_ENABLED or not _email_tracker:
        return jsonify({"enabled": False})
    return jsonify({"enabled": True, **_email_tracker.analyze()})


# ── HTML render helper ────────────────────────────────────────

def _render_login_page():
    """
    Serve the login page.
    When EXTENSIONS_ENABLED, embeds a fresh CSRF token as a
    hidden form field and sets the CSRF cookie on the response.
    """
    src_ip     = request.remote_addr
    session_id = src_ip    # simplified: IP as session proxy in lab
    csrf_token = _csrf.generate(session_id) if EXTENSIONS_ENABLED else ""
    csrf_field = _csrf.html_field(csrf_token) if EXTENSIONS_ENABLED else ""
    html       = LOGIN_PAGE_TMPL.format(csrf_field=csrf_field)

    from flask import make_response
    resp = make_response(render_template_string(html))
    if EXTENSIONS_ENABLED and csrf_token:
        resp.headers["Set-Cookie"] = _csrf.cookie_header(csrf_token)
    return resp


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, sys

    parser = argparse.ArgumentParser(
        description="Fake Login Portal — AUA Botnet Research Lab"
    )
    parser.add_argument("--port", type=int, default=80,
                        help="Listening port (default: 80)")
    parser.add_argument("--leaky-reset", action="store_true",
                        help="Make /reset-password reveal account existence "
                             "(insecure mode — for enumeration demo)")
    args = parser.parse_args()

    _LEAKY_RESET_MODE = args.leaky_reset

    print("=" * 60)
    print(" Fake Login Portal — AUA Botnet Research Lab")
    print(f" Listening on 0.0.0.0:{args.port}")
    print(f" Tarpit:         {'ENABLED' if TARPIT_ENABLED else 'DISABLED'}")
    if TARPIT_ENABLED:
        print(f" Tarpit delay:   {tarpit_state.TARPIT_DELAY} +/- "
              f"{tarpit_state.TARPIT_JITTER}s")
        print(f" State file:     {tarpit_state.STATE_FILE}")
    print(f" IP Reputation:  {'ENABLED' if REPUTATION_ENABLED else 'DISABLED'}")
    print(f" Step-up 2FA:    {'ENABLED' if TOTP_ENABLED else 'DISABLED'}")
    print(f" Clustering:     {'ENABLED' if CLUSTERING_ENABLED else 'DISABLED'}")
    print(f" Extensions:     {'ENABLED' if EXTENSIONS_ENABLED else 'DISABLED'}")
    if EXTENSIONS_ENABLED:
        print(f"   Engine 9 (browser automation artifact detection)")
        print(f"   CSRF tokens on /login form")
        print(f"   POST /reset-password  ({'LEAKY' if _LEAKY_RESET_MODE else 'SECURE'} mode)")
        print(f"   POST /api/mobile/login  (Device-ID rate limiting)")
        print(f"   GET/POST /oauth/*  (token abuse detection)")
    print(f" CAPTCHA:        after {CAPTCHA_FAIL_THRESHOLD} failures per IP")
    print(f" Username limit: {USERNAME_RATE_MAX} per {USERNAME_RATE_WINDOW}s per email")
    print(f" Hard block:     after {N_BEFORE_BLOCK} post-tarpit attempts → HTTP 429")
    print(f" Breach check:   {len(BREACHED_PASSWORDS)} known-breached passwords")
    print(f" Reset mode:     {'LEAKY (--leaky-reset)' if _LEAKY_RESET_MODE else 'SECURE (uniform response)'}")
    print()
    print(" Endpoints:")
    print("   GET/POST /login            Main credential stuffing target")
    print("   POST     /reset-password   Account enumeration demo")
    print("   POST     /api/mobile/login Mobile API blind-spot demo")
    print("   POST     /oauth/authorize  OAuth token planting demo")
    print("   POST     /oauth/token      Token exchange / refresh")
    print("   POST     /oauth/revoke     Token revocation defense")
    print("   GET      /attempts         Attempt log + tarpit summary")
    print("   POST     /attempts/reset   Clear state between runs")
    print("   GET      /tarpit/status    Graph 3 TPR counter")
    print("   GET      /stats/advanced   All IDS Engine 5 signals")
    print("   GET      /stats/extensions New-module stats (debug)")
    print("   GET      /2fa/status       Step-up 2FA admin")
    print("   GET      /clustering/status Username clustering admin")
    print("=" * 60)

    app.run(host="0.0.0.0", port=args.port, debug=False)