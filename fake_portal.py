"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Dummy Login Portal (Credential Stuffing Target)
 Run on victim VM: sudo python3 fake_portal.py
 Environment: ISOLATED VM LAB ONLY
====================================================

A minimal Flask web app with a /login endpoint.
The IDS behavioral engine monitors POST requests
to this endpoint to detect credential stuffing via
CV-based timing analysis.

TARPIT INTEGRATION:
  When ids_detector.py Engine 2 flags an IP (CV < 0.15),
  it writes that IP to tarpit_state.json. This portal
  reads that file on every /login request:

  Flagged IP  → response delayed by 8±2 seconds
               (attacker's throughput → near zero)
               (connection is kept alive, not blocked)
  Normal IP   → response in <200ms (unchanged)

  This is non-blocking tarpitting: the bot stays connected
  and receives a valid HTTP response, but so slowly that
  testing 1,000 credentials now takes ~2.2 hours instead
  of ~5 minutes. Crucially, the attacker cannot detect
  that they are blocked — no 429, no RST, no error.

GRAPH 3 DETECTION PROXY:
  collect_graph23_data.py uses GET /tarpit/status to measure
  whether the IDS fired during a jitter-level sweep.  The
  response includes two counters:
    total_delayed     — increments when a /login response is
                        actually delayed (race-prone: only
                        increments if the bot is still sending
                        requests after the flag is set)
    total_flag_events — increments the instant tarpit_state.flag()
                        is called, before any response is delayed
                        (race-condition-free)
  collect_graph23_data.py prefers total_flag_events when present.

NEW DEFENSES (added to match Castle credential stuffing article):
  1. Unknown-account tracking  — counts attempts against emails not
     in the user DB; exposed per-IP in /stats/advanced for Engine 5.
  2. Per-username rate limiting — 429 after USERNAME_RATE_MAX attempts
     per email per USERNAME_RATE_WINDOW seconds.
  3. IP reputation scoring     — every request scored via
     ip_reputation.py (datacenter subnet, suspicious UA, missing
     headers, X-Fwd cycling, cross-IP fingerprint reuse).
  4. Progressive CAPTCHA        — after CAPTCHA_FAIL_THRESHOLD
     consecutive failures from one IP, a math challenge is issued.
     Bots using plain urllib/requests cannot solve it without custom
     parsing code, increasing attacker cost.
  5. Hard block (429)          — after N_BEFORE_BLOCK further failures
     post-tarpit, escalates to an explicit 429 to demonstrate the
     silent tarpit → detected escalation path.
  6. Breach credential detection — flags passwords found in a
     known-breached list (HIBP k-Anonymity API simulation).
  7. /stats/advanced endpoint  — all new signals for IDS Engine 5.
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
    print("[PORTAL] WARNING: tarpit_state.py not found — tarpit disabled")

# ── IP reputation scoring (new) ───────────────────────────────
try:
    import ip_reputation
    REPUTATION_ENABLED = True
except ImportError:
    REPUTATION_ENABLED = False
    print("[PORTAL] WARNING: ip_reputation.py not found — scoring disabled")

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

# ── Known-breached password list (HIBP simulation, new) ───────
# In production: call the k-Anonymity HIBP API.
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
    # total_flag_events mirrors tarpit_state.get_flag_count().
    # Kept in memory here so /tarpit/status reflects the most current
    # value without an extra file read on every request.
    "total_flag_events":   0,
}
_stats_lock  = threading.Lock()

# ── Per-username rate limiting (new) ─────────────────────────
USERNAME_RATE_WINDOW  = 60    # seconds
USERNAME_RATE_MAX     = 5     # max attempts per email per window
_username_attempts: dict = defaultdict(lambda: deque())
_username_lock = threading.Lock()

# ── Progressive CAPTCHA state (new) ──────────────────────────
CAPTCHA_FAIL_THRESHOLD = 3     # consecutive failures before challenge
CAPTCHA_TTL            = 120   # seconds before challenge expires
_captcha_state: dict = {}
_captcha_lock = threading.Lock()

# ── Hard block escalation (new) ──────────────────────────────
N_BEFORE_BLOCK = 10
_post_tarpit_fails: dict = defaultdict(int)

# ── Unknown account tracking (new) ───────────────────────────
_unknown_acct_counts: dict = defaultdict(int)  # src_ip → count
_unknown_acct_total   = 0

# ── Off-hours tracking (new) ─────────────────────────────────
_hourly_counts: dict = defaultdict(int)   # hour → count

# ── Reputation snapshot (new) ────────────────────────────────
_rep_scores: dict = {}   # src_ip → latest reputation dict

# ── Breach credential hit counter (new) ──────────────────────
_breached_cred_hits = 0

# ── HTML ──────────────────────────────────────────────────────
LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head><title>MyApp Login</title>
<style>
  body { font-family: Arial; max-width: 400px; margin: 100px auto; }
  input { width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }
  button { width: 100%; padding: 10px; background: #2980B9; color: white; border: none; cursor: pointer; }
</style>
</head>
<body>
  <h2>Login to MyApp</h2>
  <form method="POST" action="/login">
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Login</button>
  </form>
</body>
</html>
"""

# ── Helpers (new) ─────────────────────────────────────────────

def _make_captcha() -> dict:
    """Generate a simple arithmetic CAPTCHA challenge."""
    a  = random.randint(2, 20)
    b  = random.randint(2, 20)
    op = random.choice(["+", "-", "*"])
    answer = a + b if op == "+" else (a - b if op == "-" else a * b)
    return {"question": f"What is {a} {op} {b}?", "answer": answer}


def _check_username_rate_limit(email: str) -> bool:
    """Return True if this email has exceeded the per-username rate limit."""
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


# ── Routes ────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(LOGIN_PAGE)


@app.route("/login", methods=["GET", "POST"])
def login():
    global _unknown_acct_total, _breached_cred_hits

    if request.method == "GET":
        return render_template_string(LOGIN_PAGE)

    if request.is_json:
        data     = request.get_json() or {}
        email    = data.get("email", "")
        password = data.get("password", "")
        captcha_answer = data.get("captcha_answer")
    else:
        email    = request.form.get("email", "")
        password = request.form.get("password", "")
        captcha_answer = request.form.get("captcha_answer")

    timestamp = time.time()
    src_ip    = request.remote_addr
    headers   = dict(request.headers)
    hour      = datetime.now().hour

    # ── Track off-hours attempts (new) ────────────────────────
    with _stats_lock:
        _hourly_counts[hour] += 1

    # ── IP reputation scoring (new) ───────────────────────────
    rep = {}
    if REPUTATION_ENABLED:
        rep = ip_reputation.score_request(src_ip, headers)
        with _stats_lock:
            _rep_scores[src_ip] = rep

    # ── Per-username rate limiting (new) ──────────────────────
    if email and _check_username_rate_limit(email):
        logging.warning(
            f"RATE-LIMITED | src={src_ip} | email={email} | "
            f">{USERNAME_RATE_MAX} attempts in {USERNAME_RATE_WINDOW}s"
        )
        return jsonify({
            "status":  "error",
            "message": "Too many login attempts for this account. Try again later.",
        }), 429

    # ── Unknown account detection (new) ──────────────────────
    email_known = email in USERS
    if not email_known:
        with _stats_lock:
            _unknown_acct_counts[src_ip] += 1
            _unknown_acct_total += 1

    # ── Breach credential detection (new) ────────────────────
    is_breached = password in BREACHED_PASSWORDS
    if is_breached:
        with _stats_lock:
            _breached_cred_hits += 1
        logging.warning(
            f"BREACHED-CRED | src={src_ip} | email={email} | "
            f"password in known-breached list (HIBP simulation)"
        )

    # ── CAPTCHA check (new) ───────────────────────────────────
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

    # ── Hard block after tarpit + persistence (new) ───────────
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

    # ── TARPIT CHECK ─────────────────────────────────────────
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
            tarpit_stats["total_delayed"]      += 1
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

    # ── Update CAPTCHA failure counter (new) ──────────────────
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

    # ── Log attempt ──────────────────────────────────────────
    # Original fields preserved; new fields appended (additive, backward-compatible).
    entry = {
        "ts":           timestamp,
        "src":          src_ip,
        "email":        email,
        "success":      success,
        "tarpitted":    tarpitted,
        "tarpit_delay": round(tarpit_delay_s, 2),
        "dt":           datetime.now().isoformat(),
        # new fields
        "email_known":  email_known,
        "is_breached":  is_breached,
        "rep_score":    rep.get("score", 0),
        "rep_band":     rep.get("band", "UNKNOWN"),
        "fingerprint":  rep.get("fingerprint", ""),
    }
    with _stats_lock:
        attempt_log.append(entry)

    logging.info(
        f"LOGIN   | src={src_ip} | email={email} | "
        f"success={success} | tarpitted={tarpitted}"
    )

    if success:
        return jsonify({"status": "success", "message": "Welcome!"})
    else:
        return jsonify({"status": "fail", "message": "Invalid credentials"}), 401


@app.route("/attempts")
def view_attempts():
    """Admin endpoint — inspect login log, tarpit stats, and flagged IPs."""
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
        "total_attempts":  total,
        "recent":          recent,
        "success_count":   success_count,
        "fail_count":      fail_count,
        "tarpit": {
            "enabled":           TARPIT_ENABLED,
            "currently_flagged": flagged_ips,
            "total_delayed":     ts_delayed,
            "total_delay_sec":   ts_delay_sec,
            "total_flag_events": ts_flag_events,
            "recent_tarpitted":  recent_tp,
        },
    })


@app.route("/stats/advanced")
def advanced_stats():
    """
    Extended statistics endpoint consumed by IDS Engine 5.

    Fields:
      success_rate_pct     — overall login success rate (low → bot spray)
      unknown_acct_pct     — % of attempts to non-existent emails
      off_hours_pct        — % of attempts outside 08:00-22:00
      breached_cred_hits   — count of HIBP-listed passwords submitted
      per_ip_unknowns      — per-source-IP count of unknown-account hits
      reputation_scores    — latest IP reputation band per IP
      captcha_active       — IPs currently under CAPTCHA challenge
      hard_blocked_ips     — IPs that hit the post-tarpit block threshold
      hourly_distribution  — request counts by hour-of-day
      total_flag_events    — cumulative tarpit flag counter (Graph 3)
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

    return jsonify({
        "total_attempts":      total,
        "success_count":       success_count,
        "fail_count":          total - success_count,
        "success_rate_pct":    round(success_count / max(1, total) * 100, 2),
        "unknown_acct_count":  unknown_count,
        "unknown_acct_pct":    round(unknown_count / max(1, total) * 100, 2),
        "off_hours_count":     off_hours,
        "off_hours_pct":       round(off_hours / max(1, total_counted) * 100, 2),
        "breached_cred_hits":  breached_count,
        "per_ip_unknowns":     per_ip_unknowns,
        "reputation_scores":   rep_snap,
        "captcha_active":      captcha_active,
        "hard_blocked_ips":    hard_blocked,
        "hourly_distribution": hourly_snap,
        "total_flag_events":   ts_flag_events,
        "tarpit_enabled":      TARPIT_ENABLED,
        "reputation_enabled":  REPUTATION_ENABLED,
    })


@app.route("/attempts/reset", methods=["POST"])
def reset_attempts():
    """
    Reset the in-memory attempt log and tarpit stats.

    Used by collect_graph23_data.py between jitter-level sweeps so that
    each measurement window starts from a clean baseline.

    Optional JSON body:
      {"clear_tarpit": true}  — also wipe tarpit_state.json (default false)
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

    clear_tarpit = data.get("clear_tarpit", False)
    if clear_tarpit and TARPIT_ENABLED:
        tarpit_state.clear_all()
        logging.info("RESET    | attempt log, tarpit stats, and tarpit flags cleared")
    else:
        logging.info("RESET    | attempt log and tarpit stats cleared")

    return jsonify({"status": "reset", "cleared_tarpit": clear_tarpit})


@app.route("/tarpit/flag", methods=["POST"])
def tarpit_flag():
    """
    IDS → portal signal endpoint (HTTP alternative to file-based state).
    POST {"ip": "192.168.100.11"} to flag an IP programmatically.
    Also increments total_flag_events so collect_graph23_data.py counts
    this detection path even if the bot finishes before a delayed response
    is served.
    """
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
    """Remove a tarpit flag."""
    if not TARPIT_ENABLED:
        return jsonify({"error": "tarpit disabled"}), 503
    data = request.get_json() or {}
    ip   = data.get("ip", "")
    tarpit_state.unflag(ip)
    return jsonify({"status": "unflagged", "ip": ip})


@app.route("/tarpit/status")
def tarpit_status():
    """
    Show current tarpit state.

    Response includes:
      enabled           — whether tarpit_state.py was importable
      flagged           — list of currently flagged IPs
      stats             — counters:
        total_delayed       — requests actually delayed (race-prone)
        total_delay_seconds — total seconds of artificial delay served
        total_flag_events   — IPs ever flagged this session (race-free)
      ttl_sec           — per-IP flag expiry in seconds
      delay_sec         — nominal delay applied to flagged IPs

    collect_graph23_data.py reads stats.total_flag_events as its
    primary Graph 3 TPR detection proxy.
    """
    flagged = tarpit_state.list_flagged() if TARPIT_ENABLED else []

    # Sync from file before responding so we always return the latest value
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


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print(" Fake Login Portal - AUA Botnet Research Lab")
    print(" Listening on 0.0.0.0:80")
    print(f" Tarpit:         {'ENABLED' if TARPIT_ENABLED else 'DISABLED (tarpit_state.py missing)'}")
    if TARPIT_ENABLED:
        print(f" Tarpit delay:   {tarpit_state.TARPIT_DELAY}±{tarpit_state.TARPIT_JITTER}s")
        print(f" State file:     {tarpit_state.STATE_FILE}")
    print(f" IP Reputation:  {'ENABLED' if REPUTATION_ENABLED else 'DISABLED (ip_reputation.py missing)'}")
    print(f" CAPTCHA:        ENABLED (triggers after {CAPTCHA_FAIL_THRESHOLD} consecutive failures per IP)")
    print(f" Username limit: {USERNAME_RATE_MAX} attempts per {USERNAME_RATE_WINDOW}s per email")
    print(f" Hard block:     after {N_BEFORE_BLOCK} post-tarpit attempts → HTTP 429")
    print(f" Breach check:   ENABLED ({len(BREACHED_PASSWORDS)} known-breached passwords)")
    print(" Monitor:        GET /attempts | GET /tarpit/status | GET /stats/advanced")
    print(" Graph 3:        stats.total_flag_events = race-free detection counter")
    print("=" * 55)
    app.run(host="0.0.0.0", port=80, debug=False)