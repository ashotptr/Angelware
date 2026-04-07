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

TARPIT INTEGRATION (new):
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
"""

import time
import json
import random
import logging
import threading
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string

# Import tarpit state module (must be in same directory)
try:
    import tarpit_state
    TARPIT_ENABLED = True
except ImportError:
    TARPIT_ENABLED = False
    print("[PORTAL] WARNING: tarpit_state.py not found — tarpit disabled")

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

# ── Attempt log (in-memory, inspectable via /attempts) ────────
attempt_log  = []
tarpit_stats = {"total_delayed": 0, "total_delay_seconds": 0.0}
_stats_lock  = threading.Lock()

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

# ── Routes ────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(LOGIN_PAGE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE)

    # Parse credentials from form or JSON body
    if request.is_json:
        data     = request.get_json() or {}
        email    = data.get("email", "")
        password = data.get("password", "")
    else:
        email    = request.form.get("email", "")
        password = request.form.get("password", "")

    timestamp = time.time()
    src_ip    = request.remote_addr
    success   = USERS.get(email) == password

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
        # Normal response: small fixed delay simulates DB lookup
        time.sleep(0.1)

    # ── Log attempt ──────────────────────────────────────────
    entry = {
        "ts":            timestamp,
        "src":           src_ip,
        "email":         email,
        "success":       success,
        "tarpitted":     tarpitted,
        "tarpit_delay":  round(tarpit_delay_s, 2),
        "dt":            datetime.now().isoformat(),
    }
    with _stats_lock:
        attempt_log.append(entry)

    logging.info(
        f"LOGIN   | src={src_ip} | email={email} | "
        f"success={success} | tarpitted={tarpitted}"
    )

    # Respond — identical format regardless of tarpit (opaque to attacker)
    if success:
        return jsonify({"status": "success", "message": "Welcome!"})
    else:
        return jsonify({"status": "fail", "message": "Invalid credentials"}), 401


@app.route("/attempts")
def view_attempts():
    """Admin endpoint — inspect login log, tarpit stats, and flagged IPs."""
    recent        = attempt_log[-200:]
    flagged_ips   = tarpit_state.list_flagged() if TARPIT_ENABLED else []
    tarpitted_log = [e for e in attempt_log if e.get("tarpitted")]

    return jsonify({
        "total_attempts":       len(attempt_log),
        "recent":               recent,
        "success_count":        sum(1 for a in attempt_log if a["success"]),
        "fail_count":           sum(1 for a in attempt_log if not a["success"]),
        "tarpit": {
            "enabled":          TARPIT_ENABLED,
            "currently_flagged": flagged_ips,
            "total_delayed":    tarpit_stats["total_delayed"],
            "total_delay_sec":  round(tarpit_stats["total_delay_seconds"], 1),
            "recent_tarpitted": tarpitted_log[-50:],
        }
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
    data = request.get_json(silent=True) or {}
    with _stats_lock:
        attempt_log.clear()
        tarpit_stats["total_delayed"]      = 0
        tarpit_stats["total_delay_seconds"] = 0.0

    if data.get("clear_tarpit", False) and TARPIT_ENABLED:
        tarpit_state.clear_all()
        logging.info("RESET    | attempt log, tarpit stats, and tarpit flags cleared")
    else:
        logging.info("RESET    | attempt log and tarpit stats cleared")

    return jsonify({"status": "reset", "cleared_tarpit": data.get("clear_tarpit", False)})


@app.route("/tarpit/flag", methods=["POST"])
def tarpit_flag():
    """
    IDS → portal signal endpoint (alternative to file-based state).
    POST {"ip": "192.168.100.11"} to flag an IP programmatically.
    """
    if not TARPIT_ENABLED:
        return jsonify({"error": "tarpit disabled"}), 503
    data = request.get_json() or {}
    ip   = data.get("ip", "")
    if not ip:
        return jsonify({"error": "no ip"}), 400
    tarpit_state.flag(ip)
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
    """Show current tarpit state."""
    flagged = tarpit_state.list_flagged() if TARPIT_ENABLED else []
    return jsonify({
        "enabled":   TARPIT_ENABLED,
        "flagged":   flagged,
        "stats":     tarpit_stats,
        "ttl_sec":   tarpit_state.TTL_SECONDS   if TARPIT_ENABLED else None,
        "delay_sec": tarpit_state.TARPIT_DELAY  if TARPIT_ENABLED else None,
    })


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print(" Fake Login Portal - AUA Botnet Research Lab")
    print(" Listening on 0.0.0.0:80")
    print(f" Tarpit: {'ENABLED' if TARPIT_ENABLED else 'DISABLED (tarpit_state.py missing)'}")
    if TARPIT_ENABLED:
        print(f" Tarpit delay: {tarpit_state.TARPIT_DELAY}±{tarpit_state.TARPIT_JITTER}s")
        print(f" State file:   {tarpit_state.STATE_FILE}")
    print(" Monitor: GET /attempts | GET /tarpit/status")
    print("=" * 55)
    app.run(host="0.0.0.0", port=80, debug=False)