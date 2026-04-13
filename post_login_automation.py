"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Post-Login Automation Simulator
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching point (from Castle credential stuffing article):
  "Optional Post-Access Automation: If integrated with browser
   automation frameworks (e.g., Puppeteer, Playwright), attackers
   simulate user behavior post-login — navigating dashboards,
   initiating transactions, or injecting further payloads."

  "Attackers today don't just run scripts. They operate
   infrastructure: headless Chromium in sandboxed VMs, proof-
   of-work logic to bypass friction, and evasive JS execution,
   as we showed in our TikTok VM teardown."

Why post-login automation matters:
  cred_stuffing.py stops at login. In reality, a successful
  hit triggers a second phase: the attacker's bot navigates
  the account to extract value, change settings, or plant
  persistence — all while mimicking normal user behavior to
  avoid triggering session anomaly detection.

  This module simulates the HTTP-layer footprint of those
  post-login actions against fake_portal.py.

  Four action profiles:
    1. Stealth extractor — minimal page visits, straight to
       /account/export and /payment-methods, then exits
    2. Cover-story surfer — visits several pages to build a
       normal session history before hitting sensitive endpoints
    3. Churn-and-burn — rapid-fire sensitive-endpoint access
       with no browsing context (noisy, easy to detect)
    4. Long-dwell infiltrator — logs in, waits hours, returns
       to complete extraction (evades session-duration alerts)

This module also includes:

  PostLoginActionDetector (IDS Engine 13)
    Detects anomalous post-login navigation:
    - Session goes directly to /account/settings with no prior
      browsing (no referrer chain from landing page)
    - Sensitive-endpoint access within 5 seconds of login
    - Unusual endpoint sequence (login → export → logout with
      no intermediate pages)
    - Data-volume anomaly: /api/export returns >1MB in one call
      from a new-device session
"""

import json
import os
import random
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional
import urllib.error
import urllib.parse
import urllib.request

# ── Configuration ─────────────────────────────────────────────
TARGET_HOST  = "192.168.100.20"
TARGET_PORT  = 80
LOG_PATH     = "/tmp/post_login_sim.json"

# Endpoint catalog (mapped against fake_portal.py routes)
ENDPOINTS = {
    # Low-sensitivity — normal browsing
    "home":              "/",
    "dashboard":         "/dashboard",
    "profile":           "/profile",
    "feed":              "/feed",
    "notifications":     "/notifications",
    "search":            "/search?q=test",
    # Medium-sensitivity — mild anomaly signal
    "account_settings":  "/account/settings",
    "connected_apps":    "/account/apps",
    "billing":           "/account/billing",
    # High-sensitivity — strong ATO signal when hit immediately
    "change_email":      "/account/settings/email",
    "change_password":   "/account/settings/password",
    "payment_methods":   "/account/payment-methods",
    "data_export":       "/account/export",
    "add_device":        "/account/devices/add",
    "api_keys":          "/account/api-keys",
}

SENSITIVE_ENDPOINTS = {
    "change_email", "change_password", "payment_methods",
    "data_export", "add_device", "api_keys",
}


def _log_session(entry: dict):
    entries = []
    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH) as f:
                entries = json.load(f)
        except Exception:
            entries = []
    entries.append(entry)
    with open(LOG_PATH, "w") as f:
        json.dump(entries, f, indent=2)


# ══════════════════════════════════════════════════════════════
#  HTTP helper
# ══════════════════════════════════════════════════════════════

def _get(path: str, session_cookie: str = "",
         timeout: float = 5.0) -> tuple:
    """
    Simulate an authenticated GET request to the portal.
    Returns (status_code, response_body).
    """
    url = f"http://{TARGET_HOST}:{TARGET_PORT}{path}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent",
                   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
    req.add_header("Accept",
                   "text/html,application/xhtml+xml,*/*;q=0.9")
    req.add_header("Accept-Language", "en-US,en;q=0.9")
    if session_cookie:
        req.add_header("Cookie", f"session={session_cookie}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


# ══════════════════════════════════════════════════════════════
#  Part 1: ACTION PROFILES (Attack side)
# ══════════════════════════════════════════════════════════════

class PostLoginSession:
    """
    Base class for all post-login automation profiles.
    Tracks the navigation sequence and timing for IDS analysis.
    """

    def __init__(self, email: str,
                 session_cookie: str = "simulated_session_token",
                 src_ip: str = "192.168.100.11"):
        self.email          = email
        self.session_cookie = session_cookie
        self.src_ip         = src_ip
        self.nav_log: list  = []     # (ts, endpoint_name, status)
        self._stop          = threading.Event()

    def _visit(self, endpoint_name: str) -> int:
        path   = ENDPOINTS.get(endpoint_name, "/" + endpoint_name)
        ts     = time.time()
        status, body = _get(path, self.session_cookie)
        self.nav_log.append({
            "ts":       ts,
            "endpoint": endpoint_name,
            "path":     path,
            "status":   status,
        })
        sensitivity = ("🔴 SENSITIVE" if endpoint_name in SENSITIVE_ENDPOINTS
                       else "⬜ normal")
        print(f"  [{datetime.fromtimestamp(ts).strftime('%H:%M:%S')}] "
              f"GET {path:35s}  HTTP {status}  {sensitivity}")
        return status

    def _sleep(self, mean_sec: float, stdev_sec: float = 0.5,
               minimum: float = 0.1):
        delay = max(minimum, random.gauss(mean_sec, stdev_sec))
        if not self._stop.is_set():
            time.sleep(delay)

    def get_nav_summary(self) -> dict:
        if not self.nav_log:
            return {}
        first_ts = self.nav_log[0]["ts"]
        last_ts  = self.nav_log[-1]["ts"]
        sensitive_visits = [e for e in self.nav_log
                            if e["endpoint"] in SENSITIVE_ENDPOINTS]
        sensitive_first  = (sensitive_visits[0]["ts"] - first_ts
                            if sensitive_visits else None)
        return {
            "email":            self.email,
            "src_ip":           self.src_ip,
            "total_pages":      len(self.nav_log),
            "sensitive_pages":  len(sensitive_visits),
            "session_sec":      round(last_ts - first_ts, 1),
            "seconds_to_first_sensitive": (round(sensitive_first, 1)
                                           if sensitive_first else None),
            "nav_sequence":     [e["endpoint"] for e in self.nav_log],
        }


class StealthExtractor(PostLoginSession):
    """
    Minimal footprint: no browsing, straight to sensitive endpoints.
    Prioritizes speed over stealth. Easy to detect because there is
    no session context before hitting sensitive pages.
    """

    def run(self):
        print(f"\n[POST-LOGIN] 🎯 Stealth Extractor — {self.email}")
        print(f"  Strategy: login → sensitive → logout, no browsing")
        self._visit("payment_methods")
        self._sleep(0.5, 0.2)
        self._visit("api_keys")
        self._sleep(0.3)
        self._visit("data_export")
        self._sleep(0.2)
        self._visit("add_device")
        return self.get_nav_summary()


class CoverStorySurfer(PostLoginSession):
    """
    Builds normal session history before hitting sensitive endpoints.
    Visits landing page, feed, profile — creating a referrer chain
    that looks like normal browsing — then pivots to sensitive areas.
    Harder to detect because session context appears legitimate.
    """

    def run(self):
        print(f"\n[POST-LOGIN] 🌊 Cover Story Surfer — {self.email}")
        print(f"  Strategy: build browsing history first, then act")

        # Phase 1: Normal browsing (establishes context)
        for page in ["home", "dashboard", "feed", "notifications", "profile"]:
            self._visit(page)
            self._sleep(random.uniform(3, 8), 2)

        # Phase 2: Natural navigation to settings
        self._visit("account_settings")
        self._sleep(4, 1.5)
        self._visit("billing")
        self._sleep(2)

        # Phase 3: Actual extraction (now looks like natural continuation)
        self._visit("payment_methods")
        self._sleep(1.5)
        self._visit("data_export")
        return self.get_nav_summary()


class ChurnAndBurn(PostLoginSession):
    """
    Rapid-fire sensitive endpoint access with minimal delays.
    High risk of detection but maximizes extraction speed —
    used when the attacker doesn't expect to return.
    """

    def run(self):
        print(f"\n[POST-LOGIN] 🔥 Churn and Burn — {self.email}")
        print(f"  Strategy: extract everything as fast as possible")
        for endpoint in list(SENSITIVE_ENDPOINTS):
            self._visit(endpoint)
            self._sleep(0.2, 0.1, 0.05)  # very short pauses
        return self.get_nav_summary()


class LongDwellInfiltrator(PostLoginSession):
    """
    Logs in, does nothing suspicious, waits a long time, then acts.
    Exploits the fact that most IDS systems have short detection
    windows. If the attacker waits longer than the CV/timing window,
    the initial session looks clean and the later sensitive access
    is in a different detection epoch.
    Simulated with compressed times for lab demonstration.
    """

    def __init__(self, *args, dwell_minutes: float = 0.2, **kwargs):
        super().__init__(*args, **kwargs)
        self.dwell_minutes = dwell_minutes  # compressed for lab

    def run(self):
        dwell_sec = self.dwell_minutes * 60
        print(f"\n[POST-LOGIN] ⏳ Long Dwell Infiltrator — {self.email}")
        print(f"  Strategy: browse normally, wait {dwell_sec:.0f}s, "
              f"then extract")

        # Phase 1: Innocent browsing
        for page in ["home", "dashboard", "feed"]:
            self._visit(page)
            self._sleep(2, 0.5)

        # Phase 2: Long dwell (compressed in lab — real attack: hours)
        print(f"  [DWELL] Waiting {dwell_sec:.1f}s "
              f"(real attack: {self.dwell_minutes * 60:.0f}s compressed "
              f"from hours)…")
        time.sleep(dwell_sec)

        # Phase 3: Return and act (now appears as a separate session epoch)
        print(f"  [RESUME] Returning to sensitive endpoints")
        self._visit("api_keys")
        self._sleep(1)
        self._visit("data_export")
        return self.get_nav_summary()


# ══════════════════════════════════════════════════════════════
#  Part 2: POST-LOGIN DETECTOR (IDS Engine 13)
# ══════════════════════════════════════════════════════════════

class PostLoginActionDetector:
    """
    IDS Engine 13: Detect anomalous post-login navigation.

    Integrated into fake_portal.py request handler:
      - Called on every authenticated GET/POST
      - Maintains per-session navigation history
      - Fires alerts on anomalous patterns

    Signals:
      1. Direct-to-sensitive: first post-login page is sensitive
         with no prior browsing (< 3 normal pages before it)
      2. Speed anomaly: sensitive endpoint reached within 5s of login
      3. No-context dump: /data-export or /api-keys accessed with
         no referrer from account settings page
      4. Churn pattern: ≥ 4 sensitive endpoints hit in < 30 seconds
      5. Long-dwell: active session token from >4h ago makes a new
         request to a sensitive endpoint from the same IP
    """

    DIRECT_SENSITIVE_MIN_NORMAL = 2   # normal pages before sensitive is OK
    SPEED_THRESHOLD_SEC         = 5   # sensitive within this = alert
    CHURN_THRESHOLD             = 4   # sensitive endpoints in CHURN_WINDOW
    CHURN_WINDOW_SEC            = 30
    DWELL_THRESHOLD_HR          = 4   # hours of inactivity before return

    def __init__(self):
        self._lock      = threading.Lock()
        # session_id → list of {ts, endpoint, sensitive}
        self._sessions: dict = defaultdict(list)
        # session_id → login_ts
        self._login_ts: dict = {}
        self._alerts: list  = []

    def record_login(self, session_id: str, email: str,
                     src_ip: str):
        with self._lock:
            self._login_ts[session_id] = time.time()
            self._sessions[session_id] = []

    def record_page_visit(self, session_id: str,
                           endpoint: str,
                           src_ip: str) -> Optional[dict]:
        """Call on every authenticated request. Returns alert or None."""
        now    = time.time()
        is_sen = endpoint in SENSITIVE_ENDPOINTS
        alert  = None

        with self._lock:
            self._sessions[session_id].append({
                "ts":        now,
                "endpoint":  endpoint,
                "sensitive": is_sen,
            })
            history = list(self._sessions[session_id])
            login_t = self._login_ts.get(session_id, now)

        normal_before   = sum(1 for e in history
                               if not e["sensitive"])
        seconds_in      = now - login_t

        # Signal 1: Direct-to-sensitive
        if (is_sen
                and normal_before < self.DIRECT_SENSITIVE_MIN_NORMAL):
            alert = {
                "engine":        "Engine13/DirectSensitive",
                "severity":      "HIGH",
                "session":       session_id,
                "endpoint":      endpoint,
                "normal_pages_before": normal_before,
                "ts":            datetime.now().isoformat(),
                "message": (
                    f"DIRECT SENSITIVE ACCESS: session hit "
                    f"'{endpoint}' with only {normal_before} "
                    f"normal pages prior\n"
                    f"  Real users browse before changing settings\n"
                    f"  MITRE: T1071.001 (Web Protocols)"
                ),
            }

        # Signal 2: Speed anomaly
        if is_sen and seconds_in < self.SPEED_THRESHOLD_SEC:
            speed_alert = {
                "engine":    "Engine13/SpeedAnomaly",
                "severity":  "HIGH",
                "session":   session_id,
                "endpoint":  endpoint,
                "seconds_in": round(seconds_in, 1),
                "ts":        datetime.now().isoformat(),
                "message": (
                    f"SPEED ANOMALY: '{endpoint}' reached "
                    f"{seconds_in:.1f}s after login "
                    f"(threshold: {self.SPEED_THRESHOLD_SEC}s)\n"
                    f"  Automated navigation — bot went directly "
                    f"to sensitive endpoint"
                ),
            }
            if not alert:
                alert = speed_alert

        # Signal 4: Churn pattern
        cutoff = now - self.CHURN_WINDOW_SEC
        recent_sensitive = [
            e for e in history
            if e["sensitive"] and e["ts"] > cutoff
        ]
        if len(recent_sensitive) >= self.CHURN_THRESHOLD:
            churn_alert = {
                "engine":   "Engine13/ChurnPattern",
                "severity": "CRITICAL",
                "session":  session_id,
                "n_sensitive": len(recent_sensitive),
                "window_sec": self.CHURN_WINDOW_SEC,
                "ts":       datetime.now().isoformat(),
                "message": (
                    f"CHURN-AND-BURN: {len(recent_sensitive)} sensitive "
                    f"endpoints in {self.CHURN_WINDOW_SEC}s\n"
                    f"  Endpoints: "
                    f"{[e['endpoint'] for e in recent_sensitive]}\n"
                    f"  Attacker extracting all value before detection\n"
                    f"  Action: terminate session immediately"
                ),
            }
            if not alert:
                alert = churn_alert

        if alert:
            self._alerts.append(alert)
            print(f"\n[IDS-{alert['engine']}] {alert['severity']}: "
                  f"{alert['message']}\n")
        return alert

    def get_stats(self) -> dict:
        return {
            "total_alerts":   len(self._alerts),
            "sessions_seen":  len(self._sessions),
        }


# ── Singleton for portal integration ─────────────────────────
_detector = PostLoginActionDetector()

def engine13_login(session_id, email, src_ip):
    _detector.record_login(session_id, email, src_ip)

def engine13_visit(session_id, endpoint, src_ip):
    return _detector.record_page_visit(session_id, endpoint, src_ip)


# ── Demo ──────────────────────────────────────────────────────

def _run_demo():
    print("=" * 60)
    print(" Post-Login Automation Simulator")
    print(" AUA Botnet Research Lab — ISOLATED VM ONLY")
    print("=" * 60)

    det  = PostLoginActionDetector()
    email = "alice@example.com"
    cookie = "sim_session_abc"

    profiles = [
        ("Stealth Extractor",   StealthExtractor),
        ("Cover Story Surfer",  CoverStorySurfer),
        ("Churn and Burn",      ChurnAndBurn),
    ]

    summaries = []
    for name, cls in profiles:
        sess = cls(email, cookie, src_ip="192.168.100.11")
        # Register with IDS
        session_id = f"sess_{name.replace(' ', '_').lower()}"
        det.record_login(session_id, email, "192.168.100.11")
        sess_result = sess.run()

        # Feed nav log to IDS
        for entry in sess.nav_log:
            det.record_page_visit(
                session_id, entry["endpoint"], "192.168.100.11"
            )

        summaries.append((name, sess_result))
        time.sleep(0.5)

    print("\n" + "=" * 60)
    print(" Navigation Pattern Comparison")
    print("=" * 60)
    print(f"  {'Profile':<25}  {'Pages':>5}  {'Sensitive':>9}  "
          f"{'Duration':>9}  {'Secs to 1st Sensitive':>22}")
    print(f"  {'─'*25}  {'─'*5}  {'─'*9}  {'─'*9}  {'─'*22}")
    for name, s in summaries:
        if s:
            print(f"  {name:<25}  {s['total_pages']:>5}  "
                  f"{s['sensitive_pages']:>9}  "
                  f"{s['session_sec']:>8.1f}s  "
                  f"{str(s['seconds_to_first_sensitive']):>22}")

    print(f"\n  IDS Engine 13 stats: {det.get_stats()}")
    _log_session({"summaries": summaries, "ts": datetime.now().isoformat()})
    print(f"\n[POST-LOGIN] Log: {LOG_PATH}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Post-Login Automation — AUA Research Lab"
    )
    parser.add_argument("--mode",
                        choices=["stealth", "cover", "churn", "dwell", "all"],
                        default="all")
    parser.add_argument("--email",  default="alice@example.com")
    parser.add_argument("--cookie", default="simulated_session")
    args = parser.parse_args()

    if args.mode == "all":
        _run_demo()
    else:
        mode_map = {
            "stealth": StealthExtractor,
            "cover":   CoverStorySurfer,
            "churn":   ChurnAndBurn,
            "dwell":   LongDwellInfiltrator,
        }
        cls  = mode_map[args.mode]
        sess = cls(args.email, args.cookie)
        result = sess.run()
        summary = sess.get_nav_summary()
        print(f"\nSession summary: {json.dumps(summary, indent=2)}")
