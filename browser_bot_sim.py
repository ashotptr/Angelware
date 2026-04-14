"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Browser Automation Traffic Simulator
            + IDS Engine 9: Browser Automation Detection
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching point (from Castle credential stuffing article):
  "Browser automation frameworks: Tools like Puppeteer and
   Playwright offer full browser control. When patched to remove
   automation artifacts (like navigator.webdriver), they can run
   JavaScript and evade basic bot defenses."

  "Detect automation artifacts like navigator.webdriver,
   inconsistencies in WebGL or audio fingerprints, or signs of
   Chrome DevTools Protocol (CDP) injection."

Two components in this file:

1. BrowserBotSimulator (Attack side)
   Generates the HTTP-level signatures that headless browser
   bots produce. Since we cannot run a real browser in the
   isolated lab, we simulate the observable fingerprints:
   - CDP-injected header artifacts
   - WebDriver flag in custom header
   - Inconsistent Accept headers for a "Chrome" UA
   - Missing Sec-Fetch-* headers (older automation)
   - Uniform timing (no mouse events)
   - Suspicious TLS cipher ordering (Python ssl vs real Chrome)

2. BrowserArtifactDetector (Defense side / IDS Engine 9)
   Analyzes HTTP request headers received by the portal and
   scores them for browser automation artifacts.
   Integrated into fake_portal.py and ids_detector.py.
"""

import argparse
import hashlib
import json
import os
import random
import sys
import threading
import time
import urllib.request
import urllib.error
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

# ── Configuration ─────────────────────────────────────────────
DEFAULT_HOST = "192.168.100.20"
DEFAULT_PORT = 8080
LOGIN_PATH   = "/login"

# ── Known automation artifact header patterns ─────────────────
#
# These are HTTP-level signals a server can observe.
# Real Puppeteer/Playwright with default settings leaks some of these.
# "Stealth" plugins patch many but rarely all.

# Automation tools often use these UA strings
AUTOMATION_UA_FRAGMENTS = [
    "HeadlessChrome",
    "PhantomJS",
    "Selenium",
    "WebDriver",
    "puppeteer",
    "playwright",
    "ChromeHeadless",
    "Electron",
]

# Headers Puppeteer/Playwright with default config omit or get wrong
# compared to a real Chrome browser
EXPECTED_CHROME_HEADERS = {
    "sec-ch-ua",                # Chrome Client Hints — automation often omits
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "accept-language",
}

# CDP (Chrome DevTools Protocol) injection artifacts
# When a bot controls Chrome via CDP, certain internal headers
# or patterns sometimes appear.
CDP_ARTIFACTS = [
    "x-devtools-emulate-network-conditions-client-id",
    "x-client-data",   # sometimes injected by Chromium builds
]

# Playwright default Accept header for navigation (differs from real Chrome)
PLAYWRIGHT_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
CHROME_ACCEPT     = ("text/html,application/xhtml+xml,application/xml;"
                     "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,"
                     "application/signed-exchange;v=b3;q=0.7")


# ══════════════════════════════════════════════════════════════
#  Part 1: BROWSER BOT SIMULATOR (Attack side)
# ══════════════════════════════════════════════════════════════

class BrowserBotSimulator:
    """
    Simulates the HTTP-level signature of a headless browser bot.

    We cannot run a real browser in the isolated lab, but we can
    generate the same header fingerprints that automation tools
    produce so the IDS Engine 9 has something to detect.

    Mode "naive":   Default Puppeteer with no stealth patches.
                    Leaks HeadlessChrome UA, missing Sec-* headers.
    Mode "stealth": Simulates a bot that has applied common
                    stealth patches (UA patched, navigator.webdriver
                    removed) but still has subtle inconsistencies.
    Mode "human":   Sends fully realistic browser headers.
                    Should NOT trigger Engine 9.
    """

    def __init__(self, host: str, port: int,
                 mode: str = "naive",
                 interval_ms: int = 500,
                 jitter_ms: int = 0):
        self.host        = host
        self.port        = port
        self.mode        = mode
        self.interval_ms = interval_ms
        self.jitter_ms   = jitter_ms
        self.hits        = []
        self.attempts    = 0
        self._stop       = threading.Event()

    def _build_headers(self) -> dict:
        """Build headers appropriate for the chosen mode."""
        if self.mode == "naive":
            return self._naive_headers()
        elif self.mode == "stealth":
            return self._stealth_headers()
        else:
            return self._human_headers()

    def _naive_headers(self) -> dict:
        """
        Default headless Chrome headers — easy to detect.
        Missing Sec-Fetch-*, missing Sec-CH-UA, HeadlessChrome UA.
        """
        return {
            # Dead giveaway: HeadlessChrome in UA
            "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "HeadlessChrome/120.0.0.0 Safari/537.36"),
            "Accept":             PLAYWRIGHT_ACCEPT,
            "Accept-Language":    "en-US,en;q=0.9",
            "Accept-Encoding":    "gzip, deflate",
            "Content-Type":       "application/x-www-form-urlencoded",
            # No Sec-Fetch-* headers — not sent by default in older Playwright
            # No Sec-CH-UA headers
        }

    def _stealth_headers(self) -> dict:
        """
        'Stealth' patched bot — removed HeadlessChrome from UA,
        but still has tells:
          - Accept-Language present but only one locale (bots rarely
            send multiple with realistic q-values)
          - Sec-CH-UA present but formatted slightly wrong
          - Sec-Fetch-User missing (only sent on user-initiated navigation)
          - Accept header matches Playwright default, not real Chrome
        """
        return {
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0.0.0 Safari/537.36"),
            # Real Chrome sends: "Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"
            # Automation tools often get the order or escaping wrong
            "Sec-CH-UA":          '"Chromium";v="120", "Not-A.Brand";v="24"',
            "Sec-CH-UA-Mobile":   "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "Sec-Fetch-Dest":     "document",
            "Sec-Fetch-Mode":     "navigate",
            "Sec-Fetch-Site":     "none",
            # Sec-Fetch-User is MISSING — only browser sends it on real user gestures
            "Accept":             PLAYWRIGHT_ACCEPT,  # Playwright default, not Chrome
            "Accept-Language":    "en-US,en;q=0.9",   # Real Chrome: "en-US,en;q=0.9,fr;q=0.8"
            "Accept-Encoding":    "gzip, deflate, br",
            "Content-Type":       "application/x-www-form-urlencoded",
        }

    def _human_headers(self) -> dict:
        """
        Fully realistic browser headers. Should pass Engine 9.
        Baseline for comparison experiments.
        """
        chrome_version = random.choice(["118", "119", "120", "121"])
        platform = random.choice(['"Windows"', '"macOS"', '"Linux"'])
        return {
            "User-Agent": (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           f"AppleWebKit/537.36 (KHTML, like Gecko) "
                           f"Chrome/{chrome_version}.0.0.0 Safari/537.36"),
            "Sec-CH-UA": (f'"Not_A Brand";v="8", "Chromium";v="{chrome_version}", '
                          f'"Google Chrome";v="{chrome_version}"'),
            "Sec-CH-UA-Mobile":   "?0",
            "Sec-CH-UA-Platform": platform,
            "Sec-Fetch-Dest":     "document",
            "Sec-Fetch-Mode":     "navigate",
            "Sec-Fetch-Site":     "same-origin",
            "Sec-Fetch-User":     "?1",    # Present: real user clicked
            "Accept":             CHROME_ACCEPT,
            "Accept-Language":    "en-US,en;q=0.9,fr;q=0.8",
            "Accept-Encoding":    "gzip, deflate, br",
            "Content-Type":       "application/x-www-form-urlencoded",
            "Cache-Control":      "max-age=0",
            "Upgrade-Insecure-Requests": "1",
        }

    def _attempt(self, email: str, password: str) -> str:
        url     = f"http://{self.host}:{self.port}{LOGIN_PATH}"
        body    = f"email={email}&password={password}".encode()
        headers = self._build_headers()
        req     = urllib.request.Request(url, data=body, method="POST")
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body_resp = resp.read().decode(errors="replace")
                if '"status": "success"' in body_resp or "Welcome" in body_resp:
                    return "hit"
                return "miss"
        except urllib.error.HTTPError as e:
            if e.code == 429:
                return "rate_limited"
            if e.code == 403:
                return "captcha"
            return "miss"
        except Exception:
            return "error"

    def run(self, credentials: list, max_attempts: int = None):
        print(f"\n[BROWSER-BOT] {'='*50}")
        print(f"[BROWSER-BOT] Browser Automation Simulation")
        print(f"[BROWSER-BOT] Mode:   {self.mode.upper()}")
        print(f"[BROWSER-BOT] Target: http://{self.host}:{self.port}{LOGIN_PATH}")
        print(f"[BROWSER-BOT] Teaching points per mode:")
        if self.mode == "naive":
            print(f"[BROWSER-BOT]   HeadlessChrome UA → detected by UA check")
            print(f"[BROWSER-BOT]   Missing Sec-Fetch-* → detected by Engine 9")
        elif self.mode == "stealth":
            print(f"[BROWSER-BOT]   UA patched but Accept-Language only 1 locale")
            print(f"[BROWSER-BOT]   Sec-Fetch-User absent → Engine 9 partial flag")
            print(f"[BROWSER-BOT]   Accept header = Playwright default, not Chrome")
        else:
            print(f"[BROWSER-BOT]   Human-realistic headers → Engine 9 should PASS")
        print(f"[BROWSER-BOT] {'='*50}\n")

        creds = credentials[:max_attempts] if max_attempts else credentials
        for email, password in creds:
            if self._stop.is_set():
                break
            result = self._attempt(email, password)
            self.attempts += 1
            ts = datetime.now().strftime("%H:%M:%S")
            status = {"hit": "✓ HIT", "miss": "✗ miss",
                      "captcha": "⚠ CAPTCHA", "rate_limited": "⚠ RATE-LIMITED",
                      "error": "? ERROR"}.get(result, result)
            if result == "hit":
                self.hits.append((email, password))
            if self.attempts % 10 == 0 or result in ("hit", "captcha", "rate_limited"):
                print(f"[BROWSER-BOT] {ts}  {status:20s}  {email}")

            sleep_ms = self.interval_ms + (
                random.randint(-self.jitter_ms, self.jitter_ms)
                if self.jitter_ms > 0 else 0
            )
            time.sleep(max(50, sleep_ms) / 1000.0)

        print(f"\n[BROWSER-BOT] Done: {self.attempts} attempts, {len(self.hits)} hits")


# ══════════════════════════════════════════════════════════════
#  Part 2: IDS ENGINE 9 — Browser Automation Detection
# ══════════════════════════════════════════════════════════════

class BrowserArtifactDetector:
    """
    IDS Engine 9: Detects browser automation artifacts in HTTP headers.

    Called by fake_portal.py on every request. Scores headers
    for automation signals and returns a risk score 0-100.

    Integrates with the portal's /stats/advanced endpoint.

    Teaching point: "Detect automation artifacts like
    navigator.webdriver, inconsistencies in WebGL or audio
    fingerprints, or signs of Chrome DevTools Protocol (CDP)
    injection." — Castle blog

    At the HTTP level (no JS), we detect:
      - HeadlessChrome / WebDriver strings in UA
      - Missing Sec-Fetch-* headers on a Chrome UA
      - Missing Sec-CH-UA on Chrome 89+
      - Playwright/Puppeteer default Accept strings
      - CDP artifact headers
      - Suspicious Accept-Language (single locale, no q-values)
      - Sec-Fetch-User absent (not sent on automated navigation)
    """

    def __init__(self, alert_threshold: int = 50,
                 window_sec: float = 300.0):
        self.alert_threshold = alert_threshold
        self.window_sec      = window_sec
        self._lock           = threading.Lock()
        # ip → deque of (timestamp, score) tuples
        self._ip_scores: dict = defaultdict(lambda: deque(maxlen=100))
        # ip → alert count
        self._alerts:    dict = defaultdict(int)

    def score_headers(self, headers: dict, src_ip: str = "?") -> dict:
        """
        Score a request's headers for browser automation artifacts.

        headers: dict of lowercase header-name → value
        Returns:
          {
            score:         int 0-100,
            signals:       list[str],   # human-readable findings
            classification: str,        # CLEAN / SUSPECT / BOT
            src_ip:        str,
          }
        """
        signals = []
        score   = 0

        ua = headers.get("user-agent", "").lower()

        # ── Signal 1: HeadlessChrome / automation UA string ──────
        for fragment in AUTOMATION_UA_FRAGMENTS:
            if fragment.lower() in ua:
                signals.append(
                    f"Automation UA fragment '{fragment}' in User-Agent: "
                    f"'{headers.get('user-agent', '')}'"
                )
                score += 40
                break

        # ── Signal 2: Chrome UA but missing Sec-CH-UA ────────────
        is_chrome_ua = "chrome" in ua and "chromium" not in ua.replace("chromium","")
        # Simplification: any UA with "Chrome/8" or higher
        if "chrome/" in ua:
            try:
                ver_str = ua.split("chrome/")[1].split(".")[0]
                chrome_ver = int(ver_str)
            except (IndexError, ValueError):
                chrome_ver = 0
            if chrome_ver >= 89:
                # Chrome 89+ always sends Sec-CH-UA
                if "sec-ch-ua" not in headers:
                    signals.append(
                        "Chrome 89+ UA but Sec-CH-UA header absent — "
                        "headless or automation tool (Chrome Hints not emitted)"
                    )
                    score += 20
                # Check Sec-CH-UA format correctness
                elif headers.get("sec-ch-ua"):
                    cha = headers["sec-ch-ua"]
                    # Real Chrome includes "Not_A Brand" (with underscore)
                    if "Not_A Brand" not in cha and "Not A Brand" not in cha:
                        signals.append(
                            f"Sec-CH-UA format looks non-Chrome: '{cha}' — "
                            "automation tool may have patched UA incorrectly"
                        )
                        score += 10

        # ── Signal 3: Missing Sec-Fetch-* headers ────────────────
        if "chrome/" in ua or "safari/" in ua:
            missing_sec = []
            for h in ("sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"):
                if h not in headers:
                    missing_sec.append(h)
            if missing_sec:
                signals.append(
                    f"Browser UA but missing Sec-Fetch headers: "
                    f"{missing_sec} — older automation (pre-stealth patch)"
                )
                score += 15 * len(missing_sec)

        # ── Signal 4: Sec-Fetch-User absent on form POST ─────────
        # Real browsers send Sec-Fetch-User: ?1 on user-initiated
        # form submissions. Automation never sends it.
        if ("sec-fetch-dest" in headers and
                headers.get("sec-fetch-dest") == "document" and
                "sec-fetch-user" not in headers):
            signals.append(
                "Sec-Fetch-Dest=document but Sec-Fetch-User absent — "
                "form POST initiated by automation, not real user gesture"
            )
            score += 15

        # ── Signal 5: Playwright default Accept string ────────────
        accept = headers.get("accept", "")
        if accept.strip() == PLAYWRIGHT_ACCEPT.strip():
            signals.append(
                f"Accept header exactly matches Playwright default: "
                f"'{accept[:60]}…' — high confidence automation"
            )
            score += 25

        # ── Signal 6: Accept-Language suspicious ─────────────────
        al = headers.get("accept-language", "")
        if not al:
            signals.append("Accept-Language header absent — scripted HTTP client")
            score += 15
        elif al == "en-US,en;q=0.9":
            # Exact single-locale default, no secondary languages
            # Real users almost always have 2+ locales
            signals.append(
                f"Accept-Language='{al}' — single locale, no secondary languages; "
                "typical of automation default config"
            )
            score += 5

        # ── Signal 7: CDP artifact headers ───────────────────────
        for artifact in CDP_ARTIFACTS:
            if artifact in headers:
                signals.append(
                    f"CDP artifact header present: '{artifact}' — "
                    "Chrome DevTools Protocol injection detected"
                )
                score += 35

        # ── Signal 8: Suspicious Content-Type for form POST ──────
        ct = headers.get("content-type", "")
        if ct == "application/x-www-form-urlencoded" and not signals:
            pass  # Normal form POST — no signal alone
        # If UA claims to be Chrome but Content-Type is raw form-encoded
        # without other browser headers, it's suspicious
        if "chrome/" in ua and ct == "application/x-www-form-urlencoded":
            # Real Chrome login forms typically also send Origin and Referer
            if "origin" not in headers and "referer" not in headers:
                signals.append(
                    "Chrome UA with form POST but no Origin or Referer headers — "
                    "automation tool constructing raw HTTP, not a browser form submit"
                )
                score += 10

        score = min(100, score)

        if score == 0:
            classification = "CLEAN"
        elif score < 30:
            classification = "SUSPECT"
        elif score < 60:
            classification = "LIKELY_BOT"
        else:
            classification = "BOT"

        result = dict(
            score=score,
            signals=signals,
            classification=classification,
            src_ip=src_ip,
        )

        # Record for per-IP tracking
        with self._lock:
            self._ip_scores[src_ip].append((time.time(), score))

        return result

    def get_ip_stats(self, src_ip: str) -> dict:
        """Return aggregated automation score for an IP."""
        with self._lock:
            entries = [
                (ts, s) for ts, s in self._ip_scores.get(src_ip, [])
                if time.time() - ts < self.window_sec
            ]
        if not entries:
            return {"n": 0, "avg_score": 0, "max_score": 0, "classification": "CLEAN"}
        scores = [s for _, s in entries]
        avg    = sum(scores) / len(scores)
        mx     = max(scores)
        band   = "CLEAN" if mx < 30 else "SUSPECT" if mx < 60 else "BOT"
        return {"n": len(scores), "avg_score": round(avg, 1),
                "max_score": mx, "classification": band}

    def get_all_stats(self) -> dict:
        """Dump all per-IP stats for /stats/advanced."""
        with self._lock:
            ips = list(self._ip_scores.keys())
        return {ip: self.get_ip_stats(ip) for ip in ips}


# ── Singleton for import by fake_portal.py and ids_detector.py
_detector = BrowserArtifactDetector()


def engine9_score(headers: dict, src_ip: str = "?") -> dict:
    """Drop-in call for portal and IDS integration."""
    return _detector.score_headers(headers, src_ip)


def engine9_get_stats() -> dict:
    return _detector.get_all_stats()


# ── Self-test / demo ──────────────────────────────────────────

def _run_demo():
    det = BrowserArtifactDetector()
    test_cases = [
        ("Naive headless bot", {
            "user-agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36"),
            "accept":        PLAYWRIGHT_ACCEPT,
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate",
            "content-type":  "application/x-www-form-urlencoded",
        }),
        ("Stealth bot (partially patched)", {
            "user-agent":  ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"),
            "sec-ch-ua":         '"Chromium";v="120", "Not-A.Brand";v="24"',
            "sec-ch-ua-mobile":  "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest":    "document",
            "sec-fetch-mode":    "navigate",
            "sec-fetch-site":    "none",
            # sec-fetch-user ABSENT
            "accept":            PLAYWRIGHT_ACCEPT,
            "accept-language":   "en-US,en;q=0.9",
            "accept-encoding":   "gzip, deflate, br",
            "content-type":      "application/x-www-form-urlencoded",
        }),
        ("Real browser (human)", {
            "user-agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"),
            "sec-ch-ua":          '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec-ch-ua-mobile":   "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest":     "document",
            "sec-fetch-mode":     "navigate",
            "sec-fetch-site":     "same-origin",
            "sec-fetch-user":     "?1",
            "accept":             CHROME_ACCEPT,
            "accept-language":    "en-US,en;q=0.9,fr;q=0.8",
            "accept-encoding":    "gzip, deflate, br",
            "content-type":       "application/x-www-form-urlencoded",
            "origin":             "http://192.168.100.20",
            "referer":            "http://192.168.100.20/login",
            "cache-control":      "max-age=0",
            "upgrade-insecure-requests": "1",
        }),
    ]

    print("\nEngine 9 — Browser Automation Detection Demo\n")
    for name, headers in test_cases:
        result = det.score_headers(headers, src_ip="1.2.3.4")
        print(f"  Case: {name}")
        print(f"    Score: {result['score']}/100  |  {result['classification']}")
        for sig in result["signals"]:
            print(f"    ⚠ {sig}")
        if not result["signals"]:
            print(f"    ✓ No automation artifacts detected")
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Browser Bot Simulator + Engine 9 Demo — AUA Research Lab"
    )
    parser.add_argument("--demo",    action="store_true",
                        help="Run Engine 9 header scoring demo")
    parser.add_argument("--attack",  action="store_true",
                        help="Run browser bot simulation against fake portal")
    parser.add_argument("--mode",    default="naive",
                        choices=["naive", "stealth", "human"],
                        help="Bot mode (default: naive)")
    parser.add_argument("--host",    default=DEFAULT_HOST)
    parser.add_argument("--port",    type=int, default=DEFAULT_PORT)
    parser.add_argument("--max",     type=int, default=30)
    args = parser.parse_args()

    print("=" * 60)
    print(" Browser Automation Simulator + IDS Engine 9")
    print(" AUA Botnet Research Lab — ISOLATED VM ONLY")
    print("=" * 60)

    if args.demo or not args.attack:
        _run_demo()

    if args.attack:
        # Synthetic credentials for demo
        creds = [(f"user{i:03d}@example.com", f"pass{i}") for i in range(args.max)]
        bot = BrowserBotSimulator(
            host=args.host, port=args.port,
            mode=args.mode,
            interval_ms=400, jitter_ms=100,
        )
        bot.run(creds, max_attempts=args.max)
