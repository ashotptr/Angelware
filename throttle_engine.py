"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: API Throttling Engine
 Environment: ISOLATED VM LAB ONLY

 Source: "API Rate Limiting vs. Throttling: Key Differences"
         DreamFactory / Kevin McGahey, April 2025

 This module implements the two throttling algorithms described
 in the article that are NOT present anywhere else in the lab:

   Token Bucket  — tokens accumulate at rate R/s; each request
                   consumes one token; bursts allowed up to capacity B.
                   Article: "Tokens accumulate at a fixed rate;
                   each request uses one token."

   Leaky Bucket  — incoming requests pour into a bucket; the bucket
                   leaks (processes) at a fixed rate R/s; overflow is
                   rejected (bucket is full) or queued up to Q items.
                   Article: "Requests are processed at a constant rate,
                   with overflow requests queued."

 DISTINCTION FROM fake_portal.py's RATE LIMITING:
   fake_portal.py uses RATE LIMITING: count requests → reject at N.
   Article distinction:
     Rate Limiting  → "Extra requests rejected outright (HTTP 429)"
     Throttling     → "Extra requests delayed or queued"
   ThrottleMiddleware here wraps Flask and DELAYS requests instead
   of immediately rejecting them, demonstrating the softer UX of
   throttling vs. the hard wall of rate limiting.

 Integration with fake_portal.py:
   from throttle_engine import ThrottleMiddleware, TokenBucketThrottle

   # Wrap the Flask app (throttle by IP, 10 req/s, burst 20):
   throttle = ThrottleMiddleware(app, rate=10, capacity=20)
   app.wsgi_app = throttle

   # Or use per-IP buckets in the /login handler:
   _tok = TokenBucketThrottle(rate=5, capacity=10)
   allowed, wait_s = _tok.consume(src_ip)
   if not allowed:
       time.sleep(wait_s)   # throttle: delay, not reject

 Standalone demo:
   python3 throttle_engine.py          # runs built-in self-test
   python3 throttle_engine.py --demo   # side-by-side comparison
====================================================
"""

import argparse
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Optional, Tuple


# ══════════════════════════════════════════════════════════════
#  TOKEN BUCKET THROTTLE
#  Article: "Manages bursts of traffic while keeping average
#             rates steady."
# ══════════════════════════════════════════════════════════════

class TokenBucketThrottle:
    """
    Per-key token bucket throttle.

    Parameters
    ----------
    rate     : float  tokens added per second
    capacity : int    maximum tokens a bucket can hold (burst ceiling)

    How it works (from Article 1):
      - A virtual bucket starts full (capacity tokens).
      - Each request removes one token.
      - Tokens refill at `rate` per second, up to `capacity`.
      - If the bucket is empty the caller must wait until a token
        accumulates — the request is DELAYED, not rejected.

    Teaching comparison:
      TokenBucket  → allows short bursts (capacity > 1), average
                     rate enforced over time.
      LeakyBucket  → strictly smooths output; no burst allowance.
    """

    def __init__(self, rate: float = 10.0, capacity: int = 20):
        self.rate     = rate       # tokens / second
        self.capacity = capacity   # max tokens
        self._buckets: dict = {}   # key → (tokens, last_refill_ts)
        self._lock    = threading.Lock()

    def _refill(self, tokens: float, last_ts: float, now: float) -> float:
        """Add tokens earned since last_ts, capped at capacity."""
        earned = (now - last_ts) * self.rate
        return min(float(self.capacity), tokens + earned)

    def consume(self, key: str, tokens: float = 1.0) -> Tuple[bool, float]:
        """
        Try to consume `tokens` from key's bucket.

        Returns
        -------
        (allowed, wait_seconds)
          allowed=True  : tokens consumed; caller may proceed immediately
          allowed=False : bucket empty; wait_seconds until token available
        """
        now = time.time()
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = (float(self.capacity), now)
            current_tokens, last_ts = self._buckets[key]

            current_tokens = self._refill(current_tokens, last_ts, now)

            if current_tokens >= tokens:
                self._buckets[key] = (current_tokens - tokens, now)
                return True, 0.0
            else:
                # How long until we have enough tokens?
                deficit       = tokens - current_tokens
                wait_s        = deficit / self.rate
                # Don't store updated tokens here — caller will retry
                self._buckets[key] = (current_tokens, now)
                return False, wait_s

    def consume_blocking(self, key: str) -> float:
        """
        Block until a token is available, then consume it.
        Returns the actual time spent waiting (seconds).
        Implements throttling-as-delay rather than throttling-as-reject.
        """
        total_wait = 0.0
        while True:
            allowed, wait_s = self.consume(key)
            if allowed:
                return total_wait
            time.sleep(min(wait_s, 0.05))   # sleep in small increments
            total_wait += min(wait_s, 0.05)

    def stats(self) -> dict:
        """Return per-key token counts for monitoring."""
        now = time.time()
        with self._lock:
            return {
                k: round(self._refill(tok, ts, now), 2)
                for k, (tok, ts) in self._buckets.items()
            }

    def reset(self, key: str = None) -> None:
        """Reset one key (or all) to full capacity."""
        with self._lock:
            if key:
                self._buckets.pop(key, None)
            else:
                self._buckets.clear()


# ══════════════════════════════════════════════════════════════
#  LEAKY BUCKET THROTTLE
#  Article: "Ensures a steady output, regardless of input rate."
# ══════════════════════════════════════════════════════════════

class LeakyBucketThrottle:
    """
    Per-key leaky bucket throttle.

    Parameters
    ----------
    rate       : float  requests processed per second (the "leak rate")
    queue_size : int    maximum requests queued per key before overflow

    How it works (from Article 1):
      - Incoming requests are poured into a bucket (queue).
      - The bucket leaks at a constant rate: one request leaves every
        (1/rate) seconds, regardless of how fast requests arrive.
      - If the bucket overflows (queue_size exceeded), new requests
        are rejected with HTTP 429 — the ONLY rejection in the system.
        All other requests wait in the queue.

    Teaching comparison:
      - Rate limiting: most requests pass freely, then sudden wall.
      - Leaky bucket: every request is slightly delayed at high load;
        no sudden wall until queue_size is exhausted.
    """

    def __init__(self, rate: float = 5.0, queue_size: int = 50):
        self.rate         = rate         # requests per second
        self.queue_size   = queue_size   # max items queued per key
        self._interval    = 1.0 / rate   # seconds between releases
        self._queues: dict       = {}    # key → deque of (arrive_ts,)
        self._next_slot:  dict   = {}    # key → next_available_ts
        self._lock        = threading.Lock()

    def submit(self, key: str) -> Tuple[bool, float]:
        """
        Submit a request from `key`.

        Returns
        -------
        (accepted, wait_seconds)
          accepted=True  : request queued; caller should sleep wait_seconds
                           then proceed.
          accepted=False : queue full; caller should return HTTP 429.
        """
        now = time.time()
        with self._lock:
            if key not in self._queues:
                self._queues[key]   = deque()
                self._next_slot[key] = now

            q          = self._queues[key]
            next_slot  = self._next_slot[key]

            # Purge completed requests (older than next_slot)
            while q and q[0] <= now:
                q.popleft()

            if len(q) >= self.queue_size:
                # Overflow — reject like HTTP 429
                return False, 0.0

            # Schedule this request at next_slot (or now if slot is free)
            slot = max(next_slot, now)
            q.append(slot + self._interval)
            self._next_slot[key] = slot + self._interval
            wait_s = max(0.0, slot - now)
            return True, wait_s

    def submit_blocking(self, key: str) -> bool:
        """
        Submit and block until the request can be processed.
        Returns False if the queue is full (HTTP 429 equivalent).
        """
        accepted, wait_s = self.submit(key)
        if not accepted:
            return False
        if wait_s > 0:
            time.sleep(wait_s)
        return True

    def stats(self) -> dict:
        """Return per-key queue depth."""
        with self._lock:
            return {k: len(q) for k, q in self._queues.items()}


# ══════════════════════════════════════════════════════════════
#  IP-RATE WINDOW (Simple rate limiter — mirrors Article table)
#  Article table row: "Rate Limiting: Extra Requests Rejected outright"
#  Complementary to throttling: use BOTH for layered control.
# ══════════════════════════════════════════════════════════════

class IPRateWindow:
    """
    Sliding-window rate limiter (mirrors what fake_portal.py does for
    username rate limiting, here generalised to any key).

    Extra requests are REJECTED (HTTP 429) — this is RATE LIMITING
    as defined in Article 1, NOT throttling.

    Article quote:
      "Per Second: 10 requests → HTTP 429 + 1-second delay
       Per Minute: 100 requests → HTTP 429 + 60-second delay"

    This class implements that table literally.
    """

    def __init__(self, max_requests: int, window_sec: float):
        self.max_requests = max_requests
        self.window_sec   = window_sec
        self._windows: dict = defaultdict(deque)
        self._lock     = threading.Lock()

    def is_allowed(self, key: str) -> Tuple[bool, int]:
        """
        Check if key is below the rate limit.

        Returns (allowed, retry_after_seconds).
        retry_after_seconds is 0 if allowed, else seconds to wait.
        """
        now    = time.time()
        cutoff = now - self.window_sec
        with self._lock:
            dq = self._windows[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.max_requests:
                # Earliest request + window_sec = when limit resets
                retry = int(dq[0] + self.window_sec - now) + 1
                return False, retry
            dq.append(now)
            return True, 0


# ══════════════════════════════════════════════════════════════
#  FLASK WSGI MIDDLEWARE WRAPPER
#  Wraps fake_portal.py's Flask app transparently.
# ══════════════════════════════════════════════════════════════

class ThrottleMiddleware:
    """
    WSGI middleware that applies TokenBucket throttling to every
    request, by remote IP.

    Usage (in fake_portal.py):
        from throttle_engine import ThrottleMiddleware
        app.wsgi_app = ThrottleMiddleware(app.wsgi_app, rate=10, capacity=20)

    Article teaching point:
      Unlike the rate limiter (which rejects immediately), this
      middleware delays requests until a token is available.
      Users experience "slower response or delay" not "abrupt denial" —
      matching the Article's "User Impact" row for Throttling.

    The delay is bounded: if a request would have to wait >
    MAX_WAIT_SEC, it is rejected (HTTP 429) instead of queued
    indefinitely — this is the queue_size concept from LeakyBucket.
    """

    MAX_WAIT_SEC = 5.0   # reject if wait would exceed this

    def __init__(self, wsgi_app, rate: float = 10.0, capacity: int = 20):
        self.app    = wsgi_app
        self.bucket = TokenBucketThrottle(rate=rate, capacity=capacity)

    def __call__(self, environ, start_response):
        remote_ip = environ.get("REMOTE_ADDR", "unknown")
        allowed, wait_s = self.bucket.consume(remote_ip)

        if not allowed:
            if wait_s > self.MAX_WAIT_SEC:
                # Queue would be too long — reject
                body = b'{"status":"error","message":"Too many requests. Throttled."}'
                start_response(
                    "429 Too Many Requests",
                    [("Content-Type", "application/json"),
                     ("Retry-After", str(int(wait_s))),
                     ("Content-Length", str(len(body)))],
                )
                return [body]
            # Throttle: sleep, then proceed
            time.sleep(wait_s)
            self.bucket.consume(remote_ip)   # consume the now-available token

        return self.app(environ, start_response)


# ══════════════════════════════════════════════════════════════
#  SELF-TEST / DEMO
# ══════════════════════════════════════════════════════════════

def _demo_token_bucket():
    print("\n── Token Bucket (rate=3/s, capacity=5) ──")
    bucket = TokenBucketThrottle(rate=3.0, capacity=5)
    # Burst: first 5 requests should succeed instantly
    for i in range(1, 8):
        ok, wait = bucket.consume("test_ip")
        tag = "OK" if ok else f"WAIT {wait:.3f}s"
        print(f"  Request {i:2d}: {tag}")
    print("  → Burst of 5 consumed instantly; next requests throttled.")


def _demo_leaky_bucket():
    print("\n── Leaky Bucket (rate=2/s, queue_size=4) ──")
    lb = LeakyBucketThrottle(rate=2.0, queue_size=4)
    for i in range(1, 8):
        ok, wait = lb.submit("test_ip")
        if ok:
            print(f"  Request {i:2d}: accepted — wait {wait:.3f}s before processing")
        else:
            print(f"  Request {i:2d}: REJECTED (queue full → HTTP 429)")


def _demo_rate_window():
    print("\n── IP Rate Window (max=3 per 10s) ──")
    rw = IPRateWindow(max_requests=3, window_sec=10)
    for i in range(1, 6):
        ok, retry = rw.is_allowed("192.168.1.1")
        tag = "allowed" if ok else f"BLOCKED — retry in {retry}s"
        print(f"  Request {i}: {tag}")
    print("  → Rate limiting rejects immediately at max=3; throttling would delay instead.")


def _demo_comparison():
    """
    Side-by-side comparison matching the Article's Quick Comparison table.
    """
    print("\n" + "="*60)
    print("  Article 1 Quick Comparison — Live Demo")
    print("="*60)
    print("""
  Feature         | Rate Limiting          | Throttling (Token Bucket)
  --------------- | ---------------------- | -------------------------
  Extra Requests  | Rejected (HTTP 429)    | Delayed (token wait)
  Server Load     | Lower (no queue mgmt)  | Higher (manages wait)
  User Impact     | Abrupt denial          | Slower response
  Best For        | Abuse prevention       | Traffic surges
    """)
    print("Rate Limiting demo (IPRateWindow, max=2 per 10s):")
    rw = IPRateWindow(max_requests=2, window_sec=10)
    for i in range(1, 5):
        ok, retry = rw.is_allowed("bot_ip")
        print(f"  Req {i}: {'PASS' if ok else f'REJECTED (429) retry in {retry}s'}")

    print("\nThrottling demo (TokenBucket, rate=2/s, capacity=2):")
    tb = TokenBucketThrottle(rate=2.0, capacity=2)
    for i in range(1, 5):
        ok, wait = tb.consume("bot_ip")
        if ok:
            print(f"  Req {i}: PASS (immediate)")
        else:
            print(f"  Req {i}: throttled → wait {wait:.2f}s (not rejected)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Throttle Engine — self-test")
    parser.add_argument("--demo", action="store_true",
                        help="Show side-by-side rate-limiting vs throttling comparison")
    args = parser.parse_args()

    if args.demo:
        _demo_comparison()
    else:
        print("Throttle Engine Self-Test")
        print("  Source: Article 1 — API Rate Limiting vs. Throttling (DreamFactory)")
        _demo_token_bucket()
        _demo_leaky_bucket()
        _demo_rate_window()
        print("\nAll demos complete.")
        print("\nIntegration hint:")
        print("  from throttle_engine import ThrottleMiddleware, TokenBucketThrottle")
        print("  app.wsgi_app = ThrottleMiddleware(app.wsgi_app, rate=10, capacity=20)")
