#!/usr/bin/env python3
"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Behavioral Biometrics + Passwordless Auth
 Environment: ISOLATED VM LAB ONLY
====================================================

Source: Frontegg "Credential Stuffing: What It Is, How It Works and
7 Ways to Prevent It" §6-7

Implements the two credential-stuffing defences from that article that
are NOT already present in fake_portal.py:

Defense 6 — Passwordless Authentication
  Generates single-use email tokens as an alternative login flow.
  Bots cannot intercept email tokens from a real inbox, so this
  eliminates the password attack surface entirely when activated.

Defense 7 — Behavioral Biometrics
  "Behavioural biometrics authenticate users based on unique patterns
   like typing speed, mouse movements, or interaction style."

  Implementation:
    a) TypingCadenceProfile  — models inter-keystroke timing (IKT)
         Builds a per-user Gaussian baseline from normal sessions.
         Flags sessions whose IKT mean or CV deviates from the
         baseline by more than Z_THRESHOLD standard deviations.

    b) MouseMovementProfile  — models mouse movement entropy
         Real users produce non-linear, curved paths.
         Bots produce perfectly straight or jerky movements.
         Entropy score distinguishes organic from synthetic paths.

    c) SessionBiometricScorer — combines both signals into a
         0-100 bot probability score for integration with
         fake_portal.py and ids_detector.py.

Integration
───────────
  In fake_portal.py /login POST handler, add:

    from behavioral_biometrics import get_scorer
    scorer = get_scorer()
    bio_score = scorer.score_session(
        email        = email,
        ikt_samples  = json.loads(form.get("ikt_data", "[]")),
        mouse_events = json.loads(form.get("mouse_data", "[]")),
        src_ip       = request.remote_addr,
    )
    if bio_score["bot_probability"] > 0.75:
        # Treat as bot — escalate to 2FA / CAPTCHA / tarpit

  The login form should include hidden JS that collects:
    ikt_data    = JSON array of inter-keystroke intervals in ms
    mouse_data  = JSON array of {x, y, t} movement samples

HTML snippet (include in LOGIN_PAGE_TMPL inside fake_portal.py):
  <script>
    const ikt=[];let last=0;
    document.querySelector('[name=password]').addEventListener('keydown',e=>{
      const now=Date.now();if(last)ikt.push(now-last);last=now;
    });
    const mouse=[];
    document.addEventListener('mousemove',e=>{
      mouse.push({x:e.clientX,y:e.clientY,t:Date.now()});
    });
    document.querySelector('form').addEventListener('submit',()=>{
      document.querySelector('[name=ikt_data]').value=JSON.stringify(ikt);
      document.querySelector('[name=mouse_data]').value=JSON.stringify(mouse.slice(-50));
    });
  </script>
  <input type="hidden" name="ikt_data">
  <input type="hidden" name="mouse_data">
"""

import hashlib
import hmac
import math
import os
import secrets
import statistics
import threading
import time
from collections import defaultdict, deque
from typing import List, Optional


# ── Configuration ─────────────────────────────────────────────
Z_THRESHOLD          = 2.5    # std-devs from baseline → bot flag
MIN_IKT_SAMPLES      = 5      # minimum keystrokes to score
MIN_MOUSE_SAMPLES    = 10     # minimum mouse points to score
PROFILE_TTL_SEC      = 86400  # 24 h — how long a biometric profile lives
TOKEN_TTL_SEC        = 900    # 15 min — passwordless token lifetime
EWMA_ALPHA           = 0.1    # profile adaptation speed


# ══════════════════════════════════════════════════════════════
#  TYPING CADENCE PROFILE
# ══════════════════════════════════════════════════════════════

class TypingCadenceProfile:
    """
    Per-user inter-keystroke timing (IKT) model.

    After MIN_PROFILE_SESSIONS sessions the profile is "established".
    Subsequent sessions are scored against the baseline:
      z_score = (session_mean - profile_mean) / profile_stddev

    Bots typically produce:
      • Very low IKT mean  (< 50 ms) — paste / API injection
      • Very low CV        (< 0.10)  — perfectly metronomic
      • Bimodal spikes     (Ctrl+V pattern)

    Legitimate users produce:
      • IKT mean 100-300 ms
      • CV 0.3-0.8  (natural variation)
    """

    MIN_PROFILE_SESSIONS = 3

    def __init__(self, user_id: str):
        self.user_id        = user_id
        self._lock          = threading.Lock()
        self._session_means: deque = deque(maxlen=50)
        self._session_cvs:   deque = deque(maxlen=50)
        self._n_sessions    = 0
        self._profile_mean  = None
        self._profile_stddev = 50.0  # seed
        self._last_seen     = time.time()

    def _cv(self, samples: list) -> float:
        """Coefficient of variation of IKT samples."""
        if len(samples) < 2:
            return 0.0
        m = statistics.mean(samples)
        if m == 0:
            return 0.0
        return statistics.stdev(samples) / m

    def update(self, ikt_samples: list):
        """
        Record a new session's IKT samples and update the rolling baseline.
        """
        if len(ikt_samples) < MIN_IKT_SAMPLES:
            return
        mean = statistics.mean(ikt_samples)
        cv   = self._cv(ikt_samples)
        with self._lock:
            self._session_means.append(mean)
            self._session_cvs.append(cv)
            self._n_sessions += 1
            self._last_seen   = time.time()
            # EWMA profile update
            if self._profile_mean is None:
                self._profile_mean = mean
            else:
                self._profile_mean = (
                    EWMA_ALPHA * mean
                    + (1 - EWMA_ALPHA) * self._profile_mean
                )
            if len(self._session_means) >= 2:
                self._profile_stddev = max(
                    10.0, statistics.stdev(list(self._session_means))
                )

    def score(self, ikt_samples: list) -> dict:
        """
        Score a session's IKT against the established profile.

        Returns:
          {
            anomalous    : bool,
            bot_signal   : str,  ("paste_injection"|"metronomic"|"organic"|"insufficient_data")
            z_score_mean : float,
            session_mean : float,
            session_cv   : float,
            profile_mean : float | None,
          }
        """
        if len(ikt_samples) < MIN_IKT_SAMPLES:
            return {"anomalous": False, "bot_signal": "insufficient_data",
                    "z_score_mean": 0.0, "session_mean": 0.0,
                    "session_cv": 0.0, "profile_mean": None}

        s_mean = statistics.mean(ikt_samples)
        s_cv   = self._cv(ikt_samples)
        anomalous   = False
        bot_signal  = "organic"

        # Signal 1: paste/API injection (< 50 ms mean IKT)
        if s_mean < 50:
            anomalous  = True
            bot_signal = "paste_injection"
            return {"anomalous": True, "bot_signal": bot_signal,
                    "z_score_mean": 99.0, "session_mean": s_mean,
                    "session_cv": s_cv, "profile_mean": self._profile_mean}

        # Signal 2: metronomic bot (CV < 0.10)
        if s_cv < 0.10 and len(ikt_samples) >= 8:
            anomalous  = True
            bot_signal = "metronomic"

        # Signal 3: z-score against established profile
        z = 0.0
        with self._lock:
            established = self._n_sessions >= self.MIN_PROFILE_SESSIONS
            if established and self._profile_mean is not None:
                z = abs(s_mean - self._profile_mean) / max(
                    self._profile_stddev, 10.0
                )
                if z > Z_THRESHOLD:
                    anomalous  = True
                    bot_signal = "profile_deviation"

        return {
            "anomalous":    anomalous,
            "bot_signal":   bot_signal,
            "z_score_mean": round(z, 2),
            "session_mean": round(s_mean, 1),
            "session_cv":   round(s_cv, 3),
            "profile_mean": round(self._profile_mean, 1)
                            if self._profile_mean else None,
        }


# ══════════════════════════════════════════════════════════════
#  MOUSE MOVEMENT PROFILE
# ══════════════════════════════════════════════════════════════

class MouseMovementProfile:
    """
    Mouse movement entropy and linearity scorer.

    Real users produce curved, high-entropy paths with natural
    acceleration/deceleration.  Bots produce:
      • Perfectly straight lines (Selenium default)
      • No movement at all (curl/API)
      • Jerky zigzag (synthetic random walker)

    Metrics:
      path_entropy   — Shannon entropy of direction changes
      straightness   — 1 - (direct_distance / path_length)
      speed_cv       — coefficient of variation of inter-event speed
    """

    def score(self, mouse_events: list) -> dict:
        """
        Score a list of {x, y, t} mouse events.

        Returns:
          {
            bot_probability : float  0-1,
            signals         : list[str],
            path_entropy    : float,
            straightness    : float,
            speed_cv        : float,
          }
        """
        if len(mouse_events) < MIN_MOUSE_SAMPLES:
            return {"bot_probability": 0.3, "signals": ["insufficient_data"],
                    "path_entropy": 0.0, "straightness": 0.0, "speed_cv": 0.0}

        try:
            xs = [float(e["x"]) for e in mouse_events]
            ys = [float(e["y"]) for e in mouse_events]
            ts = [float(e["t"]) for e in mouse_events]
        except (KeyError, TypeError, ValueError):
            return {"bot_probability": 0.5, "signals": ["parse_error"],
                    "path_entropy": 0.0, "straightness": 0.0, "speed_cv": 0.0}

        signals    = []
        bot_score  = 0.0

        # ── No movement ────────────────────────────────────────
        if max(xs) - min(xs) < 5 and max(ys) - min(ys) < 5:
            return {"bot_probability": 0.90, "signals": ["no_movement"],
                    "path_entropy": 0.0, "straightness": 1.0, "speed_cv": 0.0}

        # ── Path straightness ──────────────────────────────────
        direct_dist = math.sqrt(
            (xs[-1] - xs[0]) ** 2 + (ys[-1] - ys[0]) ** 2
        )
        path_len = sum(
            math.sqrt((xs[i] - xs[i - 1]) ** 2 + (ys[i] - ys[i - 1]) ** 2)
            for i in range(1, len(xs))
        )
        straightness = direct_dist / max(path_len, 1.0)
        if straightness > 0.95:
            signals.append("straight_line_movement")
            bot_score += 0.4

        # ── Direction entropy ──────────────────────────────────
        angles = []
        for i in range(1, len(xs)):
            dx, dy = xs[i] - xs[i - 1], ys[i] - ys[i - 1]
            if abs(dx) > 0.1 or abs(dy) > 0.1:
                angles.append(int(math.degrees(math.atan2(dy, dx))) % 360)
        path_entropy = 0.0
        if angles:
            # Discretise into 16 buckets (22.5° each)
            buckets = [0] * 16
            for a in angles:
                buckets[a // 23] += 1
            total = len(angles)
            for b in buckets:
                if b:
                    p = b / total
                    path_entropy -= p * math.log2(p)
            # Max entropy for 16 buckets = log2(16) = 4.0
            # Real users: > 2.5.  Bots: < 1.5
            if path_entropy < 1.5:
                signals.append("low_direction_entropy")
                bot_score += 0.3

        # ── Speed consistency ──────────────────────────────────
        speeds = []
        for i in range(1, len(xs)):
            dt = (ts[i] - ts[i - 1]) / 1000.0  # s
            if dt > 0:
                dist = math.sqrt(
                    (xs[i] - xs[i - 1]) ** 2 + (ys[i] - ys[i - 1]) ** 2
                )
                speeds.append(dist / dt)
        speed_cv = 0.0
        if len(speeds) >= 3:
            m = statistics.mean(speeds)
            speed_cv = statistics.stdev(speeds) / max(m, 1.0)
            if speed_cv < 0.15:
                signals.append("constant_speed")
                bot_score += 0.3

        return {
            "bot_probability": min(1.0, bot_score),
            "signals":         signals,
            "path_entropy":    round(path_entropy, 3),
            "straightness":    round(straightness, 3),
            "speed_cv":        round(speed_cv, 3),
        }


# ══════════════════════════════════════════════════════════════
#  SESSION BIOMETRIC SCORER  (combined signal)
# ══════════════════════════════════════════════════════════════

class SessionBiometricScorer:
    """
    Combines typing cadence + mouse movement into a single bot-probability
    score per session.

    Integration point for fake_portal.py:
      scorer = get_scorer()
      result = scorer.score_session(email, ikt_samples, mouse_events, src_ip)
      if result["bot_probability"] > 0.75:
          # escalate
    """

    def __init__(self):
        self._profiles: dict      = {}          # email → TypingCadenceProfile
        self._mouse               = MouseMovementProfile()
        self._lock                = threading.Lock()

    def _get_profile(self, user_id: str) -> TypingCadenceProfile:
        with self._lock:
            if user_id not in self._profiles:
                self._profiles[user_id] = TypingCadenceProfile(user_id)
            return self._profiles[user_id]

    def score_session(
        self,
        email:        str,
        ikt_samples:  list,
        mouse_events: list,
        src_ip:       str  = "0.0.0.0",
        update_profile: bool = True,
    ) -> dict:
        """
        Score a login session.

        Args:
          email        : user identifier
          ikt_samples  : list of inter-keystroke intervals in ms
          mouse_events : list of {x, y, t} dicts
          src_ip       : source IP (for logging correlation)
          update_profile: whether to update the user's baseline on success

        Returns:
          {
            bot_probability  : float 0-1,
            anomalous        : bool,
            confidence       : str ("HIGH"|"MEDIUM"|"LOW"),
            typing_result    : dict,
            mouse_result     : dict,
            alerts           : list[str],
          }
        """
        profile     = self._get_profile(email)
        typing_res  = profile.score(ikt_samples)
        mouse_res   = self._mouse.score(mouse_events)

        # Weighted combination
        #  typing has more weight (more discriminating for bots)
        typing_weight = 0.65
        mouse_weight  = 0.35

        typing_prob = 0.9 if typing_res["anomalous"] else 0.1
        mouse_prob  = mouse_res["bot_probability"]
        combined    = typing_weight * typing_prob + mouse_weight * mouse_prob

        alerts = []
        if typing_res["anomalous"]:
            alerts.append(
                f"BIOMETRIC ANOMALY [typing]: {typing_res['bot_signal']} "
                f"(IKT mean={typing_res['session_mean']}ms, "
                f"CV={typing_res['session_cv']:.3f})"
            )
        if mouse_res["bot_probability"] > 0.60:
            alerts.append(
                f"BIOMETRIC ANOMALY [mouse]: {', '.join(mouse_res['signals'])} "
                f"(entropy={mouse_res['path_entropy']:.2f}, "
                f"straightness={mouse_res['straightness']:.2f})"
            )

        # Confidence based on data availability
        has_typing = len(ikt_samples) >= MIN_IKT_SAMPLES
        has_mouse  = len(mouse_events) >= MIN_MOUSE_SAMPLES
        confidence = (
            "HIGH"   if has_typing and has_mouse else
            "MEDIUM" if has_typing or has_mouse  else
            "LOW"
        )

        # Update profile for clean sessions (don't pollute with bot traffic)
        if update_profile and not typing_res["anomalous"] and has_typing:
            profile.update(ikt_samples)

        return {
            "bot_probability": round(combined, 3),
            "anomalous":       combined > 0.60,
            "confidence":      confidence,
            "typing_result":   typing_res,
            "mouse_result":    mouse_res,
            "alerts":          alerts,
        }

    def forget(self, email: str):
        """Remove a user's biometric profile (GDPR erasure)."""
        with self._lock:
            self._profiles.pop(email, None)


# ══════════════════════════════════════════════════════════════
#  DEFENSE 6 — PASSWORDLESS AUTH  (Doc 3 §6)
# ══════════════════════════════════════════════════════════════

class PasswordlessManager:
    """
    Single-use magic-link token manager.

    Docs source: "Passwordless authentication removes the dependence on
    passwords altogether, eliminating a significant vulnerability
    exploited by credential stuffing."

    Flow:
      1. User submits email to POST /passwordless/request
      2. Manager generates a HMAC-signed token (URL-safe, 32 bytes)
      3. Token delivered out-of-band (email / SMS — simulated in lab)
      4. User submits token to POST /passwordless/verify
      5. Manager verifies token, marks as used, issues session

    Bots cannot intercept real inbox tokens, so stuffing is impossible
    regardless of whether the email:password pair is in a breach dump.
    """

    def __init__(self, secret: str = None, ttl: int = TOKEN_TTL_SEC):
        self._secret    = (secret or os.environ.get(
            "PASSWORDLESS_SECRET", "AUA_LAB_PASSWORDLESS_2026"
        )).encode()
        self._ttl       = ttl
        self._lock      = threading.Lock()
        # token → {email, expires_at, used}
        self._tokens: dict = {}

    def _sign(self, token_bytes: bytes, email: str) -> str:
        """Produce HMAC-SHA256 of token||email for integrity."""
        return hmac.new(
            self._secret,
            msg=token_bytes + email.encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()

    def request_token(self, email: str) -> dict:
        """
        Generate a single-use login token for *email*.

        Returns:
          {
            token    : str   (opaque URL-safe value — send via email)
            email    : str,
            expires  : str   (ISO timestamp),
          }
        """
        token_bytes = secrets.token_bytes(32)
        token_str   = token_bytes.hex()
        sig         = self._sign(token_bytes, email)
        full_token  = f"{token_str}.{sig[:16]}"   # shortened sig
        expires_at  = time.time() + self._ttl

        with self._lock:
            self._tokens[full_token] = {
                "email":      email,
                "expires_at": expires_at,
                "used":       False,
            }

        # In a real system this would dispatch an email.
        # In lab mode: print to console so the test harness can collect it.
        print(f"[PASSWORDLESS] Token for {email}: {full_token} "
              f"(expires in {self._ttl}s)")

        return {
            "token":   full_token,
            "email":   email,
            "expires": datetime.datetime.fromtimestamp(
                expires_at
            ).isoformat() if _dt_imported() else str(expires_at),
        }

    def verify_token(self, token: str, email: str) -> dict:
        """
        Verify a token submitted by the user.

        Returns:
          {
            valid   : bool,
            reason  : str,
            email   : str | None,
          }
        """
        with self._lock:
            rec = self._tokens.get(token)
            if rec is None:
                return {"valid": False, "reason": "token_not_found", "email": None}
            if rec["used"]:
                return {"valid": False, "reason": "token_already_used", "email": None}
            if time.time() > rec["expires_at"]:
                return {"valid": False, "reason": "token_expired", "email": None}
            if rec["email"].lower() != email.lower():
                return {"valid": False, "reason": "email_mismatch", "email": None}
            # Mark consumed — single-use
            rec["used"] = True

        return {"valid": True, "reason": "ok", "email": email}

    def _purge_expired(self):
        """Remove expired tokens (call periodically)."""
        now = time.time()
        with self._lock:
            expired = [t for t, r in self._tokens.items()
                       if r["used"] or now > r["expires_at"] + 3600]
            for t in expired:
                del self._tokens[t]

    def stats(self) -> dict:
        with self._lock:
            total   = len(self._tokens)
            active  = sum(1 for r in self._tokens.values()
                          if not r["used"] and time.time() <= r["expires_at"])
            expired = total - active
        return {"total": total, "active": active, "expired": expired}


def _dt_imported() -> bool:
    try:
        import datetime as _dt  # noqa
        return True
    except ImportError:
        return False


import datetime  # noqa: E402  (needed inside PasswordlessManager)


# ══════════════════════════════════════════════════════════════
#  MODULE-LEVEL SINGLETONS
# ══════════════════════════════════════════════════════════════

_scorer_instance:    Optional[SessionBiometricScorer] = None
_passwordless_instance: Optional[PasswordlessManager] = None
_singleton_lock = threading.Lock()


def get_scorer() -> SessionBiometricScorer:
    global _scorer_instance
    with _singleton_lock:
        if _scorer_instance is None:
            _scorer_instance = SessionBiometricScorer()
    return _scorer_instance


def get_passwordless_manager() -> PasswordlessManager:
    global _passwordless_instance
    with _singleton_lock:
        if _passwordless_instance is None:
            _passwordless_instance = PasswordlessManager()
    return _passwordless_instance


# ══════════════════════════════════════════════════════════════
#  SELF-TEST
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import random

    print("=" * 60)
    print("Behavioral Biometrics — self-test")
    print("=" * 60)

    scorer = get_scorer()
    rng    = random.Random(42)

    # ── Typing: legitimate user ────────────────────────────────
    print("\n--- Legitimate user typing ---")
    human_ikt = [rng.gauss(180, 60) for _ in range(12)]
    res = scorer.score_session(
        "alice@example.com", human_ikt,
        [{"x": i * 10 + rng.gauss(0, 3),
          "y": i * 5  + rng.gauss(0, 3),
          "t": 1000 + i * 50 + rng.randint(-20, 20)}
         for i in range(20)],
        update_profile=True,
    )
    print(f"  bot_probability={res['bot_probability']:.2f}  "
          f"anomalous={res['anomalous']}  confidence={res['confidence']}")

    # ── Typing: paste injection (bot) ──────────────────────────
    print("\n--- Bot: paste injection (IKT < 50 ms) ---")
    bot_ikt = [rng.gauss(12, 2) for _ in range(12)]
    res = scorer.score_session(
        "alice@example.com", bot_ikt,
        [{"x": i * 5, "y": 0, "t": 1000 + i * 8} for i in range(20)],
        update_profile=False,
    )
    print(f"  bot_probability={res['bot_probability']:.2f}  "
          f"signal={res['typing_result']['bot_signal']}")
    for alert in res["alerts"]:
        print(f"  ⚠  {alert}")

    # ── Typing: metronomic bot ─────────────────────────────────
    print("\n--- Bot: metronomic (CV < 0.10) ---")
    metro_ikt = [150.0 + rng.gauss(0, 3) for _ in range(12)]  # CV ≈ 0.02
    res = scorer.score_session(
        "alice@example.com", metro_ikt,
        [{"x": i, "y": 0, "t": 1000 + i * 150} for i in range(20)],
        update_profile=False,
    )
    print(f"  bot_probability={res['bot_probability']:.2f}  "
          f"signal={res['typing_result']['bot_signal']}")

    # ── Passwordless token test ────────────────────────────────
    print("\n--- Passwordless auth ---")
    pm = get_passwordless_manager()
    tok = pm.request_token("bob@example.com")["token"]
    v1  = pm.verify_token(tok, "bob@example.com")
    v2  = pm.verify_token(tok, "bob@example.com")   # second use — should fail
    print(f"  First verify:  valid={v1['valid']} reason={v1['reason']}")
    print(f"  Replay verify: valid={v2['valid']} reason={v2['reason']}")
    print(f"  Token stats: {pm.stats()}")
