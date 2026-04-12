"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Adaptive / ML Anomaly Detection (IDS Engine 8)
 Environment: ISOLATED VM LAB ONLY
====================================================

Replaces static CV thresholds with an adaptive baseline that
learns normal traffic patterns and flags statistical anomalies.

Problem with static thresholds (e.g. CV < 0.15):
  - The threshold was chosen empirically.  A service with naturally
    fast machine-to-machine clients (e.g. mobile apps with push) would
    have many legitimate sessions near the threshold.
  - A slow-mode attacker (jitter_ms ≥ 500) deliberately targets the
    threshold and can tune their jitter to stay just above it.

Adaptive approach:
  - EWMA Baseline: learns the rolling mean and variance of the CV
    distribution during normal (non-attack) traffic.
  - Z-score Detection: flags sessions whose CV is LOWER than the
    baseline by more than Z_THRESHOLD standard deviations.
  - As normal traffic baseline shifts (e.g. new app version runs
    faster), the detector adapts — no manual re-tuning required.
  - Multivariate mode: combines CV z-score + request rate z-score +
    success-rate z-score into a single anomaly score.

Optional sklearn IsolationForest:
  - If scikit-learn is installed, also trains an IsolationForest on
    feature vectors [cv, rate, success_pct, unknown_acct_pct].
  - The forest is trained on a warmup window and updated every
    RETRAIN_EVERY samples.
  - Contamination = 0.05 (expected 5% anomalous during warmup).

Article mapping (Castle blog):
  "Evolving detection signals: the bot ecosystem moves quickly...
   static detections degrade fast.  Your system needs to ingest
   fresh signals, retrain detection logic, and respond to
   campaign-level shifts as they emerge."

Usage:
  from ml_detector import AdaptiveDetector
  det = AdaptiveDetector()
  result = det.update(cv=0.08, rate=2.1, success_pct=1.2, unknown_pct=60.0)
  if result["anomalous"]:
      print(result["reason"])
"""

import math
import time
import threading
from collections import deque
from typing import Optional

# ── Optional sklearn import ───────────────────────────────────
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    _SKLEARN_OK = True
except ImportError:
    _SKLEARN_OK = False

# ── Configuration ─────────────────────────────────────────────
EWMA_ALPHA        = 0.05   # EWMA smoothing factor (lower = slower adaptation)
Z_THRESHOLD       = 2.5    # z-scores below this (for CV) → flag as anomalous
RATE_Z_THRESHOLD  = 3.0    # z-score above this for request rate → flag
WARMUP_SAMPLES    = 20     # samples before adaptive detection activates
RETRAIN_EVERY     = 50     # retrain IsolationForest every N samples
IF_CONTAMINATION  = 0.05   # fraction assumed anomalous during training


class EWMABaseline:
    """
    Exponentially Weighted Moving Average baseline for a scalar signal.

    Tracks mean and variance using Welford-style EWMA:
      mean_n  = alpha * x + (1-alpha) * mean_(n-1)
      var_n   = (1-alpha) * (var_(n-1) + alpha * (x - mean_(n-1))^2)

    z_score(x) = (x - mean) / stddev
      Positive z → x is above baseline
      Negative z → x is below baseline (low CV = rigid bot timing)
    """

    def __init__(self, alpha: float = EWMA_ALPHA):
        self.alpha   = alpha
        self.mean    = None
        self.var     = 0.01   # small non-zero seed to avoid div-by-zero
        self.n       = 0
        self._lock   = threading.Lock()

    def update(self, x: float):
        with self._lock:
            if self.mean is None:
                self.mean = x
                self.n    = 1
                return
            delta     = x - self.mean
            self.mean += self.alpha * delta
            self.var   = (1 - self.alpha) * (self.var + self.alpha * delta ** 2)
            self.n    += 1

    @property
    def stddev(self) -> float:
        with self._lock:
            return math.sqrt(max(self.var, 1e-9))

    def z_score(self, x: float) -> float:
        with self._lock:
            if self.mean is None:
                return 0.0
            return (x - self.mean) / max(math.sqrt(self.var), 1e-9)

    @property
    def ready(self) -> bool:
        with self._lock:
            return self.n >= WARMUP_SAMPLES

    def snapshot(self) -> dict:
        with self._lock:
            return dict(mean=round(self.mean or 0, 4),
                        stddev=round(self.stddev, 4),
                        n=self.n)


class AdaptiveDetector:
    """
    Adaptive anomaly detector for credential stuffing signals.

    Maintains EWMA baselines for:
      - cv          (low values = bot-like rigid timing)
      - rate        (high values = volumetric surge)
      - success_pct (low values = spraying wrong passwords)
      - unknown_pct (high values = bulk breach dump)

    Also maintains an optional IsolationForest (sklearn) trained
    on feature vectors, retrained periodically on normal-traffic
    samples (those not flagged by the EWMA detector).

    Call update() for every new measurement window.
    Returns a result dict; result["anomalous"] = True triggers alert.
    """

    def __init__(self,
                 z_cv: float = Z_THRESHOLD,
                 z_rate: float = RATE_Z_THRESHOLD,
                 use_forest: bool = _SKLEARN_OK):
        self.z_cv     = z_cv
        self.z_rate   = z_rate
        self.use_forest = use_forest and _SKLEARN_OK
        self._lock    = threading.Lock()

        # EWMA baselines (one per feature)
        self.cv_base       = EWMABaseline()
        self.rate_base     = EWMABaseline()
        self.success_base  = EWMABaseline()
        self.unknown_base  = EWMABaseline()

        # IsolationForest state
        self._train_buf: deque = deque(maxlen=500)  # rolling training window
        self._forest    = None
        self._retrain_counter = 0

        # History for per-IP tracking
        self._ip_cvs: dict = {}    # src_ip → deque of recent CV values

    def _maybe_retrain(self):
        """Retrain IsolationForest from the current training buffer."""
        if not self.use_forest:
            return
        if len(self._train_buf) < WARMUP_SAMPLES:
            return
        if self._retrain_counter % RETRAIN_EVERY != 0:
            return
        X = np.array(list(self._train_buf))
        self._forest = IsolationForest(
            contamination=IF_CONTAMINATION,
            n_estimators=100,
            random_state=42,
        ).fit(X)

    def update(self,
               cv: float,
               rate: float,
               success_pct: float,
               unknown_pct: float = 0.0,
               src_ip: str = "?") -> dict:
        """
        Submit a new measurement.  Returns a result dict:
          {
            anomalous   : bool,
            score       : float,   # 0-100 composite anomaly score
            reason      : str,
            triggers    : list[str],
            baselines   : dict,
            forest_flag : bool,
          }
        """
        triggers = []
        score    = 0.0

        # Update baselines
        self.cv_base.update(cv)
        self.rate_base.update(rate)
        self.success_base.update(success_pct)
        self.unknown_base.update(unknown_pct)

        # Compute z-scores
        z_cv      = self.cv_base.z_score(cv)
        z_rate    = self.rate_base.z_score(rate)
        z_success = self.success_base.z_score(success_pct)
        z_unknown = self.unknown_base.z_score(unknown_pct)

        adaptive_ready = (self.cv_base.ready and self.rate_base.ready)

        # ── Rule 1: low CV z-score (rigid bot timing below baseline) ──
        if adaptive_ready and z_cv < -self.z_cv:
            triggers.append(
                f"CV z-score = {z_cv:.2f} (below baseline by {abs(z_cv):.1f}σ); "
                f"CV={cv:.4f}, baseline mean={self.cv_base.snapshot()['mean']:.4f}"
            )
            score += min(50, 15 * abs(z_cv))

        # Fallback static check during warmup
        if not adaptive_ready and cv < 0.15:
            triggers.append(f"CV={cv:.4f} below static threshold 0.15 (warming up)")
            score += 40

        # ── Rule 2: request rate surge ─────────────────────────────────
        if adaptive_ready and z_rate > self.z_rate:
            triggers.append(
                f"Rate z-score = {z_rate:.2f} (above baseline by {z_rate:.1f}σ); "
                f"rate={rate:.2f} req/s, baseline={self.rate_base.snapshot()['mean']:.2f}"
            )
            score += min(30, 10 * z_rate)

        # ── Rule 3: success-rate drop ──────────────────────────────────
        if adaptive_ready and z_success < -2.0 and success_pct < 10.0:
            triggers.append(
                f"Success-rate drop: {success_pct:.1f}% "
                f"(z={z_success:.2f}, baseline={self.success_base.snapshot()['mean']:.1f}%)"
            )
            score += min(20, 10 * abs(z_success))

        # ── Rule 4: unknown-account spike ──────────────────────────────
        if adaptive_ready and z_unknown > 2.0 and unknown_pct > 30.0:
            triggers.append(
                f"Unknown-account spike: {unknown_pct:.1f}% "
                f"(z={z_unknown:.2f})"
            )
            score += min(20, 10 * z_unknown)

        # ── IsolationForest check ──────────────────────────────────────
        forest_flag = False
        if self.use_forest:
            vec = [cv, rate, success_pct, unknown_pct]
            with self._lock:
                self._retrain_counter += 1
                self._maybe_retrain()
                if self._forest is not None:
                    pred = self._forest.predict([vec])[0]  # -1=anomaly, 1=normal
                    forest_flag = pred == -1
                    if forest_flag:
                        score = min(100, score + 20)
                        triggers.append(
                            f"IsolationForest flagged feature vector "
                            f"[cv={cv:.3f}, rate={rate:.1f}, "
                            f"success={success_pct:.1f}%, unknown={unknown_pct:.1f}%]"
                        )
                if not triggers or not forest_flag:
                    # Only add to training buf when not obviously anomalous
                    self._train_buf.append(vec)

        score = min(100.0, score)
        anomalous = score >= 35.0

        return dict(
            anomalous    = anomalous,
            score        = round(score, 1),
            triggers     = triggers,
            forest_flag  = forest_flag,
            adaptive_ready = adaptive_ready,
            reason       = (
                ("ADAPTIVE ANOMALY DETECTED — " + "; ".join(triggers))
                if triggers else "Normal traffic"
            ),
            baselines    = {
                "cv":      self.cv_base.snapshot(),
                "rate":    self.rate_base.snapshot(),
                "success": self.success_base.snapshot(),
                "unknown": self.unknown_base.snapshot(),
            },
        )

    def get_status(self) -> dict:
        """Return current baseline state for admin/debug."""
        return dict(
            adaptive_ready = self.cv_base.ready,
            sklearn_forest = self.use_forest,
            forest_trained = self._forest is not None,
            baselines = {
                "cv":      self.cv_base.snapshot(),
                "rate":    self.rate_base.snapshot(),
                "success": self.success_base.snapshot(),
                "unknown": self.unknown_base.snapshot(),
            },
        )


# ── Per-IP adaptive detector ──────────────────────────────────

class PerIPAdaptiveDetector:
    """
    Maintains a separate AdaptiveDetector per source IP.

    This is important: the global detector learns the population-level
    normal CV.  But an individual IP that is always "fast" (e.g. a
    Selenium test suite) would be normal for that IP.  Per-IP
    baselines separate the global campaign signal from per-session
    anomalies.

    In practice, both global and per-IP detectors run in parallel.
    """

    def __init__(self):
        self._detectors: dict = {}
        self._lock = threading.Lock()

    def update(self, src_ip: str, cv: float, rate: float,
               success_pct: float, unknown_pct: float = 0.0) -> dict:
        with self._lock:
            if src_ip not in self._detectors:
                self._detectors[src_ip] = AdaptiveDetector()
        return self._detectors[src_ip].update(
            cv=cv, rate=rate,
            success_pct=success_pct, unknown_pct=unknown_pct,
            src_ip=src_ip,
        )

    def get_all_status(self) -> dict:
        with self._lock:
            return {ip: det.get_status()
                    for ip, det in self._detectors.items()}


# ── Singletons for ids_detector.py integration ───────────────
global_detector = AdaptiveDetector()
per_ip_detector = PerIPAdaptiveDetector()


def engine8_update(cv: float, rate: float, success_pct: float,
                   unknown_pct: float = 0.0, src_ip: str = "?") -> dict:
    """
    Drop-in call from ids_detector.py Engine 2 / Engine 5.
    Returns the global detector result.
    """
    return global_detector.update(
        cv=cv, rate=rate,
        success_pct=success_pct, unknown_pct=unknown_pct,
        src_ip=src_ip,
    )


if __name__ == "__main__":
    import random
    print("Adaptive Detector — self-test")
    print(f"sklearn available: {_SKLEARN_OK}")
    det = AdaptiveDetector()

    print("\n--- Phase 1: feeding 30 normal samples (CV~0.6, rate~1.0) ---")
    for _ in range(30):
        result = det.update(cv=random.gauss(0.6, 0.15), rate=random.gauss(1.0, 0.2),
                            success_pct=random.gauss(80, 5), unknown_pct=random.gauss(5, 2))
    print(f"Baselines after warmup: {result['baselines']}")

    print("\n--- Phase 2: inject 5 bot-like samples (CV=0.02) ---")
    for i in range(5):
        result = det.update(cv=0.02, rate=2.5, success_pct=0.5, unknown_pct=65.0)
        flag = "⚠️  ANOMALOUS" if result["anomalous"] else "✓  normal"
        print(f"  Sample {i+1}: score={result['score']}  {flag}")
        for t in result["triggers"]:
            print(f"    → {t}")
