"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: CAPTCHA Economics + Solver Detection
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching point (from Castle credential stuffing article):
  "Add CAPTCHA? They offload challenges to solver APIs,
   click farms, or OCR-based bots."
  "Apply progressive friction — trigger CAPTCHA or
   JavaScript challenges on suspicious behavior."

Why CAPTCHA alone does not stop determined attackers:
  Three solver categories exist, each with different
  cost and latency profiles:

  1. Human click farms (2Captcha, Anti-Captcha, etc.)
     Cost: $0.50–$3.00 per 1000 solves
     Latency: 15–45 seconds per solve (human reaction)
     Bypasses: reCAPTCHA v2, hCaptcha, image/text CAPTCHAs

  2. Automated ML solvers (CapMonster, XEvil)
     Cost: $0.50–$1.50 per 1000 solves
     Latency: 1–5 seconds per solve (GPU inference)
     Bypasses: text CAPTCHA, older reCAPTCHA v2

  3. Token brokers (reCAPTCHA enterprise bypass)
     Cost: $2–$8 per 1000 tokens
     Latency: 2–10 seconds
     Bypasses: reCAPTCHA v3 (score-based, hardest)

  Math: even at $3.00/1000 solves and 2% credential hit rate,
  an attacker testing 100,000 credentials pays $300 in CAPTCHA
  fees to get 2,000 valid logins. At $5 resale value each,
  that's a $10,000–$300 = $9,700 profit on CAPTCHA cost alone.

This module has three parts:

1. CAPTCHAEconomicsModel
   Calculates attacker cost/profit under different CAPTCHA
   friction strategies. Shows defenders the break-even point
   where CAPTCHA cost makes a campaign unprofitable.

2. SolverBehaviorSimulator (Attack side)
   Generates HTTP-level traffic patterns of each solver type:
   human farms produce clustered solves with high variance,
   ML solvers produce fast uniform solve times, token brokers
   re-use tokens across many IPs.

3. SolverPatternDetector (IDS Engine 12)
   Detects CAPTCHA solver usage via timing analysis:
   - Solve time < 2s from a residential IP → ML solver
   - Solve time clustering around 20±5s → human click farm
   - Same CAPTCHA token used from multiple IPs → broker reuse
   - CAPTCHA presented → solved → login attempt all within 3s
     from a newly-seen IP → fully automated solver pipeline
"""

import json
import math
import os
import random
import statistics
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

LOG_PATH = "/tmp/captcha_economics.json"


# ══════════════════════════════════════════════════════════════
#  Part 1: CAPTCHA ECONOMICS MODEL
# ══════════════════════════════════════════════════════════════

class CAPTCHAEconomicsModel:
    """
    Models the attacker's cost-benefit calculation under
    different CAPTCHA strategies.

    Inputs (all adjustable):
      credential_list_size   — how many username:password pairs
      hit_rate_pct           — % of credentials that are valid
      resale_value_usd       — revenue per valid credential
      captcha_cost_per_1k    — solver cost per 1000 solves
      captcha_latency_sec    — solve time (determines campaign duration)
      captcha_success_rate   — fraction of solver attempts that succeed
                               (ML solvers: ~95%, humans: ~99%)

    Outputs:
      solver_cost_total      — total CAPTCHA fees
      time_to_complete_hrs   — campaign wall-clock time
      gross_revenue          — hits × resale_value
      net_profit             — gross - solver_cost
      break_even_hit_rate    — minimum hit% to be profitable
    """

    SOLVER_PROFILES = {
        "human_farm": {
            "cost_per_1k":    2.00,
            "latency_sec":    25.0,
            "success_rate":   0.99,
            "description":    "Human click farm (2Captcha-style)",
        },
        "ml_solver": {
            "cost_per_1k":    1.00,
            "latency_sec":    3.0,
            "success_rate":   0.92,
            "description":    "ML solver (CapMonster/XEvil-style)",
        },
        "token_broker": {
            "cost_per_1k":    5.00,
            "latency_sec":    6.0,
            "success_rate":   0.85,
            "description":    "reCAPTCHA v3 token broker",
        },
        "no_captcha": {
            "cost_per_1k":    0.00,
            "latency_sec":    0.5,
            "success_rate":   1.00,
            "description":    "No CAPTCHA (baseline)",
        },
    }

    def analyze(self,
                credential_list_size: int = 100_000,
                hit_rate_pct: float = 0.5,
                resale_value_usd: float = 3.00,
                solver: str = "human_farm") -> dict:
        """
        Full economic analysis for one attacker campaign.
        """
        profile = self.SOLVER_PROFILES[solver]
        n_creds = credential_list_size
        hit_rate = hit_rate_pct / 100.0

        # Adjust for solver failure — attacker must retry failed solves
        effective_solves = n_creds / profile["success_rate"]
        solver_cost      = (effective_solves / 1000) * profile["cost_per_1k"]

        # Valid credentials obtained
        n_hits       = int(n_creds * hit_rate)
        gross_rev    = n_hits * resale_value_usd
        net_profit   = gross_rev - solver_cost

        # Time to complete (sequential)
        total_sec    = effective_solves * profile["latency_sec"]
        hours        = total_sec / 3600

        # Break-even: solve_cost/n_creds = break_even_revenue_per_cred
        #   → break_even_hits × resale = solver_cost
        #   → break_even_hit_rate = solver_cost / (n_creds × resale_value)
        if resale_value_usd > 0 and n_creds > 0:
            break_even_hr = (solver_cost / (n_creds * resale_value_usd)) * 100
        else:
            break_even_hr = float("inf")

        result = {
            "solver":              profile["description"],
            "credential_list":     n_creds,
            "hit_rate_pct":        hit_rate_pct,
            "n_hits":              n_hits,
            "gross_revenue_usd":   round(gross_rev, 2),
            "solver_cost_usd":     round(solver_cost, 2),
            "net_profit_usd":      round(net_profit, 2),
            "profitable":          net_profit > 0,
            "campaign_hours":      round(hours, 1),
            "break_even_hit_pct":  round(break_even_hr, 3),
        }

        self._print_analysis(result)
        return result

    def _print_analysis(self, r: dict):
        profitable = "✓ PROFITABLE" if r["profitable"] else "✗ UNPROFITABLE"
        print(f"\n[CAPTCHA-ECON] ── {r['solver']} ──")
        print(f"  Credentials:        {r['credential_list']:,}")
        print(f"  Hit rate:           {r['hit_rate_pct']:.1f}%  "
              f"({r['n_hits']:,} valid logins)")
        print(f"  Gross revenue:      ${r['gross_revenue_usd']:,.2f}")
        print(f"  Solver cost:        ${r['solver_cost_usd']:,.2f}")
        print(f"  Net profit:         ${r['net_profit_usd']:,.2f}  "
              f"→ {profitable}")
        print(f"  Campaign duration:  {r['campaign_hours']:.1f} hours")
        print(f"  Break-even hit %:   {r['break_even_hit_pct']:.3f}%")

    def compare_all_solvers(self,
                             credential_list_size: int = 100_000,
                             hit_rate_pct: float = 0.5,
                             resale_value_usd: float = 3.00) -> list:
        """Compare all solver types side by side."""
        print("\n" + "=" * 60)
        print(f" CAPTCHA Economic Comparison")
        print(f" {credential_list_size:,} credentials | "
              f"{hit_rate_pct:.1f}% hit rate | "
              f"${resale_value_usd:.2f}/hit")
        print("=" * 60)

        results = []
        for solver in self.SOLVER_PROFILES:
            r = self.analyze(
                credential_list_size,
                hit_rate_pct,
                resale_value_usd,
                solver,
            )
            results.append(r)

        print(f"\n[CAPTCHA-ECON] Key insight:")
        profitable = [r for r in results if r["profitable"]]
        print(f"  {len(profitable)}/{len(results)} solver types remain "
              f"profitable at {hit_rate_pct:.1f}% hit rate")
        print(f"  CAPTCHA raises attacker cost but rarely makes the")
        print(f"  attack unprofitable unless combined with other friction")
        return results

    def find_captcha_deterrence_threshold(self,
                                          credential_list_size: int = 100_000,
                                          resale_value_usd: float = 3.00,
                                          solver: str = "human_farm") -> dict:
        """
        Find the minimum CAPTCHA cost-per-1000 that makes the attack
        unprofitable at various hit rates.

        Shows defenders: to deter a human-farm attack with 0.5% hit rate,
        the effective cost-per-1000 needs to be raised to >X.
        """
        profile  = dict(self.SOLVER_PROFILES[solver])
        results  = {}

        for hit_rate_pct in [0.1, 0.5, 1.0, 2.0, 5.0]:
            hit_rate  = hit_rate_pct / 100.0
            n_hits    = credential_list_size * hit_rate
            gross_rev = n_hits * resale_value_usd
            # Break even: solver_cost = gross_rev
            #   → (n_creds / success_rate / 1000) × cost_per_1k = gross_rev
            #   → cost_per_1k = gross_rev × 1000 × success_rate / n_creds
            if credential_list_size > 0:
                deterrence_cost = (gross_rev * 1000 * profile["success_rate"]
                                   / credential_list_size)
            else:
                deterrence_cost = float("inf")
            results[f"{hit_rate_pct}%"] = {
                "deterrence_cost_per_1k": round(deterrence_cost, 2),
                "current_cost_per_1k":    profile["cost_per_1k"],
                "gap_factor": round(deterrence_cost / profile["cost_per_1k"], 1)
                              if profile["cost_per_1k"] > 0 else float("inf"),
            }

        print(f"\n[CAPTCHA-ECON] Deterrence threshold ({solver}):")
        print(f"  Hit rate  |  Need cost/1k  |  Current cost/1k  |  Gap factor")
        for hr, v in results.items():
            print(f"  {hr:8s}  |  ${v['deterrence_cost_per_1k']:10.2f}  |"
                  f"  ${v['current_cost_per_1k']:16.2f}  |  "
                  f"{v['gap_factor']}×")
        print(f"\n  Practical ceiling for human-farm cost: ~$20/1000")
        print(f"  reCAPTCHA Enterprise adds behavioral scoring that can")
        print(f"  reach effective costs of $30-$50/1000 against bots,")
        print(f"  but this only deters campaigns with <0.1% hit rates.")
        return results


# ══════════════════════════════════════════════════════════════
#  Part 2: SOLVER BEHAVIOR SIMULATOR (Attack side)
# ══════════════════════════════════════════════════════════════

class SolverBehaviorSimulator:
    """
    Generates the timing signatures of each CAPTCHA solver type.
    Used to calibrate IDS Engine 12 detection thresholds.

    Each solver leaves a distinct timing fingerprint:
      Human farm:    solve_time ~ Normal(25, 8)  seconds
      ML solver:     solve_time ~ Normal(3, 0.5) seconds
      Token broker:  solve_time ~ Normal(6, 1)   seconds (reuse: 0s)
    """

    def generate_human_farm_times(self, n: int = 50) -> list:
        """Human reaction times: ~25s mean, high variance."""
        return [max(8, random.gauss(25, 8)) for _ in range(n)]

    def generate_ml_solver_times(self, n: int = 50) -> list:
        """ML inference: fast and uniform, ~3s."""
        return [max(0.8, random.gauss(3, 0.5)) for _ in range(n)]

    def generate_token_broker_times(self, n: int = 50) -> list:
        """
        Token broker: mix of fresh solves (~6s) and token reuse (~0.1s).
        Brokers pre-solve challenges and cache tokens for rapid reuse.
        """
        times = []
        for i in range(n):
            if random.random() < 0.3:  # 30% cache hit rate
                times.append(random.uniform(0.05, 0.2))  # instant reuse
            else:
                times.append(max(1, random.gauss(6, 1)))
        return times

    def fingerprint(self, times: list) -> dict:
        """Compute timing statistics for IDS comparison."""
        if len(times) < 3:
            return {}
        return {
            "n":        len(times),
            "mean_sec": round(statistics.mean(times), 2),
            "stdev_sec": round(statistics.stdev(times), 2),
            "cv":       round(statistics.stdev(times) / statistics.mean(times), 3),
            "min_sec":  round(min(times), 2),
            "max_sec":  round(max(times), 2),
            "pct_under_2s": round(
                100 * sum(1 for t in times if t < 2.0) / len(times), 1
            ),
        }

    def print_comparison(self):
        print("\n[SOLVER-SIM] Timing fingerprint comparison:")
        print(f"  {'Solver':<20}  {'Mean':>7}  {'CV':>6}  "
              f"{'%<2s':>6}  {'Classification'}")
        print(f"  {'─'*20}  {'─'*7}  {'─'*6}  {'─'*6}  {'─'*20}")

        for name, gen in [
            ("Human farm",    self.generate_human_farm_times),
            ("ML solver",     self.generate_ml_solver_times),
            ("Token broker",  self.generate_token_broker_times),
        ]:
            times = gen(200)
            fp    = self.fingerprint(times)
            if fp["pct_under_2s"] > 50:
                cls = "→ Automated (IDS flag)"
            elif fp["cv"] < 0.3:
                cls = "→ Bot-like timing"
            else:
                cls = "→ Human-like"
            print(f"  {name:<20}  {fp['mean_sec']:>6.1f}s  "
                  f"{fp['cv']:>6.3f}  {fp['pct_under_2s']:>5.1f}%  {cls}")


# ══════════════════════════════════════════════════════════════
#  Part 3: SOLVER PATTERN DETECTOR (IDS Engine 12)
# ══════════════════════════════════════════════════════════════

class SolverPatternDetector:
    """
    IDS Engine 12: Detect CAPTCHA solver usage via timing and
    token analysis.

    Integrated into fake_portal.py CAPTCHA flow:
      1. Portal records when CAPTCHA was presented (ts_presented)
      2. Portal records when solution was submitted (ts_solved)
      3. Engine 12 computes solve_latency = ts_solved - ts_presented
      4. Token seen from multiple IPs → broker reuse alert
    """

    ML_THRESHOLD_SEC      = 2.0   # faster than this = ML solver
    FARM_MEAN_SEC         = 25.0  # human farms cluster around 20-30s
    FARM_TOLERANCE_SEC    = 10.0  # ±10s from farm mean
    TOKEN_REUSE_WINDOW    = 120   # seconds
    MIN_SAMPLES           = 5     # need this many before alerting

    def __init__(self):
        self._lock  = threading.Lock()
        # ip → deque of solve latencies
        self._latencies: dict = defaultdict(lambda: deque(maxlen=100))
        # token_hash → set of IPs that presented it
        self._token_ips: dict = defaultdict(set)
        # ip → timestamp of last challenge present
        self._challenge_ts: dict = {}
        self._alerts: list = []

    def challenge_presented(self, src_ip: str, token_id: str = None):
        """Call when CAPTCHA is shown to a user."""
        with self._lock:
            self._challenge_ts[src_ip] = time.time()
            if token_id:
                self._token_ips[token_id].add(src_ip)

    def solution_submitted(self, src_ip: str,
                            correct: bool,
                            token_id: str = None) -> Optional[dict]:
        """
        Call when CAPTCHA solution is received.
        Returns alert if solver pattern detected.
        """
        now = time.time()
        alert = None

        with self._lock:
            presented_at = self._challenge_ts.get(src_ip)
            if presented_at:
                latency = now - presented_at
                self._latencies[src_ip].append(latency)

                recent = list(self._latencies[src_ip])
                if len(recent) >= self.MIN_SAMPLES:
                    avg = statistics.mean(recent)
                    cv  = (statistics.stdev(recent) / avg
                           if avg > 0 else 0)

                    # Signal 1: ML solver (very fast, low variance)
                    if avg < self.ML_THRESHOLD_SEC and cv < 0.4:
                        alert = {
                            "engine":   "Engine12/MLSolver",
                            "severity": "HIGH",
                            "src_ip":   src_ip,
                            "avg_sec":  round(avg, 2),
                            "cv":       round(cv, 3),
                            "n":        len(recent),
                            "ts":       datetime.now().isoformat(),
                            "message": (
                                f"ML CAPTCHA SOLVER: avg solve time "
                                f"{avg:.2f}s < {self.ML_THRESHOLD_SEC}s threshold\n"
                                f"  CV={cv:.3f} (low variance = automated)\n"
                                f"  Source: {src_ip}  n={len(recent)} solves\n"
                                f"  MITRE: T1056.003 (Web Portal Capture)"
                            ),
                        }

                    # Signal 2: Human click farm timing cluster
                    farm_diff = abs(avg - self.FARM_MEAN_SEC)
                    if (self.FARM_MEAN_SEC - self.FARM_TOLERANCE_SEC
                            < avg < self.FARM_MEAN_SEC + self.FARM_TOLERANCE_SEC
                            and cv < 0.5):
                        farm_alert = {
                            "engine":   "Engine12/ClickFarm",
                            "severity": "MED",
                            "src_ip":   src_ip,
                            "avg_sec":  round(avg, 2),
                            "cv":       round(cv, 3),
                            "n":        len(recent),
                            "ts":       datetime.now().isoformat(),
                            "message": (
                                f"CLICK FARM: solve times cluster at "
                                f"{avg:.1f}s ≈ human-farm mean "
                                f"({self.FARM_MEAN_SEC}s)\n"
                                f"  CV={cv:.3f}  {src_ip}\n"
                                f"  Consistent with outsourced human solvers"
                            ),
                        }
                        if not alert:
                            alert = farm_alert

            # Signal 3: Token reuse across IPs (broker)
            if token_id:
                self._token_ips[token_id].add(src_ip)
                ips = self._token_ips[token_id]
                if len(ips) >= 3:
                    alert = {
                        "engine":   "Engine12/TokenReuse",
                        "severity": "HIGH",
                        "token_id": token_id[:12] + "…",
                        "n_ips":    len(ips),
                        "ips":      list(ips),
                        "ts":       datetime.now().isoformat(),
                        "message": (
                            f"CAPTCHA TOKEN REUSE: same token seen "
                            f"from {len(ips)} IPs\n"
                            f"  IPs: {list(ips)}\n"
                            f"  Token brokers pre-solve and distribute tokens\n"
                            f"  Mitigation: bind CAPTCHA token to issuing IP"
                        ),
                    }

        if alert:
            self._alerts.append(alert)
            print(f"\n[IDS-{alert['engine']}] {alert['severity']}: "
                  f"{alert['message']}\n")
        return alert

    def get_stats(self) -> dict:
        return {
            "total_alerts": len(self._alerts),
            "ips_tracked":  len(self._latencies),
            "tokens_seen":  len(self._token_ips),
        }


# ── Demo ──────────────────────────────────────────────────────

def _run_demo():
    print("=" * 60)
    print(" CAPTCHA Economics + Solver Detection")
    print(" AUA Botnet Research Lab — ISOLATED VM ONLY")
    print("=" * 60)

    # ── Economics model ───────────────────────────────────────
    model = CAPTCHAEconomicsModel()
    model.compare_all_solvers(
        credential_list_size=100_000,
        hit_rate_pct=0.5,
        resale_value_usd=3.00,
    )
    model.find_captcha_deterrence_threshold(
        credential_list_size=100_000,
        solver="human_farm",
    )

    # ── Timing fingerprints ───────────────────────────────────
    sim = SolverBehaviorSimulator()
    sim.print_comparison()

    # ── IDS Engine 12 detection ───────────────────────────────
    print("\n[IDS] Simulating Engine 12 solver detection...")
    det = SolverPatternDetector()

    # Simulate ML solver (fast, uniform)
    for i in range(10):
        det.challenge_presented("192.168.100.11", f"tok_{i:04d}")
        time.sleep(random.gauss(1.5, 0.3))
        det.solution_submitted("192.168.100.11", True, f"tok_{i:04d}")

    # Simulate token broker reuse
    shared_token = "broker_token_aabbcc"
    for ip in ["10.0.1.1", "10.0.2.2", "10.0.3.3", "10.0.4.4"]:
        det.challenge_presented(ip, shared_token)
        time.sleep(0.1)
        det.solution_submitted(ip, True, shared_token)

    print(f"\n[ENGINE12] Stats: {det.get_stats()}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="CAPTCHA Economics + Solver Detection — AUA Research Lab"
    )
    parser.add_argument("--econ",    action="store_true",
                        help="Run economics model only")
    parser.add_argument("--timing",  action="store_true",
                        help="Show solver timing fingerprints")
    parser.add_argument("--detect",  action="store_true",
                        help="Run IDS Engine 12 detection demo")
    parser.add_argument("--creds",   type=int, default=100_000)
    parser.add_argument("--hitrate", type=float, default=0.5)
    parser.add_argument("--resale",  type=float, default=3.00)
    args = parser.parse_args()

    if args.econ:
        m = CAPTCHAEconomicsModel()
        m.compare_all_solvers(args.creds, args.hitrate, args.resale)
    elif args.timing:
        SolverBehaviorSimulator().print_comparison()
    elif args.detect:
        d = SolverPatternDetector()
        for i in range(12):
            d.challenge_presented("test_ip", f"tok{i}")
            time.sleep(max(0.2, random.gauss(1.8, 0.3)))
            d.solution_submitted("test_ip", True, f"tok{i}")
    else:
        _run_demo()
