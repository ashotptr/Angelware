"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Polymorphic Execution Engine
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching points:
  The resource used a simple random-lambda executor to produce
  non-deterministic execution paths.

  This module implements a proper multi-layer polymorphic engine
  modeled on techniques used by real malware:

  Layer 1 — Code path diversity:
    Randomized execution order of setup steps, with no-op
    "junk" operations inserted between real operations.
    Each run produces a different call graph.

  Layer 2 — Timing polymorphism:
    Randomized sleep intervals drawn from different distributions
    depending on the "variant" selected at runtime. Makes timing-
    based behavioral signatures fragile.

  Layer 3 — Identifier mutation:
    Variable names, thread names, and log prefixes are randomized
    per execution. Defeats regex-based behavioral rules that look
    for specific string patterns in memory.

  Layer 4 — Import obfuscation:
    Sensitive imports are deferred and loaded by string name at
    runtime, preventing static import-graph analysis.

  WHY THIS MATTERS FOR DEFENDERS:
    AV/EDR products use behavioral signatures like:
      "process calls sleep(), then socket.connect(), then send()"
    Polymorphic ordering breaks exact-sequence matching.
    Defenders must use machine-learned behavioral models
    (like IDS Engine 8's EWMA) instead.

Defense side (PolymorphismDetector — IDS Engine 21):
  Detects polymorphic behavior through INVARIANTS — properties
  that remain constant regardless of code path randomization:
    - Network connections still happen (invariant)
    - Process still spawns (invariant)
    - File writes still occur (invariant)
    - Sequence of OS calls still follows a pattern (invariant)

  The detector tracks WHAT happens, not HOW it happens,
  making it resilient to execution-path polymorphism.

CLI:
  python3 polymorphic_engine.py --demo
  python3 polymorphic_engine.py --variants N    (run N variants)
  python3 polymorphic_engine.py --detect        (IDS demo)
  python3 polymorphic_engine.py --profile       (behavioral profile)
"""

import os
import sys
import time
import json
import math
import uuid
import random
import hashlib
import threading
import importlib
from datetime import datetime
from collections import defaultdict, deque


# ════════════════════════════════════════════════════════════════
#  ATTACK SIDE: Polymorphic Execution Engine
# ════════════════════════════════════════════════════════════════

class _JunkOps:
    """No-op operations used as code path padding."""

    @staticmethod
    def compute_prime(n: int = None) -> int:
        """Computationally benign: find a prime near n."""
        if n is None:
            n = random.randint(100, 10000)
        while True:
            n += 1
            if all(n % i != 0 for i in range(2, int(math.sqrt(n)) + 1)):
                return n

    @staticmethod
    def hash_random() -> str:
        data = os.urandom(random.randint(16, 64))
        algo = random.choice(["sha256", "sha1", "md5"])
        return hashlib.new(algo, data).hexdigest()

    @staticmethod
    def sleep_jitter() -> float:
        """Sleep for a randomized short duration."""
        duration = random.uniform(0.01, 0.3)
        time.sleep(duration)
        return duration

    @staticmethod
    def build_decoy_string() -> str:
        words = ["service", "update", "sync", "monitor",
                 "agent", "proxy", "daemon", "helper"]
        return "_".join(random.sample(words, k=random.randint(1, 3)))

    @staticmethod
    def read_proc_stat():
        """Read /proc/stat — mimics performance monitoring."""
        try:
            with open("/proc/stat") as f:
                return f.readline()
        except FileNotFoundError:
            return ""

    @staticmethod
    def env_check():
        """Read some environment variables — looks like config loading."""
        return {
            "HOME":   os.environ.get("HOME", ""),
            "USER":   os.environ.get("USER", ""),
            "SHELL":  os.environ.get("SHELL", ""),
        }


class PolymorphicExecutor:
    """
    Multi-layer polymorphic execution wrapper.

    Wraps any sequence of operations in a polymorphic shell that:
      1. Randomizes execution order of non-dependent steps
      2. Inserts junk operations between real ones
      3. Randomizes thread/process naming
      4. Uses deferred/dynamic imports for sensitive modules
      5. Varies sleep timing distributions per run

    Usage:
        executor = PolymorphicExecutor(operation_list)
        executor.run()
    """

    # Timing profiles — each run randomly picks one
    TIMING_PROFILES = {
        "rapid":    {"dist": "uniform",  "min": 0.0, "max": 0.1},
        "periodic": {"dist": "normal",   "mean": 0.5, "std": 0.05},
        "jittered": {"dist": "uniform",  "min": 0.1, "max": 2.0},
        "bursty":   {"dist": "bimodal",  "fast": 0.05, "slow": 3.0},
        "human":    {"dist": "lognormal","mean": 0.5, "std": 0.8},
    }

    def __init__(self, operations: list = None,
                 junk_ratio: float = 0.3,
                 shuffle: bool = True):
        """
        operations: list of callables. If None, uses built-in demo ops.
        junk_ratio: fraction of execution steps that are junk/no-op.
        shuffle:    randomize operation order on each run.
        """
        self._ops        = operations or self._default_ops()
        self._junk_ratio = junk_ratio
        self._shuffle    = shuffle
        self._junk       = _JunkOps()
        self._run_id     = None
        self._profile    = None
        self._results    = []

    def _default_ops(self) -> list:
        """Default demo operations — all benign."""
        return [
            ("read_hostname",  lambda: __import__("socket").gethostname()),
            ("check_cpu",      lambda: __import__("os").cpu_count()),
            ("hash_self",      lambda: hashlib.sha256(b"self").hexdigest()[:8]),
            ("list_dir",       lambda: os.listdir("/tmp")),
            ("read_uptime",    lambda: open("/proc/uptime").read() if os.path.exists("/proc/uptime") else ""),
        ]

    def _get_junk_ops(self, n: int) -> list:
        """Return n random junk operations."""
        pool = [
            self._junk.compute_prime,
            self._junk.hash_random,
            self._junk.sleep_jitter,
            self._junk.build_decoy_string,
            self._junk.read_proc_stat,
            self._junk.env_check,
        ]
        return random.choices(pool, k=n)

    def _sample_sleep(self) -> float:
        """Draw a sleep duration from the current timing profile."""
        profile = self._profile
        dist = profile.get("dist", "uniform")
        if dist == "uniform":
            return random.uniform(profile["min"], profile["max"])
        elif dist == "normal":
            return max(0, random.gauss(profile["mean"], profile["std"]))
        elif dist == "lognormal":
            return random.lognormvariate(
                math.log(profile["mean"]), profile["std"]
            )
        elif dist == "bimodal":
            return (profile["fast"] if random.random() < 0.7
                    else profile["slow"])
        return 0.1

    def run(self, verbose: bool = True) -> dict:
        """Execute operations with polymorphic wrapping."""
        # Per-run identity — changes every execution
        self._run_id = str(uuid.uuid4())[:8]
        self._profile = random.choice(list(self.TIMING_PROFILES.values()))
        profile_name  = [k for k, v in self.TIMING_PROFILES.items()
                         if v is self._profile][0]
        thread_name   = f"svc_{self._junk.build_decoy_string()}"

        if verbose:
            print(f"[Poly-{self._run_id}] Starting (profile={profile_name}, "
                  f"thread={thread_name})")

        # Build execution sequence: interleave real ops with junk
        real_ops = list(self._ops)
        if self._shuffle:
            random.shuffle(real_ops)

        n_junk = max(1, int(len(real_ops) * self._junk_ratio))
        junk   = [(f"junk_{i}", j) for i, j in
                  enumerate(self._get_junk_ops(n_junk))]

        # Interleave junk with real ops
        all_ops = real_ops[:]
        for i, jop in enumerate(junk):
            pos = random.randint(0, len(all_ops))
            all_ops.insert(pos, jop)

        results = {}
        for name, fn in all_ops:
            sleep_t = self._sample_sleep()
            time.sleep(sleep_t)
            try:
                val = fn()
                results[name] = {"ok": True, "value": str(val)[:40]}
                if verbose and not name.startswith("junk"):
                    print(f"[Poly-{self._run_id}] ✓ {name}")
            except Exception as e:
                results[name] = {"ok": False, "error": str(e)}

        self._results = results
        if verbose:
            real_count = sum(1 for n in results if not n.startswith("junk"))
            junk_count = sum(1 for n in results if n.startswith("junk"))
            print(f"[Poly-{self._run_id}] Done: {real_count} ops, "
                  f"{junk_count} junk, profile={profile_name}")

        return {
            "run_id":   self._run_id,
            "profile":  profile_name,
            "thread":   thread_name,
            "ops_real": sum(1 for n in results if not n.startswith("junk")),
            "ops_junk": sum(1 for n in results if n.startswith("junk")),
            "results":  results,
        }

    def run_n_variants(self, n: int = 5) -> list:
        """
        Run n variants and compare behavioral profiles.
        Demonstrates how polymorphism changes the observable sequence
        while the underlying operations remain the same.
        """
        print(f"[PolyEngine] Running {n} variants to demonstrate path diversity...")
        all_results = []
        for i in range(n):
            print(f"\n{'─'*40}")
            print(f"  Variant {i+1}/{n}")
            result = self.run()
            all_results.append(result)
            time.sleep(0.5)

        # Analysis
        print(f"\n{'='*60}")
        print(f"  Polymorphism analysis across {n} variants:")
        print(f"{'─'*60}")
        profiles = [r["profile"] for r in all_results]
        from collections import Counter
        for profile, count in Counter(profiles).most_common():
            print(f"  timing profile '{profile}': {count} runs")

        # Show execution order diversity
        print(f"\n  Operation order (first 4 real ops per run):")
        for i, r in enumerate(all_results):
            real = [k for k in r["results"] if not k.startswith("junk")][:4]
            print(f"  Variant {i+1}: {' → '.join(real)}")

        return all_results


# ════════════════════════════════════════════════════════════════
#  DEFENSE SIDE: Polymorphism Detector (IDS Engine 21)
# ════════════════════════════════════════════════════════════════

def _default_alert(engine, severity, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'='*60}\n  ALERT [{severity}]  {engine}  @ {ts}\n  {msg}\n{'='*60}\n")

_alert_fn = _default_alert

def register_alert_fn(fn):
    global _alert_fn
    _alert_fn = fn


class PolymorphismDetector:
    """
    IDS Engine 21 — Polymorphic Behavior Detection.

    KEY PRINCIPLE: Polymorphism changes HOW things happen.
    Behavioral invariants define WHAT must happen.
    We detect invariants, not sequences.

    Invariants of a bot that are hard to randomize away:
      A) It connects to the network (port scan, C2 beacon, etc.)
      B) It reads certain files (/proc/net/tcp, /etc/passwd)
      C) It spawns child processes
      D) Its CPU usage follows a pattern (burst+idle cycling)
      E) Its memory growth follows an allocation pattern
      F) It writes files to /tmp or ~ directories

    This detector builds a behavioral fingerprint from these
    invariants and flags processes that match the bot profile
    even when their execution path is randomized.
    """

    def __init__(self):
        # Per-PID behavioral fingerprint
        self._fingerprints: dict[int, dict] = defaultdict(lambda: {
            "net_conns":     0,
            "file_reads":    [],
            "child_spawns":  0,
            "cpu_spikes":    0,
            "tmp_writes":    0,
            "first_seen":    time.time(),
            "last_seen":     time.time(),
        })
        self._cooldown: dict[str, float] = {}
        self._lock = threading.Lock()

    def _cooldown_ok(self, key: str, secs: float = 120.0) -> bool:
        now = time.time()
        if now - self._cooldown.get(key, 0) >= secs:
            self._cooldown[key] = now
            return True
        return False

    def observe_network(self, pid: int, dst_ip: str, dst_port: int):
        """Record a network connection by a process."""
        with self._lock:
            fp = self._fingerprints[pid]
            fp["net_conns"] += 1
            fp["last_seen"] = time.time()
        self._check_invariants(pid)

    def observe_file_read(self, pid: int, path: str):
        """Record a file read by a process."""
        with self._lock:
            fp = self._fingerprints[pid]
            if path not in fp["file_reads"]:
                fp["file_reads"].append(path)
            fp["last_seen"] = time.time()
        self._check_invariants(pid)

    def observe_child_spawn(self, pid: int):
        """Record a child process spawned."""
        with self._lock:
            fp = self._fingerprints[pid]
            fp["child_spawns"] += 1
            fp["last_seen"] = time.time()
        self._check_invariants(pid)

    def observe_tmp_write(self, pid: int, path: str):
        """Record a write to /tmp or similar writable directory."""
        with self._lock:
            fp = self._fingerprints[pid]
            fp["tmp_writes"] += 1
        self._check_invariants(pid)

    def _check_invariants(self, pid: int):
        """
        Score the process against bot behavioral invariants.
        Fires alert when enough invariants are met, regardless
        of execution path randomization.
        """
        with self._lock:
            fp = dict(self._fingerprints[pid])

        score = 0
        evidence = []

        # Invariant A: Network connections
        if fp["net_conns"] > 0:
            score += 1
            evidence.append(f"net_conns={fp['net_conns']}")

        # Invariant B: Sensitive file reads
        sensitive = [p for p in fp["file_reads"]
                     if any(s in p for s in
                            ["/proc/net", "/etc/passwd", "/etc/shadow",
                             "/proc/cpuinfo", "/sys/bus/vmbus"])]
        if sensitive:
            score += 1
            evidence.append(f"sensitive_reads={sensitive[:3]}")

        # Invariant C: Child process spawning (more than 3)
        if fp["child_spawns"] > 3:
            score += 1
            evidence.append(f"child_spawns={fp['child_spawns']}")

        # Invariant E: Writes to /tmp
        if fp["tmp_writes"] > 0:
            score += 1
            evidence.append(f"tmp_writes={fp['tmp_writes']}")

        # Score >= 3 of 4 invariants → alert
        if score >= 3:
            if self._cooldown_ok(f"invariant_{pid}"):
                _alert_fn(
                    "Polymorphic/BehavioralInvariant", "HIGH",
                    f"POLYMORPHIC BOT DETECTED via behavioral invariants\n"
                    f"  PID={pid}\n"
                    f"  Score: {score}/4 invariants matched\n"
                    f"  Evidence: {'; '.join(evidence)}\n"
                    f"  Execution path randomization does not change WHAT "
                    f"the process does, only HOW.\n"
                    f"  Invariant detection is resilient to polymorphism.\n"
                    f"  MITRE: T1027.007 (Obfuscated Files or Information: "
                    f"Dynamic API Resolution)"
                )

    def run_demo(self):
        """Simulate a polymorphic bot and detect it via invariants."""
        print("[IDS-E21] Simulating polymorphic bot behavior...")
        pid = 12345

        # Variant 1: different order, same invariants
        self.observe_file_read(pid, "/proc/net/tcp")
        self.observe_network(pid, "192.168.100.10", 5000)
        self.observe_child_spawn(pid)
        self.observe_tmp_write(pid, "/tmp/.svc_update")
        self.observe_child_spawn(pid)
        self.observe_child_spawn(pid)
        self.observe_child_spawn(pid)
        self.observe_file_read(pid, "/etc/passwd")

        print(f"[IDS-E21] All invariants observed. "
              f"Fingerprint: {dict(self._fingerprints[pid])}")
        print("[IDS-E21] Demo complete.")


# ════════════════════════════════════════════════════════════════
#  BEHAVIORAL PROFILE COMPARISON
# ════════════════════════════════════════════════════════════════

def compare_variant_profiles(results: list) -> dict:
    """
    Analyze multiple variant results for behavioral invariants.
    Shows that despite different execution orders, invariant
    operations always appear.
    """
    all_op_sets = []
    for r in results:
        ops = set(k for k in r["results"] if not k.startswith("junk"))
        all_op_sets.append(ops)

    # Invariant ops: appear in ALL variants
    invariant = set.intersection(*all_op_sets) if all_op_sets else set()
    # Variant ops: appear in SOME but not all
    union = set.union(*all_op_sets) if all_op_sets else set()
    variable = union - invariant

    return {
        "invariant_ops":  sorted(invariant),
        "variable_ops":   sorted(variable),
        "n_variants":     len(results),
        "teaching_point": (
            "Invariant operations appear in every run regardless of randomization. "
            "A behavioral IDS that monitors for these operations will detect the "
            "bot even when sequence-based signatures fail."
        ),
    }


# ════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Polymorphic Execution Engine")
    parser.add_argument("--demo",     action="store_true",
                        help="Full attack+defense demo")
    parser.add_argument("--variants", type=int, default=3,
                        help="Run N variants (default 3)")
    parser.add_argument("--detect",   action="store_true",
                        help="Run IDS Engine 21 demo")
    parser.add_argument("--profile",  action="store_true",
                        help="Show behavioral profile comparison")
    args = parser.parse_args()

    if args.demo or args.variants:
        n = args.variants if not args.demo else 4
        engine  = PolymorphicExecutor()
        results = engine.run_n_variants(n)

        if args.profile or args.demo:
            profile = compare_variant_profiles(results)
            print(f"\n{'='*60}")
            print(f"  Behavioral Profile Comparison:")
            print(f"{'─'*60}")
            print(f"  Invariant ops (appear in ALL variants): "
                  f"{profile['invariant_ops']}")
            print(f"  Variable ops (differ across variants):  "
                  f"{profile['variable_ops']}")
            print(f"\n  {profile['teaching_point']}")

    if args.detect or args.demo:
        print()
        det = PolymorphismDetector()
        det.run_demo()
