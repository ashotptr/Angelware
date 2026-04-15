"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Enhanced Host Process Security Scanner
 Environment: ISOLATED VM LAB ONLY

 Source: "Day 14 — I Built ProcWatch: A Linux Process Security
          Scanner for Forensics & Incident Response"
          Hafiz Shamnad, DEV Community, March 2025

 This module implements the ProcWatch detections that are
 NOT covered by the existing host engine in ids_detector.py:

   Detection 1  Execution from writable directories          ✓ NEW
                /tmp, /dev/shm, /var/tmp, /run/user, /dev/mqueue
   Detection 3  UID/effective-UID mismatch (SUID escalation) ✓ NEW
                real UID ≠ effective UID → privilege escalation
   Detection 3b Root process running from /home/*            ✓ NEW
   Detection 4  Reverse shell / C2 port detection            ✓ NEW
                ESTABLISHED outbound to ports 4444,5555,7777,31337
   Detection 5  Cryptominer keyword detection                ✓ NEW
                xmrig, monero, stratum, pool in cmdline/name
   Detection 7  LD_PRELOAD injection detection               ✓ NEW
                env var LD_PRELOAD pointing to /tmp or /dev/*
   (bonus)      Binary recovery hint                         ✓ NEW
                Prints: cp /proc/<pid>/exe recovered_binary

 Already implemented in ids_detector.py (host engine):
   - Ghost process (/proc/pid/exe → "(deleted)")
   - Sustained CPU ≥ 85%
   - Process name spoof (comm ≠ exe basename)

 Integration:
   Standalone:
     sudo python3 procwatch_engine.py [scan | watch | info <pid> | list]

   As IDS engine (import from ids_detector.py):
     from procwatch_engine import ProcWatchEngine
     pw = ProcWatchEngine(alert_cb=alert)
     pw.scan()        # one-shot
     pw.watch(10)     # continuous, check every 10s

 Scan modes:
   scan   — one-shot scan, print all findings, exit
   watch  — continuous monitor, alert only on NEW suspicious processes
   info   — detailed info for a specific PID
   list   — list all running processes with their risk tier
====================================================
"""

import os
import sys
import time
import stat
import shutil
import argparse
import threading
from collections import defaultdict
from datetime import datetime

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    print("[PROCWATCH] psutil not installed.  pip3 install psutil")
    PSUTIL_OK = False


# ── Configuration ──────────────────────────────────────────────

SUSPICIOUS_LOCATIONS = [
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run/user",
    "/dev/mqueue",
]

# Interpreter names that warrant scrutiny when combined with other signals
SUSPICIOUS_INTERPRETERS = {
    "bash", "sh", "dash", "zsh", "ksh",
    "nc", "ncat", "netcat",
    "python", "python2", "python3",
    "perl", "ruby", "lua",
    "socat", "nmap",
}

# Ports strongly associated with reverse shells and C2 listeners
REVSHELL_PORTS = {4444, 5555, 7777, 8888, 31337, 1337, 9001, 6666}

# Keywords in cmdline / process name → cryptominer suspicion
MINER_KEYWORDS = {
    "xmrig", "xmr-stak", "monero", "stratum", "mining-proxy",
    "pool.supportxmr", "pool.minexmr", "cryptonight", "nicehash",
    "ethminer", "cgminer", "bfgminer", "cpuminer", "minerd",
}

# CPU threshold for miner-by-behavior detection (%)
MINER_CPU_THRESHOLD = 70.0

# Paths that are legitimate for root processes
SYSTEM_PATHS = (
    "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/",
    "/opt/", "/snap/", "/usr/local/",
)

SCAN_INTERVAL = 10.0   # seconds between watch-mode scans


# ══════════════════════════════════════════════════════════════
#  HELPER UTILITIES
# ══════════════════════════════════════════════════════════════

def _read_proc_file(pid: int, filename: str) -> str:
    """Read a /proc/<pid>/<filename> safely; return '' on any error."""
    try:
        with open(f"/proc/{pid}/{filename}", "r", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _get_exe_path(proc: "psutil.Process") -> str:
    try:
        return proc.exe()
    except Exception:
        return ""


def _get_cmdline(proc: "psutil.Process") -> list:
    try:
        return proc.cmdline()
    except Exception:
        return []


def _get_environ(proc: "psutil.Process") -> dict:
    try:
        return proc.environ()
    except Exception:
        return {}


def _get_connections(proc: "psutil.Process") -> list:
    try:
        return proc.connections(kind="inet")
    except Exception:
        return []


def _get_uids(proc: "psutil.Process"):
    """Return (real, effective, saved) UIDs or None."""
    try:
        return proc.uids()
    except Exception:
        return None


def _is_deleted(pid: int) -> bool:
    """True if /proc/<pid>/exe points to a deleted binary."""
    try:
        target = os.readlink(f"/proc/{pid}/exe")
        return "(deleted)" in target
    except Exception:
        return False


def _is_in_suspicious_location(path: str) -> str | None:
    """Return the suspicious prefix if path starts with one, else None."""
    for loc in SUSPICIOUS_LOCATIONS:
        if path.startswith(loc + "/") or path == loc:
            return loc
    return None


def _recover_hint(pid: int) -> str:
    """Return the forensic binary-recovery command."""
    return f"sudo cp /proc/{pid}/exe /tmp/recovered_pid{pid}"


# ══════════════════════════════════════════════════════════════
#  INDIVIDUAL DETECTION FUNCTIONS
# ══════════════════════════════════════════════════════════════

def detect_writable_dir_execution(proc: "psutil.Process") -> list[dict]:
    """
    Detection 1: Execution from writable directories.

    Legitimate software almost never runs from /tmp or /dev/shm.
    Memory-backed /dev/shm is especially suspicious — evidence
    disappears on reboot.
    """
    findings = []
    exe = _get_exe_path(proc)
    if not exe:
        return findings

    suspicious_loc = _is_in_suspicious_location(exe)
    if suspicious_loc:
        findings.append({
            "type":     "WRITABLE_DIR_EXECUTION",
            "severity": "CRITICAL",
            "detail":   f"Process running from {suspicious_loc}: {exe}",
            "recovery": _recover_hint(proc.pid),
            "mitre":    "T1036.005 (Masquerading: Match Legitimate Name or Location)",
        })
    return findings


def detect_uid_mismatch(proc: "psutil.Process") -> list[dict]:
    """
    Detection 3: UID / effective-UID mismatch.

    If real UID ≠ effective UID the process is running with elevated
    privileges via a SUID binary.  If caught mid-escalation this is
    a strong indicator of privilege escalation in progress.

    Also flags: root process (eUID=0) whose executable is under /home/*.
    """
    findings = []
    uids = _get_uids(proc)
    if uids is None:
        return findings

    real, effective, _ = uids.real, uids.effective, uids.saved

    # SUID escalation in progress
    if real != effective:
        findings.append({
            "type":     "UID_MISMATCH",
            "severity": "HIGH",
            "detail":   (
                f"Real UID={real} ≠ Effective UID={effective} — "
                f"SUID privilege escalation detected for PID {proc.pid} "
                f"({proc.name()})"
            ),
            "mitre":    "T1548.001 (Abuse Elevation Control: Setuid and Setgid)",
        })

    # Root process running from a user home directory
    if effective == 0:
        exe = _get_exe_path(proc)
        if exe.startswith("/home/") or exe.startswith("/root/tmp/"):
            findings.append({
                "type":     "ROOT_FROM_HOMEDIR",
                "severity": "HIGH",
                "detail":   (
                    f"Root process (eUID=0) running from home directory: {exe}\n"
                    f"  Root processes belong in /usr/bin, /sbin — not /home/*."
                ),
                "mitre":    "T1548 (Abuse Elevation Control Mechanism)",
            })
    return findings


def detect_revshell_connections(proc: "psutil.Process") -> list[dict]:
    """
    Detection 4: Reverse shell / C2 port detection.

    LISTEN on a classic revshell port → suspicious.
    ESTABLISHED outbound → almost certain compromise.
    Classic ports: 4444, 5555, 7777, 8888, 31337, 1337, 9001, 6666.
    """
    findings = []
    connections = _get_connections(proc)

    for conn in connections:
        rport = conn.raddr.port if conn.raddr else None
        lport = conn.laddr.port if conn.laddr else None
        status = getattr(conn, "status", "")

        # Outbound ESTABLISHED to a classic revshell port
        if rport in REVSHELL_PORTS and status == "ESTABLISHED":
            findings.append({
                "type":     "REVSHELL_OUTBOUND",
                "severity": "CRITICAL",
                "detail":   (
                    f"PID {proc.pid} ({proc.name()}) has ESTABLISHED outbound "
                    f"connection to port {rport} "
                    f"({conn.laddr.ip}:{conn.laddr.port} → "
                    f"{conn.raddr.ip}:{conn.raddr.port})\n"
                    f"  Classic reverse-shell / C2 port — near-certain compromise."
                ),
                "mitre":    "T1059 (Command and Scripting Interpreter) + T1095 (Non-Application Layer Protocol)",
            })

        # LISTEN on a classic revshell port
        elif lport in REVSHELL_PORTS and status == "LISTEN":
            findings.append({
                "type":     "REVSHELL_LISTEN",
                "severity": "HIGH",
                "detail":   (
                    f"PID {proc.pid} ({proc.name()}) LISTENING on "
                    f"classic revshell port {lport}\n"
                    f"  Possible bind-shell or C2 listener."
                ),
                "mitre":    "T1071 (Application Layer Protocol)",
            })
    return findings


def detect_miner_keywords(proc: "psutil.Process") -> list[dict]:
    """
    Detection 5a: Cryptominer keyword detection.

    Scans the process name and full command-line for known miner
    binary/pool keywords.  Complements the CPU-threshold check
    already in ids_detector.py host engine.
    """
    findings = []
    name    = (proc.name() or "").lower()
    cmdline = " ".join(_get_cmdline(proc)).lower()
    combined = f"{name} {cmdline}"

    matched = [kw for kw in MINER_KEYWORDS if kw in combined]
    if matched:
        findings.append({
            "type":     "MINER_KEYWORD",
            "severity": "HIGH",
            "detail":   (
                f"Cryptominer keyword(s) detected in PID {proc.pid}:\n"
                f"  Matched: {', '.join(matched)}\n"
                f"  Name: {proc.name()}\n"
                f"  Cmdline: {' '.join(_get_cmdline(proc))[:120]}"
            ),
            "mitre":    "T1496 (Resource Hijacking)",
        })
    return findings


def detect_miner_behavior(proc: "psutil.Process") -> list[dict]:
    """
    Detection 5b: Cryptominer by behavior (sustained high CPU).

    Extends the existing ids_detector.py CPU≥85% check with:
    - Lower threshold (70%) for processes with miner-like names/paths.
    - Cross-check with interpreter list (a Python/bash process at 90%
      CPU with no terminal is highly suspicious).
    """
    findings = []
    try:
        cpu = proc.cpu_percent(interval=0.1)
    except Exception:
        return findings

    if cpu < MINER_CPU_THRESHOLD:
        return findings

    name = (proc.name() or "").lower()
    exe  = _get_exe_path(proc)
    try:
        terminal = proc.terminal()
    except Exception:
        terminal = None

    # Interpreter running at high CPU with no terminal → headless script miner
    is_interpreter = any(interp in name for interp in SUSPICIOUS_INTERPRETERS)

    if is_interpreter and terminal is None and cpu >= MINER_CPU_THRESHOLD:
        findings.append({
            "type":     "MINER_BEHAVIOR",
            "severity": "HIGH",
            "detail":   (
                f"Interpreter ({proc.name()}) running at {cpu:.1f}% CPU "
                f"with no terminal — PID {proc.pid}\n"
                f"  Headless high-CPU interpreter is consistent with a "
                f"scripted miner or cryptojacking payload."
            ),
            "mitre":    "T1496 (Resource Hijacking)",
        })
    return findings


def detect_ld_preload_injection(proc: "psutil.Process") -> list[dict]:
    """
    Detection 7: LD_PRELOAD library injection.

    If LD_PRELOAD is set to a path in /tmp, /dev/shm, or any other
    writable location, a malicious shared library is being injected
    into the process's address space.  This is how user-space rootkits
    hide files, steal passwords, and fake authentication.

    Catching this is almost always a confirmed compromise.
    """
    findings = []
    env = _get_environ(proc)
    if not env:
        return findings

    preload = env.get("LD_PRELOAD", "") or env.get("LD_PRELOAD_PATH", "")
    if not preload:
        return findings

    # Check every path in LD_PRELOAD (colon-separated)
    for lib_path in preload.split(":"):
        lib_path = lib_path.strip()
        if not lib_path:
            continue
        suspicious_loc = _is_in_suspicious_location(lib_path)
        if suspicious_loc:
            findings.append({
                "type":     "LD_PRELOAD_INJECTION",
                "severity": "CRITICAL",
                "detail":   (
                    f"LD_PRELOAD injection detected in PID {proc.pid} ({proc.name()}):\n"
                    f"  LD_PRELOAD={lib_path}\n"
                    f"  Library loaded from {suspicious_loc} — "
                    f"intercepting system calls.\n"
                    f"  This is how user-space rootkits hide files and steal credentials.\n"
                    f"  Catching this is almost always a confirmed compromise."
                ),
                "mitre":    "T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking)",
            })
        elif lib_path and not lib_path.startswith(SYSTEM_PATHS):
            # LD_PRELOAD from a non-system, non-temp path — still suspicious
            findings.append({
                "type":     "LD_PRELOAD_NONSTANDARD",
                "severity": "MED",
                "detail":   (
                    f"Non-standard LD_PRELOAD in PID {proc.pid} ({proc.name()}):\n"
                    f"  LD_PRELOAD={lib_path}\n"
                    f"  Library not in a standard system path."
                ),
                "mitre":    "T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking)",
            })
    return findings


def detect_interpreter_with_network(proc: "psutil.Process") -> list[dict]:
    """
    Detection 2 (extended): Suspicious interpreter + network activity.

    An interpreter (python, bash, nc, socat) alone is normal.
    The same interpreter with an active outbound ESTABLISHED connection
    is a strong reverse-shell indicator — especially if the process
    has no terminal.
    """
    findings = []
    name = (proc.name() or "").lower()
    if not any(interp in name for interp in SUSPICIOUS_INTERPRETERS):
        return findings

    connections = _get_connections(proc)
    established = [
        c for c in connections
        if getattr(c, "status", "") == "ESTABLISHED" and c.raddr
    ]
    if not established:
        return findings

    try:
        terminal = proc.terminal()
    except Exception:
        terminal = None

    if terminal is None:
        # Interpreter, network, no terminal → very likely revshell
        for conn in established:
            findings.append({
                "type":     "INTERPRETER_REVSHELL",
                "severity": "CRITICAL",
                "detail":   (
                    f"Interpreter ({proc.name()}) with ESTABLISHED connection "
                    f"and NO terminal — PID {proc.pid}\n"
                    f"  {conn.laddr.ip}:{conn.laddr.port} → "
                    f"{conn.raddr.ip}:{conn.raddr.port}\n"
                    f"  This is the classic reverse shell pattern: "
                    f"shell piped over a network socket."
                ),
                "mitre":    "T1059 (Command and Scripting Interpreter)",
            })
    return findings


# ══════════════════════════════════════════════════════════════
#  PROCESS RISK SCORER
# ══════════════════════════════════════════════════════════════

SEVERITY_SCORE = {"CRITICAL": 100, "HIGH": 50, "MED": 20, "LOW": 5}

DETECTORS = [
    detect_writable_dir_execution,
    detect_uid_mismatch,
    detect_revshell_connections,
    detect_miner_keywords,
    detect_miner_behavior,
    detect_ld_preload_injection,
    detect_interpreter_with_network,
]


def scan_process(proc: "psutil.Process") -> dict:
    """
    Run all detectors against a single process.
    Returns a result dict with findings list and total risk score.
    """
    result = {
        "pid":      proc.pid,
        "name":     "?",
        "exe":      "",
        "cmdline":  [],
        "findings": [],
        "score":    0,
    }
    try:
        result["name"]    = proc.name()
        result["exe"]     = _get_exe_path(proc)
        result["cmdline"] = _get_cmdline(proc)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return result

    for detector in DETECTORS:
        try:
            findings = detector(proc)
            result["findings"].extend(findings)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break
        except Exception:
            pass

    result["score"] = sum(
        SEVERITY_SCORE.get(f.get("severity", "LOW"), 0)
        for f in result["findings"]
    )
    return result


# ══════════════════════════════════════════════════════════════
#  PROCWATCH ENGINE
# ══════════════════════════════════════════════════════════════

class ProcWatchEngine:
    """
    Orchestrates all detectors over the full process list.

    Modes:
      scan()   — one-shot scan of all running processes
      watch()  — continuous monitor; alerts only on NEW findings
      info()   — detailed report for a specific PID
    """

    def __init__(self, alert_cb=None):
        self._alert_cb = alert_cb or self._default_alert
        self._seen_findings: set = set()   # dedup key: (pid, type)
        self._lock = threading.Lock()

    @staticmethod
    def _default_alert(engine: str, severity: str, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n{'='*60}")
        print(f"  ALERT  [{severity}]  Engine: {engine}  @ {ts}")
        print(f"  {msg}")
        print(f"{'='*60}\n")

    def scan(self, verbose: bool = True) -> list[dict]:
        """Scan all processes. Return list of risky results."""
        if not PSUTIL_OK:
            print("[PROCWATCH] psutil unavailable")
            return []

        print(f"\n[PROCWATCH] Scanning {len(list(psutil.pids()))} processes...\n")
        risky = []

        for proc in psutil.process_iter():
            try:
                result = scan_process(proc)
            except Exception:
                continue
            if result["findings"]:
                risky.append(result)
                if verbose:
                    self._print_result(result)
                for finding in result["findings"]:
                    self._alert_cb(
                        f"ProcWatch/{finding['type']}",
                        finding["severity"],
                        finding["detail"],
                    )

        if verbose:
            print(f"\n[PROCWATCH] Scan complete.  "
                  f"Suspicious processes found: {len(risky)}\n")
        return risky

    def watch(self, interval: float = SCAN_INTERVAL) -> None:
        """Continuous monitoring; alert only on new findings."""
        if not PSUTIL_OK:
            print("[PROCWATCH] psutil unavailable")
            return

        print(f"[PROCWATCH] Watch mode — scanning every {interval}s.  "
              f"Press Ctrl-C to stop.\n")
        try:
            while True:
                for proc in psutil.process_iter():
                    try:
                        result = scan_process(proc)
                    except Exception:
                        continue
                    if not result["findings"]:
                        continue
                    for finding in result["findings"]:
                        key = (result["pid"], finding["type"])
                        with self._lock:
                            if key in self._seen_findings:
                                continue
                            self._seen_findings.add(key)
                        # New finding
                        self._alert_cb(
                            f"ProcWatch/{finding['type']}",
                            finding["severity"],
                            finding["detail"],
                        )
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[PROCWATCH] Watch stopped.")

    def info(self, pid: int) -> None:
        """Print a detailed security report for one process."""
        try:
            proc   = psutil.Process(pid)
            result = scan_process(proc)
        except psutil.NoSuchProcess:
            print(f"[PROCWATCH] PID {pid} not found.")
            return

        print(f"\n{'='*60}")
        print(f"  PROCWATCH DETAILED REPORT — PID {pid}")
        print(f"{'='*60}")
        print(f"  Name    : {result['name']}")
        print(f"  Exe     : {result['exe']}")
        print(f"  Cmdline : {' '.join(result['cmdline'])[:100]}")

        try:
            uids = proc.uids()
            print(f"  UIDs    : real={uids.real}  effective={uids.effective}  saved={uids.saved}")
        except Exception:
            pass

        try:
            conns = proc.connections(kind="inet")
            for c in conns:
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "(none)"
                print(f"  Network : {c.laddr.ip}:{c.laddr.port} → {raddr}  [{c.status}]")
        except Exception:
            pass

        env = _get_environ(proc)
        if env.get("LD_PRELOAD"):
            print(f"  LD_PRELOAD: {env['LD_PRELOAD']}")

        deleted = _is_deleted(pid)
        if deleted:
            print(f"  Binary  : DELETED FROM DISK (memory-resident)")
            print(f"  Recover : {_recover_hint(pid)}")

        print(f"\n  Risk score : {result['score']}")
        if result["findings"]:
            print(f"  Findings   : {len(result['findings'])}")
            for i, f in enumerate(result["findings"], 1):
                print(f"\n  [{i}] {f['type']}  [{f['severity']}]")
                print(f"      {f['detail']}")
                if "mitre" in f:
                    print(f"      MITRE: {f['mitre']}")
                if "recovery" in f:
                    print(f"      Recovery: {f['recovery']}")
        else:
            print("  No suspicious findings.")
        print(f"{'='*60}\n")

    def list_all(self) -> None:
        """Print a risk-tiered list of all running processes."""
        if not PSUTIL_OK:
            return
        print(f"\n{'PID':>7}  {'NAME':<20}  {'SCORE':>5}  {'FINDINGS':<40}")
        print("-" * 80)
        results = []
        for proc in psutil.process_iter():
            try:
                r = scan_process(proc)
                results.append(r)
            except Exception:
                pass
        results.sort(key=lambda x: x["score"], reverse=True)
        for r in results:
            if r["score"] == 0 and not r["findings"]:
                continue   # skip clean processes
            types = ", ".join(f["type"] for f in r["findings"])
            print(f"  {r['pid']:>5}  {r['name']:<20}  {r['score']:>5}  {types[:40]}")
        print()

    @staticmethod
    def _print_result(result: dict) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n{'─'*60}")
        print(f"  [PROCWATCH] PID={result['pid']}  name={result['name']}  "
              f"score={result['score']}  @ {ts}")
        print(f"  exe: {result['exe']}")
        for f in result["findings"]:
            print(f"\n  ⚠  [{f['severity']}] {f['type']}")
            for line in f["detail"].splitlines():
                print(f"     {line}")
            if "mitre" in f:
                print(f"     MITRE: {f['mitre']}")
            if "recovery" in f:
                print(f"     Recovery cmd: {f['recovery']}")
        print(f"{'─'*60}")


# ══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════

def _print_banner() -> None:
    print("\n" + "="*60)
    print("  ProcWatch — Host Process Security Scanner")
    print("  AUA CS 232/337 Botnet Research Lab")
    print("  Detects: writable-dir exec, UID mismatch, revshells,")
    print("           miners, LD_PRELOAD injection, interpreter C2")
    print("="*60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ProcWatch — Linux Process Security Scanner\n"
                    "Source: Hafiz Shamnad, DEV Community, March 2025",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", help="Mode")

    sub.add_parser("scan",  help="One-shot scan of all processes")

    watch_p = sub.add_parser("watch", help="Continuous monitor (alert on new findings)")
    watch_p.add_argument("--interval", type=float, default=SCAN_INTERVAL,
                         help=f"Scan interval in seconds (default: {SCAN_INTERVAL})")

    info_p = sub.add_parser("info", help="Detailed report for one PID")
    info_p.add_argument("pid", type=int, help="Process ID to inspect")

    sub.add_parser("list",  help="Risk-tiered list of all processes")

    args = parser.parse_args()
    _print_banner()

    if os.getuid() != 0:
        print("[PROCWATCH] WARNING: not running as root.")
        print("  Run with: sudo python3 procwatch_engine.py <mode>")
        print("  Without root, environment variables and some connections")
        print("  of other users' processes will not be visible.\n")

    engine = ProcWatchEngine()

    if args.cmd == "scan" or args.cmd is None:
        engine.scan(verbose=True)

    elif args.cmd == "watch":
        engine.watch(interval=args.interval)

    elif args.cmd == "info":
        engine.info(args.pid)

    elif args.cmd == "list":
        engine.list_all()
