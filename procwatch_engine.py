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


def detect_ptrace_trace(proc: "psutil.Process") -> list[dict]:
    """
    Detect processes being traced via ptrace.

    Reads /proc/<pid>/status for TracerPid.  A non-zero TracerPid means
    another process has attached to this one with ptrace(PTRACE_ATTACH)
    or is intercepting its syscalls via ptrace(PTRACE_SYSCALL).

    Attacker uses:
      - Anti-debugging hooks (injecting shellcode into running processes)
      - Password harvesting (reading credential data from target processes)
      - Keystroke injection into shell sessions
      - Rootkit implantation via live kernel patching

    False-positive note: gdb, strace, and ltrace all set TracerPid.
    ProcWatch cross-checks: if the tracer binary is strace/gdb in a
    SYSTEM_PATH it is LOW severity.  If the tracer is from /tmp or has
    no recognisable name it is CRITICAL.
    """
    findings = []
    status_text = _read_proc_file(proc.pid, "status")
    if not status_text:
        return findings

    for line in status_text.splitlines():
        if line.startswith("TracerPid:"):
            try:
                tracer_pid = int(line.split(":")[1].strip())
            except ValueError:
                continue
            if tracer_pid == 0:
                break   # not being traced

            # Process is being traced — investigate the tracer
            tracer_name = "unknown"
            tracer_exe  = ""
            severity    = "HIGH"
            note        = "Process is being traced by another process."

            try:
                tracer      = psutil.Process(tracer_pid)
                tracer_name = tracer.name()
                tracer_exe  = tracer.exe()
            except Exception:
                pass

            # Benign debuggers in standard system paths → LOW
            benign_tracers = {"gdb", "strace", "ltrace", "perf"}
            if (tracer_name in benign_tracers
                    and tracer_exe.startswith(SYSTEM_PATHS)):
                severity = "LOW"
                note = (
                    f"Tracer is {tracer_name} from {tracer_exe} — "
                    f"likely legitimate debugging session."
                )
            elif _is_in_suspicious_location(tracer_exe):
                severity = "CRITICAL"
                note = (
                    f"Tracer binary in suspicious location: {tracer_exe}\n"
                    f"  This pattern matches attacker-controlled ptrace injection.\n"
                    f"  Possible techniques: shellcode injection, credential theft,\n"
                    f"  keystroke injection into privileged shell."
                )
            else:
                severity = "HIGH"
                note = (
                    f"Tracer '{tracer_name}' (PID {tracer_pid}) not in standard "
                    f"system path: {tracer_exe}\n"
                    f"  Unexpected ptrace attachment — investigate tracer process."
                )

            findings.append({
                "type":     "PTRACE_ATTACHED",
                "severity": severity,
                "detail":   (
                    f"PID {proc.pid} ({proc.name()}) is being traced by "
                    f"PID {tracer_pid} ({tracer_name})\n"
                    f"  Tracer exe: {tracer_exe}\n"
                    f"  {note}"
                ),
                "mitre":    "T1055 (Process Injection) + T1003 (OS Credential Dumping)",
            })
            break   # only one tracer possible
    return findings


def detect_deleted_binary(proc: "psutil.Process") -> list[dict]:
    """
    Detection 6 (standalone): Process running from a deleted binary.

    Attackers often:
      1. Copy payload to /tmp
      2. Execute it
      3. Immediately delete the file: rm -f /tmp/payload

    Linux keeps the process alive in memory.  /proc/<pid>/exe shows
    the path with " (deleted)" appended.  The binary can be recovered:

        cp /proc/<pid>/exe /tmp/recovered_binary

    This technique is a standard anti-forensics evasion: no file on
    disk means traditional AV and file-hash scanners miss it entirely.
    ProcWatch catches it at the kernel level via /proc.
    """
    findings = []
    if not _is_deleted(proc.pid):
        return findings

    try:
        link = os.readlink(f"/proc/{proc.pid}/exe")
    except Exception:
        link = "(unreadable)"

    findings.append({
        "type":     "DELETED_BINARY_RUNNING",
        "severity": "HIGH",
        "detail":   (
            f"PID {proc.pid} ({proc.name()}) is running from a DELETED binary.\n"
            f"  /proc/{proc.pid}/exe → {link}\n"
            f"  The binary was deleted from disk after launch — anti-forensics.\n"
            f"  The process lives only in memory; it disappears on reboot.\n"
            f"  Forensic recovery: sudo cp /proc/{proc.pid}/exe "
            f"/tmp/recovered_pid{proc.pid}"
        ),
        "recovery": _recover_hint(proc.pid),
        "mitre":    "T1070.004 (Indicator Removal: File Deletion)",
    })
    return findings


# ── YARA memory scanner ────────────────────────────────────────

# Default ruleset: byte patterns and strings found in common malware,
# reverse shells, miners, and dropper scripts.
# Extend by adding (name, pattern_bytes_or_str, severity, mitre) tuples.
#
# Patterns are compiled once at import time.
#
# NOTE: Scanning /proc/<pid>/mem requires root AND the pid's maps file
#       to determine readable virtual address ranges.  Non-readable
#       ranges are skipped.  This is equivalent to YARA process scanning
#       but implemented in pure Python without the YARA library.

import re as _re

_YARA_RULES = [
    # Reverse shell indicators
    ("REVSHELL_BASH",
     b"/bin/bash -i",
     "HIGH", "T1059.004"),
    ("REVSHELL_PYTHON",
     b"import socket,subprocess,os",
     "HIGH", "T1059.006"),
    ("REVSHELL_NC",
     b"nc -e /bin/",
     "HIGH", "T1059"),
    ("REVSHELL_SOCAT",
     b"socat exec:",
     "HIGH", "T1059"),
    # Miner pool patterns
    ("MINER_POOL_STRATUM",
     b"stratum+tcp://",
     "HIGH", "T1496"),
    ("MINER_POOL_XMR",
     b"pool.supportxmr.com",
     "HIGH", "T1496"),
    ("MINER_XMRIG_BINARY",
     b"xmrig",
     "MED", "T1496"),
    # Shellcode stagers
    ("SHELLCODE_MSFVENOM",
     b"\xfc\xe8\x82\x00\x00\x00",      # Metasploit x86 stager prelude
     "CRITICAL", "T1059"),
    ("SHELLCODE_EGG",
     b"\x90\x90\x90\x90\x90\x90\x90\x90",  # NOP sled ≥8 bytes
     "MED", "T1203"),
    # C2 beacon patterns
    ("C2_CURL_BEACON",
     b"curl -s http",
     "MED", "T1071.001"),
    ("C2_WGET_BEACON",
     b"wget -q http",
     "MED", "T1071.001"),
    # Dropper cleanup
    ("DROPPER_SELF_DELETE",
     b"rm -f /tmp/",
     "MED", "T1070.004"),
    # LD_PRELOAD in memory-mapped data
    ("LD_PRELOAD_MEM",
     b"LD_PRELOAD=/tmp",
     "CRITICAL", "T1574.006"),
]

# Compile byte patterns for fast search
_COMPILED_RULES = [
    (name, pattern, sev, mitre)
    for name, pattern, sev, mitre in _YARA_RULES
]

# Maximum bytes to read per VMA region (avoid spending hours on huge heaps)
_YARA_REGION_LIMIT = 4 * 1024 * 1024   # 4 MiB


def yara_memory_scan(proc: "psutil.Process",
                     custom_rules: list = None) -> list[dict]:
    """
    Scan process memory for known malicious byte patterns.

    Reads /proc/<pid>/maps to enumerate readable virtual memory regions,
    then reads each region from /proc/<pid>/mem and searches for the
    patterns in _YARA_RULES (plus any custom_rules).

    Args:
        proc         : psutil.Process to scan
        custom_rules : optional list of (name, pattern_bytes, severity, mitre)
                       tuples to append to the default ruleset

    Returns a list of finding dicts (same format as other detectors).

    Requires root to read arbitrary /proc/<pid>/mem regions.
    On non-root, only self-process memory is accessible.

    This is architecturally identical to running:
        yara rule_file.yar /proc/<pid>/mem
    but with zero external dependencies.
    """
    findings = []
    rules = _COMPILED_RULES + (custom_rules or [])

    maps_text = _read_proc_file(proc.pid, "maps")
    if not maps_text:
        return findings

    mem_path = f"/proc/{proc.pid}/mem"
    try:
        mem_fd = open(mem_path, "rb")
    except PermissionError:
        return findings   # need root
    except Exception:
        return findings

    try:
        for line in maps_text.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            perms = parts[1]
            # Only scan readable, non-device regions (skip [vvar], [vsyscall])
            if "r" not in perms:
                continue
            region_name = parts[-1] if len(parts) >= 6 else ""
            if region_name in ("[vvar]", "[vsyscall]"):
                continue

            try:
                addr_range = parts[0].split("-")
                start = int(addr_range[0], 16)
                end   = int(addr_range[1], 16)
            except (IndexError, ValueError):
                continue

            size = min(end - start, _YARA_REGION_LIMIT)
            if size <= 0:
                continue

            try:
                mem_fd.seek(start)
                data = mem_fd.read(size)
            except Exception:
                continue

            if not data:
                continue

            for rule_name, pattern, severity, mitre in rules:
                idx = data.find(pattern)
                if idx == -1:
                    continue
                offset = start + idx
                # Context: up to 40 bytes around the match
                ctx_start = max(0, idx - 20)
                ctx_end   = min(len(data), idx + len(pattern) + 20)
                context = repr(data[ctx_start:ctx_end])

                findings.append({
                    "type":     f"YARA_{rule_name}",
                    "severity": severity,
                    "detail":   (
                        f"YARA match [{rule_name}] in PID {proc.pid} "
                        f"({proc.name()})\n"
                        f"  Virtual address : 0x{offset:016x}\n"
                        f"  Region          : {parts[0]}  perms={perms}"
                        f"  {f'  file={region_name}' if region_name else ''}\n"
                        f"  Pattern         : {pattern!r}\n"
                        f"  Context (±20B)  : {context}"
                    ),
                    "mitre":    mitre,
                })
    finally:
        try:
            mem_fd.close()
        except Exception:
            pass

    return findings


# ── eBPF syscall monitor ───────────────────────────────────────

class EBPFMonitor:
    """
    eBPF-based syscall monitoring for ProcWatch.

    Two operating modes, selected at runtime based on availability:

    Mode A — Native eBPF (requires root + kernel ≥ 4.4 + bcc):
      Generates and compiles a BPF C program that attaches kprobes to
      sys_execve, sys_connect, and sys_openat.  Fires an alert whenever
      a traced process calls these syscalls with suspicious arguments.

    Mode B — /proc/pid/syscall fallback (pure Python, always available):
      Reads /proc/<pid>/syscall every POLL_INTERVAL seconds.  This file
      exposes the currently-executing syscall number and arguments in hex.
      Less precise than eBPF (poll-based vs. event-based) but zero
      kernel dependencies.

    Usage:
        monitor = EBPFMonitor(target_pid=1234, alert_cb=my_alert)
        monitor.start()          # non-blocking background thread
        # ... later ...
        monitor.stop()

    Or use the class method scan_all() to snapshot all suspicious
    syscall states in one pass (no background thread needed).
    """

    # Syscall numbers (x86_64 Linux ABI)
    SYS_EXECVE  = 59
    SYS_EXECVEAT= 322
    SYS_CONNECT = 42
    SYS_OPENAT  = 257
    SYS_CLONE   = 56

    # If these syscalls are the *current* one for a process, flag it
    SUSPICIOUS_SYSCALLS = {
        SYS_EXECVE:   ("SYSCALL_EXECVE",   "HIGH",   "T1059"),
        SYS_EXECVEAT: ("SYSCALL_EXECVEAT", "HIGH",   "T1059"),
        SYS_CONNECT:  ("SYSCALL_CONNECT",  "MED",    "T1071"),
        SYS_CLONE:    ("SYSCALL_CLONE",    "MED",    "T1055"),
    }

    POLL_INTERVAL = 1.0   # seconds

    # eBPF C source template
    _BPF_SOURCE = """\
/* ProcWatch eBPF program — AUA CS 232/337 Research Lab
 * Attach to sys_execve, sys_connect, sys_openat kprobes.
 * Compile with: clang -O2 -target bpf -c procwatch.bpf.c -o procwatch.bpf.o
 * Or load via BCC: BPF(text=BPF_SOURCE).attach_kprobe(...)
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct event_t {
    u32 pid;
    u32 uid;
    u64 syscall_nr;
    char comm[16];
    char path[256];
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx, const char __user *filename) {
    struct event_t evt = {};
    evt.pid       = bpf_get_current_pid_tgid() >> 32;
    evt.uid       = bpf_get_current_uid_gid();
    evt.syscall_nr = 59;  // SYS_execve
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.path, sizeof(evt.path), filename);
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

int trace_connect(struct pt_regs *ctx, int fd,
                  struct sockaddr __user *uservaddr, int addrlen) {
    struct event_t evt = {};
    evt.pid       = bpf_get_current_pid_tgid() >> 32;
    evt.uid       = bpf_get_current_uid_gid();
    evt.syscall_nr = 42;  // SYS_connect
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    // path field: store sockaddr bytes for userspace to decode
    bpf_probe_read_user(&evt.path, sizeof(evt.path), uservaddr);
    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

    def __init__(self, target_pid: int = None, alert_cb=None):
        self._target_pid = target_pid
        self._alert_cb   = alert_cb or ProcWatchEngine._default_alert
        self._stop       = threading.Event()
        self._thread     = None
        self._bcc_ok     = self._check_bcc()

    @staticmethod
    def _check_bcc() -> bool:
        try:
            import bcc  # noqa
            return True
        except ImportError:
            return False

    def start(self):
        """Start monitoring in a background thread."""
        if self._bcc_ok:
            self._thread = threading.Thread(
                target=self._bcc_loop, daemon=True, name="ebpf-monitor"
            )
            print("[EBPF] BCC available — using native eBPF kprobe monitoring.")
        else:
            self._thread = threading.Thread(
                target=self._procfs_loop, daemon=True, name="ebpf-procfs"
            )
            print("[EBPF] BCC not available — using /proc/pid/syscall fallback.")
            print("[EBPF] Install BCC for full eBPF support:")
            print("[EBPF]   sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def generate_bpf_source(self) -> str:
        """Return the eBPF C source for external compilation/loading."""
        return self._BPF_SOURCE

    def _bcc_loop(self):
        """Native eBPF using BCC — hooks execve and connect kprobes."""
        try:
            from bcc import BPF
            b = BPF(text=self._BPF_SOURCE)
            b.attach_kprobe(event="sys_execve",  fn_name="trace_execve")
            b.attach_kprobe(event="sys_connect", fn_name="trace_connect")

            def handle_event(cpu, data, size):
                evt = b["events"].event(data)
                pid  = evt.pid
                comm = evt.comm.decode(errors="replace")
                path = evt.path.decode(errors="replace")
                sysn = evt.syscall_nr
                name, severity, mitre = self.SUSPICIOUS_SYSCALLS.get(
                    sysn, ("SYSCALL_OTHER", "LOW", "T1059")
                )
                self._alert_cb(
                    f"ProcWatch/EBPF_{name}", severity,
                    f"eBPF: PID {pid} ({comm}) syscall {sysn} arg={path[:80]}\n"
                    f"  MITRE: {mitre}"
                )

            b["events"].open_perf_buffer(handle_event)
            while not self._stop.is_set():
                b.perf_buffer_poll(timeout=500)
        except Exception as e:
            print(f"[EBPF] BCC loop error: {e} — falling back to /proc")
            self._procfs_loop()

    def _procfs_loop(self):
        """
        Fallback: poll /proc/<pid>/syscall for all processes (or target_pid).
        Detects processes currently blocked inside a suspicious syscall.
        """
        while not self._stop.is_set():
            pids = ([self._target_pid] if self._target_pid
                    else (psutil.pids() if PSUTIL_OK else []))
            for pid in pids:
                syscall_text = _read_proc_file(pid, "syscall")
                if not syscall_text or syscall_text.startswith("running"):
                    continue
                parts = syscall_text.split()
                if not parts:
                    continue
                try:
                    syscall_nr = int(parts[0])
                except ValueError:
                    continue
                if syscall_nr not in self.SUSPICIOUS_SYSCALLS:
                    continue
                name, severity, mitre = self.SUSPICIOUS_SYSCALLS[syscall_nr]
                args_hex = " ".join(parts[1:]) if len(parts) > 1 else "(no args)"
                self._alert_cb(
                    f"ProcWatch/EBPF_{name}", severity,
                    f"/proc/{pid}/syscall: PID {pid} currently in syscall "
                    f"{syscall_nr} ({name})\n"
                    f"  Args (hex): {args_hex}\n"
                    f"  MITRE: {mitre}"
                )
            time.sleep(self.POLL_INTERVAL)

    @classmethod
    def scan_all(cls, alert_cb=None) -> list[dict]:
        """
        One-shot /proc scan: return all processes currently in a
        suspicious syscall.  Does not require BCC or root.
        """
        results = []
        cb = alert_cb or (lambda *_: None)
        if not PSUTIL_OK:
            return results
        for pid in psutil.pids():
            syscall_text = _read_proc_file(pid, "syscall")
            if not syscall_text or syscall_text.startswith("running"):
                continue
            parts = syscall_text.split()
            if not parts:
                continue
            try:
                syscall_nr = int(parts[0])
            except ValueError:
                continue
            if syscall_nr not in cls.SUSPICIOUS_SYSCALLS:
                continue
            name, severity, mitre = cls.SUSPICIOUS_SYSCALLS[syscall_nr]
            try:
                proc_name = psutil.Process(pid).name()
            except Exception:
                proc_name = "?"
            args_hex = " ".join(parts[1:]) if len(parts) > 1 else "(no args)"
            finding = {
                "type":     f"EBPF_{name}",
                "severity": severity,
                "detail":   (
                    f"PID {pid} ({proc_name}) in syscall {syscall_nr} ({name})\n"
                    f"  Args (hex): {args_hex}\n"
                    f"  MITRE: {mitre}"
                ),
                "mitre":    mitre,
            }
            results.append({"pid": pid, "name": proc_name, "finding": finding})
        return results


# ══════════════════════════════════════════════════════════════
#  PROCESS RISK SCORER
# ══════════════════════════════════════════════════════════════

SEVERITY_SCORE = {"CRITICAL": 100, "HIGH": 50, "MED": 20, "LOW": 5}

DETECTORS = [
    detect_writable_dir_execution,
    detect_deleted_binary,          # standalone (was only in info() before)
    detect_uid_mismatch,
    detect_revshell_connections,
    detect_miner_keywords,
    detect_miner_behavior,
    detect_ld_preload_injection,
    detect_interpreter_with_network,
    detect_ptrace_trace,            # NEW: ptrace attachment detection
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

    def scan(self, verbose: bool = True,
             output_json: bool = False,
             run_yara: bool = False) -> list[dict]:
        """
        Scan all processes.  Return list of risky results.

        Args:
            verbose:     print human-readable findings as they are found
            output_json: if True, print a JSON report to stdout at the end
            run_yara:    if True, also run YARA memory scan on each risky
                         process (requires root; slower)
        """
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

            # Optional YARA memory scan on processes that already have findings
            if run_yara and result["findings"]:
                try:
                    yara_findings = yara_memory_scan(proc)
                    result["findings"].extend(yara_findings)
                    result["score"] += sum(
                        SEVERITY_SCORE.get(f.get("severity", "LOW"), 0)
                        for f in yara_findings
                    )
                except Exception:
                    pass

            if result["findings"]:
                risky.append(result)
                if verbose and not output_json:
                    self._print_result(result)
                for finding in result["findings"]:
                    self._alert_cb(
                        f"ProcWatch/{finding['type']}",
                        finding["severity"],
                        finding["detail"],
                    )

        # eBPF one-shot syscall snapshot (always runs; zero cost)
        ebpf_hits = EBPFMonitor.scan_all()
        for hit in ebpf_hits:
            # Check if we already have this pid in risky
            existing = next((r for r in risky if r["pid"] == hit["pid"]), None)
            if existing:
                existing["findings"].append(hit["finding"])
            else:
                risky.append({
                    "pid":      hit["pid"],
                    "name":     hit["name"],
                    "exe":      "",
                    "cmdline":  [],
                    "findings": [hit["finding"]],
                    "score":    SEVERITY_SCORE.get(hit["finding"]["severity"], 0),
                })

        if verbose and not output_json:
            print(f"\n[PROCWATCH] Scan complete.  "
                  f"Suspicious processes found: {len(risky)}\n")

        if output_json:
            import json as _json
            report = {
                "ts":            datetime.now().isoformat(),
                "total_scanned": len(list(psutil.pids())),
                "suspicious":    len(risky),
                "results":       risky,
            }
            print(_json.dumps(report, indent=2))

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
    print("  Detections: writable-dir exec, deleted binary, UID mismatch,")
    print("              revshells, miners, LD_PRELOAD, interpreter C2,")
    print("              ptrace attachment, YARA memory scan, eBPF syscalls")
    print("="*60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "ProcWatch — Linux Process Security Scanner\n"
            "Source: Hafiz Shamnad, DEV Community, March 2025\n"
            "AUA CS 232/337 Botnet Research Lab\n\n"
            "Usage:\n"
            "  procwatch scan [-v] [-j] [--yara] [--ebpf]\n"
            "  procwatch watch [--interval N]\n"
            "  procwatch info <pid>\n"
            "  procwatch list\n"
            "  procwatch ebpf  -- show eBPF C source for manual loading\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", help="Mode")

    scan_p = sub.add_parser("scan",  help="One-shot scan of all processes")
    scan_p.add_argument("-v", "--verbose", action="store_true", default=True,
                        help="Verbose output (default: on)")
    scan_p.add_argument("-j", "--json", action="store_true",
                        help="Output results as JSON (mirrors original article -j flag)")
    scan_p.add_argument("--yara", action="store_true",
                        help="Run YARA memory scan on suspicious processes (root req.)")
    scan_p.add_argument("--no-ebpf", action="store_true",
                        help="Skip eBPF/syscall snapshot")

    watch_p = sub.add_parser("watch", help="Continuous monitor (alert on new findings)")
    watch_p.add_argument("--interval", type=float, default=SCAN_INTERVAL,
                         help=f"Scan interval in seconds (default: {SCAN_INTERVAL})")

    info_p = sub.add_parser("info", help="Detailed report for one PID")
    info_p.add_argument("pid", type=int, help="Process ID to inspect")
    info_p.add_argument("--yara", action="store_true",
                        help="Also run YARA memory scan on this PID")

    sub.add_parser("list",  help="Risk-tiered list of all processes")

    ebpf_p = sub.add_parser("ebpf", help="eBPF tools")
    ebpf_p.add_argument("--source",  action="store_true",
                        help="Print eBPF C source for manual compilation/loading")
    ebpf_p.add_argument("--scan",    action="store_true",
                        help="One-shot /proc syscall scan (no BCC needed)")
    ebpf_p.add_argument("--monitor", type=int, metavar="PID",
                        help="Continuously monitor a specific PID via eBPF/procfs")

    args = parser.parse_args()
    _print_banner()

    if os.getuid() != 0:
        print("[PROCWATCH] WARNING: not running as root.")
        print("  Run with: sudo python3 procwatch_engine.py <mode>")
        print("  Without root: env vars, some connections, and YARA scans")
        print("  of other users' processes will not be visible.\n")

    engine = ProcWatchEngine()

    if args.cmd == "scan" or args.cmd is None:
        run_yara = getattr(args, "yara", False)
        out_json = getattr(args, "json", False)
        engine.scan(verbose=not out_json, output_json=out_json, run_yara=run_yara)

    elif args.cmd == "watch":
        engine.watch(interval=args.interval)

    elif args.cmd == "info":
        engine.info(args.pid)
        if getattr(args, "yara", False):
            try:
                proc = psutil.Process(args.pid)
                yara_hits = yara_memory_scan(proc)
                if yara_hits:
                    print(f"\n[YARA] {len(yara_hits)} pattern match(es) in PID {args.pid}:")
                    for h in yara_hits:
                        print(f"  [{h['severity']}] {h['type']}")
                        for line in h['detail'].splitlines():
                            print(f"    {line}")
                else:
                    print(f"\n[YARA] No pattern matches in PID {args.pid}.")
            except Exception as e:
                print(f"[YARA] Error: {e}")

    elif args.cmd == "list":
        engine.list_all()

    elif args.cmd == "ebpf":
        em = EBPFMonitor()
        if getattr(args, "source", False):
            print("[EBPF] BPF C source (compile with clang -O2 -target bpf):\n")
            print(em.generate_bpf_source())
            print("\n[EBPF] Load with BCC:")
            print("  from bcc import BPF")
            print("  b = BPF(text=open('procwatch.bpf.c').read())")
            print("  b.attach_kprobe(event='sys_execve', fn_name='trace_execve')")
            print("  b.attach_kprobe(event='sys_connect', fn_name='trace_connect')")
        elif getattr(args, "scan", False):
            hits = EBPFMonitor.scan_all()
            if hits:
                print(f"[EBPF] {len(hits)} processes in suspicious syscalls:")
                for h in hits:
                    print(f"  PID {h['pid']} ({h['name']}): "
                          f"[{h['finding']['severity']}] {h['finding']['type']}")
            else:
                print("[EBPF] No processes currently in suspicious syscalls.")
        elif getattr(args, "monitor", None):
            print(f"[EBPF] Monitoring PID {args.monitor}  (Ctrl-C to stop)")
            em2 = EBPFMonitor(target_pid=args.monitor)
            em2.start()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                em2.stop()
                print("\n[EBPF] Monitor stopped.")
        else:
            print("[EBPF] Specify --source, --scan, or --monitor <pid>.")
            ebpf_p.print_help()