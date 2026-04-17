"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Process Monitor / Viewer
 Environment: ISOLATED VM LAB ONLY

 Source: "How to Make a Process Monitor in Python Tutorial"
         The Python Code (thepythoncode.com), process_monitor.py

 This module implements the process VIEWER from the article.

 Distinction from procwatch_engine.py:
   procwatch_engine.py = SECURITY SCANNER: detects writable-dir
     execution, UID mismatch, reverse shells, LD_PRELOAD injection,
     ptrace, cryptominer keywords.  Focused on SUSPICIOUS processes.
   procwatch_reporter.py = PROCESS VIEWER: lists ALL running processes
     in a sortable table with CPU, memory, I/O, thread count.
     Focused on VISIBILITY — the article's primary teaching point.

 Both are needed: the reporter gives operators situational awareness
 (which processes exist at all); the engine flags which are malicious.

 Article fields implemented here:
   pid, name, create_time, cores (cpu_affinity), cpu_usage,
   status, nice, memory_usage (uss), read_bytes, write_bytes,
   n_threads, username

 Pandas is optional — falls back to a plain text table so the
 tool works on minimal VMs without pip install pandas.

 Usage:
   python3 procwatch_reporter.py                      # default: top 25 by memory
   python3 procwatch_reporter.py -n 10 -s cpu_usage --descending
   python3 procwatch_reporter.py -u                   # live-update every 0.7s
   python3 procwatch_reporter.py -c name,cpu_usage,status  # custom columns
   python3 procwatch_reporter.py --suspicious         # flag ProcWatch hits too
====================================================
"""

import argparse
import os
import sys
import time
from datetime import datetime
from typing import List, Optional

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    print("[reporter] psutil not installed.  pip3 install psutil")
    sys.exit(1)

try:
    import pandas as pd
    PANDAS_OK = True
except ImportError:
    PANDAS_OK = False

# Optional: integration with ProcWatch security scanner
try:
    from procwatch_engine import ProcWatchEngine, PSUTIL_OK as _pw_ok
    PROCWATCH_OK = True
except ImportError:
    PROCWATCH_OK = False


# ── Column definitions ────────────────────────────────────────
ALL_COLUMNS = [
    "name", "create_time", "cores", "cpu_usage", "status",
    "nice", "memory_usage", "read_bytes", "write_bytes",
    "n_threads", "username",
]
DEFAULT_COLUMNS = ",".join([
    "name", "cpu_usage", "memory_usage", "read_bytes",
    "write_bytes", "status", "create_time", "nice", "n_threads", "cores",
])


# ══════════════════════════════════════════════════════════════
#  SIZE FORMATTER
#  Article: def get_size(bytes): for unit in ['','K','M','G','T','P']
# ══════════════════════════════════════════════════════════════

def get_size(bytes_val: int) -> str:
    """
    Convert raw byte count to human-readable string.

    Article implementation — unchanged:
        for unit in ['', 'K', 'M', 'G', 'T', 'P']:
            if bytes < 1024:
                return f"{bytes:.2f}{unit}B"
            bytes /= 1024
    """
    val = float(bytes_val)
    for unit in ["", "K", "M", "G", "T", "P"]:
        if val < 1024:
            return f"{val:.2f}{unit}B"
        val /= 1024
    return f"{val:.2f}PB"


# ══════════════════════════════════════════════════════════════
#  PROCESS INFO COLLECTOR
#  Article: def get_processes_info()
#  Iterates psutil.process_iter() with oneshot() for efficiency.
# ══════════════════════════════════════════════════════════════

def get_processes_info() -> List[dict]:
    """
    Collect per-process metrics using psutil.

    Mirrors the article's get_processes_info() exactly, with one
    addition: a 'suspicious' flag populated by procwatch_engine
    when --suspicious mode is active.

    Article fields:
      pid           — process ID
      name          — executable name
      create_time   — datetime when process was spawned
      cores         — number of CPU cores this process can run on
      cpu_usage     — CPU usage percentage
      status        — running / sleeping / idle / zombie / etc.
      nice          — scheduling priority (lower = higher priority)
      memory_usage  — Unique Set Size (USS) in bytes — "true" footprint
      read_bytes    — total bytes read from disk
      write_bytes   — total bytes written to disk
      n_threads     — number of threads
      username      — owner of the process
    """
    processes = []

    for proc in psutil.process_iter():
        with proc.oneshot():
            pid = proc.pid
            if pid == 0:
                continue   # skip System Idle (Windows) / PID 0

            name = proc.name()

            try:
                create_time = datetime.fromtimestamp(proc.create_time())
            except OSError:
                create_time = datetime.fromtimestamp(psutil.boot_time())

            try:
                cores = len(proc.cpu_affinity())
            except (psutil.AccessDenied, AttributeError):
                cores = 0

            cpu_usage = proc.cpu_percent()

            status = proc.status()

            try:
                nice = int(proc.nice())
            except psutil.AccessDenied:
                nice = 0

            try:
                memory_usage = proc.memory_full_info().uss
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                memory_usage = 0

            try:
                io = proc.io_counters()
                read_bytes  = io.read_bytes
                write_bytes = io.write_bytes
            except (psutil.AccessDenied, AttributeError):
                read_bytes  = 0
                write_bytes = 0

            n_threads = proc.num_threads()

            try:
                username = proc.username()
            except (psutil.AccessDenied, KeyError):
                username = "N/A"

        processes.append({
            "pid":          pid,
            "name":         name,
            "create_time":  create_time,
            "cores":        cores,
            "cpu_usage":    cpu_usage,
            "status":       status,
            "nice":         nice,
            "memory_usage": memory_usage,
            "read_bytes":   read_bytes,
            "write_bytes":  write_bytes,
            "n_threads":    n_threads,
            "username":     username,
        })

    return processes


# ══════════════════════════════════════════════════════════════
#  DISPLAY HELPERS
# ══════════════════════════════════════════════════════════════

def _format_create_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _prepare_rows(processes: List[dict], columns: List[str],
                  sort_by: str, descending: bool,
                  n: int) -> List[dict]:
    """Sort, trim to n, and format byte fields for display."""
    # Sort
    reverse = descending
    key_fn  = lambda p: p.get(sort_by, 0)
    processes = sorted(processes, key=key_fn, reverse=reverse)

    # Limit
    if n > 0:
        processes = processes[:n]

    # Format for display (human-readable sizes, date strings)
    display = []
    for p in processes:
        row = {k: v for k, v in p.items()}
        row["memory_usage"] = get_size(p["memory_usage"])
        row["read_bytes"]   = get_size(p["read_bytes"])
        row["write_bytes"]  = get_size(p["write_bytes"])
        row["create_time"]  = _format_create_time(p["create_time"])
        display.append({c: row[c] for c in ["pid"] + columns if c in row})
    return display


def _print_plain(rows: List[dict], columns: List[str]) -> None:
    """Plain-text tabular output (no pandas required)."""
    all_cols = ["pid"] + [c for c in columns if c != "pid"]
    # Compute column widths
    widths = {c: max(len(str(c)), max((len(str(r.get(c, ""))) for r in rows), default=0))
              for c in all_cols}

    # Header
    header = "  ".join(str(c).ljust(widths[c]) for c in all_cols)
    sep    = "  ".join("-" * widths[c] for c in all_cols)
    print(header)
    print(sep)
    for row in rows:
        line = "  ".join(str(row.get(c, "")).ljust(widths[c]) for c in all_cols)
        print(line)


def display_report(processes: List[dict], columns_str: str,
                   sort_by: str, descending: bool, n: int) -> None:
    """Format and print the process table."""
    cols = [c.strip() for c in columns_str.split(",") if c.strip() in ALL_COLUMNS]
    if not cols:
        cols = [c.strip() for c in DEFAULT_COLUMNS.split(",")]

    rows = _prepare_rows(processes, cols, sort_by, descending, n)
    if not rows:
        print("[reporter] No processes found.")
        return

    if PANDAS_OK:
        # Article: df.to_string() for full display
        df = pd.DataFrame(rows).set_index("pid")
        cols_present = [c for c in cols if c in df.columns]
        print(df[cols_present].to_string())
    else:
        _print_plain(rows, cols)


# ══════════════════════════════════════════════════════════════
#  SUSPICIOUS PROCESS OVERLAY
#  Integration with procwatch_engine.py security scanner.
#  Adds a risk tier to each row so the table highlights
#  malicious processes alongside their resource metrics.
# ══════════════════════════════════════════════════════════════

def _overlay_suspicious(processes: List[dict]) -> List[dict]:
    """Add 'risk' field via ProcWatchEngine.scan() results."""
    if not PROCWATCH_OK:
        return processes

    pw      = ProcWatchEngine()
    # Build a PID → risk map from ProcWatch scan
    pid_risk = {}
    for pid in psutil.pids():
        try:
            proc     = psutil.Process(pid)
            findings = pw.scan_process(proc)
            if findings:
                sev_order = {"CRITICAL": 4, "HIGH": 3, "MED": 2, "LOW": 1}
                top = max(findings, key=lambda f: sev_order.get(f["severity"], 0))
                pid_risk[pid] = top["severity"]
        except Exception:
            pass

    for p in processes:
        p["risk"] = pid_risk.get(p["pid"], "")
    return processes


# ══════════════════════════════════════════════════════════════
#  MAIN / CLI
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Process Viewer & Monitor — AUA Botnet Research Lab\n"
            "Source: Article 2 — 'How to Make a Process Monitor in Python'\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c", "--columns",
        default=DEFAULT_COLUMNS,
        help=(
            f"Comma-separated columns to show. Available: {', '.join(ALL_COLUMNS)}. "
            f"Default: {DEFAULT_COLUMNS}"
        ),
    )
    parser.add_argument(
        "-s", "--sort-by",
        dest="sort_by",
        default="memory_usage",
        choices=ALL_COLUMNS,
        help="Column to sort by (default: memory_usage)",
    )
    parser.add_argument(
        "--descending",
        action="store_true",
        help="Sort in descending order",
    )
    parser.add_argument(
        "-n",
        type=int,
        default=25,
        help="Number of processes to show; 0 = all (default: 25)",
    )
    parser.add_argument(
        "-u", "--live-update",
        action="store_true",
        help="Keep running and refresh every 0.7s (like the article's live-update mode)",
    )
    parser.add_argument(
        "--suspicious",
        action="store_true",
        help="Overlay ProcWatch security scan (requires procwatch_engine.py)",
    )

    args = parser.parse_args()

    def _run_once():
        procs = get_processes_info()
        if args.suspicious:
            procs = _overlay_suspicious(procs)
        n = args.n if args.n > 0 else len(procs)
        display_report(procs, args.columns, args.sort_by, args.descending, n)

    # First run
    _run_once()

    # Article: live-update loop, refresh every 0.7s
    if args.live_update:
        while True:
            try:
                time.sleep(0.7)
                os.system("cls" if os.name == "nt" else "clear")
                _run_once()
            except KeyboardInterrupt:
                print("\n[reporter] Live update stopped.")
                break


if __name__ == "__main__":
    main()
