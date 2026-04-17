#!/usr/bin/env python3
"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Centralised Syslog Aggregator
 Environment: ISOLATED VM LAB ONLY
====================================================

Source: JHU HotSoS '24 §3.1
  "The Syslog service captures and centralises the activity logs from
   each container, enabling us to analyse the tactics and interactions
   of the bots thoroughly."

Architecture
────────────
  Each honeypot container emits one JSON line per event to
  UDP/TCP 0.0.0.0:5140 (matching docker-compose.yml).
  This aggregator:
    1. Receives raw syslog/JSON frames from ALL services simultaneously
    2. Writes a single unified NDJSON file: /var/log/syslog-central/all.json
    3. Keeps per-service rotating files:
         /var/log/syslog-central/ssh.json
         /var/log/syslog-central/http.json
         /var/log/syslog-central/smtp.json
         /var/log/syslog-central/ldap.json
         /var/log/syslog-central/rdp.json
         /var/log/syslog-central/ftp.json
    4. Exposes GET /syslog/status HTTP endpoint (port 5141) for IDS
    5. Optionally forwards HIGH-severity events to ids_detector.py

Usage
─────
  python3 syslog_aggregator.py [--host 0.0.0.0] [--port 5140]
  python3 syslog_aggregator.py --dump       # pretty-print last 50 events
  python3 syslog_aggregator.py --stats      # per-service counts
"""

import argparse
import datetime
import json
import os
import queue
import socket
import socketserver
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────
LISTEN_HOST   = "0.0.0.0"
LISTEN_PORT   = 5140
STATUS_PORT   = 5141            # HTTP endpoint for GET /syslog/status
LOG_ROOT      = Path("/var/log/syslog-central")
LOG_ROOT.mkdir(parents=True, exist_ok=True)
ALL_LOG       = LOG_ROOT / "all.json"
MAX_QUEUE     = 10_000          # drop-tail if IDS consumer falls behind

# ── Service name → log file mapping ───────────────────────────
SERVICE_FILES = {
    "SSH":   LOG_ROOT / "ssh.json",
    "FTP":   LOG_ROOT / "ftp.json",
    "HTTP":  LOG_ROOT / "http.json",
    "HTTPS": LOG_ROOT / "http.json",   # combined with HTTP
    "SMTP":  LOG_ROOT / "smtp.json",
    "LDAP":  LOG_ROOT / "ldap.json",
    "RDP":   LOG_ROOT / "rdp.json",
}

# ── Shared state ───────────────────────────────────────────────
_event_queue:   queue.Queue = queue.Queue(maxsize=MAX_QUEUE)
_write_lock   = threading.Lock()
_stats: dict  = defaultdict(int)   # service → event count
_stats_lock   = threading.Lock()
_recent: list = []                 # last 50 events (circular)
_recent_lock  = threading.Lock()
RECENT_SIZE   = 50


# ══════════════════════════════════════════════════════════════
#  PARSERS
# ══════════════════════════════════════════════════════════════

def _parse_event(raw: bytes) -> dict:
    """
    Accept either:
      • A JSON line (emitted by multi_service_honeypot.py / fake_portal.py)
      • A BSD syslog frame  <PRI>TIMESTAMP HOST TAG: MSG
    Returns a normalised dict with at minimum:
      { timestamp, service, remote_ip, data, raw }
    """
    text = raw.decode("utf-8", errors="replace").strip()

    # Try JSON first
    if text.startswith("{"):
        try:
            ev = json.loads(text)
            ev.setdefault("timestamp", datetime.datetime.now().isoformat())
            ev.setdefault("service",   "UNKNOWN")
            ev.setdefault("remote_ip", "0.0.0.0")
            ev.setdefault("data",      "")
            ev["_raw"] = text
            return ev
        except json.JSONDecodeError:
            pass

    # Try BSD syslog (<PRI>MMDD HH:MM:SS host tag: msg)
    ev = {
        "timestamp": datetime.datetime.now().isoformat(),
        "service":   "SYSLOG",
        "remote_ip": "0.0.0.0",
        "data":      text,
        "_raw":      text,
    }
    if text.startswith("<"):
        try:
            end = text.index(">")
            pri = int(text[1:end])
            ev["syslog_facility"] = pri >> 3
            ev["syslog_severity"] = pri & 0x07
            rest = text[end + 1:].strip()
            # Attempt to extract hostname and tag
            parts = rest.split(None, 3)
            if len(parts) >= 3:
                ev["syslog_host"] = parts[1]
                ev["syslog_tag"]  = parts[2].rstrip(":")
                ev["data"]        = parts[3] if len(parts) > 3 else ""
        except (ValueError, IndexError):
            pass
    return ev


# ══════════════════════════════════════════════════════════════
#  WRITERS
# ══════════════════════════════════════════════════════════════

def _writer_thread():
    """
    Consumes events from _event_queue and writes to per-service files.
    Single writer → no file-handle contention.
    """
    open_handles: dict = {}

    def _fh(path: Path):
        if path not in open_handles:
            open_handles[path] = open(path, "a", buffering=1)
        return open_handles[path]

    while True:
        try:
            ev = _event_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        line = json.dumps(ev) + "\n"

        with _write_lock:
            # Always write to the unified log
            _fh(ALL_LOG).write(line)

            # Write to per-service log
            svc = ev.get("service", "UNKNOWN").upper()
            svc_file = SERVICE_FILES.get(svc)
            if svc_file:
                _fh(svc_file).write(line)

        # Update stats
        with _stats_lock:
            _stats[svc] += 1
            _stats["__total__"] += 1

        # Update recent window
        with _recent_lock:
            _recent.append(ev)
            if len(_recent) > RECENT_SIZE:
                _recent.pop(0)


# ══════════════════════════════════════════════════════════════
#  UDP SERVER
# ══════════════════════════════════════════════════════════════

class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, _ = self.request
        if not data:
            return
        ev = _parse_event(data)
        try:
            _event_queue.put_nowait(ev)
        except queue.Full:
            pass  # drop-tail under overload


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads      = True


# ══════════════════════════════════════════════════════════════
#  TCP SERVER
# ══════════════════════════════════════════════════════════════

class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            for raw_line in self.rfile:
                ev = _parse_event(raw_line)
                try:
                    _event_queue.put_nowait(ev)
                except queue.Full:
                    pass
        except Exception:
            pass


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads      = True


# ══════════════════════════════════════════════════════════════
#  HTTP STATUS ENDPOINT  (GET /syslog/status)
# ══════════════════════════════════════════════════════════════

class _StatusHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # suppress default access log

    def do_GET(self):
        if self.path == "/syslog/status":
            with _stats_lock:
                stats_snap = dict(_stats)
            with _recent_lock:
                recent_snap = list(_recent[-10:])

            payload = json.dumps({
                "timestamp":   datetime.datetime.now().isoformat(),
                "stats":       stats_snap,
                "queue_depth": _event_queue.qsize(),
                "recent":      recent_snap,
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        elif self.path == "/syslog/recent":
            with _recent_lock:
                recent_snap = list(_recent)
            payload = json.dumps(recent_snap, default=str).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        else:
            self.send_response(404)
            self.end_headers()


# ══════════════════════════════════════════════════════════════
#  STATS / DUMP CLI HELPERS
# ══════════════════════════════════════════════════════════════

def _cli_stats():
    """Print per-service counts from the unified log file."""
    if not ALL_LOG.exists():
        print(f"[SYSLOG] No log file at {ALL_LOG}")
        return
    counts: dict = defaultdict(int)
    with open(ALL_LOG) as f:
        for line in f:
            try:
                ev = json.loads(line)
                counts[ev.get("service", "UNKNOWN")] += 1
            except Exception:
                pass
    total = sum(counts.values())
    print(f"\n{'Service':<12} {'Events':>8}")
    print("─" * 22)
    for svc, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {svc:<10} {n:>8}")
    print("─" * 22)
    print(f"  {'TOTAL':<10} {total:>8}\n")


def _cli_dump(n: int = 50):
    """Pretty-print the last n events from the unified log."""
    if not ALL_LOG.exists():
        print(f"[SYSLOG] No log file at {ALL_LOG}")
        return
    lines = ALL_LOG.read_text().strip().split("\n")
    for line in lines[-n:]:
        try:
            ev = json.loads(line)
            print(f"  [{ev.get('timestamp','?')}] [{ev.get('service','?'):5}] "
                  f"{ev.get('remote_ip','?'):<16} {str(ev.get('data',''))[:80]}")
        except Exception:
            print(f"  {line[:100]}")


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Centralised Syslog Aggregator — AUA CS 232/337"
    )
    parser.add_argument("--host",  default=LISTEN_HOST)
    parser.add_argument("--port",  type=int, default=LISTEN_PORT)
    parser.add_argument("--stats", action="store_true",
                        help="Print per-service counts and exit")
    parser.add_argument("--dump",  action="store_true",
                        help="Print last 50 events and exit")
    args = parser.parse_args()

    if args.stats:
        _cli_stats(); return
    if args.dump:
        _cli_dump();  return

    # Start writer thread
    wt = threading.Thread(target=_writer_thread, daemon=True, name="writer")
    wt.start()

    # Start UDP server
    udp_srv = ThreadedUDPServer((args.host, args.port), _UDPHandler)
    ut = threading.Thread(target=udp_srv.serve_forever,
                          daemon=True, name="udp")
    ut.start()

    # Start TCP server
    tcp_srv = ThreadedTCPServer((args.host, args.port), _TCPHandler)
    tt = threading.Thread(target=tcp_srv.serve_forever,
                          daemon=True, name="tcp")
    tt.start()

    # Start HTTP status server
    http_srv = HTTPServer((args.host, STATUS_PORT), _StatusHandler)
    ht = threading.Thread(target=http_srv.serve_forever,
                          daemon=True, name="http_status")
    ht.start()

    print(f"[SYSLOG] Aggregator listening on {args.host}:{args.port} "
          f"(UDP+TCP)")
    print(f"[SYSLOG] Status endpoint: http://{args.host}:{STATUS_PORT}/syslog/status")
    print(f"[SYSLOG] Unified log:     {ALL_LOG}")
    print(f"[SYSLOG] Per-service logs in {LOG_ROOT}/")
    print(f"[SYSLOG] Press Ctrl-C to stop.")

    try:
        while True:
            time.sleep(5)
            with _stats_lock:
                total = _stats.get("__total__", 0)
            print(f"[SYSLOG] {datetime.datetime.now().strftime('%H:%M:%S')} "
                  f"total={total}  queue={_event_queue.qsize()}", end="\r")
    except KeyboardInterrupt:
        print("\n[SYSLOG] Shutting down.")
        udp_srv.shutdown()
        tcp_srv.shutdown()
        http_srv.shutdown()


if __name__ == "__main__":
    main()
