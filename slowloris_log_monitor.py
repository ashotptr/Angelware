"""
====================================================
 slowloris_log_monitor.py
 AUA CS 232/337 — Slowloris Log Monitor

 Gap closed: The Indusface article's first detection method:
   "Monitoring Server Logs: Regularly review server logs for
    unusual patterns, such as an abnormal number of open
    connections from a single IP address or repeated connections
    without completing requests."
 had no corresponding implementation in the project.
 ids_engine_slowloris.py works at the packet/socket level,
 which is complementary but mechanically different.
 This module implements the log-based detection path.

 Three detection signals:

   Signal A — 408 burst (access log)
     HTTP 408 (Request Timeout) is emitted when Apache/Nginx
     closes a connection that never completed its request — the
     defining signature of a Slowloris socket that finally timed
     out.  A burst of 408s from a single IP is a HIGH-confidence
     indicator.

   Signal B — reqtimeout error burst (error log)
     mod_reqtimeout logs AH01360 ("Request header read timeout")
     and AH01114 ("HTTP: failed to read request within time limit")
     to the error log each time it kills a Slowloris-style
     connection.  A burst of these from one IP is also HIGH.

   Signal C — connection rate (access log)
     Many new connections from a single IP in a short window,
     especially when accompanied by few or zero successful
     responses, is a MED indicator of connection-exhaustion.

   Signal D — live connection count (ss / netstat)
     The article: "Connection Tracking: keep track of open
     connections and their duration."  A background thread runs
     ss/netstat periodically and fires HIGH if any single IP
     holds >= NETSTAT_CONN_THRESH simultaneous ESTABLISHED
     connections to the monitored port, even before any
     timeout appears in the logs (the lagging indicator).

 Integration with ids_detector.py:
   import slowloris_log_monitor as slm
   _monitor = slm.start(alert_fn=alert)
   # runs in daemon threads; call _monitor.stop() on shutdown

 Standalone usage:
   sudo python3 slowloris_log_monitor.py
   sudo python3 slowloris_log_monitor.py --nginx
   sudo python3 slowloris_log_monitor.py \
       --access /var/log/apache2/access.log \
       --error  /var/log/apache2/error.log  \
       --port 80 --window 60 --interval 10
====================================================
"""

import argparse
import re
import subprocess
import sys
import time
import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Callable, Optional

# ── Default log paths ──────────────────────────────────────────
APACHE_ACCESS_LOG = "/var/log/apache2/access.log"
APACHE_ERROR_LOG  = "/var/log/apache2/error.log"
NGINX_ACCESS_LOG  = "/var/log/nginx/access.log"
NGINX_ERROR_LOG   = "/var/log/nginx/error.log"

# ── Apache error codes that signal Slowloris connection drops ──
# AH01360 = mod_reqtimeout: Request header read timeout
# AH01114 = HTTP: failed to read request within time limit
# AH00137 = unable to read request (keep-alive or initial)
REQTIMEOUT_CODES = {"AH01360", "AH01114", "AH00137"}

# ── Detection thresholds ───────────────────────────────────────
WINDOW_SEC          = 60    # rolling window size in seconds
TIMEOUT_408_THRESH  = 5     # 408 responses from one IP in window → HIGH
ERROR_BURST_THRESH  = 3     # reqtimeout error entries per IP in window → HIGH
CONN_RATE_THRESH    = 20    # total connections from one IP in window → MED
NETSTAT_CONN_THRESH = 15    # simultaneous ESTABLISHED connections per IP → HIGH
NETSTAT_INTERVAL    = 10    # seconds between ss/netstat checks
ALERT_COOLDOWN      = 30    # seconds before repeating same-IP same-severity alert


# ══════════════════════════════════════════════════════════════
#  LOG LINE PARSERS
# ══════════════════════════════════════════════════════════════

# Combined / Common Log Format:
# IP - user [date] "METHOD /path PROTO" STATUS size [referrer user-agent]
_ACCESS_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|\S+) '   # IPv4 or hostname
    r'\S+ \S+ \[[^\]]+\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

def parse_access_line(line: str) -> Optional[dict]:
    """
    Parse one line from an Apache or Nginx access log.
    Returns None if the line doesn't match or isn't interesting.
    """
    m = _ACCESS_RE.match(line.strip())
    if not m:
        return None
    return {
        "ip":     m.group("ip"),
        "status": int(m.group("status")),
        "path":   m.group("path"),
        "method": m.group("method"),
        "ts":     time.monotonic(),
    }


# Apache error log:
# [date] [module:level] [pid N] [client IP:port] AHxxxxx: message
_ERROR_APACHE_RE = re.compile(
    r'\[client (?P<ip>[\d.]+):\d+\]\s*(?P<code>AH\d+)?[: ]*(?P<msg>.*)'
)

def parse_error_line(line: str) -> Optional[dict]:
    """
    Parse one line from an Apache or Nginx error log.
    Returns a dict only for lines that indicate a Slowloris-style timeout.
    """
    low = line.lower()

    # Nginx: "upstream timed out", "client timed out", "request timed out"
    if any(kw in low for kw in ("request timed out", "client timed out",
                                 "header timeout",    "reading client request")):
        ip_m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
        if ip_m:
            return {"ip": ip_m.group(1), "code": "NGINX_TIMEOUT", "ts": time.monotonic()}

    # Apache: look for AH codes or generic timeout phrases
    m = _ERROR_APACHE_RE.search(line)
    if not m:
        return None

    code = m.group("code") or ""
    msg  = m.group("msg").lower()
    if code not in REQTIMEOUT_CODES and "timeout" not in msg and "failed to read" not in msg:
        return None

    return {
        "ip":   m.group("ip"),
        "code": code or "TIMEOUT",
        "ts":   time.monotonic(),
    }


# ══════════════════════════════════════════════════════════════
#  DETECTOR
# ══════════════════════════════════════════════════════════════

class SlowlorisLogDetector:
    """
    Stateful, rolling-window detector for log-based Slowloris signals.

    Thread-safe.  Call:
      process_access(event)   on each parsed access log line
      process_error(event)    on each parsed error log line
      check_netstat(port)     periodically for live connection counts
    """

    def __init__(self,
                 window_sec: float = WINDOW_SEC,
                 alert_fn: Callable = None):
        self.window_sec = window_sec
        self.alert_fn   = alert_fn or _default_alert

        self._lock = threading.Lock()

        # per-IP lists of monotonic timestamps inside the window
        self._ip_408:   dict[str, list] = defaultdict(list)
        self._ip_error: dict[str, list] = defaultdict(list)
        self._ip_conn:  dict[str, list] = defaultdict(list)

        # cooldown: {f"{ip}:{severity}"} → last alert monotonic time
        self._last_alert: dict[str, float] = defaultdict(float)

    # ── Internal helpers ───────────────────────────────────────

    def _prune(self, now: float) -> None:
        """Drop events older than the window.  Must hold _lock."""
        cutoff = now - self.window_sec
        for store in (self._ip_408, self._ip_error, self._ip_conn):
            for ip in list(store.keys()):
                store[ip] = [t for t in store[ip] if t > cutoff]
                if not store[ip]:
                    del store[ip]

    def _fire(self, ip: str, now: float, severity: str, msg: str) -> None:
        """Emit alert if cooldown has expired.  Must hold _lock."""
        key = f"{ip}:{severity}"
        if now - self._last_alert[key] >= ALERT_COOLDOWN:
            self._last_alert[key] = now
            self.alert_fn(severity, msg)

    # ── Public event handlers ──────────────────────────────────

    def process_access(self, event: dict) -> None:
        """Call with the dict returned by parse_access_line()."""
        if not event:
            return
        now = event["ts"]
        ip  = event["ip"]

        with self._lock:
            self._prune(now)
            self._ip_conn[ip].append(now)

            if event["status"] == 408:
                self._ip_408[ip].append(now)

            n_408  = len(self._ip_408.get(ip, []))
            n_conn = len(self._ip_conn.get(ip, []))

            # Signal A: 408 burst
            if n_408 >= TIMEOUT_408_THRESH:
                self._fire(
                    ip, now, "HIGH",
                    f"SLOWLORIS DETECTED (log — 408 burst): {ip}\n"
                    f"  {n_408} HTTP 408 Request Timeout responses in "
                    f"{self.window_sec:.0f}s window.\n"
                    f"  A 408 is emitted when the server closes a connection\n"
                    f"  that never sent a complete HTTP request — each one\n"
                    f"  represents a Slowloris socket that finally timed out.\n"
                    f"  Threshold: >={TIMEOUT_408_THRESH} per {self.window_sec:.0f}s.\n"
                    f"  Article ref: 'Monitoring Server Logs' (Detection §1)\n"
                    f"  MITRE: T1499.002 (Service Exhaustion Flood — HTTP)"
                )

            # Signal C: connection rate
            if n_conn >= CONN_RATE_THRESH:
                self._fire(
                    ip, now, "MED",
                    f"SLOWLORIS SUSPECTED (log — connection rate): {ip}\n"
                    f"  {n_conn} connections logged in {self.window_sec:.0f}s window.\n"
                    f"  High connection rate, especially when accompanied by\n"
                    f"  few successful responses, indicates connection-exhaustion.\n"
                    f"  Threshold: >={CONN_RATE_THRESH} per {self.window_sec:.0f}s.\n"
                    f"  Article ref: 'Monitoring Server Logs' (Detection §1)\n"
                    f"  MITRE: T1499.002"
                )

    def process_error(self, event: dict) -> None:
        """Call with the dict returned by parse_error_line()."""
        if not event:
            return
        now = event["ts"]
        ip  = event["ip"]

        with self._lock:
            self._prune(now)
            self._ip_error[ip].append(now)
            n_err = len(self._ip_error[ip])

            # Signal B: reqtimeout error burst
            if n_err >= ERROR_BURST_THRESH:
                self._fire(
                    ip, now, "HIGH",
                    f"SLOWLORIS DETECTED (log — reqtimeout errors): {ip}\n"
                    f"  {n_err} mod_reqtimeout/timeout error entries in "
                    f"{self.window_sec:.0f}s window.\n"
                    f"  Code: {event.get('code', 'TIMEOUT')}\n"
                    f"  These fire when Apache enforces MinRate — a Slowloris\n"
                    f"  drip sends ~10 bytes every 10s (1 B/s), far below the\n"
                    f"  500 B/s MinRate threshold, so mod_reqtimeout closes it\n"
                    f"  and writes this entry to the error log.\n"
                    f"  Threshold: >={ERROR_BURST_THRESH} per {self.window_sec:.0f}s.\n"
                    f"  Article ref: 'Monitoring Server Logs' (Detection §1)\n"
                    f"  MITRE: T1499.002"
                )

    def check_netstat(self, port: int = 80) -> dict:
        """
        Signal D: live connection count via ss/netstat.
        The article: 'Connection Tracking — identify connections that remain
        open for an extended period without completing requests.'
        This supplements the log signals, which lag by the reqtimeout value
        (10–20 s by default).  ss fires as soon as connections are ESTABLISHED,
        before any timeout entry appears in any log.

        Returns {ip: count} for all IPs with >= 1 connection.
        """
        per_ip = _count_connections(port)
        now    = time.monotonic()

        with self._lock:
            for ip, count in per_ip.items():
                if count >= NETSTAT_CONN_THRESH:
                    self._fire(
                        ip, now, "HIGH",
                        f"SLOWLORIS DETECTED (netstat — open connections): {ip}\n"
                        f"  {count} simultaneous ESTABLISHED TCP connections\n"
                        f"  to port {port} right now.\n"
                        f"  Each open connection blocks one Apache worker thread.\n"
                        f"  This is a pre-log signal: it fires before any 408 or\n"
                        f"  reqtimeout entry appears in the logs.\n"
                        f"  Threshold: >={NETSTAT_CONN_THRESH} concurrent.\n"
                        f"  Article ref: 'Connection Tracking' (Detection §3)\n"
                        f"  MITRE: T1499.002"
                    )
        return per_ip

    def stats(self) -> dict:
        """Return current window stats — useful for /stats endpoints."""
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            return {
                "window_sec":      self.window_sec,
                "ips_with_408":    {ip: len(ts) for ip, ts in self._ip_408.items()},
                "ips_with_errors": {ip: len(ts) for ip, ts in self._ip_error.items()},
                "ips_by_conn":     {ip: len(ts) for ip, ts in self._ip_conn.items()},
            }


def _default_alert(severity: str, msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n[LOG-MONITOR {ts}] [{severity}]\n{msg}\n", flush=True)


def _count_connections(port: int) -> dict:
    """
    Count ESTABLISHED TCP connections to `port` per remote IP.
    Tries 'ss' first (iproute2), falls back to 'netstat'.
    Returns {ip: count}.
    """
    per_ip: dict = defaultdict(int)

    try:
        result = subprocess.run(
            ["ss", "-tn", f"dport = :{port}"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "ESTAB" not in line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                peer = parts[4]
                ip   = peer.rsplit(":", 1)[0].strip("[]")
                if ip:
                    per_ip[ip] += 1
        return dict(per_ip)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    try:
        result = subprocess.run(
            ["netstat", "-tn"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "ESTABLISHED" not in line:
                continue
            parts = line.split()
            if len(parts) >= 5 and f":{port}" in parts[3]:
                ip = parts[4].rsplit(":", 1)[0]
                per_ip[ip] += 1
        return dict(per_ip)
    except Exception:
        return {}


# ══════════════════════════════════════════════════════════════
#  LOG TAILER
# ══════════════════════════════════════════════════════════════

class LogTailer:
    """
    Follows a log file like 'tail -F'.
    Reads new lines as they arrive; re-opens on log rotation (inode change).
    Calls handler(line) from a daemon thread.
    """

    def __init__(self, path: str, handler: Callable[[str], None],
                 poll_interval: float = 0.25):
        self.path          = path
        self.handler       = handler
        self.poll_interval = poll_interval
        self._stop         = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "LogTailer":
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name=f"tailer:{self.path}",
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        import os
        fh    = None
        inode = None
        while not self._stop.is_set():
            try:
                stat = os.stat(self.path)
            except FileNotFoundError:
                time.sleep(self.poll_interval)
                continue

            if fh is None or stat.st_ino != inode:
                if fh:
                    fh.close()
                try:
                    fh    = open(self.path, "r", errors="replace")
                    inode = stat.st_ino
                    fh.seek(0, 2)   # jump to end; ignore history
                except OSError:
                    time.sleep(self.poll_interval)
                    continue

            line = fh.readline()
            if line:
                try:
                    self.handler(line.rstrip("\n"))
                except Exception:
                    pass
            else:
                time.sleep(self.poll_interval)

        if fh:
            fh.close()


# ══════════════════════════════════════════════════════════════
#  MONITOR ORCHESTRATOR
# ══════════════════════════════════════════════════════════════

class SlowlorisLogMonitor:
    """
    Wires together: two LogTailers (access + error logs),
    a SlowlorisLogDetector, and a periodic netstat background check.

    Use start() to launch all daemon threads, stop() to clean up.
    """

    def __init__(self,
                 access_log: str = APACHE_ACCESS_LOG,
                 error_log:  str = APACHE_ERROR_LOG,
                 port: int       = 80,
                 window_sec: float = WINDOW_SEC,
                 netstat_interval: float = NETSTAT_INTERVAL,
                 alert_fn: Callable = None):
        self.access_log       = access_log
        self.error_log        = error_log
        self.port             = port
        self.netstat_interval = netstat_interval

        self.detector = SlowlorisLogDetector(
            window_sec=window_sec,
            alert_fn=alert_fn,
        )
        self._tailers: list = []
        self._stop          = threading.Event()

    def start(self) -> "SlowlorisLogMonitor":
        print(f"[log-monitor] Tailing access log : {self.access_log}")
        self._tailers.append(
            LogTailer(self.access_log, self._on_access).start()
        )
        print(f"[log-monitor] Tailing error log  : {self.error_log}")
        self._tailers.append(
            LogTailer(self.error_log, self._on_error).start()
        )
        t = threading.Thread(target=self._netstat_loop, daemon=True,
                             name="log-monitor:netstat")
        t.start()
        print(f"[log-monitor] netstat check every {self.netstat_interval}s "
              f"on port {self.port}")
        print("[log-monitor] Running. Ctrl-C to stop.\n")
        return self

    def stop(self) -> None:
        self._stop.set()
        for t in self._tailers:
            t.stop()

    def _on_access(self, line: str) -> None:
        self.detector.process_access(parse_access_line(line))

    def _on_error(self, line: str) -> None:
        self.detector.process_error(parse_error_line(line))

    def _netstat_loop(self) -> None:
        while not self._stop.wait(self.netstat_interval):
            try:
                self.detector.check_netstat(self.port)
            except Exception as exc:
                print(f"[log-monitor] netstat error: {exc}")


# ── Integration helper (imported by ids_detector.py) ──────────

def start(access_log: str = APACHE_ACCESS_LOG,
          error_log:  str = APACHE_ERROR_LOG,
          port: int       = 80,
          window_sec: float = WINDOW_SEC,
          alert_fn: Callable = None) -> SlowlorisLogMonitor:
    """
    Convenience entry-point for ids_detector.py:

        import slowloris_log_monitor as slm
        _log_monitor = slm.start(alert_fn=alert)
        # ... later ...
        _log_monitor.stop()
    """
    m = SlowlorisLogMonitor(
        access_log=access_log,
        error_log=error_log,
        port=port,
        window_sec=window_sec,
        alert_fn=alert_fn,
    )
    return m.start()


# ══════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════

def main() -> None:
    p = argparse.ArgumentParser(
        description="Slowloris log-based detector — AUA CS 232/337"
    )
    p.add_argument("--access", default=APACHE_ACCESS_LOG,
                   help=f"Path to web server access log "
                        f"(default: {APACHE_ACCESS_LOG})")
    p.add_argument("--error",  default=APACHE_ERROR_LOG,
                   help=f"Path to web server error log "
                        f"(default: {APACHE_ERROR_LOG})")
    p.add_argument("--nginx",  action="store_true",
                   help="Use Nginx default log paths instead of Apache")
    p.add_argument("--port",   type=int, default=80,
                   help="TCP port to watch via ss/netstat (default: 80)")
    p.add_argument("--window", type=float, default=WINDOW_SEC,
                   help=f"Rolling detection window in seconds "
                        f"(default: {WINDOW_SEC})")
    p.add_argument("--interval", type=float, default=NETSTAT_INTERVAL,
                   help=f"Seconds between netstat/ss checks "
                        f"(default: {NETSTAT_INTERVAL})")
    args = p.parse_args()

    if args.nginx:
        args.access = NGINX_ACCESS_LOG
        args.error  = NGINX_ERROR_LOG

    monitor = SlowlorisLogMonitor(
        access_log       = args.access,
        error_log        = args.error,
        port             = args.port,
        window_sec       = args.window,
        netstat_interval = args.interval,
    )
    monitor.start()

    try:
        while True:
            time.sleep(60)
            s = monitor.detector.stats()
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[log-monitor {ts}] Window stats:")
            for label, d in [
                ("408s/ip",  s["ips_with_408"]),
                ("errors/ip",s["ips_with_errors"]),
                ("conns/ip", s["ips_by_conn"]),
            ]:
                if d:
                    top = sorted(d.items(), key=lambda x: -x[1])[:3]
                    print(f"  {label}: {top}")
    except KeyboardInterrupt:
        print("\n[log-monitor] Stopping.")
        monitor.stop()


if __name__ == "__main__":
    main()
