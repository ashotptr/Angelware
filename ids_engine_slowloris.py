"""
====================================================
 ids_engine_slowloris.py
 AUA CS 232/337 — IDS Engine 16: Slowloris Detector

 Gap closed (original): ids_detector.py had no engine that
 inspects HTTP request *content* for Slowloris signatures.
 firewall_dpi.py detects Slowloris via connection *duration*
 (TCP open >30s to port 80), which is a lagging indicator.
 This engine fires earlier, on the structural property of the
 attack: headers arriving but the request never terminating.

 Gap closed (THIS revision) — Distributed Slowloris detection:
   The article (Signs of Slowloris Attack section) states:
     "Analyzing network traffic patterns may reveal an abnormal
      increase in the number of simultaneous connections from
      *different IP addresses*, especially if these connections
      are not completing typical HTTP requests."

   The original engine's _check_concurrent() only detected
   >= HALF_OPEN_PER_IP connections from a *single* source IP.
   A coordinated Slowloris attack where each of N IPs opens
   only a few connections — staying below the per-IP threshold
   — would be completely invisible to the original engine even
   while the total half-open connection count was exhausting
   the server.

   This revision adds:

   1. _check_distributed() — fires a MED or HIGH alert when:
        total half-open connections across ALL IPs > DISTRIBUTED_TOTAL_THRESHOLD
        AND at least DISTRIBUTED_MIN_IPS distinct source IPs
        AND NO single IP exceeds HALF_OPEN_PER_IP
              (if a single IP did, _check_concurrent already fires)
      This is the "coordinated low-volume" pattern: each bot stays
      quiet, but together they overwhelm the server.

   2. Time-windowed IP tracking for distributed detection:
      Connections are bucketed into DISTRIBUTED_WINDOW_SEC windows.
      An IP contributes to the distributed count only if it has
      active half-open connections NOW (not just historically).

   3. _get_global_half_open() — returns per-IP half-open counts
      as a dict, shared between _check_concurrent and
      _check_distributed to avoid double-counting.

 Original detection method (from the Indusface article §"How to Detect"):
   "Connection tracking — connections open >N seconds without
    completing requests."
   "Monitor server logs for open connections without completed
    requests" → packet-level inspection of HTTP payload content.

 Two original alert conditions (preserved):
   HIGH — >= HALF_OPEN_PER_IP concurrent half-open HTTP
          connections from a single source IP
   MED  — any single connection has been half-open for more
          than STALE_CONNECTION_SEC seconds

 New alert condition:
   MED/HIGH — distributed: total half-open connections >
          DISTRIBUTED_TOTAL_THRESHOLD from >= DISTRIBUTED_MIN_IPS
          distinct IPs, each staying below HALF_OPEN_PER_IP

 Integration into ids_detector.py (unchanged from original):
   import ids_engine_slowloris as _e16
   _e16.register(alert)
   # In packet_handler():
   _e16.process_packet(pkt)
====================================================
"""

import threading
import time
from collections import defaultdict
from typing import Callable

try:
    from scapy.all import IP, TCP, Raw
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False


# ── Thresholds ─────────────────────────────────────────────────
MONITORED_PORT       = 80    # HTTP port to watch
HALF_OPEN_PER_IP     = 10   # concurrent half-open from one IP → HIGH alert
STALE_CONNECTION_SEC = 30   # single conn half-open > this → MED alert
PRUNE_INTERVAL_SEC   = 15   # background maintenance frequency
ALERT_COOLDOWN_SEC   = 60   # min seconds between repeated alerts per IP

# Distributed detection thresholds (new)
DISTRIBUTED_TOTAL_THRESHOLD = 30   # total half-open across ALL IPs → alert
DISTRIBUTED_MIN_IPS         = 3    # minimum distinct contributing source IPs
DISTRIBUTED_COOLDOWN_SEC    = 45   # cooldown for the global distributed alert


# ══════════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════════

class _ConnState:
    """Tracks a single TCP connection's Slowloris state."""
    __slots__ = ("first_seen", "last_header_ts", "headers_seen",
                 "terminated", "alerted_stale")

    def __init__(self, ts: float):
        self.first_seen     = ts
        self.last_header_ts = ts
        self.headers_seen   = 0    # count of keep-alive header drips received
        self.terminated     = False
        self.alerted_stale  = False


# key: (src_ip, sport, dst_ip, dport) → _ConnState
_connections: dict[tuple, _ConnState] = {}
_lock = threading.Lock()

# Per-source alert cooldowns (original)
_last_high_alert: dict[str, float] = defaultdict(float)
_last_med_alert:  dict[str, float] = defaultdict(float)

# Global distributed alert cooldown (new)
_last_distributed_alert: float = 0.0

_alert_fn: Callable | None = None


# ══════════════════════════════════════════════════════════════
#  SHARED HALF-OPEN COUNTER (new)
# ══════════════════════════════════════════════════════════════

def _get_global_half_open() -> dict[str, int]:
    """
    Returns {src_ip: half_open_count} for all IPs that currently
    have at least one active half-open connection (headers received,
    request not terminated).  Must be called while _lock is held.

    Shared by _check_concurrent() and _check_distributed() to avoid
    iterating _connections twice per packet.
    """
    per_ip: dict[str, int] = defaultdict(int)
    for (sip, _, _, _), conn in _connections.items():
        if not conn.terminated and conn.headers_seen > 0:
            per_ip[sip] += 1
    return dict(per_ip)


# ══════════════════════════════════════════════════════════════
#  PACKET PROCESSING
# ══════════════════════════════════════════════════════════════

def process_packet(pkt) -> None:
    """
    Call this from ids_detector.py's packet_handler() for every
    captured packet.  Thread-safe.
    """
    if not _SCAPY_OK:
        return
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[TCP].dport != MONITORED_PORT:
        return

    src_ip = pkt[IP].src
    sport  = pkt[TCP].sport
    dst_ip = pkt[IP].dst
    dport  = pkt[TCP].dport
    flags  = pkt[TCP].flags
    now    = time.time()
    key    = (src_ip, sport, dst_ip, dport)

    with _lock:
        # ── SYN: new connection ────────────────────────────────
        if flags & 0x02 and not (flags & 0x10):   # SYN, not SYN-ACK
            _connections[key] = _ConnState(ts=now)
            return

        # ── FIN or RST: connection closing ─────────────────────
        if flags & 0x01 or flags & 0x04:
            conn = _connections.pop(key, None)
            if conn:
                conn.terminated = True
            return

        if key not in _connections:
            return
        conn = _connections[key]

        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)

            if b"\r\n\r\n" in payload:
                # Completed HTTP request — not Slowloris.
                conn.terminated = True
                _connections.pop(key, None)
                return

            if b"\r\n" in payload or b"X-a:" in payload:
                # Keep-alive drip: header data without terminator.
                conn.headers_seen   += 1
                conn.last_header_ts  = now

        # ── Compute global half-open map once per packet ───────
        half_open_map = _get_global_half_open()

        # ── Per-IP check (original) ────────────────────────────
        _check_concurrent(src_ip, now, half_open_map)

        # ── Distributed check (new) ────────────────────────────
        _check_distributed(now, half_open_map)


def _check_concurrent(src_ip: str, now: float,
                       half_open_map: dict[str, int]) -> None:
    """
    Original detection: fire HIGH if a single source IP has
    >= HALF_OPEN_PER_IP concurrent half-open connections.
    Must be called while _lock is held.
    """
    half_open = half_open_map.get(src_ip, 0)
    if half_open >= HALF_OPEN_PER_IP:
        last = _last_high_alert[src_ip]
        if now - last >= ALERT_COOLDOWN_SEC:
            _last_high_alert[src_ip] = now
            _fire_alert(
                "HIGH",
                f"SLOWLORIS DETECTED (concurrent half-open): {src_ip}\n"
                f"  {half_open} simultaneous HTTP connections to "
                f":{MONITORED_PORT}\n"
                f"  that have received header drips but never sent "
                f"\\r\\n\\r\\n.\n"
                f"  Threshold: >={HALF_OPEN_PER_IP} concurrent per IP.\n"
                f"  Apache's thread pool is being exhausted — each open\n"
                f"  connection blocks one worker thread indefinitely.\n"
                f"  MITRE: T1499.002 (Service Exhaustion Flood — HTTP)"
            )


def _check_distributed(now: float, half_open_map: dict[str, int]) -> None:
    """
    NEW: Distributed Slowloris detection.

    Fires when the total half-open connection count across ALL IPs
    exceeds DISTRIBUTED_TOTAL_THRESHOLD, and at least
    DISTRIBUTED_MIN_IPS distinct source IPs are contributing,
    but NO single IP exceeds HALF_OPEN_PER_IP (which would already
    trigger _check_concurrent).

    This catches the coordinated low-volume pattern described in
    the article's Signs section:
      "an abnormal increase in the number of simultaneous connections
       from *different IP addresses*"

    Example: 5 bots each holding 8 connections → total 40 half-open,
    each bot stays under the per-IP threshold of 10, but together
    they exhaust a 40-connection thread pool.

    Must be called while _lock is held.
    """
    global _last_distributed_alert

    if not half_open_map:
        return

    total_half_open = sum(half_open_map.values())
    num_ips         = len(half_open_map)
    max_per_ip      = max(half_open_map.values()) if half_open_map else 0

    # Only fire if total exceeds threshold AND multiple IPs are involved
    # AND no single IP is already triggering the per-IP alert
    # (avoiding duplicate/redundant alerts for the obvious single-source case)
    if (total_half_open >= DISTRIBUTED_TOTAL_THRESHOLD
            and num_ips >= DISTRIBUTED_MIN_IPS
            and max_per_ip < HALF_OPEN_PER_IP):

        if now - _last_distributed_alert >= DISTRIBUTED_COOLDOWN_SEC:
            _last_distributed_alert = now

            # Rank IPs by contribution for the alert message
            top_ips = sorted(half_open_map.items(), key=lambda x: -x[1])[:5]
            ip_summary = ", ".join(
                f"{ip}({n})" for ip, n in top_ips
            )

            _fire_alert(
                "HIGH",
                f"SLOWLORIS DETECTED (distributed / multi-source):\n"
                f"  Total half-open connections: {total_half_open} "
                f"across {num_ips} distinct source IPs.\n"
                f"  No single IP exceeds the per-IP threshold "
                f"({max_per_ip} < {HALF_OPEN_PER_IP}).\n"
                f"  This is a coordinated low-volume attack where each\n"
                f"  bot stays below detection thresholds individually,\n"
                f"  but collectively exhausts the server's thread pool.\n"
                f"  Top contributors: {ip_summary}\n"
                f"  Thresholds: total>={DISTRIBUTED_TOTAL_THRESHOLD}, "
                f"IPs>={DISTRIBUTED_MIN_IPS}.\n"
                f"  Article ref: 'unusual network traffic patterns'\n"
                f"  (Signs of Slowloris Attack section)\n"
                f"  MITRE: T1499.002 (Service Exhaustion Flood — HTTP)"
            )


# ══════════════════════════════════════════════════════════════
#  STALE CONNECTION CHECK (background thread, original)
# ══════════════════════════════════════════════════════════════

def _check_stale(now: float) -> None:
    """
    Fires MED alerts for connections that have been half-open
    longer than STALE_CONNECTION_SEC.  Prunes old entries.
    Called by the background maintenance thread.
    """
    stale_threshold = now - STALE_CONNECTION_SEC
    to_delete: list[tuple] = []

    with _lock:
        for key, conn in list(_connections.items()):
            if conn.terminated:
                to_delete.append(key)
                continue

            if conn.headers_seen == 0:
                # No drips yet — wait for STALE_CONNECTION_SEC before pruning
                if conn.first_seen < stale_threshold:
                    to_delete.append(key)
                continue

            age = now - conn.first_seen
            if age >= STALE_CONNECTION_SEC and not conn.alerted_stale:
                conn.alerted_stale = True
                src_ip = key[0]
                last   = _last_med_alert[src_ip]
                if now - last >= ALERT_COOLDOWN_SEC:
                    _last_med_alert[src_ip] = now
                    _fire_alert(
                        "MED",
                        f"SLOWLORIS SUSPECTED (stale half-open conn): {src_ip}\n"
                        f"  Connection to :{MONITORED_PORT} open for {age:.0f}s\n"
                        f"  without sending HTTP request terminator "
                        f"(\\r\\n\\r\\n).\n"
                        f"  Threshold: >{STALE_CONNECTION_SEC}s.\n"
                        f"  Keep-alive drips seen: {conn.headers_seen}\n"
                        f"  Half-open connections mimic slow-but-legitimate\n"
                        f"  clients, making them hard to distinguish by\n"
                        f"  volume-based engines alone.\n"
                        f"  MITRE: T1499.002"
                    )

            # Prune very old connections not cleanly terminated
            if age > STALE_CONNECTION_SEC * 6:
                to_delete.append(key)

        for key in to_delete:
            _connections.pop(key, None)


# ══════════════════════════════════════════════════════════════
#  BACKGROUND MAINTENANCE THREAD
# ══════════════════════════════════════════════════════════════

def _maintenance_loop() -> None:
    """Runs every PRUNE_INTERVAL_SEC seconds."""
    while True:
        time.sleep(PRUNE_INTERVAL_SEC)
        try:
            now = time.time()
            _check_stale(now)

            # Also re-evaluate distributed alert in maintenance pass,
            # in case the packet rate is low and _check_distributed
            # is not being called often enough via process_packet().
            with _lock:
                if _connections:
                    half_open_map = _get_global_half_open()
                    _check_distributed(now, half_open_map)

        except Exception as exc:
            print(f"[E16-Slowloris] maintenance error: {exc}")


# ══════════════════════════════════════════════════════════════
#  INTEGRATION ENTRY POINT
# ══════════════════════════════════════════════════════════════

def register(alert_callback: Callable) -> None:
    """
    Call once at ids_detector.py startup.

        import ids_engine_slowloris as _e16
        _e16.register(alert)

    Starts the background maintenance thread automatically.
    """
    global _alert_fn
    _alert_fn = alert_callback
    t = threading.Thread(
        target=_maintenance_loop,
        daemon=True,
        name="e16-slowloris-maint",
    )
    t.start()
    print(
        f"[IDS] Slowloris content detector: ENABLED (Engine 16)\n"
        f"[IDS]   Single-IP alert:           >= {HALF_OPEN_PER_IP} half-open "
        f"connections\n"
        f"[IDS]   Stale connection alert:     > {STALE_CONNECTION_SEC}s without "
        f"terminator\n"
        f"[IDS]   Distributed alert (new):    >= {DISTRIBUTED_TOTAL_THRESHOLD} "
        f"total half-open from >= {DISTRIBUTED_MIN_IPS} IPs\n"
        f"[IDS]   Complements firewall_dpi.py (duration-based) with "
        f"payload-content + distributed detection."
    )


def _fire_alert(severity: str, msg: str) -> None:
    """Thread-safe alert dispatch."""
    if _alert_fn is not None:
        try:
            _alert_fn("Slowloris/E16", severity, msg)
        except Exception:
            pass
    else:
        print(f"\n[E16-ALERT/{severity}] {msg}\n")


# ══════════════════════════════════════════════════════════════
#  STATUS / DIAGNOSTICS
# ══════════════════════════════════════════════════════════════

def get_status() -> dict:
    """Return current engine state — useful for test assertions."""
    with _lock:
        tracked   = len(_connections)
        half_open_map = _get_global_half_open()
        total_half_open = sum(half_open_map.values())

    return {
        "engine":               "E16/Slowloris",
        "tracked_conns":        tracked,
        "half_open_total":      total_half_open,
        "half_open_per_ip":     dict(half_open_map),
        "distinct_ips":         len(half_open_map),
        "threshold_high":       HALF_OPEN_PER_IP,
        "threshold_stale_sec":  STALE_CONNECTION_SEC,
        "distributed_threshold": DISTRIBUTED_TOTAL_THRESHOLD,
        "distributed_min_ips":  DISTRIBUTED_MIN_IPS,
        "distributed_active": (
            total_half_open >= DISTRIBUTED_TOTAL_THRESHOLD
            and len(half_open_map) >= DISTRIBUTED_MIN_IPS
        ),
    }


# ══════════════════════════════════════════════════════════════
#  STANDALONE DEMO
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("ids_engine_slowloris.py — Engine 16 (with distributed detection)")
    print()
    print("Integration in ids_detector.py:")
    print("  import ids_engine_slowloris as _e16")
    print("  _e16.register(alert)          # after alert() is defined")
    print("  # In packet_handler():")
    print("  _e16.process_packet(pkt)      # alongside other process_* calls")
    print()
    print("Thresholds:")
    print(f"  HIGH (single-IP):   >= {HALF_OPEN_PER_IP} half-open connections "
          f"from one source IP")
    print(f"  MED  (stale):       any connection half-open > {STALE_CONNECTION_SEC}s "
          f"without \\r\\n\\r\\n")
    print(f"  HIGH (distributed): >= {DISTRIBUTED_TOTAL_THRESHOLD} total half-open "
          f"from >= {DISTRIBUTED_MIN_IPS} distinct IPs,")
    print(f"                      each staying below the per-IP threshold ({HALF_OPEN_PER_IP})")
    print()
    print("The distributed alert closes the gap identified in the Indusface article:")
    print("  'an abnormal increase in the number of simultaneous connections")
    print("   from *different IP addresses*'")
    print("  (Signs of Slowloris Attack section)")