"""
====================================================
 ids_engine_slowloris.py
 AUA CS 232/337 — IDS Engine 16: Slowloris Detector

 Gap closed: ids_detector.py had no engine that inspects
 HTTP request *content* for Slowloris signatures. The
 existing firewall_dpi.py detects Slowloris via connection
 *duration* (TCP open >30s to port 80), which is a lagging
 indicator — the connection must already be old before it
 fires. This engine fires earlier, on the structural
 property of the attack: headers arriving but the request
 never being terminated.

 Detection method (from the Indusface article §"How to Detect"):
   "Connection tracking — connections open >N seconds without
    completing requests."
   "Monitor server logs for open connections without completed
    requests" → translated here to packet-level inspection of
    HTTP payload content.

 Two alert conditions:
   HIGH — ≥ HALF_OPEN_PER_IP concurrent half-open HTTP
           connections from a single source IP
           (article: "numerous incomplete connections from
            various IP addresses")
   MED  — any single connection has been half-open for more
           than STALE_CONNECTION_SEC seconds
           (article: "connection tracking … without completing
            requests")

 Integration into ids_detector.py (two lines):
 ──────────────────────────────────────────────
   # At the top, with the other engine imports:
   import ids_engine_slowloris as _e16
   _e16.register(alert)

   # In packet_handler(), alongside the other process_* calls:
   _e16.process_packet(pkt)

   # Optional: add the maintenance tick to the sniff callback
   # or let _e16's background thread handle it automatically
   # (it starts on register()).
 ──────────────────────────────────────────────
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


# ── Tunable thresholds ─────────────────────────────────────────
MONITORED_PORT       = 80       # HTTP port to watch
HALF_OPEN_PER_IP     = 10       # concurrent half-open connections → HIGH alert
STALE_CONNECTION_SEC = 30       # single conn half-open longer than this → MED
PRUNE_INTERVAL_SEC   = 15       # background maintenance frequency
ALERT_COOLDOWN_SEC   = 60       # minimum seconds between repeated alerts per IP


# ══════════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════════

class _ConnState:
    """Tracks a single TCP connection's Slowloris state."""
    __slots__ = ("first_seen", "last_header_ts", "headers_seen",
                 "terminated", "alerted_stale")

    def __init__(self, ts: float):
        self.first_seen    = ts
        self.last_header_ts = ts
        self.headers_seen  = 0    # count of X-a: keep-alive lines received
        self.terminated    = False
        self.alerted_stale = False


# key: (src_ip, sport, dst_ip, dport)
_connections: dict[tuple, _ConnState] = {}
_lock = threading.Lock()

# Per-source alert cooldowns
_last_high_alert: dict[str, float] = defaultdict(float)
_last_med_alert:  dict[str, float] = defaultdict(float)

_alert_fn: Callable | None = None


# ══════════════════════════════════════════════════════════════
#  PACKET PROCESSING
# ══════════════════════════════════════════════════════════════

def process_packet(pkt) -> None:
    """
    Call this from ids_detector.py's packet_handler() for every
    captured packet.
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
        if flags & 0x01 or flags & 0x04:          # FIN or RST
            conn = _connections.pop(key, None)
            if conn:
                conn.terminated = True
            return

        # ── Data packet: inspect HTTP payload ──────────────────
        if key not in _connections:
            return
        conn = _connections[key]

        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)

            # A Slowloris keep-alive drip looks like:
            #   b"X-a: 1234\r\n"
            # It is a valid HTTP header line — the attack's trick is
            # that \r\n\r\n (the request terminator) is NEVER sent.
            if b"\r\n\r\n" in payload:
                # This is a completed HTTP request — not Slowloris.
                conn.terminated = True
                _connections.pop(key, None)
                return

            # Header data without terminator = keep-alive drip
            if b"\r\n" in payload or b"X-a:" in payload:
                conn.headers_seen   += 1
                conn.last_header_ts  = now

        # ── Per-IP concurrent half-open count check (HIGH) ────
        _check_concurrent(src_ip, now)


def _check_concurrent(src_ip: str, now: float) -> None:
    """
    Count concurrent half-open connections from this source.
    Must be called while _lock is held.
    """
    half_open = sum(
        1
        for (sip, _, _, _), conn in _connections.items()
        if sip == src_ip
        and not conn.terminated
        and conn.headers_seen > 0          # at least one header drip seen
    )

    if half_open >= HALF_OPEN_PER_IP:
        last = _last_high_alert[src_ip]
        if now - last >= ALERT_COOLDOWN_SEC:
            _last_high_alert[src_ip] = now
            _fire_alert(
                "HIGH",
                f"SLOWLORIS DETECTED (concurrent half-open): {src_ip}\n"
                f"  {half_open} simultaneous HTTP connections to :{MONITORED_PORT}\n"
                f"  that have received header drips but never sent \\r\\n\\r\\n.\n"
                f"  Threshold: >={HALF_OPEN_PER_IP} concurrent half-open connections.\n"
                f"  Apache's thread pool is being exhausted — each open\n"
                f"  connection blocks one worker thread indefinitely.\n"
                f"  MITRE: T1499.002 (Service Exhaustion Flood — HTTP)",
            )


def _check_stale(now: float) -> None:
    """
    Called periodically by the background thread.
    Fires MED alerts for connections that have been half-open too long.
    Prunes terminated and timed-out entries.
    """
    stale_threshold = now - STALE_CONNECTION_SEC
    to_delete: list[tuple] = []

    with _lock:
        for key, conn in list(_connections.items()):
            if conn.terminated:
                to_delete.append(key)
                continue

            if conn.headers_seen == 0:
                # No header drips yet — might be a legitimate slow client,
                # or a connection mid-handshake. Give it STALE_CONNECTION_SEC.
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
                        f"  without sending HTTP request terminator (\\r\\n\\r\\n).\n"
                        f"  Threshold: >{STALE_CONNECTION_SEC}s.\n"
                        f"  Keep-alive drips seen: {conn.headers_seen}\n"
                        f"  Half-open connections mimic slow-but-legitimate\n"
                        f"  clients, making them hard to distinguish by\n"
                        f"  volume-based engines (Engines 1 and 11) alone.\n"
                        f"  MITRE: T1499.002 (Service Exhaustion Flood — HTTP)",
                    )

            # Prune very old connections that were never terminated cleanly
            # (e.g. the TCP FIN was not captured on this interface)
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
            _check_stale(time.time())
        except Exception as exc:
            print(f"[E16-Slowloris] maintenance error: {exc}")


# ══════════════════════════════════════════════════════════════
#  INTEGRATION ENTRY POINT
# ══════════════════════════════════════════════════════════════

def register(alert_callback: Callable) -> None:
    """
    Call once at ids_detector.py startup to wire the engine in.

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
        f"[IDS]   Half-open concurrent alert: >={HALF_OPEN_PER_IP} connections\n"
        f"[IDS]   Stale connection alert:     >{STALE_CONNECTION_SEC}s without terminator\n"
        f"[IDS]   Complements firewall_dpi.py (duration-based) with "
        f"payload-content-based detection."
    )


def _fire_alert(severity: str, msg: str) -> None:
    """Thread-safe alert dispatch to ids_detector.py's alert() function."""
    if _alert_fn is not None:
        try:
            _alert_fn("Slowloris/E16", severity, msg)
        except Exception:
            pass
    else:
        # Fallback if used standalone
        print(f"\n[E16-ALERT/{severity}] {msg}\n")


# ══════════════════════════════════════════════════════════════
#  STATUS / DIAGNOSTICS
# ══════════════════════════════════════════════════════════════

def get_status() -> dict:
    """Return current engine state — useful for test assertions."""
    with _lock:
        tracked = len(_connections)
        half_open = sum(
            1 for c in _connections.values()
            if not c.terminated and c.headers_seen > 0
        )
        per_ip: dict[str, int] = defaultdict(int)
        for (sip, _, _, _), c in _connections.items():
            if not c.terminated and c.headers_seen > 0:
                per_ip[sip] += 1

    return {
        "engine":         "E16/Slowloris",
        "tracked_conns":  tracked,
        "half_open":      half_open,
        "per_ip":         dict(per_ip),
        "threshold_high": HALF_OPEN_PER_IP,
        "threshold_stale_sec": STALE_CONNECTION_SEC,
    }


# ══════════════════════════════════════════════════════════════
#  STANDALONE DEMO
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("ids_engine_slowloris.py — Engine 16")
    print("Integration instructions:")
    print()
    print("  # In ids_detector.py, with the other engine imports:")
    print("  import ids_engine_slowloris as _e16")
    print()
    print("  # After the alert() function is defined:")
    print("  _e16.register(alert)")
    print()
    print("  # In packet_handler(), alongside the other process_* calls:")
    print("  _e16.process_packet(pkt)")
    print()
    print(f"Thresholds:")
    print(f"  HIGH alert: >={HALF_OPEN_PER_IP} concurrent half-open HTTP "
          f"connections from one IP")
    print(f"  MED  alert: any connection half-open >{STALE_CONNECTION_SEC}s "
          f"without \\r\\n\\r\\n")
    print(f"  Cooldown:   {ALERT_COOLDOWN_SEC}s between repeated alerts per IP")
    print()
    print("This engine complements firewall_dpi.py's duration-based check with")
    print("earlier payload-content detection — it fires as soon as the concurrent")
    print("threshold is reached, not after waiting 30s for a connection to age out.")
