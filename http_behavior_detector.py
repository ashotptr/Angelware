"""
====================================================
 Angelware — HTTP Behavior & Network Anomaly Detector
 Ported/adapted from: C2Detective (martinkubecka)
====================================================

Three missing detection capabilities combined:

1. Big HTTP Body Size  (C2Detective: detect_big_http_body_size)
   ─────────────────────────────────────────────────────────────
   Checks the Content-Length header of every captured HTTP session
   against a configurable threshold.  Large HTTP response bodies can
   indicate C2 payload delivery or data exfiltration.

   Angelware's DPI engine only detected Slowloris (connection duration).
   This adds Content-Length threshold checking.

2. C2 Beaconing Frequency  (C2Detective: detect_connections_with_excessive_frequency)
   ─────────────────────────────────────────────────────────────────────────────────
   Tracks the count of each unique (src_ip, src_port, dst_ip, dst_port)
   4-tuple across all packets.  A 4-tuple appearing in >MAX_FREQUENCY%
   of all packets flags C2 beaconing behaviour (rigid, high-frequency
   check-ins from a bot to a specific C2 IP:port).

   Angelware's Engine 1 counted volumetric SYN/UDP packets from one IP
   per second — designed to catch floods, not beaconing.

3. Long TCP Connection Duration  (C2Detective: detect_long_connection)
   ────────────────────────────────────────────────────────────────────
   Groups packets by TCP session, measures elapsed time between the
   first and last packet, and flags sessions exceeding MAX_DURATION.
   C2 frameworks maintain persistent long-lived sessions for command
   delivery; exfiltration tunnels also exhibit this behaviour.

   Angelware's DPI engine specifically targeted Slowloris (HTTP
   connections lasting >30s without completing the request).  This
   adds general TCP session duration tracking for ALL protocols.

All three detectors can work in:
  - Offline pcap mode  → feed pre-parsed data from pcap_ioc_extractor.py
  - Live IDS mode      → call per-packet hooks

CLI:
  python3 http_behavior_detector.py --pcap capture.pcap
  python3 http_behavior_detector.py --pcap capture.pcap \
          --max-http-size 50000 --max-frequency 10 --max-duration 14000
"""

import argparse
import logging
import os
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

_HERE = os.path.dirname(os.path.realpath(__file__))

# ── Defaults (mirror C2Detective config example) ────────────────────────────
DEFAULT_MAX_HTTP_SIZE  = 50_000    # bytes
DEFAULT_MAX_FREQUENCY  = 10        # percentage of total packets
DEFAULT_MAX_DURATION   = 14_000    # seconds (~3.9 hours)


def _ts() -> str:
    return time.strftime("%H:%M:%S")


# ═══════════════════════════════════════════════════════════════════════════════
#  1. BIG HTTP BODY SIZE DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class BigHTTPBodyDetector:
    """
    Detect HTTP sessions with unusually large Content-Length values.

    Offline usage:
        d = BigHTTPBodyDetector(max_size=50000)
        hits = d.scan(http_sessions_list)

    Live usage:
        d = BigHTTPBodyDetector()
        if d.check_session(session_dict):
            ...  # alert already printed
    """

    def __init__(self, max_size: int = DEFAULT_MAX_HTTP_SIZE):
        self.max_size = max_size

    # ------------------------------------------------------------------
    def scan(self, http_sessions: List[Dict]) -> List[Dict]:
        """
        http_sessions: list of dicts with keys:
          timestamp, src_ip, src_port, dst_ip, dst_port,
          method, url, path, http_headers (dict)

        Returns sessions where Content-Length > self.max_size.
        """
        print(f"[{_ts()}] [INFO] Checking {len(http_sessions)} HTTP sessions "
              f"for large body size (threshold: {self.max_size} bytes) …")

        hits = []
        for session in http_sessions:
            if self._exceeds_threshold(session):
                hits.append(session)

        if hits:
            print(f"[{_ts()}] [ALERT] {len(hits)} HTTP session(s) with "
                  f"unusual body size detected:")
            for s in hits:
                cl = s.get("http_headers", {}).get("Content_Length", "?")
                print(f"  {s.get('src_ip')}:{s.get('src_port')} → "
                      f"{s.get('dst_ip')}:{s.get('dst_port')}  "
                      f"Content-Length={cl}  url={s.get('url','')}")
        else:
            print(f"[{_ts()}] [INFO] No unusual HTTP body sizes detected")

        return hits

    # ------------------------------------------------------------------
    def check_session(self, session: Dict) -> bool:
        """Live mode: returns True and prints alert if session exceeds threshold."""
        if self._exceeds_threshold(session):
            cl = session.get("http_headers", {}).get("Content_Length", "?")
            print(f"[{_ts()}] [ALERT] Large HTTP body — "
                  f"{session.get('src_ip')}:{session.get('src_port')} → "
                  f"{session.get('dst_ip')}:{session.get('dst_port')}  "
                  f"Content-Length={cl} bytes  (threshold: {self.max_size})")
            return True
        return False

    # ------------------------------------------------------------------
    def _exceeds_threshold(self, session: Dict) -> bool:
        headers = session.get("http_headers") or {}
        cl = headers.get("Content_Length") or headers.get("content-length")
        if cl is None:
            return False
        try:
            return int(cl) > self.max_size
        except (ValueError, TypeError):
            return False


# ═══════════════════════════════════════════════════════════════════════════════
#  2. C2 BEACONING FREQUENCY DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class BeaconingFrequencyDetector:
    """
    Detect C2 beaconing by finding TCP connections with excessive frequency.

    A single (src_ip, src_port, dst_ip, dst_port) 4-tuple appearing in
    more than MAX_FREQUENCY % of all packets is flagged.

    Offline usage:
        d = BeaconingFrequencyDetector(max_frequency_pct=10)
        hits = d.scan(connection_frequency_dict, total_packet_count)

    Live usage — maintain your own counter dict and call scan() periodically.
    """

    def __init__(self, max_frequency_pct: float = DEFAULT_MAX_FREQUENCY):
        self.max_frequency_pct = max_frequency_pct

    # ------------------------------------------------------------------
    def scan(
        self,
        # {(src_ip, src_port, dst_ip, dst_port): count}
        connection_frequency: Dict[Tuple, int],
        total_packets: int,
        whitelisted_ips: Optional[Set[str]] = None,
    ) -> List[Dict]:
        """
        Returns list of dicts for connections exceeding the frequency threshold.
        """
        whitelisted_ips = whitelisted_ips or set()
        threshold = total_packets * (self.max_frequency_pct / 100)

        print(f"[{_ts()}] [INFO] Scanning {len(connection_frequency)} unique "
              f"4-tuple connections for beaconing "
              f"(threshold: >{self.max_frequency_pct}% of {total_packets} packets "
              f"= {threshold:.0f} packets) …")

        hits = []
        for (src_ip, src_port, dst_ip, dst_port), count in connection_frequency.items():
            if src_ip in whitelisted_ips or dst_ip in whitelisted_ips:
                continue
            if count > threshold:
                hits.append({
                    "src_ip":    src_ip,
                    "src_port":  src_port,
                    "dst_ip":    dst_ip,
                    "dst_port":  dst_port,
                    "frequency": count,
                    "pct_of_total": round(count / total_packets * 100, 2)
                    if total_packets else 0,
                })

        if hits:
            print(f"[{_ts()}] [ALERT] {len(hits)} connection(s) with excessive "
                  f"beaconing frequency detected:")
            for h in hits:
                print(f"  {h['src_ip']}:{h['src_port']} → "
                      f"{h['dst_ip']}:{h['dst_port']}  "
                      f"count={h['frequency']}  ({h['pct_of_total']}% of packets)")
        else:
            print(f"[{_ts()}] [INFO] No connections with excessive beaconing frequency")

        return hits


# ═══════════════════════════════════════════════════════════════════════════════
#  3. LONG TCP CONNECTION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class LongConnectionDetector:
    """
    Detect TCP sessions lasting longer than MAX_DURATION seconds.

    Tracks sessions involving at least one public IP address.
    Long-lived sessions may indicate persistent C2 channels, exfiltration
    tunnels, or covert channels masquerading as keep-alive connections.

    Offline usage:
        d = LongConnectionDetector(max_duration=14000)
        hits = d.scan(grouped_connections_dict)

    grouped_connections_dict schema (from Scapy packets.sessions()):
        {"TCP <src>:<port> > <dst>:<port>": [packet, packet, ...], ...}
    """

    def __init__(self, max_duration: int = DEFAULT_MAX_DURATION):
        self.max_duration = max_duration

    # ------------------------------------------------------------------
    def scan(
        self,
        connections: Dict,              # Scapy sessions() dict
        whitelisted_ips: Optional[Set[str]] = None,
    ) -> List[Dict]:
        """
        Iterates grouped TCP connections, measures first-to-last packet
        elapsed time, flags sessions exceeding self.max_duration.
        """
        from ipaddress import ip_address

        whitelisted_ips = whitelisted_ips or set()

        print(f"[{_ts()}] [INFO] Scanning {len(connections)} grouped connections "
              f"for long duration (threshold: >{self.max_duration}s) …")

        hits = []
        for session_key, packets in connections.items():
            if "TCP" not in session_key:
                continue

            parts = session_key.split()
            try:
                src_ip, src_port = parts[1].split(":")
                dst_ip, dst_port = parts[3].split(":")
            except (IndexError, ValueError):
                continue

            if src_ip in whitelisted_ips or dst_ip in whitelisted_ips:
                continue

            try:
                src_pub = not ip_address(src_ip).is_private
                dst_pub = not ip_address(dst_ip).is_private
            except ValueError:
                continue

            if not src_pub and not dst_pub:
                continue   # skip pure internal sessions

            if len(packets) < 2:
                continue

            duration = float(packets[-1].time) - float(packets[0].time)
            if duration > self.max_duration:
                hits.append({
                    "src_ip":   src_ip,
                    "src_port": src_port,
                    "dst_ip":   dst_ip,
                    "dst_port": dst_port,
                    "duration": int(duration),
                    "packets":  len(packets),
                })

        if hits:
            print(f"[{_ts()}] [ALERT] {len(hits)} long TCP connection(s) detected:")
            for h in hits:
                print(f"  {h['src_ip']}:{h['src_port']} → "
                      f"{h['dst_ip']}:{h['dst_port']}  "
                      f"duration={h['duration']}s  packets={h['packets']}")
        else:
            print(f"[{_ts()}] [INFO] No long TCP connections detected")

        return hits


# ═══════════════════════════════════════════════════════════════════════════════
#  COMBINED RUNNER (for pcap_ioc_extractor integration)
# ═══════════════════════════════════════════════════════════════════════════════

class HTTPBehaviorDetector:
    """Convenience wrapper that runs all three detectors and returns combined results."""

    def __init__(
        self,
        max_http_size:    int   = DEFAULT_MAX_HTTP_SIZE,
        max_frequency_pct: float = DEFAULT_MAX_FREQUENCY,
        max_duration:     int   = DEFAULT_MAX_DURATION,
    ):
        self.body_detector    = BigHTTPBodyDetector(max_http_size)
        self.beacon_detector  = BeaconingFrequencyDetector(max_frequency_pct)
        self.longconn_detector = LongConnectionDetector(max_duration)

    def run_all(
        self,
        http_sessions:        List[Dict],
        connection_frequency: Dict[Tuple, int],
        total_packets:        int,
        grouped_connections:  Dict,
        whitelisted_ips:      Optional[Set[str]] = None,
    ) -> Dict[str, List]:
        results = {}

        print(f"\n{'─'*60}")
        print(f"[{_ts()}] [INFO] Running HTTP Behavior Detector …")
        results["big_http_body"]        = self.body_detector.scan(http_sessions)
        results["excessive_beaconing"]  = self.beacon_detector.scan(
            connection_frequency, total_packets, whitelisted_ips)
        results["long_connections"]     = self.longconn_detector.scan(
            grouped_connections, whitelisted_ips)

        return results


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        prog="http_behavior_detector",
        description="HTTP body / beaconing / long-connection detector — Angelware add-on"
    )
    ap.add_argument("--pcap",           metavar="FILE",
                    help="Analyse a pcap file (requires pcap_ioc_extractor.py)")
    ap.add_argument("--max-http-size",  type=int, default=DEFAULT_MAX_HTTP_SIZE,
                    help=f"Max HTTP Content-Length (default: {DEFAULT_MAX_HTTP_SIZE})")
    ap.add_argument("--max-frequency",  type=float, default=DEFAULT_MAX_FREQUENCY,
                    help=f"Max beaconing %% of total packets (default: {DEFAULT_MAX_FREQUENCY})")
    ap.add_argument("--max-duration",   type=int, default=DEFAULT_MAX_DURATION,
                    help=f"Max TCP session duration in seconds (default: {DEFAULT_MAX_DURATION})")
    args = ap.parse_args()

    if not args.pcap:
        ap.print_help()
        return

    sys.path.insert(0, _HERE)
    try:
        from pcap_ioc_extractor import PcapIOCExtractor
    except ImportError:
        print("[ERROR] pcap_ioc_extractor.py not found in the same directory.")
        sys.exit(1)

    extractor = PcapIOCExtractor(args.pcap)
    detector  = HTTPBehaviorDetector(
        max_http_size=args.max_http_size,
        max_frequency_pct=args.max_frequency,
        max_duration=args.max_duration,
    )
    results = detector.run_all(
        http_sessions        = extractor.http_sessions,
        connection_frequency = extractor.connection_frequency,
        total_packets        = len(extractor.packets),
        grouped_connections  = extractor.connections,
    )
    print(f"\nSummary:")
    for k, v in results.items():
        print(f"  {k:<30} {len(v)} hit(s)")


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
