"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: RST Detector P2P Coordination Mesh
 Environment: ISOLATED VM LAB ONLY
====================================================

Implements the third proposed future feature from:
  "Traffic Anomaly Detection – TCP and DNS"
  Rishi Narang, Infosec Resources, June 2012

  Original quote:
    "P2P model to let the scripts interact with each other on
     different hosts and isolate the malicious IP address as a
     network of analysis. This will make the anomaly detection
     a holistic approach."

What this does:
  Each host running rst_detector.py can now also run an
  RSTMeshNode that broadcasts scanner-IP alerts to peers and
  receives alerts from them.  When a quorum of peers agree
  that an IP is malicious, the local DHCP isolator fires
  automatically — no single host has to see the full scan
  flood on its own.

Architecture:
  - UDP multicast on 224.0.0.251:7779 (mDNS subnet, always
    reachable on an isolated /24 without a router).
  - Each node sends a SCANNER_ALERT message when rst_detector
    exceeds its RST/SYN threshold.
  - Each node counts alerts per scanner IP.  When QUORUM
    peers (default 2) agree, a CONSENSUS_ISOLATE is emitted
    and the optional DHCP isolator fires.
  - Message format: compact JSON, max 512 bytes.
  - Authentication: HMAC-SHA256 with a shared lab key to
    prevent injected alerts from the attacker VM.
  - All state is in-memory; no external dependencies beyond
    the Python standard library.

Wire protocol (UDP datagrams):
  {
    "v":  1,                        # protocol version
    "t":  "SCANNER_ALERT"           # message type (see MSG_* consts)
          | "CONSENSUS_ISOLATE"
          | "PEER_HELLO"
          | "PEER_BYE"
          | "STATUS_REQUEST"
          | "STATUS_REPLY",
    "ip": "192.168.100.11",         # scanner IP being reported
    "src_host": "192.168.100.20",   # reporting node
    "confidence": 0.9,              # 0.0–1.0 (RST count / threshold)
    "ts": 1714000000.0,             # Unix timestamp
    "hmac": "aabbcc..."             # HMAC-SHA256 hex (over all other fields)
  }

Integration with rst_detector.py:
  from rst_p2p_mesh import RSTMeshNode

  mesh = RSTMeshNode(local_ip="192.168.100.20")
  mesh.start()

  # Pass mesh.on_local_detection as the alert_cb to RSTCounter/SYNCounter:
  rst_counter = RSTCounter(alert_cb=mesh.on_local_detection)

  # Or call directly when a scanner is confirmed:
  mesh.report_scanner("192.168.100.11", confidence=0.95)

  # On shutdown:
  mesh.stop()

Standalone demo (two terminals):
  Terminal 1 (victim VM):  sudo python3 rst_p2p_mesh.py --host 192.168.100.20
  Terminal 2 (bot VM):     sudo python3 rst_p2p_mesh.py --host 192.168.100.11 --inject 192.168.100.50
====================================================
"""

import hashlib
import hmac
import json
import logging
import os
import socket
import struct
import sys
import threading
import time
import argparse
from collections import defaultdict
from datetime import datetime
from typing import Optional, Callable

# ── Constants ──────────────────────────────────────────────────
MESH_MULTICAST_GROUP = "224.0.0.251"   # mDNS group, no router needed
MESH_PORT            = 7779
MESH_TTL             = 1               # link-local only
MESH_SHARED_KEY      = b"AUA_RST_MESH_2026"   # HMAC key — change per deployment
PROTOCOL_VERSION     = 1
MAX_DATAGRAM         = 512             # bytes

# Message types
MSG_SCANNER_ALERT    = "SCANNER_ALERT"
MSG_CONSENSUS        = "CONSENSUS_ISOLATE"
MSG_HELLO            = "PEER_HELLO"
MSG_BYE              = "PEER_BYE"
MSG_STATUS_REQ       = "STATUS_REQUEST"
MSG_STATUS_REPLY     = "STATUS_REPLY"

# Detection consensus
DEFAULT_QUORUM       = 2    # peers that must agree before consensus_isolate fires
SCANNER_EXPIRY_SEC   = 120  # forget scanner votes older than this
MAX_PEERS            = 32

LOG_PATH             = "/tmp/rst_mesh.log"

logger = logging.getLogger("rst_p2p_mesh")
logging.basicConfig(
    level=logging.INFO,
    format="[RST-MESH] %(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_PATH),
    ],
)


# ══════════════════════════════════════════════════════════════
#  MESSAGE HELPERS
# ══════════════════════════════════════════════════════════════

def _hmac_sign(payload: dict, key: bytes = MESH_SHARED_KEY) -> str:
    """Sign a dict (excluding 'hmac' key) with HMAC-SHA256."""
    canonical = json.dumps(
        {k: v for k, v in sorted(payload.items()) if k != "hmac"},
        separators=(",", ":"),
    )
    return hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()


def _hmac_verify(payload: dict, key: bytes = MESH_SHARED_KEY) -> bool:
    expected = _hmac_sign(payload, key)
    received = payload.get("hmac", "")
    return hmac.compare_digest(expected, received)


def _build_msg(msg_type: str, src_host: str,
               scanner_ip: str = "",
               confidence: float = 1.0,
               extra: dict = None) -> bytes:
    payload = {
        "v":          PROTOCOL_VERSION,
        "t":          msg_type,
        "ip":         scanner_ip,
        "src_host":   src_host,
        "confidence": round(confidence, 3),
        "ts":         round(time.time(), 3),
    }
    if extra:
        payload.update(extra)
    payload["hmac"] = _hmac_sign(payload)
    raw = json.dumps(payload, separators=(",", ":")).encode()
    if len(raw) > MAX_DATAGRAM:
        raise ValueError(f"Message too large: {len(raw)} > {MAX_DATAGRAM} bytes")
    return raw


def _parse_msg(data: bytes) -> Optional[dict]:
    try:
        payload = json.loads(data.decode())
        if payload.get("v") != PROTOCOL_VERSION:
            return None
        if not _hmac_verify(payload):
            logger.warning("HMAC verification failed — possible injected message")
            return None
        return payload
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════
#  PEER REGISTRY
# ══════════════════════════════════════════════════════════════

class PeerRegistry:
    """
    Tracks live mesh peers.
    A peer is considered dead if no HELLO has been received within
    PEER_EXPIRY_SEC seconds.
    """
    PEER_EXPIRY_SEC = 90

    def __init__(self):
        self._lock  = threading.Lock()
        self._peers: dict = {}   # host_ip → last_seen_ts

    def hello(self, host: str):
        with self._lock:
            self._peers[host] = time.time()

    def bye(self, host: str):
        with self._lock:
            self._peers.pop(host, None)

    def live_peers(self) -> list:
        cutoff = time.time() - self.PEER_EXPIRY_SEC
        with self._lock:
            return [h for h, ts in self._peers.items() if ts > cutoff]

    def count(self) -> int:
        return len(self.live_peers())


# ══════════════════════════════════════════════════════════════
#  VOTE TRACKER
# ══════════════════════════════════════════════════════════════

class VoteTracker:
    """
    Tracks per-scanner-IP votes from peers.

    Votes expire after SCANNER_EXPIRY_SEC.
    When the number of distinct-peer votes (not counting self)
    reaches quorum, consensus_reached() returns True once.
    """

    def __init__(self, quorum: int = DEFAULT_QUORUM):
        self.quorum  = quorum
        self._lock   = threading.Lock()
        # scanner_ip → {peer_host: (timestamp, confidence)}
        self._votes: dict = defaultdict(dict)
        # scanner_ip → True if consensus already fired
        self._fired: set  = set()

    def add_vote(self, scanner_ip: str, peer_host: str,
                 confidence: float, ts: float) -> bool:
        """
        Record a vote.  Returns True the FIRST time quorum is reached
        for this scanner_ip (to fire exactly one CONSENSUS_ISOLATE).
        """
        now    = time.time()
        cutoff = now - SCANNER_EXPIRY_SEC

        with self._lock:
            self._votes[scanner_ip][peer_host] = (ts, confidence)
            # Prune stale votes
            self._votes[scanner_ip] = {
                p: (t, c) for p, (t, c)
                in self._votes[scanner_ip].items()
                if t > cutoff
            }

            n_peers = len(self._votes[scanner_ip])
            if n_peers >= self.quorum and scanner_ip not in self._fired:
                self._fired.add(scanner_ip)
                return True
        return False

    def vote_summary(self, scanner_ip: str) -> dict:
        with self._lock:
            votes = dict(self._votes.get(scanner_ip, {}))
        return {
            "scanner":    scanner_ip,
            "n_votes":    len(votes),
            "peers":      list(votes.keys()),
            "avg_conf":   round(sum(c for _, c in votes.values()) / max(1, len(votes)), 3),
            "consensus":  scanner_ip in self._fired,
        }

    def all_scanners(self) -> list:
        now    = time.time()
        cutoff = now - SCANNER_EXPIRY_SEC
        with self._lock:
            result = []
            for ip, votes in self._votes.items():
                recent = {p: (t, c) for p, (t, c) in votes.items() if t > cutoff}
                if recent:
                    result.append({
                        "scanner_ip": ip,
                        "n_peers":    len(recent),
                        "peers":      list(recent.keys()),
                        "fired":      ip in self._fired,
                    })
        return result


# ══════════════════════════════════════════════════════════════
#  MESH NODE
# ══════════════════════════════════════════════════════════════

class RSTMeshNode:
    """
    A single node in the RST-detector P2P coordination mesh.

    Usage:
        mesh = RSTMeshNode(local_ip="192.168.100.20")
        mesh.start()

        # When rst_detector fires a local alert:
        mesh.report_scanner("192.168.100.11", confidence=0.95)

        # Shutdown cleanly:
        mesh.stop()

    The isolate_cb callable is called with (scanner_ip, summary_dict)
    when consensus is reached.  Use it to trigger DHCPIsolator.release().
    """

    def __init__(self,
                 local_ip: str,
                 quorum: int = DEFAULT_QUORUM,
                 isolate_cb: Callable = None):
        self.local_ip   = local_ip
        self._quorum    = quorum
        self._isolate_cb = isolate_cb or self._default_isolate_cb

        self._peers     = PeerRegistry()
        self._votes     = VoteTracker(quorum=quorum)
        self._stop      = threading.Event()

        # UDP multicast socket (send + receive)
        self._sock      = self._create_socket()
        self._send_lock = threading.Lock()

        self._recv_thread  = threading.Thread(
            target=self._recv_loop, daemon=True, name="mesh-recv"
        )
        self._hello_thread = threading.Thread(
            target=self._hello_loop, daemon=True, name="mesh-hello"
        )

    # ── Lifecycle ──────────────────────────────────────────────

    def start(self):
        """Start the mesh node (non-blocking)."""
        self._recv_thread.start()
        self._hello_thread.start()
        self._broadcast(MSG_HELLO)
        logger.info(f"Mesh node started on {self.local_ip}:{MESH_PORT}  "
                    f"quorum={self._quorum}")

    def stop(self):
        """Gracefully shut down the mesh node."""
        self._broadcast(MSG_BYE)
        self._stop.set()
        try:
            self._sock.close()
        except Exception:
            pass
        logger.info("Mesh node stopped.")

    # ── Public API ─────────────────────────────────────────────

    def report_scanner(self, scanner_ip: str, confidence: float = 1.0):
        """
        Called by the local rst_detector when a scanner is confirmed.
        Broadcasts a SCANNER_ALERT to all mesh peers.
        Also counts as a self-vote for consensus tracking.
        """
        logger.info(f"LOCAL DETECTION: scanner={scanner_ip}  "
                    f"confidence={confidence:.2f}  broadcasting to peers")
        self._broadcast(MSG_SCANNER_ALERT,
                        scanner_ip=scanner_ip,
                        confidence=confidence)
        # Count own detection as a vote
        self._tally_vote(scanner_ip, self.local_ip, confidence, time.time())

    def on_local_detection(self, engine: str, severity: str, msg: str):
        """
        Drop-in alert_cb for RSTCounter / SYNCounter.
        Parses the scanner IP from the alert message and calls report_scanner().
        """
        # Extract IP from known alert message format
        ip = self._extract_ip_from_alert(msg)
        if ip:
            confidence = 1.0 if severity == "HIGH" else 0.6
            self.report_scanner(ip, confidence=confidence)

    def status(self) -> dict:
        return {
            "local_ip":    self.local_ip,
            "quorum":      self._quorum,
            "live_peers":  self._peers.live_peers(),
            "scanners":    self._votes.all_scanners(),
        }

    # ── Network I/O ────────────────────────────────────────────

    def _create_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        sock.bind(("", MESH_PORT))
        # Join multicast group
        mreq = struct.pack("4sL",
                           socket.inet_aton(MESH_MULTICAST_GROUP),
                           socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MESH_TTL)
        sock.settimeout(2.0)
        return sock

    def _broadcast(self, msg_type: str, scanner_ip: str = "",
                   confidence: float = 1.0, extra: dict = None):
        try:
            data = _build_msg(msg_type, self.local_ip,
                              scanner_ip=scanner_ip,
                              confidence=confidence,
                              extra=extra)
            with self._send_lock:
                self._sock.sendto(data, (MESH_MULTICAST_GROUP, MESH_PORT))
        except Exception as e:
            logger.debug(f"_broadcast error: {e}")

    def _recv_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(MAX_DATAGRAM * 2)
                sender_ip  = addr[0]
                if sender_ip == self.local_ip:
                    continue   # ignore own messages
                self._handle(data, sender_ip)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                logger.debug(f"_recv_loop error: {e}")

    def _hello_loop(self):
        """Broadcast HELLO every 30s so peers know we're alive."""
        while not self._stop.is_set():
            for _ in range(30):
                if self._stop.is_set():
                    return
                time.sleep(1)
            self._broadcast(MSG_HELLO)

    def _handle(self, data: bytes, sender_ip: str):
        msg = _parse_msg(data)
        if not msg:
            return

        t = msg.get("t")

        if t == MSG_HELLO:
            self._peers.hello(msg["src_host"])
            logger.debug(f"HELLO from {msg['src_host']}  "
                         f"(live peers: {self._peers.count()})")

        elif t == MSG_BYE:
            self._peers.bye(msg["src_host"])
            logger.info(f"BYE from {msg['src_host']}  "
                        f"(live peers: {self._peers.count()})")

        elif t == MSG_SCANNER_ALERT:
            scanner_ip = msg.get("ip", "")
            confidence = float(msg.get("confidence", 1.0))
            ts         = float(msg.get("ts", time.time()))
            peer       = msg.get("src_host", sender_ip)
            self._peers.hello(peer)
            logger.warning(f"PEER ALERT from {peer}: scanner={scanner_ip}  "
                           f"confidence={confidence:.2f}")
            self._tally_vote(scanner_ip, peer, confidence, ts)

        elif t == MSG_STATUS_REQ:
            self._broadcast(MSG_STATUS_REPLY,
                            extra={"status": self.status()})

        elif t == MSG_STATUS_REPLY:
            remote_status = msg.get("status", {})
            logger.info(f"STATUS from {msg.get('src_host')}: "
                        f"{len(remote_status.get('scanners', []))} scanners tracked")

    def _tally_vote(self, scanner_ip: str, peer: str,
                    confidence: float, ts: float):
        consensus_reached = self._votes.add_vote(
            scanner_ip, peer, confidence, ts
        )
        if consensus_reached:
            summary = self._votes.vote_summary(scanner_ip)
            logger.warning(
                f"CONSENSUS: {scanner_ip} confirmed as scanner by "
                f"{summary['n_votes']} peers "
                f"(quorum={self._quorum})  avg_conf={summary['avg_conf']:.2f}"
            )
            self._broadcast(MSG_CONSENSUS, scanner_ip=scanner_ip,
                            confidence=summary["avg_conf"])
            self._isolate_cb(scanner_ip, summary)

    # ── Helpers ────────────────────────────────────────────────

    @staticmethod
    def _extract_ip_from_alert(msg: str) -> Optional[str]:
        """
        Pull the first IPv4 address from an rst_detector alert string.
        """
        import re
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", msg)
        return m.group(1) if m else None

    @staticmethod
    def _default_isolate_cb(scanner_ip: str, summary: dict):
        print(f"\n[MESH-CONSENSUS] ⚠  ISOLATE {scanner_ip}")
        print(f"  Agreed by {summary['n_peers']} peers: {summary['peers']}")
        print(f"  Average confidence: {summary['avg_conf']:.0%}")
        print(f"  Action: trigger DHCPIsolator.release('{scanner_ip}')")
        print(f"  (Pass isolate_cb=dhcp_isolator.release to RSTMeshNode)")

    # ── Context manager support ───────────────────────────────

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()


# ══════════════════════════════════════════════════════════════
#  CLI / DEMO
# ══════════════════════════════════════════════════════════════

def _run_demo(local_ip: str, inject_ip: str = None):
    """
    Demo: start a mesh node, optionally inject a scanner alert.
    Run on two VMs simultaneously to see peer coordination.
    """
    print("=" * 60)
    print(" RST Detector P2P Mesh — AUA Botnet Research Lab")
    print(f" Local IP : {local_ip}")
    print(f" Multicast: {MESH_MULTICAST_GROUP}:{MESH_PORT}")
    print(f" Quorum   : {DEFAULT_QUORUM} peer agreements → isolate")
    print("=" * 60)

    def isolate(ip, summary):
        print(f"\n  *** MESH CONSENSUS — ISOLATING {ip} ***")
        print(f"  Peers in agreement: {summary['peers']}")

    with RSTMeshNode(local_ip=local_ip, isolate_cb=isolate) as mesh:
        time.sleep(2)  # let HELLO propagate

        if inject_ip:
            print(f"\n[DEMO] Injecting scanner alert for {inject_ip}...")
            mesh.report_scanner(inject_ip, confidence=0.95)

        print(f"\n[DEMO] Running.  Ctrl-C to stop.")
        print(f"[DEMO] Status: {json.dumps(mesh.status(), indent=2)}")

        try:
            while True:
                time.sleep(10)
                s = mesh.status()
                print(f"\r[MESH] peers={len(s['live_peers'])}  "
                      f"scanners_tracked={len(s['scanners'])}", end="", flush=True)
        except KeyboardInterrupt:
            print("\n[DEMO] Stopping.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "RST Detector P2P Mesh — distributed scanner consensus\n"
            "Implements the P2P future feature from Rishi Narang, Infosec 2012.\n"
            "AUA CS 232/337 — ISOLATED VM ONLY"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host",   required=True,
                        help="This node's IP address (e.g., 192.168.100.20)")
    parser.add_argument("--inject", metavar="SCANNER_IP",
                        help="Inject a scanner alert for this IP (demo mode)")
    parser.add_argument("--quorum", type=int, default=DEFAULT_QUORUM,
                        help=f"Peer agreement threshold (default: {DEFAULT_QUORUM})")
    args = parser.parse_args()

    _run_demo(local_ip=args.host, inject_ip=args.inject)
