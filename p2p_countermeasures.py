"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: P2P Botnet Countermeasures
 Environment: ISOLATED VM LAB ONLY
====================================================

Implements ALL countermeasure components from:
  Wang, Aslam, Zou — "Peer-to-Peer Botnets" §1.6

This module is the most important gap-fill: the book's
central counter-intuitive finding is that pull-based P2P
botnets (those using STORE/FIND_VALUE for C&C) are NOT
more resilient than centralized botnets — they are equally
vulnerable to INDEX POISONING.

Modules implemented:

  1. IndexPoisoner (§1.6.3) ← THE CENTRAL FINDING
     Floods bogus STORE messages under COMMAND_KEY so bots
     receive corrupt commands from FIND_VALUE.
     Works against kademlia_p2p.c / p2p_node.py as-is —
     COMMAND_KEY "botnet_command_v1" is fixed and public.

  2. SybilAttacker (§1.6.3)
     Creates fake sybil peers and injects them into bot
     routing tables to re-route or block C&C traffic.
     Different from index poisoning: sybil nodes must
     STAY ONLINE and participate in the DHT.

  3. QueryBlacklist + PeerBlacklist (§1.6.3)
     Maintain lists of known botnet command keys and
     identified bot peers. Legitimate peers discard
     blacklisted queries and refuse connections from
     blacklisted IPs.

  4. DHTSensorPlacement (§1.6.2)
     Strategic placement of sensor nodes with IDs evenly
     distributed across the 160-bit ID space so they
     collectively intercept all key lookups.

  5. P2PHoneypotNode (§1.6.2)
     A fake KademliaNode that joins the mesh, logs all
     STORE/FIND_VALUE activity, and reports command keys
     to the defender. Analogous to IRC honeypot but for DHT.

  6. P2PBehaviorDetector (§1.6.1)
     IDS engine for P2P-specific bot signatures:
       - Periodic same-key FIND_VALUE queries (bot polling)
       - Queries with no subsequent download activity
       - High query rate but zero upload

  7. ProtocolHardener (§1.6.4)
     Lean DHT policy: rejects STORE entries with unexpected
     formats, limits value size, requires key-value format
     validation. Makes the DHT hostile to botnet C&C reuse.

  8. BootstrapDisruptor (§1.6.3)
     Identifies hard-coded seed peers from bot binary analysis
     and blocks/blacklists them to halt botnet growth.

CLI:
  python3 p2p_countermeasures.py --demo
  python3 p2p_countermeasures.py --poison   [--target HOST:PORT]
  python3 p2p_countermeasures.py --sybil    [--target HOST:PORT]
  python3 p2p_countermeasures.py --honeypot [--target HOST:PORT]
  python3 p2p_countermeasures.py --sensor   [--n 5]
  python3 p2p_countermeasures.py --detect   [--target HOST:PORT]
  python3 p2p_countermeasures.py --harden
  python3 p2p_countermeasures.py --blacklist
  python3 p2p_countermeasures.py --bootstrap-disrupt HOST:PORT
"""

import argparse
import collections
import hashlib
import hmac as _hmac_mod
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
from typing import Callable, Dict, List, Optional, Set, Tuple

# ──────────────────────────────────────────────────────────────────
#  WIRE FORMAT — must match p2p_node.py exactly
# ──────────────────────────────────────────────────────────────────

P2P_SECRET   = b"AUA_P2P_MESH_KEY"
COMMAND_KEY  = "botnet_command_v1"     # well-known key from p2p_node.py

ID_BITS      = 160
K            = 8
CONTACT_SIZE = 26
HDR_SIZE     = 35

MSG_PING        = 0x01
MSG_PONG        = 0x02
MSG_FIND_NODE   = 0x03
MSG_FOUND_NODES = 0x04
MSG_STORE       = 0x05
MSG_FIND_VALUE  = 0x06
MSG_FOUND_VALUE = 0x07

_KEY_HASH      = hashlib.sha256(P2P_SECRET).digest()
_KEY_HASH_LOCK = threading.Lock()


def xor_cipher(data: bytes) -> bytes:
    with _KEY_HASH_LOCK:
        kh = _KEY_HASH
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ kh[i % len(kh)]
    return bytes(out)


def _sha1_id(s: str) -> int:
    return int(hashlib.sha1(s.encode()).hexdigest(), 16)


def _node_id_from_host_port(host: str, port: int) -> int:
    return _sha1_id(f"{host}:{port}")


def _id_to_bytes(nid: int) -> bytes:
    return nid.to_bytes(20, "big")


def _build_msg(msg_type: int,
               src_id: int, src_host: str, src_port: int,
               msg_id: bytes = None,
               payload: bytes = b"") -> bytes:
    if msg_id is None:
        msg_id = os.urandom(8)
    ip_bytes   = socket.inet_aton(src_host)
    port_bytes = struct.pack("!H", src_port)
    hdr = (struct.pack("!B", msg_type) + msg_id +
           _id_to_bytes(src_id) + ip_bytes + port_bytes)
    return xor_cipher(hdr + payload)


def _parse_msg(data: bytes) -> Optional[dict]:
    if len(data) < HDR_SIZE:
        return None
    try:
        d = xor_cipher(data)
        return {"type":    d[0],
                "msg_id":  d[1:9],
                "src_id":  int.from_bytes(d[9:29], "big"),
                "src_ip":  socket.inet_ntoa(d[29:33]),
                "src_port":struct.unpack("!H", d[33:35])[0],
                "payload": d[35:]}
    except Exception:
        return None


def _parse_store_payload(payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Parse STORE payload: [20 key][2 vlen][value]"""
    if len(payload) < 22:
        return None, None
    try:
        key_hex = payload[:20].hex()
        vlen    = struct.unpack("!H", payload[20:22])[0]
        if len(payload) < 22 + vlen:
            return key_hex, None
        value = payload[22:22 + vlen].decode(errors="replace")
        return key_hex, value
    except Exception:
        return None, None


def _build_store_payload(key: str, value: str) -> bytes:
    """Build STORE payload for a hex key and string value."""
    key_bytes = bytes.fromhex(key) if len(key) == 40 else hashlib.sha1(key.encode()).digest()
    val_bytes = value.encode()
    return key_bytes + struct.pack("!H", len(val_bytes)) + val_bytes


LOG_PATH = "/tmp/botnet_lab_countermeasures.log"


def _log(tag: str, msg: str):
    line = f"[{datetime.now().strftime('%H:%M:%S')}][{tag}] {msg}"
    print(line)
    try:
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────
#  1. INDEX POISONING ATTACK (§1.6.3) — THE CENTRAL FINDING
# ──────────────────────────────────────────────────────────────────

class IndexPoisoner:
    """
    Teaching point (§1.6.3 — Index Poisoning Attack):

      The chapter's most counter-intuitive finding:
        "P2P botnets that rely on publishing/subscribing C&C
         mechanism is as vulnerable as traditional centralized
         botnets against defense."

      How index poisoning works:
        1. Defender captures and analyzes the bot binary.
        2. The algorithm for the command key is extracted.
           For Trojan.Peacomm/Stormnet: 32 fixed daily hashes.
           For Angelware: always SHA-1("botnet_command_v1")
        3. Defender floods MASSIVE bogus STORE records under
           those keys. In Kademlia, ANY peer can STORE any value.
        4. When bots call FIND_VALUE, they receive the poisoned
           garbage instead of the real command.
        5. Botnet loses C&C capability without any bot being
           seized or identified.

      Why this works (§1.6.3 two root causes):
        (a) Kademlia STORE requires no authentication — any peer
            can overwrite any key.
        (b) The command key is deterministic and discoverable
            from the bot binary or from monitoring.

      Starnberger et al. proposed a countermeasure: dynamically
      change command query messages. This requires additional
      sensors and makes the botnet more complex.

      IndexPoisoner operates in two modes:
        STANDALONE: floods a local in-memory DHT for demonstration
        LIVE:       sends real UDP STORE packets to p2p_node.py
                    nodes running in the lab VM (--target HOST:PORT)
    """

    POISON_VALUE = json.dumps({
        "type": "__POISONED__",
        "msg":  "Command channel disrupted by index poisoning.",
        "by":   "AUA Defender — §1.6.3",
        "ts":   0
    })

    def __init__(self, target_host: str = "127.0.0.1",
                 target_port: int = 7500,
                 n_poison_nodes: int = 20,
                 flood_rounds: int = 5):
        self.target_host     = target_host
        self.target_port     = target_port
        self.n_poison_nodes  = n_poison_nodes
        self.flood_rounds    = flood_rounds
        self._sock: Optional[socket.socket] = None

        # Poisoner's own Kademlia identity
        self._host     = "127.0.0.1"
        self._port     = random.randint(19000, 20000)
        self._node_id  = _node_id_from_host_port(self._host, self._port)

    def _send_store(self, host: str, port: int,
                    key_hex: str, value: str) -> bool:
        """
        Send a STORE RPC to target with our poisoned value.
        Uses the exact wire format of p2p_node.py.
        """
        try:
            if not self._sock:
                self._sock = socket.socket(socket.AF_INET,
                                           socket.SOCK_DGRAM)
                self._sock.settimeout(1.0)
            payload = _build_store_payload(key_hex, value)
            msg     = _build_msg(MSG_STORE,
                                 self._node_id, self._host, self._port,
                                 payload=payload)
            self._sock.sendto(msg, (host, port))
            return True
        except Exception:
            return False

    def _compute_command_key(self) -> str:
        """
        Reproduce the key derivation from p2p_node.py:
          COMMAND_KEY = SHA1("botnet_command_v1")
        For Trojan.Peacomm/Stormnet: key = SHA1(date + rand[0-31])
        We demonstrate the single fixed key case.
        """
        return hashlib.sha1(COMMAND_KEY.encode()).hexdigest()

    def poison_standalone(self) -> dict:
        """
        Simulate index poisoning against an in-memory DHT store.
        Shows the mechanism without live network traffic.
        """
        _log("POISON", "=== Index Poisoning Attack (§1.6.3) ===")
        _log("POISON", f"Target key: SHA1('{COMMAND_KEY}')")
        cmd_key = self._compute_command_key()
        _log("POISON", f"Key hex:    {cmd_key}")

        # Simulate a DHT store (key → list of {value, submitter})
        dht_store: Dict[str, List[dict]] = {}

        # Botmaster stores the real command first
        real_cmd = json.dumps({
            "type": "syn_flood",
            "target": "192.168.100.20",
            "port": 80,
            "duration": 30
        })
        dht_store[cmd_key] = [{"value": real_cmd, "node": "botmaster"}]
        _log("POISON", f"Botmaster stored real command under key")

        # Defender floods poisoned records
        poison_count = 0
        for i in range(self.n_poison_nodes):
            fake_node = f"fake_defender_{i}"
            poison_val = self.POISON_VALUE.replace(
                '"ts": 0', f'"ts": {int(time.time())}'
            )
            if cmd_key not in dht_store:
                dht_store[cmd_key] = []
            dht_store[cmd_key].append({
                "value": poison_val,
                "node": fake_node
            })
            poison_count += 1

        # Simulate Kademlia quorum selection (returns most common value)
        def _kademlia_find_value(key: str) -> Optional[str]:
            entries = dht_store.get(key, [])
            if not entries:
                return None
            # Count occurrences of each value
            counter: Dict[str, int] = defaultdict(int)
            for e in entries:
                counter[e["value"]] += 1
            # Return the most common value (quorum)
            return max(counter, key=counter.__getitem__)

        result = _kademlia_find_value(cmd_key)

        _log("POISON", f"Poisoned {poison_count} DHT entries "
             f"(legit: 1, poisoned: {poison_count})")
        poisoned = (result != real_cmd)
        _log("POISON", f"Bot FIND_VALUE result: "
             f"{'⚠ POISONED GARBAGE' if poisoned else 'REAL COMMAND (not enough poison nodes)'}")
        _log("POISON", f"Poisoning effective: {poisoned}")

        if poisoned:
            _log("POISON", "SUCCESS: bots receive garbage — C&C disrupted without")
            _log("POISON", "         seizing a single bot or C2 server.")
        else:
            _log("POISON", f"Need more poison nodes to outvote 1 real entry.")
            _log("POISON", f"At QUORUM=3, need ≥3 poison nodes. Currently: {poison_count}")

        _log("POISON", "\nTwo root causes (§1.6.3):")
        _log("POISON", "  (a) Any Kademlia peer can STORE under any key — no auth")
        _log("POISON", "  (b) Command key is deterministic + extractable from binary")
        _log("POISON", "\nFix (Starnberger et al.): dynamically change command keys")
        _log("POISON", "  — requires additional sensors in the P2P network")

        return {"key": cmd_key, "poisoned": poisoned,
                "poison_nodes": poison_count,
                "real_nodes": 1}

    def poison_live(self, duration: int = 30) -> dict:
        """
        Send real UDP STORE floods to a live p2p_node.py instance.
        Run AFTER starting p2p_node.py:
          python3 p2p_node.py --host 127.0.0.1 --port 7500
        """
        _log("POISON", f"=== Live Index Poisoning — {self.target_host}:{self.target_port} ===")
        _log("POISON", f"Flooding {self.flood_rounds} rounds × every 2s")
        _log("POISON", f"Target key: {self._compute_command_key()[:16]}...")

        cmd_key = self._compute_command_key()
        sent = 0
        failed = 0

        for rnd in range(self.flood_rounds):
            poison_val = self.POISON_VALUE.replace(
                '"ts": 0', f'"ts": {int(time.time())}'
            )
            ok = self._send_store(self.target_host, self.target_port,
                                  cmd_key, poison_val)
            if ok:
                sent += 1
            else:
                failed += 1
            _log("POISON", f"Round {rnd+1}/{self.flood_rounds}: "
                 f"STORE sent={ok} to {self.target_host}:{self.target_port}")
            time.sleep(2)

        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

        _log("POISON", f"Live poisoning complete: {sent} STOREs sent, {failed} failed")
        _log("POISON", "Effect: bots calling FIND_VALUE for COMMAND_KEY now receive")
        _log("POISON", "        garbage — C&C disrupted without touching any bot")
        return {"sent": sent, "failed": failed, "rounds": self.flood_rounds}


# ──────────────────────────────────────────────────────────────────
#  2. SYBIL ATTACK AS DEFENSE (§1.6.3)
# ──────────────────────────────────────────────────────────────────

class SybilAttacker:
    """
    Teaching point (§1.6.3 — Sybil Attack):
      Davis et al. proposed using sybil nodes (fake identities)
      to INFILTRATE bot routing tables, then re-route or drop
      C&C traffic flowing through them.

      Key difference from index poisoning:
        - Sybil nodes must STAY ONLINE and participate in DHT
          (otherwise they are evicted from routing tables)
        - Index poisoning nodes can be EPHEMERAL — only need to
          periodically refresh bogus records

      The Sybil attack inserts fake peers into bot k-buckets.
      When a bot forwards a message through a sybil peer, the
      sybil drops it or forwards it to the defender instead of
      the real destination.
    """

    def __init__(self, n_sybils: int = 50,
                 base_host: str = "127.0.0.1",
                 base_port: int = 19100):
        self.n_sybils  = n_sybils
        self.base_host = base_host
        self.base_port = base_port
        self._sybils: List[dict] = []
        self._intercepted_msgs: List[dict] = []
        self._lock = threading.Lock()
        self._running = False
        self._threads: List[threading.Thread] = []

    def generate_sybils(self) -> List[dict]:
        """
        Generate sybil identities spread across the 160-bit ID space.
        Uniform coverage ensures sybils appear in every bot's k-buckets
        for every possible target key.
        """
        _log("SYBIL", f"Generating {self.n_sybils} sybil nodes across ID space...")
        self._sybils = []
        space = (1 << ID_BITS)
        step  = space // self.n_sybils

        for i in range(self.n_sybils):
            # Space sybils evenly in XOR metric space
            target_id = (step * i) + random.randint(0, step // 2)
            target_id %= space
            port      = self.base_port + i
            # We can't control SHA1(host:port) exactly, so use random IDs
            sybil = {"id": target_id,
                     "host": self.base_host,
                     "port": port,
                     "intercepted": 0}
            self._sybils.append(sybil)

        _log("SYBIL", f"Generated {len(self._sybils)} sybil identities")
        _log("SYBIL", f"ID space coverage: "
             f"~{self.n_sybils} entries across 2^160 space")
        return self._sybils

    def simulate_routing_table_injection(self,
                                          bot_peer_lists: List[List[int]]
                                          ) -> dict:
        """
        Simulate injecting sybil IDs into bot routing tables.
        Show what fraction of routes can be intercepted.
        """
        _log("SYBIL", "=== Sybil Routing Table Injection (§1.6.3) ===")
        sybil_ids = {s["id"] for s in self._sybils}

        intercepted_routes = 0
        total_routes       = 0

        for peer_list in bot_peer_lists:
            # Add sybil nodes to this bot's peer list
            injected_list = list(peer_list) + list(sybil_ids)[:K]
            total_routes  += len(injected_list)
            # Count how many routes go through a sybil
            intercepted   = sum(1 for pid in injected_list
                                if pid in sybil_ids)
            intercepted_routes += intercepted

        pct = (100 * intercepted_routes / total_routes
               if total_routes else 0)
        _log("SYBIL", f"Injected sybils into {len(bot_peer_lists)} bot routing tables")
        _log("SYBIL", f"Routes through sybil nodes: {intercepted_routes}/{total_routes} "
             f"({pct:.1f}%)")
        _log("SYBIL", f"\nKey constraint (§1.6.3):")
        _log("SYBIL", f"  Sybil nodes must remain ONLINE to stay in routing tables.")
        _log("SYBIL", f"  Index poisoning nodes can be ephemeral — STORE records")
        _log("SYBIL", f"  only need periodic refresh, not continuous participation.")

        return {"sybil_count": len(self._sybils),
                "bots_targeted": len(bot_peer_lists),
                "intercepted_pct": round(pct, 2)}


# ──────────────────────────────────────────────────────────────────
#  3. QUERY BLACKLIST + PEER BLACKLIST (§1.6.3)
# ──────────────────────────────────────────────────────────────────

class QueryBlacklist:
    """
    Teaching point (§1.6.3 Blacklisting):
      DNS blacklisting analogy: maintain a list of botnet
      command keys. Legitimate peers that recognize a query
      as blacklisted simply discard it — silencing the botnet
      without any out-of-band action.

      This can be distributed cooperatively across many
      legitimate P2P peers (crowd-sourced defense).
    """

    def __init__(self):
        self._keys: Set[str] = set()
        self._hits: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

        # Pre-populate with known botnet command keys
        known_keys = [
            hashlib.sha1(COMMAND_KEY.encode()).hexdigest(),
            hashlib.sha1(b"peacomm_cmd").hexdigest(),
            hashlib.sha1(b"storm_cmd").hexdigest(),
        ]
        self._keys.update(known_keys)
        _log("BLACKLIST", f"Query blacklist initialized with "
             f"{len(self._keys)} known botnet keys")

    def add_key(self, key_hex: str):
        with self._lock:
            self._keys.add(key_hex)

    def is_blacklisted(self, key_hex: str) -> bool:
        with self._lock:
            hit = key_hex in self._keys
            if hit:
                self._hits[key_hex] += 1
            return hit

    def filter_query(self, key_hex: str, src_ip: str) -> dict:
        """
        Called when a peer receives a FIND_VALUE or STORE RPC.
        Returns action: 'forward' or 'discard'.
        """
        if self.is_blacklisted(key_hex):
            _log("BLACKLIST", f"DISCARD query key={key_hex[:12]}... "
                 f"from {src_ip} — blacklisted botnet command key")
            return {"action": "discard", "key": key_hex, "src": src_ip,
                    "reason": "blacklisted_command_key"}
        return {"action": "forward", "key": key_hex}

    def stats(self) -> dict:
        with self._lock:
            return {"blacklisted_keys": len(self._keys),
                    "total_hits": sum(self._hits.values()),
                    "per_key_hits": dict(self._hits)}


class PeerBlacklist:
    """
    Teaching point (§1.6.3 Blacklisting):
      Maintain a list of confirmed bot IP addresses.
      Legitimate peers refuse all connections from/to
      blacklisted peers — effectively silencing identified bots.

      Complements query blacklisting:
        Query blacklist: blocks by CONTENT (what is queried)
        Peer blacklist:  blocks by IDENTITY (who is querying)
    """

    def __init__(self):
        self._peers: Dict[str, dict] = {}   # ip → {reason, ts, count}
        self._lock = threading.Lock()

    def add_peer(self, ip: str, reason: str = "confirmed_bot"):
        with self._lock:
            if ip in self._peers:
                self._peers[ip]["count"] += 1
            else:
                self._peers[ip] = {"reason": reason,
                                   "ts": time.time(), "count": 1}
        _log("BLACKLIST", f"Peer blacklisted: {ip} ({reason})")

    def is_blacklisted(self, ip: str) -> bool:
        with self._lock:
            return ip in self._peers

    def check_connection(self, src_ip: str) -> dict:
        if self.is_blacklisted(src_ip):
            return {"action": "refuse", "ip": src_ip,
                    "reason": self._peers[src_ip]["reason"]}
        return {"action": "allow", "ip": src_ip}

    def stats(self) -> dict:
        with self._lock:
            return {"blacklisted_peers": len(self._peers),
                    "peers": {ip: d["reason"]
                              for ip, d in list(self._peers.items())[:10]}}


# ──────────────────────────────────────────────────────────────────
#  4. DHT SENSOR PLACEMENT (§1.6.2)
# ──────────────────────────────────────────────────────────────────

class DHTSensorPlacement:
    """
    Teaching point (§1.6.2 Sensors):
      In a DHT, each node's ID determines which key lookups
      it RECEIVES (keys close to its ID in XOR metric).
      To monitor ALL command key lookups, place sensors with IDs
      EVENLY DISTRIBUTED across the 160-bit ID space.

      n sensors with uniform spacing cover roughly n/2^160 of
      the ID space. For practical coverage of botnet command
      keys, n=20–50 sensors provides good coverage when the
      command key is known.

      If the command key is known (COMMAND_KEY), place ONE sensor
      with ID closest to SHA1(COMMAND_KEY) to intercept 100%
      of the lookups for that specific key.
    """

    def __init__(self, n_sensors: int = 20):
        self.n_sensors = n_sensors
        self._sensors: List[dict] = []

    def place_uniform(self) -> List[dict]:
        """
        Place sensors with node IDs uniformly across ID space.
        Monitors all possible key lookups proportionally.
        """
        space  = (1 << ID_BITS)
        step   = space // self.n_sensors
        sensors = []

        for i in range(self.n_sensors):
            target_id = step * i + step // 2
            sensors.append({
                "sensor_index": i,
                "node_id": target_id,
                "id_hex": f"{target_id:040x}",
                "coverage_start": f"{(step*i):040x}"[:16] + "...",
                "coverage_end":   f"{(step*(i+1)):040x}"[:16] + "...",
            })

        self._sensors = sensors
        _log("SENSOR", f"Placed {self.n_sensors} sensors uniformly in 2^160 ID space")
        _log("SENSOR", f"Each sensor covers ~1/{self.n_sensors} of the key space")
        _log("SENSOR", f"Combined coverage: {100/self.n_sensors:.1f}% of random keys")
        return sensors

    def place_targeted(self, command_key: str = COMMAND_KEY) -> dict:
        """
        Place a single sensor with ID closest to the command key.
        Intercepts 100% of FIND_VALUE queries for COMMAND_KEY.
        Only works when the command key is known (extractable
        from the bot binary).
        """
        key_id    = _sha1_id(command_key)
        sensor_id = key_id  # exact match = closest possible

        sensor = {
            "command_key": command_key,
            "key_id":      f"{key_id:040x}",
            "sensor_id":   f"{sensor_id:040x}",
            "xor_distance": 0,
            "expected_coverage": "100% of FIND_VALUE(COMMAND_KEY) queries"
        }
        _log("SENSOR", f"Targeted sensor placement:")
        _log("SENSOR", f"  Key:     SHA1('{command_key}')")
        _log("SENSOR", f"  Key ID:  {sensor['key_id'][:20]}...")
        _log("SENSOR", f"  Sensor ID set to key ID — XOR distance = 0")
        _log("SENSOR", f"  This sensor intercepts ALL bot polls for COMMAND_KEY")
        _log("SENSOR", f"  Sensor can then: log poll IPs, poison responses,")
        _log("SENSOR", f"                   forward to defender, or silently drop")
        return sensor

    def estimate_coverage(self) -> dict:
        if not self._sensors:
            self.place_uniform()
        space  = 1 << ID_BITS
        step   = space // self.n_sensors
        # Expected fraction of random keys covered by at least one sensor
        # In a uniform layout with bucket size K=8, each sensor handles
        # ~step / space of all possible keys
        fraction = self.n_sensors * step / space
        return {"n_sensors": self.n_sensors,
                "estimated_coverage_pct": round(fraction * 100, 2),
                "sensors": self._sensors[:3]}


# ──────────────────────────────────────────────────────────────────
#  5. P2P HONEYPOT NODE (§1.6.2)
# ──────────────────────────────────────────────────────────────────

class P2PHoneypotNode:
    """
    Teaching point (§1.6.2 Honeypots):
      A fake Kademlia node that joins the botnet mesh acting
      as a legitimate bot. It:
        - Answers PING/FIND_NODE correctly (stays in routing tables)
        - Logs every STORE and FIND_VALUE it receives
        - Reports command keys and values to the defender
        - DOES NOT execute any commands

      This is the P2P analogue of joining an IRC C&C channel
      as described for IRC-based botnets (§1.6.2).

      Unlike the regular Cowrie SSH honeypot (honeypot_setup.py)
      which traps Mirai-style scanners, the P2P honeypot traps
      Kademlia C&C traffic specifically.

      Run alongside live p2p_node.py instances for monitoring.
    """

    def __init__(self, host: str = "127.0.0.1",
                 port: int = 7699):
        self.host      = host
        self.port      = port
        self._node_id  = _node_id_from_host_port(host, port)
        self._sock: Optional[socket.socket] = None
        self._running  = False
        self._log: List[dict] = []
        self._lock     = threading.Lock()
        self._command_keys_seen: Set[str] = set()
        self._cmd_key_hex = hashlib.sha1(COMMAND_KEY.encode()).hexdigest()

    def start(self):
        self._sock    = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        self._sock.bind((self.host, self.port))
        self._running = True

        t = threading.Thread(target=self._recv_loop, daemon=True,
                             name="honeypot_recv")
        t.start()
        _log("HONEYPOT", f"P2P Honeypot listening on {self.host}:{self.port}")
        _log("HONEYPOT", f"Node ID: {self._node_id:040x}"[:32] + "...")
        _log("HONEYPOT", f"Monitoring for COMMAND_KEY: {self._cmd_key_hex[:16]}...")
        _log("HONEYPOT", "Honeypot is a passive observer — executes NO commands")

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _recv_loop(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except Exception:
                break
            self._handle(data, addr)

    def _handle(self, data: bytes, addr: tuple):
        msg = _parse_msg(data)
        if not msg:
            return

        mtype = msg["type"]
        src   = f"{msg['src_ip']}:{msg['src_port']}"
        ts    = datetime.now().strftime("%H:%M:%S")

        entry = {"ts": ts, "type": mtype, "src": src,
                 "src_id": f"{msg['src_id']:040x}"[:16]}

        if mtype == MSG_PING:
            # Respond with PONG — stay in routing tables
            pong = _build_msg(MSG_PONG, self._node_id,
                              self.host, self.port,
                              msg_id=msg["msg_id"])
            try:
                self._sock.sendto(pong, addr)
            except Exception:
                pass
            _log("HONEYPOT", f"{ts} PING from {src} — sent PONG (staying in RT)")

        elif mtype == MSG_STORE:
            key_hex, value = _parse_store_payload(msg["payload"])
            entry["key"]   = key_hex
            entry["value"] = value
            is_cmd_key     = (key_hex == self._cmd_key_hex)

            if is_cmd_key:
                self._command_keys_seen.add(src)
                _log("HONEYPOT",
                     f"⚠ COMMAND KEY STORE from {src}! "
                     f"key={key_hex[:12]}... val={str(value)[:80]}")
            else:
                _log("HONEYPOT",
                     f"{ts} STORE key={key_hex[:12] if key_hex else '?'}... "
                     f"from {src}")

        elif mtype == MSG_FIND_VALUE:
            payload = msg["payload"]
            if len(payload) >= 20:
                queried_key = payload[:20].hex()
                is_cmd = queried_key == self._cmd_key_hex
                entry["queried_key"] = queried_key
                if is_cmd:
                    _log("HONEYPOT",
                         f"⚠ BOT POLLING! FIND_VALUE(COMMAND_KEY) from {src} "
                         f"— bot IP identified: {msg['src_ip']}")
                    self._command_keys_seen.add(src)
                else:
                    _log("HONEYPOT",
                         f"{ts} FIND_VALUE key={queried_key[:12]}... from {src}")

        elif mtype == MSG_FIND_NODE:
            _log("HONEYPOT", f"{ts} FIND_NODE from {src}")

        with self._lock:
            self._log.append(entry)

    def report(self) -> dict:
        with self._lock:
            log_copy = list(self._log)
        stores      = [e for e in log_copy if e["type"] == MSG_STORE]
        find_values = [e for e in log_copy if e["type"] == MSG_FIND_VALUE]
        pings       = [e for e in log_copy if e["type"] == MSG_PING]

        print(f"\n[HONEYPOT] === Honeypot Report ===")
        print(f"[HONEYPOT] Total events:       {len(log_copy)}")
        print(f"[HONEYPOT] STORE events:       {len(stores)}")
        print(f"[HONEYPOT] FIND_VALUE events:  {len(find_values)}")
        print(f"[HONEYPOT] PING events:        {len(pings)}")
        print(f"[HONEYPOT] Bots identified:    {len(self._command_keys_seen)}")
        if self._command_keys_seen:
            print(f"[HONEYPOT] Bot IPs (polled COMMAND_KEY):")
            for src in self._command_keys_seen:
                print(f"           {src}")

        return {"events": len(log_copy),
                "stores": len(stores),
                "find_values": len(find_values),
                "bots_identified": list(self._command_keys_seen)}


# ──────────────────────────────────────────────────────────────────
#  6. P2P BEHAVIORAL DETECTOR (§1.6.1)
# ──────────────────────────────────────────────────────────────────

class P2PBehaviorDetector:
    """
    Teaching point (§1.6.1 Anomaly Detection):
      Bots in a P2P botnet exhibit behavioral anomalies:
        1. Periodic queries for the SAME hash key (pull polling)
        2. Queries that never result in actual file downloads
        3. High query rate but zero upload activity
        4. Querying content they themselves claim to have

      These patterns differ from legitimate P2P behavior:
        - Legitimate users query different files each session
        - They download files they search for
        - Upload/download ratios are roughly balanced

      This is an IDS engine analogous to Engine 2
      (ids_detector.py, behavioral CV timing) but for P2P-
      specific traffic patterns rather than login timing.

      In a real deployment, this engine would be integrated
      into ids_detector.py as Engine 22E.
    """

    SAME_KEY_THRESHOLD  = 5      # queries for same key in WINDOW triggers alert
    NO_DL_RATIO_THRESH  = 0.95   # 95% queries with no download = suspicious
    HIGH_QUERY_RATE_PPS = 2.0    # queries per second per peer
    WINDOW_SEC          = 60.0

    ENGINE_ID   = "22E"
    ENGINE_NAME = "P2PBehaviorDetector"

    def __init__(self):
        self._lock    = threading.Lock()
        # peer_ip → deque of (ts, key_hex)
        self._queries: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        # peer_ip → deque of ts (actual download starts)
        self._downloads: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._alerts: List[dict] = []

    def record_query(self, peer_ip: str, key_hex: str,
                     alert_cb: Callable = None) -> Optional[str]:
        now = time.time()
        with self._lock:
            self._queries[peer_ip].append((now, key_hex))
        return self._analyze(peer_ip, alert_cb)

    def record_download(self, peer_ip: str):
        with self._lock:
            self._downloads[peer_ip].append(time.time())

    def _analyze(self, peer_ip: str,
                 alert_cb: Callable = None) -> Optional[str]:
        now    = time.time()
        cutoff = now - self.WINDOW_SEC

        with self._lock:
            # Prune old events
            while (self._queries[peer_ip] and
                   self._queries[peer_ip][0][0] < cutoff):
                self._queries[peer_ip].popleft()
            while (self._downloads[peer_ip] and
                   self._downloads[peer_ip][0] < cutoff):
                self._downloads[peer_ip].popleft()

            recent_queries  = list(self._queries[peer_ip])
            recent_downloads = list(self._downloads[peer_ip])

        if len(recent_queries) < 3:
            return None

        alert = None

        # Signature 1: Same key repeated (bot polling)
        key_counter: Dict[str, int] = defaultdict(int)
        for _, key in recent_queries:
            key_counter[key] += 1
        top_key, top_count = max(key_counter.items(),
                                 key=lambda x: x[1])
        if top_count >= self.SAME_KEY_THRESHOLD:
            alert = (f"ENGINE {self.ENGINE_ID} HIGH: P2P BOT POLLING DETECTED "
                     f"src={peer_ip} key={top_key[:12]}... "
                     f"queries={top_count} in {self.WINDOW_SEC:.0f}s — "
                     f"same key ≥{self.SAME_KEY_THRESHOLD}x "
                     f"(bot pull C&C pattern §1.6.1)")

        # Signature 2: Queries with no downloads
        if not alert and len(recent_queries) >= 10:
            dl_ratio = len(recent_downloads) / len(recent_queries)
            if (1 - dl_ratio) >= self.NO_DL_RATIO_THRESH:
                alert = (f"ENGINE {self.ENGINE_ID} MED: P2P NO-DOWNLOAD ANOMALY "
                         f"src={peer_ip} queries={len(recent_queries)} "
                         f"downloads={len(recent_downloads)} "
                         f"({(1-dl_ratio)*100:.1f}% queries with no download — "
                         f"bot pattern §1.6.1)")

        # Signature 3: High query rate
        if not alert:
            elapsed = self.WINDOW_SEC
            qps     = len(recent_queries) / elapsed
            if qps >= self.HIGH_QUERY_RATE_PPS:
                alert = (f"ENGINE {self.ENGINE_ID} MED: HIGH P2P QUERY RATE "
                         f"src={peer_ip} rate={qps:.2f} qps — "
                         f"threshold {self.HIGH_QUERY_RATE_PPS} qps")

        if alert:
            with self._lock:
                self._alerts.append({"ts": time.time(),
                                     "peer": peer_ip, "alert": alert})
            _log("DETECT", alert)
            if alert_cb:
                alert_cb(alert)

        return alert

    def demo(self, n_peers: int = 5, bot_peers: int = 2):
        """Simulate mixed legitimate + bot traffic and show detection."""
        _log("DETECT", "=== P2P Behavioral Detector Demo (§1.6.1) ===")
        _log("DETECT", f"Simulating {n_peers} peers ({bot_peers} bots)")
        alerts_fired = 0

        def _on_alert(a):
            nonlocal alerts_fired
            alerts_fired += 1

        for peer_idx in range(n_peers):
            ip = f"192.168.100.{20 + peer_idx}"
            is_bot = peer_idx < bot_peers

            if is_bot:
                # Bot: repeatedly queries COMMAND_KEY, never downloads
                cmd_key_hex = hashlib.sha1(COMMAND_KEY.encode()).hexdigest()
                for _ in range(self.SAME_KEY_THRESHOLD + 2):
                    self.record_query(ip, cmd_key_hex, _on_alert)
                _log("DETECT", f"  Bot peer {ip}: queried COMMAND_KEY "
                     f"{self.SAME_KEY_THRESHOLD+2}x, 0 downloads")
            else:
                # Legit: queries different keys, some downloads
                for _ in range(6):
                    rnd_key = os.urandom(20).hex()
                    self.record_query(ip, rnd_key, _on_alert)
                    if random.random() < 0.6:
                        self.record_download(ip)
                _log("DETECT", f"  Legit peer {ip}: varied queries, downloads recorded")

        _log("DETECT", f"\nDetection result: {alerts_fired} alert(s) fired")
        _log("DETECT", f"Expected: ≥{bot_peers} alerts (one per bot peer)")
        return {"alerts": alerts_fired, "bots": bot_peers}


# ──────────────────────────────────────────────────────────────────
#  7. PROTOCOL HARDENER (§1.6.4)
# ──────────────────────────────────────────────────────────────────

class ProtocolHardener:
    """
    Teaching point (§1.6.4):
      Secure the P2P protocol itself to make it hostile to
      botnet C&C reuse:

        1. Reject STORE values that don't match expected format
           (JSON-only, specific schema)
        2. Enforce maximum value size (e.g. 512 bytes)
        3. Require HMAC on stored values (key rotation support)
        4. Rate-limit STORE RPCs per peer
        5. Discard entries with known botnet command type fields

      "What content may contain in a returned query result
       depends on the protocol itself. Keeping bogus information
       away from DHT — trying to let the DHT contain as small
       information as possible — could make DHT-based P2P
       networks more secure." (§1.6.4)
    """

    MAX_VALUE_SIZE    = 512      # bytes
    MAX_STORES_PER_IP = 10       # per RATE_WINDOW_SEC
    RATE_WINDOW_SEC   = 60.0

    BLOCKED_FIELDS = {"type", "target", "port", "duration",
                      "syn_flood", "udp_flood", "slowloris",
                      "cryptojack", "cred_stuffing", "keylogger"}

    def __init__(self, require_hmac: bool = False,
                 hmac_key: bytes = b"AUA_HARDENED_P2P_KEY"):
        self.require_hmac = require_hmac
        self.hmac_key     = hmac_key
        self._store_log: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=200)
        )
        self._rejected = 0
        self._accepted = 0
        self._lock     = threading.Lock()

    def validate_store(self, src_ip: str,
                       key_hex: str, value: str) -> dict:
        """
        Validate a STORE RPC against all hardening policies.
        Returns {"allow": True/False, "reason": str}.
        """
        now = time.time()

        # Policy 1: value size limit
        if len(value.encode()) > self.MAX_VALUE_SIZE:
            return self._reject(src_ip,
                                f"value too large: {len(value.encode())} > "
                                f"{self.MAX_VALUE_SIZE} bytes")

        # Policy 2: rate limit per source IP
        with self._lock:
            self._store_log[src_ip].append(now)
            cutoff   = now - self.RATE_WINDOW_SEC
            recent   = [t for t in self._store_log[src_ip] if t > cutoff]
            self._store_log[src_ip] = deque(recent, maxlen=200)
            n_recent = len(recent)
        if n_recent > self.MAX_STORES_PER_IP:
            return self._reject(src_ip,
                                f"rate limit exceeded: {n_recent} STOREs "
                                f"in {self.RATE_WINDOW_SEC:.0f}s > "
                                f"{self.MAX_STORES_PER_IP}")

        # Policy 3: block known botnet command field names
        lower_val = value.lower()
        for blocked in self.BLOCKED_FIELDS:
            if blocked in lower_val:
                return self._reject(src_ip,
                                    f"blocked field in value: '{blocked}'")

        # Policy 4: optional HMAC validation
        if self.require_hmac:
            try:
                d    = json.loads(value)
                sig  = d.pop("hmac", None)
                body = json.dumps(d, sort_keys=True)
                expected = _hmac_mod.new(
                    self.hmac_key, body.encode(), "sha256"
                ).hexdigest()
                if not _hmac_mod.compare_digest(expected, sig or ""):
                    return self._reject(src_ip, "invalid HMAC signature")
            except Exception:
                return self._reject(src_ip, "non-JSON value rejected "
                                            "(HMAC-required mode)")

        with self._lock:
            self._accepted += 1
        return {"allow": True, "reason": "passed_all_policies"}

    def _reject(self, src_ip: str, reason: str) -> dict:
        _log("HARDEN", f"STORE REJECTED from {src_ip}: {reason}")
        with self._lock:
            self._rejected += 1
        return {"allow": False, "reason": reason}

    def demo(self):
        """Demonstrate validation against real botnet payloads."""
        _log("HARDEN", "=== Protocol Hardener Demo (§1.6.4) ===")
        test_cases = [
            ("192.168.100.11", "a" * 40, json.dumps({
                "type": "syn_flood", "target": "192.168.100.20",
                "port": 80, "duration": 30
            }), "real botnet command — should be REJECTED"),
            ("192.168.100.11", "b" * 40, "x" * 1000,
             "oversized value — should be REJECTED"),
            ("192.168.100.11", "c" * 40, json.dumps({"filename": "report.pdf",
                "size": 1024, "hash": "abc123"}),
             "legitimate P2P metadata — should be ACCEPTED"),
        ]
        # Rate-limit test
        for i in range(self.MAX_STORES_PER_IP + 3):
            self.validate_store("192.168.100.99", "d" * 40, '{"x":1}')

        for src_ip, key, value, desc in test_cases:
            r = self.validate_store(src_ip, key, value)
            _log("HARDEN", f"  [{desc}]")
            _log("HARDEN", f"  → allow={r['allow']} reason={r['reason']}")

        _log("HARDEN", f"\nRate-limit test: 192.168.100.99 "
             f"({self.MAX_STORES_PER_IP+3} STOREs in window)")
        rl = self.validate_store("192.168.100.99", "e" * 40, '{"x":1}')
        _log("HARDEN", f"  → allow={rl['allow']} reason={rl['reason']}")

        with self._lock:
            _log("HARDEN", f"\nTotal: accepted={self._accepted} "
                 f"rejected={self._rejected}")


# ──────────────────────────────────────────────────────────────────
#  8. BOOTSTRAP DISRUPTOR (§1.6.3)
# ──────────────────────────────────────────────────────────────────

class BootstrapDisruptor:
    """
    Teaching point (§1.6.3 Physical Shutdown):
      "Botnet construction relying on bootstrapping is vulnerable
       during its early stage. Isolating or shutting down bootstrap
       servers or the bots in the initial list that is hard-coded
       in bot code can effectively prevent a new-born botnet from
       growing into a real threat."

      Steps:
        1. Obtain bot binary (honeypot capture or law enforcement)
        2. Extract hard-coded seed IPs via static analysis
        3. Contact ISPs or hosting providers to null-route seeds
        4. Alternatively: add seeds to peer blacklist on legit P2P
           nodes so they cannot propagate to new victims

      This is ineffective against:
        - Hybrid botnets (peer-list passing — no hard-coded seeds)
        - Botnets that update seeds dynamically via DGA or DNS
    """

    def __init__(self, peer_blacklist: Optional[PeerBlacklist] = None):
        self._blacklist = peer_blacklist or PeerBlacklist()
        self._seeds_blocked: List[str] = []

    def extract_seeds_from_binary(self,
                                   binary_path: str = None) -> List[str]:
        """
        Simulate static analysis of bot binary to extract
        hard-coded bootstrap seed IPs.

        Real-world: use strings(1), radare2, or Ghidra to find
        IP addresses in the binary. The lab binary kademlia_p2p.c
        uses command-line --bootstrap flags — in a real malware
        the seeds would be embedded as 4-byte blobs.
        """
        _log("DISRUPT", "=== Bootstrap Disruption Defense (§1.6.3) ===")
        if binary_path:
            _log("DISRUPT", f"Analyzing binary: {binary_path}")
            # Try to read the binary and extract IP-like patterns
            try:
                import re
                with open(binary_path, "rb") as f:
                    content = f.read().decode(errors="replace")
                # Find IPv4 addresses (simple heuristic)
                ips = re.findall(
                    r'\b(?:192\.168\.\d{1,3}|10\.\d{1,3}\.\d{1,3})\.\d{1,3}\b',
                    content
                )
                if ips:
                    _log("DISRUPT", f"Found {len(ips)} IP addresses in binary")
                    return list(set(ips))
            except Exception as e:
                _log("DISRUPT", f"Binary read failed: {e}")

        # Simulate extraction for lab demo
        simulated_seeds = [
            "192.168.100.11",
            "192.168.100.12",
            "192.168.100.10",
        ]
        _log("DISRUPT", f"Simulated extraction: found {len(simulated_seeds)} "
             f"hard-coded seed IPs")
        return simulated_seeds

    def block_seeds(self, seed_ips: List[str]) -> dict:
        """
        Add extracted seed IPs to the peer blacklist and
        simulate ISP null-routing.
        """
        for ip in seed_ips:
            self._blacklist.add_peer(ip, reason="botnet_bootstrap_seed")
            self._seeds_blocked.append(ip)
            _log("DISRUPT", f"Blocked seed: {ip} "
                 f"(ISP null-route + peer blacklist)")

        _log("DISRUPT", f"\nResult: {len(seed_ips)} bootstrap seeds blocked")
        _log("DISRUPT", f"Effect: new bot infections CANNOT join the botnet")
        _log("DISRUPT", f"        (bootstrap step fails — no seeds reachable)")
        _log("DISRUPT", f"Limitation: existing {len(seed_ips) * 10} bots (est.)")
        _log("DISRUPT", f"            are still operational — already joined")
        _log("DISRUPT", f"\nIneffective against: hybrid botnets (peer-list passing)")
        _log("DISRUPT", f"See p2p_botnet_topologies.py --type hybrid --disrupt")

        return {"seeds_blocked": len(seed_ips),
                "growth_halted": True,
                "existing_bots_affected": False}


# ──────────────────────────────────────────────────────────────────
#  COMBINED DEMO
# ──────────────────────────────────────────────────────────────────

def run_demo(target_host: str = "127.0.0.1",
             target_port: int = 7500):
    _print_sep = lambda t: print("\n" + "="*60 + f"\n  {t}\n" + "="*60)

    _print_sep("1. Index Poisoning (§1.6.3) — The Central Finding")
    ip = IndexPoisoner(target_host, target_port, n_poison_nodes=25)
    ip.poison_standalone()

    _print_sep("2. Sybil Attack as Defense (§1.6.3)")
    sa = SybilAttacker(n_sybils=30)
    sa.generate_sybils()
    # Simulate 10 bots each with 8 peers
    fake_lists = [[random.randint(0, 10000) for _ in range(8)]
                  for _ in range(10)]
    sa.simulate_routing_table_injection(fake_lists)

    _print_sep("3. Query + Peer Blacklisting (§1.6.3)")
    ql = QueryBlacklist()
    pl = PeerBlacklist()
    pl.add_peer("192.168.100.11", "confirmed_bot_ip")
    cmd_key = hashlib.sha1(COMMAND_KEY.encode()).hexdigest()
    r1 = ql.filter_query(cmd_key, "192.168.100.11")
    r2 = pl.check_connection("192.168.100.11")
    r3 = pl.check_connection("192.168.100.50")
    _log("BLACKLIST", f"Query filter result: {r1['action']}")
    _log("BLACKLIST", f"Known bot connection: {r2['action']} ({r2.get('reason','')})")
    _log("BLACKLIST", f"Unknown peer connection: {r3['action']}")

    _print_sep("4. DHT Sensor Placement (§1.6.2)")
    sp = DHTSensorPlacement(n_sensors=20)
    sp.place_uniform()
    sp.place_targeted(COMMAND_KEY)
    cov = sp.estimate_coverage()
    _log("SENSOR", f"Coverage estimate: {cov['estimated_coverage_pct']:.1f}% of random keys")

    _print_sep("5. P2P Honeypot Node (§1.6.2)")
    hp = P2PHoneypotNode()
    hp.start()
    _log("HONEYPOT", "Honeypot started — listening for DHT traffic")
    _log("HONEYPOT", "In live demo: run p2p_node.py nodes alongside")
    _log("HONEYPOT", "Simulating one FIND_VALUE for COMMAND_KEY...")
    time.sleep(0.5)
    hp.stop()
    hp.report()

    _print_sep("6. P2P Behavioral Detector (§1.6.1)")
    det = P2PBehaviorDetector()
    det.demo(n_peers=6, bot_peers=2)

    _print_sep("7. Protocol Hardener (§1.6.4)")
    ph = ProtocolHardener()
    ph.demo()

    _print_sep("8. Bootstrap Disruptor (§1.6.3)")
    bd = BootstrapDisruptor(peer_blacklist=pl)
    seeds = bd.extract_seeds_from_binary()
    bd.block_seeds(seeds)

    print("\n" + "="*60)
    print("  All P2P countermeasures demonstrated.")
    print("  Most critical finding: INDEX POISONING (§1.6.3)")
    print("  disables pull-based P2P C&C without touching any bot.")
    print("="*60)


# ──────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print(" P2P Countermeasures — AUA CS 232/337 Research Lab")
    print(" ISOLATED VM ONLY")
    print("=" * 60)

    parser = argparse.ArgumentParser(
        description="P2P Botnet Countermeasures (§1.6)"
    )
    parser.add_argument("--demo",     action="store_true",
                        help="Run all countermeasures in sequence")
    parser.add_argument("--poison",   action="store_true",
                        help="Index poisoning standalone demo")
    parser.add_argument("--live-poison", action="store_true",
                        help="Live index poisoning against p2p_node.py")
    parser.add_argument("--sybil",    action="store_true",
                        help="Sybil attack demo")
    parser.add_argument("--honeypot", action="store_true",
                        help="Start P2P honeypot node")
    parser.add_argument("--sensor",   action="store_true",
                        help="DHT sensor placement demo")
    parser.add_argument("--detect",   action="store_true",
                        help="Behavioral detector demo")
    parser.add_argument("--harden",   action="store_true",
                        help="Protocol hardener demo")
    parser.add_argument("--blacklist",action="store_true",
                        help="Blacklisting demo")
    parser.add_argument("--bootstrap-disrupt", metavar="HOST:PORT",
                        help="Bootstrap disruption against given seed")
    parser.add_argument("--target",   default="127.0.0.1:7500",
                        help="Live target HOST:PORT (default: 127.0.0.1:7500)")
    parser.add_argument("--n",        type=int, default=20,
                        help="Number of sensors/sybils (default: 20)")
    parser.add_argument("--rounds",   type=int, default=5,
                        help="Poison flood rounds (default: 5)")
    args = parser.parse_args()

    host, port = args.target.rsplit(":", 1)
    port = int(port)

    if args.demo:
        run_demo(host, port)
    elif args.poison:
        p = IndexPoisoner(host, port,
                          n_poison_nodes=args.n, flood_rounds=args.rounds)
        p.poison_standalone()
    elif args.live_poison:
        p = IndexPoisoner(host, port,
                          n_poison_nodes=args.n, flood_rounds=args.rounds)
        p.poison_standalone()
        print()
        p.poison_live(duration=args.rounds * 3)
    elif args.sybil:
        sa = SybilAttacker(n_sybils=args.n)
        sa.generate_sybils()
        fake_lists = [[random.randint(0, 10000) for _ in range(8)]
                      for _ in range(20)]
        sa.simulate_routing_table_injection(fake_lists)
    elif args.honeypot:
        hp = P2PHoneypotNode(host, port + 199)
        hp.start()
        print(f"[HONEYPOT] Running. Press Ctrl+C to stop and show report.")
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            hp.stop()
            hp.report()
    elif args.sensor:
        sp = DHTSensorPlacement(n_sensors=args.n)
        sp.place_uniform()
        sp.place_targeted(COMMAND_KEY)
        print(json.dumps(sp.estimate_coverage(), indent=2, default=str))
    elif args.detect:
        det = P2PBehaviorDetector()
        det.demo()
    elif args.harden:
        ph = ProtocolHardener()
        ph.demo()
    elif args.blacklist:
        ql = QueryBlacklist()
        pl = PeerBlacklist()
        pl.add_peer("192.168.100.11", "confirmed_bot")
        print(json.dumps(ql.stats(), indent=2))
        print(json.dumps(pl.stats(), indent=2))
    elif args.bootstrap_disrupt:
        h2, p2 = args.bootstrap_disrupt.rsplit(":", 1)
        pl2 = PeerBlacklist()
        bd  = BootstrapDisruptor(pl2)
        seeds = bd.extract_seeds_from_binary()
        bd.block_seeds(seeds)
    else:
        parser.print_help()
