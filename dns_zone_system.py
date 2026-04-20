"""
====================================================
 AUA CS 232/337 — Botnet Research Project
 Component: Full DNS Zone Record System
 Environment: ISOLATED VM LAB ONLY
====================================================

Mirrors Spinnekop:
  internal/models/srv_models/models_srv.go   (all record data structs)
  cmd/server/config.go                       (YAML loading, applyDefaults,
                                              validateZoneConsistency,
                                              validateZoneConsistency)
  internal/models/srv_models/utils.go        (FindZone, IsAuthoritative)
  internal/server/process_request.go         (buildAndSendResponse, record lookup)

Supported record types: A, AAAA, CNAME, MX, NS, TXT, SOA
Zone operations:
  - Load from configs/dns_server.yaml
  - Apply TTL defaults
  - Validate consistency (glue records, CNAME conflicts, MX targets)
  - Resolve queries and build raw DNS responses for all record types
  - Wildcard A record support (*.zone.com)

Usage:
  # From YAML file:
  zs = ZoneSystem.from_yaml("configs/dns_server.yaml")

  # Quick single-zone (backwards-compat with old dns_zflag_server.py Zone):
  zs = ZoneSystem.simple("timeserversync.com.", "127.0.0.1")

  # Resolve + build response:
  resp = zs.build_response(qname, qtype_int, msg_id, flags, z_value=2)

  # Authoritative check:
  zone = zs.find_zone("sub.timeserversync.com.")
  is_auth = zs.is_authoritative("sub.timeserversync.com.")

  # Consistency validation:
  errors = zs.validate_all()
"""

import ipaddress
import os
import socket
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dns_zflag_crafter import QTYPE_MAP, encode_dns_name


# ═════════════════════════════════════════════════════════════
#  Record data classes
#  Mirror Spinnekop internal/models/srv_models/models_srv.go
# ═════════════════════════════════════════════════════════════

@dataclass
class SOARecord:
    """Start of Authority record."""
    primary: str           # Primary NS FQDN
    admin:   str           # Admin e-mail (@ → .)
    serial:  int = 2024010101
    refresh: int = 3600    # Secondary refresh interval (s)
    retry:   int = 1800    # Retry after failed transfer (s)
    expire:  int = 604800  # Secondaries expire data after (s)
    minimum: int = 86400   # Minimum / negative caching TTL (s)

@dataclass
class NSRecord:
    name: str   # Nameserver FQDN
    ip:   str   # IP address (used for glue validation)

@dataclass
class ARecord:
    name: str
    ip:   str
    ttl:  int = 0           # 0 = inherit zone default TTL

@dataclass
class AAAARecord:
    name: str
    ip:   str
    ttl:  int = 0

@dataclass
class CNAMERecord:
    name:   str             # Alias name
    target: str             # Canonical target FQDN
    ttl:    int = 0

@dataclass
class MXRecord:
    name:     str
    priority: int = 10
    target:   str = ""      # Mail-server FQDN
    ttl:      int = 0

@dataclass
class TXTRecord:
    name: str
    text: str
    ttl:  int = 0

@dataclass
class ZoneConfig:
    """
    Complete DNS zone — all record types.
    Mirrors Spinnekop internal/models/srv_models/models_srv.go ZoneConfig.
    """
    name:         str
    description:  str               = ""
    ttl:          int               = 300
    soa:          Optional[SOARecord]    = None
    nameservers:  List[NSRecord]         = field(default_factory=list)
    a_records:    List[ARecord]          = field(default_factory=list)
    aaaa_records: List[AAAARecord]       = field(default_factory=list)
    cname_records:List[CNAMERecord]      = field(default_factory=list)
    mx_records:   List[MXRecord]         = field(default_factory=list)
    txt_records:  List[TXTRecord]        = field(default_factory=list)


# ═════════════════════════════════════════════════════════════
#  YAML / config loader
#  Mirrors Spinnekop cmd/server/config.go ConfigLoader.Load()
# ═════════════════════════════════════════════════════════════

def load_server_yaml(path: str) -> dict:
    """Load full server config from YAML (or JSON fallback)."""
    with open(path) as f:
        content = f.read()
    try:
        import yaml
        return yaml.safe_load(content) or {}
    except ImportError:
        import json
        return json.loads(content)


def parse_zones_from_config(cfg: dict) -> List[ZoneConfig]:
    """
    Parse zone list from the loaded config dict.
    Mirrors Spinnekop ConfigLoader parsing logic.
    """
    zones: List[ZoneConfig] = []
    for z in cfg.get("zones", []):
        name = z.get("name", "")
        if name and not name.endswith("."):
            name += "."

        soa_raw = z.get("soa", {})
        soa = SOARecord(
            primary = soa_raw.get("primary", f"ns1.{name}"),
            admin   = soa_raw.get("admin",   f"admin.{name}"),
            serial  = soa_raw.get("serial",  2024010101),
            refresh = soa_raw.get("refresh", 3600),
            retry   = soa_raw.get("retry",   1800),
            expire  = soa_raw.get("expire",  604800),
            minimum = soa_raw.get("minimum", 86400),
        ) if soa_raw else None

        zone = ZoneConfig(
            name        = name,
            description = z.get("description", ""),
            ttl         = z.get("ttl", 300),
            soa         = soa,
            nameservers = [
                NSRecord(name=ns.get("name", ""), ip=ns.get("ip", ""))
                for ns in z.get("nameservers", [])
            ],
            a_records = [
                ARecord(name=r.get("name",""), ip=r.get("ip",""), ttl=r.get("ttl",0))
                for r in z.get("a_records", [])
            ],
            aaaa_records = [
                AAAARecord(name=r.get("name",""), ip=r.get("ip",""), ttl=r.get("ttl",0))
                for r in z.get("aaaa_records", [])
            ],
            cname_records = [
                CNAMERecord(name=r.get("name",""), target=r.get("target",""),
                            ttl=r.get("ttl",0))
                for r in z.get("cname_records", [])
            ],
            mx_records = [
                MXRecord(name=r.get("name",""), priority=r.get("priority",10),
                         target=r.get("target",""), ttl=r.get("ttl",0))
                for r in z.get("mx_records", [])
            ],
            txt_records = [
                TXTRecord(name=r.get("name",""), text=r.get("text",""),
                          ttl=r.get("ttl",0))
                for r in z.get("txt_records", [])
            ],
        )
        zones.append(zone)
    return zones


def apply_zone_defaults(zone: ZoneConfig) -> None:
    """
    Inherit zone default TTL on records that left TTL=0.
    Mirrors Spinnekop ConfigLoader.applyZoneDefaults().
    """
    for rec in (zone.a_records + zone.aaaa_records + zone.cname_records
                + zone.mx_records + zone.txt_records):
        if rec.ttl == 0:
            rec.ttl = zone.ttl


# ═════════════════════════════════════════════════════════════
#  Zone consistency validation
#  Mirrors Spinnekop cmd/server/config.go validateZoneConsistency()
# ═════════════════════════════════════════════════════════════

def validate_zone_consistency(zone: ZoneConfig) -> List[str]:
    """
    Enforce three classic DNS correctness rules:

    1. Nameserver glue records
       Every NS entry must have a matching A or AAAA record, so
       resolvers can find the nameserver without a separate lookup.

    2. CNAME exclusivity
       A CNAME record cannot share its owner name with any other
       record type (RFC 1034 §3.6.2).

    3. MX target validity
       MX targets should resolve in-zone or be a FQDN outside.

    Returns a list of error/warning strings (empty = consistent).
    """
    errors: List[str] = []

    a_names    = {r.name.lower() for r in zone.a_records}
    aaaa_names = {r.name.lower() for r in zone.aaaa_records}
    cname_names= {r.name.lower() for r in zone.cname_records}
    all_names  = a_names | aaaa_names | cname_names

    # Rule 1: Glue records
    for ns in zone.nameservers:
        ns_l = ns.name.lower()
        if ns_l not in a_names and ns_l not in aaaa_names:
            errors.append(
                f"[error] Nameserver '{ns.name}' (IP {ns.ip}) has no A or AAAA glue record"
            )

    # Rule 2: CNAME conflicts
    for cname in zone.cname_records:
        cn_l = cname.name.lower()
        if cn_l in a_names:
            errors.append(
                f"[error] CNAME '{cname.name}' conflicts with A record of same name"
            )
        if cn_l in aaaa_names:
            errors.append(
                f"[error] CNAME '{cname.name}' conflicts with AAAA record of same name"
            )

    # Rule 3: MX targets
    for mx in zone.mx_records:
        target_l = mx.target.lower().rstrip(".")
        # Check if target is in-zone or looks like an external FQDN
        if target_l not in {n.lower().rstrip(".") for n in all_names}:
            if not mx.target.endswith("."):
                errors.append(
                    f"[warning] MX target '{mx.target}' for '{mx.name}' "
                    f"is not in zone and is not a FQDN — may not be resolvable"
                )

    return errors


def validate_record_ips(zone: ZoneConfig) -> List[str]:
    """Validate A records contain valid IPv4 and AAAA records valid IPv6."""
    errors: List[str] = []
    for r in zone.a_records:
        try:
            addr = ipaddress.ip_address(r.ip)
            if not isinstance(addr, ipaddress.IPv4Address):
                errors.append(f"[error] A record '{r.name}': '{r.ip}' is not IPv4")
        except ValueError:
            errors.append(f"[error] A record '{r.name}': '{r.ip}' is not a valid IP")
    for r in zone.aaaa_records:
        try:
            addr = ipaddress.ip_address(r.ip)
            if not isinstance(addr, ipaddress.IPv6Address):
                errors.append(f"[error] AAAA record '{r.name}': '{r.ip}' is not IPv6")
        except ValueError:
            errors.append(f"[error] AAAA record '{r.name}': '{r.ip}' is not a valid IP")
    return errors


# ═════════════════════════════════════════════════════════════
#  ZoneSystem — multi-zone resolver + response builder
#  Mirrors Spinnekop:
#    internal/models/srv_models/utils.go  (FindZone, IsAuthoritative)
#    internal/server/process_request.go   (buildAndSendResponse)
# ═════════════════════════════════════════════════════════════

class ZoneSystem:
    """
    Multi-zone DNS resolver.
    Given a query name and type, finds the authoritative zone,
    looks up matching records, and builds a raw DNS response.
    """

    def __init__(self, zones: List[ZoneConfig]):
        self.zones = zones

    # ── Constructors ─────────────────────────────────────────

    @classmethod
    def from_yaml(cls, config_path: str) -> "ZoneSystem":
        """
        Full constructor: load zones from YAML, apply defaults.
        Mirrors Spinnekop ConfigLoader.Load().
        """
        cfg   = load_server_yaml(config_path)
        zones = parse_zones_from_config(cfg)
        for z in zones:
            apply_zone_defaults(z)
        return cls(zones)

    @classmethod
    def simple(cls, zone_name: str, zone_ip: str,
               ttl: int = 300) -> "ZoneSystem":
        """
        Minimal single-zone constructor (backwards-compatible with the
        old dns_zflag_server.py Zone class).
        Creates: SOA, two NS records, glue A records, and a wildcard A.
        """
        if not zone_name.endswith("."):
            zone_name += "."
        ns1 = f"ns1.{zone_name}"
        ns2 = f"ns2.{zone_name}"
        zone = ZoneConfig(
            name        = zone_name,
            description = "Auto-generated minimal zone",
            ttl         = ttl,
            soa         = SOARecord(primary=ns1, admin=f"admin.{zone_name}"),
            nameservers = [NSRecord(name=ns1, ip=zone_ip),
                           NSRecord(name=ns2, ip=zone_ip)],
            a_records   = [
                ARecord(name=ns1, ip=zone_ip, ttl=ttl),
                ARecord(name=ns2, ip=zone_ip, ttl=ttl),
                ARecord(name=f"www.{zone_name}", ip=zone_ip, ttl=ttl),
                ARecord(name=f"*.{zone_name}", ip=zone_ip, ttl=ttl),  # wildcard
            ],
        )
        return cls([zone])

    # ── Zone lookup ───────────────────────────────────────────

    def find_zone(self, qname: str) -> Optional[ZoneConfig]:
        """
        Find the most-specific zone that is authoritative for qname.
        Exact match takes priority over parent-zone match.
        Mirrors Spinnekop Config.FindZone().
        """
        if not qname.endswith("."):
            qname += "."
        qname = qname.lower()
        best: Optional[ZoneConfig] = None
        best_len = -1
        for zone in self.zones:
            zn = zone.name.lower()
            if qname == zn or qname.endswith("." + zn):
                if len(zn) > best_len:
                    best = zone
                    best_len = len(zn)
        return best

    def is_authoritative(self, qname: str) -> bool:
        """True if we have a zone covering qname."""
        return self.find_zone(qname) is not None

    # ── Consistency validation ────────────────────────────────

    def validate_all(self) -> List[str]:
        """
        Run all consistency checks across all zones.
        Mirrors Spinnekop ConfigLoader.ValidateZoneConsistency().
        Returns combined list of errors/warnings.
        """
        all_errors: List[str] = []
        for zone in self.zones:
            errs = validate_zone_consistency(zone) + validate_record_ips(zone)
            for e in errs:
                all_errors.append(f"[zone:{zone.name}] {e}")
        return all_errors

    # ── Response builder (top-level entry point) ──────────────

    def build_response(self, qname: str, qtype_int: int,
                       msg_id: int, original_flags: int,
                       z_value: int = 0) -> bytes:
        """
        Build a complete raw DNS response for the given query.
        Injects z_value into the response's Z-flag bits (4-6).
        Returns REFUSED if not authoritative, NXDOMAIN/NOTIMP as appropriate.
        Mirrors Spinnekop buildAndSendResponse().
        """
        zone = self.find_zone(qname)
        if zone is None:
            return _make_error(msg_id, original_flags, rcode=5,
                               qname=qname, qtype=qtype_int)  # REFUSED

        # Route by query type
        type_map = {
            QTYPE_MAP.get("A",    1):   self._resolve_a,
            QTYPE_MAP.get("AAAA", 28):  self._resolve_aaaa,
            QTYPE_MAP.get("CNAME", 5):  self._resolve_cname,
            QTYPE_MAP.get("MX",   15):  self._resolve_mx,
            QTYPE_MAP.get("TXT",  16):  self._resolve_txt,
            QTYPE_MAP.get("NS",    2):  self._resolve_ns,
            QTYPE_MAP.get("SOA",   6):  self._resolve_soa,
            QTYPE_MAP.get("ANY", 255):  self._resolve_any,
        }
        resolver = type_map.get(qtype_int)
        if resolver is None:
            return _make_error(msg_id, original_flags, rcode=4,
                               qname=qname, qtype=qtype_int)  # NOTIMP

        records = resolver(zone, qname)
        if not records:
            return _make_error(msg_id, original_flags, rcode=3,
                               qname=qname, qtype=qtype_int)  # NXDOMAIN

        return _build_response(msg_id, original_flags, qname,
                               qtype_int, records, z_value)

    # ── Per-type record resolvers ─────────────────────────────

    def _resolve_a(self, zone: ZoneConfig, qname: str) -> List[dict]:
        results = []
        qname_l = qname.lower()
        for r in zone.a_records:
            name_l = r.name.lower()
            if name_l == qname_l:
                results.append({"type": "A", "name": qname, "ttl": r.ttl, "ip": r.ip})
            elif name_l.startswith("*."):
                # Wildcard: *.zone.com matches any.zone.com
                wild_base = name_l[2:]           # strip "*."
                if qname_l != wild_base and (
                    qname_l.endswith("." + wild_base) or qname_l == wild_base
                ):
                    results.append({"type": "A", "name": qname, "ttl": r.ttl, "ip": r.ip})
        return results

    def _resolve_aaaa(self, zone: ZoneConfig, qname: str) -> List[dict]:
        qname_l = qname.lower()
        return [
            {"type": "AAAA", "name": qname, "ttl": r.ttl, "ip": r.ip}
            for r in zone.aaaa_records if r.name.lower() == qname_l
        ]

    def _resolve_cname(self, zone: ZoneConfig, qname: str) -> List[dict]:
        qname_l = qname.lower()
        return [
            {"type": "CNAME", "name": qname, "ttl": r.ttl, "target": r.target}
            for r in zone.cname_records if r.name.lower() == qname_l
        ]

    def _resolve_mx(self, zone: ZoneConfig, qname: str) -> List[dict]:
        qname_l = qname.lower()
        recs = [
            {"type": "MX", "name": qname, "ttl": r.ttl,
             "priority": r.priority, "target": r.target}
            for r in zone.mx_records if r.name.lower() == qname_l
        ]
        return sorted(recs, key=lambda x: x["priority"])

    def _resolve_txt(self, zone: ZoneConfig, qname: str) -> List[dict]:
        qname_l = qname.lower()
        return [
            {"type": "TXT", "name": qname, "ttl": r.ttl, "text": r.text}
            for r in zone.txt_records if r.name.lower() == qname_l
        ]

    def _resolve_ns(self, zone: ZoneConfig, qname: str) -> List[dict]:
        # NS records are only served at the zone apex
        if qname.lower() == zone.name.lower():
            return [
                {"type": "NS", "name": qname, "ttl": zone.ttl, "target": ns.name}
                for ns in zone.nameservers
            ]
        return []

    def _resolve_soa(self, zone: ZoneConfig, qname: str) -> List[dict]:
        if zone.soa and qname.lower() == zone.name.lower():
            return [{"type": "SOA", "name": qname, "ttl": zone.ttl, "soa": zone.soa}]
        return []

    def _resolve_any(self, zone: ZoneConfig, qname: str) -> List[dict]:
        """Collect every record type for an ANY query."""
        results: List[dict] = []
        for fn in (self._resolve_a, self._resolve_aaaa, self._resolve_cname,
                   self._resolve_mx, self._resolve_txt,
                   self._resolve_ns, self._resolve_soa):
            results.extend(fn(zone, qname))
        return results


# ═════════════════════════════════════════════════════════════
#  Raw DNS response assembly
# ═════════════════════════════════════════════════════════════

def _build_response(msg_id: int, original_flags: int,
                    qname: str, qtype: int,
                    records: List[dict], z_value: int) -> bytes:
    """
    Build a full DNS response packet.
    Sets QR=1, AA=1, preserves RD, clears RCODE, injects Z-value.
    """
    # QR=1 AA=1; preserve RD from query; clear RCODE and Z bits
    flags = (original_flags | 0x8400) & 0xFFF0
    flags &= 0xFF8F                          # clear Z bits
    flags |= ((z_value & 0x07) << 4)        # set Z value

    qname_enc = encode_dns_name(qname)
    question  = qname_enc + struct.pack("!HH", qtype, 1)   # qtype, IN

    answer_bytes = b"".join(
        rr for rec in records for rr in [_build_rr(rec)] if rr is not None
    )

    header = struct.pack("!HHHHHH",
                         msg_id, flags,
                         1,            # QDCOUNT
                         len(records), # ANCOUNT
                         0, 0)
    return header + question + answer_bytes


def _make_error(msg_id: int, original_flags: int, rcode: int,
                qname: str = "", qtype: int = 1) -> bytes:
    """Minimal error response: REFUSED (5), NXDOMAIN (3), NOTIMP (4)."""
    flags = (original_flags | 0x8000) & 0xFFF0
    flags |= (rcode & 0x0F)
    qdcount = 1 if qname else 0
    header  = struct.pack("!HHHHHH", msg_id, flags, qdcount, 0, 0, 0)
    if qname:
        question = encode_dns_name(qname) + struct.pack("!HH", qtype, 1)
        return header + question
    return header


def _build_rr(rec: dict) -> Optional[bytes]:
    """Build one DNS resource record (wire format) from a record dict."""
    rtype_str = rec.get("type", "A")
    rtype     = QTYPE_MAP.get(rtype_str, 1)
    name_enc  = encode_dns_name(rec.get("name", "."))
    ttl       = rec.get("ttl", 300)
    rclass    = 1   # IN

    try:
        if rtype_str == "A":
            rdata = socket.inet_aton(rec["ip"])
            return name_enc + struct.pack("!HHiH", rtype, rclass, ttl, 4) + rdata

        if rtype_str == "AAAA":
            rdata = socket.inet_pton(socket.AF_INET6, rec["ip"])
            return name_enc + struct.pack("!HHiH", rtype, rclass, ttl, 16) + rdata

        if rtype_str == "CNAME":
            rdata = encode_dns_name(rec["target"])
            return name_enc + struct.pack("!HHiH", rtype, rclass, ttl, len(rdata)) + rdata

        if rtype_str == "NS":
            rdata = encode_dns_name(rec["target"])
            return name_enc + struct.pack("!HHiH", rtype, rclass, ttl, len(rdata)) + rdata

        if rtype_str == "MX":
            target_enc = encode_dns_name(rec["target"])
            rdata = struct.pack("!H", rec.get("priority", 10)) + target_enc
            return name_enc + struct.pack("!HHiH", rtype, rclass, ttl, len(rdata)) + rdata

        if rtype_str == "TXT":
            raw   = rec.get("text", "").encode()
            # TXT RDATA: each string is length-prefixed (max 255 bytes per chunk)
            chunks = [raw[i:i + 255] for i in range(0, max(1, len(raw)), 255)]
            rdata  = b"".join(bytes([len(c)]) + c for c in chunks)
            return name_enc + struct.pack("!HHiH", rtype, rclass, ttl, len(rdata)) + rdata

        if rtype_str == "SOA":
            soa   = rec["soa"]
            rdata = (encode_dns_name(soa.primary) +
                     encode_dns_name(soa.admin) +
                     struct.pack("!IIIII",
                                 soa.serial, soa.refresh,
                                 soa.retry,  soa.expire, soa.minimum))
            return name_enc + struct.pack("!HHiH", rtype, rclass, ttl, len(rdata)) + rdata

    except Exception:
        return None

    return None


# ═════════════════════════════════════════════════════════════
#  Self-test
# ═════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=== ZoneSystem self-test ===\n")

    zs = ZoneSystem.simple("timeserversync.com.", "127.0.0.1")

    zone = zs.find_zone("www.timeserversync.com.")
    print(f"Zone found for www.timeserversync.com.: {zone.name}")

    zone2 = zs.find_zone("sub.timeserversync.com.")
    print(f"Zone found for sub.timeserversync.com.: {zone2.name}")

    print(f"Is authoritative for 'other.com.': {zs.is_authoritative('other.com.')}")

    errors = zs.validate_all()
    if errors:
        print(f"Consistency errors:\n" + "\n".join(errors))
    else:
        print("Zone consistency: OK")

    # Build a test A response
    resp = zs.build_response("www.timeserversync.com.", 1, 12345, 0x0100, z_value=2)
    z_extracted = (struct.unpack_from("!H", resp, 2)[0] >> 4) & 0x07
    print(f"\nA response bytes: {len(resp)}, Z-value in response: {z_extracted}")
    assert z_extracted == 2, "Z injection failed"

    # REFUSED for non-authoritative
    refused = zs.build_response("example.com.", 1, 99, 0x0100, z_value=0)
    rcode   = struct.unpack_from("!H", refused, 2)[0] & 0x0F
    print(f"Non-authoritative → RCODE={rcode} (expected 5)")
    assert rcode == 5

    print("\n✅ All assertions passed.")
