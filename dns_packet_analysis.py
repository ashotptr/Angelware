"""
====================================================
 AUA CS 232/337 — Botnet Research Project
 Component: DNS Packet Analysis Pipeline
 Environment: ISOLATED VM LAB ONLY
====================================================

Mirrors Spinnekop:
  internal/parser/models.go    (ParsedPacket, HeaderAnalysis,
                                QuestionAnalysis, PacketAnalysis)
  internal/parser/parser.go    (DNSParser.ParsePacket, analyzeHeader,
                                analyzeQuestion, analyzePacket)
  internal/parser/helpers.go   (PrintAnalysis, helper converters)

The analysis pipeline has four stages:
  1. Parse raw bytes → structured dict (via dns_zflag_crafter)
  2. Analyze header  → HeaderAnalysis  (Z-value, derived flags, counts)
  3. Analyze question → QuestionAnalysis (FQDN, wildcard, class, labels)
  4. High-level analysis → PacketAnalysis
       - RFC-compliance check (Z-flag, AA/RA in queries)
       - Non-standard class detection
       - EDNS OPT record detection
       - Domain structural validation
       - Authoritative zone check (requires ZoneSystem)
       - Issue + Warning lists

Usage:
  from dns_packet_analysis import DNSPacketAnalyzer
  from dns_zone_system import ZoneSystem

  zs       = ZoneSystem.simple("timeserversync.com.", "127.0.0.1")
  analyzer = DNSPacketAnalyzer(zone_system=zs)
  result   = analyzer.analyze(raw_bytes, client_ip)

  if result.valid:
      print(result.header.z, result.header.has_non_zero_z)
      print(result.question.is_fqdn)
      print(result.analysis.warnings)

  DNSPacketAnalyzer.print_analysis(result)   # full human-readable dump
"""

import os
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dns_zflag_crafter import (
    Z_COMMAND_MAP, QTYPE_MAP, QTYPE_REVERSE, QCLASS_REVERSE,
    read_z_flag, read_header, parse_dns_packet,
)


# ═════════════════════════════════════════════════════════════
#  Data classes
#  Mirror Spinnekop internal/parser/models.go
# ═════════════════════════════════════════════════════════════

@dataclass
class HeaderAnalysis:
    """
    Detailed DNS header field analysis.
    Mirrors Spinnekop parser.HeaderAnalysis.
    """
    id:               int
    qr:               bool
    qr_string:        str   # "Query" | "Response"
    opcode:           int
    opcode_string:    str
    aa:               bool
    tc:               bool
    rd:               bool
    ra:               bool
    z:                int   # Raw 3-bit Z-value (0-7)
    z_command:        str   # Human-readable Z command name
    rcode:            int
    rcode_string:     str
    question_count:   int
    answer_count:     int
    authority_count:  int
    additional_count: int
    # Derived flags
    is_query:             bool = False
    is_response:          bool = False
    is_standard_query:    bool = False   # is_query AND opcode == QUERY(0)
    has_non_zero_z:       bool = False   # primary Spinnekop indicator
    is_recursion_desired: bool = False


@dataclass
class QuestionAnalysis:
    """
    Detailed DNS question section analysis.
    Mirrors Spinnekop parser.QuestionAnalysis.
    """
    name:          str
    qtype:         int
    qtype_string:  str
    qclass:        int
    qclass_string: str
    # Derived
    is_valid_domain:   bool = False   # structural label/length checks
    is_fqdn:           bool = False   # ends with "."
    domain_labels:     List[str] = field(default_factory=list)
    is_wildcard:       bool = False   # first label == "*"
    is_standard_class: bool = True    # class == IN (1)


@dataclass
class PacketAnalysis:
    """
    High-level packet analysis.
    Mirrors Spinnekop parser.PacketAnalysis.
    """
    packet_type:         str    # STANDARD_QUERY | QUERY_OPCODE_N | RESPONSE | MALFORMED
    is_well_formed:      bool   # no issues
    is_standard:         bool   # no RFC violations
    has_edns:            bool   # OPT record found in additional section
    supported_by_server: bool   # authoritative zone found
    issues:              List[str] = field(default_factory=list)
    warnings:            List[str] = field(default_factory=list)


@dataclass
class ParsedPacket:
    """
    Fully analyzed DNS packet — the top-level result object.
    Mirrors Spinnekop parser.ParsedPacket.
    """
    raw_data:    bytes
    size:        int
    received_at: datetime
    client_addr: str
    valid:       bool
    error:       Optional[str]           = None
    header:      Optional[HeaderAnalysis]   = None
    question:    Optional[QuestionAnalysis] = None
    analysis:    Optional[PacketAnalysis]   = None


# ═════════════════════════════════════════════════════════════
#  DNSPacketAnalyzer
#  Mirrors Spinnekop internal/parser/parser.go DNSParser
# ═════════════════════════════════════════════════════════════

class DNSPacketAnalyzer:
    """
    Full four-stage DNS packet analysis pipeline.

    Stage 1: Parse raw bytes using dns_zflag_crafter.parse_dns_packet()
    Stage 2: Analyze header — all flags, Z-value, derived flags
    Stage 3: Analyze question — domain labels, FQDN check, class
    Stage 4: High-level analysis — RFC violations, EDNS, zone authority
    """

    def __init__(self, zone_system=None):
        """
        zone_system: optional ZoneSystem for authoritative zone lookup.
        If None, supported_by_server is always False (zone check skipped).
        """
        self._zones = zone_system

    # ── Entry point ───────────────────────────────────────────

    def analyze(self, raw_data: bytes,
                client_addr: str = "") -> ParsedPacket:
        """
        Full analysis pipeline. Mirrors DNSParser.ParsePacket().
        Returns a ParsedPacket whether or not the packet is valid.
        """
        result = ParsedPacket(
            raw_data    = raw_data,
            size        = len(raw_data),
            received_at = datetime.now(),
            client_addr = client_addr,
            valid       = False,
        )

        # Minimum size check
        if len(raw_data) < 12:
            result.error = (
                f"Packet too short: {len(raw_data)} bytes "
                f"(DNS minimum header is 12 bytes)"
            )
            result.analysis = PacketAnalysis(
                packet_type="MALFORMED", is_well_formed=False,
                is_standard=False, has_edns=False,
                supported_by_server=False, issues=[result.error],
            )
            return result

        # Stage 1: Parse
        parsed = parse_dns_packet(raw_data)
        if "error" in parsed:
            result.error = parsed["error"]
            result.analysis = PacketAnalysis(
                packet_type="MALFORMED", is_well_formed=False,
                is_standard=False, has_edns=False,
                supported_by_server=False, issues=[result.error],
            )
            return result

        result.valid = True
        hdr_raw  = parsed.get("header",    {})
        questions = parsed.get("questions", [])
        answers   = parsed.get("answers",   [])

        # Stage 2: Header analysis
        result.header = self._analyze_header(raw_data, hdr_raw)

        # Stage 3: Question analysis
        if questions:
            result.question = self._analyze_question(questions[0])

        # Stage 4: High-level analysis
        result.analysis = self._analyze_packet(
            raw_data, result.header, result.question, answers
        )

        return result

    # ── Stage 2 ───────────────────────────────────────────────

    def _analyze_header(self, raw_data: bytes,
                        hdr: dict) -> HeaderAnalysis:
        """
        Detailed header analysis.
        Z-value is extracted from raw bytes because dns_zflag_crafter
        already exposes it, and the standard library hides it.
        Mirrors Spinnekop DNSParser.analyzeHeader().
        """
        z_val = read_z_flag(raw_data)

        analysis = HeaderAnalysis(
            id               = hdr.get("id",    0),
            qr               = bool(hdr.get("qr", False)),
            qr_string        = "Response" if hdr.get("qr") else "Query",
            opcode           = hdr.get("opcode",  0),
            opcode_string    = hdr.get("opcode_str", "QUERY"),
            aa               = bool(hdr.get("aa", False)),
            tc               = bool(hdr.get("tc", False)),
            rd               = bool(hdr.get("rd", False)),
            ra               = bool(hdr.get("ra", False)),
            z                = z_val,
            z_command        = Z_COMMAND_MAP.get(z_val, f"RESERVED({z_val})"),
            rcode            = hdr.get("rcode",  0),
            rcode_string     = hdr.get("rcode_str", "NOERROR"),
            question_count   = hdr.get("qdcount", 0),
            answer_count     = hdr.get("ancount", 0),
            authority_count  = hdr.get("nscount", 0),
            additional_count = hdr.get("arcount", 0),
        )

        # Derived flags
        analysis.is_query           = not analysis.qr
        analysis.is_response        = analysis.qr
        analysis.is_standard_query  = (analysis.is_query and
                                       analysis.opcode == 0)
        analysis.has_non_zero_z     = z_val != 0
        analysis.is_recursion_desired = analysis.rd

        return analysis

    # ── Stage 3 ───────────────────────────────────────────────

    def _analyze_question(self, q: dict) -> QuestionAnalysis:
        """
        Detailed question section analysis.
        Mirrors Spinnekop DNSParser.analyzeQuestion().
        """
        name   = q.get("name",   "")
        qtype  = q.get("qtype",   1)
        qclass = q.get("qclass",  1)
        labels = [l for l in name.rstrip(".").split(".") if l]

        analysis = QuestionAnalysis(
            name         = name,
            qtype        = qtype,
            qtype_string = q.get("qtype_str",  str(qtype)),
            qclass       = qclass,
            qclass_string= q.get("qclass_str", str(qclass)),
        )

        analysis.is_fqdn          = name.endswith(".")
        analysis.domain_labels    = labels
        analysis.is_wildcard      = bool(labels) and labels[0] == "*"
        analysis.is_valid_domain  = self._is_valid_domain(name)
        analysis.is_standard_class = (qclass == 1)  # IN class

        return analysis

    # ── Stage 4 ───────────────────────────────────────────────

    def _analyze_packet(self, raw_data: bytes,
                         header:   Optional[HeaderAnalysis],
                         question: Optional[QuestionAnalysis],
                         answers:  list) -> PacketAnalysis:
        """
        High-level packet analysis.
        Populates issues (hard problems) and warnings (RFC deviations).
        Mirrors Spinnekop DNSParser.analyzePacket().
        """
        issues:   List[str] = []
        warnings: List[str] = []
        is_standard = True

        # ── Packet type ───────────────────────────────────────
        if header and header.is_query:
            pkt_type = ("STANDARD_QUERY" if header.is_standard_query
                        else f"QUERY_OPCODE_{header.opcode}")
        else:
            pkt_type = "RESPONSE"

        # ── RFC 1035 Z-bit violation ──────────────────────────
        if header and header.has_non_zero_z:
            is_standard = False
            warnings.append(
                f"Non-zero Z flag: {header.z} ({header.z_command}) — "
                f"RFC 1035 §4.1.1 requires Z bits be zero in all messages"
            )

        # ── RA set in query ───────────────────────────────────
        if header and header.is_query and header.ra:
            warnings.append(
                "RA (Recursion Available) set in query — "
                "RFC 1035 §4.1.1: RA is only meaningful in responses"
            )

        # ── AA set in query ───────────────────────────────────
        if header and header.is_query and header.aa:
            warnings.append(
                "AA (Authoritative Answer) set in query — "
                "RFC 1035 §4.1.1: AA is only set by authoritative servers"
            )

        # ── Non-standard class ────────────────────────────────
        if question and not question.is_standard_class:
            is_standard = False
            warnings.append(
                f"Non-standard DNS class: {question.qclass_string} "
                f"({question.qclass}) — RFC 1035 expects IN (1) for "
                f"internet queries. Possible covert channel or class abuse."
            )

        # ── Domain structural validity ────────────────────────
        if question and not question.is_valid_domain:
            issues.append(
                f"Domain '{question.name}' fails structural validation "
                f"(label too long, total length > 253, or empty label)"
            )

        # ── FQDN check ────────────────────────────────────────
        if question and not question.is_fqdn:
            warnings.append(
                f"'{question.name}' is not fully qualified — "
                f"should end with '.' (trailing dot)"
            )

        # ── Wildcard query ────────────────────────────────────
        if question and question.is_wildcard:
            warnings.append(f"Wildcard query detected: {question.name}")

        # ── EDNS OPT record detection ─────────────────────────
        has_edns = self._detect_edns(raw_data, header)

        # ── Authoritative zone check ──────────────────────────
        supported = False
        if question and self._zones is not None:
            supported = self._zones.is_authoritative(question.name)
            if not supported:
                issues.append(
                    f"Server is not authoritative for domain: {question.name}"
                )
            # Check query type support
            if supported:
                supported_types = {
                    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "ANY"
                }
                if question.qtype_string.upper() not in supported_types:
                    issues.append(
                        f"Unsupported query type: {question.qtype_string}"
                    )

        return PacketAnalysis(
            packet_type         = pkt_type,
            is_well_formed      = len(issues) == 0,
            is_standard         = is_standard,
            has_edns            = has_edns,
            supported_by_server = supported,
            issues              = issues,
            warnings            = warnings,
        )

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _is_valid_domain(name: str) -> bool:
        """
        Basic domain name structural validation.
        Mirrors Spinnekop DNSParser.isValidDomainName().
        """
        if not name or name == ".":
            return True   # root domain is valid
        clean  = name.rstrip(".")
        labels = clean.split(".")
        for label in labels:
            if not label or len(label) > 63:
                return False
        return len(name) <= 253

    @staticmethod
    def _detect_edns(raw_data: bytes,
                     header: Optional[HeaderAnalysis]) -> bool:
        """
        Detect EDNS OPT record in the additional section.
        OPT type = 41 (0x0029).
        Mirrors Spinnekop analyzePacket() EDNS check.
        """
        if not header or header.additional_count == 0:
            return False
        # Scan for OPT type bytes in payload beyond the 12-byte header
        return b"\x00\x29" in raw_data[12:]

    # ── PrintAnalysis ─────────────────────────────────────────

    @staticmethod
    def print_analysis(result: ParsedPacket) -> None:
        """
        Full human-readable analysis output.
        Mirrors Spinnekop ParsedPacket.PrintAnalysis() in parser/helpers.go.
        """
        sep = "=" * 42
        print(f"\n{sep}")
        print("  DNS Packet Analysis")
        print(sep)
        print(f"  Size:      {result.size} bytes")
        print(f"  Client:    {result.client_addr or '(unknown)'}")
        print(f"  Received:  {result.received_at.isoformat()}")
        print(f"  Valid:     {result.valid}")

        if not result.valid:
            print(f"  Error:     {result.error}")
            print(sep)
            return

        if result.header:
            h = result.header
            print("\n  --- Header ---")
            print(f"  ID:       {h.id} (0x{h.id:04X})")
            print(f"  QR:       {int(h.qr)} ({h.qr_string})")
            print(f"  Opcode:   {h.opcode} ({h.opcode_string})")
            print(f"  AA:       {int(h.aa)}")
            print(f"  TC:       {int(h.tc)}")
            print(f"  RD:       {int(h.rd)} (Recursion Desired)")
            print(f"  RA:       {int(h.ra)} (Recursion Available)")
            z_note = f"  ⚠  {h.z_command}" if h.z != 0 else "  (compliant)"
            print(f"  Z:        {h.z}{z_note}")
            print(f"  RCODE:    {h.rcode} ({h.rcode_string})")
            print(f"  Counts:   Q={h.question_count} AN={h.answer_count} "
                  f"NS={h.authority_count} AR={h.additional_count}")
            print(f"  IsQuery:{h.is_query}  StdQuery:{h.is_standard_query}  "
                  f"NonZeroZ:{h.has_non_zero_z}  RD:{h.is_recursion_desired}")

        if result.question:
            q = result.question
            print("\n  --- Question ---")
            print(f"  Name:    {q.name}")
            print(f"  Type:    {q.qtype} ({q.qtype_string})")
            cls_warn = "" if q.is_standard_class else "  ⚠ Non-standard!"
            print(f"  Class:   {q.qclass} ({q.qclass_string}){cls_warn}")
            print(f"  FQDN:    {q.is_fqdn}   Valid: {q.is_valid_domain}   "
                  f"Wildcard: {q.is_wildcard}")
            print(f"  Labels:  {q.domain_labels}")

        if result.analysis:
            a = result.analysis
            print("\n  --- Analysis ---")
            print(f"  PacketType:   {a.packet_type}")
            print(f"  WellFormed:   {a.is_well_formed}")
            print(f"  RFCCompliant: {a.is_standard}")
            print(f"  EDNS:         {a.has_edns}")
            print(f"  Authoritative:{a.supported_by_server}")

            if a.issues:
                print(f"\n  🚨 Issues ({len(a.issues)}):")
                for issue in a.issues:
                    print(f"    • {issue}")
            if a.warnings:
                print(f"\n  ⚠  Warnings ({len(a.warnings)}):")
                for w in a.warnings:
                    print(f"    • {w}")

        print(sep + "\n")


# ═════════════════════════════════════════════════════════════
#  Self-test
# ═════════════════════════════════════════════════════════════

if __name__ == "__main__":
    from dns_zflag_crafter import build_dns_query, apply_z_flag
    from dns_zone_system import ZoneSystem

    print("=== DNSPacketAnalyzer self-test ===\n")

    zs       = ZoneSystem.simple("timeserversync.com.", "127.0.0.1")
    analyzer = DNSPacketAnalyzer(zone_system=zs)

    # Test 1: Normal A query (Z=0)
    pkt = bytearray(build_dns_query("www.timeserversync.com.", z_value=0))
    r   = analyzer.analyze(bytes(pkt), "192.168.1.1")
    print(f"Test 1 — Normal A query:")
    print(f"  valid={r.valid}  z={r.header.z}  has_non_zero_z={r.header.has_non_zero_z}")
    print(f"  is_standard={r.analysis.is_standard}  warnings={r.analysis.warnings}")
    assert r.valid and not r.header.has_non_zero_z and r.analysis.is_standard

    # Test 2: Suspicious Z=3 response
    pkt2 = bytearray(build_dns_query("www.timeserversync.com.", qr=True, z_value=0))
    apply_z_flag(pkt2, 3)
    r2   = analyzer.analyze(bytes(pkt2), "127.0.0.1")
    print(f"\nTest 2 — Z=3 (HTTP_MODE) response:")
    print(f"  z={r2.header.z}  z_command={r2.header.z_command}")
    print(f"  has_non_zero_z={r2.header.has_non_zero_z}")
    print(f"  warnings={r2.analysis.warnings}")
    assert r2.header.z == 3 and r2.header.has_non_zero_z
    assert not r2.analysis.is_standard

    # Test 3: Non-authoritative domain
    pkt3 = bytearray(build_dns_query("evil.com.", z_value=0))
    r3   = analyzer.analyze(bytes(pkt3), "10.0.0.1")
    print(f"\nTest 3 — Non-authoritative domain:")
    print(f"  supported_by_server={r3.analysis.supported_by_server}")
    print(f"  issues={r3.analysis.issues}")
    assert not r3.analysis.supported_by_server

    # Test 4: Too-short packet
    r4 = analyzer.analyze(b"\x00\x01\x02", "bad-client")
    print(f"\nTest 4 — Malformed short packet:")
    print(f"  valid={r4.valid}  error={r4.error}")
    assert not r4.valid

    print("\n✅ All assertions passed.\n")
    DNSPacketAnalyzer.print_analysis(r2)
