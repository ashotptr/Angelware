"""
====================================================
 AUA CS 232/337 — Botnet Research Project
 Component: Interactive PCAP Analyzer TUI
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching points implemented here (from Spinnekop cmd/analyzer/):

This is a Python curses port of Spinnekop's termbox-go TUI.
It provides the same two-view interface:

1. PACKET LIST VIEW
   ┌──────────────────────────────────────────────────────────┐
   │Source IP         Dest IP           Type    Record  Size  │
   │──────────────────────────────────────────────────────────│
   │192.168.100.11    192.168.100.10    Query   A       45    │
   │192.168.100.10    192.168.100.11    Response A      89 ⚠  │ ← Z!=0
   └──────────────────────────────────────────────────────────┘
   Navigation: ↑/↓ scroll, Enter view detail, q quit

2. PACKET DETAIL VIEW
   Full header analysis with:
   - Z-value highlighted in red if non-zero (⚠ WARNING)
   - RDATA analysis for TXT records (Hex/Base64/Capacity)
   - Non-standard class warnings
   - All standard DNS header fields

Detection signals highlighted:
  • Non-zero Z-flag (primary Spinnekop indicator)
  • Encoded subdomains (high entropy → Z=2 exfiltration)
  • TXT record RDATA with hex/base64 encoding
  • Non-standard query classes

Requirements:
  pip3 install scapy   (already in Angelware lab)

Usage:
  # Analyse an existing pcap:
  python3 dns_pcap_analyzer.py -pcap /tmp/lab_capture.pcap

  # With verbose output (no TUI — pipe-safe):
  python3 dns_pcap_analyzer.py -pcap capture.pcap --no-tui

  # Generate a test pcap for demo:
  python3 dns_pcap_analyzer.py --generate-test
"""

import curses
import math
import os
import struct
import sys
import time
from collections import Counter
from typing import List, Optional, Tuple, Dict

# ─── path bootstrap ──────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dns_zflag_crafter import (
    read_z_flag, read_header, parse_dns_packet,
    analyze_rdata, detect_hex, detect_base64,
    is_likely_encoded_subdomain, decode_subdomain_info, shannon_entropy,
    Z_COMMAND_MAP, QTYPE_MAP, QTYPE_REVERSE, QCLASS_REVERSE,
)


# ─────────────────────────────────────────────────────────────
#  DNS PACKET MODEL
# ─────────────────────────────────────────────────────────────

class DNSPacketRecord:
    """Parsed DNS packet record — equivalent to models.DNSPacket in Spinnekop."""

    def __init__(self, src_ip: str, dst_ip: str, raw: bytes):
        self.src_ip  = src_ip
        self.dst_ip  = dst_ip
        self.raw     = raw

        self.z_value     = read_z_flag(raw)
        self.parsed      = parse_dns_packet(raw)
        self.header      = self.parsed.get("header", {})
        self.questions   = self.parsed.get("questions", [])
        self.answers     = self.parsed.get("answers",   [])

        self.is_response = bool(self.header.get("qr", False))
        self.pkt_type    = "Response" if self.is_response else "Query"

        self.record_type = "Unknown"
        if self.questions:
            self.record_type = self.questions[0].get("qtype_str", "?")
        if self.is_response and self.answers:
            self.record_type = self.answers[0].get("rtype_str", self.record_type)

        # RDATA analysis for responses with TXT answers
        self.rdata_analysis: Optional[Dict] = None
        if self.is_response:
            for ans in self.answers:
                r = analyze_rdata(ans)
                if r:
                    self.rdata_analysis = r
                    break

        # Subdomain entropy analysis
        self.subdomain_alert = False
        self.subdomain_decoded = ""
        if self.questions:
            qname  = self.questions[0].get("name", "")
            parts  = qname.rstrip(".").split(".")
            if len(parts) >= 3:
                sub = parts[0]
                if is_likely_encoded_subdomain(sub):
                    self.subdomain_alert  = True
                    self.subdomain_decoded = decode_subdomain_info(sub)

        # Non-standard class
        self.non_std_class = any(
            q.get("non_std_class", False) for q in self.questions
        )

    def summary_line(self, width: int = 80) -> str:
        alert = " ⚠" if (self.z_value != 0 or self.subdomain_alert
                          or self.non_std_class) else ""
        ra = "RDATA" if self.rdata_analysis and self.rdata_analysis.get("alert") else ""
        return (f"{self.src_ip:<17} {self.dst_ip:<17} "
                f"{self.pkt_type:<8} {self.record_type:<7} {len(self.raw):<5}{alert} {ra}")[:width]


# ─────────────────────────────────────────────────────────────
#  PCAP READER (uses scapy or raw struct depending on availability)
# ─────────────────────────────────────────────────────────────

def read_pcap(filepath: str) -> List[DNSPacketRecord]:
    """
    Extract all DNS packets from a pcap file.
    Uses Scapy if available, falls back to raw pcap parsing.
    Mirrors Spinnekop internal/pcap/extractor.go ExtractDNSPackets().
    """
    packets = []

    try:
        from scapy.all import rdpcap, DNS, IP, IPv6, UDP
        raw_pkts = rdpcap(filepath)
        for pkt in raw_pkts:
            if pkt.haslayer(DNS) and pkt.haslayer(UDP):
                dns_bytes = bytes(pkt[DNS])
                src_ip = pkt[IP].src if pkt.haslayer(IP) else (
                    pkt[IPv6].src if pkt.haslayer(IPv6) else "?")
                dst_ip = pkt[IP].dst if pkt.haslayer(IP) else (
                    pkt[IPv6].dst if pkt.haslayer(IPv6) else "?")
                try:
                    rec = DNSPacketRecord(src_ip, dst_ip, dns_bytes)
                    packets.append(rec)
                except Exception:
                    pass
        return packets
    except ImportError:
        pass  # fall through to raw parser

    # Raw pcap parser (no scapy)
    with open(filepath, "rb") as f:
        magic = struct.unpack("<I", f.read(4))[0]
        if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
            raise ValueError("Not a valid pcap file")
        f.read(20)  # skip rest of global header

        while True:
            rec_hdr = f.read(16)
            if len(rec_hdr) < 16:
                break
            _, _, incl_len, _ = struct.unpack("<IIII", rec_hdr)
            raw = f.read(incl_len)
            if len(raw) < incl_len:
                break

            # Try to interpret as raw DNS (linktype=101 from our capture)
            # or skip IP/UDP headers for standard captures
            dns_bytes = _try_extract_dns(raw)
            if dns_bytes and len(dns_bytes) >= 12:
                try:
                    rec = DNSPacketRecord("?.?.?.?", "?.?.?.?", dns_bytes)
                    packets.append(rec)
                except Exception:
                    pass
    return packets


def _try_extract_dns(raw: bytes) -> Optional[bytes]:
    """Try to extract DNS payload from a raw ethernet/IP/UDP frame."""
    # Ethernet: 14 bytes; IP: variable; UDP: 8 bytes
    if len(raw) < 42:
        return None
    try:
        # Ethernet type
        eth_type = struct.unpack_from("!H", raw, 12)[0]
        if eth_type == 0x0800:  # IPv4
            ip_hdr_len = (raw[14] & 0x0F) * 4
            proto = raw[23]
            if proto == 17:  # UDP
                udp_offset = 14 + ip_hdr_len
                dns_offset = udp_offset + 8
                return raw[dns_offset:]
    except Exception:
        pass
    # Assume raw DNS (linktype 101)
    return raw


# ─────────────────────────────────────────────────────────────
#  TUI APPLICATION (curses)
#  Mirrors Spinnekop cmd/analyzer/ AppState + App struct
# ─────────────────────────────────────────────────────────────

COLOR_DEFAULT  = 0
COLOR_HEADER   = 1
COLOR_SELECTED = 2
COLOR_WARNING  = 3
COLOR_Z_ALERT  = 4
COLOR_CYAN     = 5
COLOR_INFO     = 6


def _init_colors() -> None:
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(COLOR_HEADER,   curses.COLOR_WHITE,  -1)
    curses.init_pair(COLOR_SELECTED, curses.COLOR_BLACK,  curses.COLOR_WHITE)
    curses.init_pair(COLOR_WARNING,  curses.COLOR_RED,    -1)
    curses.init_pair(COLOR_Z_ALERT,  curses.COLOR_YELLOW, -1)
    curses.init_pair(COLOR_CYAN,     curses.COLOR_CYAN,   -1)
    curses.init_pair(COLOR_INFO,     curses.COLOR_GREEN,  -1)


def _safe_addstr(win, y: int, x: int, text: str, attr: int = 0) -> None:
    """Write text to window, silently ignoring out-of-bounds errors."""
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    max_len = w - x - 1
    if max_len <= 0:
        return
    try:
        win.addstr(y, x, text[:max_len], attr)
    except curses.error:
        pass


class AnalyzerApp:
    """
    Two-state TUI application.
    State LIST: scrollable packet list.
    State DETAIL: full per-packet analysis view.
    Mirrors Spinnekop App struct with StateList / StateDetail.
    """

    STATE_LIST   = "list"
    STATE_DETAIL = "detail"

    def __init__(self, packets: List[DNSPacketRecord]):
        self.packets  = packets
        self.state    = self.STATE_LIST
        self.selected = 0
        self.offset   = 0
        self.current: Optional[DNSPacketRecord] = None

    def run(self, stdscr) -> None:
        _init_colors()
        curses.curs_set(0)
        stdscr.keypad(True)

        while True:
            stdscr.clear()
            h, w = stdscr.getmaxyx()

            if self.state == self.STATE_LIST:
                self._render_list(stdscr, h, w)
            else:
                self._render_detail(stdscr, h, w)

            stdscr.refresh()

            key = stdscr.getch()
            if self.state == self.STATE_LIST:
                should_exit = self._handle_list_key(key)
            else:
                should_exit = self._handle_detail_key(key)

            if should_exit:
                break

    # ── LIST VIEW ────────────────────────────────────────────

    def _render_list(self, win, h: int, w: int) -> None:
        # Header row
        hdr = f"{'Source IP':<17} {'Dest IP':<17} {'Type':<8} {'Record':<7} {'Size':<5}  {'Alerts'}"
        _safe_addstr(win, 0, 0, hdr[:w], curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        _safe_addstr(win, 1, 0, "─" * min(w - 1, 70), curses.color_pair(COLOR_HEADER))

        max_visible = max(1, h - 4)

        # Adjust scroll offset
        if self.selected < self.offset:
            self.offset = self.selected
        elif self.selected >= self.offset + max_visible:
            self.offset = self.selected - max_visible + 1

        for i in range(max_visible):
            idx = self.offset + i
            if idx >= len(self.packets):
                break
            pkt = self.packets[idx]

            # Build line
            alert_flags = []
            if pkt.z_value != 0:
                alert_flags.append(f"Z={pkt.z_value}")
            if pkt.subdomain_alert:
                alert_flags.append("ENUM")
            if pkt.non_std_class:
                alert_flags.append("CLASS")
            if pkt.rdata_analysis and pkt.rdata_analysis.get("alert"):
                alert_flags.append("RDATA")
            alert_str = " ".join(alert_flags)

            line = (f"{pkt.src_ip:<17} {pkt.dst_ip:<17} {pkt.pkt_type:<8} "
                    f"{pkt.record_type:<7} {len(pkt.raw):<5}  {alert_str}")

            attr = curses.color_pair(COLOR_DEFAULT)
            if idx == self.selected:
                attr = curses.color_pair(COLOR_SELECTED)
            elif alert_flags:
                attr = curses.color_pair(COLOR_WARNING)

            _safe_addstr(win, i + 2, 0, line[:w - 1], attr)

        # Status bar
        total_z = sum(1 for p in self.packets if p.z_value != 0)
        status = (f"  {len(self.packets)} packets  |  {total_z} Z-flag alerts  "
                  f"|  {self.selected + 1}/{len(self.packets)}  "
                  "  ↑/↓ Navigate  Enter Detail  q Quit")
        _safe_addstr(win, h - 1, 0, status[:w - 1],
                     curses.color_pair(COLOR_Z_ALERT))

    def _handle_list_key(self, key: int) -> bool:
        if key in (curses.KEY_UP, ord("k")):
            self.selected = max(0, self.selected - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            self.selected = min(len(self.packets) - 1, self.selected + 1)
        elif key in (curses.KEY_ENTER, ord("\n"), ord("\r")):
            if self.packets:
                self.current = self.packets[self.selected]
                self.state = self.STATE_DETAIL
        elif key in (ord("q"), ord("Q"), 27):  # ESC
            return True
        return False

    # ── DETAIL VIEW ──────────────────────────────────────────

    def _render_detail(self, win, h: int, w: int) -> None:
        if self.current is None:
            return
        pkt = self.current
        y   = 0

        # Title bar
        title = f"  DNS PACKET DETAIL  — #{self.selected + 1}/{len(self.packets)}"
        _safe_addstr(win, y, 0, title.center(min(w - 1, 70), "═"),
                     curses.color_pair(COLOR_CYAN) | curses.A_BOLD)
        y += 2

        # ── Packet info ────────────────────────
        _safe_addstr(win, y, 0, "📦 PACKET INFORMATION",
                     curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1
        _safe_addstr(win, y, 2,
                     f"Source: {pkt.src_ip}  →  Destination: {pkt.dst_ip}")
        y += 1
        _safe_addstr(win, y, 2,
                     f"Type: {pkt.pkt_type}  |  Record: {pkt.record_type}  |  Size: {len(pkt.raw)} bytes")
        y += 2

        # ── DNS Header ─────────────────────────
        _safe_addstr(win, y, 0, "🏷  DNS HEADER",
                     curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
        y += 1
        hdr = pkt.header
        _safe_addstr(win, y, 2, "├─────────────────────────────────")
        y += 1
        _safe_addstr(win, y, 2, f"├ ID:     {hdr.get('id', 0)}")
        y += 1
        qr_s = "Response" if hdr.get("qr") else "Query"
        _safe_addstr(win, y, 2, f"├ QR:     {int(bool(hdr.get('qr')))} ({qr_s})")
        y += 1
        _safe_addstr(win, y, 2, f"├ Opcode: {hdr.get('opcode',0)} ({hdr.get('opcode_str','?')})")
        y += 1
        _safe_addstr(win, y, 2, f"├ AA:     {int(bool(hdr.get('aa')))} (Authoritative: {'Yes' if hdr.get('aa') else 'No'})")
        y += 1
        _safe_addstr(win, y, 2, f"├ TC:     {int(bool(hdr.get('tc')))} (Truncated: {'Yes' if hdr.get('tc') else 'No'})")
        y += 1
        _safe_addstr(win, y, 2, f"├ RD:     {int(bool(hdr.get('rd')))} (Recursion Desired: {'Yes' if hdr.get('rd') else 'No'})")
        y += 1
        _safe_addstr(win, y, 2, f"├ RA:     {int(bool(hdr.get('ra')))} (Recursion Available: {'Yes' if hdr.get('ra') else 'No'})")
        y += 1

        # Z-value — highlighted red if non-zero
        z = pkt.z_value
        zcmd = Z_COMMAND_MAP.get(z, "?")
        z_attr = (curses.color_pair(COLOR_WARNING) | curses.A_BOLD
                  if z != 0 else curses.color_pair(COLOR_DEFAULT))
        _safe_addstr(win, y, 2,
                     f"├ Z:      {z} (Reserved — should be 0)  [{zcmd}]", z_attr)
        y += 1
        if z != 0:
            _safe_addstr(win, y, 2, f"├ ⚠  NON-ZERO Z-FLAG DETECTED — RFC 1035 VIOLATION",
                         curses.color_pair(COLOR_WARNING) | curses.A_BOLD)
            y += 1

        rcode = hdr.get("rcode", 0)
        _safe_addstr(win, y, 2, f"├ RCODE:  {rcode} ({hdr.get('rcode_str','?')})")
        y += 1
        _safe_addstr(win, y, 2, "├─────────────────────────────────")
        y += 1
        _safe_addstr(win, y, 2, f"├ Questions:  {hdr.get('qdcount',0)}")
        y += 1
        _safe_addstr(win, y, 2, f"├ Answers:    {hdr.get('ancount',0)}")
        y += 1
        _safe_addstr(win, y, 2, f"├ Authority:  {hdr.get('nscount',0)}")
        y += 1
        _safe_addstr(win, y, 2, f"├ Additional: {hdr.get('arcount',0)}")
        y += 1
        _safe_addstr(win, y, 2, "└─────────────────────────────────")
        y += 2

        if y >= h - 3:
            _safe_addstr(win, h - 1, 0, "  Press q to return...",
                         curses.color_pair(COLOR_Z_ALERT))
            return

        # ── RDATA Analysis ─────────────────────
        if pkt.rdata_analysis:
            _safe_addstr(win, y, 0, "🔍 RDATA ANALYSIS",
                         curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
            y += 1
            ra = pkt.rdata_analysis
            _safe_addstr(win, y, 2, "├─────────────────────────────────")
            y += 1
            hex_c = (curses.color_pair(COLOR_WARNING) | curses.A_BOLD
                     if ra["hex_detected"] else curses.color_pair(COLOR_DEFAULT))
            _safe_addstr(win, y, 2, f"├ HEX DETECTED:    {'TRUE ⚠' if ra['hex_detected'] else 'False'}", hex_c)
            y += 1
            b64_c = (curses.color_pair(COLOR_WARNING) | curses.A_BOLD
                     if ra["base64_detected"] else curses.color_pair(COLOR_DEFAULT))
            _safe_addstr(win, y, 2, f"├ BASE64 DETECTED: {'TRUE ⚠' if ra['base64_detected'] else 'False'}", b64_c)
            y += 1
            cap_c = (curses.color_pair(COLOR_WARNING) | curses.A_BOLD
                     if ra["capacity"] >= 90 else curses.color_pair(COLOR_DEFAULT))
            _safe_addstr(win, y, 2, f"├ Capacity:        {ra['capacity']:.1f}%", cap_c)
            y += 1
            _safe_addstr(win, y, 2, "└─────────────────────────────────")
            y += 2

        if y >= h - 3:
            _safe_addstr(win, h - 1, 0, "  Press q to return...",
                         curses.color_pair(COLOR_Z_ALERT))
            return

        # ── Question Section ────────────────────
        if pkt.questions:
            _safe_addstr(win, y, 0, "❓ QUESTION SECTION",
                         curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
            y += 1
            for i, q in enumerate(pkt.questions):
                if y >= h - 5:
                    break
                _safe_addstr(win, y, 2, f"{i+1}. Name:  {q.get('name','')}")
                y += 1
                _safe_addstr(win, y, 4, f"Type:  {q.get('qtype_str','?')} ({q.get('qtype',0)})")
                y += 1
                cls_str = q.get("qclass_str", "?")
                cls_val = q.get("qclass", 1)
                cls_attr = (curses.color_pair(COLOR_WARNING) | curses.A_BOLD
                            if q.get("non_std_class") else curses.color_pair(COLOR_DEFAULT))
                _safe_addstr(win, y, 4, f"Class: {cls_str} ({cls_val})"
                             + ("  ⚠ Non-standard!" if q.get("non_std_class") else ""),
                             cls_attr)
                y += 1

                # Subdomain entropy analysis
                qname = q.get("name", "")
                parts = qname.rstrip(".").split(".")
                if len(parts) >= 3:
                    sub = parts[0]
                    ent = shannon_entropy(sub)
                    if ent > 3.5:
                        _safe_addstr(win, y, 4,
                                     f"⚠ High-entropy subdomain: '{sub[:40]}' (H={ent:.2f})",
                                     curses.color_pair(COLOR_WARNING) | curses.A_BOLD)
                        y += 1
                    if is_likely_encoded_subdomain(sub) and y < h - 4:
                        decoded = decode_subdomain_info(sub)
                        _safe_addstr(win, y, 6,
                                     f"Decoded: {decoded[:60]}",
                                     curses.color_pair(COLOR_INFO))
                        y += 1
            y += 1

        # ── Answer Section ──────────────────────
        if pkt.answers and y < h - 5:
            _safe_addstr(win, y, 0,
                         f"✅ ANSWER SECTION ({len(pkt.answers)} records)",
                         curses.color_pair(COLOR_HEADER) | curses.A_BOLD)
            y += 1
            for i, ans in enumerate(pkt.answers):
                if y >= h - 4:
                    break
                line = (f"{i+1}. {ans.get('name','')}  {ans.get('ttl',0)}s  "
                        f"{ans.get('rtype_str','?')}  {ans.get('rdata','')[:50]}")
                _safe_addstr(win, y, 2, line)
                y += 1

        # Footer
        _safe_addstr(win, h - 1, 0,
                     "  q / Esc: return to list  |  ←/→: prev/next packet",
                     curses.color_pair(COLOR_Z_ALERT))

    def _handle_detail_key(self, key: int) -> bool:
        if key in (ord("q"), ord("Q"), 27, ord("\b")):
            self.state = self.STATE_LIST
        elif key in (curses.KEY_RIGHT, ord("n")):
            if self.selected < len(self.packets) - 1:
                self.selected += 1
                self.current = self.packets[self.selected]
        elif key in (curses.KEY_LEFT, ord("p")):
            if self.selected > 0:
                self.selected -= 1
                self.current = self.packets[self.selected]
        return False


# ─────────────────────────────────────────────────────────────
#  NON-TUI SUMMARY (pipe / redirect mode)
# ─────────────────────────────────────────────────────────────

def print_summary(packets: List[DNSPacketRecord]) -> None:
    """Print a text summary for pipe-safe / no-TUI mode."""
    print(f"\n{'='*60}")
    print(f"  DNS PCAP Analysis Summary — {len(packets)} packets")
    print(f"{'='*60}\n")

    queries   = [p for p in packets if not p.is_response]
    responses = [p for p in packets if p.is_response]
    z_alerts  = [p for p in responses if p.z_value != 0]
    rdata_al  = [p for p in responses if p.rdata_analysis and p.rdata_analysis.get("alert")]
    enum_al   = [p for p in packets  if p.subdomain_alert]

    print(f"  Queries:        {len(queries)}")
    print(f"  Responses:      {len(responses)}")
    print(f"  Z-flag alerts:  {len(z_alerts)}")
    print(f"  RDATA alerts:   {len(rdata_al)}")
    print(f"  Encoded subs:   {len(enum_al)}")

    if z_alerts:
        print(f"\n  ⚠  Z-Flag Anomalies:")
        z_dist: Counter = Counter()
        for p in z_alerts:
            z_dist[p.z_value] += 1
        for z, n in sorted(z_dist.items()):
            cmd = Z_COMMAND_MAP.get(z, "?")
            print(f"    Z={z} ({cmd:<12}): {n} packet(s)")

    if enum_al:
        print(f"\n  🔍 Encoded Subdomains (Z=2 exfiltration):")
        seen = set()
        for p in enum_al:
            q = p.questions[0] if p.questions else {}
            qname = q.get("name", "")
            sub   = qname.rstrip(".").split(".")[0]
            if sub not in seen:
                seen.add(sub)
                dec = decode_subdomain_info(sub)
                print(f"    {sub[:40]}…  →  {dec[:60]}")

    for p in z_alerts[:5]:
        print(f"\n  Packet: {p.src_ip} → {p.dst_ip}  Z={p.z_value} "
              f"({Z_COMMAND_MAP.get(p.z_value,'?')})")
        if p.questions:
            print(f"    Query: {p.questions[0].get('name', '')}")
        if p.rdata_analysis:
            ra = p.rdata_analysis
            print(f"    RDATA: hex={ra['hex_detected']} "
                  f"b64={ra['base64_detected']} "
                  f"cap={ra['capacity']:.1f}%")

    print()


# ─────────────────────────────────────────────────────────────
#  TEST PCAP GENERATOR
# ─────────────────────────────────────────────────────────────

def generate_test_pcap(path: str) -> None:
    """
    Generate a minimal test pcap with a mix of normal and suspicious
    DNS packets including non-zero Z-values and TXT RDATA exfiltration.
    """
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from dns_zflag_crafter import build_dns_query, apply_z_flag

    MAGIC       = 0xA1B2C3D4
    PCAP_HEADER = struct.pack("<IHHiIII", MAGIC, 2, 4, 0, 0, 65535, 101)

    def _pcap_record(data: bytes) -> bytes:
        ts = int(time.time())
        return struct.pack("<IIII", ts, 0, len(data), len(data)) + data

    pkts = []
    # Normal A query (Z=0)
    pkts.append(build_dns_query("www.timeserversync.com.", z_value=0))
    # Response Z=0
    r = bytearray(build_dns_query("www.timeserversync.com.", qr=True, z_value=0))
    pkts.append(bytes(r))
    # Suspicious response Z=2 (ENUMERATE)
    r2 = bytearray(build_dns_query("www.timeserversync.com.", qr=True, z_value=0))
    apply_z_flag(r2, 2)
    pkts.append(bytes(r2))
    # Encoded subdomain query (Z=2 exfiltration in progress)
    from dns_zflag_crafter import encode_system_info_for_subdomain, collect_system_info
    label = encode_system_info_for_subdomain(collect_system_info())
    pkts.append(build_dns_query(f"{label}.timeserversync.com.", z_value=0))
    # TXT record response with hex-encoded data
    hex_data = "48656c6c6f20576f726c64212048657820656e636f6465642064617461"
    pkts.append(build_dns_query(
        "data.timeserversync.com.", qtype="TXT", qr=True, z_value=0,
        answers=[{"name": "data.timeserversync.com.", "type": "TXT",
                  "class": "IN", "ttl": 300, "data": hex_data}]
    ))
    # Response with Z=7 (TERMINATE)
    r7 = bytearray(build_dns_query("www.timeserversync.com.", qr=True, z_value=0))
    apply_z_flag(r7, 7)
    pkts.append(bytes(r7))

    with open(path, "wb") as f:
        f.write(PCAP_HEADER)
        for p in pkts:
            f.write(_pcap_record(p))

    print(f"[test] Generated {len(pkts)}-packet test pcap → {path}")
    print("[test] Includes: Z=2 response, Z=7 TERMINATE, TXT hex RDATA, encoded subdomain")


# ─────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Interactive DNS PCAP Analyzer")
    ap.add_argument("-pcap",   "--pcap",  metavar="FILE",
                   help="Path to pcap file")
    ap.add_argument("--no-tui", action="store_true",
                   help="Text summary only (no interactive TUI)")
    ap.add_argument("--generate-test", metavar="PATH",
                   nargs="?", const="/tmp/test_dns.pcap",
                   help="Generate a test pcap file")
    args = ap.parse_args()

    if args.generate_test:
        generate_test_pcap(args.generate_test)
        if not args.pcap:
            args.pcap = args.generate_test

    if not args.pcap:
        ap.print_help()
        sys.exit(0)

    if not os.path.exists(args.pcap):
        print(f"[error] File not found: {args.pcap}")
        sys.exit(1)

    print(f"[analyzer] Loading {args.pcap}...")
    try:
        pkts = read_pcap(args.pcap)
    except Exception as e:
        print(f"[error] Could not read pcap: {e}")
        sys.exit(1)

    if not pkts:
        print("[analyzer] No DNS packets found in capture.")
        sys.exit(0)

    print(f"[analyzer] Loaded {len(pkts)} DNS packets.")

    if args.no_tui or not sys.stdout.isatty():
        print_summary(pkts)
    else:
        app = AnalyzerApp(pkts)
        try:
            curses.wrapper(app.run)
        except KeyboardInterrupt:
            pass
        finally:
            # Print quick summary after TUI exits
            print_summary(pkts)
