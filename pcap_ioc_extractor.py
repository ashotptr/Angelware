"""
====================================================
 Angelware — PCAP IOC Extractor
 Ported/adapted from: C2Detective (martinkubecka)
====================================================

Missing capability added to Angelware:
  C2Detective's core is offline analysis of .pcap/.cap/.pcapng files.
  It loads the capture with Scapy (rdpcap), extracts a rich set of IOCs,
  and feeds them to all detection engines.

  Angelware had packet_capture.py (live sniffing + wrpcap only) and
  scapy_tools.py (standalone Scapy tools). Neither performed deep IOC
  extraction from stored pcap files.

  This module provides all the extraction C2Detective performs:
    • Capture timestamps (start, end)
    • External TCP connections + 4-tuple frequency counts
    • Public source + destination IP address lists
    • Unique combined IP list
    • DNS packets + domain names from DNSQR
    • HTTP sessions (method, host, path, url, all headers)
    • TLS certificates (via tshark) — for c2_tls_cert_detector.py
    • JA3 digests (via ja3 CLI tool) — for tls_ja3.py
    • Capture SHA256 hash

Usage:
    extractor = PcapIOCExtractor("capture.pcap")
    print(extractor.domain_names)
    print(extractor.http_sessions)
    print(extractor.connection_frequency)
    data = extractor.as_dict()    # full serialisable dict

CLI:
    python3 pcap_ioc_extractor.py capture.pcap
    python3 pcap_ioc_extractor.py capture.pcap -o extracted_data.json
    python3 pcap_ioc_extractor.py capture.pcap --stats
"""

import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from ipaddress import ip_address
from time import perf_counter
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Lazy Scapy import (avoid slow import at module level)
_scapy = None


def _get_scapy():
    global _scapy
    if _scapy is None:
        from scapy import all as s
        _scapy = s
    return _scapy


def _ts() -> str:
    return time.strftime("%H:%M:%S")


def _is_public(ip_str: str) -> bool:
    try:
        return not ip_address(ip_str).is_private
    except ValueError:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
#  PCAP IOC EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

class PcapIOCExtractor:
    """
    Load a pcap/cap/pcapng file and extract all IOCs needed by Angelware
    detectors.

    Attributes exposed (read-only after __init__):
      packets                list      all Scapy packets
      connections            dict      Scapy sessions() grouped by key
      start_time             str       %Y-%m-%d %H:%M:%S
      end_time               str
      connection_frequency   dict      {(src_ip,src_port,dst_ip,dst_port): count}
      external_tcp_connections list   [(ts, src_ip, src_port, dst_ip, dst_port)]
      public_src_ip_list     list
      public_dst_ip_list     list
      public_ip_list         list      combined src+dst
      src_unique_ip_list     list
      dst_unique_ip_list     list
      combined_unique_ip_list list
      src_ip_counter         Counter
      dst_ip_counter         Counter
      all_ip_counter         Counter
      dns_packets            list
      domain_names           list      unique FQDN strings
      http_sessions          list      [{timestamp, src_ip, …, http_headers}]
      http_payloads          list
      unique_urls            list
      certificates           list      [{src_ip, dst_ip, …, issuer, subject}]
      ja3_digests            list      [{timestamp, ja3, ja3_digest, …}]
      capture_sha256         str
      statistics             dict
    """

    def __init__(
        self,
        input_file: str,
        print_stats: bool = False,
        write_json:  Optional[str] = None,
    ):
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Capture file not found: {input_file}")
        self.input_file = input_file

        print(f"[{_ts()}] [INFO] Loading '{input_file}' …")
        t0 = perf_counter()
        sc = _get_scapy()
        self.packets = sc.rdpcap(input_file)
        t1 = perf_counter()
        print(f"[{_ts()}] [INFO] {len(self.packets)} packets loaded in {t1-t0:.2f}s")

        self.connections = self._get_connections()
        self._extract_all()
        self._count_ips()
        self.certificates  = self._extract_certificates()
        self.ja3_digests   = self._get_ja3_digests()
        self.capture_sha256 = self._sha256()
        self.statistics    = self._build_statistics()

        if print_stats:
            self.print_statistics()
        if write_json:
            self.write_json(write_json)

    # ── Internal extraction ───────────────────────────────────────────

    def _get_connections(self) -> Dict:
        t0 = perf_counter()
        conn = self.packets.sessions()
        t1   = perf_counter()
        print(f"[{_ts()}] [INFO] {len(conn)} connections grouped in {t1-t0:.2f}s")
        return conn

    def _extract_all(self):
        sc = _get_scapy()
        from scapy.layers import http as _http

        self.start_time              = None
        self.end_time                = None
        self.connection_frequency:   Dict[Tuple, int] = {}
        self.external_tcp_connections: List[Tuple]   = []
        self.public_src_ip_list:     List[str] = []
        self.public_dst_ip_list:     List[str] = []
        self.public_ip_list:         List[str] = []
        self.dns_packets:            List      = []
        domain_names_set:            Set[str]  = set()
        self.http_sessions:          List[Dict] = []
        self.http_payloads:          List       = []
        unique_urls_set:             Set[str]   = set()

        print(f"[{_ts()}] [INFO] Extracting IOCs from {len(self.packets)} packets …")

        for pkt in self.packets:
            pkt_time = datetime.fromtimestamp(
                round(float(pkt.time), 6)
            ).strftime("%Y-%m-%d %H:%M:%S")

            if self.start_time is None:
                self.start_time = pkt_time

            if pkt.haslayer(sc.IP):
                src_ip = pkt[sc.IP].src
                dst_ip = pkt[sc.IP].dst

                if _is_public(src_ip):
                    self.public_src_ip_list.append(src_ip)
                    self.public_ip_list.append(src_ip)
                if _is_public(dst_ip):
                    self.public_dst_ip_list.append(dst_ip)
                    self.public_ip_list.append(dst_ip)

                if pkt.haslayer(sc.TCP):
                    src_port = pkt[sc.TCP].sport
                    dst_port = pkt[sc.TCP].dport

                    if _is_public(src_ip) or _is_public(dst_ip):
                        conn_key = (src_ip, src_port, dst_ip, dst_port)
                        self.connection_frequency[conn_key] = (
                            self.connection_frequency.get(conn_key, 0) + 1
                        )
                        self.external_tcp_connections.append(
                            (pkt_time, src_ip, src_port, dst_ip, dst_port)
                        )

            if pkt.haslayer(sc.DNS):
                self.dns_packets.append(pkt)

            if pkt.haslayer(sc.DNSQR):
                try:
                    raw_q = pkt[sc.DNSQR].qname.decode("utf-8")
                    fqdn  = raw_q.rstrip(".")
                    domain_names_set.add(fqdn)
                except UnicodeDecodeError:
                    pass

            if pkt.haslayer("HTTPRequest") or pkt.haslayer("HTTPResponse"):
                sess = self._parse_http_packet(pkt, pkt_time, _http,
                                               domain_names_set, unique_urls_set)
                if sess:
                    self.http_sessions.append(sess)
                if pkt.haslayer("Raw"):
                    self.http_payloads.append(pkt["Raw"].load)

            self.end_time = pkt_time

        self.domain_names = list(domain_names_set)
        self.unique_urls  = list(unique_urls_set)

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_http_packet(pkt, pkt_time, http_mod, domain_names_set, unique_urls_set) -> Optional[Dict]:
        sc = _get_scapy()
        try:
            src_ip   = pkt[sc.IP].src
            src_port = pkt[sc.IP].sport
            dst_ip   = pkt[sc.IP].dst
            dst_port = pkt[sc.IP].dport
        except Exception:
            return None

        headers = (
            pkt.getlayer("HTTPRequest").fields
            if pkt.haslayer("HTTPRequest")
            else pkt.getlayer("HTTPResponse").fields
        )
        headers = _bytes_to_str(headers)

        method = host = path = url = ""
        req = pkt.getlayer(http_mod.HTTPRequest)
        if req:
            method = _decode_bytes(req.fields.get("Method"))
            host   = _decode_bytes(req.fields.get("Host"))
            path   = _decode_bytes(req.fields.get("Path"))
            if host:
                domain_names_set.add(host)
                url = f"{host}{path}"
                unique_urls_set.add(url)

        return {
            "timestamp":    pkt_time,
            "src_ip":       src_ip,
            "src_port":     src_port,
            "dst_ip":       dst_ip,
            "dst_port":     dst_port,
            "method":       method,
            "url":          url,
            "path":         path,
            "http_headers": headers,
        }

    # ------------------------------------------------------------------
    def _count_ips(self):
        self.src_unique_ip_list      = list(set(self.public_src_ip_list))
        self.dst_unique_ip_list      = list(set(self.public_dst_ip_list))
        self.combined_unique_ip_list = list(set(self.public_ip_list))
        self.src_ip_counter          = Counter(self.public_src_ip_list)
        self.dst_ip_counter          = Counter(self.public_dst_ip_list)
        self.all_ip_counter          = Counter(self.public_ip_list)

    # ------------------------------------------------------------------
    def _extract_certificates(self) -> List[Dict]:
        """Extract TLS certificate fields via tshark."""
        print(f"[{_ts()}] [INFO] Extracting TLS certificates via tshark …")
        # Import the C2 cert detector's tshark parser
        try:
            _here = os.path.dirname(os.path.realpath(__file__))
            sys.path.insert(0, _here)
            from c2_tls_cert_detector import C2CertDetector
            detector = C2CertDetector()
            return detector._extract_via_tshark(self.input_file)
        except Exception as e:
            logger.warning("TLS certificate extraction failed: %s", e)
            print(f"[{_ts()}] [WARNING] TLS cert extraction unavailable: {e}")
            return []

    # ------------------------------------------------------------------
    def _get_ja3_digests(self) -> List[Dict]:
        """Extract JA3 fingerprints via the ja3 CLI tool."""
        digests = []
        try:
            cmd    = f"ja3 --json --any_port {self.input_file}"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
            raw    = json.loads(output)
            for item in raw:
                ts = datetime.fromtimestamp(
                    round(item["timestamp"], 6)
                ).strftime("%Y-%m-%d %H:%M:%S")
                item["timestamp"] = ts
            digests = raw
            print(f"[{_ts()}] [INFO] {len(digests)} JA3 fingerprint(s) extracted")
        except Exception as e:
            logger.info("JA3 extraction skipped: %s", e)
            print(f"[{_ts()}] [INFO] JA3 extraction unavailable "
                  "(install pyja3 and ensure 'ja3' is in PATH)")
        return digests

    # ------------------------------------------------------------------
    def _sha256(self) -> str:
        h = hashlib.sha256()
        with open(self.input_file, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    # ------------------------------------------------------------------
    def _build_statistics(self) -> Dict:
        return {
            "filepath":                          self.input_file,
            "capture_sha256":                    self.capture_sha256,
            "capture_start_time":                self.start_time,
            "capture_end_time":                  self.end_time,
            "total_packets":                     len(self.packets),
            "number_of_external_tcp_connections": len(self.external_tcp_connections),
            "number_of_unique_domain_names":     len(self.domain_names),
            "number_of_unique_public_ips":       len(self.combined_unique_ip_list),
            "number_of_http_sessions":           len(self.http_sessions),
            "number_of_extracted_urls":          len(self.unique_urls),
            "number_of_tls_certificates":        len(self.certificates),
            "number_of_ja3_fingerprints":        len(self.ja3_digests),
        }

    # ── Public helpers ────────────────────────────────────────────────

    def print_statistics(self):
        print("\n" + "─" * 60)
        for key, val in self.statistics.items():
            print(f"  {key:<45} {val}")
        print("─" * 60 + "\n")

    def as_dict(self) -> Dict:
        """Return a fully serialisable dict of all extracted data."""
        return {
            **self.statistics,
            "extracted_domains":   self.domain_names,
            "extracted_urls":      self.unique_urls,
            "public_src_ips":      self.src_unique_ip_list,
            "public_dst_ips":      self.dst_unique_ip_list,
            "combined_public_ips": self.combined_unique_ip_list,
            "http_sessions":       self.http_sessions,
            "tls_certificates":    self.certificates,
            "ja3_fingerprints":    self.ja3_digests,
        }

    def write_json(self, path: str):
        print(f"[{_ts()}] [INFO] Writing extracted data to '{path}' …")
        with open(path, "w") as fh:
            json.dump(self.as_dict(), fh, indent=4, default=str)


# ── Utility functions ─────────────────────────────────────────────────────────

def _decode_bytes(val) -> str:
    if val is None:
        return ""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val)


def _bytes_to_str(obj):
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {_bytes_to_str(k): _bytes_to_str(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_bytes_to_str(i) for i in obj]
    return obj


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        prog="pcap_ioc_extractor",
        description="PCAP IOC Extractor — Angelware add-on (C2Detective port)"
    )
    ap.add_argument("pcap",    metavar="FILE",
                    help="Input .pcap / .cap / .pcapng file")
    ap.add_argument("-o", "--output", metavar="FILE",
                    help="Write extracted data JSON to this file")
    ap.add_argument("-s", "--stats", action="store_true",
                    help="Print capture statistics")
    args = ap.parse_args()

    extractor = PcapIOCExtractor(
        args.pcap,
        print_stats=args.stats,
        write_json=args.output,
    )

    if not args.stats and not args.output:
        extractor.print_statistics()
        print(f"Domain names ({len(extractor.domain_names)}):")
        for d in extractor.domain_names[:20]:
            print(f"  {d}")
        if len(extractor.domain_names) > 20:
            print(f"  … and {len(extractor.domain_names)-20} more")


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
