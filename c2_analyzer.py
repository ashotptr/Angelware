#!/usr/bin/env python3
"""
====================================================
 Angelware — c2_analyzer.py
 Full offline C2 detection (C2Detective feature set)
====================================================

This is the main entry point that gives Angelware everything
C2Detective provided, integrated as a new module alongside
the existing live-IDS and botnet-simulation components.

What this adds to Angelware (all 13 missing features):
  1. Offline .pcap/.cap/.pcapng analysis (PcapIOCExtractor)
  2. Tor node & exit node traffic detection (TorDetector)
  3. C2 TLS certificate field matching (C2CertDetector)
  4. DNS Tunneling via subdomain length (DnsTunnelDetector)
  5. Crypto/cryptojacking domain blocklist (CryptoDomainDetector)
  6. Unusual HTTP body size detection (BigHTTPBodyDetector)
  7. C2 beaconing frequency detection (BeaconingFrequencyDetector)
  8. Long TCP connection detection (LongConnectionDetector)
  9. External IOC enrichment — 6 services (IOCEnricher)
 10. C2 threat feed — Feodo Tracker, URLhaus, ThreatFox (C2ThreatFeed)
 11. Domain whitelist (DomainWhitelist)
 12. Aggregate detection scoring (DetectionScorer)
 13. HTML + PDF per-capture analysis report (PcapReportGenerator)

New additions ported from C2Detective (previously missing):
 14. Live packet capture → immediate offline analysis pipeline (-p flag)
 15. Proofpoint ET JA3 rules updater and cache (--update-ja3-rules flag)
 16. IOC cache staleness warnings at startup (mirrors C2Detective behaviour)

Usage:
  # First-time setup — update all threat intelligence caches:
  python3 c2_analyzer.py --update-all

  # Analyse a pcap file:
  python3 c2_analyzer.py -i capture.pcap
  python3 c2_analyzer.py -i capture.pcap -s          # print statistics
  python3 c2_analyzer.py -i capture.pcap -e          # enable enrichment
  python3 c2_analyzer.py -i capture.pcap --dga       # enable DGA detection
  python3 c2_analyzer.py -i capture.pcap --threat-feed
  python3 c2_analyzer.py -i capture.pcap -o reports/ --pdf

  # Live capture then analyse (NEW — from C2Detective -p flag):
  python3 c2_analyzer.py --packet-capture            # uses config sniffing section
  python3 c2_analyzer.py -p -s -e                    # capture + stats + enrich

  # Update specific caches:
  python3 c2_analyzer.py --update-tor
  python3 c2_analyzer.py --update-crypto
  python3 c2_analyzer.py --update-ja3-rules          # NEW
  python3 c2_analyzer.py --update-all                # includes JA3 rules now

Compatible with: Linux (requires tshark for TLS cert extraction;
  wkhtmltopdf for PDF; all optional — the tool degrades gracefully
  if any external tool is missing)
"""

import argparse
import json
import logging
import os
import sys
import time
import yaml
from datetime import datetime
from typing import Dict, List, Optional, Set

# ── Angelware add-on imports ──────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _HERE)

from pcap_ioc_extractor    import PcapIOCExtractor
from tor_detector           import TorDetector, TorUpdater
from c2_tls_cert_detector   import C2CertDetector
from dns_tunnel_detector    import DnsTunnelDetector, CryptoDomainDetector, CryptoDomainUpdater
from http_behavior_detector import BigHTTPBodyDetector, BeaconingFrequencyDetector, LongConnectionDetector
from ioc_enricher           import IOCEnricher
from c2_threat_feed         import C2ThreatFeed, C2FeedUpdater
from detection_scorer       import DetectionScorer, DomainWhitelist
from pcap_report            import PcapReportGenerator

# NEW: unified IOC updater (adds JA3 rules updater + staleness checks)
from c2_ioc_updater import (
    TorNodesUpdater, JA3RulesUpdater,
    warn_if_stale, print_status as _ioc_status,
    TOR_MAX_AGE_SEC, CRYPTO_MAX_AGE_SEC, JA3_MAX_AGE_SEC,
)

# Also import Angelware's existing JA3 detector
try:
    from tls_ja3 import JA3Detector, KNOWN_BAD_JA3
    _HAS_JA3_ENGINE = True
except ImportError:
    _HAS_JA3_ENGINE = False

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = os.path.join(_HERE, "config", "c2_analyzer.yml")


# ── Banner ────────────────────────────────────────────────────────────────────

def _banner():
    print(r"""
   ___  ___   ___         _
  / __||_  ) |   \  ___  | |_  ___  __  | |_  ___  _ _
 | (__ / /  | |) |/ -_) |  _|/ -_)/ _| |  _|/ _ \| '_|
  \___|/___| |___/ \___|  \__|\___|\__|  \__|\___/|_|

  Angelware — Offline C2 Detection (C2Detective feature set)
""")


def _ts() -> str:
    return time.strftime("%H:%M:%S")


# ── Config loader ─────────────────────────────────────────────────────────────

def _load_config(path: str) -> Dict:
    if not os.path.exists(path):
        print(f"[{_ts()}] [WARNING] Config not found at {path} — using defaults")
        return {}
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


# ── Staleness checks (NEW — mirrors C2Detective's startup warnings) ────────────

def _check_all_caches(cfg: Dict) -> None:
    """
    Warn if any IOC cache is stale before starting analysis.
    C2Detective warns about Tor (30 min), crypto (24 h), JA3 (24 h).
    Previously Angelware had no staleness checking at all.
    """
    fp = cfg.get("file_paths", {})

    def _abs(key, default):
        return os.path.join(_HERE, fp.get(key, default))

    warn_if_stale(
        _abs("tor_node_cache", "c2_iocs/tor_nodes.json"),
        TOR_MAX_AGE_SEC,
        "Tor node list",
        "--update-tor",
    )
    warn_if_stale(
        _abs("crypto_domain_cache", "c2_iocs/crypto_domains.json"),
        CRYPTO_MAX_AGE_SEC,
        "Crypto domain list",
        "--update-crypto",
    )
    warn_if_stale(
        _abs("ja3_rules_cache", "c2_iocs/ja3_rules.json"),
        JA3_MAX_AGE_SEC,
        "JA3 rules (Proofpoint ET)",
        "--update-ja3-rules",
    )


# ── Update helpers ─────────────────────────────────────────────────────────────

def _update_tor(cfg: Dict):
    fp    = cfg.get("file_paths", {})
    feeds = cfg.get("feeds", {})
    cache = os.path.join(_HERE, fp.get("tor_node_cache", "c2_iocs/tor_nodes.json"))
    TorNodesUpdater(
        cache_path=cache,
        all_nodes_url=feeds.get("tor_node_list"),
        exit_nodes_url=feeds.get("tor_exit_node_list"),
    ).update(force=True)


def _update_crypto(cfg: Dict):
    fp    = cfg.get("file_paths", {})
    feeds = cfg.get("feeds", {})
    cache = os.path.join(_HERE, fp.get("crypto_domain_cache", "c2_iocs/crypto_domains.json"))
    CryptoDomainUpdater(
        cache_path=cache,
        url=feeds.get("crypto_domains"),
    ).update(force=True)


def _update_ja3(cfg: Dict):
    """Update Proofpoint ET JA3 rules cache. NEW — was absent from Angelware."""
    fp    = cfg.get("file_paths", {})
    feeds = cfg.get("feeds", {})
    cache = os.path.join(_HERE, fp.get("ja3_rules_cache", "c2_iocs/ja3_rules.json"))
    JA3RulesUpdater(
        cache_path=cache,
        url=feeds.get("ja3_rules"),
    ).update(force=True)


def _update_threat_feed():
    C2FeedUpdater().update_all()


# ── Live packet capture (NEW — from C2Detective's -p / --packet-capture flag) ──

def _do_live_capture(cfg: Dict, output_dir: str) -> str:
    """
    Sniff packets on the configured interface for the configured timeout,
    write to a pcap file, and return the file path for analysis.

    Configuration comes from the 'sniffing' section of c2_analyzer.yml:
      sniffing:
        interface: enp0s3
        filter: ""          # optional BPF filter
        timeout: 120        # seconds
        filename: live_capture.pcap

    This mirrors C2Detective's PacketCapture class and the -p pipeline:
      PacketCapture(sniffing_cfg, output_dir).capture_packets() → filepath
    The existing Angelware packet_capture.py is a queue-based live IDS sniffer;
    this path writes to a pcap file and feeds it to offline analysis.
    """
    sniff_cfg = cfg.get("sniffing", {})
    iface     = sniff_cfg.get("interface", "enp0s3")
    filt      = sniff_cfg.get("filter", "")
    timeout   = int(sniff_cfg.get("timeout", 120))
    filename  = sniff_cfg.get("filename", "live_capture.pcap")

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)

    print(f"[{_ts()}] [INFO]  Capturing packets on '{iface}' for {timeout}s …")
    logging.info(f"Live capture on {iface} for {timeout}s → {output_path}")

    try:
        from scapy.all import sniff as scapy_sniff, wrpcap
    except ImportError:
        print(f"[{_ts()}] [ERROR] Scapy not installed — "
              "cannot perform live capture. Install with: pip3 install scapy")
        sys.exit(1)

    kwargs: dict = dict(iface=iface, timeout=timeout)
    if filt:
        kwargs["filter"] = filt

    packets = scapy_sniff(**kwargs)
    wrpcap(output_path, packets)
    print(f"[{_ts()}] [INFO]  Captured {len(packets)} packets → {output_path}")
    logging.info(f"Captured {len(packets)} packets to {output_path}")
    return output_path


# ── Main analysis pipeline ────────────────────────────────────────────────────

def analyse(
    input_file:          str,
    config:              Dict,
    output_dir:          str          = "reports",
    print_stats:         bool         = False,
    write_extracted:     bool         = True,
    enrich_iocs:         bool         = False,
    dga_detection:       bool         = False,
    threat_feed:         bool         = False,
    create_pdf:          bool         = False,
    quiet:               bool         = False,
):
    if not quiet:
        _banner()

    if not os.path.exists(input_file):
        print(f"[{_ts()}] [ERROR] File not found: {input_file}")
        sys.exit(1)

    # NEW: check IOC cache staleness before analysis
    _check_all_caches(config)

    thresholds = config.get("thresholds", {})
    fp         = config.get("file_paths", {})
    feeds      = config.get("feeds", {})

    def _path(key: str, default: str) -> str:
        return os.path.join(_HERE, fp.get(key, default))

    whitelist_path  = _path("domain_whitelist",     "config/domain_whitelist.txt")
    tor_cache       = _path("tor_node_cache",       "c2_iocs/tor_nodes.json")
    crypto_cache    = _path("crypto_domain_cache",  "c2_iocs/crypto_domains.json")
    cert_db         = _path("c2_tls_cert_db",       "c2_iocs/c2_tls_certificate_values.json")
    feed_db         = _path("c2_threat_feed_db",    "c2_iocs/c2_threat_feed.db")
    # NEW: path for Proofpoint ET JA3 rules cache
    ja3_rules_cache = _path("ja3_rules_cache",      "c2_iocs/ja3_rules.json")

    os.makedirs(output_dir, exist_ok=True)

    # ── Step 1: Extract IOCs from pcap ────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"[{_ts()}] [INFO] ── Step 1: PCAP IOC Extraction ──")
    extractor = PcapIOCExtractor(
        input_file,
        print_stats=print_stats,
        write_json=os.path.join(output_dir, "extracted_data.json") if write_extracted else None,
    )

    # ── Load whitelist ────────────────────────────────────────────────────────
    whitelist  = DomainWhitelist(whitelist_path)
    wl_domains = set(whitelist._entries)
    wl_ips:    Set[str] = set()

    # Filter domain names through whitelist
    clean_domains = whitelist.filter_domains(extractor.domain_names)

    # ── Step 2: Detections ────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"[{_ts()}] [INFO] ── Step 2: Detection Engines ──")

    MAX_FREQ       = thresholds.get("MAX_FREQUENCY",        10)
    MAX_DUR        = thresholds.get("MAX_DURATION",      14000)
    MAX_HTTP       = thresholds.get("MAX_HTTP_SIZE",     50000)
    MAX_SUB        = thresholds.get("MAX_SUBDOMAIN_LENGTH",  30)

    # Determine total detector count for scoring
    total_checks = 9   # baseline detectors
    if dga_detection:
        total_checks += 1
    if threat_feed:
        total_checks += 4   # c2 IPs, potential c2 IPs, c2 domains, c2 URLs

    scorer = DetectionScorer(total_checks=total_checks)
    detection_results: Dict = {
        "filepath":                 input_file,
        "analysis_timestamp":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "aggregated_ip_addresses":  set(),
        "aggregated_domain_names":  set(),
        "aggregated_urls":          set(),
    }

    # 1. Beaconing frequency
    beacon_det   = BeaconingFrequencyDetector(max_frequency_pct=MAX_FREQ)
    beacon_hits  = beacon_det.scan(
        extractor.connection_frequency, len(extractor.packets), wl_ips
    )
    detection_results["excessive_beaconing"] = beacon_hits
    scorer.record("Excessive beaconing frequency", bool(beacon_hits), "MED",
                  f"{len(beacon_hits)} connection(s)" if beacon_hits else "")
    for h in beacon_hits:
        detection_results["aggregated_ip_addresses"].update([h["src_ip"], h["dst_ip"]])

    # 2. Long connections
    longconn_det  = LongConnectionDetector(max_duration=MAX_DUR)
    longconn_hits = longconn_det.scan(extractor.connections, wl_ips)
    detection_results["long_connections"] = longconn_hits
    scorer.record("Long TCP connections", bool(longconn_hits), "MED",
                  f"{len(longconn_hits)} session(s)" if longconn_hits else "")
    for h in longconn_hits:
        detection_results["aggregated_ip_addresses"].update([h["src_ip"], h["dst_ip"]])

    # 3. Big HTTP body
    http_det  = BigHTTPBodyDetector(max_size=MAX_HTTP)
    http_hits = http_det.scan(extractor.http_sessions)
    detection_results["big_http_body"] = http_hits
    scorer.record("Unusual HTTP body size", bool(http_hits), "MED",
                  f"{len(http_hits)} session(s)" if http_hits else "")
    for s in http_hits:
        detection_results["aggregated_ip_addresses"].update([s["src_ip"], s["dst_ip"]])

    # 4. C2 TLS cert matching
    cert_det  = C2CertDetector(cert_db)
    cert_hits = cert_det._match_all(extractor.certificates)
    detection_results["malicious_tls_certs"] = cert_hits
    scorer.record("Malicious C2 TLS certificate values", bool(cert_hits), "HIGH",
                  ", ".join(h["c2_framework"] for h in cert_hits) if cert_hits else "")
    for h in cert_hits:
        detection_results["aggregated_ip_addresses"].update([h.get("src_ip",""), h.get("dst_ip","")])

    # 5. JA3 fingerprints
    # NEW: augment Angelware's hardcoded KNOWN_BAD_JA3 with live Proofpoint ET rules
    ja3_hits: List = []
    if _HAS_JA3_ENGINE:
        try:
            ja3_engine = JA3Detector()
            # Merge updatable Proofpoint rules into the detector's known-bad set
            updater = JA3RulesUpdater(ja3_rules_cache)
            proofpoint_rules = updater.load()
            if proofpoint_rules:
                for rule in proofpoint_rules:
                    h = rule.get("hash", "")
                    t = rule.get("type", "Proofpoint ET")
                    if h and h not in ja3_engine.known_bad:
                        ja3_engine.known_bad[h] = {
                            "tool":   t,
                            "risk":   "HIGH",
                            "reason": f"Proofpoint Emerging Threats: {t}",
                        }
            ja3_hits = ja3_engine.scan_digests(extractor.ja3_digests)
            detection_results["ja3_matches"] = ja3_hits
        except Exception as e:
            detection_results["ja3_matches"] = []
    else:
        detection_results["ja3_matches"] = []
    scorer.record("Malicious JA3 TLS fingerprints", bool(ja3_hits), "HIGH",
                  f"{len(ja3_hits)} match(es)" if ja3_hits else "")

    # 6. DGA detection (optional — uses dgad like C2Detective)
    dga_hits: List = []
    if dga_detection:
        try:
            os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
            from dgad.prediction import Detective
            detective = Detective()
            converted, _ = detective.prepare_domains(extractor.domain_names)
            detective.investigate(converted)
            for entry in converted:
                report = str(entry)
                if "is_dga=True" in report:
                    raw = report.split("raw='")[1].split("', words=")[0]
                    dga_hits.append(raw)
                    detection_results["aggregated_domain_names"].add(raw)
        except Exception as e:
            print(f"[{_ts()}] [WARNING] DGA detection unavailable: {e} "
                  "(pip install dgad)")
        detection_results["dga_domains"] = dga_hits
        scorer.record("DGA domain names", bool(dga_hits), "HIGH",
                      f"{len(dga_hits)} domain(s)" if dga_hits else "")

    # 7. DNS Tunneling
    tunnel_det  = DnsTunnelDetector(max_subdomain_len=MAX_SUB)
    tunnel_hits = tunnel_det.scan(clean_domains, wl_domains)
    detection_results["dns_tunneling"] = tunnel_hits
    scorer.record("DNS Tunneling", bool(tunnel_hits), "HIGH",
                  f"{len(tunnel_hits)} parent domain(s)" if tunnel_hits else "")
    for parent, data in tunnel_hits.items():
        detection_results["aggregated_domain_names"].update(data.get("queries", []))

    # 8. Tor relay + exit node traffic
    tor_det    = TorDetector(tor_cache)
    tor_result = tor_det.scan_connections(extractor.external_tcp_connections, wl_ips)
    detection_results.update(tor_result)
    scorer.record("Tor relay traffic",     bool(tor_result["tor_relay_connections"]), "HIGH",
                  f"{len(tor_result['tor_relay_connections'])} connection(s)"
                  if tor_result["tor_relay_connections"] else "")
    scorer.record("Tor exit node traffic", bool(tor_result["tor_exit_connections"]), "HIGH",
                  f"{len(tor_result['tor_exit_connections'])} connection(s)"
                  if tor_result["tor_exit_connections"] else "")
    for entry in tor_result["tor_relay_connections"]:
        detection_results["aggregated_ip_addresses"].update([entry["src_ip"], entry["dst_ip"]])

    # 9. Crypto domain blocklist
    crypto_det  = CryptoDomainDetector(crypto_cache)
    crypto_hits = crypto_det.scan(clean_domains)
    detection_results["crypto_domains"] = crypto_hits
    scorer.record("Crypto/cryptojacking domains", bool(crypto_hits), "MED",
                  f"{len(crypto_hits)} domain(s)" if crypto_hits else "")
    detection_results["aggregated_domain_names"].update(crypto_hits)

    # 10–13. C2 Threat Feed (optional)
    if threat_feed:
        print(f"\n{'─'*60}")
        print(f"[{_ts()}] [INFO] ── C2 Threat Feed Lookup ──")
        combined_ips = list(
            set(detection_results["aggregated_ip_addresses"]) |
            set(extractor.combined_unique_ip_list)
        )
        feed = C2ThreatFeed(feed_db)
        feed_results = feed.scan_all(
            combined_ips,
            list(detection_results["aggregated_domain_names"] | set(extractor.domain_names)),
            extractor.unique_urls,
        )
        detection_results.update(feed_results)
        scorer.record("Confirmed C2 IPs (threat feed)",
                      bool(feed_results.get("c2_ips")), "HIGH",
                      f"{len(feed_results.get('c2_ips',[]))} IP(s)")
        scorer.record("Potential C2 IPs (threat feed)",
                      bool(feed_results.get("potential_c2_ips")), "MED",
                      f"{len(feed_results.get('potential_c2_ips',[]))} IP(s)")
        scorer.record("Confirmed C2 domains (threat feed)",
                      bool(feed_results.get("c2_domains")), "HIGH",
                      f"{len(feed_results.get('c2_domains',[]))} domain(s)")
        scorer.record("Confirmed C2 URLs (threat feed)",
                      bool(feed_results.get("c2_urls")), "HIGH",
                      f"{len(feed_results.get('c2_urls',[]))} URL(s)")

    # ── Finalise aggregated IOC lists ─────────────────────────────────────────
    from ipaddress import ip_address as _ipa
    all_ips = list(detection_results["aggregated_ip_addresses"])
    public_only = []
    for ip in all_ips:
        try:
            if not _ipa(ip).is_private:
                public_only.append(ip)
        except ValueError:
            pass
    detection_results["aggregated_ip_addresses"]  = public_only
    detection_results["aggregated_domain_names"]  = list(detection_results["aggregated_domain_names"])
    detection_results["aggregated_urls"]          = list(detection_results["aggregated_urls"])
    detection_results["thresholds"]               = thresholds

    # ── Step 3: Verdict ───────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"[{_ts()}] [INFO] ── Step 3: Verdict ──")
    scorer.print_verdict()

    # ── Step 4: Enrichment (optional) ────────────────────────────────────────
    enriched_iocs: Dict = {}
    if enrich_iocs:
        print(f"\n{'─'*60}")
        print(f"[{_ts()}] [INFO] ── Step 4: IOC Enrichment ──")
        api_keys         = config.get("api_keys", {})
        enabled_services = config.get("enrichment_services", {})
        if any(enabled_services.values()):
            enricher     = IOCEnricher(
                api_keys=api_keys,
                enabled_services=enabled_services,
                api_urls=config.get("api_urls"),
            )
            enriched_iocs = enricher.enrich(
                public_only,
                detection_results["aggregated_domain_names"],
                detection_results["aggregated_urls"],
            )
        else:
            print(f"[{_ts()}] [WARNING] All enrichment services disabled in config — "
                  "enable at least one in config/c2_analyzer.yml")

    # ── Step 5: Reports ───────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"[{_ts()}] [INFO] ── Step 5: Reports ──")
    reporter = PcapReportGenerator(
        output_dir          = output_dir,
        thresholds          = thresholds,
        statistics          = extractor.statistics,
        detection_results   = detection_results,
        enriched_iocs       = enriched_iocs,
        scorer              = scorer,
        dga_enabled         = dga_detection,
        threat_feed_enabled = threat_feed,
    )
    reporter.write_detected_iocs_json()
    if enriched_iocs:
        reporter.write_enriched_iocs_json()
    reporter.create_html_report()
    if create_pdf:
        reporter.create_pdf_report()

    print(f"\n[{_ts()}] [INFO] Analysis complete. Output → '{output_dir}/'")
    print(f"  detected_iocs.json         — all detection findings")
    print(f"  extracted_data.json        — all IOCs extracted from capture")
    print(f"  c2_analysis_report.html    — full HTML report")
    if create_pdf:
        print(f"  c2_analysis_report.pdf     — PDF version")
    print()


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    ap = argparse.ArgumentParser(
        prog="c2_analyzer",
        description="Angelware offline C2 analyzer — C2Detective feature set",
    )

    ap.add_argument("-q", "--quiet",    action="store_true",
                    help="Do not print banner")
    ap.add_argument("-c", "--config",   metavar="FILE", default=DEFAULT_CONFIG,
                    help=f"Config file (default: {DEFAULT_CONFIG})")

    # Input (mutually exclusive: pcap file OR live capture)
    input_group = ap.add_mutually_exclusive_group()
    input_group.add_argument("-i", "--input",  metavar="FILE",
                             help="Input .pcap / .cap / .pcapng file to analyse")
    # NEW: live capture flag — mirrors C2Detective's -p / --packet-capture
    input_group.add_argument("-p", "--packet-capture", action="store_true",
                             help="Capture live packets then analyse "
                                  "(configure interface/timeout in config sniffing section)")

    # Output
    ap.add_argument("-o", "--output",   metavar="DIR", default="reports",
                    help="Output directory (default: reports/)")
    ap.add_argument("-s", "--stats",    action="store_true",
                    help="Print capture statistics")
    ap.add_argument("-w", "--write-extracted", action="store_true",
                    help="Write extracted IOC data to extracted_data.json")
    ap.add_argument("--pdf",            action="store_true",
                    help="Generate PDF report (requires wkhtmltopdf)")

    # Optional detection modules
    ap.add_argument("-d", "--dga",      action="store_true",
                    help="Enable DGA domain detection (requires dgad)")
    ap.add_argument("-t", "--threat-feed", action="store_true",
                    help="Enable C2 threat feed lookup (Feodo/URLhaus/ThreatFox)")
    ap.add_argument("-e", "--enrich",   action="store_true",
                    help="Enable external IOC enrichment (configure API keys first)")

    # Update options
    update = ap.add_argument_group("update options")
    update.add_argument("--update-all",         action="store_true",
                        help="Update Tor nodes, crypto domains, threat feed, and JA3 rules")
    update.add_argument("--update-tor",         action="store_true",
                        help="Update Tor node / exit node cache")
    update.add_argument("--update-crypto",      action="store_true",
                        help="Update crypto/cryptojacking domain blocklist")
    update.add_argument("--update-threat-feed", action="store_true",
                        help="Update C2 threat feed DB (Feodo/URLhaus/ThreatFox)")
    # NEW: JA3 rules update flag
    update.add_argument("--update-ja3-rules", "--ujr", action="store_true",
                        dest="update_ja3_rules",
                        help="Update Proofpoint ET JA3 rules cache")
    # NEW: cache status flag
    update.add_argument("--cache-status",       action="store_true",
                        help="Print IOC cache staleness status and exit")

    return ap.parse_args(args=None if sys.argv[1:] else ["--help"])


def main():
    args   = parse_args()
    config = _load_config(args.config)

    logging.basicConfig(
        level   = logging.DEBUG,
        format  = "%(created)f; %(asctime)s; %(levelname)s; %(name)s; %(message)s",
        filename = os.path.join(os.path.dirname(args.output or "reports"),
                                "c2_analyzer.log"),
    )

    # ── Cache status ──────────────────────────────────────────────────────────
    if args.cache_status:
        _ioc_status(config)
        return

    # ── Update modes ──────────────────────────────────────────────────────────
    if args.update_all:
        _update_tor(config)
        _update_crypto(config)
        _update_threat_feed()
        _update_ja3(config)          # NEW: JA3 rules now included in --update-all
        return

    if args.update_tor:
        _update_tor(config)
        return

    if args.update_crypto:
        _update_crypto(config)
        return

    if args.update_threat_feed:
        _update_threat_feed()
        return

    # NEW: JA3 rules update
    if args.update_ja3_rules:
        _update_ja3(config)
        return

    # ── Live capture mode (NEW — from C2Detective -p pipeline) ────────────────
    if args.packet_capture:
        input_file = _do_live_capture(config, args.output)
    elif args.input:
        input_file = args.input
    else:
        print("[ERROR] Specify an input file (-i) or use live capture (-p).")
        sys.exit(1)

    # ── Analysis mode ─────────────────────────────────────────────────────────
    analyse(
        input_file       = input_file,
        config           = config,
        output_dir       = args.output,
        print_stats      = args.stats,
        write_extracted  = args.write_extracted,
        enrich_iocs      = args.enrich,
        dga_detection    = args.dga,
        threat_feed      = args.threat_feed,
        create_pdf       = args.pdf,
        quiet            = args.quiet,
    )


if __name__ == "__main__":
    main()