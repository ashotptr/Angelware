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

  # Update specific caches:
  python3 c2_analyzer.py --update-tor
  python3 c2_analyzer.py --update-crypto
  python3 c2_analyzer.py --update-threat-feed

Compatible with: Linux (requires tshark for TLS cert extraction;
  ja3 CLI for JA3 digests; wkhtmltopdf for PDF; all optional — the
  tool degrades gracefully if any external tool is missing)
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

# Also import Angelware's existing JA3 detector
try:
    from tls_ja3 import JA3Detector, KNOWN_BOT_JA3
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


# ── Update helpers ────────────────────────────────────────────────────────────

def _update_tor(cfg: Dict):
    cache = cfg.get("file_paths", {}).get(
        "tor_node_cache", "c2_iocs/tor_nodes.json"
    )
    TorUpdater(os.path.join(_HERE, cache)).update(force=True)


def _update_crypto(cfg: Dict):
    cache = cfg.get("file_paths", {}).get(
        "crypto_domain_cache", "c2_iocs/crypto_domains.json"
    )
    CryptoDomainUpdater(os.path.join(_HERE, cache)).update(force=True)


def _update_threat_feed():
    C2FeedUpdater().update_all()


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

    # 5. JA3 fingerprints (via Angelware's existing tls_ja3.py)
    ja3_hits: List = []
    if _HAS_JA3_ENGINE:
        try:
            ja3_engine = JA3Detector()
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


# ── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    ap = argparse.ArgumentParser(
        prog="c2_analyzer",
        description="Angelware offline C2 analyzer — C2Detective feature set",
    )

    ap.add_argument("-q", "--quiet",    action="store_true",
                    help="Do not print banner")
    ap.add_argument("-c", "--config",   metavar="FILE", default=DEFAULT_CONFIG,
                    help=f"Config file (default: {DEFAULT_CONFIG})")

    # Input
    ap.add_argument("-i", "--input",    metavar="FILE",
                    help="Input .pcap / .cap / .pcapng file to analyse")

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
                        help="Update Tor nodes, crypto domains, and threat feed")
    update.add_argument("--update-tor",         action="store_true",
                        help="Update Tor node / exit node cache")
    update.add_argument("--update-crypto",      action="store_true",
                        help="Update crypto/cryptojacking domain blocklist")
    update.add_argument("--update-threat-feed", action="store_true",
                        help="Update C2 threat feed DB (Feodo/URLhaus/ThreatFox)")

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

    # ── Update modes ──────────────────────────────────────────────────────────
    if args.update_all:
        _update_tor(config)
        _update_crypto(config)
        _update_threat_feed()
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

    # ── Analysis mode ─────────────────────────────────────────────────────────
    if not args.input:
        print("[ERROR] -i / --input is required for analysis mode.")
        sys.exit(1)

    analyse(
        input_file       = args.input,
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
