"""
====================================================
 Angelware — IOC Enrichment Engine
 Ported/adapted from: C2Detective (martinkubecka)
====================================================

Missing capability added to Angelware:
  C2Detective queries SIX external threat intelligence services for
  every detected IOC (IP address, domain name, URL):

    1. AbuseIPDB      — abuse confidence scores, report count
    2. CIRCL BGP Ranking — autonomous system maliciousness ranking
    3. Shodan         — open ports, banners, service fingerprints
    4. ThreatFox      — malware IOC database (abuse.ch)
    5. URLhaus        — malicious URL database (abuse.ch)
    6. VirusTotal     — multi-AV scan results

  Angelware had only:
    • ip_reputation.py   — local heuristic scorer (no API calls)
    • geoip_sim.py       — simulated, in-memory lookups
    • breach_dump_enricher.py — credential metadata (no threat intel)

API keys needed (add to config/c2_analyzer.yml):
  abuseipdb:   from https://www.abuseipdb.com/account/api
  virustotal:  from https://www.virustotal.com/gui/my-apikey
  shodan:      from https://account.shodan.io/
  (ThreatFox, URLhaus, AlienVault OTX, CIRCL BGP Ranking are free/keyless)

Usage:
  engine = IOCEnricher(api_keys={...}, enabled_services={...})
  enriched = engine.enrich(ip_list, domain_list, url_list)

CLI (demo / test):
  python3 ioc_enricher.py --ip 8.8.8.8 --domain google.com
  python3 ioc_enricher.py --ip 185.220.101.50  # Tor exit node test
"""

import argparse
import json
import logging
import os
import sys
import time
from ipaddress import ip_address, IPv4Address
from typing import Any, Dict, List, Optional, Set

import requests

logger = logging.getLogger(__name__)


def _ts() -> str:
    return time.strftime("%H:%M:%S")


def _is_ipv4(target: str) -> bool:
    try:
        return isinstance(ip_address(target), IPv4Address)
    except ValueError:
        return False


def _is_ip(target: str) -> bool:
    try:
        ip_address(target)
        return True
    except ValueError:
        return False


def _get_ip_type(target: str) -> str:
    try:
        t = ip_address(target)
        return "IPv4" if isinstance(t, IPv4Address) else "IPv6"
    except ValueError:
        return "domain"


# ═══════════════════════════════════════════════════════════════════════════════
#  IOC ENRICHER
# ═══════════════════════════════════════════════════════════════════════════════

class IOCEnricher:
    """
    Enrich detected IOCs by querying external threat intelligence services.

    Mirrors C2Detective's EnrichmentEngine with additional CIRCL BGP Ranking.

    Parameters
    ----------
    api_keys : dict
        Keys: abuseipdb, virustotal, shodan
    enabled_services : dict
        Keys: abuseipdb, virustotal, shodan, threatfox, urlhaus,
               alienvault, circl_bgp — values: bool
    api_urls : dict
        Override default API URLs (useful for proxies / testing)
    """

    DEFAULT_URLS = {
        "abuseipdb":   "https://api.abuseipdb.com/api/v2/check",
        "threatfox":   "https://threatfox-api.abuse.ch/api/v1/",
        "virustotal":  "https://www.virustotal.com/vtapi/v2/",
        "shodan":      "https://api.shodan.io/",
        "alienvault":  "https://otx.alienvault.com/api/v1/indicators/",
        "urlhaus":     "https://urlhaus-api.abuse.ch/v1/",
        "circl_bgp":   "https://bgpranking-ng.circl.lu/json/asn",
    }

    def __init__(
        self,
        api_keys:          Optional[Dict[str, str]] = None,
        enabled_services:  Optional[Dict[str, bool]] = None,
        api_urls:          Optional[Dict[str, str]] = None,
    ):
        self.api_keys = api_keys or {}
        self.enabled  = {
            "abuseipdb": False,
            "virustotal": False,
            "shodan":    False,
            "threatfox": True,   # free, no key needed
            "urlhaus":   True,   # free, no key needed
            "alienvault": False,
            "circl_bgp": True,   # free, no key needed
        }
        if enabled_services:
            self.enabled.update(enabled_services)

        self.urls = dict(self.DEFAULT_URLS)
        if api_urls:
            self.urls.update(api_urls)

    # ------------------------------------------------------------------
    def enrich(
        self,
        ip_list:     List[str],
        domain_list: List[str],
        url_list:    List[str],
    ) -> Dict[str, Dict]:
        """
        Returns {
          "ip_addresses":  {ip:  {"abuseipdb": {...}, "shodan": {...}, ...}},
          "domain_names":  {dom: {...}},
          "urls":          {url: {...}},
        }
        """
        result: Dict[str, Dict] = {
            "ip_addresses":  {},
            "domain_names":  {},
            "urls":          {},
        }

        if ip_list:
            print(f"[{_ts()}] [INFO] Enriching {len(ip_list)} IP address IOC(s) …")
            for ip in ip_list:
                result["ip_addresses"][ip] = self._enrich_ip(ip)

        if domain_list:
            print(f"[{_ts()}] [INFO] Enriching {len(domain_list)} domain IOC(s) …")
            for domain in domain_list:
                result["domain_names"][domain] = self._enrich_domain(domain)

        if url_list:
            print(f"[{_ts()}] [INFO] Enriching {len(url_list)} URL IOC(s) …")
            for url in url_list:
                result["urls"][url] = self._enrich_url(url)

        return result

    # ── Per-type enrichment ───────────────────────────────────────────

    def _enrich_ip(self, ip: str) -> Dict:
        data: Dict[str, Any] = {}

        if self.enabled.get("abuseipdb"):
            data["abuseipdb"]  = self._query_abuseipdb(ip)
        if self.enabled.get("threatfox"):
            data["threatfox"]  = self._query_threatfox(ip)
        if self.enabled.get("virustotal"):
            data["virustotal"] = self._query_virustotal(ip)
        if self.enabled.get("shodan"):
            data["shodan"]     = self._query_shodan(ip)
        if self.enabled.get("alienvault"):
            data["alienvault"] = self._query_alienvault(ip)
        if self.enabled.get("urlhaus") and _is_ipv4(ip):
            data["urlhaus"]    = self._query_urlhaus(ip, "host")
        if self.enabled.get("circl_bgp") and _is_ip(ip):
            data["circl_bgp"]  = self._query_circl_bgp(ip)
        return data

    def _enrich_domain(self, domain: str) -> Dict:
        data: Dict[str, Any] = {}

        if self.enabled.get("abuseipdb"):
            data["abuseipdb"]  = self._query_abuseipdb(domain)
        if self.enabled.get("threatfox"):
            data["threatfox"]  = self._query_threatfox(domain)
        if self.enabled.get("virustotal"):
            data["virustotal"] = self._query_virustotal(domain)
        if self.enabled.get("shodan"):
            data["shodan"]     = self._query_shodan(domain)
        if self.enabled.get("alienvault"):
            data["alienvault"] = self._query_alienvault(domain)
        if self.enabled.get("urlhaus"):
            data["urlhaus"]    = self._query_urlhaus(domain, "host")
        return data

    def _enrich_url(self, url: str) -> Dict:
        data: Dict[str, Any] = {}

        data["abuseipdb"]  = {}   # not applicable
        if self.enabled.get("threatfox"):
            data["threatfox"]  = self._query_threatfox(url)
        if self.enabled.get("virustotal"):
            data["virustotal"] = self._query_virustotal(url)
        data["shodan"]     = {}   # not applicable
        data["alienvault"] = {}
        if self.enabled.get("urlhaus"):
            data["urlhaus"]    = self._query_urlhaus(url, "url")
        return data

    # ── Service query methods ─────────────────────────────────────────

    def _query_abuseipdb(self, target: str) -> Dict:
        """https://docs.abuseipdb.com/#check-endpoint"""
        key = self.api_keys.get("abuseipdb")
        if not key:
            return {"error": "no_api_key"}
        try:
            resp = requests.get(
                self.urls["abuseipdb"],
                headers={"Accept": "application/json", "Key": key},
                params={"ipAddress": target, "maxAgeInDays": "90", "verbose": ""},
                timeout=15,
            )
            if resp.status_code == 401:
                return {"error": "auth_failed"}
            return resp.json()
        except Exception as e:
            logger.error("AbuseIPDB error for %s: %s", target, e)
            return {"error": str(e)}

    def _query_threatfox(self, target: str) -> Dict:
        """https://threatfox.abuse.ch/api/"""
        try:
            resp = requests.post(
                self.urls["threatfox"],
                data=json.dumps({"query": "search_ioc", "search_term": target}),
                timeout=15,
            )
            data = resp.json()
            return data if data.get("query_status") == "ok" else {}
        except Exception as e:
            logger.error("ThreatFox error for %s: %s", target, e)
            return {}

    def _query_virustotal(self, target: str) -> Dict:
        """https://developers.virustotal.com/v2.0/reference"""
        key = self.api_keys.get("virustotal")
        if not key:
            return {"error": "no_api_key"}
        base = self.urls["virustotal"]
        result: Dict = {}
        try:
            # URL scan report (works for IPs, domains, URLs)
            resp = requests.get(
                f"{base}url/report",
                params={"apikey": key, "resource": target, "scan": "1"},
                timeout=15,
            )
            if resp.status_code == 204:
                return {"error": "rate_limited"}
            result.update(resp.json())

            # Supplemental IP or domain report
            if _is_ip(target):
                resp2 = requests.get(
                    f"{base}ip-address/report",
                    params={"apikey": key, "ip": target},
                    timeout=15,
                )
                if resp2.status_code != 204:
                    result.update(resp2.json())
            else:
                resp2 = requests.get(
                    f"{base}domain/report",
                    params={"apikey": key, "domain": target},
                    timeout=15,
                )
                if resp2.status_code != 204:
                    result.update(resp2.json())
        except Exception as e:
            logger.error("VirusTotal error for %s: %s", target, e)
            return {"error": str(e)}
        return result

    def _query_shodan(self, target: str) -> Dict:
        """https://shodan.readthedocs.io/"""
        key = self.api_keys.get("shodan")
        if not key:
            return {"error": "no_api_key"}
        try:
            import shodan as shodan_lib
        except ImportError:
            return {"error": "shodan_lib_not_installed"}
        try:
            api = shodan_lib.Shodan(key)
            if not _is_ip(target):
                # Resolve domain first
                resp = requests.get(
                    f"{self.urls['shodan']}dns/resolve",
                    params={"hostnames": target, "key": key},
                    timeout=15,
                )
                resolved = resp.json().get(target)
                if not resolved:
                    return {}
                target = resolved
            return api.host(target)
        except Exception as e:
            logger.info("Shodan no result for %s: %s", target, e)
            return {}

    def _query_alienvault(self, target: str) -> Dict:
        """https://otx.alienvault.com/assets/static/external_api.html"""
        base      = self.urls["alienvault"]
        ip_type   = _get_ip_type(target)
        sections  = ["general", "geo", "url_list", "passive_dns", "malware", "http_scans"]
        result: Dict = {}
        try:
            if ip_type == "IPv4":
                prefix = f"IPv4/{target}"
            elif ip_type == "IPv6":
                prefix = f"IPv6/{target}"
            else:
                prefix = f"domain/{target}"

            for section in sections:
                resp = requests.get(f"{base}{prefix}/{section}", timeout=15)
                result[section] = resp.json()
        except Exception as e:
            logger.error("AlienVault error for %s: %s", target, e)
        return result

    def _query_urlhaus(self, target: str, endpoint: str) -> Dict:
        """https://urlhaus-api.abuse.ch"""
        api_map = {
            "url":  (f"{self.urls['urlhaus']}url/",  {"url":  target}),
            "host": (f"{self.urls['urlhaus']}host/", {"host": target}),
        }
        if endpoint not in api_map:
            return {}
        url, data = api_map[endpoint]
        try:
            resp = requests.post(url, data=data, timeout=15)
            parsed = resp.json()
            return parsed if parsed.get("query_status") == "ok" else {}
        except Exception as e:
            logger.error("URLhaus error for %s: %s", target, e)
            return {}

    def _query_circl_bgp(self, ip: str) -> Dict:
        """
        CIRCL BGP Ranking — free, no API key.
        Returns ASN reputation data indicating whether the autonomous system
        hosting this IP is associated with malicious activity.
        https://bgpranking-ng.circl.lu/
        """
        try:
            # Resolve IP → ASN via whois-based API
            asn_resp = requests.get(
                f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}",
                timeout=15,
            )
            asn_data = asn_resp.json().get("data", {})
            asns = asn_data.get("asns", [])
            if not asns:
                return {}

            asn = str(asns[0].get("asn", ""))
            if not asn:
                return {}

            # Query BGP Ranking for this ASN
            rank_resp = requests.post(
                self.urls["circl_bgp"],
                json={"asn": f"AS{asn}"},
                timeout=15,
            )
            rank_data = rank_resp.json()
            return {
                "asn":    f"AS{asn}",
                "holder": asns[0].get("holder", ""),
                "ranking": rank_data,
            }
        except Exception as e:
            logger.info("CIRCL BGP Ranking error for %s: %s", ip, e)
            return {}


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        prog="ioc_enricher",
        description="IOC Enrichment Engine — Angelware add-on (C2Detective port)"
    )
    ap.add_argument("--ip",     action="append", default=[], metavar="IP",
                    help="IP address to enrich (can repeat)")
    ap.add_argument("--domain", action="append", default=[], metavar="DOMAIN",
                    help="Domain to enrich (can repeat)")
    ap.add_argument("--url",    action="append", default=[], metavar="URL",
                    help="URL to enrich (can repeat)")
    ap.add_argument("--config", metavar="FILE",
                    help="YAML config file with api_keys and enabled_services")
    ap.add_argument("--output", metavar="FILE",
                    help="Write enriched JSON to this file")
    args = ap.parse_args()

    api_keys: Dict         = {}
    enabled:  Dict         = {}

    if args.config:
        try:
            import yaml
            with open(args.config) as fh:
                cfg = yaml.safe_load(fh)
            api_keys = cfg.get("api_keys", {})
            enabled  = cfg.get("enrichment_services", {})
        except Exception as e:
            print(f"[ERROR] Failed to load config: {e}")
            sys.exit(1)

    if not args.ip and not args.domain and not args.url:
        # Demo mode with a public IP
        print("Demo mode — enriching 8.8.8.8 with free services …\n")
        args.ip = ["8.8.8.8"]
        enabled = {"threatfox": True, "urlhaus": True, "circl_bgp": True}

    engine   = IOCEnricher(api_keys=api_keys, enabled_services=enabled)
    enriched = engine.enrich(args.ip, args.domain, args.url)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(enriched, fh, indent=4)
        print(f"[{_ts()}] [INFO] Enriched results written to {args.output}")
    else:
        print(json.dumps(enriched, indent=2, default=str))


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
