"""
====================================================
 Angelware — DNS Tunneling + Crypto Domain Detector
 Ported/adapted from: C2Detective (martinkubecka)
====================================================

Two missing capabilities combined here:

1. DNS Tunneling via subdomain length  (C2Detective: detect_dns_tunneling)
   ─────────────────────────────────────────────────────────────────────
   Angelware's existing Engine 3 detects:
     • NXDOMAIN burst  (≥10 NXDOMAINs from one IP in 30s)
     • High-entropy labels  (Shannon H > 3.8 bits/char)

   What was missing: DNS tunneling tools (iodine, dnscat2, dns2tcp)
   encode data as unusually LONG subdomains (e.g. 45+ chars before
   the registrable domain). Entropy alone is not enough — tunnels using
   base32 have entropy ≈ 3.0 (below the threshold) but subdomain
   lengths of 60+ characters.

   DnsTunnelDetector.scan() — offline pcap mode, receives a list of
   DNS query strings, returns grouped findings per parent domain.

   Also provides a live-IDS hook: DnsTunnelDetector.process_query()
   maintains a rolling window and fires when a threshold is crossed.

2. Crypto/Cryptojacking Domain Blocklist  (C2Detective: detect_crypto_domains)
   ─────────────────────────────────────────────────────────────────────────────
   Angelware had cryptojack_sim.py (attack) + CPU-based host detection
   (ids_detector.py Host engine). What was missing: checking outbound
   DNS queries against a blocklist of known crypto mining pool domains.

   CryptoDomainDetector.update() — fetches blocklistproject list
   CryptoDomainDetector.scan()   — offline: checks queried domains
   CryptoDomainDetector.check()  — live: check one domain at lookup time

Integration with existing Angelware IDS:
  In ids_detector.py, import both classes and wire them into the
  packet-processing loop alongside Engine 3's existing checks:

    from dns_tunnel_detector import DnsTunnelDetector, CryptoDomainDetector
    _dns_tunnel  = DnsTunnelDetector()
    _crypto_doms = CryptoDomainDetector()

    # inside DNS query handler:
    _dns_tunnel.process_query(src_ip, query_string)
    _crypto_doms.check(query_string, src_ip)

CLI:
  python3 dns_tunnel_detector.py --update-crypto
  python3 dns_tunnel_detector.py --status
  python3 dns_tunnel_detector.py --pcap capture.pcap --max-subdomain 30
  python3 dns_tunnel_detector.py --check-domain coinhive.com
"""

import argparse
import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import requests

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False
    print("[WARNING] tldextract not installed — using fallback domain parser. "
          "Install with: pip install tldextract")

logger = logging.getLogger(__name__)

_HERE = os.path.dirname(os.path.realpath(__file__))

CRYPTO_DOMAIN_URL   = "https://blocklistproject.github.io/Lists/alt-version/crypto-nl.txt"
CRYPTO_CACHE_PATH   = os.path.join(_HERE, "c2_iocs", "crypto_domains.json")
UPDATE_INTERVAL_SEC = 86400  # 24 hours

DEFAULT_MAX_SUBDOMAIN_LEN = 30   # chars — same default as C2Detective
DNS_TUNNEL_WINDOW_SEC     = 60
DNS_TUNNEL_THRESHOLD      = 3    # unique long-subdomain queries per parent in window


# ── Domain parsing helper ────────────────────────────────────────────────────

def _split_domain(fqdn: str) -> Tuple[str, str, str]:
    """Returns (subdomain, domain, suffix)."""
    fqdn = fqdn.rstrip(".")
    if _HAS_TLDEXTRACT:
        ex = tldextract.extract(fqdn)
        return ex.subdomain, ex.domain, ex.suffix
    # Fallback: naive split on last two labels
    parts = fqdn.split(".")
    if len(parts) >= 3:
        return ".".join(parts[:-2]), parts[-2], parts[-1]
    elif len(parts) == 2:
        return "", parts[0], parts[1]
    return "", fqdn, ""


def _ts() -> str:
    return time.strftime("%H:%M:%S")


# ═══════════════════════════════════════════════════════════════════════════════
#  DNS TUNNELING DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class DnsTunnelDetector:
    """
    Detect DNS tunneling via unusually long subdomain labels.

    Offline pcap mode:
        detector = DnsTunnelDetector(max_subdomain_len=30)
        results  = detector.scan(domain_names_list, whitelisted_domains=set())

    Live IDS mode:
        detector = DnsTunnelDetector()
        detector.process_query(src_ip="192.168.100.11", query="aGVs...XYZ.tunnel.evil.com")
        # → prints ALERT if threshold crossed within the rolling window
    """

    def __init__(
        self,
        max_subdomain_len: int = DEFAULT_MAX_SUBDOMAIN_LEN,
        window_sec:        int = DNS_TUNNEL_WINDOW_SEC,
        threshold:         int = DNS_TUNNEL_THRESHOLD,
    ):
        self.max_subdomain_len = max_subdomain_len
        self.window_sec        = window_sec
        self.threshold         = threshold

        # Live-mode rolling window: {src_ip: {parent_domain: deque[timestamp]}}
        self._live_window: Dict[str, Dict[str, deque]] = defaultdict(
            lambda: defaultdict(deque)
        )
        self._alerted: Set[Tuple[str, str]] = set()

    # ------------------------------------------------------------------
    def scan(
        self,
        domain_names: List[str],
        whitelisted_domains: Optional[Set[str]] = None,
    ) -> Dict[str, object]:
        """
        Offline scan of a domain name list extracted from a pcap.
        Returns { parent_domain: {"queries": [fqdn, ...], "count": N}, ... }
        """
        whitelisted_domains = whitelisted_domains or set()
        detected: Dict[str, Dict] = {}

        print(f"[{_ts()}] [INFO] Scanning {len(domain_names)} domain names "
              f"for DNS tunneling indicators (max_subdomain_len={self.max_subdomain_len}) …")

        for fqdn in domain_names:
            subdomain, domain, suffix = _split_domain(fqdn)

            if not suffix:
                continue
            if "arpa" in suffix:
                continue

            # Skip whitelisted parent domains
            parent = f"{domain}.{suffix}"
            if self._is_whitelisted(parent, whitelisted_domains):
                continue

            if len(subdomain) > self.max_subdomain_len:
                if parent not in detected:
                    detected[parent] = {"queries": set(), "count": 0}
                detected[parent]["queries"].add(fqdn)
                detected[parent]["count"] += 1

        # Serialise sets → lists
        for parent in detected:
            detected[parent]["queries"] = list(detected[parent]["queries"])

        if detected:
            print(f"[{_ts()}] [ALERT] DNS Tunneling indicators detected — "
                  f"{len(detected)} parent domain(s) with long subdomains")
            for parent, data in detected.items():
                print(f"  {parent}  →  {data['count']} unique long-subdomain queries")
        else:
            print(f"[{_ts()}] [INFO] DNS Tunneling via subdomain length not detected")

        return detected

    # ------------------------------------------------------------------
    def process_query(self, src_ip: str, query: str) -> bool:
        """
        Live IDS mode: call for each observed DNS query.
        Returns True if a tunnel alert was fired.
        """
        subdomain, domain, suffix = _split_domain(query)
        if not suffix or "arpa" in suffix:
            return False

        if len(subdomain) <= self.max_subdomain_len:
            return False

        parent = f"{domain}.{suffix}"
        now = time.time()
        window = self._live_window[src_ip][parent]

        # Expire old entries
        while window and now - window[0] > self.window_sec:
            window.popleft()

        window.append(now)

        key = (src_ip, parent)
        if len(window) >= self.threshold and key not in self._alerted:
            self._alerted.add(key)
            print(f"[{_ts()}] [ENGINE3-TUNNEL] [HIGH] DNS Tunneling indicator — "
                  f"{src_ip} queried {len(window)} long subdomains for '{parent}' "
                  f"in {self.window_sec}s (subdomain len={len(subdomain)} > "
                  f"{self.max_subdomain_len})")
            logger.warning("DNS Tunneling: %s → %s (%d queries)", src_ip, parent, len(window))
            return True

        return False

    # ------------------------------------------------------------------
    @staticmethod
    def _is_whitelisted(parent: str, whitelist: Set[str]) -> bool:
        if not whitelist:
            return False
        _, wl_domain, _ = _split_domain(parent)
        for wl_entry in whitelist:
            _, wl_name, _ = _split_domain(wl_entry)
            if wl_domain == wl_name:
                return True
        return False


# ═══════════════════════════════════════════════════════════════════════════════
#  CRYPTO DOMAIN DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class CryptoDomainUpdater:
    """Fetch and cache the crypto/cryptojacking domain blocklist."""

    def __init__(self, cache_path: str = CRYPTO_CACHE_PATH):
        self.cache_path = cache_path
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)

    def needs_update(self) -> bool:
        if not os.path.exists(self.cache_path):
            return True
        return time.time() - os.path.getmtime(self.cache_path) >= UPDATE_INTERVAL_SEC

    def update(self, force: bool = False) -> bool:
        if not force and not self.needs_update():
            print(f"[{_ts()}] [INFO] Crypto domain list is fresh — skipping update")
            return True

        print(f"[{_ts()}] [INFO] Fetching crypto/cryptojacking domain blocklist …")
        try:
            resp = requests.get(CRYPTO_DOMAIN_URL, timeout=30)
            resp.raise_for_status()
        except Exception as exc:
            print(f"[{_ts()}] [ERROR] Failed to fetch crypto domain list: {exc}")
            logger.error("Crypto domain fetch failed: %s", exc)
            return False

        domains = [
            line.strip()
            for line in resp.text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        payload = {
            "fetched_at":    datetime.utcnow().isoformat() + "Z",
            "crypto_domains": domains,
        }
        with open(self.cache_path, "w") as fh:
            json.dump(payload, fh, indent=2)

        print(f"[{_ts()}] [INFO] Crypto domain list updated — "
              f"{len(domains)} domains → {self.cache_path}")
        return True


class CryptoDomainDetector:
    """
    Detect outbound DNS queries to known crypto mining / cryptojacking domains.

    Offline pcap mode:
        d = CryptoDomainDetector()
        hits = d.scan(domain_names_list)

    Live IDS mode:
        d = CryptoDomainDetector()
        if d.check("coinhive.com", src_ip="192.168.100.11"):
            # alert already printed
            ...
    """

    def __init__(self, cache_path: str = CRYPTO_CACHE_PATH):
        self.cache_path = cache_path
        self._domains: Set[str] = set()
        self._loaded_at: Optional[str] = None
        self._load()

    # ------------------------------------------------------------------
    def _load(self):
        if not os.path.exists(self.cache_path):
            print(f"[{_ts()}] [WARNING] Crypto domain cache missing — "
                  "run `python3 dns_tunnel_detector.py --update-crypto`")
            return
        with open(self.cache_path) as fh:
            data = json.load(fh)
        self._domains  = set(data.get("crypto_domains", []))
        self._loaded_at = data.get("fetched_at", "unknown")
        print(f"[{_ts()}] [INFO] Crypto domain blocklist loaded — "
              f"{len(self._domains)} domains (fetched {self._loaded_at})")

    # ------------------------------------------------------------------
    def check(self, domain: str, src_ip: str = "") -> bool:
        """Live mode: returns True and prints an alert if the domain is blocked."""
        if domain in self._domains:
            src_tag = f" from {src_ip}" if src_ip else ""
            print(f"[{_ts()}] [ALERT] Crypto/cryptojacking domain queried{src_tag}: "
                  f"{domain}")
            logger.warning("Crypto domain hit%s: %s", src_tag, domain)
            return True
        return False

    # ------------------------------------------------------------------
    def scan(self, domain_names: List[str]) -> List[str]:
        """Offline: returns list of queried domains that match the blocklist."""
        print(f"[{_ts()}] [INFO] Checking {len(domain_names)} domains against "
              f"crypto blocklist ({len(self._domains)} entries) …")

        hits = [d for d in domain_names if d in self._domains]

        if hits:
            print(f"[{_ts()}] [ALERT] {len(hits)} crypto/cryptojacking domain(s) detected:")
            for d in hits:
                print(f"  {d}")
        else:
            print(f"[{_ts()}] [INFO] No crypto/cryptojacking domains detected")

        return hits

    # ------------------------------------------------------------------
    def status(self) -> Dict:
        return {
            "cache_path":     self.cache_path,
            "domain_count":   len(self._domains),
            "fetched_at":     self._loaded_at,
            "needs_update":   CryptoDomainUpdater(self.cache_path).needs_update(),
        }


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        prog="dns_tunnel_detector",
        description="DNS Tunneling + Crypto Domain Detector — Angelware add-on"
    )
    ap.add_argument("--update-crypto", action="store_true",
                    help="Fetch / refresh the crypto domain blocklist")
    ap.add_argument("--force",         action="store_true",
                    help="Force update even if cache is fresh")
    ap.add_argument("--status",        action="store_true",
                    help="Show cache status for both detectors")
    ap.add_argument("--pcap",          metavar="FILE",
                    help="Scan domain names extracted from a pcap "
                         "(requires pcap_ioc_extractor.py)")
    ap.add_argument("--max-subdomain", type=int, default=DEFAULT_MAX_SUBDOMAIN_LEN,
                    help=f"Subdomain length threshold (default: {DEFAULT_MAX_SUBDOMAIN_LEN})")
    ap.add_argument("--check-domain",  metavar="DOMAIN",
                    help="Check a single domain against the crypto blocklist")
    ap.add_argument("--check-tunnel",  metavar="FQDN",
                    help="Check a single FQDN for tunneling indicators")
    args = ap.parse_args()

    if args.update_crypto:
        CryptoDomainUpdater().update(force=args.force)
        return

    if args.status:
        cd_status = CryptoDomainDetector().status()
        print("Crypto domain blocklist:")
        for k, v in cd_status.items():
            print(f"  {k:<20} {v}")
        print("\nDNS Tunnel Detector:")
        print(f"  max_subdomain_len  {DEFAULT_MAX_SUBDOMAIN_LEN}")
        return

    if args.check_domain:
        d = CryptoDomainDetector()
        hit = d.check(args.check_domain)
        if not hit:
            print(f"  {args.check_domain}  →  not in crypto blocklist")
        return

    if args.check_tunnel:
        dt = DnsTunnelDetector(max_subdomain_len=args.max_subdomain)
        subdomain, domain, suffix = _split_domain(args.check_tunnel)
        print(f"  subdomain = '{subdomain}' (len={len(subdomain)})")
        print(f"  parent    = '{domain}.{suffix}'")
        if len(subdomain) > args.max_subdomain:
            print(f"  RESULT    → LONG SUBDOMAIN (> {args.max_subdomain}) — potential tunnel")
        else:
            print(f"  RESULT    → normal length")
        return

    if args.pcap:
        # Import the pcap extractor from the same directory
        sys.path.insert(0, _HERE)
        try:
            from pcap_ioc_extractor import PcapIOCExtractor
            extractor = PcapIOCExtractor(args.pcap)
            domain_names = extractor.domain_names
        except ImportError:
            print("[ERROR] pcap_ioc_extractor.py not found in the same directory.")
            sys.exit(1)

        dt = DnsTunnelDetector(max_subdomain_len=args.max_subdomain)
        dt.scan(domain_names)

        cd = CryptoDomainDetector()
        cd.scan(domain_names)
        return

    ap.print_help()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
