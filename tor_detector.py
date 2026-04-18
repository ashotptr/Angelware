"""
====================================================
 Angelware — Tor Node & Exit Node Detector
 Ported/adapted from: C2Detective (martinkubecka)
====================================================

Missing capability added to Angelware:
  C2Detective fetches live Tor node lists from dan.me.uk and cross-
  references every observed TCP connection against them, distinguishing
  traffic to ANY Tor relay from traffic specifically to EXIT nodes.
  Angelware had zero equivalent.

Two classes:
  TorUpdater  — downloads and caches tor_nodes.json
                (all_nodes list + exit_nodes list)
  TorDetector — checks a list of (src_ip, dst_ip) pairs against
                the cached lists and returns structured findings

Integration with Angelware:
  1. Offline pcap mode  → called by pcap_ioc_extractor.py
  2. Live IDS mode      → import TorDetector in ids_detector.py,
                          call check_connection() from the packet loop
  3. Standalone update  → python3 tor_detector.py --update
  4. Standalone check   → python3 tor_detector.py --check-ip <ip>

CLI:
  python3 tor_detector.py --update
  python3 tor_detector.py --status
  python3 tor_detector.py --check-ip 185.220.101.50
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import requests

logger = logging.getLogger(__name__)

# ── Default paths (override in config or constructor) ───────────────────────
DEFAULT_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "c2_iocs", "tor_nodes.json"
)

# dan.me.uk asks you to cache for at least 30 minutes
TOR_NODE_URL      = "https://www.dan.me.uk/torlist/"
TOR_EXIT_NODE_URL = "https://www.dan.me.uk/torlist/?exit"
UPDATE_INTERVAL   = 1800  # seconds — respect dan.me.uk's caching request


# ── TorUpdater ───────────────────────────────────────────────────────────────

class TorUpdater:
    """Fetch and cache the current Tor relay and exit-node lists."""

    def __init__(self, cache_path: str = DEFAULT_CACHE_PATH):
        self.cache_path = cache_path
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)

    # ------------------------------------------------------------------
    def needs_update(self) -> bool:
        """True if the cache is missing or older than UPDATE_INTERVAL."""
        if not os.path.exists(self.cache_path):
            return True
        age = time.time() - os.path.getmtime(self.cache_path)
        return age >= UPDATE_INTERVAL

    # ------------------------------------------------------------------
    def update(self, force: bool = False) -> bool:
        """Download fresh lists and write to cache. Returns success."""
        if not force and not self.needs_update():
            print(f"[{_ts()}] [INFO] Tor node list is fresh — skipping update "
                  f"(use --force to override)")
            return True

        all_nodes  = self._fetch(TOR_NODE_URL,      "Tor relay list")
        exit_nodes = self._fetch(TOR_EXIT_NODE_URL,  "Tor exit-node list")

        if not all_nodes or not exit_nodes:
            print(f"[{_ts()}] [ERROR] Tor node update failed — keeping old cache")
            logger.error("Tor node update failed")
            return False

        payload = {
            "fetched_at": datetime.utcnow().isoformat() + "Z",
            "all_nodes":  all_nodes,
            "exit_nodes": exit_nodes,
        }
        with open(self.cache_path, "w") as fh:
            json.dump(payload, fh, indent=2)

        print(f"[{_ts()}] [INFO] Tor node cache updated — "
              f"{len(all_nodes)} relays, {len(exit_nodes)} exits → {self.cache_path}")
        logger.info("Tor node cache updated: %d relays, %d exits",
                    len(all_nodes), len(exit_nodes))
        return True

    # ------------------------------------------------------------------
    def _fetch(self, url: str, label: str) -> List[str]:
        print(f"[{_ts()}] [INFO] Fetching {label} from {url} …")
        try:
            resp = requests.get(url, timeout=20)
            resp.raise_for_status()
            nodes = [line.strip() for line in resp.text.splitlines()
                     if line.strip() and not line.startswith("#")]
            print(f"[{_ts()}] [INFO] Got {len(nodes)} entries for {label}")
            return nodes
        except Exception as exc:
            print(f"[{_ts()}] [ERROR] Failed to fetch {label}: {exc}")
            logger.error("Failed to fetch %s: %s", label, exc, exc_info=True)
            return []


# ── TorDetector ──────────────────────────────────────────────────────────────

class TorDetector:
    """
    Check TCP connections against cached Tor node lists.

    Usage (offline / pcap mode):
        detector = TorDetector()
        results  = detector.scan_connections(external_tcp_connections)

    Usage (live IDS integration):
        detector = TorDetector()
        hit = detector.check_connection(src_ip, dst_ip)
    """

    def __init__(self, cache_path: str = DEFAULT_CACHE_PATH):
        self.cache_path = cache_path
        self.all_nodes:  Set[str] = set()
        self.exit_nodes: Set[str] = set()
        self._loaded_at: Optional[str] = None
        self._load_cache()

    # ------------------------------------------------------------------
    def _load_cache(self):
        if not os.path.exists(self.cache_path):
            print(f"[{_ts()}] [WARNING] Tor cache missing at {self.cache_path} — "
                  "run `python3 tor_detector.py --update` first")
            logger.warning("Tor cache missing: %s", self.cache_path)
            return

        with open(self.cache_path) as fh:
            data = json.load(fh)

        self.all_nodes  = set(data.get("all_nodes",  []))
        self.exit_nodes = set(data.get("exit_nodes", []))
        self._loaded_at = data.get("fetched_at", "unknown")
        print(f"[{_ts()}] [INFO] Tor cache loaded — "
              f"{len(self.all_nodes)} relays, {len(self.exit_nodes)} exits "
              f"(fetched {self._loaded_at})")
        logger.info("Tor cache loaded: %d relays, %d exits",
                    len(self.all_nodes), len(self.exit_nodes))

    # ------------------------------------------------------------------
    def check_connection(
        self, src_ip: str, dst_ip: str
    ) -> Dict[str, object]:
        """
        Returns a dict with keys:
          is_tor_relay   (bool)
          is_exit_node   (bool)
          tor_ip         (str | None) — whichever end matched
        """
        result = {"is_tor_relay": False, "is_exit_node": False, "tor_ip": None}

        for ip in (src_ip, dst_ip):
            if ip in self.exit_nodes:
                result["is_exit_node"] = True
                result["is_tor_relay"] = True
                result["tor_ip"]       = ip
                return result
            if ip in self.all_nodes:
                result["is_tor_relay"] = True
                result["tor_ip"]       = ip
                # keep looking — the other end might be an exit node
        return result

    # ------------------------------------------------------------------
    def scan_connections(
        self,
        # Each entry: (timestamp, src_ip, src_port, dst_ip, dst_port)
        external_tcp_connections: List[Tuple],
        whitelisted_ips: Optional[Set[str]] = None,
    ) -> Dict[str, object]:
        """
        Full scan of all external TCP connections.

        Returns {
            "tor_relay_connections":     [...],  # hits on any relay
            "tor_exit_connections":      [...],  # hits specifically on exits
            "detected_tor_relay_ips":   [...],
            "detected_tor_exit_ips":    [...],
        }
        """
        whitelisted_ips = whitelisted_ips or set()

        relay_conns:     List[Dict] = []
        exit_conns:      List[Dict] = []
        seen_relay:      Set        = set()
        seen_exit:       Set        = set()
        relay_ips:       Set[str]   = set()
        exit_ips:        Set[str]   = set()

        for entry in external_tcp_connections:
            timestamp, src_ip, src_port, dst_ip, dst_port = entry[:5]

            if src_ip in whitelisted_ips or dst_ip in whitelisted_ips:
                continue

            hit = self.check_connection(src_ip, dst_ip)

            if hit["is_tor_relay"]:
                relay_ips.add(hit["tor_ip"])
                key = frozenset({src_ip, src_port, dst_ip, dst_port})
                if key not in seen_relay:
                    seen_relay.add(key)
                    relay_conns.append({
                        "timestamp": timestamp,
                        "src_ip":    src_ip,
                        "src_port":  src_port,
                        "dst_ip":    dst_ip,
                        "dst_port":  dst_port,
                        "tor_ip":    hit["tor_ip"],
                        "is_exit":   hit["is_exit_node"],
                    })

            if hit["is_exit_node"]:
                exit_ips.add(hit["tor_ip"])
                key = frozenset({src_ip, src_port, dst_ip, dst_port})
                if key not in seen_exit:
                    seen_exit.add(key)
                    exit_conns.append({
                        "timestamp": timestamp,
                        "src_ip":    src_ip,
                        "src_port":  src_port,
                        "dst_ip":    dst_ip,
                        "dst_port":  dst_port,
                        "tor_ip":    hit["tor_ip"],
                    })

        if relay_conns:
            print(f"[{_ts()}] [ALERT] Tor relay traffic detected — "
                  f"{len(relay_conns)} unique connections to "
                  f"{len(relay_ips)} nodes")
        else:
            print(f"[{_ts()}] [INFO] No Tor relay traffic detected")

        if exit_conns:
            print(f"[{_ts()}] [ALERT] Tor EXIT node traffic detected — "
                  f"{len(exit_conns)} unique connections to "
                  f"{len(exit_ips)} exit nodes")
        else:
            print(f"[{_ts()}] [INFO] No Tor exit-node traffic detected")

        return {
            "tor_relay_connections":   relay_conns,
            "tor_exit_connections":    exit_conns,
            "detected_tor_relay_ips":  list(relay_ips),
            "detected_tor_exit_ips":   list(exit_ips),
        }

    # ------------------------------------------------------------------
    def status(self) -> Dict[str, object]:
        return {
            "cache_path":   self.cache_path,
            "relay_count":  len(self.all_nodes),
            "exit_count":   len(self.exit_nodes),
            "fetched_at":   self._loaded_at,
            "cache_age_s":  (
                round(time.time() - os.path.getmtime(self.cache_path))
                if os.path.exists(self.cache_path) else None
            ),
            "needs_update": TorUpdater(self.cache_path).needs_update(),
        }


# ── helpers ──────────────────────────────────────────────────────────────────

def _ts() -> str:
    return time.strftime("%H:%M:%S")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        prog="tor_detector",
        description="Tor node detection — Angelware add-on (C2Detective port)"
    )
    ap.add_argument("--update",    action="store_true",
                    help="Fetch fresh Tor node lists and update cache")
    ap.add_argument("--force",     action="store_true",
                    help="Force update even if cache is fresh")
    ap.add_argument("--status",    action="store_true",
                    help="Show cache status")
    ap.add_argument("--check-ip",  metavar="IP",
                    help="Check whether an IP is a Tor relay or exit node")
    ap.add_argument("--cache",     default=DEFAULT_CACHE_PATH,
                    help=f"Cache file path (default: {DEFAULT_CACHE_PATH})")
    args = ap.parse_args()

    if args.update or (not args.status and not args.check_ip):
        TorUpdater(args.cache).update(force=args.force)

    if args.status:
        info = TorDetector(args.cache).status()
        for k, v in info.items():
            print(f"  {k:<20} {v}")

    if args.check_ip:
        detector = TorDetector(args.cache)
        hit = detector.check_connection(args.check_ip, "0.0.0.0")
        if hit["is_exit_node"]:
            print(f"  {args.check_ip}  →  TOR EXIT NODE")
        elif hit["is_tor_relay"]:
            print(f"  {args.check_ip}  →  Tor relay")
        else:
            print(f"  {args.check_ip}  →  not a Tor node")


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
