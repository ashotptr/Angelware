#!/usr/bin/env python3
"""
====================================================
 Angelware — c2_ioc_updater.py
 IOC Cache Manager (ported from C2Detective)
====================================================

Consolidates the three independent C2Detective IOC updater scripts
(update_tor_nodes.py, update_crypto_domains.py, update_ja3_rules.py)
into a single importable module used by c2_analyzer.py.

The key addition is the Proofpoint Emerging Threats JA3 rules updater,
which was present in C2Detective but absent from Angelware.
Angelware's tls_ja3.py carried only a hardcoded KNOWN_BAD_JA3 dict;
this module fetches and caches the live Proofpoint rule set so the
JA3 detector stays current without code edits.

Also provides:
  check_staleness(path, max_age_seconds) → (is_stale, age_seconds)
  Used by c2_analyzer.py at startup to warn when caches need refresh,
  mirroring C2Detective's "recommend update every N minutes" behaviour.

Usage (standalone):
  python3 c2_ioc_updater.py --all
  python3 c2_ioc_updater.py --tor
  python3 c2_ioc_updater.py --crypto
  python3 c2_ioc_updater.py --ja3
  python3 c2_ioc_updater.py --status   # print age of every cache

Usage (from c2_analyzer.py):
  from c2_ioc_updater import TorNodesUpdater, CryptoDomainUpdater, JA3RulesUpdater
  from c2_ioc_updater import check_staleness, warn_if_stale
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from typing import Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# ── Default feed URLs (same sources C2Detective uses) ─────────────────────────
TOR_NODE_LIST_URL      = "https://www.dan.me.uk/torlist/"
TOR_EXIT_NODE_LIST_URL = "https://www.dan.me.uk/torlist/?exit"
CRYPTO_DOMAINS_URL     = "https://blocklistproject.github.io/Lists/alt-version/crypto-nl.txt"
JA3_RULES_URL          = (
    "https://rules.emergingthreats.net/open/suricata-5.0/rules/ja3-rules.txt"
)

# ── Staleness thresholds matching C2Detective ──────────────────────────────────
TOR_MAX_AGE_SEC    = 30 * 60          # Tor node list: 30 minutes
CRYPTO_MAX_AGE_SEC = 24 * 60 * 60    # Crypto domains: 24 hours
JA3_MAX_AGE_SEC    = 24 * 60 * 60    # JA3 rules: 24 hours


def _ts() -> str:
    return time.strftime("%H:%M:%S")


# ── Staleness helper ───────────────────────────────────────────────────────────

def check_staleness(path: str, max_age_seconds: int) -> Tuple[bool, float]:
    """
    Return (is_stale, age_seconds).
    is_stale is True when the file doesn't exist or is older than max_age_seconds.
    """
    if not os.path.exists(path):
        return True, float("inf")
    age = time.time() - os.path.getmtime(path)
    return age > max_age_seconds, age


def warn_if_stale(path: str, max_age_seconds: int, label: str, flag: str) -> None:
    """
    Print a staleness warning if the cache at *path* is older than *max_age_seconds*.
    *label*: human-readable name, e.g. "Tor node list".
    *flag*:  the CLI flag to refresh, e.g. "--update-tor".
    """
    stale, age = check_staleness(path, max_age_seconds)
    if not os.path.exists(path):
        print(f"[{_ts()}] [ERROR]  {label} cache not found at '{path}' "
              f"(run: python3 c2_analyzer.py {flag})")
        logging.error(f"{label} cache missing: {path}")
    elif stale:
        hours = age / 3600
        print(f"[{_ts()}] [INFO]   {label} cache is {hours:.1f}h old — "
              f"recommend refresh (python3 c2_analyzer.py {flag})")
        logging.info(f"{label} cache stale ({hours:.1f}h old)")
    else:
        print(f"[{_ts()}] [INFO]   {label} cache is up-to-date "
              f"({age/60:.0f} min old)")
        logging.info(f"{label} cache up-to-date ({age:.0f}s old)")


# ── Tor node updater ───────────────────────────────────────────────────────────

class TorNodesUpdater:
    """
    Fetches all Tor nodes and exit nodes from dan.me.uk and caches
    them as a JSON file with keys 'all_nodes' and 'exit_nodes'.
    Mirrors C2Detective's iocs/tor/update_tor_nodes.py::TorNodes.
    """

    def __init__(
        self,
        cache_path:          str,
        all_nodes_url:       str = TOR_NODE_LIST_URL,
        exit_nodes_url:      str = TOR_EXIT_NODE_LIST_URL,
    ):
        self.cache_path     = cache_path
        self.all_nodes_url  = all_nodes_url
        self.exit_nodes_url = exit_nodes_url

    def update(self, force: bool = False) -> bool:
        stale, _ = check_staleness(self.cache_path, TOR_MAX_AGE_SEC)
        if not stale and not force:
            print(f"[{_ts()}] [INFO]  Tor node cache is current — skipping update")
            return True

        print(f"[{_ts()}] [INFO]  Fetching Tor node list …")
        logging.info("Fetching Tor node list")
        try:
            r = requests.get(self.all_nodes_url, timeout=30)
            r.raise_for_status()
            all_nodes = [l for l in r.text.splitlines() if l.strip()]
        except Exception as exc:
            print(f"[{_ts()}] [ERROR] Tor node list fetch failed: {exc}")
            logging.error(f"Tor node list fetch failed: {exc}")
            return False

        print(f"[{_ts()}] [INFO]  Fetching Tor exit node list …")
        logging.info("Fetching Tor exit node list")
        try:
            r = requests.get(self.exit_nodes_url, timeout=30)
            r.raise_for_status()
            exit_nodes = [l for l in r.text.splitlines() if l.strip()]
        except Exception as exc:
            print(f"[{_ts()}] [ERROR] Tor exit node list fetch failed: {exc}")
            logging.error(f"Tor exit node list fetch failed: {exc}")
            return False

        if not all_nodes or not exit_nodes:
            print(f"[{_ts()}] [ERROR] Empty Tor node lists — aborting cache write")
            return False

        os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
        data = {"all_nodes": all_nodes, "exit_nodes": exit_nodes}
        with open(self.cache_path, "w") as fh:
            json.dump(data, fh, indent=2)
        print(f"[{_ts()}] [INFO]  Tor cache written: {len(all_nodes)} nodes, "
              f"{len(exit_nodes)} exit nodes → {self.cache_path}")
        logging.info(f"Tor cache written to {self.cache_path}")
        return True


# ── Crypto domain updater ──────────────────────────────────────────────────────

class CryptoDomainUpdater:
    """
    Fetches the BlocklistProject crypto domain list and caches it as
    {'crypto_domains': [...]} JSON.
    Mirrors C2Detective's iocs/crypto_domains/update_crypto_domains.py::CryptoDomains.
    """

    def __init__(self, cache_path: str, url: str = CRYPTO_DOMAINS_URL):
        self.cache_path = cache_path
        self.url        = url

    def update(self, force: bool = False) -> bool:
        stale, _ = check_staleness(self.cache_path, CRYPTO_MAX_AGE_SEC)
        if not stale and not force:
            print(f"[{_ts()}] [INFO]  Crypto domain cache is current — skipping")
            return True

        print(f"[{_ts()}] [INFO]  Fetching crypto/cryptojacking domain list …")
        logging.info("Fetching crypto domain list")
        try:
            r = requests.get(self.url, timeout=30)
            r.raise_for_status()
            domains = [
                line.strip() for line in r.text.splitlines()
                if line.strip() and not line.startswith("#")
            ]
        except Exception as exc:
            print(f"[{_ts()}] [ERROR] Crypto domain fetch failed: {exc}")
            logging.error(f"Crypto domain fetch failed: {exc}")
            return False

        if not domains:
            print(f"[{_ts()}] [ERROR] Empty crypto domain list — aborting")
            return False

        os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
        with open(self.cache_path, "w") as fh:
            json.dump({"crypto_domains": domains}, fh, indent=2)
        print(f"[{_ts()}] [INFO]  Crypto domain cache: {len(domains)} entries "
              f"→ {self.cache_path}")
        logging.info(f"Crypto domain cache written to {self.cache_path}")
        return True


# ── JA3 rules updater (NEW — absent from Angelware, present in C2Detective) ───

class JA3RulesUpdater:
    """
    Fetches Proofpoint Emerging Threats JA3 Suricata rules and caches
    them as {'ja3_rules': [{'type': ..., 'hash': ...}, ...]} JSON.

    This class is the primary addition over the original Angelware codebase:
      • tls_ja3.py used a hard-coded KNOWN_BAD_JA3 dict that never updated.
      • c2_analyzer.py had no --update-ja3-rules flag.
      • c2_analyzer.yml had no ja3_rules feed URL or cache path.
    All three gaps are resolved here and in the corresponding changes to
    c2_analyzer.py and c2_analyzer.yml.

    Mirrors C2Detective's iocs/ja3/update_ja3_rules.py::JA3Rules exactly,
    with the same regex pattern and the same "Fake Firefox Font Update" skip.
    """

    _PATTERN = re.compile(r'msg:"([^"]*)".*?ja3\.hash;\s*content:"([^"]*)"')
    _SKIP    = {"Fake Firefox Font Update"}

    def __init__(self, cache_path: str, url: str = JA3_RULES_URL):
        self.cache_path = cache_path
        self.url        = url

    def update(self, force: bool = False) -> bool:
        stale, _ = check_staleness(self.cache_path, JA3_MAX_AGE_SEC)
        if not stale and not force:
            print(f"[{_ts()}] [INFO]  JA3 rules cache is current — skipping")
            return True

        print(f"[{_ts()}] [INFO]  Fetching Proofpoint Emerging Threats JA3 rules …")
        logging.info("Fetching Proofpoint ET JA3 rules")
        try:
            r = requests.get(self.url, timeout=30)
            r.raise_for_status()
        except Exception as exc:
            print(f"[{_ts()}] [ERROR] JA3 rules fetch failed: {exc}")
            logging.error(f"JA3 rules fetch failed: {exc}")
            return False

        ja3_rules = []
        for line in r.iter_lines(decode_unicode=True):
            m = self._PATTERN.search(line)
            if not m:
                continue
            try:
                msg  = m.group(1).split("- ")[-1].strip()
                hash_ = m.group(2).strip()
                if msg in self._SKIP:
                    continue
                ja3_rules.append({"type": msg, "hash": hash_})
            except Exception:
                continue

        if not ja3_rules:
            print(f"[{_ts()}] [ERROR] No JA3 rules parsed — aborting cache write")
            logging.error("JA3 rules parse result was empty")
            return False

        os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
        with open(self.cache_path, "w") as fh:
            json.dump({"ja3_rules": ja3_rules}, fh, indent=2)
        print(f"[{_ts()}] [INFO]  JA3 rules cache: {len(ja3_rules)} rules "
              f"→ {self.cache_path}")
        logging.info(f"JA3 rules cache written to {self.cache_path}")
        return True

    def load(self) -> list:
        """Load cached rules; return list of {type, hash} dicts."""
        if not os.path.exists(self.cache_path):
            return []
        try:
            with open(self.cache_path) as fh:
                return json.load(fh).get("ja3_rules", [])
        except Exception:
            return []


# ── Status report ──────────────────────────────────────────────────────────────

def print_status(cfg: dict) -> None:
    """Print staleness status for all three IOC caches."""
    fp = cfg.get("file_paths", {})
    _HERE = os.path.dirname(os.path.realpath(__file__))

    def _abs(key, default):
        return os.path.join(_HERE, fp.get(key, default))

    caches = [
        (_abs("tor_node_cache",      "c2_iocs/tor_nodes.json"),
         TOR_MAX_AGE_SEC,    "Tor node list",         "--update-tor"),
        (_abs("crypto_domain_cache", "c2_iocs/crypto_domains.json"),
         CRYPTO_MAX_AGE_SEC, "Crypto domain list",    "--update-crypto"),
        (_abs("ja3_rules_cache",     "c2_iocs/ja3_rules.json"),
         JA3_MAX_AGE_SEC,    "JA3 rules (Proofpoint)", "--update-ja3-rules"),
    ]
    print(f"\n{'─'*60}")
    print(f"  IOC Cache Status")
    print(f"{'─'*60}")
    for path, max_age, label, flag in caches:
        stale, age = check_staleness(path, max_age)
        if not os.path.exists(path):
            status = "MISSING"
            detail = f"run c2_analyzer.py {flag}"
        elif stale:
            status = "STALE"
            detail = f"{age/3600:.1f}h old — refresh with c2_analyzer.py {flag}"
        else:
            status = "OK"
            detail = f"{age/60:.0f} min old"
        marker = "✅" if status == "OK" else "⚠️ " if status == "STALE" else "❌"
        print(f"  {marker}  {label:<28}  {status:<7}  {detail}")
    print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def _parse():
    ap = argparse.ArgumentParser(
        prog="c2_ioc_updater",
        description="Angelware IOC cache manager — Tor nodes, crypto domains, JA3 rules",
    )
    ap.add_argument("--all",    action="store_true", help="Update all three caches")
    ap.add_argument("--tor",    action="store_true", help="Update Tor node list")
    ap.add_argument("--crypto", action="store_true", help="Update crypto domain list")
    ap.add_argument("--ja3",    action="store_true", help="Update JA3 rules (Proofpoint ET)")
    ap.add_argument("--status", action="store_true", help="Print cache staleness status")
    return ap.parse_args(args=None if sys.argv[1:] else ["--help"])


def main():
    import yaml
    args = _parse()

    _HERE = os.path.dirname(os.path.realpath(__file__))
    cfg_path = os.path.join(_HERE, "config", "c2_analyzer.yml")
    cfg: dict = {}
    if os.path.exists(cfg_path):
        with open(cfg_path) as fh:
            cfg = yaml.safe_load(fh) or {}

    fp    = cfg.get("file_paths", {})
    feeds = cfg.get("feeds", {})

    def _abs(key, default):
        return os.path.join(_HERE, fp.get(key, default))

    if args.status:
        print_status(cfg)
        return

    if args.all or args.tor:
        TorNodesUpdater(
            cache_path=_abs("tor_node_cache", "c2_iocs/tor_nodes.json"),
            all_nodes_url=feeds.get("tor_node_list", TOR_NODE_LIST_URL),
            exit_nodes_url=feeds.get("tor_exit_node_list", TOR_EXIT_NODE_LIST_URL),
        ).update(force=True)

    if args.all or args.crypto:
        CryptoDomainUpdater(
            cache_path=_abs("crypto_domain_cache", "c2_iocs/crypto_domains.json"),
            url=feeds.get("crypto_domains", CRYPTO_DOMAINS_URL),
        ).update(force=True)

    if args.all or args.ja3:
        JA3RulesUpdater(
            cache_path=_abs("ja3_rules_cache", "c2_iocs/ja3_rules.json"),
            url=feeds.get("ja3_rules", JA3_RULES_URL),
        ).update(force=True)


if __name__ == "__main__":
    main()
