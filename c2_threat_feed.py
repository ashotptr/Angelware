"""
====================================================
 Angelware — C2 Threat Feed (C2Hunter Plugin port)
 Ported/adapted from: C2Detective (martinkubecka)
====================================================

Missing capability added to Angelware:
  C2Detective integrates with C2Hunter — a companion tool that builds a
  local SQLite database from three curated threat feeds and exposes them
  for bulk IOC matching against pcap-extracted indicators.

  Feeds replicated here:
    • Feodo Tracker (abuse.ch)  — active C2 IP addresses for banking
                                   malware (Emotet, QakBot, DridEx, …)
    • URLhaus     (abuse.ch)    — malicious URLs and their host IPs
    • ThreatFox   (abuse.ch)    — multi-malware IOC database:
                                   IP:port, domain, URL type entries

  Two classes:
    C2FeedUpdater  — downloads feeds, creates/updates SQLite DB
    C2ThreatFeed   — queries DB for matches against extracted IOC lists

  This gives Angelware a local, offline-capable, regularly-updated
  C2 threat intelligence layer that does NOT require API keys.

DB schema:
  feodotracker  (ip_address TEXT, port INT, malware TEXT, first_seen TEXT, last_seen TEXT)
  urlhaus       (url TEXT, host TEXT, tags TEXT, first_seen TEXT, url_status TEXT)
  threatfox     (ioc TEXT, ioc_type TEXT, malware TEXT, confidence INT, first_seen TEXT)

CLI:
  python3 c2_threat_feed.py --update        # refresh all feeds
  python3 c2_threat_feed.py --update --feed feodo
  python3 c2_threat_feed.py --status
  python3 c2_threat_feed.py --query-ip 185.220.101.50
  python3 c2_threat_feed.py --query-domain cobaltstrike.evil.com
  python3 c2_threat_feed.py --query-url http://evil.com/gate.php
"""

import argparse
import csv
import io
import json
import logging
import os
import re
import sqlite3
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

_HERE     = os.path.dirname(os.path.realpath(__file__))
DB_PATH   = os.path.join(_HERE, "c2_iocs", "c2_threat_feed.db")

FEODO_URL    = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
URLHAUS_URL  = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

CHUNK_SIZE = 500  # rows per SQLite query


def _ts() -> str:
    return time.strftime("%H:%M:%S")


# ═══════════════════════════════════════════════════════════════════════════════
#  DATABASE BOOTSTRAP
# ═══════════════════════════════════════════════════════════════════════════════

def _init_db(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur  = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS feodotracker (
        ip_address TEXT NOT NULL,
        port       INTEGER,
        malware    TEXT,
        first_seen TEXT,
        last_seen  TEXT,
        PRIMARY KEY (ip_address, port)
    );
    CREATE TABLE IF NOT EXISTS urlhaus (
        url        TEXT PRIMARY KEY,
        host       TEXT,
        tags       TEXT,
        first_seen TEXT,
        url_status TEXT
    );
    CREATE TABLE IF NOT EXISTS threatfox (
        ioc        TEXT PRIMARY KEY,
        ioc_type   TEXT,
        malware    TEXT,
        confidence INTEGER,
        first_seen TEXT
    );
    CREATE TABLE IF NOT EXISTS feed_metadata (
        feed       TEXT PRIMARY KEY,
        updated_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_feodo_ip    ON feodotracker(ip_address);
    CREATE INDEX IF NOT EXISTS idx_urlhaus_host ON urlhaus(host);
    CREATE INDEX IF NOT EXISTS idx_threatfox_type ON threatfox(ioc_type);
    """)
    conn.commit()
    return conn


# ═══════════════════════════════════════════════════════════════════════════════
#  C2 FEED UPDATER
# ═══════════════════════════════════════════════════════════════════════════════

class C2FeedUpdater:
    """Download threat feeds and populate the local SQLite database."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path

    # ------------------------------------------------------------------
    def update_all(self):
        print(f"[{_ts()}] [INFO] Updating all C2 threat feeds …")
        self.update_feodotracker()
        self.update_urlhaus()
        self.update_threatfox()

    # ------------------------------------------------------------------
    def update_feodotracker(self):
        print(f"[{_ts()}] [INFO] Fetching Feodo Tracker IP blocklist …")
        try:
            resp = requests.get(FEODO_URL, timeout=30)
            resp.raise_for_status()
        except Exception as e:
            print(f"[{_ts()}] [ERROR] Feodo Tracker fetch failed: {e}")
            return

        conn = _init_db(self.db_path)
        cur  = conn.cursor()
        count = 0

        reader = csv.reader(
            line for line in resp.text.splitlines() if not line.startswith("#")
        )
        # CSV: first_seen, dst_ip, dst_port, c2_status, malware
        for row in reader:
            if len(row) < 5:
                continue
            first_seen, ip_address, port, _status, malware = row[:5]
            try:
                cur.execute(
                    "INSERT OR REPLACE INTO feodotracker "
                    "(ip_address, port, malware, first_seen, last_seen) "
                    "VALUES (?,?,?,?,?)",
                    (ip_address.strip(), int(port.strip()) if port.strip().isdigit() else None,
                     malware.strip(), first_seen.strip(),
                     datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
                )
                count += 1
            except Exception:
                continue

        cur.execute(
            "INSERT OR REPLACE INTO feed_metadata VALUES ('feodotracker', ?)",
            (datetime.utcnow().isoformat() + "Z",),
        )
        conn.commit()
        conn.close()
        print(f"[{_ts()}] [INFO] Feodo Tracker: {count} C2 IPs indexed")

    # ------------------------------------------------------------------
    def update_urlhaus(self):
        print(f"[{_ts()}] [INFO] Fetching URLhaus recent URLs …")
        try:
            resp = requests.get(URLHAUS_URL, timeout=60)
            resp.raise_for_status()
        except Exception as e:
            print(f"[{_ts()}] [ERROR] URLhaus fetch failed: {e}")
            return

        conn = _init_db(self.db_path)
        cur  = conn.cursor()
        count = 0

        # URLhaus CSV: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        lines = [l for l in resp.text.splitlines() if not l.startswith("#")]
        reader = csv.reader(lines)
        for row in reader:
            if len(row) < 6:
                continue
            try:
                _id, date_added, url, url_status, _last, threat, *rest = row
                tags = rest[0] if rest else ""
                # Extract host from URL
                host_match = re.search(r"https?://([^/:?#\s]+)", url)
                host = host_match.group(1) if host_match else ""
                cur.execute(
                    "INSERT OR REPLACE INTO urlhaus "
                    "(url, host, tags, first_seen, url_status) VALUES (?,?,?,?,?)",
                    (url.strip(), host, tags.strip(),
                     date_added.strip(), url_status.strip()),
                )
                count += 1
            except Exception:
                continue

        cur.execute(
            "INSERT OR REPLACE INTO feed_metadata VALUES ('urlhaus', ?)",
            (datetime.utcnow().isoformat() + "Z",),
        )
        conn.commit()
        conn.close()
        print(f"[{_ts()}] [INFO] URLhaus: {count} malicious URLs indexed")

    # ------------------------------------------------------------------
    def update_threatfox(self):
        print(f"[{_ts()}] [INFO] Fetching ThreatFox recent IOCs (last 7 days) …")
        try:
            resp = requests.post(
                THREATFOX_URL,
                data=json.dumps({"query": "get_iocs", "days": 7}),
                timeout=60,
            )
            data = resp.json()
        except Exception as e:
            print(f"[{_ts()}] [ERROR] ThreatFox fetch failed: {e}")
            return

        if data.get("query_status") != "ok":
            print(f"[{_ts()}] [WARNING] ThreatFox returned: {data.get('query_status')}")
            return

        iocs  = data.get("data", [])
        conn  = _init_db(self.db_path)
        cur   = conn.cursor()
        count = 0

        for entry in iocs:
            try:
                cur.execute(
                    "INSERT OR REPLACE INTO threatfox "
                    "(ioc, ioc_type, malware, confidence, first_seen) VALUES (?,?,?,?,?)",
                    (entry.get("ioc", ""),
                     entry.get("ioc_type", ""),
                     entry.get("malware_printable", ""),
                     entry.get("confidence_level", 0),
                     entry.get("first_seen", "")),
                )
                count += 1
            except Exception:
                continue

        cur.execute(
            "INSERT OR REPLACE INTO feed_metadata VALUES ('threatfox', ?)",
            (datetime.utcnow().isoformat() + "Z",),
        )
        conn.commit()
        conn.close()
        print(f"[{_ts()}] [INFO] ThreatFox: {count} IOCs indexed")


# ═══════════════════════════════════════════════════════════════════════════════
#  C2 THREAT FEED QUERY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class C2ThreatFeed:
    """
    Query the local SQLite threat feed database for matches against IOC lists.

    Usage:
        feed = C2ThreatFeed()
        results = feed.scan_all(ip_list, domain_list, url_list)
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path   = db_path
        self.chunk_size = CHUNK_SIZE
        if not os.path.exists(db_path):
            print(f"[{_ts()}] [WARNING] Threat feed DB not found at {db_path}. "
                  "Run: python3 c2_threat_feed.py --update")

    # ------------------------------------------------------------------
    def scan_all(
        self,
        ip_list:     List[str],
        domain_list: List[str],
        url_list:    List[str],
    ) -> Dict[str, object]:
        """
        Returns {
            "c2_ips":           [ip, ...],       # Feodo + URLhaus + ThreatFox hits
            "potential_c2_ips": [ip, ...],       # broader ThreatFox IP:port matches
            "c2_domains":       [domain, ...],
            "c2_urls":          [url, ...],
            "c2_ip_connections": [...],          # populated by caller using external TCP list
        }
        """
        print(f"[{_ts()}] [INFO] Querying C2 threat feed — "
              f"{len(ip_list)} IPs, {len(domain_list)} domains, {len(url_list)} URLs …")

        confirmed_ips = self._query_confirmed_ips(ip_list)
        potential_ips = self._query_potential_ips(ip_list)
        domains       = self._query_domains(domain_list)
        urls          = self._query_urls(url_list)

        self._print_results("Confirmed C2 IP addresses", confirmed_ips)
        self._print_results("Potential C2 IP addresses", potential_ips)
        self._print_results("C2 domain names", domains)
        self._print_results("C2 URLs", urls)

        return {
            "c2_ips":           confirmed_ips,
            "potential_c2_ips": potential_ips,
            "c2_domains":       domains,
            "c2_urls":          urls,
        }

    # ------------------------------------------------------------------
    def _chunked_query(self, conn, query_template: str, items: List[str]) -> List:
        results = []
        cur = conn.cursor()
        for i in range(0, len(items), self.chunk_size):
            chunk = items[i:i + self.chunk_size]
            query = query_template.format(
                placeholders=",".join("?" * len(chunk))
            )
            cur.execute(query, chunk)
            results.extend(cur.fetchall())
        return results

    # ------------------------------------------------------------------
    def _query_confirmed_ips(self, ips: List[str]) -> List[str]:
        if not ips or not os.path.exists(self.db_path):
            return []
        conn = sqlite3.connect(self.db_path)
        hits: List[str] = []

        # Feodo Tracker
        q = "SELECT ip_address FROM feodotracker WHERE ip_address IN ({placeholders})"
        hits += [r[0] for r in self._chunked_query(conn, q, ips)]

        # URLhaus — IPs embedded in URLs
        url_q = ("SELECT url FROM urlhaus WHERE ("
                 + " OR ".join(["url LIKE ?"] * min(len(ips), self.chunk_size))
                 + ")")
        for i in range(0, len(ips), self.chunk_size):
            chunk = ips[i:i + self.chunk_size]
            like_params = [f"%{ip}%" for ip in chunk]
            conn.cursor().execute(
                "SELECT url FROM urlhaus WHERE " +
                " OR ".join(["url LIKE ?"] * len(chunk)), like_params
            )
            for (url,) in conn.cursor().fetchall():
                m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", url)
                if m:
                    hits.append(m.group(0))

        # ThreatFox
        tf_q = ("SELECT ioc FROM threatfox WHERE ioc_type IN ('ip:port','ip') "
                "AND ({placeholders})")
        for i in range(0, len(ips), self.chunk_size):
            chunk = ips[i:i + self.chunk_size]
            cur = conn.cursor()
            cur.execute(
                "SELECT ioc FROM threatfox WHERE ioc_type IN ('ip:port','ip') AND ("
                + " OR ".join(["ioc LIKE ?"] * len(chunk)) + ")",
                [f"%{ip}%" for ip in chunk],
            )
            for (ioc,) in cur.fetchall():
                m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", ioc)
                if m:
                    hits.append(m.group(0))

        conn.close()
        return list(set(hits))

    # ------------------------------------------------------------------
    def _query_potential_ips(self, ips: List[str]) -> List[str]:
        """IPs that appear in the broader Shodan/ThreatFox dataset but are not
        confirmed C2 (lower confidence threshold)."""
        if not ips or not os.path.exists(self.db_path):
            return []
        conn = sqlite3.connect(self.db_path)
        hits = []
        for i in range(0, len(ips), self.chunk_size):
            chunk = ips[i:i + self.chunk_size]
            cur = conn.cursor()
            cur.execute(
                "SELECT ioc FROM threatfox WHERE confidence < 75 AND ("
                + " OR ".join(["ioc LIKE ?"] * len(chunk)) + ")",
                [f"%{ip}%" for ip in chunk],
            )
            for (ioc,) in cur.fetchall():
                m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", ioc)
                if m:
                    hits.append(m.group(0))
        conn.close()
        return list(set(hits))

    # ------------------------------------------------------------------
    def _query_domains(self, domains: List[str]) -> List[str]:
        if not domains or not os.path.exists(self.db_path):
            return []
        conn = sqlite3.connect(self.db_path)
        q = ("SELECT ioc FROM threatfox WHERE ioc_type='domain' "
             "AND ioc IN ({placeholders})")
        hits = [r[0] for r in self._chunked_query(conn, q, domains)]
        conn.close()
        return list(set(hits))

    # ------------------------------------------------------------------
    def _query_urls(self, urls: List[str]) -> List[str]:
        if not urls or not os.path.exists(self.db_path):
            return []
        conn = sqlite3.connect(self.db_path)
        hits = []
        for i in range(0, len(urls), self.chunk_size):
            chunk = urls[i:i + self.chunk_size]
            cur = conn.cursor()
            cur.execute(
                "SELECT url FROM urlhaus WHERE "
                + " OR ".join(["url LIKE ?"] * len(chunk)),
                [f"%{u}%" for u in chunk],
            )
            hits += [r[0] for r in cur.fetchall()]
            cur.execute(
                "SELECT ioc FROM threatfox WHERE ioc_type='url' AND ("
                + " OR ".join(["ioc LIKE ?"] * len(chunk)) + ")",
                [f"%{u}%" for u in chunk],
            )
            hits += [r[0] for r in cur.fetchall()]
        conn.close()
        return list(set(hits))

    # ------------------------------------------------------------------
    @staticmethod
    def _print_results(label: str, items: List[str]):
        if items:
            print(f"[{_ts()}] [ALERT] {label} detected — {len(items)} match(es):")
            for item in items:
                print(f"  {item}")
        else:
            print(f"[{_ts()}] [INFO] {label}: no matches")

    # ------------------------------------------------------------------
    def status(self) -> Dict:
        if not os.path.exists(self.db_path):
            return {"db_path": self.db_path, "status": "missing"}
        conn = sqlite3.connect(self.db_path)
        cur  = conn.cursor()
        counts = {}
        for table in ("feodotracker", "urlhaus", "threatfox"):
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            counts[table] = cur.fetchone()[0]

        metadata: Dict[str, str] = {}
        try:
            cur.execute("SELECT feed, updated_at FROM feed_metadata")
            for feed, ts in cur.fetchall():
                metadata[feed] = ts
        except Exception:
            pass

        conn.close()
        return {
            "db_path":   self.db_path,
            "counts":    counts,
            "updated_at": metadata,
            "db_size_kb": round(os.path.getsize(self.db_path) / 1024, 1),
        }


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        prog="c2_threat_feed",
        description="C2 Threat Feed (Feodo/URLhaus/ThreatFox) — Angelware add-on"
    )
    ap.add_argument("--update",       action="store_true",
                    help="Update all threat feeds")
    ap.add_argument("--feed",         choices=["feodo", "urlhaus", "threatfox"],
                    help="Update only a specific feed")
    ap.add_argument("--status",       action="store_true",
                    help="Show DB status and record counts")
    ap.add_argument("--query-ip",     metavar="IP",
                    help="Query a single IP against all feeds")
    ap.add_argument("--query-domain", metavar="DOMAIN",
                    help="Query a single domain against ThreatFox")
    ap.add_argument("--query-url",    metavar="URL",
                    help="Query a single URL against URLhaus + ThreatFox")
    ap.add_argument("--db",           default=DB_PATH,
                    help=f"DB path (default: {DB_PATH})")
    args = ap.parse_args()

    updater = C2FeedUpdater(args.db)
    feed    = C2ThreatFeed(args.db)

    if args.update:
        if args.feed == "feodo":
            updater.update_feodotracker()
        elif args.feed == "urlhaus":
            updater.update_urlhaus()
        elif args.feed == "threatfox":
            updater.update_threatfox()
        else:
            updater.update_all()
        return

    if args.status:
        info = feed.status()
        print(f"  db_path    {info['db_path']}")
        print(f"  db_size    {info.get('db_size_kb','?')} KB")
        for table, count in info.get("counts", {}).items():
            ts = info.get("updated_at", {}).get(table, "never")
            print(f"  {table:<16} {count:>8} rows  (updated: {ts})")
        return

    if args.query_ip:
        r = feed.scan_all([args.query_ip], [], [])
        print(json.dumps(r, indent=2))
        return

    if args.query_domain:
        r = feed.scan_all([], [args.query_domain], [])
        print(json.dumps(r, indent=2))
        return

    if args.query_url:
        r = feed.scan_all([], [], [args.query_url])
        print(json.dumps(r, indent=2))
        return

    ap.print_help()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
