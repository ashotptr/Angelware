"""
====================================================
 Angelware — C2 TLS Certificate Field Detector
 Ported/adapted from: C2Detective (martinkubecka)
====================================================

Missing capability added to Angelware:
  C2Detective maintains a JSON database of known-malicious values
  embedded in TLS certificate fields (serial number, issuer CN/O/L/ST/C,
  subject CN/O/L/ST/C) by specific C2 frameworks, then runs tshark on
  the pcap to extract those fields and matches against the signatures.
  Angelware had tls_ja3.py (JA3 handshake hash) — completely different.

Known C2 framework certificate signatures:
  Cobalt Strike  → serialNumber = "146473198"
  Metasploit     → issuer/subject contains "MetasploitSelfSignedCA"
  Covenant       → issuer/subject contains "Covenant"
  Mythic         → issuer/subject contains "Mythic"
  PoshC2         → issuer/subject contains "P18055077"
  Sliver         → issuer/subject contains both "multiplayer" AND "operators"
                   (composite + match, e.g. SAN or OU field)

Two classes:
  C2CertDB      — loads/saves the JSON signature database
  C2CertDetector — extracts certs from a pcap via tshark and matches

Integration:
  Offline pcap  → called by pcap_ioc_extractor.py
  Live capture  → parse TLS cert fields from Scapy TLS layer (if available)
                  and call C2CertDetector.match_cert_entry()

CLI:
  python3 c2_tls_cert_detector.py --pcap capture.pcap
  python3 c2_tls_cert_detector.py --list-sigs
  python3 c2_tls_cert_detector.py --add-sig "NewFramework" "BadValue"
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Default paths ─────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.realpath(__file__))
DEFAULT_DB_PATH = os.path.join(_HERE, "c2_iocs", "c2_tls_certificate_values.json")

# ── Built-in signatures (mirrors C2Detective's database) ─────────────────────
BUILTIN_SIGNATURES: Dict[str, List[str]] = {
    "Cobalt Strike":         ["146473198"],
    "Metasploit Framework":  ["MetasploitSelfSignedCA"],
    "Covenant":              ["Covenant"],
    "Mythic":                ["Mythic"],
    "PoshC2":                ["P18055077"],
    "Sliver":                ["multiplayer+operators"],   # '+' = AND match
    # Additional community signatures not in original C2Detective:
    "Brute Ratel C4":        ["BruteRatelC4"],
    "Havoc C2":              ["havoc"],
    "SilverC2":              ["silver"],
    "Nighthawk":             ["nighthawk"],
}


# ── C2CertDB ──────────────────────────────────────────────────────────────────

class C2CertDB:
    """Load and persist the C2 TLS certificate signature database."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.signatures: Dict[str, List[str]] = {}
        self._load()

    # ------------------------------------------------------------------
    def _load(self):
        if os.path.exists(self.db_path):
            with open(self.db_path) as fh:
                self.signatures = json.load(fh)
            print(f"[{_ts()}] [INFO] C2 TLS cert DB loaded — "
                  f"{len(self.signatures)} frameworks from {self.db_path}")
        else:
            # Seed with built-ins on first run
            self.signatures = dict(BUILTIN_SIGNATURES)
            self._save()
            print(f"[{_ts()}] [INFO] C2 TLS cert DB initialised with "
                  f"{len(self.signatures)} built-in signatures → {self.db_path}")

    # ------------------------------------------------------------------
    def _save(self):
        with open(self.db_path, "w") as fh:
            json.dump(self.signatures, fh, indent=4)

    # ------------------------------------------------------------------
    def add_signature(self, framework: str, value: str):
        self.signatures.setdefault(framework, [])
        if value not in self.signatures[framework]:
            self.signatures[framework].append(value)
            self._save()
            print(f"[{_ts()}] [INFO] Added signature '{value}' for '{framework}'")
        else:
            print(f"[{_ts()}] [INFO] Signature already present")

    # ------------------------------------------------------------------
    def list_signatures(self):
        for fw, vals in self.signatures.items():
            print(f"  {fw}:")
            for v in vals:
                print(f"    - {v}")


# ── C2CertDetector ────────────────────────────────────────────────────────────

class C2CertDetector:
    """
    Detect known C2 framework TLS certificate signatures in a pcap.

    Two modes:
      1. pcap_file mode — uses tshark to extract cert fields from a file
      2. entry mode     — pass a pre-parsed cert dict for real-time checking
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db = C2CertDB(db_path)

    # ------------------------------------------------------------------
    def scan_pcap(self, pcap_path: str) -> List[Dict]:
        """
        Extract TLS certificates from pcap_path via tshark, then match.
        Returns a list of detected-cert dicts, each with:
          src_ip, dst_ip, src_port, dst_port,
          serialNumber, issuer, subject,
          c2_framework, malicious_value
        """
        print(f"[{_ts()}] [INFO] Extracting TLS certificates from {pcap_path} …")
        raw_certs = self._extract_via_tshark(pcap_path)
        print(f"[{_ts()}] [INFO] {len(raw_certs)} TLS certificates extracted")
        return self._match_all(raw_certs)

    # ------------------------------------------------------------------
    def match_cert_entry(self, cert: Dict) -> Optional[Dict]:
        """
        Check a single pre-parsed cert dict (from Scapy or tshark).
        Returns the cert dict augmented with c2_framework + malicious_value,
        or None if no match.
        """
        results = self._match_all([cert])
        return results[0] if results else None

    # ------------------------------------------------------------------
    # ── Internal helpers ──────────────────────────────────────────────

    def _match_all(self, certs: List[Dict]) -> List[Dict]:
        detected = []
        for cert in certs:
            serial       = cert.get("serialNumber", "")
            issuer_vals  = list(cert.get("issuer",  {}).values())
            subject_vals = list(cert.get("subject", {}).values())
            all_vals     = [serial] + issuer_vals + subject_vals

            for framework, mal_values in self.db.signatures.items():
                for mal_value in mal_values:
                    if self._value_matches(mal_value, serial, issuer_vals, subject_vals):
                        hit = dict(cert)
                        hit["c2_framework"]    = framework
                        hit["malicious_value"] = mal_value
                        detected.append(hit)
                        print(f"[{_ts()}] [ALERT] C2 TLS cert match — "
                              f"'{mal_value}' → {framework}  "
                              f"({hit.get('src_ip','?')}:{hit.get('src_port','?')} → "
                              f"{hit.get('dst_ip','?')}:{hit.get('dst_port','?')})")
                        break  # one match per framework per cert is enough

        if not detected:
            print(f"[{_ts()}] [INFO] No known C2 TLS certificate signatures detected")
        else:
            print(f"[{_ts()}] [ALERT] {len(detected)} C2 TLS certificate match(es) found")
        return detected

    # ------------------------------------------------------------------
    @staticmethod
    def _value_matches(
        mal_value: str,
        serial: str,
        issuer_vals: List[str],
        subject_vals: List[str],
    ) -> bool:
        """Handle plain match and composite '+' AND match."""
        all_fields = [serial] + issuer_vals + subject_vals

        if "+" in mal_value:
            parts = mal_value.split("+")
            return all(
                any(part in field for field in all_fields)
                for part in parts
            )
        else:
            return any(mal_value in field for field in all_fields)

    # ------------------------------------------------------------------
    def _extract_via_tshark(self, pcap_path: str) -> List[Dict]:
        """
        Run tshark on the pcap and parse TLS certificate fields.
        Returns a list of cert dicts (same schema as C2Detective).
        """
        cmd = (
            f'tshark -nr {pcap_path} '
            f'-Y "tls.handshake.certificate" -V'
        )
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as exc:
            print(f"[{_ts()}] [ERROR] tshark failed: {exc}")
            logger.error("tshark failed on %s: %s", pcap_path, exc)
            return []

        lines = output.decode("utf-8", errors="replace").splitlines()
        return self._parse_tshark_output(lines)

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_tshark_output(lines: List[str]) -> List[Dict]:
        """Parse tshark -V output into cert dicts. Mirrors C2Detective logic."""
        certs: List[Dict]       = []
        current: Dict           = {}
        cert_flag: str          = ""
        issuer_fields: Dict     = {}
        subject_fields: Dict    = {}

        _FIELD_PARSERS = {
            "emailAddress":         "emailAddress",
            "commonName":           "commonName",
            "organizationalUnitName": "organizationalUnitName",
            "organizationName":     "organizationName",
            "localityName":         "localityName",
            "stateOrProvinceName":  "stateOrProvinceName",
            "countryName":          "countryName",
        }

        for idx, line in enumerate(lines):
            stripped = line.lstrip()

            if stripped.startswith("Source Address"):
                current["src_ip"] = stripped.split()[-1]
            elif stripped.startswith("Destination Address"):
                current["dst_ip"] = stripped.split()[-1]
            elif stripped.startswith("Source Port"):
                current["src_port"] = stripped.split()[-1]
            elif stripped.startswith("Destination Port"):
                current["dst_port"] = stripped.split()[-1]
            elif stripped.startswith("serialNumber"):
                current["serialNumber"] = stripped.split()[-1]
            elif stripped.startswith("issuer"):
                issuer_fields = {}
                cert_flag = "issuer"
            elif stripped.startswith("subject"):
                subject_fields = {}
                cert_flag = "subject"
            elif stripped.startswith("rdnSequence"):
                rdn_values = re.findall(r"\((.*?)\)", stripped)
                try:
                    fields_str = rdn_values[0] if rdn_values else stripped.split()[-1]
                    field_entries = fields_str.split(",")
                except (IndexError, AttributeError):
                    field_entries = []

                for entry in field_entries:
                    for key, attr in _FIELD_PARSERS.items():
                        if key in entry:
                            val = entry.split(f"{key}=")[-1].replace(")", "").strip()
                            if cert_flag == "issuer":
                                issuer_fields[attr] = val
                            else:
                                subject_fields[attr] = val

                if cert_flag == "issuer":
                    current["issuer"] = issuer_fields
                elif cert_flag == "subject":
                    current["subject"] = subject_fields

            elif line.startswith("Frame") or idx == len(lines) - 1:
                if current:
                    current.setdefault("issuer",  {})
                    current.setdefault("subject", {})
                    current.setdefault("serialNumber", "")
                    certs.append(current)
                current = {}

        return certs


# ── helpers ──────────────────────────────────────────────────────────────────

def _ts() -> str:
    return time.strftime("%H:%M:%S")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        prog="c2_tls_cert_detector",
        description="C2 TLS certificate signature detector — Angelware add-on"
    )
    ap.add_argument("--pcap",      metavar="FILE",
                    help="Scan a pcap file for C2 TLS certificate signatures")
    ap.add_argument("--list-sigs", action="store_true",
                    help="List all loaded C2 certificate signatures")
    ap.add_argument("--add-sig",   nargs=2, metavar=("FRAMEWORK", "VALUE"),
                    help="Add a new signature value for a C2 framework")
    ap.add_argument("--db",        default=DEFAULT_DB_PATH,
                    help=f"Signature DB path (default: {DEFAULT_DB_PATH})")
    args = ap.parse_args()

    if args.list_sigs:
        db = C2CertDB(args.db)
        db.list_signatures()
        return

    if args.add_sig:
        db = C2CertDB(args.db)
        db.add_signature(args.add_sig[0], args.add_sig[1])
        return

    if args.pcap:
        detector = C2CertDetector(args.db)
        hits = detector.scan_pcap(args.pcap)
        if hits:
            print(f"\nDetected {len(hits)} malicious TLS certificate(s):")
            for h in hits:
                print(f"  [{h['c2_framework']}] value='{h['malicious_value']}' "
                      f"{h.get('src_ip')}:{h.get('src_port')} → "
                      f"{h.get('dst_ip')}:{h.get('dst_port')}")
        return

    ap.print_help()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
