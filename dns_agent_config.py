"""
====================================================
 AUA CS 232/337 — Botnet Research Project
 Component: DNS Agent Config Builder + Validator
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching points implemented here:

1. COMPILE-TIME CONFIG VALIDATION (Spinnekop cmd/build/main.go)
   Spinnekop's build tool reads YAML → validates all fields at
   compile time → code-generates cmd/agent/config.go → cross-compiles.
   This Python equivalent: reads a YAML/JSON config, validates all
   fields (same rules as validate_request.go), and writes a locked-down
   Python config module that the agent imports.

   Validation rules (from Spinnekop internal/validate/validate_request.go):
   - resolver.ip:    valid IPv4 address format
   - resolver.port:  1–65535
   - header.id:      0–65535
   - header.z:       0–7  (RFC 1035: Z bits are 3-bit wide)
   - header.rcode:   0–15 (RFC 1035: RCODE is 4-bit wide)
   - question.type:  must be in QTYPE_MAP
   - question.class: if std_class=True, must be in QCLASS_MAP

2. MISSING DOCUMENTATION: docs/request_opts.md
   Spinnekop had an empty placeholder file:
     "Here add all the potential options for the fields in our agent's
      request / Later too will map this to what they really mean"
   This module fulfils that intent by:
   - Printing a complete field-reference table (--show-opts)
   - Documenting every valid opcode, qtype, qclass value
   - Showing the allowed ranges for header fields

3. DEFAULT CONFIGS
   Two templates matching Spinnekop's configs/ directory:
   - request_template:  for sending test queries (request.yaml equivalent)
   - agent_template:    for the embedded agent config (response.yaml equivalent)

Usage:
  # Validate a config file:
  python3 dns_agent_config.py --validate configs/dns_agent.yaml

  # Generate default agent config:
  python3 dns_agent_config.py --generate-agent > configs/dns_agent.yaml

  # Show all valid field options (fills request_opts.md gap):
  python3 dns_agent_config.py --show-opts

  # Build (validate + write locked agent_config_embedded.py):
  python3 dns_agent_config.py --build configs/dns_agent.yaml

  # Cross-compile targets info:
  python3 dns_agent_config.py --targets
"""

import json
import os
import re
import socket
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# ─── path bootstrap ──────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dns_zflag_crafter import (
    OPCODE_MAP, QTYPE_MAP, QCLASS_MAP, Z_COMMAND_MAP, RCODE_MAP,
)


# ─────────────────────────────────────────────────────────────
#  VALIDATION ERRORS
#  Mirrors Spinnekop internal/validate/validate_request.go
# ─────────────────────────────────────────────────────────────

class ValidationErrors(Exception):
    def __init__(self, errors: List[str]):
        self.errors = errors

    def __str__(self) -> str:
        lines = ["Configuration validation failed:"]
        for e in self.errors:
            lines.append(f"  - {e}")
        return "\n".join(lines)


def validate_request_config(cfg: Dict) -> List[str]:
    """
    Validate agent DNS request configuration.
    Returns list of error strings (empty = valid).
    Mirrors Spinnekop internal/validate/validate_request.go ValidateRequest().
    """
    errors: List[str] = []

    res  = cfg.get("resolver", {})
    hdr  = cfg.get("header",   {})
    q    = cfg.get("question", {})

    # ── Resolver ──────────────────────────────
    if not res.get("use_system_defaults", False):
        ip = res.get("ip", "")
        if not ip:
            errors.append("resolver.ip: not specified")
        else:
            try:
                socket.inet_aton(ip)
            except Exception:
                errors.append(f"resolver.ip: '{ip}' is not a valid IPv4 address")
        port = res.get("port", 0)
        if not (1 <= port <= 65535):
            errors.append(f"resolver.port: {port} out of valid range 1–65535")

    # ── Header ────────────────────────────────
    msg_id = hdr.get("id", 0)
    if not (0 <= msg_id <= 65535):
        errors.append(f"header.id: {msg_id} out of valid range 0–65535")

    opcode = hdr.get("opcode", "QUERY")
    if opcode not in OPCODE_MAP:
        errors.append(f"header.opcode: '{opcode}' not a valid opcode — "
                      f"valid: {list(OPCODE_MAP.keys())}")

    z = hdr.get("z", 0)
    if not (0 <= z <= 7):
        errors.append(f"header.z: {z} out of valid range 0–7 (3-bit field)")

    rcode = hdr.get("rcode", 0)
    if not (0 <= rcode <= 15):
        errors.append(f"header.rcode: {rcode} out of valid range 0–15 (4-bit field)")

    for flag in ("qr", "authoritative", "truncated", "recursion_desired",
                 "recursion_available"):
        v = hdr.get(flag)
        if v is not None and not isinstance(v, bool):
            errors.append(f"header.{flag}: must be true or false, got {type(v).__name__}")

    # ── Question ──────────────────────────────
    qtype = q.get("type", "")
    if qtype not in QTYPE_MAP:
        errors.append(f"question.type: '{qtype}' not a valid record type — "
                      f"common: A, AAAA, TXT, MX, NS, CNAME, SOA")

    name = q.get("name", "")
    if not name:
        errors.append("question.name: domain name cannot be empty")
    elif not re.match(r"^([a-zA-Z0-9*]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+$", name):
        errors.append(f"question.name: '{name}' does not look like a valid FQDN "
                      f"(must end with '.')")

    std_class = q.get("std_class", True)
    if std_class:
        qclass = q.get("class", "IN")
        if qclass not in QCLASS_MAP:
            errors.append(f"question.class: '{qclass}' not a valid standard class — "
                          f"valid: {list(QCLASS_MAP.keys())}")
    else:
        cclass = q.get("custom_class", 1)
        if not (0 <= cclass <= 65535):
            errors.append(f"question.custom_class: {cclass} out of range 0–65535")

    # ── Answers (for agent in response mode) ──
    for i, ans in enumerate(cfg.get("answers", [])):
        atype = ans.get("type", "")
        if atype not in QTYPE_MAP:
            errors.append(f"answers[{i}].type: '{atype}' not a valid record type")
        ttl = ans.get("ttl", 300)
        if not (0 <= ttl <= 2147483647):
            errors.append(f"answers[{i}].ttl: {ttl} out of valid range")

    return errors


def validate_and_raise(cfg: Dict) -> None:
    """Validate config, raising ValidationErrors if invalid."""
    errs = validate_request_config(cfg)
    if errs:
        raise ValidationErrors(errs)


# ─────────────────────────────────────────────────────────────
#  DEFAULT CONFIGURATION TEMPLATES
#  Mirrors Spinnekop configs/request.yaml + configs/response.yaml
# ─────────────────────────────────────────────────────────────

REQUEST_TEMPLATE: Dict = {
    "_comment": "DNS request template — edit before testing. Mirrors Spinnekop configs/request.yaml",
    "resolver": {
        "use_system_defaults": False,
        "ip":   "127.0.0.1",
        "port": 53,
    },
    "header": {
        "id":                  0,
        "qr":                  False,
        "opcode":              "QUERY",
        "authoritative":       False,
        "truncated":           False,
        "recursion_desired":   True,
        "recursion_available": False,
        "z":                   0,
        "rcode":               0,
    },
    "question": {
        "name":         "www.timeserversync.com.",
        "type":         "A",
        "class":        "IN",
        "std_class":    True,
        "custom_class": 1,
    },
}

AGENT_TEMPLATE: Dict = {
    "_comment": (
        "Agent embedded config — validate + build with dns_agent_config.py --build. "
        "Mirrors Spinnekop configs/response.yaml"
    ),
    "resolver": {
        "use_system_defaults": False,
        "ip":   "192.168.100.10",
        "port": 53,
    },
    "header": {
        "id":                  0,
        "qr":                  False,
        "opcode":              "QUERY",
        "authoritative":       False,
        "truncated":           False,
        "recursion_desired":   True,
        "recursion_available": False,
        "z":                   0,
        "rcode":               0,
    },
    "question": {
        "name":         "www.timeserversync.com.",
        "type":         "A",
        "class":        "IN",
        "std_class":    True,
        "custom_class": 1,
    },
    "http": {
        "server_url":   "http://192.168.100.10:8080",
        "target_file":  "dummy.zip",
        "chunk_size":   1048576,
    },
    "answers": [],
}


# ─────────────────────────────────────────────────────────────
#  EMBEDDED CONFIG WRITER
#  Mirrors Spinnekop cmd/build/main.go generateEmbeddedConfig()
#  + cmd/build/template.go configGoTemplate
# ─────────────────────────────────────────────────────────────

EMBEDDED_CONFIG_TEMPLATE = '''"""
Auto-generated by dns_agent_config.py on {timestamp}
DO NOT EDIT — regenerate via: python3 dns_agent_config.py --build <config.yaml>
Mirrors Spinnekop cmd/agent/config.go (generated by cmd/build/main.go)
"""

# ── Embedded Agent Configuration ─────────────────────────────
EMBEDDED_AGENT_CONFIG = {config_repr}

def get_embedded_agent_config() -> dict:
    """Return the embedded configuration dict. Called by dns_zflag_agent.py."""
    return EMBEDDED_AGENT_CONFIG
'''


def write_embedded_config(cfg: Dict, output_path: str) -> None:
    """
    Write a validated config as a locked-down Python module.
    Fixes Spinnekop: mirrors cmd/build/main.go generateEmbeddedConfig().
    """
    ts   = datetime.now().isoformat()
    body = EMBEDDED_CONFIG_TEMPLATE.format(
        timestamp   = ts,
        config_repr = json.dumps(cfg, indent=4),
    )
    with open(output_path, "w") as f:
        f.write(body)
    print(f"[build] ✅ Wrote embedded config → {output_path}")


# ─────────────────────────────────────────────────────────────
#  REQUEST OPTIONS DOCUMENTATION
#  Fills Spinnekop's empty docs/request_opts.md placeholder
# ─────────────────────────────────────────────────────────────

DNS_REQUEST_OPTS_DOC = """
# DNS Agent Request Configuration Options
# docs/dns_request_opts.md
# (Fills the empty Spinnekop docs/request_opts.md placeholder)
#
# This document maps every config field to its valid values,
# constraints, and wire-format meaning.

==============================================================
SECTION: resolver
==============================================================

Field: use_system_defaults (bool)
  true   — Auto-discover OS DNS resolver (reads /etc/resolv.conf
           on Linux/macOS, runs ipconfig /all on Windows)
  false  — Use manually specified ip + port

Field: ip (string, required if use_system_defaults=false)
  Valid: any IPv4 address in dotted-decimal notation
  Example: "192.168.100.10"

Field: port (integer, required if use_system_defaults=false)
  Valid: 1–65535
  DNS standard: 53

==============================================================
SECTION: header
==============================================================

Field: id (integer)
  Valid: 0–65535
  Special: 0 = generate a random ID per beacon (recommended)
  Wire: 16-bit big-endian, bytes 0–1 of DNS header

Field: qr (bool)
  false = QUERY   (agent sends queries)
  true  = RESPONSE (set to true in testing/simulation configs)
  Wire: bit 15 of flags field (byte 2)

Field: opcode (string)
  Valid values:
    "QUERY"    (0) — Standard DNS lookup
    "IQUERY"   (1) — Inverse query (deprecated RFC 3425)
    "STATUS"   (2) — Server status request
    "NOTIFY"   (4) — Zone change notification (RFC 1996)
    "UPDATE"   (5) — Dynamic DNS update (RFC 2136)
    "STATEFUL" (6) — DNS Stateful Operations (RFC 8490)
  Wire: bits 14–11 of flags field

Field: authoritative (bool)
  false = query (standard for agent queries)
  true  = authoritative answer (set by server, not client)
  Wire: bit 10 of flags field (AA flag)

Field: truncated (bool)
  false = normal (standard)
  true  = message truncated, client should retry over TCP
  Wire: bit 9 of flags field (TC flag)

Field: recursion_desired (bool)
  true  = ask resolver to recurse (standard)
  false = non-recursive query
  Wire: bit 8 of flags field (RD flag)

Field: recursion_available (bool)
  false = query (server sets this, not client)
  Wire: bit 7 of flags field (RA flag)

Field: z (integer) ← THE COVERT CHANNEL
  Valid: 0–7  (3 reserved bits, RFC 1035: "must be zero")
  Command meanings:
    0 = CONTINUE   — normal beaconing
    1 = SLEEP      — enter 1-hour extended sleep
    2 = ENUMERATE  — enable subdomain exfiltration encoding
    3 = HTTP_MODE  — switch to HTTPS exfil channel
    4 = RESERVED_4 — reserved, no action
    5 = RESERVED_5 — reserved, no action
    6 = RESERVED_6 — reserved, no action
    7 = TERMINATE  — agent self-terminates cleanly
  Wire: bits 6–4 of flags field (bytes 2–3)
  Clear mask: 0xFF8F  Set: flags |= (z & 0x07) << 4

Field: rcode (integer)
  Valid: 0–15  (4-bit RCODE field)
  Standard codes:
    0  = NOERROR   — no error
    1  = FORMERR   — format error
    2  = SERVFAIL  — server failure
    3  = NXDOMAIN  — name does not exist
    4  = NOTIMP    — not implemented
    5  = REFUSED   — query refused
    6  = YXDOMAIN  — name exists but shouldn't
    7  = YXRRSET   — RR set exists but shouldn't
    8  = NXRRSET   — RR set should exist but doesn't
    9  = NOTAUTH   — server not authoritative
   10  = NOTZONE   — name not in zone
   11–15 = Reserved (encodable, no standard meaning)
  Wire: bits 3–0 of flags field

==============================================================
SECTION: question
==============================================================

Field: name (string, FQDN)
  Must end with '.' (trailing dot = absolute FQDN)
  Max total length: 253 characters
  Max label length: 63 characters
  Example: "www.timeserversync.com."
  Z=2 mode: <base64_encoded_sysinfo>.timeserversync.com.

Field: type (string)
  Common record types:
    "A"      (1)   — IPv4 address lookup (standard for beaconing)
    "AAAA"   (28)  — IPv6 address lookup
    "TXT"    (16)  — Text record (common for data exfiltration)
    "MX"     (15)  — Mail exchange
    "NS"     (2)   — Name server
    "CNAME"  (5)   — Canonical name alias
    "SOA"    (6)   — Start of authority
    "PTR"    (12)  — Reverse DNS
    "ANY"    (255) — All records
  Wire: 16-bit integer in question section

Field: class (string)
  Standard classes (when std_class=true):
    "IN"  (1)   — Internet (standard; use this for all real traffic)
    "CS"  (2)   — CSNET (obsolete)
    "CH"  (3)   — CHAOS
    "HS"  (4)   — Hesiod
    "NO"  (254) — NONE (used in dynamic updates)
    "AN"  (255) — ANY class

Field: std_class (bool)
  true  = use the 'class' string field (standard)
  false = use custom_class raw integer (for non-standard class abuse)

Field: custom_class (integer, used when std_class=false)
  Valid: 0–65535
  Any uint16 value. Non-standard classes (e.g. 67) are
  a detection signal — see analyzer RDATA class warnings.

==============================================================
SECTION: http
==============================================================

Field: server_url (string)
  Base URL of the HTTP exfil server.
  Used by Z=3 HTTP_MODE command.
  Example: "http://192.168.100.10:8080"

Field: target_file (string)
  Local file path to exfiltrate when Z=3 is received.
  Example: "dummy.zip" or "/etc/passwd"

Field: chunk_size (integer)
  Base64 chunk size in bytes (before encoding).
  Default: 1048576 (1 MB)

==============================================================
SECTION: answers  (optional, for response-mode testing)
==============================================================

Field: answers (array of resource records)
  Each record:
    name  (string) — owner name (FQDN)
    type  (string) — record type (see question.type)
    class (string) — record class (see question.class)
    ttl   (integer, 0–2147483647) — time to live in seconds
    data  (string) — record data
      - For TXT: text string or hex-encoded binary
      - For A:   dotted-decimal IPv4 (e.g. "192.168.1.1")
"""


# ─────────────────────────────────────────────────────────────
#  YAML LOADER (with fallback to JSON)
# ─────────────────────────────────────────────────────────────

def load_config_file(path: str) -> Dict:
    """Load config from YAML or JSON file."""
    with open(path) as f:
        content = f.read()

    # Try YAML first
    try:
        import yaml
        return yaml.safe_load(content)
    except ImportError:
        pass

    # Fall back to JSON
    return json.loads(content)


def save_config_file(cfg: Dict, path: str) -> None:
    """Save config as YAML or JSON depending on extension."""
    try:
        import yaml
        with open(path, "w") as f:
            yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
    except ImportError:
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2)


# ─────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="DNS Agent Config Builder & Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--validate",    metavar="FILE",
                    help="Validate a config file and report errors")
    ap.add_argument("--build",       metavar="FILE",
                    help="Validate + write agent_config_embedded.py")
    ap.add_argument("--output",      metavar="FILE",
                    default="agent_config_embedded.py",
                    help="Output path for --build (default: agent_config_embedded.py)")
    ap.add_argument("--generate-agent", action="store_true",
                    help="Print default agent config to stdout")
    ap.add_argument("--generate-request", action="store_true",
                    help="Print default request template to stdout")
    ap.add_argument("--show-opts",   action="store_true",
                    help="Show all valid field options (request_opts documentation)")
    ap.add_argument("--targets",     action="store_true",
                    help="List supported build targets")
    args = ap.parse_args()

    if args.show_opts:
        print(DNS_REQUEST_OPTS_DOC)

    elif args.generate_agent:
        try:
            import yaml
            print(yaml.dump(AGENT_TEMPLATE, default_flow_style=False, sort_keys=False))
        except ImportError:
            print(json.dumps(AGENT_TEMPLATE, indent=2))

    elif args.generate_request:
        try:
            import yaml
            print(yaml.dump(REQUEST_TEMPLATE, default_flow_style=False, sort_keys=False))
        except ImportError:
            print(json.dumps(REQUEST_TEMPLATE, indent=2))

    elif args.validate:
        print(f"[build] Reading config from '{args.validate}'...")
        cfg  = load_config_file(args.validate)
        errs = validate_request_config(cfg)
        if errs:
            print(f"[build] ❌ Configuration is INVALID ({len(errs)} error(s)):")
            for e in errs:
                print(f"  - {e}")
            sys.exit(1)
        else:
            print("[build] ✅ Configuration is valid.")

    elif args.build:
        print(f"[build] 🕷  DNS Agent Config Build Process")
        print(f"[build] Reading YAML config from '{args.build}'...")
        cfg  = load_config_file(args.build)
        errs = validate_request_config(cfg)
        if errs:
            print(f"[build] ❌ Build Error — Configuration invalid:")
            for e in errs:
                print(f"  - {e}")
            sys.exit(1)
        print("[build] Configuration validated successfully ✅")
        write_embedded_config(cfg, args.output)
        print(f"[build] Build complete. Import in agent: "
              f"from {args.output[:-3]} import get_embedded_agent_config")

    elif args.targets:
        print("Supported platforms (Python is cross-platform by default):\n")
        targets = [
            ("current",      "Host OS/arch (python3)"),
            ("linux-amd64",  "Linux x86_64"),
            ("linux-arm64",  "Linux ARM64"),
            ("windows-amd64","Windows x64 (py2exe / PyInstaller)"),
            ("darwin-amd64", "macOS Intel"),
            ("darwin-arm64", "macOS Apple Silicon"),
        ]
        for t, desc in targets:
            print(f"  {t:<18} {desc}")
        print("\nTo bundle into a standalone executable:")
        print("  pip3 install pyinstaller")
        print("  pyinstaller --onefile dns_zflag_agent.py")

    else:
        ap.print_help()
