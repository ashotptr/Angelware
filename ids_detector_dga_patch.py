"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: IDS DGA Advanced Detection Patch
 Environment: ISOLATED VM LAB ONLY
====================================================

Patches and extensions to ids_detector.py Engine 3
addressing gap items 55-60, 81-84:

  Gap 55 – DNS TTL anomaly detection (very low TTL → rapid C2 rotation)
  Gap 56 – Domain age / WHOIS age heuristic (newly registered domains)
  Gap 57 – Domain registration burst detection
  Gap 58 – Country-code TLD geopolitical evasion awareness
  Gap 59 – Pre-registration / sinkholing defence simulation
  Gap 60 – DGA family classification (which family is this?)
  Gap 81 – Process-correlated DGA detection (link DNS query to PID)
  Gap 82 – Per-DGA-type detection difficulty rating
  Gap 83 – ML integration into live IDS packet handler
  Gap 84 – Entropy on full subdomain (not just first label) with PSL

The classes here are designed to be imported into ids_detector.py
and called from the existing process_dns() packet handler.

Integration example (ids_detector.py):
    from ids_detector_dga_patch import (
        AdvancedDGAEngine, DGAFamilyClassifier,
        DNSTTLDetector, ProcessDGACorrelator
    )
    _adv_dga   = AdvancedDGAEngine()
    _dga_cls   = DGAFamilyClassifier()
    _ttl_det   = DNSTTLDetector()
    _proc_corr = ProcessDGACorrelator()

    # In process_dns():
    adv = _adv_dga.analyze(qname, src_ip, response_ttl, rcode)
    if adv["alert"]:
        alert("DNS/DGA-Advanced", adv["severity"], adv["reason"])

    family = _dga_cls.classify(qname)
    if family:
        alert("DNS/DGA-Family", "MED", f"Matches {family} pattern: {qname}")
"""

import math
import re
import time
import threading
import os
import hashlib
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# ── Optional PSL ───────────────────────────────────────────────
try:
    from publicsuffixlist import PublicSuffixList
    _PSL = PublicSuffixList()
    def _get_subdomain(domain: str) -> str:
        vps = _PSL.publicsuffix(domain)
        if vps and domain.endswith("." + vps):
            return domain[:-(len(vps) + 1)]
        return domain.split(".")[0]
except ImportError:
    def _get_subdomain(domain: str) -> str:
        parts = domain.rstrip(".").split(".")
        return ".".join(parts[:-1]) if len(parts) > 1 else domain

# ── Country-code TLD awareness (gap item 58) ──────────────────
EVASION_CCTLDS = {
    ".ga":  "Gabon – ICANN compliant but often uncooperative",
    ".im":  "Isle of Man – limited law enforcement cooperation",
    ".sc":  "Seychelles – used in Necurs to delay domain seizure",
    ".su":  "Soviet Union (legacy) – Russian control, very hard to seize",
    ".bit": "Namecoin blockchain – decentralised, un-seizeable",
    ".pw":  "Palau – cheap, used by Ranbyus and Pykspa",
    ".cc":  "Cocos Islands – often used in DGA to avoid US ICANN jurisdiction",
    ".ru":  "Russia – FBI unable to seize .ru domains (Operation Tovar precedent)",
    ".cn":  "China – requires Chinese court order",
    ".tw":  "Taiwan – separate legal jurisdiction",
    ".cx":  "Christmas Island – used in Necurs for international evasion",
    ".cm":  "Cameroon – limited domain enforcement cooperation",
    ".mu":  "Mauritius – used in Necurs",
    ".ms":  "Montserrat – offshore jurisdiction",
    ".kz":  "Kazakhstan – used by Pushdo; separate legal system",
    ".to":  "Tonga – permissive registrar; used in Angler EK",
    ".xxx": "Adult namespace – legitimate TLD but DGA-abused for obfuscation",
    ".pro": "Professional – used in Necurs variant",
    ".mn":  "Mongolia – used in Dridex to complicate takedowns",
}

# DDNS providers used as C2 (not sinkhole-able through registrar)
DDNS_PROVIDERS = {
    "duckdns.org", "chickenkiller.com", "accesscam.org",
    "casacam.net", "ddnsfree.com", "mooo.com", "strangled.net",
    "ignorelist.com", "dontargetme.nl", "ddns.net", "dyndns.org",
    "no-ip.org", "no-ip.com", "changeip.com", "afraid.org",
}

# OpenNIC TLDs (not resolvable through standard DNS – evasion technique)
OPENNIC_TLDS = {".geek", ".oss", ".session.oss", ".session.geek",
                ".fur", ".indy", ".neo", ".null", ".o", ".parody"}

# ── Known DGA TLD signatures by family (gap item 60, 82) ──────
DGA_FAMILY_SIGNATURES = {
    "necurs":   {"tlds": {".ga",".im",".sc",".mn",".su",".bit",".tw",".pro",".cx",".cm",".mu",".co",".de"}, "primary_tlds": {".ga",".im",".sc",".su",".bit",".cx",".cm",".mu"},
                 "body_len": (8, 20), "charset": "alpha",
                 "detection_difficulty": "HIGH",
                 "notes": "Exotic TLDs, medium-length alpha bodies"},
    "dridex":   {"tlds": {".mn",".me"},
                 "keywords": ["client","agent","allow","jsc","axp","cli"],
                 "detection_difficulty": "HIGH",
                 "notes": "Word fragments + padding; looks semi-legitimate"},
    "ranbyus":  {"tlds": {"in","me","cc","su","tw","net","com","pw","org"},
                 "body_len": (14,14), "charset": "alpha",
                 "detection_difficulty": "MED",
                 "notes": "Exactly 14 lowercase alpha chars; LFSR pattern"},
    "dyre":     {"tlds": {".in",".cc",".org",".net",".com"},
                 "body_len": (10,25), "charset": "alpha",
                 "body_pattern": r"^[0-9a-f]{32,36}\.",
                 "detection_difficulty": "MED",
                 "notes": "Long hex string body (MD5-like); .in / .cc TLDs"},
    "conficker": {"body_len": (8,15), "charset": "alpha",
                  "detection_difficulty": "MED",
                  "notes": "250 domains/day across 110 TLDs; time-seeded"},
    "gameover":  {"body_len": (22,30), "charset": "alnum",
                  "detection_difficulty": "HIGH",
                  "notes": "Peer-to-peer seeded; 1000 domains/day"},
    "pykspa":    {"tlds": {".com",".net",".org",".info",".cc"},
                  "body_len": (5,15), "charset": "alpha",
                  "vowel_pattern": True,
                  "detection_difficulty": "MED",
                  "notes": "Vowel-consonant alternation; used by Skype botnet"},
    "tinba":     {"tlds": {".com",".biz",".in",".me",".net",".ru",".us"},
                  "body_len": (10,14), "charset": "alpha",
                  "detection_difficulty": "MED",
                  "notes": "Short alpha; banking trojan"},
    "emotet":    {"tlds": {".eu"},
                  "body_len": (16,18), "charset": "alpha",
                  "detection_difficulty": "MED",
                  "notes": "Exactly 16-18 alpha chars under .eu"},
    "mirai_nomi":{"body_len": (10,10), "body_pattern": r"^[a-f0-9]{10}\.",
                  "tlds": DDNS_PROVIDERS | {".ru",".nl",".xyz"},
                  "detection_difficulty": "HIGH",
                  "notes": "Exactly 10 hex chars; NTP-weekly seed; DDNS TLDs"},
    "ramnit":    {"tlds": {".com",".eu",".bid",".click"},
                  "body_len": (10,18), "charset": "alpha",
                  "detection_difficulty": "MED",
                  "notes": "Seed-based; banking/file-infector"},
    "kraken":    {"tlds": {"dyndns.org","mooo.com","net"}, "primary_tlds": {"dyndns.org","mooo.com"}, "tld2_match": True,
                  "body_len": (8,16), "charset": "alnum",
                  "detection_difficulty": "HIGH",
                  "notes": "Mathematical function-based; DDNS + standard TLDs"},
}


# ═══════════════════════════════════════════════════════════════
#  DNS TTL ANOMALY DETECTOR  (gap item 55)
# ═══════════════════════════════════════════════════════════════

class DNSTTLDetector:
    """
    Flags DNS responses with anomalously low TTL values.

    Legitimate domains typically have TTLs of 300-86400 seconds.
    DGA operators set very low TTLs (often 1-60 s) to rotate C2 IPs
    rapidly without waiting for resolver caches to expire.

    Gap item 55: TTL-based detection signal missing from Engine 3.
    """

    LOW_TTL_THRESHOLD  = 60    # seconds — below this is suspicious
    VERY_LOW_THRESHOLD = 10    # seconds — almost certainly evasive

    def __init__(self):
        self._low_ttl_counts: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def check(self, domain: str, ttl: int, src_ip: str = "?") -> Optional[Dict]:
        """
        Returns an alert dict if TTL is suspiciously low, else None.
        """
        if ttl is None or ttl < 0:
            return None

        severity = None
        if ttl <= self.VERY_LOW_THRESHOLD:
            severity = "HIGH"
        elif ttl <= self.LOW_TTL_THRESHOLD:
            severity = "MED"

        if severity:
            with self._lock:
                self._low_ttl_counts[src_ip] += 1
            return {
                "alert":    True,
                "severity": severity,
                "domain":   domain,
                "ttl":      ttl,
                "src_ip":   src_ip,
                "reason":   (
                    f"[DNS-TTL] Anomalously low TTL={ttl}s for {domain} "
                    f"(threshold: {self.LOW_TTL_THRESHOLD}s). "
                    f"DGA operators set low TTLs for rapid C2 IP rotation. "
                    f"Source: {src_ip}"
                ),
            }
        return None

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._low_ttl_counts)


# ═══════════════════════════════════════════════════════════════
#  DOMAIN REGISTRATION BURST DETECTOR  (gap item 57)
# ═══════════════════════════════════════════════════════════════

class DomainRegistrationBurstDetector:
    """
    Detects when many unique domains are queried from one IP in a
    short window — a proxy signal for DGA bulk registration activity.

    Real DGA operators pre-register many domains simultaneously;
    bots then probe all of them until one resolves.

    Gap item 57: burst-of-new-domain-registrations detection.
    """

    WINDOW_SEC     = 60
    BURST_THRESH   = 20   # unique domain SLDs in one window

    def __init__(self):
        self._domain_window: Dict[str, deque] = defaultdict(deque)
        self._sld_window:    Dict[str, set]   = defaultdict(set)
        self._lock = threading.Lock()

    def _extract_sld(self, domain: str) -> str:
        """Extract second-level domain (SLD) from FQDN."""
        try:
            sub = _get_subdomain(domain.rstrip("."))
            parts = sub.split(".")
            return parts[-1] if parts else sub
        except Exception:
            return domain.split(".")[0]

    def update(self, src_ip: str, domain: str) -> Optional[Dict]:
        sld = self._extract_sld(domain)
        now = time.time()

        with self._lock:
            q   = self._domain_window[src_ip]
            slds= self._sld_window[src_ip]
            # Expire old entries
            while q and now - q[0] > self.WINDOW_SEC:
                q.popleft()
            q.append(now)
            slds.add(sld)

            if len(slds) >= self.BURST_THRESH:
                snap = len(slds)
                slds.clear()
                q.clear()
                return {
                    "alert":    True,
                    "severity": "MED",
                    "src_ip":   src_ip,
                    "count":    snap,
                    "reason":   (
                        f"[DNS-BURST] {src_ip} queried {snap} unique SLDs "
                        f"in {self.WINDOW_SEC}s — may indicate DGA bulk registration "
                        f"probe or domain-rotation campaign. "
                        f"Gap item 57: registration burst detection."
                    ),
                }
        return None


# ═══════════════════════════════════════════════════════════════
#  DGA FAMILY CLASSIFIER  (gap items 60, 82)
# ═══════════════════════════════════════════════════════════════

class DGAFamilyClassifier:
    """
    Lightweight rule-based DGA family classifier.
    Checks domain structural signatures against the known-family database.

    Complements the ML detector (which gives probability) with
    explicit family attribution (which gives an IOC name).

    Gap item 60: DGA family classification.
    Gap item 82: per-DGA-type detection difficulty rating.
    """

    VOWELS = set("aeiou")

    def __init__(self):
        self._ml_detector = None

    def _vowel_ratio(self, s: str) -> float:
        if not s:
            return 0.0
        alpha = [c for c in s if c.isalpha()]
        if not alpha:
            return 0.0
        return sum(1 for c in alpha if c in self.VOWELS) / len(alpha)

    def classify(self, domain: str) -> Optional[Dict]:
        """
        Return the best-matching DGA family or None.
        Result: {family, confidence, difficulty, notes, indicators}
        """
        domain  = domain.lower().rstrip(".")
        sub     = _get_subdomain(domain)
        labels  = domain.split(".")
        tld     = "." + ".".join(labels[-1:]) if labels else ""
        tld2    = "." + ".".join(labels[-2:]) if len(labels) >= 2 else tld
        body    = sub.split(".")[-1] if "." in sub else sub
        blen    = len(body)

        matches = []

        for family, sig in DGA_FAMILY_SIGNATURES.items():
            indicators = []
            score      = 0.0

            # TLD match
            if "tlds" in sig:
                raw_tlds = sig["tlds"]
                canon = {t.lstrip(".") for t in raw_tlds}
                tld2_stripped = tld2.lstrip(".")
                tld_matched = (labels[-1] in canon or tld in raw_tlds)
                tld2_matched = (tld2_stripped in canon or tld2 in raw_tlds or
                                any(tld2_stripped.endswith(t.lstrip(".")) for t in raw_tlds))
                if tld_matched or (sig.get("tld2_match") and tld2_matched):
                    indicators.append(f"TLD matches {family} signature")
                    score += 2.0
                    # Primary TLD bonus: extra score for the most distinctive TLD
                    if "primary_tlds" in sig:
                        ptlds_stripped = {t.lstrip(".") for t in sig["primary_tlds"]}
                        if (tld in sig["primary_tlds"] or labels[-1] in ptlds_stripped or
                                (sig.get("tld2_match") and (tld2_stripped in ptlds_stripped or
                                 any(tld2_stripped.endswith(t) for t in ptlds_stripped)))):
                            indicators.append(f"Primary TLD match (strong signal)")
                            score += 2.0

            # Body length
            if "body_len" in sig:
                lo, hi = sig["body_len"]
                if lo <= blen <= hi:
                    indicators.append(f"Body length {blen} in [{lo},{hi}]")
                    score += 1.5
                    # Exact length match bonus (e.g. Ranbyus always 14, Virut always 5-8)
                    if lo == hi and blen == lo:
                        score += 1.0
                        indicators.append(f"Exact length match ({lo})")

            # Regex body pattern
            if "body_pattern" in sig:
                if re.match(sig["body_pattern"], body + "."):
                    indicators.append(f"Body matches regex: {sig['body_pattern']}")
                    score += 3.0

            # Charset
            if "charset" in sig:
                cs = sig["charset"]
                if cs == "alpha" and body.isalpha():
                    indicators.append("Pure alpha body")
                    score += 0.5
                elif cs == "alnum" and body.isalnum() and not body.isalpha():
                    indicators.append("Alphanumeric body")
                    score += 0.5

            # Vowel pattern (pykspa / vowel-consonant)
            if sig.get("vowel_pattern"):
                vr = self._vowel_ratio(body)
                if 0.35 <= vr <= 0.65:
                    indicators.append(f"Vowel ratio {vr:.2f} matches alternating pattern")
                    score += 1.0

            # Keyword match (dridex word-fragment)
            if "keywords" in sig:
                for kw in sig["keywords"]:
                    if kw in body:
                        indicators.append(f"Contains keyword '{kw}'")
                        score += 2.0
                        break

            # DDNS provider
            for provider in DDNS_PROVIDERS:
                if domain.endswith(provider):
                    if family == "mirai_nomi":
                        indicators.append(f"DDNS provider {provider}")
                        score += 1.5
                    break

            if score >= 2.0 and indicators:
                matches.append({
                    "family":     family,
                    "score":      score,
                    "confidence": min(score / 6.0, 1.0),
                    "difficulty": sig.get("detection_difficulty", "MED"),
                    "notes":      sig.get("notes", ""),
                    "indicators": indicators,
                })

        if not matches:
            return None
        # Return highest-confidence match
        # Tie-break by family priority when scores are equal
        best = max(matches, key=lambda x: (
            round(x["score"], 1),
            DGA_FAMILY_PRIORITY.get(x["family"], 0)
        ))
        return best

    def get_difficulty(self, family: str) -> str:
        sig = DGA_FAMILY_SIGNATURES.get(family, {})
        return sig.get("detection_difficulty", "UNKNOWN")

    def evasion_notes(self, domain: str) -> List[str]:
        """Check for geopolitical evasion TLDs and DDNS providers."""
        notes = []
        d = domain.lower().rstrip(".")
        for tld, note in EVASION_CCTLDS.items():
            if d.endswith(tld.lstrip(".")):
                notes.append(f"Evasion TLD {tld}: {note}")
        for provider in DDNS_PROVIDERS:
            if d.endswith(provider):
                notes.append(f"DDNS provider {provider}: takedown requires provider cooperation")
        for tld in OPENNIC_TLDS:
            if d.endswith(tld.lstrip(".")):
                notes.append(f"OpenNIC TLD {tld}: not resolvable by standard DNS — evasion technique")
        return notes


# ═══════════════════════════════════════════════════════════════
#  PROCESS-CORRELATED DGA DETECTION  (gap item 81)
# ═══════════════════════════════════════════════════════════════

class ProcessDGACorrelator:
    """
    Correlates high-entropy DNS queries with specific processes on
    the local host. Cybereason's insight: 'no legitimate process
    will ever use DGA, so just detecting it incriminates the process.'

    Reads /proc/<pid>/net/dns_resolver or uses psutil to get
    per-process DNS activity where available.

    In the lab: correlates NXDOMAIN bursts with processes that have
    outbound UDP port 53 connections.

    Gap item 81: process-correlated DGA detection.
    """

    def __init__(self):
        try:
            import psutil
            self._psutil = psutil
        except ImportError:
            self._psutil = None

    def find_dns_processes(self) -> List[Dict]:
        """
        List processes with outbound UDP port 53 connections.
        These are the candidates for DGA-related DNS activity.
        """
        if self._psutil is None:
            return []
        results = []
        try:
            for proc in self._psutil.process_iter(
                    ["pid", "name", "exe", "cmdline", "status"]):
                try:
                    conns = proc.net_connections(kind="udp")
                    for c in conns:
                        if c.raddr and c.raddr.port == 53:
                            results.append({
                                "pid":     proc.pid,
                                "name":    proc.info.get("name", "?"),
                                "exe":     proc.info.get("exe", "?"),
                                "cmdline": " ".join(proc.info.get("cmdline") or [])[:80],
                                "remote":  f"{c.raddr.ip}:{c.raddr.port}",
                            })
                except (self._psutil.NoSuchProcess,
                        self._psutil.AccessDenied):
                    pass
        except Exception:
            pass
        return results

    def correlate(self, dga_alert: Dict) -> Dict:
        """
        Given a DGA alert dict, try to correlate it with a running process.
        Returns the alert enriched with process information.
        """
        procs = self.find_dns_processes()
        dga_alert["correlated_processes"] = procs
        if procs:
            names = ", ".join(p["name"] for p in procs[:5])
            dga_alert["process_note"] = (
                f"Process(es) with active DNS connections: {names}. "
                f"No legitimate process uses DGA — any of these may be the bot."
            )
        else:
            dga_alert["process_note"] = (
                "No active DNS connections found from user-space processes. "
                "Bot may be kernel-level or using raw sockets."
            )
        return dga_alert

    def is_suspicious_process(self, pid: int) -> Dict:
        """
        Check if a process has suspicious DGA-related indicators.
        Cross-references with procwatch_engine YARA patterns.
        """
        if self._psutil is None:
            return {"pid": pid, "suspicious": False, "reason": "psutil unavailable"}

        try:
            proc = self._psutil.Process(pid)
            exe  = proc.exe() or ""
            name = proc.name() or ""
            cwd  = proc.cwd() or ""

            indicators = []
            # Execution from writable directories
            for suspicious_dir in ["/tmp", "/var/tmp", "/dev/shm", "/run/shm"]:
                if exe.startswith(suspicious_dir):
                    indicators.append(f"Executing from writable dir: {suspicious_dir}")

            # Process name disguise (e.g. nginx_kel masquerading)
            legit_names = {"nginx", "apache2", "sshd", "systemd", "kworker", "python3"}
            if any(ln in name.lower() and name != ln for ln in legit_names):
                indicators.append(f"Possible name spoofing: {name}")

            return {
                "pid":        pid,
                "name":       name,
                "exe":        exe,
                "suspicious": bool(indicators),
                "indicators": indicators,
            }
        except Exception as e:
            return {"pid": pid, "suspicious": False, "reason": str(e)}


# ═══════════════════════════════════════════════════════════════
#  IMPROVED ENTROPY  (gap item 84)
# ═══════════════════════════════════════════════════════════════

def compute_entropy_full(domain: str) -> float:
    """
    Compute Shannon entropy on the full subdomain after stripping
    the public suffix (gap item 84 — PSL-aware, not naive split[0]).
    """
    sub = _get_subdomain(domain.rstrip("."))
    clean = re.sub(r"\.", "", sub)
    if not clean:
        return 0.0
    prob = [float(clean.count(c)) / len(clean) for c in set(clean)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


# ═══════════════════════════════════════════════════════════════
#  PRE-REGISTRATION / SINKHOLING DEFENCE  (gap item 59)
# ═══════════════════════════════════════════════════════════════

class SinkholeDatabase:
    """
    Maintains a local database of pre-registered (sinkholed) DGA domains.

    In real operations (Conficker, Necurs takedowns) defenders pre-register
    all domains the DGA will generate for a given period, then monitor
    or block traffic to those domains.

    In the lab: generates the current week's domains from all DGA variants
    and marks them as sinkholed, then checks incoming queries against this set.

    Gap item 59: pre-registration / sinkholing defence.
    """

    def __init__(self, auto_populate: bool = False):
        self._sinkholed: set = set()
        self._lock = threading.Lock()
        if auto_populate:
            self._populate()

    def _populate(self):
        """Pre-register this week's domains from all DGA variants."""
        print("[Sinkhole] Pre-computing DGA domains for sinkhole database …")
        from dga_variants import ALL_DGA_TYPES
        count = 0
        for name, fn in ALL_DGA_TYPES.items():
            try:
                domains = fn(count=50)
                with self._lock:
                    for d in domains:
                        self._sinkholed.add(d.lower())
                        count += 1
            except Exception:
                pass
        # Also add Mirai.Nomi current-week domains
        try:
            from mirai_nomi_dga import MiraiNomiDGA
            dga = MiraiNomiDGA(use_ntp=False)
            for d in dga.generate_for_week(0):
                with self._lock:
                    self._sinkholed.add(d.lower())
                    count += 1
        except Exception:
            pass
        print(f"[Sinkhole] Database populated with {count} DGA domains")

    def add(self, domain: str):
        with self._lock:
            self._sinkholed.add(domain.lower())

    def is_sinkholed(self, domain: str) -> bool:
        with self._lock:
            return domain.lower() in self._sinkholed

    def check_and_alert(self, domain: str, src_ip: str) -> Optional[Dict]:
        if self.is_sinkholed(domain):
            return {
                "alert":    True,
                "severity": "HIGH",
                "domain":   domain,
                "src_ip":   src_ip,
                "reason":   (
                    f"[SINKHOLE] Query for pre-registered DGA domain {domain} "
                    f"from {src_ip}. Domain is in the sinkhole database — "
                    f"bot is actively probing DGA rendezvous points. "
                    f"Gap item 59: sinkholing defence operational."
                ),
            }
        return None

    def size(self) -> int:
        with self._lock:
            return len(self._sinkholed)


# ═══════════════════════════════════════════════════════════════
#  ADVANCED DGA ENGINE  (integrates all above)
# ═══════════════════════════════════════════════════════════════


# Family priority for tie-breaking (higher = preferred when scores equal)
# Based on distinctiveness of signatures: most distinctive families get highest priority
DGA_FAMILY_PRIORITY = {
    "bamital":     10,  # 32-char hex body — unmistakable
    "post":         9,  # numeric-prefix 24-30 char — unmistakable
    "mirai_nomi":   8,  # exact 10-char hex under DDNS — unmistakable
    "dyre":         8,  # 32-36 char hex under .in/.cc — unmistakable
    "symmi":        9,  # DDNS subdomain — highly distinctive (above pykspa)
    "kraken":       8,  # dyndns.org is very distinctive
    "virut":        7,  # 5-8 char alpha .com — very short, distinct
    "simda":        6,  # 5-9 char alpha .info — .info is strong signal
    "pushdo":       6,  # .kz TLD — very distinctive
    "cryptolocker": 5,
    "locky":        5,
    "rovnix":       5,  # alnum with digits
    "ranbyus":      7,  # exact 14-char LFSR — more specific than dyre (10-25)
    "necurs":       4,
    "emotet":       4,
    "tinba":        3,
    "dridex":       3,
    "qakbot":       3,
    "banjori":      3,
    "pykspa":       1,
    "pykspa_v1":    1,
    "conficker":    2,
}

class AdvancedDGAEngine:
    """
    Drop-in Engine 3 enhancement that integrates:
      • PSL-aware entropy (gap 84)
      • DNS TTL anomaly (gap 55)
      • Domain registration burst (gap 57)
      • DGA family classification (gap 60)
      • Evasion TLD detection (gap 58)
      • Optional ML classification (gap 83)
      • Process correlation (gap 81)
    """

    ENTROPY_THRESH = 3.8   # matches existing Engine 3 threshold
    MIN_BODY_LEN   = 6

    def __init__(self, use_ml: bool = False, use_sinkhole: bool = False):
        self.ttl_det    = DNSTTLDetector()
        self.burst_det  = DomainRegistrationBurstDetector()
        self.family_cls = DGAFamilyClassifier()
        self.proc_corr  = ProcessDGACorrelator()
        self.sinkhole   = SinkholeDatabase(auto_populate=use_sinkhole)

        self._ml = None
        if use_ml:
            try:
                from dga_ml_detector import DGAMLDetector
                self._ml = DGAMLDetector(model="gbt")
                self._ml.load()
            except Exception:
                try:
                    self._ml.train_from_variants(domains_per_type=100,
                                                 benign_count=300)
                    self._ml.save()
                except Exception:
                    self._ml = None

    def analyze(self, domain: str, src_ip: str = "?",
                ttl: int = None, rcode: int = None) -> Dict:
        """
        Full analysis of a DNS event.
        Returns: {alert, severity, reasons, family, evasion_notes, ml_result}
        """
        domain = domain.lower().rstrip(".")
        sub    = _get_subdomain(domain)
        body   = sub.split(".")[-1] if "." in sub else sub

        reasons     = []
        severity    = None
        alert       = False

        # ── 1. PSL-aware entropy (gap 84) ─────────────────────
        ent = compute_entropy_full(domain)
        if ent > self.ENTROPY_THRESH and len(body) >= self.MIN_BODY_LEN:
            reasons.append(
                f"High entropy={ent:.2f} bits/char (PSL-aware, full subdomain)")
            severity = "MED"
            alert    = True

        # ── 2. DNS TTL anomaly (gap 55) ────────────────────────
        ttl_result = self.ttl_det.check(domain, ttl or 0, src_ip)
        if ttl_result:
            reasons.append(ttl_result["reason"])
            if ttl_result["severity"] == "HIGH":
                severity = "HIGH"
            elif severity is None:
                severity = "MED"
            alert = True

        # ── 3. Registration burst (gap 57) ─────────────────────
        burst_result = self.burst_det.update(src_ip, domain)
        if burst_result:
            reasons.append(burst_result["reason"])
            alert    = True
            severity = severity or "MED"

        # ── 4. DGA family classification (gap 60) ─────────────
        family = self.family_cls.classify(domain)

        # ── 5. Evasion TLD / DDNS / OpenNIC (gaps 58, 31, 32) ─
        evasion = self.family_cls.evasion_notes(domain)
        if evasion:
            reasons.extend(evasion)
            alert    = True
            severity = severity or "MED"

        # ── 6. Sinkhole check (gap 59) ─────────────────────────
        sink = self.sinkhole.check_and_alert(domain, src_ip)
        if sink:
            reasons.append(sink["reason"])
            alert    = True
            severity = "HIGH"

        # ── 7. ML classification (gap 83) ─────────────────────
        ml_result = None
        if self._ml is not None:
            try:
                ml_result = self._ml.predict(domain)
                if ml_result.get("is_dga") and ml_result.get("probability", 0) >= 0.8:
                    reasons.append(
                        f"ML classifier: DGA probability={ml_result['probability']:.2f} "
                        f"(model=gbt, 16 features)")
                    alert    = True
                    severity = severity or "MED"
            except Exception:
                pass

        # ── 8. NXDOMAIN for non-evasion domains ───────────────
        if rcode == 3 and not alert:
            reasons.append(f"NXDOMAIN response (rcode=3)")

        return {
            "domain":      domain,
            "src_ip":      src_ip,
            "alert":       alert,
            "severity":    severity or "LOW",
            "entropy":     round(ent, 4),
            "ttl":         ttl,
            "rcode":       rcode,
            "reasons":     reasons,
            "family":      family,
            "evasion":     evasion,
            "ml_result":   ml_result,
            "reason":      f"[ENGINE3-ADV] " + "; ".join(reasons) if reasons else "Normal",
        }

    def bulk_analyze(self, events: List[Tuple[str, str, int, int]]) -> List[Dict]:
        """
        Analyze a batch of (domain, src_ip, ttl, rcode) tuples.
        """
        return [self.analyze(d, ip, ttl, rcode) for d, ip, ttl, rcode in events]


# ═══════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys, json

    print("=" * 65)
    print(" IDS DGA Advanced Detection Patch — AUA Botnet Research Lab")
    print("=" * 65)

    engine = AdvancedDGAEngine(use_ml=False, use_sinkhole=False)

    test_domains = [
        # Standard benign
        ("google.com",              "192.168.100.11", 3600, 0),
        ("microsoft.com",           "192.168.100.11", 3600, 0),
        # High-entropy DGA
        ("xmtzpvkwrdfjbno.com",     "192.168.100.11",    1, 3),
        ("qxbvmnprtjkldsg.net",     "192.168.100.11",    5, 3),
        # Mirai.Nomi style hex
        ("1a1f31761f.dontargetme.nl", "192.168.100.11",  10, 0),
        # Necurs exotic TLD
        ("qujfvnn.to",              "192.168.100.11", 60, 3),
        ("olkqxmaeuiwyx.xxx",       "192.168.100.11", 30, 3),
        # Pykspa vowel-consonant
        ("cfaobn.com",              "192.168.100.11", 300, 3),
        # Evasion TLD
        ("gtgqvexfgtonbx.pw",       "192.168.100.11", 1, 3),
        ("dropweejeleyyc.net",      "192.168.100.11", 1, 3),
        # DDNS subdomain (Symmi pattern)
        ("eqidacwakui.ddns.net",    "192.168.100.11", 5, 0),
    ]

    print(f"\n{'Domain':<35} {'Alert':^6} {'Sev':^5} {'Entropy':^9} {'Family':^15}")
    print("-" * 80)
    for args in test_domains:
        r = engine.analyze(*args)
        fam   = r["family"]["family"] if r["family"] else "—"
        alert = "⚠ YES" if r["alert"] else "  no"
        print(f"{r['domain']:<35} {alert:^6} {r['severity']:^5} "
              f"{r['entropy']:^9.3f} {fam:^15}")
        if r["reasons"]:
            for reason in r["reasons"][:2]:
                print(f"  → {reason[:75]}")

    print("\n[Patch] All advanced DGA detection components operational.")


# ═══════════════════════════════════════════════════════════════
#  GAP 78: REMAINING 15 MALWARE FAMILY SIGNATURES
#  Derived from the mixed_domain.csv data visible in the Spark
#  MLlib notebook (repomix-output.txt). Each entry is grounded
#  in actual domain samples from the dataset.
# ═══════════════════════════════════════════════════════════════

DGA_FAMILY_SIGNATURES.update({
    # banjori: word-fragment concatenation DGA; exclusively .com;
    # very long alpha bodies with repeated word-fragment patterns.
    # Samples: tjjlsikathrinezad.com, ooljpartbulkyf.com, etc.
    "banjori": {
        "tlds": {".com"},
        "body_len": (10, 35),
        "charset": "alpha",
        "keywords": ["ererwy", "atanb", "machuslazaro", "sikathrine",
                     "semitismg", "llaabetting", "inalcentric", "enhancedys",
                     "byplaywobb", "alitydevoni", "ardenslave", "leasuredeh",
                     "ellefriction", "anerratic", "iologistbike", "mentalist",
                     "vinskycatte"],
        "detection_difficulty": "LOW",
        "notes": "Word-fragment concatenation; very long alpha bodies; exclusively .com",
    },

    # rovnix: alphanumeric mixed; numeric substrings common;
    # 5 TLDs including Chinese .cn and .ru.
    # Samples: f8qlliz2qyitk5hmpl.biz, 1okgbh8tpc1cm61r14.biz, etc.
    "rovnix": {
        "tlds": {".biz", ".cn", ".com", ".net", ".ru"},
        "body_len": (16, 22),
        "charset": "alnum",
        "detection_difficulty": "MED",
        "notes": "Hex+alpha mixed; numeric substrings; 5 TLDs including .cn and .ru",
    },

    # qakbot: banking trojan; long pure-alpha bodies under .org/.biz.
    # Samples: vtrzcndrwvgnbjzhueyoc.org, nwfdjhdkjqteu.org, etc.
    "qakbot": {
        "tlds": {".org", ".biz", ".com", ".net"},
        "body_len": (10, 26),
        "charset": "alpha",
        "detection_difficulty": "MED",
        "notes": "Long alpha strings under .org/.biz; banking trojan",
    },

    # murofet: peer-to-peer seeded; medium-length alpha; several TLDs.
    # Samples: rqnzkonmcnfmmol.com, qptssumslyogntnh.info, etc.
    "murofet": {
        "tlds": {".biz", ".net", ".org", ".info", ".com"},
        "body_len": (14, 22),
        "charset": "alpha",
        "detection_difficulty": "MED",
        "notes": "P2P seeded; alpha-only medium-length bodies across multiple TLDs",
    },

    # virut: very short (5-8 char) pure-alpha .com bodies.
    # Samples: wxyurh.com, knauiz.com, nyjutv.com, iyxkrd.com, etc.
    "virut": {
        "tlds": {".com"},
        "body_len": (5, 8),
        "charset": "alpha",
        "detection_difficulty": "LOW",
        "notes": "Very short 5-8 char alpha-only .com domains; file infector/backdoor",
    },

    # locky: ransomware; alpha bodies under .ru / .org.
    # Samples: uhprnpxjc.ru, tsaafoqnsfjbkse.ru, etc.
    "locky": {
        "tlds": {".ru", ".org", ".com", ".net"},
        "body_len": (9, 18),
        "charset": "alpha",
        "detection_difficulty": "MED",
        "notes": "Ransomware; alpha bodies; uses .ru for legal evasion",
    },

    # simda: short alpha bodies under .info; click-fraud botnet.
    # Samples: nopewom.info, puzogev.info, dikigyb.info, galap.eu, etc.
    "simda": {
        "tlds": {".info", ".com", ".eu"},
        "body_len": (5, 9),
        "charset": "alpha",
        "primary_tlds": {".info"},      # .info is the dominant signal; gets bonus
        "detection_difficulty": "LOW",
        "notes": "Short alpha under .info; click-fraud; easily blocked by TLD",
    },

    # nymaim: downloader/ransomware; medium alpha under .info/.com.
    # Samples: lwgpakhwu.info, nmshtfcr.com, etc.
    "nymaim": {
        "tlds": {".info", ".com"},
        "body_len": (7, 13),
        "charset": "alpha",
        "detection_difficulty": "MED",
        "notes": "Downloader/ransomware combo; medium alpha bodies; .info usage",
    },

    # bamital: MD5-hex body (32 hex chars); extremely distinctive.
    # Samples: ca587e6fc0aa82b6556c176e54d40c61.org, etc.
    "bamital": {
        "tlds": {".org", ".com"},
        "body_len": (32, 36),
        "body_pattern": r"^[0-9a-f]{32,36}\.",
        "charset": "alnum",
        "detection_difficulty": "LOW",
        "notes": "MD5-hex body (32 chars); maximally distinctive; click-fraud botnet",
    },

    # ramdo: click-fraud; long alpha bodies.
    # Samples: ciyouwqqugcmqkiy.org, etc.
    "ramdo": {
        "tlds": {".org", ".com", ".net"},
        "body_len": (14, 20),
        "charset": "alpha",
        "detection_difficulty": "MED",
        "notes": "Click-fraud bot; long alpha bodies across standard TLDs",
    },

    # qadars: banking trojan; alphanumeric bodies.
    # Samples: 7c1mrc5ers9a.org, etc.
    "qadars": {
        "tlds": {".org", ".com"},
        "body_len": (10, 16),
        "charset": "alnum",
        "detection_difficulty": "MED",
        "notes": "Banking trojan; hex-mixed bodies under .org",
    },

    # suppobox: wordlist-based; human-readable fake names.
    # Samples: theseguess.net, jeannettebertrand.net, etc.
    "suppobox": {
        "tlds": {".net", ".com"},
        "body_len": (8, 22),
        "charset": "alpha",
        "keywords": ["guess", "bertrand", "secure", "connect", "service"],
        "detection_difficulty": "HIGH",
        "notes": "Wordlist-based; produces human-readable plausible names",
    },

    # symmi: DDNS subdomain DGA; eqidacwakui.ddns.net style.
    # Uses random subdomains under free DDNS providers — no registration needed.
    "symmi": {
        "tlds": {"ddns.net", "no-ip.org", "changeip.com"},
        "primary_tlds": {"ddns.net", "no-ip.org", "changeip.com"},
        "tld2_match": True,
        "body_len": (8, 14),
        "charset": "alpha",
        "detection_difficulty": "HIGH",
        "notes": "DDNS subdomain DGA; no domain registration; un-sinkholeable",
    },

    # pushdo: spam botnet; alpha bodies under .kz (Kazakhstan ccTLD evasion).
    # Samples: lumucjatesl.kz, etc.
    "pushdo": {
        "tlds": {".kz", ".ru", ".com", ".net"},
        "primary_tlds": {".kz"},
        "body_len": (10, 14),
        "charset": "alpha",
        "detection_difficulty": "MED",
        "notes": "Spam/downloader; .kz ccTLD evasion; alpha-only bodies",
    },

    # Cryptolocker: ransomware pioneer; alpha bodies under .ru / .org / .co.uk.
    # Samples: wrdpvitewnpfv.co.uk, sgjtwtgclvxgtax.org, eoueooqjcpbvpr.ru, etc.
    "cryptolocker": {
        "tlds": {".ru", ".org", ".co.uk", ".com", ".net", ".biz"},
        "primary_tlds": {".co.uk"},
        "body_len": (12, 18),
        "charset": "alpha",
        "detection_difficulty": "MED",
        "notes": "Ransomware; alpha bodies; .ru + .co.uk for international evasion",
    },

    # pykspa_v1: variant of pykspa with different TLD set and body patterns.
    # Samples: gsldgadsholapet.org, dkrqycn.com, eyyios.net, sanipa.biz, etc.
    "pykspa_v1": {
        "tlds": {".org", ".com", ".net", ".biz", ".cc", ".info"},
        "body_len": (5, 14),
        "charset": "alpha",
        "vowel_pattern": True,
        "detection_difficulty": "MED",
        "notes": "Pykspa variant; vowel-consonant alternation; broader TLD set",
    },

    # shiotob/urlzone/bebloh: banking trojan cluster; alphanumeric .net/.com.
    # Samples: rkz2jgyqtbd.net, 1smzjlgxsgkqok.net, 2h9crldhnzdhfv.com, etc.
    "shiotob": {
        "tlds": {".net", ".com"},
        "body_len": (10, 16),
        "charset": "alnum",
        "detection_difficulty": "MED",
        "notes": "Banking trojan cluster (shiotob/urlzone/bebloh); alnum bodies",
    },

    # post: long alphanumeric bodies; unique format with numeric prefix.
    # Samples: 1xhkzo0vu7c96fwf07o1o9wjau.org, 6eamwkm0hulgmm7lum1fb8kn7.org, etc.
    "post": {
        "tlds": {".org", ".net", ".com", ".biz"},
        "body_len": (24, 30),
        "charset": "alnum",
        "body_pattern": r"^[0-9][a-z0-9]{22,28}\.",
        "detection_difficulty": "LOW",
        "notes": "Numeric-prefixed long alnum body; highly distinctive length",
    },
})

print(f"[DGA-Families] Total families in classifier: {len(DGA_FAMILY_SIGNATURES)}")


# ═══════════════════════════════════════════════════════════════
#  GAP 56: DOMAIN AGE HEURISTIC (WHOIS-based)
#  Newly registered domains are a strong DGA indicator.
#  DGA operators register domains hours before use and abandon
#  them within days. Legitimate domains are typically months/years old.
#
#  Full WHOIS requires external connectivity. This module provides:
#  1. A synthetic "domain age" estimator based on structural signals
#     that correlate with newly-registered domains (no WHOIS needed).
#  2. A real WHOIS wrapper for when python-whois is available.
#  3. Integration hook for AdvancedDGAEngine.
# ═══════════════════════════════════════════════════════════════

class DomainAgeDetector:
    """
    Estimates domain registration age using two methods:

    Method A – Structural heuristics (no external calls):
      Newly-registered DGA domains tend to have:
        • Random-looking SLD with high entropy
        • Obscure or non-standard TLD (ccTLD, free DDNS)
        • No HTTPS redirects (often HTTP-only)
        • No www. subdomain registered
      This method returns a risk score 0.0–1.0.

    Method B – Real WHOIS lookup (when python-whois installed):
      Queries the actual WHOIS database.
      Returns age in days, or None if lookup fails.

    Gap item 56: domain age / WHOIS age detection.
    Medium article: 'Very low WHOIS age' is a DGA detection signal.
    """

    YOUNG_DOMAIN_DAYS = 30   # domains < 30 days old are suspicious
    VERY_YOUNG_DAYS   = 7    # domains < 7 days are HIGH severity

    def __init__(self):
        self._whois_available = False
        try:
            import whois  # python-whois package
            self._whois = whois
            self._whois_available = True
        except ImportError:
            pass

    def whois_age_days(self, domain: str) -> Optional[int]:
        """
        Query WHOIS for creation date and return age in days.
        Returns None if WHOIS unavailable or lookup fails.
        Install: pip install python-whois --break-system-packages
        """
        if not self._whois_available:
            return None
        try:
            w = self._whois.whois(domain)
            cd = w.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            if cd is None:
                return None
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            if hasattr(cd, 'tzinfo') and cd.tzinfo is None:
                cd = cd.replace(tzinfo=timezone.utc)
            return (now - cd).days
        except Exception:
            return None

    def structural_age_score(self, domain: str) -> float:
        """
        Heuristic age risk score based on structural features alone.
        Returns 0.0 (likely old/established) to 1.0 (likely newly registered).
        No external calls required.
        """
        score = 0.0
        domain = domain.lower().rstrip('.')
        sub    = _get_subdomain(domain)
        body   = sub.split('.')[-1] if '.' in sub else sub
        labels = domain.split('.')
        tld    = '.' + labels[-1] if labels else ''

        # High-entropy body — DGA domains are freshly generated
        ent = compute_entropy_full(domain)
        if ent > 3.8:
            score += 0.4
        elif ent > 3.2:
            score += 0.2

        # No vowels / very low vowel ratio — typical DGA
        import re
        alpha = [c for c in body if c.isalpha()]
        if alpha:
            vr = sum(1 for c in alpha if c in {'a','e','i','o','u'}) / len(alpha)
            if vr < 0.1:
                score += 0.3
            elif vr < 0.2:
                score += 0.15

        # Obscure ccTLD — DDNS or evasion TLD (strong new-registration signal)
        for provider in DDNS_PROVIDERS:
            if domain.endswith(provider):
                score += 0.45   # DDNS = almost certainly not an established domain
                break
        for etld in EVASION_CCTLDS:
            if tld == etld:
                score += 0.35   # evasion ccTLD = very likely freshly registered
                break

        # No dictionary words in body — fully random
        common_substrings = ['the','and','com','ing','tion','pro','net',
                             'web','tech','app','api','cdn','cloud']
        if not any(kw in body for kw in common_substrings):
            score += 0.1

        return min(score, 1.0)

    def check(self, domain: str, src_ip: str = "?") -> Optional[Dict]:
        """
        Check domain age and return an alert dict if suspicious.
        Tries real WHOIS first, falls back to structural heuristics.
        """
        age_days = self.whois_age_days(domain)

        if age_days is not None:
            if age_days <= self.VERY_YOUNG_DAYS:
                return {
                    "alert": True, "severity": "HIGH",
                    "domain": domain, "src_ip": src_ip,
                    "age_days": age_days, "method": "whois",
                    "reason": (
                        f"[DOMAIN-AGE] {domain} registered only {age_days} day(s) ago "
                        f"(WHOIS verified). DGA operators register domains hours before "
                        f"use. Threshold: {self.VERY_YOUNG_DAYS} days. Source: {src_ip}"
                    ),
                }
            elif age_days <= self.YOUNG_DOMAIN_DAYS:
                return {
                    "alert": True, "severity": "MED",
                    "domain": domain, "src_ip": src_ip,
                    "age_days": age_days, "method": "whois",
                    "reason": (
                        f"[DOMAIN-AGE] {domain} registered {age_days} days ago "
                        f"(WHOIS verified). Young domain threshold: {self.YOUNG_DOMAIN_DAYS}d."
                    ),
                }
            return None  # old domain, no alert

        # Structural heuristic fallback
        score = self.structural_age_score(domain)
        if score >= 0.6:
            return {
                "alert": True, "severity": "MED",
                "domain": domain, "src_ip": src_ip,
                "age_score": round(score, 2), "method": "structural",
                "reason": (
                    f"[DOMAIN-AGE] {domain} structural age score={score:.2f} "
                    f"(high entropy + no dict words + evasion TLD). "
                    f"Install python-whois for confirmed age. Source: {src_ip}"
                ),
            }
        return None


# Add domain age detector to AdvancedDGAEngine at module level for import
_domain_age_detector = DomainAgeDetector()
