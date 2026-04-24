"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Network + Host IDS (Defensive Layer)
 Run as root: sudo python3 ids_detector.py
 Environment: ISOLATED VM LAB ONLY
====================================================

Detection engines:
  Engine 1  - Volumetric:      SYN flood, UDP flood
  Engine 2  - Behavioral:      Credential stuffing (CV timing)
               Flags confirmed bots in tarpit_state.json
  Engine 3  - DNS Anomaly:     DGA detection via entropy + NXDOMAIN burst
  Engine 4  - DPI/Covert:      Repeated HTTPS polling -- dead-drop detection
  Engine 5  - Login Analytics: Success-rate drop, off-hours surge,
               unknown-account spike, breached-cred use,
               username clustering
  Engine 6  - CrossIP/Fingerprint: same browser fingerprint from >=3 IPs
  Engine 7  - TLS/JA3: TLS ClientHello fingerprinting
               Fires on known-bad tool hashes (urllib, curl, OpenBullet)
               and on the same fingerprint from >=3 distinct source IPs
  Engine 8  - ML/Adaptive: EWMA baseline + optional IsolationForest
               Replaces static thresholds with learned normal-traffic
               baselines; adapts as service traffic profile shifts
  Engine 9  - Browser Automation: webdriver artifact, CDP, headless GPU
  Engine 10 - Username Clustering: domain concentration, sequential names
  Engine 11 - RST/SYN Scanner + DNS Cross-Protocol Anomaly  [NEW]
               Source: "Traffic Anomaly Detection – TCP and DNS"
               Rishi Narang, Infosec, June 2012
               RST-based scanner detection (Case 2):
                 Host receiving many RSTs is scanning outward
               SYN-burst scanner detection (Case 1):
                 Host sending many SYNs is the scanner
               Log file analysis → surfaces most active IP
               DHCP lease release on confirmed scanner
               DNS anomaly indicators not in Engine 3:
                 sudden query surge, resolve-rate drop,
                 DNS:TCP session ratio, recursive burst
  Engine 12 - ProcWatch Host Process Scanner  [NEW]
               Source: "Day 14 — I Built ProcWatch"
               Hafiz Shamnad, DEV Community, March 2025
               Execution from writable directories (/tmp, /dev/shm)
               UID/eUID mismatch (SUID escalation in progress)
               Root process running from /home/* directory
               Reverse-shell port detection (4444,5555,7777,31337 ESTABLISHED)
               Cryptominer keyword detection (xmrig, monero, stratum, pool)
               LD_PRELOAD injection (user-space rootkit indicator)
               Interpreter + network + no terminal (revshell pattern)
  Host      - Cryptojacking / ghost-process / name-spoof detection
"""

import threading
import time
import math
import os
import stat
import statistics
import subprocess
import urllib.request
import json
import psutil
from collections import defaultdict, deque
from datetime import datetime

try:
    import ids_engine_slowloris as _e16
    _e16.register(alert)
    E16_OK = True
except ImportError:
    E16_OK = False
    print("[IDS] INFO: ids_engine_slowloris.py not found -- Engine 16 disabled")

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, get_if_list
    SCAPY_OK = True
except ImportError:
    print("[IDS] Scapy not installed. Run: pip3 install scapy")
    SCAPY_OK = False

try:
    import tarpit_state
    TARPIT_ENABLED = True
    print("[IDS] Tarpit integration: ENABLED")
except ImportError:
    TARPIT_ENABLED = False
    print("[IDS] WARNING: tarpit_state.py not found -- tarpit signalling disabled")

try:
    import ip_reputation
    REPUTATION_ENABLED = True
except ImportError:
    REPUTATION_ENABLED = False

# Engine 7 -- TLS JA3 Fingerprinting
try:
    import tls_ja3
    JA3_ENABLED = True
    print("[IDS] TLS JA3 fingerprinting: ENABLED (Engine 7)")
except ImportError:
    JA3_ENABLED = False
    print("[IDS] INFO: tls_ja3.py not found -- Engine 7 disabled")

# Engine 8 -- Adaptive ML
try:
    import ml_detector
    ML_ENABLED = True
    print("[IDS] Adaptive ML detector: ENABLED (Engine 8)")
except ImportError:
    ML_ENABLED = False
    print("[IDS] INFO: ml_detector.py not found -- Engine 8 disabled")

# Engine 5 extension -- Username clustering
try:
    import username_clustering as _uc_module
    CLUSTERING_ENABLED = True
except ImportError:
    CLUSTERING_ENABLED = False

# Engine 11 -- RST/SYN scanner + DNS cross-protocol anomaly
try:
    import rst_detector as _rst_mod
    RST_OK = True
    print("[IDS] RST/SYN/DNS anomaly detector: ENABLED (Engine 11)")
except ImportError:
    RST_OK = False
    print("[IDS] INFO: rst_detector.py not found -- Engine 11 disabled")

# Engine 12 -- ProcWatch host process scanner
try:
    import procwatch_engine as _pw_mod
    PROCWATCH_OK = True
    print("[IDS] ProcWatch process scanner: ENABLED (Engine 12)")
except ImportError:
    PROCWATCH_OK = False
    print("[IDS] INFO: procwatch_engine.py not found -- Engine 12 disabled")

# Engine 13 -- Account Enumeration (EnumerationDetector)
try:
    from account_enum_sim import EnumerationDetector as _EnumDet
    _enum_detector = _EnumDet()
    ENUM_OK = True
    print("[IDS] Account Enumeration detector: ENABLED (Engine 13)")
except ImportError:
    ENUM_OK = False
    _enum_detector = None
    print("[IDS] INFO: account_enum_sim.py not found -- Engine 13 disabled")

# Engine 15 -- Flow-Level Detection (flow_analyzer.py)
# Source: freeCodeCamp "Build a Real-Time IDS with Python" (Rahalkar, Jan 2025)
# Adds: per-flow feature extraction, port scan signature (packet_size<100 AND
#       packet_rate>50), flow-level IsolationForest, JSON alert log.
try:
    import flow_analyzer as _e15_mod
    _e15_mod.get_engine().register_alert_fn(alert)
    E15_OK = True
    print("[IDS] Flow-Level Detection: ENABLED (Engine 15)")
    print(f"[IDS]   Port scan rule: packet_size<{_e15_mod.SIG_PORT_SCAN_PKT_SIZE}B "
          f"AND packet_rate>{_e15_mod.SIG_PORT_SCAN_RATE} pkt/s")
    print(f"[IDS]   JSON alert log: {_e15_mod.JSON_ALERT_LOG}")
    if _e15_mod._SKLEARN_OK:
        print(f"[IDS]   IsolationForest: ENABLED (sklearn available)")
    else:
        print(f"[IDS]   IsolationForest: DISABLED (pip install scikit-learn)")
except ImportError:
    E15_OK = False
    _e15_mod = None
    print("[IDS] INFO: flow_analyzer.py not found -- Engine 15 disabled")

# Engine 7 integration patch -- JA3 rotation detector + cooldown wrap
# Applied just before sniff() in _start_sniffer().
try:
    from ids_detector_patch import patch_ids_detector as _e7_patch
    E7_PATCH_OK = True
    print("[IDS] Engine 7 patch (JA3 rotation + cooldown): ENABLED")
except ImportError:
    E7_PATCH_OK = False
    _e7_patch = None
    print("[IDS] INFO: ids_detector_patch.py not found -- Engine 7 rotation/cooldown disabled")


# ── Configuration ──────────────────────────────────────────────
SYN_THRESHOLD        = 100
UDP_THRESHOLD        = 200
CRED_WINDOW          = 8
CV_BOT_THRESHOLD     = 0.15
DGA_ENTROPY_THRESH   = 3.8
NXDOMAIN_BURST       = 10
HIGH_ENTROPY_BURST   = 5
CPU_SPIKE_THRESHOLD  = 85.0
MONITOR_INTERFACE    = "lo"  # change to enp0s3 on real VM
TARPIT_UNBLOCK_IDLE  = 120

IDS_LOG_FILE         = "/tmp/ids.log"

# Engine 5 -- Login Analytics
PORTAL_HOST               = "127.0.0.1"  # 192.168.100.20 on victim VM
PORTAL_PORT               = 8080
ENGINE5_POLL_SEC          = 30
SUCCESS_RATE_MIN          = 5.0
MIN_ATTEMPTS_FOR_RATE     = 20
OFF_HOURS_PCT_THRESH      = 50.0
UNKNOWN_ACCT_PCT_THRESH   = 40.0
BREACHED_COUNT_THRESH     = 5
_E5_ALERT_COOLDOWN        = 120

# Engine 6 -- Cross-IP Fingerprint Correlation
FP_MULTIIP_MIN   = 3
FP_WINDOW        = 300

# Engine 7 -- TLS JA3
JA3_MULTIIP_MIN  = 3
JA3_WINDOW       = 300

# Engine 8 -- Adaptive ML
ML_FEATURE_WINDOW  = 60
_ml_last_sample    = 0.0
_e8_alert_cooldown = 90.0
_e8_last_alert_ts  = [0.0]   # list to allow mutation inside nested function

# Engine 11 -- RST/SYN scanner + DNS anomaly
E11_RST_THRESHOLD       = 30    # RSTs received per E11_WINDOW → scanner
E11_SYN_THRESHOLD       = 50    # SYNs sent per E11_WINDOW → scanner
E11_WINDOW              = 5.0   # seconds for RST/SYN counters
E11_DNS_SURGE           = 15    # DNS queries from one IP per DNS_WINDOW
E11_RESOLVE_DROP_RATIO  = 0.30  # resolved/total < 30% → anomaly
E11_DNS_TCP_RATIO       = 4.0   # DNS queries : TCP sessions > 4:1
E11_RECURSIVE_BURST     = 10    # recursive queries from one IP per DNS_WINDOW
E11_LOG_DIR             = "/tmp/rst_logs"
E11_SUMMARY_INTERVAL    = 60    # seconds between top-IP summary prints

# Engine 12 -- ProcWatch
E12_SCAN_INTERVAL       = 10    # seconds between full process scans


# ── Log file setup ─────────────────────────────────────────────
_log_fh   = None
_log_lock = threading.Lock()

def _open_log_file():
    global _log_fh
    if IDS_LOG_FILE is None:
        return
    with _log_lock:
        if _log_fh is None:
            try:
                _log_fh = open(IDS_LOG_FILE, "a", buffering=1)
            except OSError as e:
                print(f"[IDS] WARNING: cannot open log file {IDS_LOG_FILE}: {e}")


# ── Shared alert function ──────────────────────────────────────
alert_count = 0
alert_lock  = threading.Lock()

def alert(engine, severity, msg):
    global alert_count
    ts = datetime.now().strftime("%H:%M:%S")
    sev_str = {
        "HIGH":     "\033[91m[HIGH]\033[0m",
        "CRITICAL": "\033[91m[CRITICAL]\033[0m",
        "MED":      "\033[93m[MED] \033[0m",
        "LOW":      "\033[94m[LOW] \033[0m",
    }.get(severity, severity)

    plain_header = (
        f"\n{'='*60}\n"
        f"  ALERT #{alert_count + 1}  [{severity}]  Engine: {engine}  @ {ts}\n"
        f"  {msg}\n"
        f"{'='*60}\n"
    )

    with alert_lock:
        alert_count += 1
        print(f"\n{'='*60}")
        print(f"  ALERT #{alert_count}  {sev_str}  Engine: {engine}  @ {ts}")
        print(f"  {msg}")
        print(f"{'='*60}\n")

        if IDS_LOG_FILE is not None:
            _open_log_file()
            if _log_fh is not None:
                try:
                    _log_fh.write(plain_header)
                    _log_fh.flush()
                except OSError:
                    pass


# ── Engines 14 and 17–22 wiring ───────────────────────────────────────
# CRASH-FIXED: was at module top before alert() was defined.
# Moved here so alert() exists when register_alert_fn() is called.
# Previously all 8 engines silently received None as the alert callback.

import ids_detector_patch_e14 as _e14
_e14.apply(globals())

# Engine 17 — System Enumeration
import system_profiler as _e17
_e17.get_detector().register_alert_fn(alert)
_e17.get_detector().start_background_monitor(interval=15)

# Engine 18 — Persistence Detection
import persistence_sim as _e18
_e18_det = _e18.PersistenceDetector()
_e18_det.start_monitoring()
_e18_det.register_alert_fn(alert)   # ADDED: was missing, Engine 18 never alerted

# Engine 19 — Exfiltration Detection
import file_transfer as _e19
_exfil_det = _e19.ExfiltrationDetector()
_exfil_det.register_alert_fn(alert)

# Engine 20 — Lateral Movement Detection
import lateral_movement_sim as _e20
_lat_det = _e20.LateralMovementDetector()
_lat_det.register_alert_fn(alert)
# Feed from packet_handler: _lat_det.observe_connection(src, dst, port)

# Engine 21 — Polymorphism Detection
import polymorphic_engine as _e21
_poly_det = _e21.PolymorphismDetector()
_poly_det.register_alert_fn(alert)

# Engine 22 — Endpoint Behavioral IDS
import ids_engine_endpoint as _e22
_e22.get_engine().register_alert_fn(alert)
_e22.get_engine().start(scan_interval=30)


# ══════════════════════════════════════════════════════════════
#  ENGINE 1: VOLUMETRIC DETECTION (SYN Flood / UDP Flood)
# ══════════════════════════════════════════════════════════════

syn_counter    = defaultdict(int)
udp_counter    = defaultdict(int)
last_vol_reset = time.time()
VOL_WINDOW     = 1.0

def process_volumetric(pkt):
    global last_vol_reset, syn_counter, udp_counter

    now = time.time()
    if now - last_vol_reset >= VOL_WINDOW:
        for ip, count in list(syn_counter.items()):
            if count >= SYN_THRESHOLD:
                alert("Volumetric", "HIGH",
                      f"SYN FLOOD detected: {ip} sent {count} SYNs in {VOL_WINDOW}s")
        for ip, count in list(udp_counter.items()):
            if count >= UDP_THRESHOLD:
                alert("Volumetric", "HIGH",
                      f"UDP FLOOD detected: {ip} sent {count} UDP packets in {VOL_WINDOW}s")
        syn_counter.clear()
        udp_counter.clear()
        last_vol_reset = now

    if pkt.haslayer(IP):
        src = pkt[IP].src
        if pkt.haslayer(TCP) and pkt[TCP].flags == 0x02:
            syn_counter[src] += 1
        if pkt.haslayer(UDP):
            udp_counter[src] += 1


# ══════════════════════════════════════════════════════════════
#  ENGINE 2: BEHAVIORAL TIMING ANALYSIS (Credential Stuffing)
#            + TARPIT FEEDBACK LOOP
# ══════════════════════════════════════════════════════════════

login_times      = defaultdict(lambda: deque(maxlen=CRED_WINDOW))
login_last_seen  = {}
login_times_lock = threading.Lock()


def compute_cv(timestamps: deque) -> float:
    if len(timestamps) < 5:
        return float('inf')
    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    if not intervals or statistics.mean(intervals) == 0:
        return float('inf')
    return statistics.stdev(intervals) / statistics.mean(intervals)


def process_credential_stuffing(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[TCP].dport != PORTAL_PORT:
        return

    try:
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
        else:
            payload = bytes(pkt[TCP].payload)

        if b"POST" in payload and b"/login" in payload:
            src_ip = pkt[IP].src
            now    = time.time()

            with login_times_lock:
                login_times[src_ip].append(now)
                login_last_seen[src_ip] = now
                q = login_times[src_ip]

                if len(q) >= CRED_WINDOW:
                    cv = compute_cv(q)

                    if cv < CV_BOT_THRESHOLD:
                        avg_interval = statistics.mean(
                            [q[i] - q[i-1] for i in range(1, len(q))]
                        )
                        alert("Behavioral/Timing", "HIGH",
                              f"CREDENTIAL STUFFING detected: {src_ip}\n"
                              f"  Requests analyzed: {len(q)}\n"
                              f"  CV = {cv:.4f} (threshold: {CV_BOT_THRESHOLD})\n"
                              f"  Avg interval: {avg_interval:.3f}s  -- bot-like rigid timing")

                        if TARPIT_ENABLED:
                            if not tarpit_state.is_flagged(src_ip):
                                tarpit_state.flag(src_ip)
                                print(f"[IDS-E2] Tarpit activated for {src_ip} "
                                      f"(CV={cv:.4f})")
                            else:
                                print(f"[IDS-E2] {src_ip} already tarpitted")

                        login_times[src_ip].clear()

    except Exception as e:
        print(f"[IDS-E2-ERR] {e}")


def tarpit_auto_unblock_loop():
    if not TARPIT_ENABLED:
        return
    print(f"[IDS-TARPIT] Auto-unblock monitor started "
          f"(idle threshold: {TARPIT_UNBLOCK_IDLE}s)")
    while True:
        time.sleep(30)
        now     = time.time()
        flagged = tarpit_state.list_flagged()
        for ip in flagged:
            with login_times_lock:
                last = login_last_seen.get(ip, 0)
            if now - last > TARPIT_UNBLOCK_IDLE:
                tarpit_state.unflag(ip)
                print(f"[IDS-TARPIT] Auto-unblocked {ip} "
                      f"(silent for >{TARPIT_UNBLOCK_IDLE}s)")


# ══════════════════════════════════════════════════════════════
#  ENGINE 3: DNS ANOMALY & DGA DETECTION
# ══════════════════════════════════════════════════════════════

nxdomain_counts     = defaultdict(int)
high_entropy_counts = defaultdict(int)
queried_domains     = defaultdict(set)
last_dns_reset      = time.time()
DNS_WINDOW          = 30.0


def shannon_entropy(name: str) -> float:
    if not name:
        return 0.0
    freq = {}
    for c in name:
        freq[c] = freq.get(c, 0) + 1
    h = 0.0
    for count in freq.values():
        p = count / len(name)
        h -= p * math.log2(p)
    return h


def process_dns(pkt):
    global last_dns_reset
    now = time.time()

    if now - last_dns_reset >= DNS_WINDOW:
        for ip, count in list(nxdomain_counts.items()):
            if count >= NXDOMAIN_BURST:
                sample = list(queried_domains.get(ip, set()))[:5]
                entropy_context = ", ".join(
                    f"{d}(H={shannon_entropy(d.split('.')[0]):.2f})"
                    for d in sample
                )
                alert("DNS/DGA", "HIGH",
                      f"DGA ACTIVITY detected (NXDOMAIN burst): {ip} "
                      f"got {count} NXDOMAIN responses in {DNS_WINDOW}s\n"
                      f"  Sample domains: {entropy_context}")

        for ip, count in list(high_entropy_counts.items()):
            if count >= HIGH_ENTROPY_BURST:
                if nxdomain_counts.get(ip, 0) < NXDOMAIN_BURST:
                    sample = list(queried_domains.get(ip, set()))[:5]
                    entropy_context = ", ".join(
                        f"{d}(H={shannon_entropy(d.split('.')[0]):.2f})"
                        for d in sample
                    )
                    alert("DNS/DGA", "MED",
                          f"DGA ACTIVITY detected (high-entropy queries): {ip} "
                          f"queried {count} high-entropy domains in {DNS_WINDOW}s\n"
                          f"  H threshold: >{DGA_ENTROPY_THRESH} bits/char\n"
                          f"  Sample domains: {entropy_context}\n"
                          f"  (NXDOMAIN burst may follow -- or DNS is slow)")

        nxdomain_counts.clear()
        high_entropy_counts.clear()
        queried_domains.clear()
        last_dns_reset = now

    if not pkt.haslayer(DNS):
        return

    src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"

    if pkt.haslayer(DNSQR):
        try:
            qname     = pkt[DNSQR].qname.decode("utf-8").rstrip(".")
            name_part = qname.split(".")[0]
            entropy   = shannon_entropy(name_part)
            queried_domains[src_ip].add(qname)
            if entropy > DGA_ENTROPY_THRESH and len(name_part) > 6:
                high_entropy_counts[src_ip] += 1
                print(f"[DNS-ENG] High-entropy query from {src_ip}: "
                      f"{qname}  H={entropy:.2f} "
                      f"(window count: {high_entropy_counts[src_ip]}/{HIGH_ENTROPY_BURST})")
        except Exception:
            pass

    if pkt[DNS].qr == 1 and pkt[DNS].rcode == 3:
        nxdomain_counts[src_ip] += 1


# ══════════════════════════════════════════════════════════════
#  ENGINE 4: DPI / COVERT CHANNEL MONITOR
# ══════════════════════════════════════════════════════════════

https_conn_tracker  = defaultdict(lambda: defaultdict(list))
last_https_reset    = time.time()
HTTPS_WINDOW        = 60.0
HTTPS_CONN_THRESH   = 10

def process_covert_channel(pkt):
    global last_https_reset
    now = time.time()

    if now - last_https_reset >= HTTPS_WINDOW:
        for src, dst_map in list(https_conn_tracker.items()):
            for dst, timestamps in dst_map.items():
                count = len(timestamps)
                if count >= HTTPS_CONN_THRESH:
                    alert("DPI/Covert", "MED",
                          f"COVERT CHANNEL suspected: {src} -> {dst}\n"
                          f"  {count} HTTPS SYNs in {HTTPS_WINDOW:.0f}s window\n"
                          f"  Pattern matches dead-drop polling (Phase 2 botnet)\n"
                          f"  Port blocking (443) would NOT detect this -- requires DPI")
        https_conn_tracker.clear()
        last_https_reset = now

    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[TCP].dport == 443 and pkt[TCP].flags == 0x02:
        src = pkt[IP].src
        dst = pkt[IP].dst
        https_conn_tracker[src][dst].append(now)


# ══════════════════════════════════════════════════════════════
#  ENGINE 5: LOGIN ANALYTICS
#  + ENGINE 5e: USERNAME CLUSTERING
#  + ENGINE 8 TRIGGER
# ══════════════════════════════════════════════════════════════

_e5_last_alert: dict = {
    "success_rate": 0.0,
    "off_hours":    0.0,
    "unknown_acct": 0.0,
    "breached":     0.0,
    "clustering":   0.0,
}


def _fetch_portal_stats() -> dict:
    url = f"http://{PORTAL_HOST}:{PORTAL_PORT}/stats/advanced"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"[IDS-E5] Cannot reach portal at {PORTAL_HOST}:{PORTAL_PORT}: {e}")
        return {}


def engine5_loop():
    print(f"[IDS-E5] Login Analytics engine started "
          f"(polling {PORTAL_HOST}:{PORTAL_PORT}/stats/advanced "
          f"every {ENGINE5_POLL_SEC}s)")
    while True:
        time.sleep(ENGINE5_POLL_SEC)
        stats = _fetch_portal_stats()
        if not stats:
            continue

        now    = time.time()
        total  = stats.get("total_attempts", 0)
        sr_pct = stats.get("success_rate_pct", 100.0)
        ua_pct = stats.get("unknown_acct_pct", 0.0)
        oh_pct = stats.get("off_hours_pct", 0.0)
        br_cnt = stats.get("breached_cred_hits", 0)

        # a) Success-rate drop
        if (total >= MIN_ATTEMPTS_FOR_RATE
                and sr_pct < SUCCESS_RATE_MIN
                and now - _e5_last_alert["success_rate"] > _E5_ALERT_COOLDOWN):
            _e5_last_alert["success_rate"] = now
            alert("LoginAnalytics/SuccessRate", "HIGH",
                  f"LOGIN SUCCESS-RATE DROP detected\n"
                  f"  Total attempts:   {total}\n"
                  f"  Success rate:     {sr_pct:.1f}%  "
                  f"(threshold: <{SUCCESS_RATE_MIN}%)\n"
                  f"  Characteristic of spray attack: many wrong passwords "
                  f"from a breach dump tested against this service.\n"
                  f"  MITRE: T1110.004 (Credential Stuffing)")

        # b) Off-hours surge
        if (total >= MIN_ATTEMPTS_FOR_RATE
                and oh_pct > OFF_HOURS_PCT_THRESH
                and now - _e5_last_alert["off_hours"] > _E5_ALERT_COOLDOWN):
            _e5_last_alert["off_hours"] = now
            alert("LoginAnalytics/OffHours", "MED",
                  f"OFF-HOURS LOGIN SURGE detected\n"
                  f"  {oh_pct:.1f}% of login attempts are outside 08:00-22:00 "
                  f"(threshold: >{OFF_HOURS_PCT_THRESH}%)\n"
                  f"  Automated campaigns often run at night or from a different "
                  f"time zone to avoid human monitoring.\n"
                  f"  Total attempts: {total}")

        # c) Unknown-account spike
        if (total >= MIN_ATTEMPTS_FOR_RATE
                and ua_pct > UNKNOWN_ACCT_PCT_THRESH
                and now - _e5_last_alert["unknown_acct"] > _E5_ALERT_COOLDOWN):
            _e5_last_alert["unknown_acct"] = now
            ua_count = stats.get("unknown_acct_count", 0)
            per_ip   = stats.get("per_ip_unknowns", {})
            top_ip   = max(per_ip, key=per_ip.get) if per_ip else "?"
            alert("LoginAnalytics/UnknownAccounts", "HIGH",
                  f"UNKNOWN-ACCOUNT SPIKE detected\n"
                  f"  {ua_count} of {total} attempts ({ua_pct:.1f}%) target "
                  f"emails not registered on this service.\n"
                  f"  Threshold: >{UNKNOWN_ACCT_PCT_THRESH}%\n"
                  f"  Top offending IP: {top_ip} "
                  f"({per_ip.get(top_ip, '?')} unknown-acct hits)\n"
                  f"  Indicates attacker used a bulk breach dump without "
                  f"pre-filtering for this service's user base.")

        # d) Breached password use
        if (br_cnt >= BREACHED_COUNT_THRESH
                and now - _e5_last_alert["breached"] > _E5_ALERT_COOLDOWN):
            _e5_last_alert["breached"] = now
            alert("LoginAnalytics/BreachedCreds", "MED",
                  f"BREACHED CREDENTIAL SPRAY detected\n"
                  f"  {br_cnt} login attempts used passwords from known-breached "
                  f"password lists (simulated HIBP k-Anonymity check).\n"
                  f"  Threshold: >={BREACHED_COUNT_THRESH} hits\n"
                  f"  Indicates automated spray from a breach combo list, "
                  f"not a human who simply forgot their password.")

        # e) Username clustering
        if CLUSTERING_ENABLED:
            clustering = stats.get("username_clustering", {})
            if clustering.get("anomalous") and clustering.get("alerts"):
                c_alerts = clustering["alerts"]
                if now - _e5_last_alert["clustering"] > _E5_ALERT_COOLDOWN:
                    _e5_last_alert["clustering"] = now
                    alert(
                        "LoginAnalytics/UsernameClustering", "MED",
                        "USERNAME CLUSTERING detected\n"
                        "  " + "\n  ".join(c_alerts) + "\n"
                        "  Indicates breach dump from a single service or\n"
                        "  automated username permutation list.\n"
                        "  MITRE: T1110.004 (Credential Stuffing)"
                    )

        # Engine 8 -- adaptive ML check
        _engine8_update(stats, now)


# ══════════════════════════════════════════════════════════════
#  ENGINE 6: CROSS-IP FINGERPRINT CORRELATION
# ══════════════════════════════════════════════════════════════

_e6_alerted_fps: set = set()


def engine6_loop():
    if not REPUTATION_ENABLED:
        print("[IDS-E6] ip_reputation.py not available -- Engine 6 disabled")
        return

    print(f"[IDS-E6] Cross-IP Fingerprint Correlation engine started "
          f"(threshold: {FP_MULTIIP_MIN} IPs / {FP_WINDOW}s)")
    while True:
        time.sleep(30)
        hits = ip_reputation.get_multiip_fingerprints(min_ips=FP_MULTIIP_MIN)
        for h in hits:
            fp = h["fingerprint"]
            if fp in _e6_alerted_fps:
                continue
            _e6_alerted_fps.add(fp)
            alert("CrossIP/Fingerprint", "HIGH",
                  f"DISTRIBUTED BOT FINGERPRINT detected\n"
                  f"  Fingerprint: {fp}\n"
                  f"  Seen from {h['n_ips']} distinct source IPs "
                  f"in {h['age_sec']:.0f}s:\n"
                  f"    {h['ips']}\n"
                  f"  Threshold: >={FP_MULTIIP_MIN} IPs / {FP_WINDOW}s\n"
                  f"  A single bot config (same UA + Accept headers) being "
                  f"used from multiple IPs indicates proxy pool rotation.\n"
                  f"  MITRE: T1090 (Proxy)")


# ══════════════════════════════════════════════════════════════
#  ENGINE 7: TLS JA3 FINGERPRINTING
# ══════════════════════════════════════════════════════════════

def process_tls_fingerprint(pkt):
    if not JA3_ENABLED:
        return
    result = tls_ja3.engine7_process(pkt)
    if result:
        alert(result["alert_type"], result.get("severity", "HIGH"),
              result["message"])


# ══════════════════════════════════════════════════════════════
#  ENGINE 8: ADAPTIVE ML ANOMALY DETECTION
# ══════════════════════════════════════════════════════════════

def _engine8_update(stats: dict, now: float):
    global _ml_last_sample
    if not ML_ENABLED:
        return

    total        = stats.get("total_attempts", 0)
    success_pct  = stats.get("success_rate_pct", 100.0)
    unknown_pct  = stats.get("unknown_acct_pct", 0.0)
    elapsed      = max(1.0, now - _ml_last_sample) if _ml_last_sample else ML_FEATURE_WINDOW
    rate         = total / elapsed

    with login_times_lock:
        all_cvs = []
        for ip, dq in login_times.items():
            if len(dq) >= 5:
                intervals = [dq[i] - dq[i-1] for i in range(1, len(dq))]
                mean = statistics.mean(intervals)
                if mean > 0:
                    all_cvs.append(statistics.stdev(intervals) / mean)
        global_cv = min(all_cvs) if all_cvs else 1.0

    result = ml_detector.engine8_update(
        cv=global_cv, rate=rate,
        success_pct=success_pct, unknown_pct=unknown_pct,
    )
    _ml_last_sample = now

    if result["anomalous"] and now - _e8_last_alert_ts[0] > _e8_alert_cooldown:
        _e8_last_alert_ts[0] = now
        trig = "\n  ".join(result["triggers"])
        bs   = result["baselines"]
        alert(
            "ML/Adaptive", "HIGH",
            f"ADAPTIVE ANOMALY DETECTED (Engine 8)\n"
            f"  Anomaly score:   {result['score']}/100\n"
            f"  Global min CV:   {global_cv:.4f}  "
            f"(baseline {bs['cv']['mean']:.4f} +/-{bs['cv']['stddev']:.4f})\n"
            f"  Request rate:    {rate:.2f} req/s  "
            f"(baseline {bs['rate']['mean']:.2f})\n"
            f"  Success rate:    {success_pct:.1f}%  "
            f"(baseline {bs['success']['mean']:.1f}%)\n"
            f"  Unknown accts:   {unknown_pct:.1f}%\n"
            f"  Triggers:\n  {trig}\n"
            f"  IsolationForest: {'flagged' if result.get('forest_flag') else 'not flagged'}\n"
            f"  Adaptive ready:  {result['adaptive_ready']}\n"
            f"  MITRE: T1110.004 (Credential Stuffing)"
        )


# ══════════════════════════════════════════════════════════════
#  ENGINE 11: RST/SYN SCANNER DETECTION + DNS CROSS-PROTOCOL
#
#  Source: "Traffic Anomaly Detection – TCP and DNS"
#          Rishi Narang, Infosec, June 2012
#
#  Implements everything the article described that was NOT
#  already present in the codebase:
#
#  Case 1 — SYN-burst detection (sender is the scanner):
#    A host sending many SYN packets is initiating connections
#    to many targets — worm propagation or port scan pattern.
#    SYN sent from one IP >= E11_SYN_THRESHOLD / E11_WINDOW → alert.
#
#  Case 2 — RST-based detection (recipient is the scanner):
#    "If HOST-A receives too many RST flags, there is a probability
#     that HOST-A is trying to scan the nearby systems with SYN."
#    RST received by one IP >= E11_RST_THRESHOLD / E11_WINDOW → alert.
#
#  Log file analysis (article future feature #1):
#    "Parse the log file to get the most 'active' IP address."
#    SYN.log and RAC.log are written; a summary thread prints
#    top-N combined-score IPs every E11_SUMMARY_INTERVAL seconds.
#
#  DHCP lease release (article future feature #2):
#    "If on a Linux host, with a strict rule the tool can release
#     the DHCP lease."
#    Implemented as DHCPIsolator (dry-run by default; set
#    E11_ENABLE_DHCP_RELEASE = True to actually run dhclient -r).
#
#  DNS anomaly indicators NOT in Engine 3:
#    - Sudden hike in DNS queries from a singular IP
#    - Sudden drop in successful DNS queries (resolve-rate drop)
#    - Increase in DNS queries vs. successful TCP sessions
#    - A jump in recursive queries
# ══════════════════════════════════════════════════════════════

E11_ENABLE_DHCP_RELEASE = False   # set True to actually run dhclient -r

# ── E11 state ─────────────────────────────────────────────────
_e11_rst_rx:            dict = defaultdict(deque)   # ip → deque[timestamp] (RST received)
_e11_syn_tx:            dict = defaultdict(deque)   # ip → deque[timestamp] (SYN sent)
_e11_confirmed_scanners: set = set()
_e11_lock                    = threading.Lock()

# DNS cross-protocol state
_e11_dns_total:   dict = defaultdict(deque)   # ip → deque[timestamp]
_e11_dns_nxdom:   dict = defaultdict(deque)   # ip → deque[timestamp]
_e11_dns_recurs:  dict = defaultdict(deque)   # ip → deque[timestamp]
_e11_tcp_sess:    dict = defaultdict(deque)   # ip → deque[timestamp]
_e11_dns_lock          = threading.Lock()

# Log file handles
_e11_syn_log  = None
_e11_rac_log  = None

def _e11_open_logs():
    global _e11_syn_log, _e11_rac_log
    try:
        os.makedirs(E11_LOG_DIR, exist_ok=True)
        _e11_syn_log = open(os.path.join(E11_LOG_DIR, "SYN.log"), "a", buffering=1)
        _e11_rac_log = open(os.path.join(E11_LOG_DIR, "RAC.log"), "a", buffering=1)
    except OSError as e:
        print(f"[E11] WARNING: cannot open log files in {E11_LOG_DIR}: {e}")


def _e11_prune(q: deque, now: float, window: float) -> None:
    cutoff = now - window
    while q and q[0] < cutoff:
        q.popleft()


def _e11_maybe_dhcp_release(scanner_ip: str) -> None:
    """Dry-run or actual DHCP release on confirmed scanner (article future feature #2)."""
    if not scanner_ip.startswith("192.168.100."):
        return
    cmd = "sudo dhclient -r enp0s3"
    print(f"\n[E11-DHCP] Scanner confirmed: {scanner_ip}")
    print(f"[E11-DHCP] Isolation command:  {cmd}")
    if not E11_ENABLE_DHCP_RELEASE:
        print(f"[E11-DHCP] DRY RUN — set E11_ENABLE_DHCP_RELEASE=True to execute")
        return
    if os.getuid() != 0:
        print(f"[E11-DHCP] Not root — cannot release DHCP lease")
        return
    try:
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"[E11-DHCP] DHCP lease released for enp0s3")
        else:
            print(f"[E11-DHCP] dhclient error: {result.stderr.strip()}")
    except Exception as e:
        print(f"[E11-DHCP] Failed: {e}")


def process_e11_rst_syn(pkt):
    """Engine 11 packet handler — RST/SYN scanner detection."""
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    now   = time.time()
    flags = pkt[TCP].flags

    # ── Case 2: RST received → destination is the scanner ──────
    if flags & 0x04:   # RST or RST+ACK
        scanner_ip = pkt[IP].dst

        with _e11_lock:
            q = _e11_rst_rx[scanner_ip]
            q.append(now)
            _e11_prune(q, now, E11_WINDOW)
            count = len(q)

        # Log to RAC.log (mirrors original infosec script)
        if _e11_rac_log:
            try:
                ts = datetime.now().strftime("%H:%M:%S.%f")
                _e11_rac_log.write(
                    f"{ts}  RST  "
                    f"src={pkt[IP].src}:{pkt[TCP].sport}  "
                    f"dst={pkt[IP].dst}:{pkt[TCP].dport}  "
                    f"flags={flags:#04x}\n"
                )
            except Exception:
                pass

        if count >= E11_RST_THRESHOLD and scanner_ip not in _e11_confirmed_scanners:
            with _e11_lock:
                _e11_confirmed_scanners.add(scanner_ip)
            alert("RST/Scanner", "HIGH",
                  f"SCANNER DETECTED (RST-based — Case 2): {scanner_ip}\n"
                  f"  Received {count} RST packets in {E11_WINDOW}s\n"
                  f"  Interpretation: {scanner_ip} is sending SYNs outward;\n"
                  f"  targets are refusing with RST — classic worm/scanner pattern.\n"
                  f"  MITRE: T1595.001 (Active Scanning: Scanning IP Blocks)")
            _e11_maybe_dhcp_release(scanner_ip)

    # ── Case 1: pure SYN sent → source is the scanner ──────────
    if flags == 0x02:   # SYN only (not SYN-ACK)
        src = pkt[IP].src

        with _e11_lock:
            q = _e11_syn_tx[src]
            q.append(now)
            _e11_prune(q, now, E11_WINDOW)
            count = len(q)

        # Log to SYN.log
        if _e11_syn_log:
            try:
                ts = datetime.now().strftime("%H:%M:%S.%f")
                _e11_syn_log.write(
                    f"{ts}  SYN  "
                    f"src={pkt[IP].src}:{pkt[TCP].sport}  "
                    f"dst={pkt[IP].dst}:{pkt[TCP].dport}\n"
                )
            except Exception:
                pass

        if count >= E11_SYN_THRESHOLD and src not in _e11_confirmed_scanners:
            with _e11_lock:
                _e11_confirmed_scanners.add(src)
            alert("SYN/Scanner", "HIGH",
                  f"SCANNER DETECTED (SYN-burst — Case 1): {src}\n"
                  f"  Sent {count} SYN packets in {E11_WINDOW}s\n"
                  f"  Interpretation: {src} is initiating connections to many targets;\n"
                  f"  consistent with worm propagation or port scan.\n"
                  f"  MITRE: T1046 (Network Service Discovery)")

    # ── SYN-ACK: successful TCP session — feeds DNS:TCP ratio ──
    if flags == 0x12:   # SYN-ACK
        session_originator = pkt[IP].dst
        with _e11_dns_lock:
            _e11_tcp_sess[session_originator].append(now)
            _e11_prune(_e11_tcp_sess[session_originator], now, DNS_WINDOW)
        _e11_check_dns_tcp_ratio(session_originator, now)


def process_e11_dns(pkt):
    """Engine 11 DNS cross-protocol anomaly handler."""
    if not pkt.haslayer(DNS) or not pkt.haslayer(IP):
        return

    now    = time.time()
    src    = pkt[IP].src
    dns    = pkt[DNS]
    qr     = dns.qr    # 0=query, 1=response
    rd     = dns.rd    # recursion desired
    rcode  = dns.rcode

    if qr == 0:   # DNS query
        with _e11_dns_lock:
            _e11_dns_total[src].append(now)
            _e11_prune(_e11_dns_total[src], now, DNS_WINDOW)
            count = len(_e11_dns_total[src])

            if rd:
                _e11_dns_recurs[src].append(now)
                _e11_prune(_e11_dns_recurs[src], now, DNS_WINDOW)
                rcnt = len(_e11_dns_recurs[src])
            else:
                rcnt = 0

        _e11_check_dns_surge(src, count, now)
        if rd and rcnt >= E11_RECURSIVE_BURST:
            alert("DNS/RecursiveBurst", "MED",
                  f"RECURSIVE DNS QUERY BURST from {src}\n"
                  f"  {rcnt} recursive queries in {DNS_WINDOW}s "
                  f"(threshold: {E11_RECURSIVE_BURST})\n"
                  f"  Bots use recursive queries to resolve DGA domains "
                  f"through external resolvers.")

    elif qr == 1 and rcode == 3:   # NXDOMAIN response
        with _e11_dns_lock:
            _e11_dns_nxdom[src].append(now)
            _e11_prune(_e11_dns_nxdom[src], now, DNS_WINDOW)
        _e11_check_resolve_drop(src, now)


def _e11_check_dns_surge(src_ip: str, count: int, now: float) -> None:
    """Sudden hike in DNS queries from a singular IP (article indicator #1)."""
    if count >= E11_DNS_SURGE:
        alert("DNS/Surge", "HIGH",
              f"DNS QUERY SURGE from {src_ip}\n"
              f"  {count} queries in {DNS_WINDOW}s "
              f"(threshold: {E11_DNS_SURGE})\n"
              f"  Consistent with DGA C2 lookup sweep or rapid host scanning.")


def _e11_check_resolve_drop(src_ip: str, now: float) -> None:
    """Sudden drop in successful DNS queries (article indicator #2)."""
    with _e11_dns_lock:
        total  = len(_e11_dns_total.get(src_ip, deque()))
        nxdom  = len(_e11_dns_nxdom.get(src_ip, deque()))
    if total < 5:
        return
    resolved = total - nxdom
    ratio    = resolved / total
    if ratio < E11_RESOLVE_DROP_RATIO:
        alert("DNS/ResolveDrop", "MED",
              f"DROP IN DNS RESOLUTION RATE from {src_ip}\n"
              f"  Resolved: {resolved}/{total} ({100*ratio:.1f}%) in {DNS_WINDOW}s\n"
              f"  Threshold: <{100*E11_RESOLVE_DROP_RATIO:.0f}%\n"
              f"  Pattern: DGA domain sweep — most generated names are NXDOMAIN.")


def _e11_check_dns_tcp_ratio(src_ip: str, now: float) -> None:
    """Increase in DNS queries vs. successful TCP sessions (article indicator #3)."""
    with _e11_dns_lock:
        dns = len(_e11_dns_total.get(src_ip, deque()))
        tcp = len(_e11_tcp_sess.get(src_ip, deque()))
    if tcp == 0 or dns < 5:
        return
    ratio = dns / tcp
    if ratio > E11_DNS_TCP_RATIO:
        alert("DNS/TCPRatio", "MED",
              f"DNS:TCP SESSION RATIO ANOMALY for {src_ip}\n"
              f"  {dns} DNS queries but only {tcp} TCP sessions "
              f"in {DNS_WINDOW}s → ratio {ratio:.1f}:1\n"
              f"  Threshold: {E11_DNS_TCP_RATIO}:1\n"
              f"  DNS queries not followed by successful sessions —\n"
              f"  consistent with DGA failed lookups or NXDOMAINs from worm spread.")


def _e11_summary_loop():
    """
    Print top active IPs (article future feature #1 — 'parse log file to get
    most active IP') every E11_SUMMARY_INTERVAL seconds.
    Combines SYN sender count + RST receiver count into a single activity score.
    """
    while True:
        time.sleep(E11_SUMMARY_INTERVAL)
        now = time.time()

        with _e11_lock:
            syn_counts = {
                ip: sum(1 for t in q if t > now - E11_WINDOW)
                for ip, q in _e11_syn_tx.items()
            }
            rst_counts = {
                ip: sum(1 for t in q if t > now - E11_WINDOW)
                for ip, q in _e11_rst_rx.items()
            }

        # Read log files for persistent totals (article approach)
        log_syn: dict = defaultdict(int)
        log_rst: dict = defaultdict(int)
        for log_path, target in [
            (os.path.join(E11_LOG_DIR, "SYN.log"), log_syn),
            (os.path.join(E11_LOG_DIR, "RAC.log"), log_rst),
        ]:
            if not os.path.exists(log_path):
                continue
            try:
                with open(log_path) as f:
                    for line in f:
                        parts = line.split()
                        # SYN.log: "ts SYN src=IP:port dst=..." → parts[2] = "src=IP:port"
                        # RAC.log: "ts RST src=IP:port dst=IP:port ..." → parts[3] = "dst=IP:port"
                        idx = 2 if "SYN" in line else 3
                        if len(parts) > idx:
                            field = parts[idx]
                            prefix = "src=" if "SYN" in line else "dst="
                            if field.startswith(prefix):
                                ip = field[len(prefix):].split(":")[0]
                                target[ip] += 1
            except Exception:
                pass

        all_ips = set(log_syn) | set(log_rst)
        combined = {
            ip: log_syn.get(ip, 0) + log_rst.get(ip, 0)
            for ip in all_ips
        }
        top = sorted(combined.items(), key=lambda x: x[1], reverse=True)[:5]

        if top:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"\n[E11 {ts}] Top scanner IPs (log file analysis — SYN+RST combined):")
            for rank, (ip, score) in enumerate(top, 1):
                confirmed = " ← CONFIRMED" if ip in _e11_confirmed_scanners else ""
                print(f"  #{rank}  {ip:<20}  log_score={score}{confirmed}")


# ══════════════════════════════════════════════════════════════
#  ENGINE 12: PROCWATCH HOST PROCESS SCANNER
#
#  Source: "Day 14 — I Built ProcWatch: A Linux Process Security
#           Scanner for Forensics & Incident Response"
#           Hafiz Shamnad, DEV Community, March 2025
#
#  Adds detections missing from the existing host engine:
#
#  Detection 1  Execution from writable directories:
#    Malware loves /tmp, /dev/shm (RAM-backed — no disk trace),
#    /var/tmp, /run/user.  Legitimate software almost never runs
#    from these paths.
#
#  Detection 3  UID/effective-UID mismatch:
#    real UID ≠ effective UID → SUID privilege escalation in progress.
#    Also catches: root process (eUID=0) running from /home/*.
#
#  Detection 4  Reverse shell & C2 port detection:
#    ESTABLISHED outbound connection to 4444, 5555, 7777, 8888,
#    31337 → "almost certain compromise" (article).
#    LISTEN on those ports → suspicious bind-shell.
#
#  Detection 5  Cryptominer keyword detection:
#    xmrig, monero, stratum, pool, etc. in process name or cmdline.
#    Complements the existing CPU≥85% host engine check.
#
#  Detection 7  LD_PRELOAD injection:
#    LD_PRELOAD=/tmp/libevil.so → user-space rootkit loading a
#    malicious shared library that intercepts system calls.
#    "Catching this is almost always a confirmed compromise."
#
#  (bonus)  Interpreter + network + no terminal:
#    python3/bash/nc with ESTABLISHED connection and no tty →
#    the classic "shell piped over a network socket" revshell.
#
#  Binary recovery hint printed for every finding:
#    sudo cp /proc/<pid>/exe /tmp/recovered_pid<pid>
# ══════════════════════════════════════════════════════════════

# ── E12 constants ─────────────────────────────────────────────
E12_SUSPICIOUS_LOCATIONS = [
    "/tmp", "/dev/shm", "/var/tmp", "/run/user", "/dev/mqueue",
]

E12_SUSPICIOUS_INTERPRETERS = {
    "bash", "sh", "dash", "zsh", "ksh",
    "nc", "ncat", "netcat",
    "python", "python2", "python3",
    "perl", "ruby", "lua",
    "socat",
}

E12_REVSHELL_PORTS = {4444, 5555, 7777, 8888, 31337, 1337, 9001, 6666}

E12_MINER_KEYWORDS = {
    "xmrig", "xmr-stak", "monero", "stratum", "mining-proxy",
    "pool.supportxmr", "pool.minexmr", "cryptonight", "nicehash",
    "ethminer", "cgminer", "bfgminer", "cpuminer", "minerd",
}

E12_SYSTEM_PATHS = (
    "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/",
    "/opt/", "/snap/", "/usr/local/",
)

E12_MINER_CPU_THRESHOLD = 70.0   # % for interpreter-with-no-terminal check

# ── E12 helpers ───────────────────────────────────────────────

def _e12_get_exe(proc) -> str:
    try:
        return proc.exe()
    except Exception:
        return ""

def _e12_get_cmdline(proc) -> list:
    try:
        return proc.cmdline()
    except Exception:
        return []

def _e12_get_environ(proc) -> dict:
    try:
        return proc.environ()
    except Exception:
        return {}

def _e12_get_connections(proc) -> list:
    try:
        return proc.connections(kind="inet")
    except Exception:
        return []

def _e12_get_uids(proc):
    try:
        return proc.uids()
    except Exception:
        return None

def _e12_in_suspicious_location(path: str):
    for loc in E12_SUSPICIOUS_LOCATIONS:
        if path.startswith(loc + "/") or path == loc:
            return loc
    return None

def _e12_recover_hint(pid: int) -> str:
    return f"sudo cp /proc/{pid}/exe /tmp/recovered_pid{pid}"

# ── E12 detectors ─────────────────────────────────────────────

def _e12_scan_process(proc) -> list:
    """
    Run all E12 detectors against a single process.
    Returns list of finding dicts.
    """
    findings = []
    try:
        pid  = proc.pid
        name = (proc.name() or "").lower()
        exe  = _e12_get_exe(proc)
        cmdline_list = _e12_get_cmdline(proc)
        cmdline = " ".join(cmdline_list).lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return findings

    # Detection 1: execution from writable directory
    if exe:
        bad_loc = _e12_in_suspicious_location(exe)
        if bad_loc:
            findings.append({
                "type":     "WRITABLE_DIR_EXECUTION",
                "severity": "CRITICAL",
                "detail": (
                    f"Process running from writable directory {bad_loc}: {exe}\n"
                    f"  PID={pid}  name={proc.name()}\n"
                    f"  Legitimate software almost never runs from here.\n"
                    f"  /dev/shm is RAM-backed — evidence disappears on reboot.\n"
                    f"  Recovery: {_e12_recover_hint(pid)}\n"
                    f"  MITRE: T1036.005 (Masquerading: Match Legitimate Name or Location)"
                ),
            })

    # Detection 3: UID/eUID mismatch + root from home dir
    uids = _e12_get_uids(proc)
    if uids is not None:
        real, effective = uids.real, uids.effective
        if real != effective:
            findings.append({
                "type":     "UID_MISMATCH",
                "severity": "HIGH",
                "detail": (
                    f"UID MISMATCH — SUID escalation: PID={pid} ({proc.name()})\n"
                    f"  real UID={real}  effective UID={effective}\n"
                    f"  A process whose real UID differs from its effective UID\n"
                    f"  is running with elevated privileges via a SUID binary.\n"
                    f"  MITRE: T1548.001 (Setuid and Setgid)"
                ),
            })
        if effective == 0 and exe and exe.startswith("/home/"):
            findings.append({
                "type":     "ROOT_FROM_HOMEDIR",
                "severity": "HIGH",
                "detail": (
                    f"Root process (eUID=0) running from home directory: {exe}\n"
                    f"  PID={pid}  name={proc.name()}\n"
                    f"  Root processes belong in /usr/bin, /sbin — not /home/*.\n"
                    f"  MITRE: T1548 (Abuse Elevation Control Mechanism)"
                ),
            })

    # Detection 4: reverse shell / C2 ports
    connections = _e12_get_connections(proc)
    for conn in connections:
        rport  = conn.raddr.port if conn.raddr else None
        lport  = conn.laddr.port if conn.laddr else None
        status = getattr(conn, "status", "")

        if rport in E12_REVSHELL_PORTS and status == "ESTABLISHED":
            findings.append({
                "type":     "REVSHELL_OUTBOUND",
                "severity": "CRITICAL",
                "detail": (
                    f"REVERSE SHELL / C2 — ESTABLISHED outbound: PID={pid} ({proc.name()})\n"
                    f"  {conn.laddr.ip}:{conn.laddr.port} → "
                    f"{conn.raddr.ip}:{conn.raddr.port}\n"
                    f"  Port {rport} is a classic reverse-shell / C2 listener port.\n"
                    f"  'ESTABLISHED outbound → almost certain compromise' (ProcWatch).\n"
                    f"  Recovery: {_e12_recover_hint(pid)}\n"
                    f"  MITRE: T1059 + T1095"
                ),
            })
        elif lport in E12_REVSHELL_PORTS and status == "LISTEN":
            findings.append({
                "type":     "REVSHELL_LISTEN",
                "severity": "HIGH",
                "detail": (
                    f"BIND SHELL — LISTEN on classic revshell port: PID={pid} ({proc.name()})\n"
                    f"  Listening on port {lport}\n"
                    f"  MITRE: T1071 (Application Layer Protocol)"
                ),
            })

    # Detection 5: miner keywords in cmdline / name
    combined = f"{name} {cmdline}"
    matched = [kw for kw in E12_MINER_KEYWORDS if kw in combined]
    if matched:
        findings.append({
            "type":     "MINER_KEYWORD",
            "severity": "HIGH",
            "detail": (
                f"CRYPTOMINER KEYWORD(S) detected: PID={pid}\n"
                f"  Matched: {', '.join(matched)}\n"
                f"  Name: {proc.name()}\n"
                f"  Cmdline: {' '.join(cmdline_list)[:120]}\n"
                f"  MITRE: T1496 (Resource Hijacking)"
            ),
        })

    # Detection 5b: interpreter at high CPU with no terminal
    is_interp = any(interp in name for interp in E12_SUSPICIOUS_INTERPRETERS)
    if is_interp:
        try:
            cpu      = proc.cpu_percent(interval=0.05)
            terminal = proc.terminal()
        except Exception:
            cpu, terminal = 0.0, "?"
        if cpu >= E12_MINER_CPU_THRESHOLD and terminal is None:
            findings.append({
                "type":     "MINER_BEHAVIOR",
                "severity": "HIGH",
                "detail": (
                    f"HEADLESS HIGH-CPU INTERPRETER: PID={pid} ({proc.name()})\n"
                    f"  CPU={cpu:.1f}%  no terminal\n"
                    f"  Headless high-CPU interpreter is consistent with a\n"
                    f"  scripted miner or cryptojacking payload.\n"
                    f"  MITRE: T1496 (Resource Hijacking)"
                ),
            })

    # Detection 7: LD_PRELOAD injection
    env = _e12_get_environ(proc)
    preload = env.get("LD_PRELOAD", "") or env.get("LD_PRELOAD_PATH", "")
    if preload:
        for lib_path in preload.split(":"):
            lib_path = lib_path.strip()
            if not lib_path:
                continue
            bad_loc = _e12_in_suspicious_location(lib_path)
            if bad_loc:
                findings.append({
                    "type":     "LD_PRELOAD_INJECTION",
                    "severity": "CRITICAL",
                    "detail": (
                        f"LD_PRELOAD INJECTION detected: PID={pid} ({proc.name()})\n"
                        f"  LD_PRELOAD={lib_path}\n"
                        f"  Library loaded from {bad_loc} — intercepting system calls.\n"
                        f"  This is how user-space rootkits hide files and steal credentials.\n"
                        f"  'Catching this is almost always a confirmed compromise' (ProcWatch).\n"
                        f"  MITRE: T1574.006 (Dynamic Linker Hijacking)"
                    ),
                })
            elif lib_path and not lib_path.startswith(E12_SYSTEM_PATHS):
                findings.append({
                    "type":     "LD_PRELOAD_NONSTANDARD",
                    "severity": "MED",
                    "detail": (
                        f"NON-STANDARD LD_PRELOAD: PID={pid} ({proc.name()})\n"
                        f"  LD_PRELOAD={lib_path}\n"
                        f"  Library not in a standard system path.\n"
                        f"  MITRE: T1574.006 (Dynamic Linker Hijacking)"
                    ),
                })

    # Bonus: interpreter + ESTABLISHED connection + no terminal → revshell
    if is_interp and connections:
        established = [
            c for c in connections
            if getattr(c, "status", "") == "ESTABLISHED" and c.raddr
        ]
        if established:
            try:
                terminal = proc.terminal()
            except Exception:
                terminal = None
            if terminal is None:
                for conn in established:
                    findings.append({
                        "type":     "INTERPRETER_REVSHELL",
                        "severity": "CRITICAL",
                        "detail": (
                            f"INTERPRETER + NETWORK + NO TERMINAL: PID={pid} ({proc.name()})\n"
                            f"  {conn.laddr.ip}:{conn.laddr.port} → "
                            f"{conn.raddr.ip}:{conn.raddr.port}\n"
                            f"  Classic reverse shell: shell piped over a network socket.\n"
                            f"  Recovery: {_e12_recover_hint(pid)}\n"
                            f"  MITRE: T1059 (Command and Scripting Interpreter)"
                        ),
                    })

    return findings


# ── E12 watch state ───────────────────────────────────────────
_e12_seen: set = set()
_e12_lock      = threading.Lock()

def _e12_procwatch_loop():
    """Engine 12: scan all processes every E12_SCAN_INTERVAL seconds."""
    if not PROCWATCH_OK:
        # Inline fallback: run detectors without importing procwatch_engine
        pass
    print(f"[IDS-E12] ProcWatch process scanner started "
          f"(scan every {E12_SCAN_INTERVAL}s)")

    while True:
        try:
            for proc in psutil.process_iter():
                try:
                    findings = _e12_scan_process(proc)
                except Exception:
                    continue

                for finding in findings:
                    key = (proc.pid, finding["type"])
                    with _e12_lock:
                        if key in _e12_seen:
                            continue
                        _e12_seen.add(key)

                    alert(
                        f"ProcWatch/{finding['type']}",
                        finding["severity"],
                        finding["detail"],
                    )
        except Exception as e:
            print(f"[IDS-E12] Error during scan: {e}")

        time.sleep(E12_SCAN_INTERVAL)


def _e13_enum_summary_loop():
    """
    Engine 13: Account enumeration monitor.

    Polls the fake_portal /stats/advanced endpoint (same pattern as Engine 5)
    and feeds reset-password probe data into the EnumerationDetector.
    The detector fires when it sees:
      - High volume of probes from one IP in a short window
      - High ratio of not-found responses (breach dump enumeration)
      - Sequential or domain-clustered email patterns (bot list)

    Falls back to processing raw /attempts data if /stats/advanced is
    unavailable or does not include enumeration fields.
    """
    if not ENUM_OK or _enum_detector is None:
        return

    print(f"[IDS-E13] Account enumeration detector started "
          f"(polls {PORTAL_HOST}:{PORTAL_PORT} every {ENGINE5_POLL_SEC}s)")

    _e13_seen_probes: set = set()   # dedup: (ip, email, timestamp bucket)

    while True:
        time.sleep(ENGINE5_POLL_SEC)
        try:
            url = f"http://{PORTAL_HOST}:{PORTAL_PORT}/attempts"
            with urllib.request.urlopen(url, timeout=3) as resp:
                data = json.loads(resp.read().decode())
        except Exception:
            continue

        # /attempts returns a list of {ip, email, status, ts} dicts
        # (or a dict with an 'attempts' list — handle both)
        attempts = data if isinstance(data, list) else data.get("attempts", [])

        for entry in attempts:
            # Only care about reset-password probes (Engine 13 scope)
            endpoint = entry.get("endpoint", entry.get("path", ""))
            if "reset" not in endpoint.lower():
                continue

            ip        = entry.get("ip",    entry.get("src_ip", ""))
            email     = entry.get("email", entry.get("username", ""))
            status    = entry.get("status", "unknown")
            ts_raw    = entry.get("ts",    entry.get("timestamp", 0))
            # Bucket timestamps to 5-second intervals for dedup
            ts_bucket = int(float(ts_raw) / 5) if ts_raw else 0
            key = (ip, email, ts_bucket)
            if key in _e13_seen_probes:
                continue
            _e13_seen_probes.add(key)

            # Feed into detector; it manages its own windows and thresholds
            _enum_detector.probe(
                src_ip=ip,
                email=email,
                found=(status.lower() not in ("not_found", "404", "no_account")),
                alert_cb=alert,
            )

        # Prune dedup set to prevent unbounded growth (keep last 10 000)
        if len(_e13_seen_probes) > 10_000:
            _e13_seen_probes.clear()

SYSTEM_PROCESS_WHITELIST = {
    "kworker", "ksoftirqd", "migration", "rcu_sched",
    "systemd", "python3", "gcc", "make", "apt", "dpkg",
}

def host_monitor_loop():
    print("[HOST] Host-based monitor started (cryptojacking + ghost process)")
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "exe"]):
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    while True:
        time.sleep(5)
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "exe",
                                          "username", "cmdline"]):
            try:
                info    = proc.info
                pid     = info["pid"]
                name    = info["name"] or ""
                cpu     = proc.cpu_percent(interval=None)
                exe     = info["exe"] or ""
                cmdline = " ".join(info["cmdline"] or [])

                # Ghost process check
                exe_path = f"/proc/{pid}/exe"
                try:
                    real_exe = subprocess.check_output(
                        ["readlink", "-f", exe_path],
                        stderr=subprocess.DEVNULL
                    ).decode().strip()
                    if "(deleted)" in real_exe:
                        alert("Host/Ghost", "HIGH",
                              f"GHOST PROCESS detected: PID={pid} name={name}\n"
                              f"  /proc/{pid}/exe -> {real_exe}\n"
                              f"  Binary deleted from disk -- memory-resident payload!\n"
                              f"  Recovery: sudo cp /proc/{pid}/exe /tmp/recovered_{name}\n"
                              f"  MITRE: T1070.004 (Indicator Removal -- File Deletion)")
                except Exception:
                    pass

                # Sustained CPU spike check
                if cpu >= CPU_SPIKE_THRESHOLD:
                    base_name = name.split("/")[0].split(":")[0]
                    if base_name not in SYSTEM_PROCESS_WHITELIST:
                        alert("Host/CPU", "MED",
                              f"HIGH CPU PROCESS: PID={pid} name={name} cpu={cpu:.1f}%\n"
                              f"  cmdline: {cmdline[:100]}\n"
                              f"  exe: {exe}\n"
                              f"  Threshold: {CPU_SPIKE_THRESHOLD}% -- possible cryptojacking\n"
                              f"  MITRE: T1496 (Resource Hijacking)")

                # Name-spoof detection
                comm_path = f"/proc/{pid}/comm"
                if exe and os.path.exists(comm_path):
                    try:
                        with open(comm_path) as f:
                            comm = f.read().strip()
                        exe_base = os.path.basename(exe).split(" ")[0]
                        if (comm in ("kworker/0:1", "syslogd", "kthreadd",
                                     "migration/0", "rcu_bh")
                                and exe_base not in ("", comm)):
                            alert("Host/Spoof", "MED",
                                  f"PROCESS NAME SPOOF detected: PID={pid}\n"
                                  f"  /proc/{pid}/comm = '{comm}'\n"
                                  f"  exe basename    = '{exe_base}'\n"
                                  f"  Classic cryptojacker signature")
                    except Exception:
                        pass

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass


# ══════════════════════════════════════════════════════════════
#  MAIN PACKET DISPATCHER
# ══════════════════════════════════════════════════════════════

def packet_handler(pkt):
    process_volumetric(pkt)
    process_credential_stuffing(pkt)
    process_dns(pkt)
    process_covert_channel(pkt)
    process_tls_fingerprint(pkt)    # Engine 7
    process_e11_rst_syn(pkt)        # Engine 11 — RST/SYN scanner (infosec article)
    process_e11_dns(pkt)            # Engine 11 — DNS cross-protocol anomaly
    if E15_OK and _e15_mod:
        _e15_mod.process_flow_packet(pkt)   # Engine 15 — flow-level detection
    if E16_OK:
        _e16.process_packet(pkt)            # Engine 16 — Slowloris (CRASH-FIXED)
    
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        dport = pkt[TCP].dport
        _lat_det.observe_connection(src, dst, dport)


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print(" AUA CS 232/337 -- Network + Host IDS")
    print(f" Interface: {MONITOR_INTERFACE}")
    print(f" Tarpit: {'ENABLED' if TARPIT_ENABLED else 'DISABLED'}")
    if IDS_LOG_FILE:
        print(f" Alert log: {IDS_LOG_FILE}")
    print()
    print(" Engines:")
    print("   1  Volumetric    -- SYN/UDP flood")
    print("   2  Behavioral    -- Credential stuffing CV timing")
    if TARPIT_ENABLED:
        print("      Tarpit       -- Flags bot IPs in tarpit_state.json")
        print(f"         Auto-unblock after {TARPIT_UNBLOCK_IDLE}s silence")
    print("   3  DNS/DGA       -- High-entropy query burst OR NXDOMAIN burst")
    print(f"      Entropy alert: >={HIGH_ENTROPY_BURST} H>{DGA_ENTROPY_THRESH:.1f} queries in {DNS_WINDOW:.0f}s")
    print(f"      NXDOMAIN alert: >={NXDOMAIN_BURST} NXDOMAINs in {DNS_WINDOW:.0f}s")
    print("   4  DPI/Covert    -- Repeated HTTPS polling pattern")
    print("   5  LoginAnalytics")
    print(f"      Success-rate drop  (< {SUCCESS_RATE_MIN}% with >= {MIN_ATTEMPTS_FOR_RATE} attempts)")
    print(f"      Off-hours surge    (> {OFF_HOURS_PCT_THRESH}% outside 08:00-22:00)")
    print(f"      Unknown-acct spike (> {UNKNOWN_ACCT_PCT_THRESH}% non-existent emails)")
    print(f"      Breached-cred use  (>= {BREACHED_COUNT_THRESH} HIBP-list hits)")
    if CLUSTERING_ENABLED:
        print("      Username clustering  -- domain conc / sequential / prefix")
    else:
        print("      Username clustering  (DISABLED -- username_clustering.py not found)")
    print(f"         Polls {PORTAL_HOST}:{PORTAL_PORT}/stats/advanced every {ENGINE5_POLL_SEC}s")
    print("   6  CrossIP/Fingerprint -- same browser fingerprint from "
          f">={FP_MULTIIP_MIN} IPs in {FP_WINDOW}s")
    if not REPUTATION_ENABLED:
        print("         (DISABLED -- ip_reputation.py not found)")
    print("   7  TLS/JA3       -- TLS ClientHello fingerprinting")
    if JA3_ENABLED:
        print(f"      Known-bad hashes: {len(tls_ja3.KNOWN_BAD_JA3)}")
        print(f"      Multi-IP alert: same JA3 from >={JA3_MULTIIP_MIN} IPs / {JA3_WINDOW}s")
    else:
        print("         (DISABLED -- tls_ja3.py not found)")
    print("   8  ML/Adaptive   -- EWMA baseline + IsolationForest")
    if ML_ENABLED:
        status = ml_detector.global_detector.get_status()
        print(f"      sklearn IsolationForest: "
              f"{'enabled' if status['sklearn_forest'] else 'disabled (pip install scikit-learn)'}")
        print(f"      warmup samples: {ml_detector.WARMUP_SAMPLES}")
    else:
        print("         (DISABLED -- ml_detector.py not found)")
    print("   11 RST/SYN Scanner + DNS Cross-Protocol  [NEW — infosec article]")
    print(f"      RST-based scanner: >= {E11_RST_THRESHOLD} RSTs received / {E11_WINDOW}s")
    print(f"      SYN-burst scanner: >= {E11_SYN_THRESHOLD} SYNs sent / {E11_WINDOW}s")
    print(f"      DNS surge:         >= {E11_DNS_SURGE} queries from one IP / {DNS_WINDOW}s")
    print(f"      Resolve-rate drop: < {100*E11_RESOLVE_DROP_RATIO:.0f}% resolved")
    print(f"      DNS:TCP ratio:     > {E11_DNS_TCP_RATIO}:1")
    print(f"      Recursive burst:   >= {E11_RECURSIVE_BURST} recursive queries / {DNS_WINDOW}s")
    print(f"      Log dir: {E11_LOG_DIR}   DHCP release: {'ENABLED' if E11_ENABLE_DHCP_RELEASE else 'dry-run'}")
    print("   12 ProcWatch Host Process Scanner  [NEW — ProcWatch article]")
    print("      Writable-dir execution (/tmp, /dev/shm, /var/tmp, …)")
    print("      Deleted binary still running  (anti-forensics)")
    print("      UID/eUID mismatch (SUID escalation in progress)")
    print("      Root process running from /home/* directory")
    print(f"      Reverse-shell ports {sorted(E12_REVSHELL_PORTS)} ESTABLISHED")
    print("      Cryptominer keywords (xmrig, monero, stratum, pool, …)")
    print("      LD_PRELOAD injection (user-space rootkit)")
    print("      Interpreter + network + no terminal (revshell pattern)")
    print("      ptrace attachment detection")
    print("      YARA memory pattern scan  (sudo + --yara flag)")
    print("      eBPF syscall snapshot  (execve/connect/clone in /proc/pid/syscall)")
    if PROCWATCH_OK:
        print(f"      [ENABLED]  procwatch_engine.ProcWatchEngine")
    else:
        print("      [DISABLED] procwatch_engine.py not found")
    print("   13 Account Enumeration  [EnumerationDetector]")
    print("      Probes on /reset-password endpoint")
    print("      High not-found ratio, sequential email patterns")
    if ENUM_OK:
        print(f"      [ENABLED]  Engine13/AccountEnumeration (MITRE T1589.002)")
    else:
        print("      [DISABLED] account_enum_sim.py not found")
    print("   15 Flow-Level Detection  [freeCodeCamp article — Rahalkar 2025]")
    print("      Per-flow feature extraction (packet_size, packet_rate,")
    print("      byte_rate, flow_duration, tcp_flags, window_size)")
    print("      Signature: port scan  (packet_size<100B AND packet_rate>50 pkt/s)")
    print("      Signature: syn_flood  (SYN flag AND packet_rate>100 pkt/s)")
    print("      Flow-level IsolationForest on [packet_size, packet_rate, byte_rate]")
    print("      JSON alert log: /tmp/ids_flow_alerts.json  (SIEM-ready NDJSON)")
    if E15_OK:
        status = _e15_mod.get_engine().status()
        print(f"      [ENABLED]  sklearn={status['sklearn_available']}, "
              f"log={status['json_log']}")
    else:
        print("      [DISABLED] flow_analyzer.py not found")
    print("   7+ Engine 7 Patch  (JA3 rotation detector + 2-min cooldown)")
    if E7_PATCH_OK:
        print("      [ENABLED]  ids_detector_patch.patch_ids_detector")
    else:
        print("      [DISABLED] ids_detector_patch.py not found")
    print("   H  Host          -- Ghost process + name spoof + CPU spike")
    print("=" * 60)

    if not SCAPY_OK:
        print("[IDS] Cannot start: Scapy required. pip3 install scapy")
        return

    if IDS_LOG_FILE:
        _open_log_file()
        if _log_fh is not None:
            print(f"[IDS] Logging alerts to {IDS_LOG_FILE}")

    # Open Engine 11 log files
    _e11_open_logs()

    # ── Start background threads ───────────────────────────────
    threading.Thread(target=host_monitor_loop,     daemon=True, name="host-monitor").start()
    threading.Thread(target=engine5_loop,           daemon=True, name="e5-login-analytics").start()
    threading.Thread(target=engine6_loop,           daemon=True, name="e6-fp-correlation").start()
    threading.Thread(target=_e11_summary_loop,      daemon=True, name="e11-rst-summary").start()
    threading.Thread(target=_e12_procwatch_loop,    daemon=True, name="e12-procwatch").start()
    if ENUM_OK:
        threading.Thread(target=_e13_enum_summary_loop,
                         daemon=True, name="e13-enum").start()

    if TARPIT_ENABLED:
        threading.Thread(target=tarpit_auto_unblock_loop,
                         daemon=True, name="tarpit-unblock").start()

    # Apply Engine 7 patch (JA3 rotation detector + cooldown) to packet_handler
    _active_handler = packet_handler
    if E7_PATCH_OK:
        _active_handler = _e7_patch(packet_handler, alert)
        print("[IDS] Engine 7 patch applied to packet_handler.")

    print(f"\n[IDS] Sniffing on {MONITOR_INTERFACE}... (Ctrl+C to stop)\n")
    try:
        sniff(iface=MONITOR_INTERFACE,
              prn=_active_handler,
              store=False)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n[IDS] Stopped. Total alerts fired: {alert_count}")
        if TARPIT_ENABLED:
            print(f"[IDS] Currently tarpitted IPs: {tarpit_state.list_flagged()}")
        with _log_lock:
            if _log_fh is not None:
                try:
                    _log_fh.flush()
                    _log_fh.close()
                except OSError:
                    pass
        # Close Engine 11 log files
        for fh in (_e11_syn_log, _e11_rac_log):
            if fh:
                try:
                    fh.flush()
                    fh.close()
                except Exception:
                    pass


if __name__ == "__main__":
    main()