"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Network + Host IDS (Defensive Layer)
 Run as root: sudo python3 ids_detector.py
 Environment: ISOLATED VM LAB ONLY
====================================================

Detection engines:
  Engine 1 - Volumetric:      SYN flood, UDP flood
  Engine 2 - Behavioral:      Credential stuffing (CV timing)
              Flags confirmed bots in tarpit_state.json
  Engine 3 - DNS Anomaly:     DGA detection via entropy + NXDOMAIN burst
  Engine 4 - DPI/Covert:      Repeated HTTPS polling -- dead-drop detection
  Engine 5 - Login Analytics: Success-rate drop, off-hours surge,
              unknown-account spike, breached-cred use,
              username clustering (new)
  Engine 6 - CrossIP/Fingerprint: same browser fingerprint from >=3 IPs
  Engine 7 - TLS/JA3: TLS ClientHello fingerprinting (new)
              Fires on known-bad tool hashes (urllib, curl, OpenBullet)
              and on the same fingerprint from >=3 distinct source IPs
  Engine 8 - ML/Adaptive: EWMA baseline + optional IsolationForest (new)
              Replaces static thresholds with learned normal-traffic
              baselines; adapts as service traffic profile shifts
  Host      - Cryptojacking / ghost-process detection
"""

import threading
import time
import math
import os
import statistics
import subprocess
import urllib.request
import json
import psutil
from collections import defaultdict, deque
from datetime import datetime

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

# Engine 7 -- TLS JA3 Fingerprinting (new)
try:
    import tls_ja3
    JA3_ENABLED = True
    print("[IDS] TLS JA3 fingerprinting: ENABLED (Engine 7)")
except ImportError:
    JA3_ENABLED = False
    print("[IDS] INFO: tls_ja3.py not found -- Engine 7 disabled")

# Engine 8 -- Adaptive ML (new)
try:
    import ml_detector
    ML_ENABLED = True
    print("[IDS] Adaptive ML detector: ENABLED (Engine 8)")
except ImportError:
    ML_ENABLED = False
    print("[IDS] INFO: ml_detector.py not found -- Engine 8 disabled")

# Engine 5 extension -- Username clustering (new)
try:
    import username_clustering as _uc_module
    CLUSTERING_ENABLED = True
except ImportError:
    CLUSTERING_ENABLED = False


# ── Configuration ──────────────────────────────────────────────
SYN_THRESHOLD        = 100
UDP_THRESHOLD        = 200
CRED_WINDOW          = 8
CV_BOT_THRESHOLD     = 0.15
DGA_ENTROPY_THRESH   = 3.8
NXDOMAIN_BURST       = 10
HIGH_ENTROPY_BURST   = 5
CPU_SPIKE_THRESHOLD  = 85.0
MONITOR_INTERFACE    = "lo" #enp0s3
TARPIT_UNBLOCK_IDLE  = 120

IDS_LOG_FILE         = "/tmp/ids.log"

# Engine 5 -- Login Analytics
PORTAL_HOST               = "127.0.0.1" #192.168.100.20
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

# Engine 7 -- TLS JA3 (new)
JA3_MULTIIP_MIN  = 3
JA3_WINDOW       = 300

# Engine 8 -- Adaptive ML (new)
ML_FEATURE_WINDOW  = 60
_ml_last_sample    = 0.0
_e8_alert_cooldown = 90.0
_e8_last_alert_ts  = [0.0]   # list to allow mutation inside nested function


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


# ── Shared alert state ──────────────────────────────────────────
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
#  + ENGINE 5e: USERNAME CLUSTERING (new)
#  + ENGINE 8 TRIGGER (new)
# ══════════════════════════════════════════════════════════════

_e5_last_alert: dict = {
    "success_rate": 0.0,
    "off_hours":    0.0,
    "unknown_acct": 0.0,
    "breached":     0.0,
    "clustering":   0.0,   # new
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

        # e) Username clustering (new)
        # Article mapping: "Clustering around similar usernames: high volumes
        #   targeting similar email patterns suggest automation using generic
        #   breach data or brute-force permutations."
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

        # Engine 8 -- adaptive ML check (new)
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
                  f"  This attack evades per-IP rate limiting -- the shared "
                  f"fingerprint is the cross-IP link.\n"
                  f"  Countermeasure: block or challenge the fingerprint, "
                  f"not just individual IPs.\n"
                  f"  MITRE: T1090 (Proxy)")


# ══════════════════════════════════════════════════════════════
#  ENGINE 7: TLS JA3 FINGERPRINTING (new)
#
#  Extracts JA3 fingerprint from TLS ClientHello packets.
#  Fires two alert classes:
#    a) KNOWN_BAD  -- hash matches a known HTTP-library fingerprint
#       (Python urllib, requests, curl, OpenBullet embedded Chromium)
#    b) MULTI_IP   -- same hash from >=3 distinct IPs within window
#       (shared bot framework; evades HTTP header rotation)
#
#  Key teaching point vs Engine 6:
#    Engine 6: HTTP header fingerprint -- defeated by rotating UA/Accept
#    Engine 7: TLS JA3 fingerprint -- cannot be changed without patching
#              the HTTP library, because ClientHello is generated below
#              the application layer
#
#  Article mapping (Castle blog):
#    "Uniform TLS or header signatures: unusual spikes linked to
#     specific TLS fingerprints across login attempts may indicate
#     a shared bot framework."
#  MITRE: T1071.001 (Application Layer Protocol: Web Protocols)
# ══════════════════════════════════════════════════════════════

def process_tls_fingerprint(pkt):
    if not JA3_ENABLED:
        return
    result = tls_ja3.engine7_process(pkt)
    if result:
        alert(result["alert_type"], result.get("severity", "HIGH"),
              result["message"])


# ══════════════════════════════════════════════════════════════
#  ENGINE 8: ADAPTIVE ML ANOMALY DETECTION (new)
#
#  Replaces static thresholds with EWMA baselines that learn the
#  normal traffic pattern for this service. Fires when a feature
#  vector [cv, rate, success_pct, unknown_pct] deviates from the
#  learned baseline by more than Z_THRESHOLD standard deviations.
#
#  Also wraps an optional IsolationForest (sklearn) retrained
#  every 50 samples on normal-traffic windows.
#
#  Article mapping (Castle blog):
#    "Evolving detection signals: the bot ecosystem moves quickly.
#     New Puppeteer forks, anti-fingerprint patches, solver APIs --
#     all ship weekly. Static detections degrade fast. Your system
#     needs to ingest fresh signals, retrain detection logic, and
#     respond to campaign-level shifts as they emerge."
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

    # Extract minimum (worst-case) CV across tracked IPs
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
#  HOST-BASED ENGINE: CRYPTOJACKING + GHOST PROCESS
# ══════════════════════════════════════════════════════════════

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
#  MAIN DISPATCHER
# ══════════════════════════════════════════════════════════════

def packet_handler(pkt):
    process_volumetric(pkt)
    process_credential_stuffing(pkt)
    process_dns(pkt)
    process_covert_channel(pkt)
    process_tls_fingerprint(pkt)   # Engine 7 (new)


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
        print("      Username clustering  -- domain conc / sequential / prefix (NEW)")
    else:
        print("      Username clustering  (DISABLED -- username_clustering.py not found)")
    print(f"         Polls {PORTAL_HOST}:{PORTAL_PORT}/stats/advanced every {ENGINE5_POLL_SEC}s")
    print("   6  CrossIP/Fingerprint -- same browser fingerprint from "
          f">={FP_MULTIIP_MIN} IPs in {FP_WINDOW}s")
    if not REPUTATION_ENABLED:
        print("         (DISABLED -- ip_reputation.py not found)")
    print("   7  TLS/JA3       -- TLS ClientHello fingerprinting (NEW)")
    if JA3_ENABLED:
        print(f"      Known-bad hashes: {len(tls_ja3.KNOWN_BAD_JA3)}")
        print(f"      Multi-IP alert: same JA3 from >={JA3_MULTIIP_MIN} IPs / {JA3_WINDOW}s")
    else:
        print("         (DISABLED -- tls_ja3.py not found)")
    print("   8  ML/Adaptive   -- EWMA baseline + IsolationForest (NEW)")
    if ML_ENABLED:
        status = ml_detector.global_detector.get_status()
        print(f"      sklearn IsolationForest: "
              f"{'enabled' if status['sklearn_forest'] else 'disabled (pip install scikit-learn)'}")
        print(f"      warmup samples: {ml_detector.WARMUP_SAMPLES}")
    else:
        print("         (DISABLED -- ml_detector.py not found)")
    print("   H  Host          -- Ghost process + name spoof + CPU spike")
    print("=" * 60)

    if not SCAPY_OK:
        print("[IDS] Cannot start: Scapy required. pip3 install scapy")
        return

    if IDS_LOG_FILE:
        _open_log_file()
        if _log_fh is not None:
            print(f"[IDS] Logging alerts to {IDS_LOG_FILE}")

    host_t = threading.Thread(target=host_monitor_loop, daemon=True,
                               name="host-monitor")
    host_t.start()

    e5_t = threading.Thread(target=engine5_loop, daemon=True,
                             name="e5-login-analytics")
    e5_t.start()

    e6_t = threading.Thread(target=engine6_loop, daemon=True,
                             name="e6-fp-correlation")
    e6_t.start()

    if TARPIT_ENABLED:
        unblock_t = threading.Thread(target=tarpit_auto_unblock_loop,
                                     daemon=True, name="tarpit-unblock")
        unblock_t.start()

    print(f"\n[IDS] Sniffing on {MONITOR_INTERFACE}... (Ctrl+C to stop)\n")
    try:
        sniff(iface=MONITOR_INTERFACE,
              prn=packet_handler,
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


if __name__ == "__main__":
    main()