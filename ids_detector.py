"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Network + Host IDS (Defensive Layer)
 Run as root: sudo python3 ids_detector.py
 Environment: ISOLATED VM LAB ONLY
====================================================

Three detection engines + covert-channel monitor + host-based monitor:
  Engine 1 - Volumetric:      SYN flood, UDP flood
  Engine 2 - Behavioral:      Credential stuffing (CV timing)
              ↳ NEW: flags confirmed bots in tarpit_state.json
                     so fake_portal.py slows their responses
  Engine 3 - DNS Anomaly:     DGA detection via entropy + NXDOMAIN burst
              ↳ Alert fires on EITHER:
                  (a) ≥ HIGH_ENTROPY_BURST high-entropy domain queries
                      from one IP within DNS_WINDOW, OR
                  (b) ≥ NXDOMAIN_BURST NXDOMAIN responses from one IP
                      within DNS_WINDOW
              Both paths write to the alert log so Graph 3 TPR
              measurement via collect_graph23_data.py works correctly.
  Engine 4 - DPI/Covert:      Repeated HTTPS polling → dead-drop detection
  Host      - Cryptojacking / ghost-process (deleted exe, high CPU)

TARPIT INTEGRATION:
  When Engine 2 fires (CV < CV_BOT_THRESHOLD), the source IP is
  written to tarpit_state.json (via tarpit_state.flag()). The
  portal reads this file and inserts a multi-second delay for that
  IP — keeping the attacker's connection open but making credential
  testing so slow it becomes economically impractical.

  The IDS also monitors the tarpit state: if an IP's request rate
  drops to zero for TARPIT_UNBLOCK_IDLE seconds, it is automatically
  unflagged (bot moved on or changed IP) to prevent stale entries.
"""

import threading
import time
import math
import os
import statistics
import subprocess
import psutil
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, get_if_list
    SCAPY_OK = True
except ImportError:
    print("[IDS] Scapy not installed. Run: pip3 install scapy")
    SCAPY_OK = False

# Import tarpit state (must be in same directory)
try:
    import tarpit_state
    TARPIT_ENABLED = True
    print("[IDS] Tarpit integration: ENABLED")
except ImportError:
    TARPIT_ENABLED = False
    print("[IDS] WARNING: tarpit_state.py not found — tarpit signalling disabled")


# ── Configuration ──────────────────────────────────────────────
SYN_THRESHOLD        = 100    # SYNs/sec from one IP before alert
UDP_THRESHOLD        = 200    # UDP packets/sec from one IP before alert
CRED_WINDOW          = 20     # requests to analyze for timing analysis
CV_BOT_THRESHOLD     = 0.15   # CV below this = bot timing detected
DGA_ENTROPY_THRESH   = 3.8    # Shannon entropy > this = suspicious domain
NXDOMAIN_BURST       = 10     # NXDOMAIN count per 30s window before alert
HIGH_ENTROPY_BURST   = 5      # high-entropy queries per 30s window before alert
CPU_SPIKE_THRESHOLD  = 85.0   # % CPU per process to flag as cryptojacking
MONITOR_INTERFACE    = "enp0s3"
TARPIT_UNBLOCK_IDLE  = 120    # seconds without login requests → auto-unflag

# Alert log file — collect_graph23_data.py reads this to count alerts.
# Set to None to disable file logging (stdout only).
IDS_LOG_FILE         = "/tmp/ids.log"


# ── Log file setup ─────────────────────────────────────────────
_log_fh   = None
_log_lock = threading.Lock()

def _open_log_file():
    """Open the IDS log file for append on first use (thread-safe)."""
    global _log_fh
    if IDS_LOG_FILE is None:
        return
    with _log_lock:
        if _log_fh is None:
            try:
                _log_fh = open(IDS_LOG_FILE, "a", buffering=1)  # line-buffered
            except OSError as e:
                print(f"[IDS] WARNING: cannot open log file {IDS_LOG_FILE}: {e}")
                print(f"[IDS] Alerts will be printed to stdout only.")


# ── Shared alert state ──────────────────────────────────────────
alert_count = 0
alert_lock  = threading.Lock()

def alert(engine, severity, msg):
    """
    Fire an IDS alert.

    Writes to:
      1. stdout  — coloured, human-readable (always)
      2. IDS_LOG_FILE — plain text, one '=' header per alert (when configured)

    collect_graph23_data.py counts lines containing the alert keyword
    (e.g. "CREDENTIAL STUFFING") in IDS_LOG_FILE to measure TPR/FPR.
    """
    global alert_count
    ts = datetime.now().strftime("%H:%M:%S")
    sev_str = {
        "HIGH": "\033[91m[HIGH]\033[0m",
        "MED":  "\033[93m[MED] \033[0m",
        "LOW":  "\033[94m[LOW] \033[0m",
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
VOL_WINDOW     = 1.0   # seconds

def process_volumetric(pkt):
    global last_vol_reset, syn_counter, udp_counter

    now = time.time()
    if now - last_vol_reset >= VOL_WINDOW:
        for ip, count in list(syn_counter.items()):
            if count >= SYN_THRESHOLD:
                alert("Volumetric", "HIGH",
                      f"SYN FLOOD detected: {ip} sent {count} SYNs in {VOL_WINDOW}s "
                      f"→ likely target port exhaustion")
        for ip, count in list(udp_counter.items()):
            if count >= UDP_THRESHOLD:
                alert("Volumetric", "HIGH",
                      f"UDP FLOOD detected: {ip} sent {count} UDP packets in {VOL_WINDOW}s")
        syn_counter.clear()
        udp_counter.clear()
        last_vol_reset = now

    if pkt.haslayer(IP):
        src = pkt[IP].src
        if pkt.haslayer(TCP) and pkt[TCP].flags == 0x02:   # SYN only
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
    """
    Coefficient of Variation = stddev / mean of inter-arrival times.
    Low CV (< 0.15) = bot-like rigid timing.
    High CV (> 0.5) = human-like irregular timing.
    """
    if len(timestamps) < 5:
        return float('inf')
    intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
    if not intervals or statistics.mean(intervals) == 0:
        return float('inf')
    return statistics.stdev(intervals) / statistics.mean(intervals)


def process_credential_stuffing(pkt):
    """
    Detect HTTP POST requests to /login, analyze timing CV.
    On confirmed bot (CV < threshold):
      1. Fire IDS alert
      2. Flag the source IP in tarpit_state → portal adds delay
    """
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[TCP].dport != 80:
        return

    try:
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
                              f"  Avg interval: {avg_interval:.3f}s  → bot-like rigid timing")

                        if TARPIT_ENABLED:
                            if not tarpit_state.is_flagged(src_ip):
                                tarpit_state.flag(src_ip)
                                print(f"[IDS-E2] Tarpit activated for {src_ip} "
                                      f"(CV={cv:.4f})")
                            else:
                                print(f"[IDS-E2] {src_ip} already tarpitted")

                        login_times[src_ip].clear()  # reset window after alert

    except Exception:
        pass


def tarpit_auto_unblock_loop():
    """
    Background thread: if a flagged IP has been silent for
    TARPIT_UNBLOCK_IDLE seconds, automatically remove its tarpit flag.
    """
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
#
#  Two independent alert triggers (both write to the alert log):
#
#    (a) HIGH-ENTROPY QUERY BURST
#        When a single source IP queries >= HIGH_ENTROPY_BURST domains
#        whose label part has Shannon entropy > DGA_ENTROPY_THRESH within
#        DNS_WINDOW seconds.  This catches DGA scanners that may not yet
#        have received NXDOMAIN responses (e.g. if DNS is slow).
#
#    (b) NXDOMAIN BURST
#        When a single source IP receives >= NXDOMAIN_BURST NXDOMAIN
#        responses within DNS_WINDOW seconds.  This is the classic DGA
#        detection signal — a bot iterating through its daily domain list
#        will receive one NXDOMAIN per domain until the registered C2
#        domain is found.
#
#  Both triggers include entropy context in the alert message so analysts
#  can verify the DGA hypothesis from the log without additional tooling.
# ══════════════════════════════════════════════════════════════

nxdomain_counts     = defaultdict(int)
high_entropy_counts = defaultdict(int)   # per-IP count of high-entropy queries
queried_domains     = defaultdict(set)   # per-IP set of queried domains (for context)
last_dns_reset      = time.time()
DNS_WINDOW          = 30.0   # seconds


def shannon_entropy(name: str) -> float:
    """H(X) = -sum P(x_i) log2 P(x_i) for character distribution."""
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
        # ── Check NXDOMAIN burst ───────────────────────────────────
        for ip, count in list(nxdomain_counts.items()):
            if count >= NXDOMAIN_BURST:
                sample = list(queried_domains.get(ip, set()))[:5]
                # Include entropy scores for analyst context
                entropy_context = ", ".join(
                    f"{d}(H={shannon_entropy(d.split('.')[0]):.2f})"
                    for d in sample
                )
                alert("DNS/DGA", "HIGH",
                      f"DGA ACTIVITY detected (NXDOMAIN burst): {ip} "
                      f"got {count} NXDOMAIN responses in {DNS_WINDOW}s\n"
                      f"  Sample domains: {entropy_context}")

        # ── Check high-entropy query burst ─────────────────────────
        for ip, count in list(high_entropy_counts.items()):
            if count >= HIGH_ENTROPY_BURST:
                # Only fire if this IP did NOT already trigger the NXDOMAIN
                # alert above (to avoid duplicate alerts for the same event)
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
                          f"  (NXDOMAIN burst may follow — or DNS is slow)")

        nxdomain_counts.clear()
        high_entropy_counts.clear()
        queried_domains.clear()
        last_dns_reset = now

    if not pkt.haslayer(DNS):
        return

    src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"

    # DNS Query — score domain entropy and track per-IP
    if pkt.haslayer(DNSQR):
        try:
            qname     = pkt[DNSQR].qname.decode("utf-8").rstrip(".")
            name_part = qname.split(".")[0]
            entropy   = shannon_entropy(name_part)
            queried_domains[src_ip].add(qname)
            if entropy > DGA_ENTROPY_THRESH and len(name_part) > 6:
                high_entropy_counts[src_ip] += 1
                # Debug line for live monitoring — does NOT replace the alert
                print(f"[DNS-ENG] High-entropy query from {src_ip}: "
                      f"{qname}  H={entropy:.2f} "
                      f"(window count: {high_entropy_counts[src_ip]}/{HIGH_ENTROPY_BURST})")
        except Exception:
            pass

    # DNS Response — detect NXDOMAIN (rcode=3)
    if pkt[DNS].qr == 1 and pkt[DNS].rcode == 3:
        nxdomain_counts[src_ip] += 1


# ══════════════════════════════════════════════════════════════
#  ENGINE 4: DPI / COVERT CHANNEL MONITOR
# ══════════════════════════════════════════════════════════════

https_conn_tracker  = defaultdict(lambda: defaultdict(list))  # src→dst→[timestamps]
last_https_reset    = time.time()
HTTPS_WINDOW        = 60.0
HTTPS_CONN_THRESH   = 10    # >10 HTTPS connections to same dest in 60s → alert

def process_covert_channel(pkt):
    """
    Detect the Phase 2 dead-drop polling pattern:
    repeated HTTPS SYN connections from one source to the same destination.
    """
    global last_https_reset
    now = time.time()

    if now - last_https_reset >= HTTPS_WINDOW:
        for src, dst_map in list(https_conn_tracker.items()):
            for dst, timestamps in dst_map.items():
                count = len(timestamps)
                if count >= HTTPS_CONN_THRESH:
                    alert("DPI/Covert", "MED",
                          f"COVERT CHANNEL suspected: {src} → {dst}\n"
                          f"  {count} HTTPS SYNs in {HTTPS_WINDOW:.0f}s window\n"
                          f"  Pattern matches dead-drop polling (Phase 2 botnet)\n"
                          f"  Port blocking (443) would NOT detect this — requires DPI")
        https_conn_tracker.clear()
        last_https_reset = now

    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[TCP].dport == 443 and pkt[TCP].flags == 0x02:   # HTTPS SYN
        src = pkt[IP].src
        dst = pkt[IP].dst
        https_conn_tracker[src][dst].append(now)


# ══════════════════════════════════════════════════════════════
#  HOST-BASED ENGINE: CRYPTOJACKING + GHOST PROCESS
# ══════════════════════════════════════════════════════════════

SYSTEM_PROCESS_WHITELIST = {
    "kworker", "ksoftirqd", "migration", "rcu_sched",
    "systemd", "python3", "gcc", "make", "apt", "dpkg",
}

def host_monitor_loop():
    """
    Poll every 5 seconds for:
      1. Memory-resident binaries: /proc/[pid]/exe → (deleted)
      2. Sustained high CPU from unexpected processes
      3. Process name spoofing (/proc/pid/comm ≠ exe basename)
    """
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

                # ── Ghost process check ──────────────────────────
                exe_path = f"/proc/{pid}/exe"
                try:
                    real_exe = subprocess.check_output(
                        ["readlink", "-f", exe_path],
                        stderr=subprocess.DEVNULL
                    ).decode().strip()
                    if "(deleted)" in real_exe:
                        alert("Host/Ghost", "HIGH",
                              f"GHOST PROCESS detected: PID={pid} name={name}\n"
                              f"  /proc/{pid}/exe → {real_exe}\n"
                              f"  Binary deleted from disk — memory-resident payload!\n"
                              f"  MITRE: T1070.004 (Indicator Removal — File Deletion)")
                except Exception:
                    pass

                # ── Sustained CPU spike check ────────────────────
                if cpu >= CPU_SPIKE_THRESHOLD:
                    base_name = name.split("/")[0].split(":")[0]
                    if base_name not in SYSTEM_PROCESS_WHITELIST:
                        alert("Host/CPU", "MED",
                              f"HIGH CPU PROCESS: PID={pid} name={name} cpu={cpu:.1f}%\n"
                              f"  cmdline: {cmdline[:100]}\n"
                              f"  exe: {exe}\n"
                              f"  Threshold: {CPU_SPIKE_THRESHOLD}% — possible cryptojacking\n"
                              f"  MITRE: T1496 (Resource Hijacking)")

                # ── Name-spoof detection ─────────────────────────
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
#  MAIN — DISPATCHER
# ══════════════════════════════════════════════════════════════

def packet_handler(pkt):
    """Route each captured packet to all relevant engines."""
    process_volumetric(pkt)
    process_credential_stuffing(pkt)
    process_dns(pkt)
    process_covert_channel(pkt)


def main():
    print("=" * 60)
    print(" AUA CS 232/337 — Network + Host IDS")
    print(f" Interface: {MONITOR_INTERFACE}")
    print(f" Tarpit: {'ENABLED' if TARPIT_ENABLED else 'DISABLED'}")
    if IDS_LOG_FILE:
        print(f" Alert log: {IDS_LOG_FILE}")
        print(f"   (collect_graph23_data.py reads this for TPR/FPR measurement)")
    print()
    print(" Engines:")
    print("   1  Volumetric    — SYN/UDP flood")
    print("   2  Behavioral    — Credential stuffing CV timing")
    if TARPIT_ENABLED:
        print("      └─ Tarpit    — Flags bot IPs in tarpit_state.json")
        print(f"         └─ Auto-unblock after {TARPIT_UNBLOCK_IDLE}s silence")
    print("   3  DNS/DGA       — High-entropy query burst OR NXDOMAIN burst")
    print(f"      └─ Entropy alert: ≥{HIGH_ENTROPY_BURST} H>{DGA_ENTROPY_THRESH:.1f} queries in {DNS_WINDOW:.0f}s")
    print(f"      └─ NXDOMAIN alert: ≥{NXDOMAIN_BURST} NXDOMAINs in {DNS_WINDOW:.0f}s")
    print("   4  DPI/Covert    — Repeated HTTPS polling pattern")
    print("   H  Host          — Ghost process + name spoof + CPU spike")
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