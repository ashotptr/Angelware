"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Network + Host IDS (Defensive Layer)
 Run as root: sudo python3 ids_detector.py
 Environment: ISOLATED VM LAB ONLY
====================================================

Three detection engines:
  Engine 1 - Volumetric:  SYN flood, UDP flood
  Engine 2 - Behavioral:  Credential stuffing (CV timing)
  Engine 3 - DNS Anomaly: DGA detection via entropy + NXDOMAIN burst
"""

import threading
import time
import math
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


# ── Configuration ──────────────────────────────────────────────
SYN_THRESHOLD        = 100   # SYNs/sec from one IP before alert
UDP_THRESHOLD        = 200   # UDP packets/sec from one IP before alert
CRED_WINDOW          = 20    # requests to analyze for timing analysis
CV_BOT_THRESHOLD     = 0.15  # CV below this = bot timing detected
DGA_ENTROPY_THRESH   = 3.8   # Shannon entropy > this = suspicious domain
NXDOMAIN_BURST       = 10    # NXDOMAIN count per 30s window before alert
CPU_SPIKE_THRESHOLD  = 85.0  # % CPU per process to flag as cryptojacking
MONITOR_INTERFACE    = "eth0"

# ── Shared alert state ──────────────────────────────────────────
alert_count = 0
alert_lock  = threading.Lock()

def alert(engine, severity, msg):
    global alert_count
    ts = datetime.now().strftime("%H:%M:%S")
    sev_str = {"HIGH": "\033[91m[HIGH]\033[0m", "MED": "\033[93m[MED] \033[0m", "LOW": "\033[94m[LOW] \033[0m"}.get(severity, severity)
    with alert_lock:
        alert_count += 1
        print(f"\n{'='*60}")
        print(f"  ALERT #{alert_count}  {sev_str}  Engine: {engine}  @ {ts}")
        print(f"  {msg}")
        print(f"{'='*60}\n")


# ══════════════════════════════════════════════════════════════
#  ENGINE 1: VOLUMETRIC DETECTION (SYN Flood / UDP Flood)
# ══════════════════════════════════════════════════════════════

syn_counter  = defaultdict(int)   # src_ip -> SYN count in current window
udp_counter  = defaultdict(int)
last_vol_reset = time.time()
VOL_WINDOW   = 1.0  # seconds

def process_volumetric(pkt):
    global last_vol_reset, syn_counter, udp_counter

    now = time.time()
    if now - last_vol_reset >= VOL_WINDOW:
        # Check thresholds before reset
        for ip, count in list(syn_counter.items()):
            if count >= SYN_THRESHOLD:
                alert("Volumetric", "HIGH",
                      f"SYN FLOOD detected: {ip} sent {count} SYNs in {VOL_WINDOW}s -> likely target port exhaustion")
        for ip, count in list(udp_counter.items()):
            if count >= UDP_THRESHOLD:
                alert("Volumetric", "HIGH",
                      f"UDP FLOOD detected: {ip} sent {count} UDP packets in {VOL_WINDOW}s")
        syn_counter.clear()
        udp_counter.clear()
        last_vol_reset = now

    if pkt.haslayer(IP):
        src = pkt[IP].src
        if pkt.haslayer(TCP) and pkt[TCP].flags == 0x02:   # SYN flag only
            syn_counter[src] += 1
        if pkt.haslayer(UDP):
            udp_counter[src] += 1


# ══════════════════════════════════════════════════════════════
#  ENGINE 2: BEHAVIORAL TIMING ANALYSIS (Credential Stuffing)
# ══════════════════════════════════════════════════════════════

# Map: src_ip -> deque of timestamps for HTTP POST to /login
login_times = defaultdict(lambda: deque(maxlen=CRED_WINDOW))

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
    cv = statistics.stdev(intervals) / statistics.mean(intervals)
    return cv

def process_credential_stuffing(pkt):
    """Detect HTTP POST requests to /login and analyze timing patterns."""
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    if pkt[TCP].dport != 80:
        return

    try:
        payload = bytes(pkt[TCP].payload)
        if b"POST" in payload and b"/login" in payload:
            src_ip = pkt[IP].src
            login_times[src_ip].append(time.time())
            q = login_times[src_ip]
            if len(q) >= CRED_WINDOW:
                cv = compute_cv(q)
                if cv < CV_BOT_THRESHOLD:
                    avg_interval = statistics.mean([q[i]-q[i-1] for i in range(1,len(q))])
                    alert("Behavioral/Timing", "HIGH",
                          f"CREDENTIAL STUFFING detected: {src_ip}\n"
                          f"  Requests analyzed: {len(q)}\n"
                          f"  CV = {cv:.4f} (threshold: {CV_BOT_THRESHOLD})\n"
                          f"  Avg interval: {avg_interval:.3f}s  -> bot-like rigid timing")
                    login_times[src_ip].clear()  # reset after alert
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════
#  ENGINE 3: DNS ANOMALY & DGA DETECTION
# ══════════════════════════════════════════════════════════════

nxdomain_counts  = defaultdict(int)   # src_ip -> NXDOMAIN count
queried_domains  = defaultdict(set)   # src_ip -> set of queried domains
last_dns_reset   = time.time()
DNS_WINDOW       = 30.0  # seconds

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
        # Check for NXDOMAIN burst
        for ip, count in list(nxdomain_counts.items()):
            if count >= NXDOMAIN_BURST:
                alert("DNS/DGA", "HIGH",
                      f"DGA ACTIVITY detected: {ip} got {count} NXDOMAIN responses in {DNS_WINDOW}s\n"
                      f"  Sample domains: {list(queried_domains[ip])[:5]}")
        nxdomain_counts.clear()
        queried_domains.clear()
        last_dns_reset = now

    if not pkt.haslayer(DNS):
        return

    src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"

    # DNS Query — check domain entropy
    if pkt.haslayer(DNSQR):
        try:
            qname = pkt[DNSQR].qname.decode("utf-8").rstrip(".")
            name_part = qname.split(".")[0]
            entropy = shannon_entropy(name_part)
            queried_domains[src_ip].add(qname)
            if entropy > DGA_ENTROPY_THRESH and len(name_part) > 6:
                print(f"[DNS-ENG] High-entropy domain query from {src_ip}: {qname}  H={entropy:.2f}")
        except Exception:
            pass

    # DNS Response — detect NXDOMAIN (rcode=3)
    if pkt[DNS].qr == 1 and pkt[DNS].rcode == 3:
        nxdomain_counts[src_ip] += 1


# ══════════════════════════════════════════════════════════════
#  HOST-BASED ENGINE: Process Monitor (psutil)
# ══════════════════════════════════════════════════════════════

BENIGN_NAMES = {"systemd", "init", "kworker", "ksoftirqd", "python3", "sshd", "bash"}

def check_ghost_processes():
    """Detect processes that have deleted their own binary (memory-resident malware)."""
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe = proc.info['exe']
            if exe and "(deleted)" in exe:
                alert("Host-Based", "HIGH",
                      f"GHOST PROCESS detected: PID={proc.info['pid']} name={proc.info['name']}\n"
                      f"  Binary deleted from disk: {exe}\n"
                      f"  This is a memory-resident bot agent (Mirai-style)")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

def check_cpu_abuse():
    """Detect sustained CPU usage (cryptojacking)."""
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            cpu = proc.info['cpu_percent']
            name = proc.info['name'] or ""
            if cpu >= CPU_SPIKE_THRESHOLD and name not in BENIGN_NAMES:
                alert("Host-Based", "MED",
                      f"CPU ABUSE detected: PID={proc.info['pid']} name={name} CPU={cpu:.1f}%\n"
                      f"  Possible cryptojacking (throttled miner at {cpu:.0f}%)")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

def host_monitor_loop():
    """Runs host-based checks every 5 seconds."""
    print("[IDS] Host-based monitor started")
    # Warm up CPU percent baseline
    for proc in psutil.process_iter(['cpu_percent']):
        try: proc.cpu_percent()
        except: pass
    time.sleep(1)

    while True:
        check_ghost_processes()
        check_cpu_abuse()
        time.sleep(5)


# ══════════════════════════════════════════════════════════════
#  MAIN PACKET DISPATCHER
# ══════════════════════════════════════════════════════════════

def packet_handler(pkt):
    """Route each captured packet to the relevant detection engines."""
    if pkt.haslayer(IP):
        process_volumetric(pkt)
        process_credential_stuffing(pkt)
    if pkt.haslayer(DNS):
        process_dns(pkt)


def main():
    print("=" * 60)
    print(" Network + Host IDS - AUA Botnet Research Lab")
    print(" ISOLATED ENVIRONMENT ONLY")
    print(f" Interface: {MONITOR_INTERFACE}")
    print("=" * 60)
    print("\nDetection engines active:")
    print("  [1] Volumetric    - SYN/UDP flood threshold")
    print("  [2] Behavioral    - Credential stuffing CV analysis")
    print("  [3] DNS/DGA       - Entropy + NXDOMAIN burst")
    print("  [4] Host-Based    - Ghost process + CPU abuse\n")

    if not SCAPY_OK:
        print("[IDS] ERROR: Scapy required. pip3 install scapy")
        return

    # Start host-based monitor in background
    host_thread = threading.Thread(target=host_monitor_loop, daemon=True)
    host_thread.start()

    print(f"[IDS] Sniffing on {MONITOR_INTERFACE}... (Ctrl+C to stop)\n")
    try:
        sniff(iface=MONITOR_INTERFACE, prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print(f"\n[IDS] Stopped. Total alerts fired: {alert_count}")


if __name__ == "__main__":
    main()
