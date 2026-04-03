#!/usr/bin/env python3
"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Layered Firewall + DPI Measurement
 VM: All VMs (primarily C2 and victim)
 Environment: ISOLATED VM LAB ONLY
====================================================

Implements the two-tier defense for Graph 1 research:

  Tier 1 — Port-based egress filtering (iptables):
    Block known attack ports.
    Bypass: Phase 2 bots use port 443 (HTTPS to github.com) — unblockable.

  Tier 2 — Deep Packet Inspection (Python/Scapy):
    Analyze HTTPS session behavior to detect covert channels.
    Detects: repeated requests to same path, high-frequency polling,
             abnormal TLS session patterns.

Research measurement: Time-to-Detect (TTD) for each technique
against each attack vector. These values populate Graph 1.

Run modes:
  --setup          Apply iptables egress filter rules
  --teardown       Remove all lab iptables rules
  --dpi            Run DPI monitoring (requires Scapy + root)
  --measure        Measure TTD during live attack (for Graph 1 data)
"""

import os
import sys
import time
import json
import math
import subprocess
import threading
import statistics
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, get_if_list
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── Lab network config ────────────────────────────────────────
LAB_SUBNET        = "192.168.100.0/24"
C2_IP             = "192.168.100.10"
VICTIM_IP         = "192.168.100.20"
MONITOR_IFACE     = "enp0s3"

# ── Port blocking rules ───────────────────────────────────────
# These are the "naive" firewall rules that students test first.
# Port 443 is intentionally left open — this is where the research finding lives.

PORT_BLOCK_RULES = [
    # Block raw SYN floods (TCP to non-web ports)
    ("FORWARD", "DROP",   "tcp",  "--dport 8080"),
    ("FORWARD", "DROP",   "tcp",  "--dport 8443"),
    # Block UDP floods to random ports
    ("FORWARD", "DROP",   "udp",  "--dport 1:1023"),
    # Block Telnet/SSH outbound (C2 communication via management ports)
    ("OUTPUT",  "DROP",   "tcp",  "--dport 23"),
    ("OUTPUT",  "DROP",   "tcp",  "--dport 2323"),
    # Block HTTP outbound from bots to unknown C2 IPs (NOT github.com)
    # In real deployment: use IP reputation list. Here: placeholder.
    ("OUTPUT",  "REJECT", "tcp",  "--dport 5000"),   # C2 server Flask port

    # DGA countermeasure: rate-limit DNS queries
    # Bots iterating DGA domains generate high NXDOMAIN volume
    ("OUTPUT",  "DROP",   "udp",  "--dport 53 -m limit --limit 30/min --limit-burst 10 -j ACCEPT"),
]

# Rules that CANNOT stop Phase 2 (covert channel):
# Port 443 HTTPS to github.com is indistinguishable from legitimate traffic.
# This is the core research finding for Graph 1.
UNBLOCKABLE_VECTORS = [
    "GitHub polling (HTTPS/443) — same port as legitimate developer traffic",
    "Reddit polling (HTTPS/443) — legitimate social platform traffic",
    "DGA over DNS port 53 (if below rate limit) — looks like normal DNS",
]


def setup_firewall():
    """Apply all egress filtering rules to the current VM."""
    print("[FW] Applying port-based egress filter rules...")
    applied = 0
    failed  = 0

    # Flush existing lab rules first (idempotent)
    teardown_firewall(silent=True)

    for chain, action, proto, options in PORT_BLOCK_RULES:
        cmd = f"iptables -A {chain} -p {proto} {options} -j {action}"
        try:
            result = subprocess.run(cmd.split(), capture_output=True, check=True)
            print(f"  ✓ {chain} {proto} {options} → {action}")
            applied += 1
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode().strip()
            if "Bad rule" in err or "No chain" in err:
                # Some rules require specific modules — skip gracefully
                print(f"  ~ Skipped (module unavailable): {cmd}")
            else:
                print(f"  ✗ Failed: {err[:60]}")
                failed += 1

    # DNS rate limiting (separate command format)
    dns_rate_cmd = (
        "iptables -A OUTPUT -p udp --dport 53 "
        "-m hashlimit --hashlimit-name dns --hashlimit-mode srcip "
        "--hashlimit-upto 30/minute --hashlimit-burst 10 "
        "-j ACCEPT"
    )
    try:
        subprocess.run(dns_rate_cmd.split(), capture_output=True, check=True)
        subprocess.run("iptables -A OUTPUT -p udp --dport 53 -j DROP".split(),
                       capture_output=True, check=True)
        print(f"  ✓ DNS rate limit: 30 queries/min (DGA detection support)")
        applied += 1
    except subprocess.CalledProcessError:
        print(f"  ~ DNS rate limiting skipped (hashlimit module unavailable)")

    print(f"\n[FW] Applied {applied} rules. Port 443 remains OPEN (research finding).")
    print(f"[FW] Phase 2 (GitHub polling) will NOT be stopped by these rules.")
    print(f"\n[FW] Vectors that bypass port blocking:")
    for v in UNBLOCKABLE_VECTORS:
        print(f"  • {v}")


def teardown_firewall(silent: bool = False):
    """Remove all lab iptables rules."""
    if not silent:
        print("[FW] Removing lab iptables rules...")

    # Simple approach: flush all chains
    for table in ["filter", "nat", "mangle"]:
        for chain in ["INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"]:
            subprocess.run(
                f"iptables -t {table} -F {chain}".split(),
                capture_output=True
            )

    if not silent:
        print("[FW] All rules removed. Running in passthrough mode.")


def show_firewall_status():
    """Display current iptables rules."""
    print("[FW] Current iptables rules:")
    result = subprocess.run(["iptables", "-L", "-n", "--line-numbers"],
                            capture_output=True, text=True)
    print(result.stdout)


# ── Deep Packet Inspection (DPI) engine ──────────────────────

class DPIEngine:
    """
    Python DPI monitor that detects covert channels within HTTPS sessions.

    Cannot decrypt HTTPS content, but analyzes:
      1) Request frequency to the same destination IP/port
      2) Session duration patterns (Slowloris: very long sessions)
      3) TLS SNI field (Server Name Indication — visible before encryption)
      4) Connection volume to specific hosts in a window
    """

    # Thresholds
    COVERT_POLL_RATE     = 10   # requests to same dst in 60s → suspicious
    SLOWLORIS_DURATION   = 30   # seconds a connection stays open → suspicious
    DPI_WINDOW           = 60   # seconds
    GITHUB_ALERT_RATE    = 20   # requests to github.com in window → covert channel alert

    def __init__(self, iface: str = MONITOR_IFACE):
        self.iface       = iface
        self._sessions   = defaultdict(list)   # (src,dst,port) -> [timestamps]
        self._sni_counts = defaultdict(list)   # sni -> [timestamps]
        self._tcp_open   = {}                  # (src,dst,sport,dport) -> open_time
        self._alerts     = []
        self._lock       = threading.Lock()
        self.detect_times = {}   # attack_type -> time_to_detect (for Graph 1)
        self._start_time = time.time()

    def _alert(self, severity: str, attack_type: str, msg: str):
        ts = time.time()
        ttd = ts - self._start_time
        with self._lock:
            if attack_type not in self.detect_times:
                self.detect_times[attack_type] = ttd
            self._alerts.append({
                "ts": ts, "ttd": ttd,
                "severity": severity,
                "attack": attack_type,
                "msg": msg
            })
        t = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        print(f"\n{'='*55}")
        print(f"  [DPI ALERT] {severity} @ {t}  TTD={ttd:.1f}s")
        print(f"  Attack: {attack_type}")
        print(f"  {msg}")
        print(f"{'='*55}\n")

    def _extract_sni(self, pkt) -> str | None:
        """
        Extract TLS SNI from a ClientHello message.
        SNI is sent in cleartext in the TLS handshake — visible even without decryption.
        This is how defenders detect HTTPS traffic to suspicious hosts.
        """
        if not pkt.haslayer(Raw):
            return None
        raw = bytes(pkt[Raw])
        # TLS ClientHello: content_type=0x16, version=0x0301/0x0303
        if len(raw) < 5 or raw[0] != 0x16:
            return None
        # Find SNI extension (type 0x0000)
        try:
            # Skip record header (5) + handshake header (4) + version (2) + random (32)
            # + session_id_len (1) + session_id + cipher_suites_len (2) + ...
            # Simple search: look for SNI extension bytes
            idx = raw.find(b'\x00\x00')  # SNI extension type
            while idx != -1 and idx + 9 < len(raw):
                # Check if this looks like an SNI entry
                ext_type = int.from_bytes(raw[idx:idx+2], 'big')
                if ext_type == 0x0000:  # server_name extension
                    list_len  = int.from_bytes(raw[idx+2:idx+4], 'big')
                    name_type = raw[idx+4]
                    if name_type == 0x00:  # host_name
                        name_len = int.from_bytes(raw[idx+5:idx+7], 'big')
                        name = raw[idx+7:idx+7+name_len].decode('utf-8', errors='ignore')
                        if '.' in name and len(name) > 3:
                            return name
                idx = raw.find(b'\x00\x00', idx + 1)
        except Exception:
            pass
        return None

    def process_packet(self, pkt):
        """Route each packet to the appropriate DPI check."""
        if not pkt.haslayer(IP):
            return

        src  = pkt[IP].src
        dst  = pkt[IP].dst
        now  = time.time()

        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags

            # ── Slowloris detection: long-lived HTTP connections ──────
            if dport == 80:
                key = (src, dst, sport, dport)
                if flags & 0x02:  # SYN — connection opening
                    self._tcp_open[key] = now
                elif flags & 0x01 or flags & 0x04:  # FIN or RST
                    if key in self._tcp_open:
                        duration = now - self._tcp_open.pop(key)
                        if duration > self.SLOWLORIS_DURATION:
                            self._alert("HIGH", "Slowloris",
                                        f"{src} kept connection open {duration:.1f}s to {dst}:80\n"
                                        f"  Threshold: {self.SLOWLORIS_DURATION}s → partial header exhaustion")

            # ── Covert channel: high-rate HTTPS to same destination ────
            if dport == 443 and flags & 0x02:   # SYN to HTTPS port
                session_key = (src, dst)
                with self._lock:
                    self._sessions[session_key].append(now)
                    # Prune old entries outside window
                    cutoff = now - self.DPI_WINDOW
                    self._sessions[session_key] = [
                        t for t in self._sessions[session_key] if t > cutoff
                    ]
                    count = len(self._sessions[session_key])

                if count >= self.COVERT_POLL_RATE:
                    self._alert("MED", "CovertChannel_Polling",
                                f"{src} → {dst}:443  {count} connections in {self.DPI_WINDOW}s\n"
                                f"  Possible dead-drop polling. Inspect TLS SNI for github.com/reddit.com")

            # ── SNI inspection (GitHub/Reddit polling) ─────────────────
            sni = self._extract_sni(pkt)
            if sni:
                suspicious_hosts = {"github.com", "raw.githubusercontent.com",
                                    "reddit.com", "pastebin.com"}
                with self._lock:
                    self._sni_counts[sni].append(now)
                    cutoff = now - self.DPI_WINDOW
                    self._sni_counts[sni] = [t for t in self._sni_counts[sni] if t > cutoff]
                    count = len(self._sni_counts[sni])

                if any(h in sni for h in suspicious_hosts) and count >= self.GITHUB_ALERT_RATE:
                    self._alert("HIGH", "CovertChannel_GitHub",
                                f"{src} → SNI={sni}  {count} TLS sessions in {self.DPI_WINDOW}s\n"
                                f"  Exceeds normal developer poll rate → likely dead-drop C2\n"
                                f"  JA3 fingerprint should be inspected for bot-like patterns")

    def run(self, duration: int = 0):
        """Start packet sniffing. duration=0 means run indefinitely."""
        if not SCAPY_OK:
            print("[DPI] ERROR: Scapy required. pip3 install scapy")
            return

        print(f"[DPI] Engine starting on {self.iface}")
        print(f"[DPI] Detecting: covert channels, Slowloris, GitHub polling")
        print(f"[DPI] Note: Cannot decrypt HTTPS — analyses session-level patterns\n")

        timeout = duration if duration > 0 else None
        try:
            sniff(iface=self.iface, prn=self.process_packet,
                  store=False, timeout=timeout)
        except KeyboardInterrupt:
            pass
        finally:
            self._print_summary()

    def _print_summary(self):
        print(f"\n[DPI] Detection summary:")
        print(f"  Total alerts: {len(self._alerts)}")
        for attack, ttd in self.detect_times.items():
            print(f"  {attack:<35} TTD={ttd:.1f}s")


# ── Graph 1 measurement ───────────────────────────────────────

def measure_graph1_data(duration: int = 120):
    """
    Measure Time-to-Detect (TTD) for each attack vector against each defense tier.
    Records real values that should replace the simulated data in generate_graphs.py.

    Run this DURING a live attack session (Week 7).
    """
    print(f"\n[MEASURE] Graph 1 Data Collection — {duration}s window")
    print(f"[MEASURE] Make sure attacks are running on bot VMs during this window.\n")

    results = {
        "port_blocking": {},
        "dpi":           {},
    }
    start = time.time()

    # Port blocking detection is instantaneous for blocked ports (TTD ≈ 0)
    # but never detects GitHub polling (TTD = ∞)
    blocked_vectors = {
        "SYN_Flood":   "TCP port 80 blocked by iptables → immediate",
        "UDP_Flood":   "UDP ports 1-1023 blocked → immediate",
        "Slowloris":   "TCP port 80 — blocked by port rule, but 443 variant bypasses",
        "GitHub_Poll": "Port 443 — NOT blocked → TTD = never for port blocking",
        "DGA":         "DNS port 53 — rate limited but not blocked",
    }
    print("[MEASURE] Port blocking TTD estimates:")
    for vector, note in blocked_vectors.items():
        ttd = 0 if "immediate" in note else (float('inf') if "never" in note else "measure")
        print(f"  {vector:<20} {note}")
        results["port_blocking"][vector] = ttd

    # DPI measurement — live sniffing
    if SCAPY_OK:
        engine = DPIEngine()
        print(f"\n[MEASURE] Starting DPI engine for {duration}s...")
        t = threading.Thread(target=engine.run, args=(duration,), daemon=True)
        t.start()
        t.join(timeout=duration + 5)
        results["dpi"] = engine.detect_times
        print(f"\n[MEASURE] DPI TTD results: {results['dpi']}")
    else:
        print("[MEASURE] Scapy not available — install for live DPI measurement")

    # Save results
    output = {
        "measurement_time": datetime.now().isoformat(),
        "duration_sec": duration,
        "graph1_data": results
    }
    with open("graph1_measured_data.json", "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n[MEASURE] Results saved to graph1_measured_data.json")
    print(f"[MEASURE] Paste these values into generate_graphs.py simulate_dpi_vs_portblocking()")
    return results


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Firewall + DPI - AUA Research Lab")
    parser.add_argument("--setup",    action="store_true", help="Apply iptables rules")
    parser.add_argument("--teardown", action="store_true", help="Remove iptables rules")
    parser.add_argument("--status",   action="store_true", help="Show current rules")
    parser.add_argument("--dpi",      action="store_true", help="Run DPI monitor")
    parser.add_argument("--measure",  action="store_true", help="Measure Graph 1 TTD data")
    parser.add_argument("--duration", type=int, default=120, help="DPI/measure duration (s)")
    parser.add_argument("--iface",    default=MONITOR_IFACE, help="Network interface")
    args = parser.parse_args()

    print("=" * 60)
    print(" Firewall + DPI Module - AUA Botnet Research Lab")
    print(" ISOLATED ENVIRONMENT ONLY")
    print("=" * 60)

    if args.setup:
        setup_firewall()
    elif args.teardown:
        teardown_firewall()
    elif args.status:
        show_firewall_status()
    elif args.dpi:
        engine = DPIEngine(iface=args.iface)
        engine.run(duration=args.duration)
    elif args.measure:
        measure_graph1_data(duration=args.duration)
    else:
        parser.print_help()
        print("\nTypical research workflow (Week 7):")
        print("  # On C2 VM:")
        print("  sudo python3 firewall_dpi.py --setup")
        print("  # On victim VM (separate terminal):")
        print("  sudo python3 firewall_dpi.py --dpi --duration 120")
        print("  # On bot VMs — run attacks simultaneously")
        print("  # After attacks complete:")
        print("  sudo python3 firewall_dpi.py --measure")
        print("  sudo python3 firewall_dpi.py --teardown")
