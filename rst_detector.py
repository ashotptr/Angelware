"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: RST-Based Scanner Detection
 Environment: ISOLATED VM LAB ONLY

 Source: "Traffic Anomaly Detection – TCP and DNS"
         Rishi Narang, Infosec, June 2012
         https://resources.infosecinstitute.com/

 Teaching point (from article, Case 2):
   "If HOST-A receives too many RST flags, there is a
    probability that the machine HOST-A is trying to scan
    the nearby systems with SYN flag set."

   In other words:
     Too many SYN received  → the SENDER   is infected (scanner).
     Too many RST received  → the RECIPIENT is infected (being scanned from).

   This module implements both sides:
     1. RSTCounter  — detects hosts receiving many RST replies
        (they are scanning outward and getting refused)
     2. SYNCounter  — detects hosts sending many SYNs
        (inbound scanner detection, complements Engine 1)
     3. LogAnalyzer — parses SYN.log / RAC.log written by the
        original infosec script and surfaces the "most active IP"
        (article's first proposed future feature)
     4. DHCPRelease — on confirmed scanner, optionally release the
        DHCP lease to isolate the host (article's second future feature)
        NOTE: only fires if run on a Linux host with dhclient; outputs
        the command for review before executing.

 Integration:
   Standalone:
     sudo python3 rst_detector.py [--interface enp0s3] [--duration 60]
                                  [--log-dir /tmp/rst_logs]
                                  [--analyze-logs <dir>]
                                  [--no-dhcp-release]

   As IDS engine (import from ids_detector.py):
     from rst_detector import RSTCounter, SYNCounter, get_top_active_ips

 Thresholds (all tunable via constructor kwargs):
   RST_THRESHOLD : int = 30   RST packets received per RST_WINDOW seconds
   SYN_THRESHOLD : int = 50   SYN packets sent per SYN_WINDOW seconds
   RST_WINDOW    : float = 5  evaluation window in seconds
   SYN_WINDOW    : float = 5  evaluation window in seconds

 Alert log files produced:
   <log_dir>/SYN.log  — SYN packets from suspicious IPs
   <log_dir>/RAC.log  — RST+ACK packets to suspicious IPs
====================================================
"""

import os
import sys
import time
import argparse
import threading
import subprocess
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP
    SCAPY_OK = True
except ImportError:
    print("[RST] Scapy not installed.  pip3 install scapy")
    SCAPY_OK = False

# ── Defaults ──────────────────────────────────────────────────
DEFAULT_RST_THRESHOLD = 30    # RST packets received in RST_WINDOW → scanner
DEFAULT_SYN_THRESHOLD = 50    # SYN packets sent   in SYN_WINDOW  → scanner
DEFAULT_RST_WINDOW    = 5.0   # seconds
DEFAULT_SYN_WINDOW    = 5.0   # seconds
DEFAULT_INTERFACE     = "lo"  # change to enp0s3 on real VM


# ══════════════════════════════════════════════════════════════
#  COUNTERS
# ══════════════════════════════════════════════════════════════

class RSTCounter:
    """
    Tracks RST packets *received* by each destination IP.

    Article Case 2:
      If HOST-A receives many RST packets, HOST-A is scanning
      outward and the targets are refusing the connections.
      RST received ≥ threshold → the HOST receiving them is the scanner.

    Scapy filter: TCP RST flag (0x04) or RST+ACK (0x14).
    """

    def __init__(self,
                 threshold: int   = DEFAULT_RST_THRESHOLD,
                 window: float    = DEFAULT_RST_WINDOW,
                 log_dir: str     = "/tmp/rst_logs",
                 alert_cb         = None):
        self.threshold = threshold
        self.window    = window
        self.log_dir   = log_dir
        self.alert_cb  = alert_cb or self._default_alert

        # ip → deque of timestamps (RST packets received)
        self._rst_rx: dict = defaultdict(lambda: deque())
        self._lock          = threading.Lock()
        self._confirmed_scanners: set = set()

        os.makedirs(log_dir, exist_ok=True)
        self._rac_log = open(os.path.join(log_dir, "RAC.log"), "a", buffering=1)

    def process_packet(self, pkt) -> None:
        """Call this for every captured TCP packet."""
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        flags = pkt[TCP].flags
        # RST (0x04) or RST+ACK (0x14)
        if not (flags & 0x04):
            return

        # The *destination* of the RST is the host that sent the original SYN.
        # That host is the scanner.
        scanner_ip = pkt[IP].dst
        now        = time.time()

        with self._lock:
            q = self._rst_rx[scanner_ip]
            q.append(now)
            # Prune entries outside the window
            cutoff = now - self.window
            while q and q[0] < cutoff:
                q.popleft()

            count = len(q)

        # Log every RST packet destined for a candidate scanner
        self._log_rac(pkt)

        if count >= self.threshold and scanner_ip not in self._confirmed_scanners:
            with self._lock:
                self._confirmed_scanners.add(scanner_ip)
            msg = (
                f"SCANNER DETECTED (RST-based): {scanner_ip}\n"
                f"  Received {count} RST packets in {self.window}s window\n"
                f"  Interpretation: {scanner_ip} is sending SYNs outward;\n"
                f"  target hosts are refusing with RST — classic worm/scanner pattern.\n"
                f"  MITRE: T1595.001 (Active Scanning: Scanning IP Blocks)"
            )
            self.alert_cb("RST/Scanner", "HIGH", msg)

    def get_top_rst_recipients(self, n: int = 5) -> list:
        """Return top-n IPs receiving the most RST packets (likely scanners)."""
        with self._lock:
            now     = time.time()
            cutoff  = now - self.window
            counts  = {}
            for ip, q in self._rst_rx.items():
                recent = [t for t in q if t > cutoff]
                if recent:
                    counts[ip] = len(recent)
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def _log_rac(self, pkt) -> None:
        ts = datetime.now().strftime("%H:%M:%S.%f")
        try:
            line = (
                f"{ts}  RST  "
                f"src={pkt[IP].src}:{pkt[TCP].sport}  "
                f"dst={pkt[IP].dst}:{pkt[TCP].dport}  "
                f"flags={pkt[TCP].flags:#04x}\n"
            )
            self._rac_log.write(line)
        except Exception:
            pass

    @staticmethod
    def _default_alert(engine: str, severity: str, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n{'='*60}")
        print(f"  ALERT  [{severity}]  Engine: {engine}  @ {ts}")
        print(f"  {msg}")
        print(f"{'='*60}\n")

    def close(self) -> None:
        try:
            self._rac_log.close()
        except Exception:
            pass


class SYNCounter:
    """
    Tracks SYN packets *sent* by each source IP.

    Article Case 1:
      If HOST-B receives many SYN packets from HOST-A, HOST-A is a scanner.
      SYN received from one source ≥ threshold → that source is a scanner.

    This complements ids_detector.py Engine 1 (which is volumetric global
    counting).  SYNCounter logs each suspect SYN to SYN.log and surfaces
    per-source counts for the LogAnalyzer.
    """

    def __init__(self,
                 threshold: int   = DEFAULT_SYN_THRESHOLD,
                 window: float    = DEFAULT_SYN_WINDOW,
                 log_dir: str     = "/tmp/rst_logs",
                 alert_cb         = None):
        self.threshold = threshold
        self.window    = window
        self.log_dir   = log_dir
        self.alert_cb  = alert_cb or RSTCounter._default_alert

        self._syn_tx: dict          = defaultdict(lambda: deque())
        self._lock                  = threading.Lock()
        self._confirmed_scanners: set = set()

        os.makedirs(log_dir, exist_ok=True)
        self._syn_log = open(os.path.join(log_dir, "SYN.log"), "a", buffering=1)

    def process_packet(self, pkt) -> None:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        # SYN only (not SYN-ACK: flag 0x02 only)
        if pkt[TCP].flags != 0x02:
            return

        src = pkt[IP].src
        now = time.time()

        with self._lock:
            q = self._syn_tx[src]
            q.append(now)
            cutoff = now - self.window
            while q and q[0] < cutoff:
                q.popleft()
            count = len(q)

        self._log_syn(pkt)

        if count >= self.threshold and src not in self._confirmed_scanners:
            with self._lock:
                self._confirmed_scanners.add(src)
            msg = (
                f"SCANNER DETECTED (SYN-burst): {src}\n"
                f"  Sent {count} SYN packets in {self.window}s window\n"
                f"  Interpretation: {src} is initiating connections to many hosts/ports;\n"
                f"  consistent with worm propagation or port scan.\n"
                f"  MITRE: T1046 (Network Service Discovery)"
            )
            self.alert_cb("SYN/Scanner", "HIGH", msg)

    def get_top_syn_senders(self, n: int = 5) -> list:
        """Return top-n IPs sending the most SYNs (likely scanners)."""
        with self._lock:
            now    = time.time()
            cutoff = now - self.window
            counts = {}
            for ip, q in self._syn_tx.items():
                recent = [t for t in q if t > cutoff]
                if recent:
                    counts[ip] = len(recent)
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def _log_syn(self, pkt) -> None:
        ts = datetime.now().strftime("%H:%M:%S.%f")
        try:
            line = (
                f"{ts}  SYN  "
                f"src={pkt[IP].src}:{pkt[TCP].sport}  "
                f"dst={pkt[IP].dst}:{pkt[TCP].dport}\n"
            )
            self._syn_log.write(line)
        except Exception:
            pass

    def close(self) -> None:
        try:
            self._syn_log.close()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════
#  LOG ANALYZER  (article future feature #1)
# ══════════════════════════════════════════════════════════════

class LogAnalyzer:
    """
    Parses SYN.log and RAC.log written by SYNCounter / RSTCounter
    and surfaces the most "active" IP addresses.

    From the article:
      "Parse the log file to get the most 'active' IP address."

    Also performs optional DNS anomaly cross-correlation:
      Sudden hike in DNS queries → flag as C2 callback candidate.
      DNS queries > TCP sessions  → anomaly (never followed up with connection).
    """

    def __init__(self, log_dir: str = "/tmp/rst_logs"):
        self.log_dir = log_dir

    def parse_syn_log(self) -> dict:
        """Return {ip: count} from SYN.log."""
        path = os.path.join(self.log_dir, "SYN.log")
        return self._parse_log(path, field_index=1, prefix="src=")

    def parse_rac_log(self) -> dict:
        """Return {ip: count} from RAC.log (RST destinations = scanners)."""
        path = os.path.join(self.log_dir, "RAC.log")
        return self._parse_log(path, field_index=2, prefix="dst=")

    @staticmethod
    def _parse_log(path: str, field_index: int, prefix: str) -> dict:
        counts: dict = defaultdict(int)
        if not os.path.exists(path):
            return dict(counts)
        try:
            with open(path) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) > field_index:
                        field = parts[field_index]
                        if field.startswith(prefix):
                            # e.g. "src=192.168.100.11:54321" → "192.168.100.11"
                            addr = field[len(prefix):].split(":")[0]
                            counts[addr] += 1
        except OSError:
            pass
        return dict(counts)

    def top_active_ips(self, n: int = 10) -> list:
        """
        Merge SYN senders and RST recipients, sum their activity scores,
        and return the top-n most active IPs.  A high combined score
        indicates the IP is both scanning outward and being refused by targets.
        """
        syn_counts = self.parse_syn_log()
        rst_counts = self.parse_rac_log()

        all_ips = set(syn_counts) | set(rst_counts)
        combined = {
            ip: syn_counts.get(ip, 0) + rst_counts.get(ip, 0)
            for ip in all_ips
        }
        return sorted(combined.items(), key=lambda x: x[1], reverse=True)[:n]

    def print_report(self) -> None:
        print("\n" + "="*60)
        print("  LOG ANALYZER REPORT")
        print(f"  Log directory: {self.log_dir}")
        print("="*60)

        syn_top = sorted(self.parse_syn_log().items(),
                         key=lambda x: x[1], reverse=True)[:10]
        rst_top = sorted(self.parse_rac_log().items(),
                         key=lambda x: x[1], reverse=True)[:10]
        combined = self.top_active_ips()

        print("\n  Top SYN SENDERS (likely scanners — Case 1):")
        if syn_top:
            for ip, count in syn_top:
                print(f"    {ip:<20}  {count:>6} SYN packets sent")
        else:
            print("    (SYN.log empty or not found)")

        print("\n  Top RST RECIPIENTS (likely scanners — Case 2):")
        if rst_top:
            for ip, count in rst_top:
                print(f"    {ip:<20}  {count:>6} RST packets received")
        else:
            print("    (RAC.log empty or not found)")

        print("\n  COMBINED ACTIVITY (most active overall):")
        if combined:
            for rank, (ip, score) in enumerate(combined, 1):
                print(f"    #{rank:<2}  {ip:<20}  score={score}")
        else:
            print("    (no data)")

        print("="*60 + "\n")


def get_top_active_ips(log_dir: str = "/tmp/rst_logs", n: int = 5) -> list:
    """Convenience wrapper for ids_detector.py integration."""
    return LogAnalyzer(log_dir).top_active_ips(n)


# ══════════════════════════════════════════════════════════════
#  DHCP RELEASE  (article future feature #2)
# ══════════════════════════════════════════════════════════════

class DHCPIsolator:
    """
    On confirmed scanner detection, release the DHCP lease of the
    scanning host (if this system is the scanner) or log the command
    for operator review.

    From the article:
      "If on a Linux host, with a strict rule the tool can release
       the DHCP lease."

    Safety design:
      - Always prints the command before running it.
      - Requires --enable-dhcp-release flag to actually execute.
      - Only releases the lease for IPs in the 192.168.100.0/24 subnet.
      - Will NOT run as a non-root user (dhclient requires root).
    """

    LAB_SUBNET_PREFIX = "192.168.100."

    def __init__(self, interface: str = "enp0s3", enabled: bool = False):
        self.interface = interface
        self.enabled   = enabled
        self._released: set = set()

    def maybe_isolate(self, scanner_ip: str) -> None:
        """
        If scanner_ip is our own IP, offer to release the DHCP lease.
        (In a P2P detection model this would be called on the bot's own
        detected-malicious IP.)
        """
        if scanner_ip in self._released:
            return
        if not scanner_ip.startswith(self.LAB_SUBNET_PREFIX):
            return

        cmd = f"sudo dhclient -r {self.interface}"
        print(f"\n[DHCP-ISOLATOR] Scanner confirmed: {scanner_ip}")
        print(f"[DHCP-ISOLATOR] Isolation command: {cmd}")

        if not self.enabled:
            print(f"[DHCP-ISOLATOR] DRY RUN — pass --enable-dhcp-release to execute")
            return

        if os.getuid() != 0:
            print(f"[DHCP-ISOLATOR] Not root — cannot release DHCP lease")
            return

        try:
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                print(f"[DHCP-ISOLATOR] Lease released for {self.interface}")
                self._released.add(scanner_ip)
            else:
                print(f"[DHCP-ISOLATOR] dhclient error: {result.stderr.strip()}")
        except Exception as e:
            print(f"[DHCP-ISOLATOR] Failed: {e}")


# ══════════════════════════════════════════════════════════════
#  DNS ANOMALY COUNTERS  (article Section: DNS Anomaly)
# ══════════════════════════════════════════════════════════════

class DNSAnomalyCounter:
    """
    Implements the four DNS anomaly indicators listed in the article
    that are NOT already covered by ids_detector.py Engine 3:

      1. Sudden hike in DNS queries from a singular IP.         ✓ new
      2. Sudden drop in successful DNS queries (resolved rate).  ✓ new
      3. Increase in DNS queries vs. successful TCP sessions.    ✓ new
      4. A jump in recursive queries.                            ✓ new

    Engine 3 in ids_detector.py handles NXDOMAIN burst and high-entropy
    DGA detection.  This class handles the four remaining indicators that
    require cross-protocol correlation (DNS vs. TCP session counts).
    """

    def __init__(self,
                 window: float = 30.0,
                 dns_surge_threshold: int   = 15,  # queries/window from one IP
                 resolve_drop_ratio: float  = 0.30, # resolved / total < 30% → anomaly
                 dns_vs_tcp_ratio: float    = 4.0,  # DNS queries : TCP sessions > 4:1
                 recursive_burst: int       = 10,   # recursive queries from one IP/window
                 alert_cb = None):
        self.window               = window
        self.dns_surge_threshold  = dns_surge_threshold
        self.resolve_drop_ratio   = resolve_drop_ratio
        self.dns_vs_tcp_ratio     = dns_vs_tcp_ratio
        self.recursive_burst      = recursive_burst
        self.alert_cb             = alert_cb or RSTCounter._default_alert

        self._lock             = threading.Lock()
        # per-IP tracking
        self._dns_total:  dict = defaultdict(lambda: deque())
        self._dns_nxdom:  dict = defaultdict(lambda: deque())
        self._dns_recurs: dict = defaultdict(lambda: deque())
        self._tcp_sess:   dict = defaultdict(lambda: deque())

    def record_dns_query(self, src_ip: str, is_recursive: bool = False) -> None:
        now = time.time()
        with self._lock:
            self._dns_total[src_ip].append(now)
            if is_recursive:
                self._dns_recurs[src_ip].append(now)
            self._prune(self._dns_total[src_ip], now)
            self._prune(self._dns_recurs[src_ip], now)

        self._check_dns_surge(src_ip, now)
        self._check_recursive_burst(src_ip, now)

    def record_nxdomain(self, src_ip: str) -> None:
        now = time.time()
        with self._lock:
            self._dns_nxdom[src_ip].append(now)
            self._prune(self._dns_nxdom[src_ip], now)
        self._check_resolve_drop(src_ip, now)

    def record_tcp_session(self, src_ip: str) -> None:
        """Call when a successful TCP connection (post-DNS) is established."""
        now = time.time()
        with self._lock:
            self._tcp_sess[src_ip].append(now)
            self._prune(self._tcp_sess[src_ip], now)
        self._check_dns_vs_tcp(src_ip, now)

    def _prune(self, q: deque, now: float) -> None:
        cutoff = now - self.window
        while q and q[0] < cutoff:
            q.popleft()

    def _count(self, q: deque, now: float) -> int:
        cutoff = now - self.window
        return sum(1 for t in q if t > cutoff)

    def _check_dns_surge(self, src_ip: str, now: float) -> None:
        with self._lock:
            count = self._count(self._dns_total[src_ip], now)
        if count >= self.dns_surge_threshold:
            self.alert_cb(
                "DNS/Surge", "HIGH",
                f"DNS QUERY SURGE from {src_ip}\n"
                f"  {count} queries in {self.window}s "
                f"(threshold: {self.dns_surge_threshold})\n"
                f"  Consistent with DGA C2 lookup sweep or rapid host scanning."
            )

    def _check_resolve_drop(self, src_ip: str, now: float) -> None:
        with self._lock:
            total  = self._count(self._dns_total[src_ip], now)
            nxdom  = self._count(self._dns_nxdom[src_ip], now)
        if total < 5:
            return
        resolved = total - nxdom
        ratio    = resolved / total if total else 1.0
        if ratio < self.resolve_drop_ratio:
            self.alert_cb(
                "DNS/ResolveDrop", "MED",
                f"DROP IN DNS RESOLUTION RATE from {src_ip}\n"
                f"  Resolved: {resolved}/{total} ({100*ratio:.1f}%) in {self.window}s\n"
                f"  Threshold: <{100*self.resolve_drop_ratio:.0f}%\n"
                f"  Pattern: DGA domain sweep — most generated names are NXDOMAIN."
            )

    def _check_dns_vs_tcp(self, src_ip: str, now: float) -> None:
        with self._lock:
            dns   = self._count(self._dns_total[src_ip], now)
            tcp   = self._count(self._tcp_sess[src_ip], now)
        if tcp == 0 or dns < 5:
            return
        ratio = dns / tcp
        if ratio > self.dns_vs_tcp_ratio:
            self.alert_cb(
                "DNS/TCPRatio", "MED",
                f"DNS:TCP SESSION RATIO ANOMALY for {src_ip}\n"
                f"  {dns} DNS queries but only {tcp} TCP sessions "
                f"in {self.window}s → ratio {ratio:.1f}:1\n"
                f"  Threshold: {self.dns_vs_tcp_ratio}:1\n"
                f"  Interpretation: DNS queries not followed by successful sessions —\n"
                f"  consistent with DGA failed lookups or NXDOMAINs from worm spread."
            )

    def _check_recursive_burst(self, src_ip: str, now: float) -> None:
        with self._lock:
            count = self._count(self._dns_recurs[src_ip], now)
        if count >= self.recursive_burst:
            self.alert_cb(
                "DNS/RecursiveBurst", "MED",
                f"RECURSIVE DNS QUERY BURST from {src_ip}\n"
                f"  {count} recursive queries in {self.window}s "
                f"(threshold: {self.recursive_burst})\n"
                f"  Bots use recursive queries to resolve DGA domains "
                f"through external resolvers."
            )


# ══════════════════════════════════════════════════════════════
#  UNIFIED PACKET PROCESSOR
# ══════════════════════════════════════════════════════════════

class TCPDNSAnomalyDetector:
    """
    Orchestrates RSTCounter, SYNCounter, and DNSAnomalyCounter
    over a live packet stream.  Replicates the full detection scope
    of the infosec article's proposed tool.

    Usage:
        detector = TCPDNSAnomalyDetector()
        detector.start(interface="enp0s3", duration=120)
    """

    def __init__(self,
                 log_dir: str          = "/tmp/rst_logs",
                 interface: str        = DEFAULT_INTERFACE,
                 enable_dhcp: bool     = False,
                 alert_cb              = None):
        self.interface  = interface
        self.log_dir    = log_dir
        self._alert_cb  = alert_cb or RSTCounter._default_alert

        self.rst_counter  = RSTCounter(log_dir=log_dir, alert_cb=self._alert_cb)
        self.syn_counter  = SYNCounter(log_dir=log_dir, alert_cb=self._alert_cb)
        self.dns_counter  = DNSAnomalyCounter(alert_cb=self._alert_cb)
        self.dhcp         = DHCPIsolator(interface=interface, enabled=enable_dhcp)
        self.log_analyzer = LogAnalyzer(log_dir=log_dir)
        self._stop        = threading.Event()

    def _process(self, pkt) -> None:
        self.rst_counter.process_packet(pkt)
        self.syn_counter.process_packet(pkt)

        # DNS counter: feed TCP SYN (session attempt) and DNS queries
        try:
            from scapy.all import DNS, DNSQR, DNSRR
            if pkt.haslayer(DNS):
                src = pkt[IP].src if pkt.haslayer(IP) else "?"
                qr  = pkt[DNS].qr  # 0=query, 1=response
                rd  = pkt[DNS].rd  # recursion desired

                if qr == 0:  # DNS query
                    self.dns_counter.record_dns_query(src, is_recursive=bool(rd))
                elif qr == 1:  # DNS response
                    # Check for NXDOMAIN (rcode=3)
                    if pkt[DNS].rcode == 3:
                        self.dns_counter.record_nxdomain(src)

            # Successful TCP session (SYN-ACK seen — connection was accepted)
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                if pkt[TCP].flags == 0x12:  # SYN-ACK
                    # The session originator is the destination of the SYN-ACK
                    self.dns_counter.record_tcp_session(pkt[IP].dst)
        except Exception:
            pass

    def start(self, duration: int = 0) -> None:
        """
        Begin packet capture.  duration=0 means run indefinitely.
        Runs a background thread that prints a summary every 30 seconds.
        """
        if not SCAPY_OK:
            print("[RST-DETECTOR] Scapy unavailable — cannot capture packets.")
            return

        print(f"\n[RST-DETECTOR] Starting on interface '{self.interface}'")
        print(f"[RST-DETECTOR] RST threshold : {self.rst_counter.threshold} RSTs/{self.rst_counter.window}s")
        print(f"[RST-DETECTOR] SYN threshold : {self.syn_counter.threshold} SYNs/{self.syn_counter.window}s")
        print(f"[RST-DETECTOR] Log directory : {self.log_dir}")
        print(f"[RST-DETECTOR] Press Ctrl-C to stop and see summary.\n")

        # Summary thread
        def _summary_loop():
            while not self._stop.is_set():
                time.sleep(30)
                if self._stop.is_set():
                    break
                top_syn = self.syn_counter.get_top_syn_senders(3)
                top_rst = self.rst_counter.get_top_rst_recipients(3)
                if top_syn or top_rst:
                    print("\n[RST-DETECTOR] 30s summary:")
                    if top_syn:
                        print(f"  Top SYN senders: "
                              f"{', '.join(f'{ip}({c})' for ip,c in top_syn)}")
                    if top_rst:
                        print(f"  Top RST recvd:   "
                              f"{', '.join(f'{ip}({c})' for ip,c in top_rst)}")

        t = threading.Thread(target=_summary_loop, daemon=True)
        t.start()

        try:
            sniff(
                iface=self.interface,
                filter="tcp or udp port 53",
                prn=self._process,
                store=False,
                timeout=duration if duration > 0 else None,
                stop_filter=lambda _: self._stop.is_set(),
            )
        except KeyboardInterrupt:
            pass
        finally:
            self._stop.set()
            self._print_final_summary()
            self.rst_counter.close()
            self.syn_counter.close()

    def _print_final_summary(self) -> None:
        print("\n" + "="*60)
        print("  RST DETECTOR — FINAL SUMMARY")
        print("="*60)

        top_syn = self.syn_counter.get_top_syn_senders(10)
        top_rst = self.rst_counter.get_top_rst_recipients(10)

        print("\n  Top SYN senders (Case 1 — scanner sending SYNs):")
        for ip, c in top_syn:
            tag = " ← CONFIRMED SCANNER" if ip in self.syn_counter._confirmed_scanners else ""
            print(f"    {ip:<20}  {c:>6} SYNs sent{tag}")

        print("\n  Top RST receivers (Case 2 — scanner getting refused):")
        for ip, c in top_rst:
            tag = " ← CONFIRMED SCANNER" if ip in self.rst_counter._confirmed_scanners else ""
            print(f"    {ip:<20}  {c:>6} RSTs rcvd{tag}")

        print("\n  Log file analysis:")
        self.log_analyzer.print_report()

    def stop(self) -> None:
        self._stop.set()


# ══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "RST/SYN/DNS Anomaly Detector — AUA Botnet Research Lab\n"
            "Implements: 'Traffic Anomaly Detection – TCP and DNS'\n"
            "(Rishi Narang, Infosec, June 2012)\n\n"
            "Feature 1 (article): SYN/RST flag counting (Cases 1 & 2)\n"
            "Feature 2 (article): Log-file analysis for top active IP\n"
            "Feature 3 (article): DHCP lease release on confirmed scanner\n"
            "Feature 4 (article): P2P mesh coordination (--mesh, --mesh-host)\n"
            "                     'Let the scripts interact with each other\n"
            "                      on different hosts and isolate the malicious\n"
            "                      IP address as a network of analysis.'\n"
            "DNS anomalies:       Surge, NXDOMAIN burst, DNS:TCP ratio,\n"
            "                     recursive burst, resolve-rate drop"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--interface",  default=DEFAULT_INTERFACE,
                        help=f"Network interface (default: {DEFAULT_INTERFACE})")
    parser.add_argument("--duration",   type=int, default=0,
                        help="Capture duration in seconds (0 = infinite)")
    parser.add_argument("--log-dir",    default="/tmp/rst_logs",
                        help="Directory for SYN.log and RAC.log (default: /tmp/rst_logs)")
    parser.add_argument("--analyze-logs", metavar="DIR", default=None,
                        help="Parse existing SYN.log/RAC.log in DIR and print report, then exit")
    parser.add_argument("--enable-dhcp-release", action="store_true",
                        help="Actually run 'dhclient -r' on confirmed scanner (default: dry-run)")
    parser.add_argument("--rst-threshold", type=int, default=DEFAULT_RST_THRESHOLD,
                        help=f"RST packets/window to confirm scanner (default: {DEFAULT_RST_THRESHOLD})")
    parser.add_argument("--syn-threshold", type=int, default=DEFAULT_SYN_THRESHOLD,
                        help=f"SYN packets/window to confirm scanner (default: {DEFAULT_SYN_THRESHOLD})")

    # P2P mesh flags (Article Feature 4)
    mesh_grp = parser.add_argument_group(
        "P2P Mesh (Article Feature 4)",
        "Coordinate scanner detection across multiple hosts.\n"
        "Run rst_detector.py with --mesh on each victim VM.\n"
        "Requires rst_p2p_mesh.py in the same directory."
    )
    mesh_grp.add_argument("--mesh", action="store_true",
                          help="Enable P2P mesh coordination (rst_p2p_mesh.py)")
    mesh_grp.add_argument("--mesh-host", metavar="IP", default=None,
                          help="This node's IP address for the mesh (e.g., 192.168.100.20)")
    mesh_grp.add_argument("--mesh-quorum", type=int, default=2,
                          help="Peer agreements needed to trigger CONSENSUS_ISOLATE (default: 2)")

    args = parser.parse_args()

    if args.analyze_logs:
        LogAnalyzer(args.analyze_logs).print_report()
        sys.exit(0)

    if os.getuid() != 0:
        print("[RST-DETECTOR] WARNING: not running as root — raw socket capture may fail.")
        print("               Run with: sudo python3 rst_detector.py")

    # ── Optionally start the P2P mesh node ─────────────────────────────
    mesh_node = None
    if args.mesh:
        if not args.mesh_host:
            print("[RST-DETECTOR] --mesh requires --mesh-host <this-vm-ip>")
            sys.exit(1)
        try:
            from rst_p2p_mesh import RSTMeshNode
            def _mesh_isolate_cb(scanner_ip, summary):
                print(f"\n[MESH-CONSENSUS] *** ISOLATE {scanner_ip} ***")
                print(f"  Peers agreed: {summary['peers']}")
                print(f"  Avg confidence: {summary['avg_conf']:.0%}")

            mesh_node = RSTMeshNode(
                local_ip=args.mesh_host,
                quorum=args.mesh_quorum,
                isolate_cb=_mesh_isolate_cb,
            )
            mesh_node.start()
            print(f"[RST-DETECTOR] P2P mesh ENABLED — "
                  f"node {args.mesh_host}  quorum={args.mesh_quorum}")
        except ImportError:
            print("[RST-DETECTOR] WARNING: rst_p2p_mesh.py not found — mesh disabled.")
            print("[RST-DETECTOR]   Ensure rst_p2p_mesh.py is in the same directory.")

    # Wire the mesh's report_scanner as the alert callback for the detectors
    def _alert_with_mesh(engine: str, severity: str, msg: str) -> None:
        # Default print
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{ts}] ALERT [{severity}] {engine}\n  {msg}\n")
        # Forward confirmed scanner IPs to the mesh
        if mesh_node and ("SCANNER" in msg or "Case" in msg):
            import re
            m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", msg)
            if m:
                conf = 1.0 if severity == "HIGH" else 0.6
                mesh_node.report_scanner(m.group(1), confidence=conf)

    detector = TCPDNSAnomalyDetector(
        log_dir=args.log_dir,
        interface=args.interface,
        enable_dhcp=args.enable_dhcp_release,
        alert_cb=_alert_with_mesh if args.mesh else None,
    )
    detector.rst_counter.threshold = args.rst_threshold
    detector.syn_counter.threshold = args.syn_threshold

    try:
        detector.start(duration=args.duration)
    finally:
        if mesh_node:
            mesh_node.stop()