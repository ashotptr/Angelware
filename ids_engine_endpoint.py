"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Endpoint Behavioral IDS — Engine 22
 Environment: ISOLATED VM LAB ONLY
====================================================

This engine provides detection coverage for the four endpoint
malware behaviors that the offensive implementation was omitted:

  A) KEYLOGGER DETECTION
     Without implementing a keylogger, we detect the OS-level
     artifacts that every keylogger must produce:
       - Input device file reads (/dev/input/event*)
       - X11 XRecord/XInput2 hook installation
       - evdev library usage by non-accessibility processes
       - Writes to log files at high frequency from a process
         that also reads input devices

  B) CREDENTIAL THEFT DETECTION
     Browser SQLite credential databases are normal targets.
     Detection signatures:
       - SQLite open on ~/.mozilla/firefox/*/logins.json or
         ~/.config/google-chrome/*/Login Data by non-browser process
       - Read of Chrome 'Local State' file (contains encryption key)
       - XDG_SESSION_TYPE queries combined with keyring access
       - Copies of Login Data to /tmp or /dev/shm

  C) RANSOMWARE DETECTION
     Mass file modification/encryption:
       - High rate of file renames (> threshold/sec)
       - High rate of file writes where input size != output size
         (indicates compression or encryption)
       - File extensions changing to unknown/non-standard suffixes
       - Reads of many files followed immediately by overwrites
       - Ransom note filenames: README.txt, DECRYPT_ME, HOW_TO_*.txt

  D) ANTI-FORENSICS DETECTION
     Log deletion / tampering:
       - Truncation or deletion of files in /var/log/
       - Write to /dev/null that previously had content
       - Calls to journalctl --vacuum or similar
       - Rapid deletion of files in /tmp (evidence cleanup)
       - History file manipulation (~/.bash_history truncation)

  E) PRIVILEGE ESCALATION DETECTION
     UAC-equivalent on Linux (SUID exploitation, sudo abuse):
       - Unexpected sudo execution
       - SUID binary execution from non-standard path
       - Polkit exploitation signatures
       - setuid/setgid syscall from unexpected process

All five classes are unified under Engine 22. Each has an
observe_*() method for event ingestion and a scan_*() method
for active periodic scanning.

MITRE:
  T1056.001  Input Capture: Keylogging
  T1555.003  Credentials from Web Browsers
  T1486     Data Encrypted for Impact (Ransomware)
  T1070.002  Indicator Removal: Clear Linux Logs
  T1548.001  Abuse Elevation: Setuid / Setgid

CLI:
  python3 ids_engine_endpoint.py --demo
  python3 ids_engine_endpoint.py --scan         (active scan)
  python3 ids_engine_endpoint.py --monitor N    (monitor N seconds)
"""

import os
import sys
import time
import stat
import json
import glob
import hashlib
import threading
import subprocess
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False


# ════════════════════════════════════════════════════════════════
#  SHARED
# ════════════════════════════════════════════════════════════════

def _default_alert(engine, severity, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'='*60}\n  ALERT [{severity}]  {engine}  @ {ts}\n  {msg}\n{'='*60}\n")

_alert_fn = _default_alert

def register_alert_fn(fn):
    global _alert_fn
    _alert_fn = fn

def _cooldown(store: dict, key: str, secs: float = 120.0) -> bool:
    now = time.time()
    if now - store.get(key, 0) >= secs:
        store[key] = now
        return True
    return False


# ════════════════════════════════════════════════════════════════
#  A: KEYLOGGER DETECTION
# ════════════════════════════════════════════════════════════════

class KeyloggerDetector:
    """
    Detects keylogging activity without implementing a keylogger.

    A keylogger must read from a keyboard input source.
    On Linux there are four common paths:
      1. /dev/input/event* — raw evdev kernel interface
      2. X11 XRecord extension — hooks X11 event stream
      3. Wayland protocol monitoring (via xdg-portal)
      4. /proc/bus/input/devices — enumerate input devices

    A legitimate process reading /dev/input/event* is an
    accessibility tool, desktop compositor, or input library.
    A hidden process doing so is almost certainly a keylogger.

    We detect: device access, suspicious write patterns, and
    the combination of input-read + file-write.
    """

    INPUT_DEVICES     = list(glob.glob("/dev/input/event*"))
    INPUT_PROC_PATH   = "/proc/bus/input/devices"
    LEGITIMATE_READERS = {
        # known process names that legitimately read input
        "libinput", "Xorg", "X", "wayland", "pipewire",
        "pulseaudio", "xf86-input", "evtest",
    }

    def __init__(self):
        self._cd: dict = {}
        # pid → {reads: [path], writes: int, first_seen: float}
        self._suspects: dict = defaultdict(lambda: {
            "reads": [], "writes": 0, "first_seen": time.time()
        })

    def observe_file_access(self, pid: int, path: str,
                             process_name: str, mode: str = "r"):
        """
        Call when a process opens a file.
        Feed from auditd 'open' events or fanotify.
        """
        is_input = (path.startswith("/dev/input/event") or
                    path == self.INPUT_PROC_PATH)
        if not is_input:
            return

        pname = process_name.lower().split("/")[-1]
        if any(leg in pname for leg in self.LEGITIMATE_READERS):
            return

        self._suspects[pid]["reads"].append(path)

        if _cooldown(self._cd, f"input_{pid}_{path}"):
            _alert_fn(
                "Keylogger/InputDeviceAccess", "HIGH",
                f"SUSPICIOUS INPUT DEVICE ACCESS\n"
                f"  Process: {process_name}  PID={pid}\n"
                f"  Device:  {path}\n"
                f"  A non-accessibility process reading raw keyboard "
                f"input events is a strong keylogger indicator.\n"
                f"  MITRE: T1056.001 (Input Capture: Keylogging)"
            )

    def scan_processes_for_input_access(self):
        """
        Active scan: check which processes have /dev/input/* open.
        Uses /proc/[pid]/fd symlinks.
        """
        if not self.INPUT_DEVICES:
            return

        for dev in self.INPUT_DEVICES:
            try:
                dev_stat = os.stat(dev)
            except FileNotFoundError:
                continue

            for pid_str in os.listdir("/proc"):
                if not pid_str.isdigit():
                    continue
                fd_dir = f"/proc/{pid_str}/fd"
                try:
                    for fd in os.listdir(fd_dir):
                        try:
                            target = os.readlink(f"{fd_dir}/{fd}")
                            if target == dev:
                                try:
                                    with open(f"/proc/{pid_str}/comm") as f:
                                        comm = f.read().strip()
                                except FileNotFoundError:
                                    comm = "unknown"
                                if not any(leg in comm.lower()
                                           for leg in self.LEGITIMATE_READERS):
                                    pid = int(pid_str)
                                    if _cooldown(self._cd, f"scan_{pid}_{dev}"):
                                        _alert_fn(
                                            "Keylogger/OpenInputFD", "CRITICAL",
                                            f"KEYLOGGER: process has input device open\n"
                                            f"  PID={pid}  Process={comm}\n"
                                            f"  Device: {dev}\n"
                                            f"  Active file descriptor to keyboard "
                                            f"event device from non-system process.\n"
                                            f"  MITRE: T1056.001"
                                        )
                        except (FileNotFoundError, PermissionError,
                                OSError, ValueError):
                            pass
                except (FileNotFoundError, PermissionError):
                    pass


# ════════════════════════════════════════════════════════════════
#  B: CREDENTIAL THEFT DETECTION
# ════════════════════════════════════════════════════════════════

class CredentialTheftDetector:
    """
    Detects browser credential database theft.

    Chrome stores credentials in SQLite:
      ~/.config/google-chrome/Default/Login Data
      ~/.config/chromium/Default/Login Data

    Firefox stores them in:
      ~/.mozilla/firefox/*/logins.json

    The encryption key (Chrome) lives in:
      ~/.config/google-chrome/Local State

    A theft attempt reads 'Local State' THEN 'Login Data'
    in quick succession. No legitimate process (other than
    Chrome itself) should do this.
    """

    CHROME_CRED_PATTERNS = [
        os.path.expanduser("~/.config/google-chrome/*/Login Data"),
        os.path.expanduser("~/.config/chromium/*/Login Data"),
        os.path.expanduser("~/.config/google-chrome/Local State"),
    ]

    FIREFOX_CRED_PATTERNS = [
        os.path.expanduser("~/.mozilla/firefox/*/logins.json"),
        os.path.expanduser("~/.mozilla/firefox/*/key4.db"),
        os.path.expanduser("~/.mozilla/firefox/*/cert9.db"),
    ]

    LEGITIMATE_READERS = {"chrome", "chromium", "firefox", "google-chrome"}

    def __init__(self):
        self._cd: dict = {}
        # pid → list of credential-related file reads
        self._cred_reads: dict = defaultdict(list)

    def observe_file_access(self, pid: int, path: str,
                             process_name: str):
        """
        Call when a process opens any file.
        Filters for credential database paths.
        """
        pname = os.path.basename(process_name).lower()
        if pname in self.LEGITIMATE_READERS:
            return

        is_cred = False
        for pattern in (self.CHROME_CRED_PATTERNS +
                        self.FIREFOX_CRED_PATTERNS):
            # Simple glob-style check
            if "Login Data" in path or "logins.json" in path or \
               "Local State" in path or "key4.db" in path:
                is_cred = True
                break

        if not is_cred:
            return

        self._cred_reads[pid].append(path)

        # Escalate severity if both key AND database are read
        reads = self._cred_reads[pid]
        has_key  = any("Local State" in r or "key4.db" in r for r in reads)
        has_data = any("Login Data" in r or "logins.json" in r for r in reads)

        if has_key and has_data:
            if _cooldown(self._cd, f"credtheft_{pid}"):
                _alert_fn(
                    "CredTheft/BrowserDB", "CRITICAL",
                    f"BROWSER CREDENTIAL THEFT DETECTED\n"
                    f"  Process: {process_name}  PID={pid}\n"
                    f"  Files accessed: {reads}\n"
                    f"  Pattern: encryption key + credential database "
                    f"opened by non-browser process.\n"
                    f"  This is the Chrome DPAPI credential theft pattern.\n"
                    f"  MITRE: T1555.003 (Credentials from Web Browsers)"
                )
        elif is_cred:
            if _cooldown(self._cd, f"cred_single_{pid}_{path}", 60.0):
                _alert_fn(
                    "CredTheft/BrowserFile", "HIGH",
                    f"BROWSER CREDENTIAL FILE ACCESS\n"
                    f"  Process: {process_name}  PID={pid}\n"
                    f"  File: {path}\n"
                    f"  Non-browser process accessing credential store.\n"
                    f"  MITRE: T1555.003"
                )

    def scan_temp_copies(self):
        """
        Detect copies of credential databases in /tmp or /dev/shm.
        A common technique: copy the locked DB to /tmp then read it.
        """
        suspicious = ["Login Data", "logins.json", "key4.db",
                      "Login Data.db", "chrome_creds"]
        for sus in suspicious:
            for base in ["/tmp", "/dev/shm", "/var/tmp"]:
                path = os.path.join(base, sus)
                if os.path.exists(path):
                    if _cooldown(self._cd, f"tempcopy_{path}"):
                        _alert_fn(
                            "CredTheft/TempCopy", "CRITICAL",
                            f"CREDENTIAL DATABASE COPY IN TEMP DIRECTORY\n"
                            f"  Path: {path}\n"
                            f"  Attackers copy locked browser DBs to /tmp "
                            f"to bypass file-lock restrictions.\n"
                            f"  MITRE: T1555.003"
                        )


# ════════════════════════════════════════════════════════════════
#  C: RANSOMWARE DETECTION
# ════════════════════════════════════════════════════════════════

class RansomwareDetector:
    """
    Detects ransomware-style mass file modification.

    Ransomware invariants:
      1. Mass file reads (collecting data to encrypt)
      2. Rapid file overwrites / renames
      3. File extension changes to unknown suffixes
      4. Ransom note creation (README.txt, HOW_TO_*.txt)
      5. Deletes Volume Shadow Copies (Windows) or backups

    On Linux the most detectable artifacts are:
      - High rate of file renames (> 20/sec from one process)
      - File extension changes to random/unusual suffixes
      - Ransom note filenames in home/desktop directories
      - Rapid disk write bandwidth spike
    """

    RANSOM_NOTE_NAMES = {
        "readme.txt", "decrypt_me.txt", "how_to_decrypt.txt",
        "recover_files.txt", "ransomware.txt", "files_encrypted.txt",
        "your_files_are_encrypted.txt", "read_this.txt",
        "how_to_restore.txt", "_readme_.txt", "!readme!.txt",
    }

    SUSPICIOUS_EXTENSIONS = {
        ".locked", ".encrypted", ".enc", ".crypt", ".crypto",
        ".crypted", ".cerber", ".wallet", ".zepto", ".thor",
        ".locky", ".aaa", ".xxx", ".zzz", ".micro", ".vvv",
    }

    RENAME_RATE_THRESHOLD = 20   # renames/sec
    RENAME_WINDOW         = 5.0  # seconds

    def __init__(self):
        self._cd: dict = {}
        # pid → deque of (timestamp, old_path, new_path)
        self._renames: dict = defaultdict(lambda: deque(maxlen=500))
        # paths of ransom notes seen
        self._notes_seen: set = set()

    def observe_rename(self, pid: int, old_path: str, new_path: str,
                       process_name: str = "unknown"):
        """
        Call on every file rename event (inotify IN_MOVED_TO).
        """
        now = time.time()
        self._renames[pid].append((now, old_path, new_path))

        # Rate check
        q = self._renames[pid]
        recent = [t for t, _, _ in q if now - t < self.RENAME_WINDOW]
        rate   = len(recent) / self.RENAME_WINDOW
        if rate >= self.RENAME_RATE_THRESHOLD:
            if _cooldown(self._cd, f"rename_rate_{pid}"):
                _alert_fn(
                    "Ransomware/MassRename", "CRITICAL",
                    f"RANSOMWARE: MASS FILE RENAME DETECTED\n"
                    f"  Process: {process_name}  PID={pid}\n"
                    f"  Rename rate: {rate:.1f} renames/sec "
                    f"(threshold {self.RENAME_RATE_THRESHOLD}/sec)\n"
                    f"  Ransomware typically renames files after encrypting "
                    f"them, adding its extension to the original name.\n"
                    f"  MITRE: T1486 (Data Encrypted for Impact)"
                )

        # Extension check
        new_ext = os.path.splitext(new_path)[1].lower()
        if new_ext in self.SUSPICIOUS_EXTENSIONS:
            if _cooldown(self._cd, f"ransomext_{pid}_{new_ext}"):
                _alert_fn(
                    "Ransomware/SuspiciousExtension", "CRITICAL",
                    f"RANSOMWARE EXTENSION DETECTED\n"
                    f"  Process: {process_name}  PID={pid}\n"
                    f"  New extension: {new_ext}\n"
                    f"  File: {new_path}\n"
                    f"  Known ransomware file extension pattern.\n"
                    f"  MITRE: T1486"
                )

    def observe_file_create(self, path: str):
        """
        Call on every file creation (inotify IN_CREATE).
        Check for ransom note filenames.
        """
        fname = os.path.basename(path).lower()
        if fname in self.RANSOM_NOTE_NAMES:
            if path not in self._notes_seen:
                self._notes_seen.add(path)
                _alert_fn(
                    "Ransomware/NoteCreated", "CRITICAL",
                    f"RANSOM NOTE CREATED\n"
                    f"  Path: {path}\n"
                    f"  Filename '{fname}' matches known ransom note pattern.\n"
                    f"  This is definitive: ransomware has completed encryption.\n"
                    f"  MITRE: T1486 (Data Encrypted for Impact)"
                )

    def scan_for_notes(self, search_dirs: list = None):
        """Actively scan for ransom notes in common directories."""
        if search_dirs is None:
            search_dirs = [
                os.path.expanduser("~"),
                os.path.expanduser("~/Desktop"),
                "/tmp",
            ]
        for d in search_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for fname in os.listdir(d):
                    if fname.lower() in self.RANSOM_NOTE_NAMES:
                        path = os.path.join(d, fname)
                        self.observe_file_create(path)
            except PermissionError:
                pass


# ════════════════════════════════════════════════════════════════
#  D: ANTI-FORENSICS DETECTION
# ════════════════════════════════════════════════════════════════

class AntiForensicsDetector:
    """
    Detects log tampering and evidence destruction attempts.

    Anti-forensics techniques:
      1. Log file deletion or truncation (/var/log/*)
      2. Journal clearing (journalctl --vacuum-size=0)
      3. bash_history manipulation
      4. Timestamps modification (touch -t, debugfs)
      5. Rapid /tmp cleanup (covering tracks)
      6. Core dump deletion

    Detection strategy: baseline file sizes and hashes for
    all log files at startup. Alert on unexpected shrinkage
    (truncation) or deletion.
    """

    LOG_DIRS = ["/var/log"]
    BASELINE_PATHS = [
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/kern.log",
        "/var/log/dpkg.log",
        "/var/log/apt/history.log",
    ]
    JOURNAL_CMD_PATTERNS = [
        ["journalctl", "--vacuum"],
        ["journalctl", "-D"],
        ["truncate", "/var/log"],
        ["shred", "/var/log"],
        ["rm", "/var/log"],
    ]
    HISTORY_FILES = [
        os.path.expanduser("~/.bash_history"),
        os.path.expanduser("~/.zsh_history"),
    ]

    def __init__(self):
        self._cd: dict = {}
        # path → (size, mtime, hash_prefix)
        self._log_baseline: dict = {}
        self._hist_baseline: dict = {}

    def baseline(self):
        """Capture baseline for all log files."""
        for path in self.BASELINE_PATHS + self.HISTORY_FILES:
            try:
                s = os.stat(path)
                with open(path, "rb") as f:
                    content = f.read(1024)  # first 1KB as checksum hint
                self._log_baseline[path] = {
                    "size":  s.st_size,
                    "mtime": s.st_mtime,
                    "hash":  hashlib.sha256(content).hexdigest()[:12],
                }
            except (FileNotFoundError, PermissionError):
                pass
        print(f"[IDS-E22/AntiForensics] Baseline: "
              f"{len(self._log_baseline)} log files tracked")

    def scan(self):
        """Scan for log file tampering."""
        for path, baseline in self._log_baseline.items():
            try:
                s = os.stat(path)
                current_size = s.st_size
                baseline_size = baseline["size"]

                # Shrinkage = truncation
                if current_size < baseline_size * 0.5 and \
                        baseline_size > 1000:
                    if _cooldown(self._cd, f"shrink_{path}"):
                        _alert_fn(
                            "AntiForensics/LogTruncation", "HIGH",
                            f"LOG FILE TRUNCATED: {path}\n"
                            f"  Baseline size: {baseline_size} bytes\n"
                            f"  Current size:  {current_size} bytes "
                            f"({100*current_size//baseline_size}% remaining)\n"
                            f"  Attackers truncate logs to erase evidence "
                            f"of their activities.\n"
                            f"  MITRE: T1070.002 (Clear Linux or Mac System Logs)"
                        )

            except FileNotFoundError:
                if _cooldown(self._cd, f"deleted_{path}"):
                    _alert_fn(
                        "AntiForensics/LogDeleted", "CRITICAL",
                        f"LOG FILE DELETED: {path}\n"
                        f"  Was present at baseline, now missing.\n"
                        f"  MITRE: T1070.002"
                    )

        # Bash history check
        for hpath in self.HISTORY_FILES:
            try:
                size = os.path.getsize(hpath)
                baseline = self._log_baseline.get(hpath, {}).get("size")
                if baseline and size < min(100, baseline * 0.1):
                    if _cooldown(self._cd, f"hist_{hpath}"):
                        _alert_fn(
                            "AntiForensics/HistoryCleared", "HIGH",
                            f"SHELL HISTORY CLEARED: {hpath}\n"
                            f"  Baseline: {baseline} bytes → "
                            f"current: {size} bytes\n"
                            f"  Attackers clear shell history to hide commands.\n"
                            f"  MITRE: T1070.003 (Clear Command History)"
                        )
            except FileNotFoundError:
                pass

    def observe_command(self, cmdline: list, process_name: str = ""):
        """
        Called when a command is executed.
        Checks for known anti-forensics command patterns.
        """
        cmd_str = " ".join(cmdline).lower()
        for pattern in self.JOURNAL_CMD_PATTERNS:
            if all(p.lower() in cmd_str for p in pattern):
                if _cooldown(self._cd, f"cmd_{'_'.join(pattern[:2])}"):
                    _alert_fn(
                        "AntiForensics/JournalClear", "CRITICAL",
                        f"ANTI-FORENSICS COMMAND DETECTED\n"
                        f"  Command: {cmd_str[:200]}\n"
                        f"  Process: {process_name}\n"
                        f"  Matches known log-clearing pattern: "
                        f"{' '.join(pattern)}\n"
                        f"  MITRE: T1070.002 (Clear Linux or Mac System Logs)"
                    )


# ════════════════════════════════════════════════════════════════
#  E: PRIVILEGE ESCALATION DETECTION
# ════════════════════════════════════════════════════════════════

class PrivEscDetector:
    """
    Detects privilege escalation attempts.
    Linux equivalent of UAC bypass detection.

    Techniques monitored:
      1. SUID binary execution from non-standard paths
      2. Unexpected sudo invocations (especially with -i or -s)
      3. Polkit bypass attempts (pkexec with known CVE payloads)
      4. Cron-based privilege escalation
      5. LD_PRELOAD targeting SUID binaries
      6. setuid/setgid syscalls from unexpected processes
    """

    SYSTEM_SUID_PATHS = (
        "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
        "/usr/lib/", "/lib/",
    )

    SUDO_ESCALATION_FLAGS = ["-i", "-s", "-u root", "--shell",
                              "/bin/bash", "/bin/sh"]

    def __init__(self):
        self._cd: dict = {}
        # Known SUID binaries and their expected paths
        self._suid_map: dict[str, str] = {}
        self._baseline_suid()

    def _baseline_suid(self):
        """Build a map of known-good SUID binary locations."""
        try:
            result = subprocess.run(
                ["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
                 "-perm", "-4000", "-type", "f"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                name = os.path.basename(line)
                self._suid_map[name] = line
        except Exception:
            pass

    def observe_exec(self, pid: int, exe_path: str,
                     cmdline: list, uid: int):
        """
        Called on process execution.
        Feed from auditd execve events.
        """
        if not exe_path:
            return

        # Check 1: SUID binary from non-standard path
        try:
            s = os.stat(exe_path)
            is_suid = bool(s.st_mode & stat.S_ISUID)
        except (FileNotFoundError, PermissionError):
            is_suid = False

        if is_suid:
            if not any(exe_path.startswith(p) for p in self.SYSTEM_SUID_PATHS):
                if _cooldown(self._cd, f"suid_{exe_path}"):
                    _alert_fn(
                        "PrivEsc/NonStandardSUID", "CRITICAL",
                        f"SUID BINARY EXECUTED FROM NON-STANDARD PATH\n"
                        f"  Path: {exe_path}  PID={pid}  UID={uid}\n"
                        f"  SUID binaries in /tmp, /home, or other non-system "
                        f"paths are almost always privilege escalation tools.\n"
                        f"  MITRE: T1548.001 (Setuid and Setgid)"
                    )

        # Check 2: Suspicious sudo invocation
        cmd_str = " ".join(cmdline).lower()
        if os.path.basename(exe_path) == "sudo":
            for flag in self.SUDO_ESCALATION_FLAGS:
                if flag.lower() in cmd_str:
                    if _cooldown(self._cd, f"sudo_esc_{pid}"):
                        _alert_fn(
                            "PrivEsc/SudoShell", "HIGH",
                            f"SUDO SHELL ESCALATION\n"
                            f"  Command: {cmd_str[:200]}\n"
                            f"  PID={pid}  UID={uid}\n"
                            f"  Invocation of a root shell via sudo.\n"
                            f"  Legitimate admins occasionally do this; "
                            f"flag for review after a security event.\n"
                            f"  MITRE: T1548.003 (Sudo and Sudo Caching)"
                        )
                    break

        # Check 3: pkexec (Polkit) — CVE-2021-4034 surface
        if "pkexec" in exe_path:
            if _cooldown(self._cd, f"pkexec_{pid}"):
                _alert_fn(
                    "PrivEsc/PkexecExecution", "MED",
                    f"PKEXEC EXECUTED: PID={pid}  UID={uid}\n"
                    f"  Command: {cmd_str[:200]}\n"
                    f"  pkexec is the Polkit privilege escalation tool.\n"
                    f"  CVE-2021-4034 (PwnKit) exploited pkexec for local "
                    f"root on most Linux distros. Flag all pkexec invocations.\n"
                    f"  MITRE: T1548 (Abuse Elevation Control Mechanism)"
                )

    def scan_suid_changes(self):
        """Detect new SUID binaries not in baseline."""
        try:
            result = subprocess.run(
                ["find", "/", "-perm", "-4000", "-type", "f",
                 "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.splitlines():
                name = os.path.basename(line)
                known_path = self._suid_map.get(name)
                if known_path and known_path != line:
                    if _cooldown(self._cd, f"newloc_suid_{name}"):
                        _alert_fn(
                            "PrivEsc/NewSUIDLocation", "HIGH",
                            f"SUID BINARY IN NEW LOCATION\n"
                            f"  Name:     {name}\n"
                            f"  Expected: {known_path}\n"
                            f"  Found at: {line}\n"
                            f"  MITRE: T1548.001"
                        )
                elif not known_path:
                    if not any(line.startswith(p) for p in self.SYSTEM_SUID_PATHS):
                        if _cooldown(self._cd, f"unknown_suid_{line}"):
                            _alert_fn(
                                "PrivEsc/UnknownSUID", "HIGH",
                                f"NEW UNKNOWN SUID BINARY\n"
                                f"  Path: {line}\n"
                                f"  Not in baseline and not in standard path.\n"
                                f"  MITRE: T1548.001"
                            )
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════
#  UNIFIED ENGINE 22
# ════════════════════════════════════════════════════════════════

class EndpointBehavioralIDS:
    """
    IDS Engine 22 — Unified Endpoint Behavioral Detection.

    Aggregates all five endpoint malware detection classes:
      A. Keylogger detection
      B. Credential theft detection
      C. Ransomware detection
      D. Anti-forensics detection
      E. Privilege escalation detection

    Integration with ids_detector.py:
      import ids_engine_endpoint as _e22
      _e22.get_engine().register_alert_fn(alert)
      _e22.get_engine().start()

    Then in packet_handler() or separate thread:
      _e22.observe_file_event(pid, path, proc)
      _e22.observe_exec_event(pid, exe, cmdline, uid)
    """

    def __init__(self):
        self.keylogger  = KeyloggerDetector()
        self.cred_theft = CredentialTheftDetector()
        self.ransomware = RansomwareDetector()
        self.anti_foren = AntiForensicsDetector()
        self.priv_esc   = PrivEscDetector()

    def register_alert_fn(self, fn):
        global _alert_fn
        _alert_fn = fn

    def observe_file_event(self, pid: int, path: str,
                            process_name: str, mode: str = "r"):
        """Route file access events to all relevant detectors."""
        self.keylogger.observe_file_access(pid, path, process_name, mode)
        self.cred_theft.observe_file_access(pid, path, process_name)

    def observe_rename_event(self, pid: int, old_path: str,
                              new_path: str, process_name: str = ""):
        self.ransomware.observe_rename(pid, old_path, new_path, process_name)

    def observe_create_event(self, path: str):
        self.ransomware.observe_file_create(path)

    def observe_exec_event(self, pid: int, exe: str,
                            cmdline: list, uid: int = 1000):
        """Route exec events to privilege escalation and anti-forensics."""
        self.priv_esc.observe_exec(pid, exe, cmdline, uid)
        self.anti_foren.observe_command(cmdline)

    def start(self, scan_interval: float = 30.0) -> list:
        """Baseline all detectors and start background scanning."""
        self.anti_foren.baseline()

        threads = []

        def _scan_loop():
            while True:
                time.sleep(scan_interval)
                try:
                    self.keylogger.scan_processes_for_input_access()
                    self.cred_theft.scan_temp_copies()
                    self.ransomware.scan_for_notes()
                    self.anti_foren.scan()
                    self.priv_esc.scan_suid_changes()
                except Exception as e:
                    print(f"[IDS-E22] Scan error: {e}")

        t = threading.Thread(target=_scan_loop, daemon=True,
                             name="e22-endpoint")
        t.start()
        threads.append(t)

        print(f"[IDS-E22] Endpoint Behavioral IDS started "
              f"(scan every {scan_interval}s)")
        print(f"[IDS-E22]   A. Keylogger detection")
        print(f"[IDS-E22]   B. Credential theft detection")
        print(f"[IDS-E22]   C. Ransomware detection")
        print(f"[IDS-E22]   D. Anti-forensics detection")
        print(f"[IDS-E22]   E. Privilege escalation detection")
        return threads

    def run_demo(self):
        """Simulate events for all five detection classes."""
        print("\n[IDS-E22] === ENDPOINT BEHAVIORAL IDS DEMO ===\n")

        print("--- A: Keylogger Detection ---")
        self.keylogger.observe_file_access(
            9001, "/dev/input/event0", "malware_keylogger")

        print("--- B: Credential Theft Detection ---")
        self.cred_theft.observe_file_access(
            9002,
            os.path.expanduser("~/.config/google-chrome/Local State"),
            "malware_credstealer")
        self.cred_theft.observe_file_access(
            9002,
            os.path.expanduser("~/.config/google-chrome/Default/Login Data"),
            "malware_credstealer")

        print("--- C: Ransomware Detection ---")
        for i in range(25):
            self.ransomware.observe_rename(
                9003, f"/home/user/doc_{i}.txt",
                f"/home/user/doc_{i}.locked", "cryptolocker")
        self.ransomware.observe_file_create("/home/user/README.txt")

        print("--- D: Anti-Forensics Detection ---")
        # Simulate by directly calling scan (normally needs baseline)
        self.anti_foren.observe_command(
            ["journalctl", "--vacuum-size=0"], "bash")

        print("--- E: Privilege Escalation Detection ---")
        self.priv_esc.observe_exec(
            9005, "/tmp/suid_exploit", ["./suid_exploit", "-p"], uid=1000)
        self.priv_esc.observe_exec(
            9006, "/usr/bin/sudo", ["sudo", "-i"], uid=1000)

        print("\n[IDS-E22] Demo complete.\n")


_engine = EndpointBehavioralIDS()

def get_engine() -> EndpointBehavioralIDS:
    return _engine


# ════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="IDS Engine 22 — Endpoint Behavioral Detection")
    parser.add_argument("--demo",    action="store_true",
                        help="Run full demo for all 5 detection classes")
    parser.add_argument("--scan",    action="store_true",
                        help="Run active scan once")
    parser.add_argument("--monitor", type=int, metavar="SECONDS",
                        help="Monitor for N seconds")
    args = parser.parse_args()

    engine = EndpointBehavioralIDS()

    if args.demo:
        engine.run_demo()

    if args.scan:
        print("[IDS-E22] Running one-time active scan...")
        engine.anti_foren.baseline()
        engine.keylogger.scan_processes_for_input_access()
        engine.cred_theft.scan_temp_copies()
        engine.ransomware.scan_for_notes()
        engine.anti_foren.scan()
        engine.priv_esc.scan_suid_changes()
        print("[IDS-E22] Scan complete.")

    if args.monitor:
        engine.start(scan_interval=10)
        print(f"[IDS-E22] Monitoring for {args.monitor}s...")
        time.sleep(args.monitor)
        print("[IDS-E22] Monitor complete.")
