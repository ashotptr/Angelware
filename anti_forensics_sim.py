"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Anti-Forensics Simulation (Attack + Defense)
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching points:
  After a successful intrusion, attackers systematically destroy
  evidence to prevent forensic analysis and extend their dwell time.
  This is MITRE T1070 — Indicator Removal.

  Understanding anti-forensics is essential for incident responders:
  knowing WHAT evidence gets destroyed tells you WHERE to look for
  artifacts that survive, and how to architect logging systems that
  are tamper-resistant.

Attack side (AntiForensicsSim):
  Five techniques demonstrated in the lab VM:

  1. Shell history clearance — T1070.003
     ~/.bash_history truncation; HISTFILE=/dev/null trick

  2. Log file clearance — T1070.002
     Clears only /tmp/botnet_lab_*.log files (lab artifacts only)
     Documents the wevtutil / shred patterns used on real systems

  3. Timestamp modification (timestomping) — T1070.006
     Sets mtime/atime to match system binaries using touch -r
     Defeats timeline analysis in forensic tools

  4. Secure file deletion — T1070.004
     Overwrites file content before unlinking (defeats file carving)
     Documents shred / srm / sdelete patterns

  5. Memory-resident artifact cleanup — T1070
     Removes .pyc cache files, core dumps, /tmp artifacts

  SAFETY CONSTRAINT: All operations target ONLY:
    - /tmp/botnet_lab_* files (lab artifacts created by this project)
    - Lab-specific log paths (/tmp/ids.log, /tmp/c2_server.log)
    - Shell history manipulation is opt-in and reversible

Defense side (IDS Engine 22D — ids_engine_endpoint.py):
  Full detection already in AntiForensicsDetector.
  This module adds:
    - Tamper-resistant remote logging reference implementation
    - Forensic artifact preservation techniques
    - Detection signatures for all five attack techniques

MITRE:
  T1070.002  Indicator Removal: Clear Linux Logs
  T1070.003  Indicator Removal: Clear Command History
  T1070.004  Indicator Removal: File Deletion
  T1070.006  Indicator Removal: Timestomping

CLI:
  python3 anti_forensics_sim.py --status          (show what can be cleared)
  python3 anti_forensics_sim.py --clear-lab       (clear lab artifacts only)
  python3 anti_forensics_sim.py --timestomp FILE  (stomp timestamps)
  python3 anti_forensics_sim.py --secure-delete F (overwrite + delete)
  python3 anti_forensics_sim.py --detect          (IDS Engine 22D demo)
  python3 anti_forensics_sim.py --preserve        (show tamper-resistance)
  python3 anti_forensics_sim.py --demo            (full demo)
"""

import os
import sys
import time
import glob
import shutil
import struct
import hashlib
import argparse
import threading
import subprocess
from datetime import datetime, timedelta
from pathlib import Path


# ════════════════════════════════════════════════════════════════
#  LAB ARTIFACT PATHS — ONLY THESE ARE TOUCHED
# ════════════════════════════════════════════════════════════════

LAB_LOG_PATTERNS = [
    "/tmp/botnet_lab_*.log",
    "/tmp/botnet_lab_*.txt",
    "/tmp/ids.log",
    "/tmp/c2_server.log",
    "/tmp/c2_analysis/",
    "/tmp/botnet_graphs/",
    "/tmp/ransomware_lab_target/",
    "/tmp/tarpit_state.json",
    "/tmp/drain_log.json",
    "/tmp/pivot_log.json",
    "/tmp/verified_hits.txt",
    "/tmp/confirmed_accounts.txt",
    "/tmp/supply_chain_audit.json",
    "/tmp/phishing_sent.json",
    "/tmp/mfa_bypass_log.json",
    "/tmp/resale_market.json",
]

SAFE_PREFIXES = ("/tmp/botnet_lab", "/tmp/ids.log", "/tmp/c2_",
                 "/tmp/tarpit_", "/tmp/drain_", "/tmp/pivot_",
                 "/tmp/verified_", "/tmp/confirmed_", "/tmp/supply_",
                 "/tmp/phishing_", "/tmp/mfa_", "/tmp/resale_",
                 "/tmp/ransomware_lab_")


def _is_safe_target(path: str) -> bool:
    """Verify path is a lab artifact before any destructive operation."""
    real = os.path.realpath(path)
    return any(real.startswith(prefix) for prefix in SAFE_PREFIXES)


# ════════════════════════════════════════════════════════════════
#  ATTACK SIDE: Anti-Forensics Simulator
# ════════════════════════════════════════════════════════════════

class AntiForensicsSim:
    """
    Demonstrates anti-forensics techniques against lab artifacts.

    All operations are constrained to /tmp/botnet_lab_* and
    other explicitly lab-generated files. The safety check
    _is_safe_target() is called before every destructive action.
    """

    # ── Technique 1: Shell History Clearance ─────────────────

    def clear_shell_history(self, dry_run: bool = True) -> dict:
        """
        Shell history clearance — T1070.003.

        Real-world technique: attackers run one of:
          history -c && history -w       (bash: clear in-memory + write)
          echo "" > ~/.bash_history      (truncate)
          unset HISTFILE                 (disable further logging)
          export HISTFILE=/dev/null      (redirect to null)
          ln -sf /dev/null ~/.bash_history (symlink trick)

        In the lab: demonstrates the mechanism; only acts if
        the user explicitly passes --no-dry-run.

        Detection artifact: ~/.bash_history shrinks from N bytes
        to 0 bytes in one write event (IDS Engine 22D catches this).
        """
        hist_path = os.path.expanduser("~/.bash_history")
        result = {
            "technique": "shell_history_clearance",
            "mitre":     "T1070.003",
            "target":    hist_path,
            "dry_run":   dry_run,
        }

        if not os.path.exists(hist_path):
            result["status"] = "not_found"
            return result

        size_before = os.path.getsize(hist_path)
        result["size_before"] = size_before

        if dry_run:
            result["status"] = "dry_run"
            result["would_do"] = (
                f"Truncate {hist_path} ({size_before} bytes) to 0 bytes\n"
                f"  Real command: history -c && history -w\n"
                f"  Or: truncate -s 0 ~/.bash_history"
            )
            return result

        # Backup first (lab only — real attackers don't backup)
        backup = f"/tmp/botnet_lab_hist_backup_{int(time.time())}"
        shutil.copy2(hist_path, backup)
        result["backup"] = backup

        with open(hist_path, "w") as f:
            f.write("")  # truncate

        result["status"]    = "cleared"
        result["size_after"] = 0
        print(f"[AntiForensics] History cleared: {hist_path} "
              f"({size_before} → 0 bytes)")
        print(f"[AntiForensics] Backup at: {backup} (restore with: "
              f"cp {backup} {hist_path})")
        return result

    # ── Technique 2: Lab Log Clearance ───────────────────────

    def clear_lab_logs(self) -> dict:
        """
        Clear lab-generated log files — T1070.002.

        Targets ONLY files matching LAB_LOG_PATTERNS.
        Documents real-world equivalent commands for each OS.

        Real-world equivalents (not executed):
          Linux:   shred -u /var/log/auth.log
                   journalctl --vacuum-size=0
                   wipe /var/log/syslog
          Windows: wevtutil cl System
                   wevtutil cl Security
                   wevtutil cl Application
        """
        cleared = []
        skipped = []
        errors  = []

        for pattern in LAB_LOG_PATTERNS:
            for path in glob.glob(pattern):
                if not _is_safe_target(path):
                    skipped.append(path)
                    continue
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                        cleared.append({"path": path, "type": "directory"})
                    elif os.path.isfile(path):
                        size = os.path.getsize(path)
                        os.remove(path)
                        cleared.append({"path": path, "type": "file",
                                        "size": size})
                    print(f"[AntiForensics] Cleared: {path}")
                except Exception as e:
                    errors.append({"path": path, "error": str(e)})

        return {
            "technique": "lab_log_clearance",
            "mitre":     "T1070.002",
            "cleared":   len(cleared),
            "skipped":   len(skipped),
            "errors":    len(errors),
            "details":   cleared,
            "real_world_note": (
                "On production Linux: shred -u /var/log/auth.log, "
                "journalctl --vacuum-size=0. "
                "On Windows: wevtutil cl System/Security/Application."
            ),
        }

    # ── Technique 3: Timestomping ────────────────────────────

    def timestomp(self, target_path: str,
                  reference_path: str = "/bin/ls") -> dict:
        """
        Timestamp modification — T1070.006.

        Sets the target file's mtime and atime to match a
        legitimate system binary, defeating timeline analysis.

        Real forensic tools (Autopsy, FTK, Sleuth Kit) sort
        events by mtime — timestomping moves the malicious file
        to a time when the victim was not under attack,
        burying it among thousands of legitimate system events.

        Detection: $STANDARD_INFORMATION mtime vs $FILE_NAME mtime
        discrepancy (Windows NTFS). On Linux: birth time (crtime)
        via statx() is not modifiable via touch, so comparing
        mtime vs crtime reveals tampering.
        """
        if not _is_safe_target(target_path):
            return {
                "status": "refused",
                "reason": f"'{target_path}' is not a lab artifact",
            }

        if not os.path.exists(target_path):
            return {"status": "error", "reason": "target not found"}

        ref = reference_path if os.path.exists(reference_path) else "/bin/sh"

        try:
            ref_stat  = os.stat(ref)
            orig_stat = os.stat(target_path)

            # os.utime(path, (atime, mtime))
            os.utime(target_path, (ref_stat.st_atime, ref_stat.st_mtime))

            new_stat = os.stat(target_path)
            return {
                "technique":     "timestomping",
                "mitre":         "T1070.006",
                "target":        target_path,
                "reference":     ref,
                "original_mtime": datetime.fromtimestamp(
                    orig_stat.st_mtime).isoformat(),
                "new_mtime":     datetime.fromtimestamp(
                    new_stat.st_mtime).isoformat(),
                "reference_mtime": datetime.fromtimestamp(
                    ref_stat.st_mtime).isoformat(),
                "status":        "stomped",
                "detection_note": (
                    "Linux: compare mtime vs crtime via statx() — "
                    "crtime cannot be modified by utime() syscall. "
                    "Discrepancy reveals tampering."
                ),
            }
        except Exception as e:
            return {"status": "error", "reason": str(e)}

    # ── Technique 4: Secure File Deletion ────────────────────

    def secure_delete(self, target_path: str, passes: int = 3) -> dict:
        """
        Secure file deletion — T1070.004.

        Overwrites file content N times before unlinking.
        Defeats simple file carving (Scalpel, Foremost) which
        recovers deleted files from unallocated disk space.

        On SSDs with wear leveling, secure deletion is unreliable
        because the controller may write to different physical cells
        — this is why full-disk encryption is the real defense.

        Real-world equivalents:
          Linux:   shred -vzu -n 3 filename
                   srm -vz filename
          Windows: sdelete -p 3 filename
        """
        if not _is_safe_target(target_path):
            return {
                "status": "refused",
                "reason": f"'{target_path}' is not a lab artifact",
            }

        if not os.path.exists(target_path):
            return {"status": "error", "reason": "file not found"}

        try:
            size = os.path.getsize(target_path)

            # Multi-pass overwrite
            with open(target_path, "r+b") as f:
                for p in range(passes):
                    f.seek(0)
                    # Pass 1: all zeros; Pass 2: all ones; Pass 3: random
                    if p == 0:
                        f.write(b"\x00" * size)
                    elif p == 1:
                        f.write(b"\xff" * size)
                    else:
                        import os as _os
                        f.write(_os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())

            os.remove(target_path)

            return {
                "technique":  "secure_delete",
                "mitre":      "T1070.004",
                "path":       target_path,
                "size":       size,
                "passes":     passes,
                "status":     "deleted",
                "ssd_note":   (
                    "On SSDs, secure deletion is unreliable due to "
                    "wear leveling and over-provisioning. "
                    "Full-disk encryption (dm-crypt/LUKS) is the "
                    "only reliable defense."
                ),
            }
        except Exception as e:
            return {"status": "error", "reason": str(e)}

    # ── Technique 5: Memory / Temp Artifact Cleanup ──────────

    def cleanup_memory_artifacts(self) -> dict:
        """
        Clean up runtime artifacts that could reveal malware presence.
        Targets only /tmp/botnet_lab_* files.

        Real-world: attackers also remove:
          - .pyc/__pycache__ (reveal Python scripts used)
          - Core dumps (contain memory snapshot of the malware)
          - /proc/[pid]/maps artifacts (removed automatically on exit)
          - Temporary extraction directories
        """
        cleaned = []

        # Python cache files in /tmp
        for pyc in glob.glob("/tmp/botnet_lab_*.pyc"):
            if _is_safe_target(pyc):
                os.remove(pyc)
                cleaned.append(pyc)

        pycache = "/tmp/botnet_lab_pycache"
        if os.path.isdir(pycache) and _is_safe_target(pycache):
            shutil.rmtree(pycache)
            cleaned.append(pycache)

        # Core dumps (if any in /tmp from lab processes)
        for core in glob.glob("/tmp/core.*"):
            if _is_safe_target(core):
                os.remove(core)
                cleaned.append(core)

        # The keylogger log itself
        kl_log = "/tmp/botnet_lab_keylogs.txt"
        if os.path.exists(kl_log) and _is_safe_target(kl_log):
            os.remove(kl_log)
            cleaned.append(kl_log)

        return {
            "technique": "artifact_cleanup",
            "mitre":     "T1070",
            "cleaned":   cleaned,
            "count":     len(cleaned),
        }

    # ── Status ───────────────────────────────────────────────

    def status(self) -> dict:
        """Show all lab artifacts that COULD be cleared."""
        artifacts = []
        total_size = 0

        for pattern in LAB_LOG_PATTERNS:
            for path in glob.glob(pattern):
                try:
                    if os.path.isdir(path):
                        size = sum(
                            f.stat().st_size
                            for f in Path(path).rglob("*")
                            if f.is_file()
                        )
                        artifacts.append({
                            "path": path,
                            "type": "directory",
                            "size": size,
                        })
                    else:
                        size = os.path.getsize(path)
                        artifacts.append({
                            "path": path,
                            "type": "file",
                            "size": size,
                        })
                    total_size += size
                except Exception:
                    pass

        return {
            "lab_artifacts_found": len(artifacts),
            "total_size_bytes":    total_size,
            "total_size_kb":       round(total_size / 1024, 1),
            "artifacts":           artifacts,
        }


# ════════════════════════════════════════════════════════════════
#  C2 TASK HANDLER
# ════════════════════════════════════════════════════════════════

def handle_c2_task(task: dict) -> dict:
    """
    Handle C2 tasks for anti-forensics.

    Task types:
      {"type": "anti_forensics"}         — clear all lab artifacts
      {"type": "anti_forensics_status"}  — list artifacts
      {"type": "timestomp", "path": "..."} — stomp one file
    """
    sim = AntiForensicsSim()
    t = task.get("type")

    if t == "anti_forensics":
        results = {}
        results["logs"]    = sim.clear_lab_logs()
        results["history"] = sim.clear_shell_history(dry_run=True)
        results["memory"]  = sim.cleanup_memory_artifacts()
        return {"status": "ok", "results": results}
    elif t == "anti_forensics_status":
        return sim.status()
    elif t == "timestomp":
        path = task.get("path", "")
        return sim.timestomp(path)
    return {"error": f"unknown task: {t}"}


# ════════════════════════════════════════════════════════════════
#  DEFENSE SIDE: Tamper-Resistant Logging Reference
# ════════════════════════════════════════════════════════════════

TAMPER_RESISTANT_LOGGING = {
    "title": "Tamper-Resistant Logging Architecture",
    "description": (
        "Anti-forensics succeeds when logs are stored only locally. "
        "The defense is to make logs tamper-resistant BEFORE an attack."
    ),
    "techniques": [
        {
            "name": "Remote syslog (RFC 5424)",
            "how":  "rsyslog / syslog-ng forwards all events to a remote "
                    "SIEM (Splunk, ELK, Graylog) in real time. "
                    "An attacker who clears local logs cannot reach "
                    "the remote copy.",
            "config": "rsyslog: *.* @siem.internal:514",
        },
        {
            "name": "systemd journal remote",
            "how":  "systemd-journal-remote sends journal entries to a "
                    "remote host. Even if journalctl --vacuum-size=0 "
                    "is run, the remote journal is unaffected.",
            "config": "systemd-journal-remote --listen-https=-3 "
                      "--trust=all --output=/var/log/remote/",
        },
        {
            "name": "Write-once S3 / object lock",
            "how":  "Ship logs to an S3 bucket with Object Lock (WORM). "
                    "Attacker cannot delete objects even with full AWS "
                    "console access if Object Lock is configured correctly.",
            "config": "aws s3 cp /var/log/ s3://siem-bucket/ "
                      "--recursive --storage-class STANDARD_IA",
        },
        {
            "name": "auditd with immutable mode",
            "how":  "auditctl -e 2 sets the audit system to immutable "
                    "mode. Changing audit rules requires a reboot. "
                    "Combined with secure boot, prevents rule tampering.",
            "config": "auditctl -e 2  # set immutable\n"
                      "auditctl -w /etc/passwd -p wa -k passwd_changes",
        },
        {
            "name": "eBPF-based event streaming",
            "how":  "Falco / Tetragon stream syscall events to a remote "
                    "endpoint in real time. Since events are streamed "
                    "as they happen, deleting logs after the fact "
                    "does not remove events already shipped.",
            "config": "falco --daemon -o 'json_output: true' "
                      "| nc siem.internal 12201",
        },
    ],
    "detection_iocs": [
        "~/.bash_history size drop > 50% in one write event",
        "journalctl --vacuum or --rotate in process execution log",
        "shred/srm/wipe invocation (auditd execve rule)",
        "wevtutil cl (Windows Security EventID 1102: audit log cleared)",
        "File mtime significantly earlier than ctime (timestomping)",
        "Rapid deletion of files in /tmp/ after a session",
    ],
}


# ════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Anti-Forensics Simulation — LAB ONLY")
    parser.add_argument("--status",        action="store_true",
                        help="Show all lab artifacts that can be cleared")
    parser.add_argument("--clear-lab",     action="store_true",
                        help="Clear all lab-generated artifacts")
    parser.add_argument("--timestomp",     metavar="FILE",
                        help="Stomp timestamps on a lab artifact file")
    parser.add_argument("--secure-delete", metavar="FILE",
                        help="Securely delete a lab artifact file")
    parser.add_argument("--clear-history", action="store_true",
                        help="Clear shell history (dry-run; use --force to act)")
    parser.add_argument("--force",         action="store_true",
                        help="Remove dry-run protection for --clear-history")
    parser.add_argument("--detect",        action="store_true",
                        help="Show IDS Engine 22D detection artifacts")
    parser.add_argument("--preserve",      action="store_true",
                        help="Show tamper-resistant logging architecture")
    parser.add_argument("--demo",          action="store_true",
                        help="Full demo cycle")
    args = parser.parse_args()

    sim = AntiForensicsSim()

    if args.status or args.demo:
        print("[AntiForensics] Lab artifact inventory:")
        s = sim.status()
        print(f"  Found {s['lab_artifacts_found']} artifact(s), "
              f"{s['total_size_kb']} KB total")
        for a in s["artifacts"]:
            kb = round(a["size"] / 1024, 1)
            print(f"  [{a['type'][:3]}] {a['path']}  ({kb} KB)")

    if args.clear_lab or args.demo:
        print("\n[AntiForensics] Clearing lab artifacts...")
        result = sim.clear_lab_logs()
        print(f"  Cleared: {result['cleared']} items")

    if args.clear_history:
        result = sim.clear_shell_history(dry_run=not args.force)
        print(f"[AntiForensics] History: {result}")

    if args.timestomp:
        result = sim.timestomp(args.timestomp)
        import json
        print(json.dumps(result, indent=2))

    if getattr(args, "secure_delete"):
        result = sim.secure_delete(args.secure_delete)
        import json
        print(json.dumps(result, indent=2))

    if args.detect or args.demo:
        print("\n[IDS-E22D] Anti-forensics detection IOCs:")
        try:
            from ids_engine_endpoint import AntiForensicsDetector
            det = AntiForensicsDetector()
            det.baseline()
            det.observe_command(["journalctl", "--vacuum-size=0"], "bash")
        except ImportError:
            for ioc in TAMPER_RESISTANT_LOGGING["detection_iocs"]:
                print(f"  • {ioc}")

    if args.preserve or args.demo:
        print("\n[AntiForensics] Tamper-resistant logging reference:")
        for t in TAMPER_RESISTANT_LOGGING["techniques"]:
            print(f"\n  [{t['name']}]")
            print(f"    {t['how'][:100]}...")
