"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: IDS Engine 7 Patch — JA3 TLS Fingerprinting
 Environment: ISOLATED VM LAB ONLY
====================================================

Patches Engine 7 (JA3 TLS fingerprinting) into ids_detector.py.

Why this file exists:
  tls_ja3.py is a standalone Engine 7 module.  It exports
  engine7_process(pkt) as a drop-in hook, but ids_detector.py's
  packet_handler() does not call it.  This patch file bridges
  the gap by:

    (a) Providing patch_ids_detector() which wraps the existing
        packet_handler with JA3-aware logic — one line to integrate.

    (b) Providing a standalone monitor for running Engine 7 alone
        on a TAP/mirror port without touching ids_detector.py.

    (c) Providing apply_patch_to_file() which surgically inserts
        the three required lines into ids_detector.py on disk.

Usage (three ways):

  1. In-process integration (preferred — no file modification):

       # In ids_detector.py, after packet_handler is defined,
       # add these lines just before the sniff() call:
       from ids_detector_patch import patch_ids_detector
       packet_handler = patch_ids_detector(packet_handler, alert)

  2. Automated file patch:

       python3 ids_detector_patch.py --patch-file ids_detector.py

  3. Standalone TLS-only monitor:

       sudo python3 ids_detector_patch.py [--iface enp0s3] [--duration 120]

Engine 7 vs Engine 6:
  Engine 6 (ip_reputation.py) catches bots that forget to rotate
    HTTP User-Agent / Accept-Language headers.
  Engine 7 (JA3) catches bots that HAVE rotated HTTP headers but
    still share a TLS stack (same library version across the botnet).
  The TLS ClientHello is generated before the application layer
  and cannot be faked without patching the HTTP library itself.
  Two IPs running Python urllib/requests will have identical JA3
  hashes regardless of what User-Agent strings they claim.

Alert conditions:
  KNOWN_BAD   — Hash in KNOWN_BAD_JA3 (Python urllib, requests,
                curl, Go, Node.js, OpenBullet / SilverBullet).
                Risk: HIGH or CRITICAL.
  MULTI_IP    — Same hash from ≥3 distinct IPs in 5 minutes.
                Indicates a shared bot framework.
                Risk: HIGH.
  ROTATION    — Unusually high number of distinct JA3 hashes from
                one IP in a short window (JA3 randomizer in use).
                Risk: MED.  Detects evasion attempts themselves.
"""

import argparse
import os
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime
from typing import Optional, Callable

try:
    from scapy.all import sniff, IP, TCP, Raw
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

try:
    from tls_ja3 import engine7_process, get_tracker_stats, JA3Tracker, classify_ja3, extract_ja3
    _JA3_OK = True
except ImportError:
    _JA3_OK = False
    print("[ENGINE7-PATCH] Warning: tls_ja3.py not found in path — Engine 7 disabled.")


# ── Configuration ──────────────────────────────────────────────
MONITOR_PORTS       = [80, 443, 8080, 8443]
ROTATION_WINDOW_SEC = 60.0
ROTATION_THRESH     = 5        # distinct JA3 hashes from one IP in ROTATION_WINDOW_SEC
LOG_PATH            = "/tmp/engine7_ja3.log"
MONITOR_IFACE       = "enp0s3"

# Insertion markers for automatic file patching
_PATCH_IMPORT = "from ids_detector_patch import patch_ids_detector  # ENGINE7"
_PATCH_CALL   = "    packet_handler = patch_ids_detector(packet_handler, alert)  # ENGINE7"
_PATCH_ANCHOR = "sniff("   # insert patch call just before the sniff() call


# ══════════════════════════════════════════════════════════════
#  JA3 ROTATION DETECTOR
#  (catches bots using per-request JA3 randomizers)
# ══════════════════════════════════════════════════════════════

class JA3RotationDetector:
    """
    Detects JA3 rotation — attackers who randomise their TLS fingerprint
    per connection to evade the KNOWN_BAD and MULTI_IP detectors.

    Ironically, randomising JA3 is itself detectable:
      A real browser uses ONE stable fingerprint across all sessions.
      An attacker rotating JA3 produces an unnaturally high number of
      distinct hashes from a single IP in a short window.

    Alert: ≥ ROTATION_THRESH distinct hashes from one IP in ROTATION_WINDOW_SEC.
    """

    def __init__(self, threshold: int = ROTATION_THRESH,
                 window_sec: float = ROTATION_WINDOW_SEC):
        self.threshold  = threshold
        self.window_sec = window_sec
        self._lock      = threading.Lock()
        # ip → list of (timestamp, ja3_hash)
        self._ip_hashes: dict = defaultdict(list)
        self._alerted:   set  = set()

    def record(self, src_ip: str, ja3_hash: str) -> Optional[dict]:
        now = time.time()
        with self._lock:
            self._ip_hashes[src_ip].append((now, ja3_hash))
            cutoff = now - self.window_sec
            self._ip_hashes[src_ip] = [
                (ts, h) for ts, h in self._ip_hashes[src_ip] if ts > cutoff
            ]
            recent  = self._ip_hashes[src_ip]
            distinct = {h for _, h in recent}

            if (len(distinct) >= self.threshold
                    and src_ip not in self._alerted):
                self._alerted.add(src_ip)
                return {
                    "alert_type": "JA3/Rotation",
                    "severity":   "MED",
                    "src_ip":     src_ip,
                    "n_hashes":   len(distinct),
                    "message": (
                        f"JA3 ROTATION DETECTED from {src_ip}\n"
                        f"  {len(distinct)} distinct TLS fingerprints in "
                        f"{self.window_sec:.0f}s (threshold: {self.threshold})\n"
                        f"  Real browsers use ONE stable JA3 hash per session.\n"
                        f"  Rotation = attacker using a per-request JA3 randomizer.\n"
                        f"  Evasion attempt detected by its own evasion pattern.\n"
                        f"  MITRE: T1110.004 (Credential Stuffing) + T1036 (Masquerading)"
                    ),
                }
        return None

    def reset_ip(self, ip: str):
        with self._lock:
            self._ip_hashes.pop(ip, None)
            self._alerted.discard(ip)


# ══════════════════════════════════════════════════════════════
#  ENGINE 7 WRAPPER
# ══════════════════════════════════════════════════════════════

class Engine7Wrapper:
    """
    Wraps the tls_ja3 singleton tracker and adds:
      - JA3 rotation detection (new)
      - Alert deduplication with cooldown
      - Log file output
      - Per-packet alert callback routing

    One instance is created by patch_ids_detector() and attached
    to the patched packet_handler as ._engine7.
    """

    def __init__(self, alert_cb: Callable = None):
        self._alert_cb      = alert_cb or self._default_alert
        self._rotation_det  = JA3RotationDetector()
        self._lock          = threading.Lock()
        self._alert_count   = 0
        # cooldown: (alert_type, src_ip) → last_fired_ts
        self._cooldown: dict = {}
        self._log = open(LOG_PATH, "a", buffering=1)
        print(f"[ENGINE7] Initialised.  Log: {LOG_PATH}")
        if _JA3_OK:
            print(f"[ENGINE7] JA3 known-bad database loaded.")

    def process_packet(self, pkt) -> None:
        """
        Called for every packet captured by the IDS sniff() loop.
        Safe to call even if Scapy or tls_ja3 are unavailable.
        """
        if not _JA3_OK or not _SCAPY_OK:
            return
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        dport = pkt[TCP].dport
        if dport not in MONITOR_PORTS:
            return

        src_ip = pkt[IP].src

        # 1. Delegate to the tls_ja3 singleton (KnownBad + MultiIP)
        alert = engine7_process(pkt)
        if alert:
            self._fire(alert["alert_type"], alert["severity"],
                       alert["message"], src_ip,
                       alert.get("ja3_hash", "?"))

        # 2. Additional: rotation detection
        if pkt.haslayer(Raw):
            info = extract_ja3(pkt)
            if info:
                rot_alert = self._rotation_det.record(src_ip, info["ja3_hash"])
                if rot_alert:
                    self._fire(rot_alert["alert_type"], rot_alert["severity"],
                               rot_alert["message"], src_ip, "rotation")

    def _fire(self, alert_type: str, severity: str, msg: str,
              src_ip: str, ja3_hash: str) -> None:
        key = (alert_type, src_ip)
        now = time.time()
        with self._lock:
            if now - self._cooldown.get(key, 0) < 120:  # 2-min cooldown
                return
            self._cooldown[key] = now
            self._alert_count += 1

        self._alert_cb(f"Engine7/{alert_type}", severity, msg)
        try:
            ts = datetime.now().isoformat()
            self._log.write(
                f"[{ts}] [{severity}] Engine7/{alert_type} "
                f"src={src_ip} ja3={ja3_hash[:16]}… "
                f"{msg.splitlines()[0]}\n"
            )
        except Exception:
            pass

    def stats(self) -> dict:
        return {
            "engine":        "Engine7/JA3",
            "total_alerts":  self._alert_count,
            "log":           LOG_PATH,
            "tracker_state": get_tracker_stats() if _JA3_OK else {},
        }

    def close(self):
        try:
            self._log.close()
        except Exception:
            pass

    @staticmethod
    def _default_alert(engine: str, severity: str, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n{'='*60}")
        print(f"  [ENGINE7] [{severity}] {engine} @ {ts}")
        print(f"  {msg}")
        print(f"{'='*60}\n")


# ══════════════════════════════════════════════════════════════
#  PATCH FUNCTION
# ══════════════════════════════════════════════════════════════

def patch_ids_detector(existing_handler: Callable,
                       alert_cb: Callable = None) -> Callable:
    """
    Wrap an existing Scapy packet_handler with Engine 7.

    Drop-in usage in ids_detector.py — insert these two lines
    just before the sniff() call:

        from ids_detector_patch import patch_ids_detector
        packet_handler = patch_ids_detector(packet_handler, alert)

    Returns a patched callable that first runs all existing
    IDS engines, then runs Engine 7 on the same packet.

    The Engine7Wrapper instance is accessible as:
        packet_handler._engine7
    """
    e7 = Engine7Wrapper(alert_cb=alert_cb)

    def patched_handler(pkt):
        existing_handler(pkt)   # Engines 1–6, 8+
        e7.process_packet(pkt)  # Engine 7 (JA3)

    patched_handler._engine7 = e7
    return patched_handler


# ══════════════════════════════════════════════════════════════
#  AUTOMATIC FILE PATCH
# ══════════════════════════════════════════════════════════════

def apply_patch_to_file(ids_detector_path: str,
                        dry_run: bool = False) -> bool:
    """
    Automatically insert Engine 7 integration lines into
    ids_detector.py on disk.

    Inserts:
      - Import line at the top (after existing imports)
      - Patch call just before the sniff() invocation

    Args:
        ids_detector_path: path to ids_detector.py
        dry_run:           if True, print diff but do not write

    Returns True on success, False if already patched or error.
    """
    try:
        with open(ids_detector_path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ENGINE7-PATCH] File not found: {ids_detector_path}")
        return False

    # Check if already patched
    if any("ENGINE7" in line for line in lines):
        print(f"[ENGINE7-PATCH] Already patched: {ids_detector_path}")
        return False

    new_lines = []
    import_inserted = False
    sniff_patched   = False

    for i, line in enumerate(lines):
        # Insert import after last "import" block line
        if (not import_inserted
                and not line.startswith("import ")
                and not line.startswith("from ")
                and i > 0
                and (lines[i-1].startswith("import ")
                     or lines[i-1].startswith("from "))):
            new_lines.append(_PATCH_IMPORT + "\n")
            import_inserted = True

        # Insert patch call just before sniff(
        if (not sniff_patched
                and _PATCH_ANCHOR in line
                and "def " not in line):
            new_lines.append(_PATCH_CALL + "\n")
            sniff_patched = True

        new_lines.append(line)

    if not import_inserted or not sniff_patched:
        print(f"[ENGINE7-PATCH] Could not locate insertion points in "
              f"{ids_detector_path}.")
        print(f"  import_inserted={import_inserted}  "
              f"sniff_patched={sniff_patched}")
        print(f"  Manual integration: add these lines before sniff():")
        print(f"    {_PATCH_IMPORT}")
        print(f"    {_PATCH_CALL}")
        return False

    if dry_run:
        print(f"[ENGINE7-PATCH] DRY RUN — would write {len(new_lines)} lines "
              f"to {ids_detector_path}")
        for line in new_lines:
            if "ENGINE7" in line:
                print(f"  + {line}", end="")
        return True

    # Write backup then patched file
    backup = ids_detector_path + ".pre_engine7.bak"
    with open(backup, "w") as f:
        f.writelines(lines)
    with open(ids_detector_path, "w") as f:
        f.writelines(new_lines)

    print(f"[ENGINE7-PATCH] Patched {ids_detector_path}")
    print(f"[ENGINE7-PATCH] Backup: {backup}")
    return True


# ══════════════════════════════════════════════════════════════
#  STANDALONE MONITOR
# ══════════════════════════════════════════════════════════════

def run_standalone(iface: str = MONITOR_IFACE, duration: int = 0):
    """Run Engine 7 as a standalone TLS fingerprint monitor."""
    if not _SCAPY_OK:
        print("[ENGINE7] Scapy required.  pip3 install scapy")
        return
    if not _JA3_OK:
        print("[ENGINE7] tls_ja3.py required in the same directory.")
        return

    e7  = Engine7Wrapper()
    bpf = " or ".join(f"port {p}" for p in MONITOR_PORTS)

    print(f"\n[ENGINE7] JA3 Standalone Monitor")
    print(f"[ENGINE7] Interface  : {iface}")
    print(f"[ENGINE7] Ports      : {MONITOR_PORTS}")
    print(f"[ENGINE7] Log        : {LOG_PATH}")
    print(f"[ENGINE7] Rotation   : ≥{ROTATION_THRESH} hashes/{ROTATION_WINDOW_SEC:.0f}s → alert")
    print(f"[ENGINE7] Duration   : {'infinite' if duration == 0 else str(duration)+'s'}")
    print(f"[ENGINE7] Press Ctrl-C to stop.\n")

    try:
        sniff(
            iface=iface,
            filter=f"tcp and ({bpf})",
            prn=e7.process_packet,
            store=False,
            timeout=duration if duration > 0 else None,
        )
    except KeyboardInterrupt:
        pass
    finally:
        s = e7.stats()
        print(f"\n[ENGINE7] Session complete.  Total alerts: {s['total_alerts']}")
        e7.close()


# ══════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "IDS Engine 7 — JA3 TLS Fingerprinting\n"
            "AUA CS 232/337 Botnet Research Lab — ISOLATED VM ONLY\n\n"
            "Modes:\n"
            "  (no flag)    Standalone TLS monitor on --iface\n"
            "  --patch-file Surgically insert Engine 7 into ids_detector.py\n"
            "  --dry-run    Show what --patch-file would change without writing\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--iface",      default=MONITOR_IFACE,
                        help=f"Network interface for standalone mode (default: {MONITOR_IFACE})")
    parser.add_argument("--duration",   type=int, default=0,
                        help="Capture duration seconds — 0 = infinite (default: 0)")
    parser.add_argument("--patch-file", metavar="PATH",
                        help="Path to ids_detector.py to patch with Engine 7")
    parser.add_argument("--dry-run",    action="store_true",
                        help="With --patch-file: show changes without writing")
    args = parser.parse_args()

    if args.patch_file:
        ok = apply_patch_to_file(args.patch_file, dry_run=args.dry_run)
        sys.exit(0 if ok else 1)

    if os.getuid() != 0:
        print("[ENGINE7] WARNING: not running as root — raw socket capture may fail.")
        print("  Run with: sudo python3 ids_detector_patch.py\n")

    run_standalone(iface=args.iface, duration=args.duration)
