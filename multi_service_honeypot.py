#!/usr/bin/env python3
"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Multi-Service Raw-Socket Honeypot
 VM: victim-honeypot (192.168.100.20)
 Environment: ISOLATED VM LAB ONLY
====================================================

Implements ALL low/medium-interaction honeypot services not covered by
Cowrie (which handles SSH/Telnet only).  Each service runs in its own
thread and logs every interaction to a unified JSON log file.

Services emulated
─────────────────
  Port  21  FTP     — banner + command capture (LOGIN, LIST, STOR, RETR)
  Port  25  SMTP    — Mailoney-style phishing-email capture
  Port  80  HTTP    — Apache 2.4.49 banner + CVE-2021-41773 path-traversal lure
  Port 389  LDAP    — bind-request credential capture
  Port 443  HTTPS   — TLS-aware banner + redirect to port-80 handler
  Port 3389 RDP     — NLA banner + credential capture

Design sources
──────────────
  Doc 1  FreeCodeCamp "Build a Honeypot in Python" (Rahalkar, Dec 2024)
           • Core Honeypot class, service-banner map, threaded listeners
           • analyze_logs() with sophistication scoring
  Doc 2  JHU HotSoS '24 high-interaction honeypot paper
           • SMTP (Mailoney), LDAP, RDP, Apache with CVE-2021-41773
           • Syslog JSON emission for syslog_aggregator.py
           • Pre-login warning banners

Run
───
  sudo python3 multi_service_honeypot.py [--analyze]
  sudo python3 multi_service_honeypot.py --analyze --log /path/to/honeypot.json
"""

import argparse
import datetime
import json
import os
import socket
import ssl
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

# ── Log directory ─────────────────────────────────────────────
LOG_DIR = Path("/tmp/honeypot_logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / f"honeypot_{datetime.datetime.now().strftime('%Y%m%d')}.json"

# ── Syslog integration (optional) ────────────────────────────
SYSLOG_HOST = "127.0.0.1"
SYSLOG_PORT = 5140   # syslog_aggregator.py listens here

# ── Warning banner (Doc 2 §4.1) ──────────────────────────────
WARNING_BANNER = (
    "*** NOTICE: This is a research honeypot. "
    "Authorised security research only. "
    "All activity is logged and analysed. ***"
)

# ── Service banners ───────────────────────────────────────────
# (Doc 1 §handle_connection + Doc 2 §3.3 service definitions)
SERVICE_BANNERS = {
    21:   f"220 FTP Server Ready ({WARNING_BANNER})\r\n",
    25:   "220 mail.internal.corp ESMTP Mailoney 0.1\r\n",
    80:   (
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.49 (Ubuntu)\r\n"          # CVE-2021-41773 bait
        "Content-Type: text/html\r\n\r\n"
        "<html><body><h1>Corporate Blog</h1>"
        "<p>Welcome to the internal blog portal.</p></body></html>"
    ),
    389:  None,   # LDAP sends no plain banner; responds to bind requests
    443:  None,   # TLS handshake handled separately
    3389: (
        "\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x02"
        "\x00\x00\x00"                                 # RDP connection confirm
    ),
}

# ── FTP command responses (Doc 1 §handle_connection) ─────────
FTP_RESPONSES = {
    "user": "331 Password required\r\n",
    "pass": "530 Login incorrect\r\n",      # always reject, log credentials
    "list": "150 Opening data connection\r\n",
    "stor": "550 Permission denied\r\n",
    "retr": "550 File not found\r\n",
    "quit": "221 Goodbye\r\n",
    "syst": "215 UNIX Type: L8\r\n",
    "feat": "211-Features:\r\n AUTH SSL\r\n211 End\r\n",
    "pwd":  '257 "/" is the current directory\r\n',
}

# ── SMTP command responses (Doc 2 / Mailoney §3.3) ───────────
SMTP_RESPONSES = {
    "ehlo": (
        "250-mail.internal.corp Hello\r\n"
        "250-SIZE 10240000\r\n"
        "250 OK\r\n"
    ),
    "helo": "250 mail.internal.corp Hello\r\n",
    "mail": "250 OK\r\n",
    "rcpt": "250 OK\r\n",
    "data": "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
    "quit": "221 Bye\r\n",
    "auth": "334 VXNlcm5hbWU6\r\n",  # base64 "Username:"
    "rset": "250 OK\r\n",
    "noop": "250 OK\r\n",
}

# ── LDAP bind-request magic bytes (Doc 2 §3.3) ───────────────
LDAP_BIND_RESPONSE = bytes([
    0x30, 0x0c,             # SEQUENCE
    0x02, 0x01, 0x01,       # messageID = 1
    0x61, 0x07,             # BindResponse
    0x0a, 0x01, 0x00,       # resultCode = success (0)
    0x04, 0x00,             # matchedDN = ""
    0x04, 0x00,             # diagnosticMessage = ""
])


# ══════════════════════════════════════════════════════════════
#  LOG HELPERS
# ══════════════════════════════════════════════════════════════

_log_lock = threading.Lock()

def _log(port: int, remote_ip: str, data, extra: dict = None):
    """Append one JSON line to LOG_FILE and optionally emit to syslog_aggregator."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    entry = {
        "timestamp":  datetime.datetime.now().isoformat(),
        "service":    _service_name(port),
        "port":       port,
        "remote_ip":  remote_ip,
        "data":       data,
    }
    if extra:
        entry.update(extra)

    line = json.dumps(entry)
    with _log_lock:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")

    # Optional: forward to syslog_aggregator.py over UDP (Doc 2 §3.2)
    _emit_syslog(line)


def _service_name(port: int) -> str:
    return {21: "FTP", 25: "SMTP", 80: "HTTP",
            389: "LDAP", 443: "HTTPS", 3389: "RDP"}.get(port, str(port))


def _emit_syslog(msg: str):
    """Non-blocking UDP emit to syslog_aggregator.py (Doc 2 §3.2)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.1)
            s.sendto(msg.encode(), (SYSLOG_HOST, SYSLOG_PORT))
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════
#  CONNECTION HANDLERS
# ══════════════════════════════════════════════════════════════

def _handle_ftp(conn: socket.socket, remote_ip: str):
    """
    FTP honeypot handler.
    Doc 1 §handle_connection: banner → receive commands → log → fake response.
    Captures USER + PASS pairs (credential intelligence).
    """
    try:
        conn.sendall(SERVICE_BANNERS[21].encode())
        last_user = ""
        while True:
            raw = conn.recv(1024)
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            cmd  = line.split()[0].lower() if line else ""

            extra = {}
            if cmd == "user":
                last_user = line[5:].strip()
                extra = {"ftp_user": last_user}
            elif cmd == "pass":
                extra = {"ftp_user": last_user, "ftp_pass": line[5:].strip()}

            _log(21, remote_ip, line, extra)
            response = FTP_RESPONSES.get(cmd, "500 Unknown command.\r\n")
            conn.sendall(response.encode())
            if cmd == "quit":
                break
    except Exception:
        pass
    finally:
        conn.close()


def _handle_smtp(conn: socket.socket, remote_ip: str):
    """
    SMTP honeypot handler — Mailoney-style (Doc 2 §3.3).
    Captures: MAIL FROM, RCPT TO, message body, AUTH credentials.
    Logs complete email content for phishing-campaign analysis.
    """
    try:
        conn.sendall(SERVICE_BANNERS[25].encode())
        mail_from = rcpt_to = auth_user = auth_pass = ""
        body_lines = []
        in_data = False

        while True:
            raw = conn.recv(4096)
            if not raw:
                break
            lines = raw.decode("utf-8", errors="replace").split("\r\n")
            for line in lines:
                if not line:
                    continue
                cmd = line.split()[0].lower() if line.strip() else ""

                if in_data:
                    if line == ".":
                        # End of DATA — log full email
                        _log(25, remote_ip, "\n".join(body_lines), {
                            "smtp_from": mail_from,
                            "smtp_rcpt": rcpt_to,
                            "smtp_body_lines": len(body_lines),
                        })
                        conn.sendall(b"250 Message accepted\r\n")
                        in_data = False
                        body_lines = []
                    else:
                        body_lines.append(line)
                    continue

                _log(25, remote_ip, line)

                if cmd in ("ehlo", "helo"):
                    conn.sendall(SMTP_RESPONSES[cmd].encode())
                elif cmd == "mail":
                    mail_from = line[10:].strip()   # MAIL FROM:<...>
                    conn.sendall(SMTP_RESPONSES["mail"].encode())
                elif cmd == "rcpt":
                    rcpt_to = line[8:].strip()      # RCPT TO:<...>
                    conn.sendall(SMTP_RESPONSES["rcpt"].encode())
                elif cmd == "data":
                    in_data = True
                    conn.sendall(SMTP_RESPONSES["data"].encode())
                elif cmd == "auth":
                    # AUTH LOGIN: collect base64-encoded credentials
                    conn.sendall(SMTP_RESPONSES["auth"].encode())
                    u_raw = conn.recv(256)
                    conn.sendall(b"334 UGFzc3dvcmQ6\r\n")  # "Password:"
                    p_raw = conn.recv(256)
                    import base64
                    try:
                        auth_user = base64.b64decode(u_raw.strip()).decode()
                        auth_pass = base64.b64decode(p_raw.strip()).decode()
                    except Exception:
                        auth_user = u_raw.decode("utf-8", errors="replace").strip()
                        auth_pass = p_raw.decode("utf-8", errors="replace").strip()
                    _log(25, remote_ip, "AUTH LOGIN", {
                        "smtp_auth_user": auth_user,
                        "smtp_auth_pass": auth_pass,
                    })
                    conn.sendall(b"535 Authentication failed\r\n")
                elif cmd == "quit":
                    conn.sendall(SMTP_RESPONSES["quit"].encode())
                    break
                else:
                    conn.sendall(SMTP_RESPONSES.get(cmd, "500 Unknown\r\n").encode())
    except Exception:
        pass
    finally:
        conn.close()


def _handle_http(conn: socket.socket, remote_ip: str):
    """
    HTTP honeypot handler — Apache 2.4.49 banner with CVE-2021-41773 lure.

    Doc 2 §3.3:
      "We built a simple blog site using Apache 2.4.49. This version has
      vulnerability CVE-2021-41773. The site does not handle errors so that
      bots can see more valid information."

    Captures:
      • Path traversal attempts (/cgi-bin/.%2e/.%2e/etc/passwd)
      • WordPress/admin path probes
      • POST bodies (credential stuffing attempts against /login)
    """
    try:
        conn.settimeout(10)
        raw = conn.recv(8192)
        if not raw:
            return
        request = raw.decode("utf-8", errors="replace")
        lines = request.split("\r\n")
        method = path = ""
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                method, path = parts[0], parts[1]

        # Detect CVE-2021-41773 path traversal (Doc 2 §3.3)
        traversal = any(x in path for x in [
            ".%2e", ".%2f", "%2e.", "..%2f", "/cgi-bin/", "etc/passwd",
        ])

        # Detect common web attack probes
        probe_type = "generic"
        if traversal:
            probe_type = "CVE-2021-41773_traversal"
        elif any(x in path.lower() for x in ["/wp-admin", "/wp-login", "wordpress"]):
            probe_type = "wordpress_probe"
        elif any(x in path.lower() for x in ["/admin", "/.env", "/phpmyadmin"]):
            probe_type = "admin_probe"
        elif "login" in path.lower() and method == "POST":
            probe_type = "login_stuffing"
        elif any(x in path for x in ["/shell", "/cmd", "/exec"]):
            probe_type = "rce_probe"

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        # Extract POST body for credential capture
        body = ""
        if "\r\n\r\n" in request:
            body = request.split("\r\n\r\n", 1)[1]

        _log(80, remote_ip, f"{method} {path}", {
            "http_method":   method,
            "http_path":     path,
            "probe_type":    probe_type,
            "user_agent":    headers.get("user-agent", ""),
            "body_preview":  body[:200],
            "traversal":     traversal,
        })

        # Respond appropriately to entice further interaction
        if traversal:
            # Return a fake passwd file — looks real to the scanner
            body_content = (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "admin:x:1000:1000:admin,,,:/home/admin:/bin/bash\n"
            )
            conn.sendall((
                f"HTTP/1.1 200 OK\r\n"
                f"Server: Apache/2.4.49 (Ubuntu)\r\n"
                f"Content-Length: {len(body_content)}\r\n\r\n"
                f"{body_content}"
            ).encode())
        elif probe_type == "login_stuffing":
            conn.sendall(
                b"HTTP/1.1 401 Unauthorized\r\n"
                b"Server: Apache/2.4.49 (Ubuntu)\r\n"
                b"WWW-Authenticate: Basic realm=\"Internal\"\r\n\r\n"
                b"<html><body>Unauthorized</body></html>"
            )
        else:
            conn.sendall(SERVICE_BANNERS[80].encode())
    except Exception:
        pass
    finally:
        conn.close()


def _handle_ldap(conn: socket.socket, remote_ip: str):
    """
    LDAP honeypot handler (Doc 2 §3.3 — custom Python LDAP service).
    Parses BER-encoded BindRequest to extract DN + password.
    Responds with BindResponse success (keeps bot engaged longer).
    Logs every bind attempt including credentials.
    """
    try:
        conn.settimeout(15)
        raw = conn.recv(1024)
        if not raw:
            return

        # Minimal BER parser: extract bind DN and simple-auth password
        dn = password = ""
        try:
            # LDAP BindRequest: 0x30(SEQUENCE) len 0x02 messageID 0x60(BindRequest)
            idx = 0
            if raw[idx] == 0x30:           # SEQUENCE
                idx += 2                    # skip tag + length
            if raw[idx] == 0x02:           # INTEGER (messageID)
                id_len = raw[idx + 1]
                idx += 2 + id_len
            if raw[idx] == 0x60:           # BindRequest application tag
                idx += 2
            if raw[idx] == 0x02:           # version
                idx += 2 + raw[idx + 1]
            if raw[idx] == 0x04:           # DN (OCTET STRING)
                dn_len = raw[idx + 1]
                idx += 2
                dn = raw[idx:idx + dn_len].decode("utf-8", errors="replace")
                idx += dn_len
            if idx < len(raw) and raw[idx] == 0x80:  # simple auth (context[0])
                pw_len = raw[idx + 1]
                idx += 2
                password = raw[idx:idx + pw_len].decode("utf-8", errors="replace")
        except Exception:
            pass  # still log whatever we got

        _log(389, remote_ip, raw, {
            "ldap_dn":       dn,
            "ldap_password": password,
        })

        # Respond with BindResponse success — attacker thinks they got in
        conn.sendall(LDAP_BIND_RESPONSE)

        # Continue receiving operations (search, modify etc.)
        while True:
            extra = conn.recv(1024)
            if not extra:
                break
            _log(389, remote_ip, extra, {"ldap_post_bind": True})
            # Generic success response
            conn.sendall(bytes([0x30, 0x07, 0x02, 0x01, 0x02,
                                0x65, 0x02, 0x0a, 0x00]))
    except Exception:
        pass
    finally:
        conn.close()


def _handle_rdp(conn: socket.socket, remote_ip: str):
    """
    RDP honeypot handler (Doc 2 §3.3 — custom Docker RDP container).
    Captures the NLA / legacy RDP connection negotiation and logs client info.
    Accepts any username/password (Linux PAM style from the paper).
    """
    try:
        conn.settimeout(15)
        raw = conn.recv(1024)
        if not raw:
            return

        # Parse TPKT / X.224 connection request to extract cookie (username)
        username = ""
        try:
            if len(raw) > 11:
                cookie_start = raw.find(b"Cookie: mstshash=")
                if cookie_start != -1:
                    end = raw.find(b"\r\n", cookie_start)
                    username = raw[cookie_start + 17:end].decode("utf-8", errors="replace")
        except Exception:
            pass

        _log(3389, remote_ip, raw, {
            "rdp_username":   username,
            "rdp_packet_len": len(raw),
        })

        # Send RDP Connection Confirm (TPKT + X.224)
        conn.sendall(SERVICE_BANNERS[3389])

        # Receive further negotiation packets
        for _ in range(5):
            pkt = conn.recv(4096)
            if not pkt:
                break
            _log(3389, remote_ip, pkt, {"rdp_negotiation": True})
    except Exception:
        pass
    finally:
        conn.close()


def _handle_https(conn: socket.socket, remote_ip: str):
    """
    HTTPS honeypot — wraps TLS around the HTTP handler (Doc 1 §handle_connection).
    Uses a self-signed cert; browsers/bots still connect and reveal their JA3.
    Falls back gracefully if SSL is unavailable.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Generate self-signed cert if not present
        cert_path = LOG_DIR / "honeypot.crt"
        key_path  = LOG_DIR / "honeypot.key"
        _ensure_self_signed_cert(cert_path, key_path)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        tls_conn = ctx.wrap_socket(conn, server_side=True)
        _handle_http(tls_conn, remote_ip)
    except ssl.SSLError:
        # TLS handshake failed — still log the raw attempt
        _log(443, remote_ip, b"TLS_HANDSHAKE_FAILED", {})
        conn.close()
    except Exception:
        conn.close()


def _ensure_self_signed_cert(cert_path: Path, key_path: Path):
    """Generate a self-signed cert for the HTTPS honeypot if needed."""
    if cert_path.exists() and key_path.exists():
        return
    try:
        import subprocess
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path),
            "-out", str(cert_path),
            "-days", "365", "-nodes",
            "-subj", "/CN=corporate.internal.corp"
        ], capture_output=True, check=True)
    except Exception:
        # If openssl not available, write dummy byte so we skip gracefully
        key_path.write_bytes(b"")
        cert_path.write_bytes(b"")


# ── Dispatch table ────────────────────────────────────────────
_HANDLERS = {
    21:   _handle_ftp,
    25:   _handle_smtp,
    80:   _handle_http,
    389:  _handle_ldap,
    443:  _handle_https,
    3389: _handle_rdp,
}


# ══════════════════════════════════════════════════════════════
#  CORE HONEYPOT CLASS  (Doc 1 §How to Build the Core Honeypot)
# ══════════════════════════════════════════════════════════════

class Honeypot:
    """
    Core honeypot class (Doc 1 architecture).

    Binds to all interfaces and starts one listener thread per port.
    Handles each inbound connection in a dedicated thread so concurrent
    scanners/bots don't block each other.
    """

    def __init__(self, bind_ip: str = "0.0.0.0", ports: list = None):
        self.bind_ip          = bind_ip
        self.ports            = ports or [21, 25, 80, 389, 443, 3389]
        self.active_connections: dict = {}
        self._stop            = threading.Event()

    def start_listener(self, port: int):
        """
        Start a raw-socket listener on *port*.
        Doc 1 §Implement the Network Listeners.
        """
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.bind_ip, port))
            server.listen(5)
            server.settimeout(1.0)
            print(f"[HONEYPOT] Listening on {self.bind_ip}:{port} "
                  f"({_service_name(port)})")

            while not self._stop.is_set():
                try:
                    client, addr = server.accept()
                    remote_ip = addr[0]
                    print(f"[HONEYPOT] {_service_name(port):<5} connection "
                          f"from {remote_ip}:{addr[1]}")
                    handler = _HANDLERS.get(port)
                    if handler:
                        t = threading.Thread(
                            target=handler,
                            args=(client, remote_ip),
                            daemon=True,
                        )
                        t.start()
                    else:
                        client.close()
                except socket.timeout:
                    continue
        except OSError as e:
            print(f"[HONEYPOT] Cannot bind port {port}: {e}")
        finally:
            try:
                server.close()
            except Exception:
                pass

    def run(self):
        """Start all listeners and block until Ctrl-C."""
        threads = []
        for port in self.ports:
            t = threading.Thread(
                target=self.start_listener,
                args=(port,),
                daemon=True,
            )
            t.start()
            threads.append(t)

        print(f"[HONEYPOT] Running {len(self.ports)} service listeners. "
              f"Logging to {LOG_FILE}")
        print(f"[HONEYPOT] Press Ctrl-C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[HONEYPOT] Shutting down …")
            self._stop.set()

    def stop(self):
        self._stop.set()


# ══════════════════════════════════════════════════════════════
#  LOG ANALYSIS  (Doc 1 §How to Analyze Honeypot Data)
# ══════════════════════════════════════════════════════════════

def analyze_logs(log_file: str) -> dict:
    """
    Enhanced honeypot log analysis with temporal and behavioural patterns.

    Matches the tutorial's exact structure:
      - IP-based analysis       (total attempts, active duration, ports, payloads)
      - Port-targeting analysis (attempts per service, unique IPs, payloads)
      - Temporal analysis       (hourly attack distribution)
      - Sophistication scoring  (Doc 1 formula: port_diversity×0.4 + payload_diversity×0.6)
      - Common payload patterns (top 10)

    Also adds Doc 2 enhancements:
      - Service-specific credential harvesting (FTP user:pass, SMTP AUTH, LDAP DN)
      - Probe-type breakdown (CVE-2021-41773, WordPress, admin panels, RDP brute-force)
    """
    ip_analysis: dict  = {}
    port_analysis: dict = {}
    hourly_attacks: dict = {}
    data_patterns: dict = {}
    credential_dump: list = []
    probe_types: dict  = defaultdict(int)
    attack_timeline: list = []

    with open(log_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                activity  = json.loads(line)
                timestamp = datetime.datetime.fromisoformat(activity["timestamp"])
                ip        = activity["remote_ip"]
                port      = activity["port"]
                data      = activity.get("data", "")
                service   = activity.get("service", str(port))

                # ── IP tracking ────────────────────────────────
                if ip not in ip_analysis:
                    ip_analysis[ip] = {
                        "total_attempts":  0,
                        "first_seen":      timestamp,
                        "last_seen":       timestamp,
                        "targeted_ports":  set(),
                        "targeted_services": set(),
                        "unique_payloads": set(),
                        "session_count":   0,
                    }
                rec = ip_analysis[ip]
                rec["total_attempts"] += 1
                rec["last_seen"]       = max(rec["last_seen"], timestamp)
                rec["targeted_ports"].add(port)
                rec["targeted_services"].add(service)
                rec["unique_payloads"].add(str(data).strip())

                # ── Hourly distribution ────────────────────────
                h = timestamp.hour
                hourly_attacks[h] = hourly_attacks.get(h, 0) + 1

                # ── Port analysis ──────────────────────────────
                if port not in port_analysis:
                    port_analysis[port] = {
                        "service":         service,
                        "total_attempts":  0,
                        "unique_ips":      set(),
                        "unique_payloads": set(),
                    }
                port_analysis[port]["total_attempts"] += 1
                port_analysis[port]["unique_ips"].add(ip)
                port_analysis[port]["unique_payloads"].add(str(data).strip())

                # ── Payload frequency ──────────────────────────
                stripped = str(data).strip()
                if stripped:
                    data_patterns[stripped] = data_patterns.get(stripped, 0) + 1

                # ── Credential capture ─────────────────────────
                for cred_field in ("ftp_user", "smtp_auth_user", "ldap_dn",
                                   "rdp_username"):
                    if cred_field in activity and activity[cred_field]:
                        credential_dump.append({
                            "ts":      activity["timestamp"],
                            "ip":      ip,
                            "service": service,
                            "field":   cred_field,
                            "value":   activity[cred_field],
                        })

                # ── Probe types ────────────────────────────────
                probe = activity.get("probe_type", "")
                if probe:
                    probe_types[probe] += 1

                attack_timeline.append({
                    "timestamp": timestamp,
                    "ip":        ip,
                    "port":      port,
                })

            except (json.JSONDecodeError, KeyError):
                continue

    # ── Serialize sets for JSON-safe output ───────────────────
    for ip, rec in ip_analysis.items():
        rec["targeted_ports"]    = list(rec["targeted_ports"])
        rec["targeted_services"] = list(rec["targeted_services"])
        rec["unique_payloads"]   = list(rec["unique_payloads"])

    for port, rec in port_analysis.items():
        rec["unique_ips"]      = list(rec["unique_ips"])
        rec["unique_payloads"] = list(rec["unique_payloads"])

    # ══════════════════════════════════════════════════════════
    #  REPORT  (Doc 1 §How to Analyze Honeypot Data — verbatim
    #           section headers + sophistication scoring)
    # ══════════════════════════════════════════════════════════

    print("\n=== Honeypot Analysis Report ===")

    # 1. IP-based Analysis (Doc 1)
    print("\nTop 10 Most Active IPs:")
    sorted_ips = sorted(
        ip_analysis.items(),
        key=lambda x: x[1]["total_attempts"],
        reverse=True,
    )[:10]

    for ip, stats in sorted_ips:
        first = stats["first_seen"]
        last  = stats["last_seen"]
        dur   = last - first if isinstance(last, datetime.datetime) else datetime.timedelta(0)
        print(f"\n  IP: {ip}")
        print(f"  Total Attempts:       {stats['total_attempts']}")
        print(f"  Active Duration:      {dur}")
        print(f"  Unique Ports:         {len(stats['targeted_ports'])} "
              f"({', '.join(map(str, stats['targeted_ports']))})")
        print(f"  Unique Services:      {', '.join(stats['targeted_services'])}")
        print(f"  Unique Payloads:      {len(stats['unique_payloads'])}")

    # 2. Port Targeting Analysis (Doc 1)
    print("\nPort Targeting Analysis:")
    for port, stats in sorted(
        port_analysis.items(),
        key=lambda x: x[1]["total_attempts"],
        reverse=True,
    ):
        print(f"\n  Port {port} ({stats['service']}):")
        print(f"  Total Attempts:       {stats['total_attempts']}")
        print(f"  Unique Attackers:     {len(stats['unique_ips'])}")
        print(f"  Unique Payloads:      {len(stats['unique_payloads'])}")

    # 3. Temporal Analysis (Doc 1)
    print("\nHourly Attack Distribution:")
    for hour in sorted(hourly_attacks):
        bar = "█" * (hourly_attacks[hour] // max(1, max(hourly_attacks.values()) // 30))
        print(f"  Hour {hour:02d}: {hourly_attacks[hour]:5d}  {bar}")

    # 4. Attacker Sophistication Analysis (Doc 1 exact formula)
    #    score = port_diversity * 0.4 + payload_diversity * 0.6
    print("\nAttacker Sophistication Analysis:")
    for ip, stats in sorted_ips:
        score = (
            len(stats["targeted_ports"])    * 0.4 +
            len(stats["unique_payloads"])   * 0.6
        )
        print(f"  IP {ip}: Sophistication Score {score:.2f}")

    # 5. Common Payload Patterns (Doc 1 — top 10)
    print("\nTop 10 Most Common Payloads:")
    sorted_payloads = sorted(
        data_patterns.items(),
        key=lambda x: x[1],
        reverse=True,
    )[:10]
    for payload, count in sorted_payloads:
        display = payload[:50] + "…" if len(payload) > 50 else payload
        print(f"  Count {count:5d}: {display}")

    # 6. Credentials Harvested (Doc 2)
    if credential_dump:
        print(f"\nCredentials Captured ({len(credential_dump)} entries):")
        for c in credential_dump[:20]:
            print(f"  [{c['service']}] {c['ip']} → {c['field']}={c['value']}")

    # 7. Probe Types (Doc 2 — CVE-2021-41773, WordPress, etc.)
    if probe_types:
        print("\nHTTP Probe Types:")
        for ptype, count in sorted(probe_types.items(), key=lambda x: -x[1]):
            print(f"  {ptype:<35} {count:5d}")

    result = {
        "ip_analysis":      ip_analysis,
        "port_analysis":    port_analysis,
        "hourly_attacks":   hourly_attacks,
        "sophistication":   {
            ip: (len(s["targeted_ports"]) * 0.4
                 + len(s["unique_payloads"]) * 0.6)
            for ip, s in ip_analysis.items()
        },
        "credential_dump":  credential_dump,
        "probe_types":      dict(probe_types),
        "top_payloads":     sorted_payloads[:10],
    }
    return result


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Multi-Service Honeypot — AUA CS 232/337"
    )
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=[21, 25, 80, 389, 443, 3389],
        help="Ports to listen on (default: 21 25 80 389 443 3389)",
    )
    parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="Bind IP (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze existing log file instead of starting honeypot",
    )
    parser.add_argument(
        "--log",
        default=str(LOG_FILE),
        help="Log file path for --analyze mode",
    )
    args = parser.parse_args()

    if args.analyze:
        if not os.path.exists(args.log):
            print(f"[ERROR] Log file not found: {args.log}")
            sys.exit(1)
        analyze_logs(args.log)
    else:
        hp = Honeypot(bind_ip=args.bind, ports=args.ports)
        hp.run()


if __name__ == "__main__":
    main()
