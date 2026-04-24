"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Real-Time Lab Dashboard
 Environment: ISOLATED VM LAB ONLY
====================================================

Terminal dashboard giving a single-pane view of the
entire running lab during an attack/defense scenario.

Panels (auto-refreshing every 2 s):
  ┌─ VM STATUS ─┐  ┌─ C2 BOT REGISTRY ──────────────┐
  │ C2  ● UP    │  │ bot-uuid-1  192.168.100.11  ✓   │
  │ Bot1 ● UP   │  │ bot-uuid-2  192.168.100.12  ✓   │
  │ Victim ● UP │  └────────────────────────────────┘
  └─────────────┘
  ┌─ ATTACK QUEUE ──┐  ┌─ IDS ALERT STREAM ─────────┐
  │ syn_flood  20s  │  │ [HIGH]  E1  SYN flood       │
  │ cred_stuff …    │  │ [MED]   E2  CV=0.09         │
  └─────────────────┘  └────────────────────────────┘
  ┌─ METRICS ──────────────────────────────────────┐
  │ Alerts: 12  |  HIGH: 4  MED: 6  LOW: 2        │
  │ Bots: 2     |  Uptime: 00:04:32               │
  └────────────────────────────────────────────────┘

Usage:
  python3 lab_dashboard.py                  # full curses UI
  python3 lab_dashboard.py --simple         # ANSI fallback (no curses)
  python3 lab_dashboard.py --export         # dump snapshot to JSON
  python3 lab_dashboard.py --help
"""

import argparse
import curses
import json
import os
import re
import socket
import sys
import time
import threading
import urllib.request
from collections import deque
from datetime import datetime

# ── Configuration ──────────────────────────────────────────────
C2_HOST   = os.getenv("C2_HOST",     "192.168.100.10")
BOT1_IP   = os.getenv("BOT1_IP",     "192.168.100.11")
BOT2_IP   = os.getenv("BOT2_IP",     "192.168.100.12")
VICTIM_IP = os.getenv("VICTIM_IP",   "192.168.100.20")
C2_PORT   = int(os.getenv("C2_PORT", "5000"))
AUTH_TOK  = os.getenv("AUTH_TOKEN",  "aw")
IDS_LOG   = os.getenv("IDS_LOG",     "/tmp/ids.log")
REFRESH   = 2   # seconds between full redraws

VM_LABELS = {
    C2_HOST:   "C2 Server",
    BOT1_IP:   "Bot Agent 1",
    BOT2_IP:   "Bot Agent 2",
    VICTIM_IP: "Victim / Honeypot",
}
VM_PORTS = {
    C2_HOST:   C2_PORT,
    BOT1_IP:   22,
    BOT2_IP:   22,
    VICTIM_IP: 80,
}

# ── Severity colours (curses pair indices) ─────────────────────
CP_TITLE  = 1   # blue on default
CP_OK     = 2   # green
CP_WARN   = 3   # yellow
CP_HIGH   = 4   # red
CP_MED    = 5   # magenta
CP_LOW    = 6   # cyan
CP_DIM    = 7   # white dim

# ─────────────────────────────────────────────────────────────
# State — refreshed by background threads
# ─────────────────────────────────────────────────────────────

class LabState:
    def __init__(self):
        self.lock       = threading.Lock()
        self.start_time = time.time()

        self.vm_status:  dict[str, bool]   = {ip: False for ip in VM_LABELS}
        self.bots:       dict              = {}
        self.alerts:     deque             = deque(maxlen=200)
        self.alert_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}

        self.ids_log_pos = 0   # byte offset — only read new lines
        self._running   = True

    # ── VM reachability ────────────────────────────────────────
    def probe_vm(self, ip: str):
        port = VM_PORTS[ip]
        try:
            s = socket.create_connection((ip, port), timeout=1.5)
            s.close()
            return True
        except OSError:
            return False

    def refresh_vms(self):
        while self._running:
            results = {}
            for ip in VM_LABELS:
                results[ip] = self.probe_vm(ip)
            with self.lock:
                self.vm_status = results
            time.sleep(5)

    # ── C2 bot registry ────────────────────────────────────────
    def refresh_bots(self):
        while self._running:
            try:
                req = urllib.request.Request(
                    f"http://{C2_HOST}:{C2_PORT}/bots",
                    headers={"X-Auth-Token": AUTH_TOK}
                )
                with urllib.request.urlopen(req, timeout=2) as resp:
                    data = json.loads(resp.read())
                with self.lock:
                    self.bots = data
            except Exception:
                pass
            time.sleep(4)

    # ── IDS alert tail ─────────────────────────────────────────
    _ALERT_RE = re.compile(
        r"ALERT\s+#?\d+\s+\[?(?P<sev>HIGH|MEDIUM|LOW)\]?\s+"
        r"Engine:\s*(?P<eng>[^\s]+)\s+@\s+(?P<ts>\S+)\s+--\s*(?P<msg>.*)",
        re.IGNORECASE
    )

    def _parse_alert_line(self, line: str) -> dict | None:
        m = self._ALERT_RE.search(line)
        if m:
            return {
                "sev": m.group("sev").upper(),
                "engine": m.group("eng"),
                "ts": m.group("ts"),
                "msg": m.group("msg").strip()[:80],
                "raw": line.strip()[:100],
            }
        # Fallback: any line with ALERT keyword
        if "ALERT" in line and ("[HIGH]" in line or "[MEDIUM]" in line or "[LOW]" in line):
            sev = "HIGH" if "[HIGH]" in line else ("MEDIUM" if "[MEDIUM]" in line else "LOW")
            return {"sev": sev, "engine": "?", "ts": "?", "msg": line.strip()[:80], "raw": line.strip()}
        return None

    def tail_ids_log(self):
        while self._running:
            if not os.path.exists(IDS_LOG):
                time.sleep(2)
                continue
            try:
                with open(IDS_LOG, "rb") as f:
                    f.seek(self.ids_log_pos)
                    chunk = f.read(32768)
                    new_pos = f.tell()
                if chunk:
                    for line in chunk.decode("utf-8", errors="replace").splitlines():
                        parsed = self._parse_alert_line(line)
                        if parsed:
                            with self.lock:
                                self.alerts.appendleft(parsed)
                                sev = parsed["sev"]
                                self.alert_counts["total"] += 1
                                if sev in self.alert_counts:
                                    self.alert_counts[sev] += 1
                    self.ids_log_pos = new_pos
            except Exception:
                pass
            time.sleep(1)

    def start_threads(self):
        for fn in (self.refresh_vms, self.refresh_bots, self.tail_ids_log):
            t = threading.Thread(target=fn, daemon=True)
            t.start()

    def stop(self):
        self._running = False

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "timestamp":   datetime.now().isoformat(),
                "uptime_s":    int(time.time() - self.start_time),
                "vm_status":   dict(self.vm_status),
                "bots":        dict(self.bots),
                "alert_counts": dict(self.alert_counts),
                "recent_alerts": list(self.alerts)[:20],
            }


# ─────────────────────────────────────────────────────────────
# Curses UI
# ─────────────────────────────────────────────────────────────

def _safe_addstr(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    text = text[:max(0, w - x - 1)]
    try:
        win.addstr(y, x, text, attr)
    except curses.error:
        pass

def _hline(win, y, x, w, attr=0):
    _safe_addstr(win, y, x, "─" * w, attr)

def _box_title(win, y, x, w, title, cp):
    inner = w - 2
    _safe_addstr(win, y, x, "┌" + "─" * inner + "┐", curses.color_pair(cp))
    _safe_addstr(win, y, x + 2, f" {title} ", curses.color_pair(cp) | curses.A_BOLD)

def _box_row(win, y, x, w, text, cp=0):
    inner = w - 2
    text = (text + " " * inner)[:inner]
    _safe_addstr(win, y, x, "│", curses.color_pair(cp))
    _safe_addstr(win, y, x + 1, text)
    _safe_addstr(win, y, x + w - 1, "│", curses.color_pair(cp))

def _box_bottom(win, y, x, w, cp):
    inner = w - 2
    _safe_addstr(win, y, x, "└" + "─" * inner + "┘", curses.color_pair(cp))


def draw_vm_panel(win, state: LabState, y: int, x: int, w: int):
    h = len(VM_LABELS) + 2
    _box_title(win, y, x, w, "VM STATUS", CP_TITLE)
    for i, (ip, label) in enumerate(VM_LABELS.items()):
        up = state.vm_status.get(ip, False)
        dot = "●" if up else "○"
        cp  = CP_OK if up else CP_HIGH
        status = "UP  " if up else "DOWN"
        row = f" {dot} {label:<20} {status}  {ip}"
        _safe_addstr(win, y + 1 + i, x, "│", curses.color_pair(CP_TITLE))
        _safe_addstr(win, y + 1 + i, x + 1, f" {dot} ", curses.color_pair(cp) | curses.A_BOLD)
        _safe_addstr(win, y + 1 + i, x + 4, f"{label:<20} {status}  {ip}")
        _safe_addstr(win, y + 1 + i, x + w - 1, "│", curses.color_pair(CP_TITLE))
    _box_bottom(win, y + h - 1, x, w, CP_TITLE)


def draw_bot_panel(win, state: LabState, y: int, x: int, w: int):
    bots = state.bots
    rows = max(4, len(bots) + 2)
    _box_title(win, y, x, w, f"C2 BOT REGISTRY  [{len(bots)} online]", CP_TITLE)
    if not bots:
        _box_row(win, y + 1, x, w, "  (no bots registered yet)")
        for r in range(2, rows - 1):
            _box_row(win, y + r, x, w, "")
    else:
        for i, (bid, info) in enumerate(list(bots.items())[:rows - 2]):
            last = info.get("last_seen", "")[:19].replace("T", " ")
            hb   = info.get("heartbeat_count", 0)
            enc  = "AES" if info.get("supports_enc") else "raw"
            row  = f"  {bid[:24]:<24}  {info.get('ip','?'):<15}  hb={hb:<4} {enc}  {last}"
            _box_row(win, y + 1 + i, x, w, row)
    _box_bottom(win, y + rows - 1, x, w, CP_TITLE)


def draw_alert_panel(win, state: LabState, y: int, x: int, w: int, max_rows: int):
    visible = max_rows - 2
    _box_title(win, y, x, w, "IDS ALERT STREAM", CP_TITLE)
    alerts = list(state.alerts)[:visible]
    SEV_CP = {"HIGH": CP_HIGH, "MEDIUM": CP_MED, "LOW": CP_LOW}
    for i in range(visible):
        if i < len(alerts):
            a   = alerts[i]
            sev = a["sev"]
            cp  = SEV_CP.get(sev, CP_DIM)
            tag = f"[{sev[:3]}]"
            eng = f"E{a['engine']}" if a["engine"] != "?" else "E?"
            msg = a["msg"][:w - 20]
            _safe_addstr(win, y + 1 + i, x, "│", curses.color_pair(CP_TITLE))
            _safe_addstr(win, y + 1 + i, x + 1, f" {tag} ", curses.color_pair(cp) | curses.A_BOLD)
            _safe_addstr(win, y + 1 + i, x + 7, f"{eng:<4}  {msg}")
            _safe_addstr(win, y + 1 + i, x + w - 1, "│", curses.color_pair(CP_TITLE))
        else:
            _box_row(win, y + 1 + i, x, w, "")
    _box_bottom(win, y + max_rows - 1, x, w, CP_TITLE)


def draw_metrics(win, state: LabState, y: int, x: int, w: int):
    counts  = state.alert_counts
    uptime  = int(time.time() - state.start_time)
    h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60
    up_str  = f"{h:02d}:{m:02d}:{s:02d}"
    n_bots  = len(state.bots)
    n_vms   = sum(1 for v in state.vm_status.values() if v)

    _box_title(win, y, x, w, "METRICS", CP_TITLE)
    row1 = (f"  Alerts: {counts['total']:<5}  "
            f"HIGH: {counts['HIGH']:<4}  "
            f"MEDIUM: {counts['MEDIUM']:<4}  "
            f"LOW: {counts['LOW']:<4}")
    row2 = (f"  VMs up: {n_vms}/4        "
            f"Bots online: {n_bots}        "
            f"Uptime: {up_str}")
    _box_row(win, y + 1, x, w, row1)
    _box_row(win, y + 2, x, w, row2)
    _box_bottom(win, y + 3, x, w, CP_TITLE)


def draw_header(win, w: int):
    title = "  AUA CS 232/337 — Botnet Research Lab Dashboard  "
    ts    = datetime.now().strftime("%H:%M:%S")
    line  = title + " " * max(0, w - len(title) - len(ts) - 2) + ts
    _safe_addstr(win, 0, 0, line[:w], curses.color_pair(CP_TITLE) | curses.A_BOLD | curses.A_REVERSE)


def draw_footer(win, h: int, w: int):
    footer = "  q: quit   r: force refresh   e: export snapshot   [auto-refresh 2s]  "
    _safe_addstr(win, h - 1, 0, footer[:w], curses.color_pair(CP_DIM) | curses.A_REVERSE)


def curses_main(stdscr, state: LabState):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(REFRESH * 1000)

    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(CP_TITLE, curses.COLOR_BLUE,    -1)
    curses.init_pair(CP_OK,    curses.COLOR_GREEN,   -1)
    curses.init_pair(CP_WARN,  curses.COLOR_YELLOW,  -1)
    curses.init_pair(CP_HIGH,  curses.COLOR_RED,     -1)
    curses.init_pair(CP_MED,   curses.COLOR_MAGENTA, -1)
    curses.init_pair(CP_LOW,   curses.COLOR_CYAN,    -1)
    curses.init_pair(CP_DIM,   curses.COLOR_WHITE,   -1)

    while True:
        key = stdscr.getch()
        if key in (ord("q"), ord("Q")):
            break
        if key in (ord("e"), ord("E")):
            snap = state.snapshot()
            with open("/tmp/lab_dashboard_snapshot.json", "w") as f:
                json.dump(snap, f, indent=2)

        stdscr.erase()
        h, w = stdscr.getmaxyx()
        if h < 20 or w < 60:
            _safe_addstr(stdscr, 0, 0, "Terminal too small — resize to ≥60×20")
            stdscr.refresh()
            continue

        draw_header(stdscr, w)
        draw_footer(stdscr, h, w)

        with state.lock:
            # Layout
            left_w  = min(52, w // 2)
            right_w = w - left_w

            # Row 1: VM panel (left) + Bot panel (right)
            vm_h   = len(VM_LABELS) + 2   # 6 rows
            draw_vm_panel(stdscr,  state, 1,          0,      left_w)
            draw_bot_panel(stdscr, state, 1,          left_w, right_w)

            # Row 2: Metrics bar
            draw_metrics(stdscr, state, 1 + vm_h, 0, w)

            # Row 3: Alert stream — takes remaining height
            alert_top  = 1 + vm_h + 4
            alert_rows = max(4, h - alert_top - 1)
            draw_alert_panel(stdscr, state, alert_top, 0, w, alert_rows)

        stdscr.refresh()

    state.stop()


# ─────────────────────────────────────────────────────────────
# Simple ANSI fallback (no curses)
# ─────────────────────────────────────────────────────────────

ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
}

def simple_loop(state: LabState):
    print(f"\n{ANSI['bold']}{ANSI['blue']}AUA CS 232/337 — Lab Dashboard (simple mode){ANSI['reset']}")
    print("Press Ctrl-C to exit\n")
    try:
        while True:
            snap = state.snapshot()
            print(f"\r\033[K{ANSI['dim']}{datetime.now().strftime('%H:%M:%S')}{ANSI['reset']}  ", end="")
            # VMs
            vm_parts = []
            for ip, label in VM_LABELS.items():
                up  = snap["vm_status"].get(ip, False)
                col = ANSI["green"] if up else ANSI["red"]
                vm_parts.append(f"{col}{'●' if up else '○'}{ANSI['reset']} {label.split()[0]}")
            print("  ".join(vm_parts), end="   ")
            # Counts
            c = snap["alert_counts"]
            print(f"Alerts: {c['total']}  "
                  f"{ANSI['red']}H:{c['HIGH']}{ANSI['reset']}  "
                  f"{ANSI['magenta']}M:{c['MEDIUM']}{ANSI['reset']}  "
                  f"{ANSI['cyan']}L:{c['LOW']}{ANSI['reset']}  "
                  f"Bots:{len(snap['bots'])}",
                  end="", flush=True)
            time.sleep(REFRESH)
    except KeyboardInterrupt:
        print("\nExiting.")
        state.stop()


# ─────────────────────────────────────────────────────────────
# Entry
# ─────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="AUA Botnet Lab Dashboard")
    ap.add_argument("--simple",   action="store_true", help="ANSI mode (no curses)")
    ap.add_argument("--export",   action="store_true", help="Export snapshot to JSON and exit")
    ap.add_argument("--c2",       default=C2_HOST,     metavar="IP", help="C2 server IP")
    ap.add_argument("--ids-log",  default=IDS_LOG,     metavar="PATH")
    args = ap.parse_args()

    global C2_HOST, IDS_LOG
    C2_HOST = args.c2
    IDS_LOG = args.ids_log

    state = LabState()
    state.start_threads()
    time.sleep(0.5)   # let first probes run

    if args.export:
        snap = state.snapshot()
        path = "/tmp/lab_dashboard_snapshot.json"
        with open(path, "w") as f:
            json.dump(snap, f, indent=2)
        print(f"Snapshot written to {path}")
        state.stop()
        return

    if args.simple:
        simple_loop(state)
        return

    try:
        curses.wrapper(curses_main, state)
    except Exception as exc:
        print(f"curses error ({exc}), falling back to simple mode")
        simple_loop(state)


if __name__ == "__main__":
    main()
