"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Tarpit Shared State
 Environment: ISOLATED VM LAB ONLY
====================================================

Lightweight inter-process state for the IDS → portal tarpit loop.

Design:
  - The IDS (ids_detector.py) calls tarpit_state.flag(ip) when it
    detects credential stuffing via Engine 2 (CV < threshold).
  - The portal (fake_portal.py) calls tarpit_state.is_flagged(ip)
    before responding; flagged IPs receive a configurable delay.
  - State is stored in a JSON file so both processes share it even
    when running in separate terminals (no shared memory needed).
  - Entries automatically expire after TTL_SECONDS so a bot that
    adds jitter and later passes the CV check gets unblocked.

This implements the "tarpitting" countermeasure described in the
README (Section 9.3): the attacker's connection is kept open but
responses are delayed by several seconds, driving their effective
credential-test throughput toward zero without a hard block that
would reveal detection.
"""

import json
import os
import time
import threading
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────
STATE_FILE    = "/tmp/tarpit_state.json"   # shared between IDS and portal
TTL_SECONDS   = 300                         # flagged entries expire after 5 min
TARPIT_DELAY  = 8.0                         # seconds to delay flagged IPs
TARPIT_JITTER = 2.0                         # ±jitter on delay (avoid timing fingerprint)

_lock = threading.Lock()


def _load() -> dict:
    """Load state from disk. Returns empty dict on missing/corrupt file."""
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(state: dict):
    """Atomically write state to disk."""
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def _prune(state: dict) -> dict:
    """Remove expired entries."""
    now = time.time()
    return {ip: ts for ip, ts in state.items() if now - ts < TTL_SECONDS}


# ── Public API ────────────────────────────────────────────────

def flag(ip: str):
    """
    Mark an IP as a confirmed bot (called by IDS Engine 2).
    Writes a timestamp; the portal reads this before responding.
    """
    with _lock:
        state = _prune(_load())
        state[ip] = time.time()
        _save(state)
    print(f"[TARPIT] Flagged {ip} — portal will now slow all responses from this IP")


def unflag(ip: str):
    """Remove a flag (e.g. if bot goes quiet and CV normalises)."""
    with _lock:
        state = _prune(_load())
        state.pop(ip, None)
        _save(state)
    print(f"[TARPIT] Unflagged {ip}")


def is_flagged(ip: str) -> bool:
    """Return True if this IP is currently in the tarpit."""
    with _lock:
        state = _prune(_load())
        _save(state)   # persist pruned version
        return ip in state


def list_flagged() -> list[str]:
    """Return all currently flagged IPs (for admin/debug)."""
    with _lock:
        state = _prune(_load())
        _save(state)
        return list(state.keys())


def clear_all():
    """Wipe all tarpit entries (cleanup / post-session reset)."""
    with _lock:
        _save({})
    print("[TARPIT] All entries cleared")


def tarpit_delay() -> float:
    """Return a jittered tarpit delay in seconds."""
    import random
    return TARPIT_DELAY + random.uniform(-TARPIT_JITTER, TARPIT_JITTER)


# ── CLI ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: python3 tarpit_state.py [list | flag <ip> | unflag <ip> | clear]")
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "list":
        ips = list_flagged()
        print(f"Currently flagged ({len(ips)} IPs):")
        for ip in ips:
            print(f"  {ip}")
    elif cmd == "flag" and len(sys.argv) == 3:
        flag(sys.argv[2])
    elif cmd == "unflag" and len(sys.argv) == 3:
        unflag(sys.argv[2])
    elif cmd == "clear":
        clear_all()
    else:
        print("Unknown command")
