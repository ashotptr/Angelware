"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Graph 2 + 3 Data Collection Helper
 Environment: ISOLATED VM LAB ONLY
====================================================

Automates the Week 7 data collection for Graphs 2 and 3.
Outputs graph2_measured_data.json and graph3_measured_data.json
which generate_graphs.py reads automatically.

Usage
-----
Graph 2 — Persistence Paradox (run on victim VM after each Mirai scan):
    python3 collect_graph23_data.py --graph2

  What it does:
    Reads the Cowrie JSON log and records the elapsed time between
    each "session.connect" from the bot VM after each wipe cycle.
    You run this interactively: wipe → reboot → scan → record → repeat.

Graph 3 — IDS accuracy vs jitter (run on bot VM):
    python3 collect_graph23_data.py --graph3 --host 192.168.100.20

  What it does:
    Runs cred_stuffing.py at 8 jitter levels (0–1000ms) for 30s each,
    then queries the portal's /attempts endpoint and the IDS log to
    compute true/false positive rates at each jitter level.

    Requires:
      - fake_portal.py running on 192.168.100.20:80
      - ids_detector.py running on 192.168.100.20 (log at /tmp/ids.log)
      - cred_stuffing.py in the same directory
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path


# ── Paths ──────────────────────────────────────────────────────
DATA_DIR     = os.path.dirname(os.path.abspath(__file__))
GRAPH2_OUT   = os.path.join(DATA_DIR, "graph2_measured_data.json")
GRAPH3_OUT   = os.path.join(DATA_DIR, "graph3_measured_data.json")

COWRIE_LOG   = Path.home() / "cowrie/var/log/cowrie/cowrie.json"
IDS_LOG      = Path("/tmp/ids.log")


# ══════════════════════════════════════════════════════════════
#  GRAPH 2: PERSISTENCE PARADOX
# ══════════════════════════════════════════════════════════════

def collect_graph2(n_wipes: int = 8, bot_ip: str = "192.168.100.11"):
    """
    Interactive data collector for Graph 2.

    Procedure (repeat n_wipes times):
      1. Wipe and reboot the victim VM.
      2. When the victim comes back up, type ENTER here.
      3. The script records the time. When a new Cowrie connection
         arrives from bot_ip, it records MTBI and prompts for the
         next wipe.

    If Cowrie is not running, you can enter the MTBI manually.
    """
    print("=" * 60)
    print(" Graph 2 Data Collection — Persistence Paradox")
    print(f" Monitoring Cowrie log: {COWRIE_LOG}")
    print(f" Bot VM IP: {bot_ip}")
    print("=" * 60)
    print()
    print("Protocol:")
    print("  1. Ensure Cowrie is running on this (victim) VM.")
    print("  2. Run ./mirai_scanner from the bot VM.")
    print("  3. After Cowrie logs a connection, type ENTER here.")
    print("  4. Wipe and reboot the victim VM, then type ENTER again.")
    print("  Repeat for each of the", n_wipes, "wipes.\n")

    wipes          = []
    mtbi_minutes   = []

    for wipe_num in range(1, n_wipes + 1):
        print(f"─── Wipe #{wipe_num} ───────────────────────────────────────")

        # Wait for user to wipe and reboot
        input(f"  Victim VM wiped and rebooted. Press ENTER when it is back up...")
        reboot_time = time.time()
        print(f"  Reboot time recorded: {datetime.now().strftime('%H:%M:%S')}")

        # Now wait for a Cowrie connection from bot_ip
        print(f"  Waiting for Mirai scanner to reconnect from {bot_ip}...")
        infection_time = _wait_for_cowrie_connect(bot_ip, reboot_time, timeout=600)

        if infection_time is not None:
            mtbi = (infection_time - reboot_time) / 60.0
            print(f"  ✅  Re-infection detected in {mtbi:.2f} minutes!")
        else:
            # Manual entry fallback
            print(f"  Could not detect automatically (Cowrie not running or log not found).")
            raw = input(f"  Enter MTBI for wipe #{wipe_num} (minutes, e.g. 2.5): ").strip()
            try:
                mtbi = float(raw)
            except ValueError:
                print("  Invalid input — using 0.0")
                mtbi = 0.0

        wipes.append(wipe_num)
        mtbi_minutes.append(round(mtbi, 2))
        print(f"  MTBI recorded: {mtbi:.2f} min\n")

    # Hardened test (optional — just asks the user)
    print("─── Hardened Credentials Test ─────────────────────────")
    print("  Change the victim VM's SSH password to something strong.")
    print("  Then run ./mirai_scanner again from the bot VM.")
    hardened_raw = input("  Was the hardened VM re-infected? [y/N]: ").strip().lower()
    hardened_reinfected = hardened_raw == "y"
    hardened_mtbi_note  = "re-infected" if hardened_reinfected else "never re-infected"
    print(f"  Hardened result: {hardened_mtbi_note}")

    # Save
    output = {
        "collection_time":      datetime.now().isoformat(),
        "bot_ip":               bot_ip,
        "n_wipes":              n_wipes,
        "wipes":                wipes,
        "mtbi_default_minutes": mtbi_minutes,
        "hardened_reinfected":  hardened_reinfected,
        "avg_mtbi_minutes":     round(sum(mtbi_minutes) / len(mtbi_minutes), 2),
        "notes": (
            f"Measured {n_wipes} wipe cycles. "
            f"Hardened result: {hardened_mtbi_note}. "
            f"Avg MTBI (default creds): {sum(mtbi_minutes)/len(mtbi_minutes):.2f} min."
        )
    }
    with open(GRAPH2_OUT, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n✅  Graph 2 data saved to {GRAPH2_OUT}")
    print(f"    Average MTBI (default creds): {output['avg_mtbi_minutes']:.2f} minutes")
    print(f"    Run python3 generate_graphs.py to regenerate the graph.\n")
    return output


def _wait_for_cowrie_connect(bot_ip: str, after_ts: float, timeout: int = 600) -> float | None:
    """
    Poll Cowrie's JSON log until a session.connect event from bot_ip
    appears with a timestamp after `after_ts`. Returns the event time
    or None on timeout.
    """
    if not COWRIE_LOG.exists():
        return None

    deadline = time.time() + timeout
    seen_lines = set()

    while time.time() < deadline:
        try:
            with open(COWRIE_LOG) as f:
                for line in f:
                    line = line.strip()
                    if not line or line in seen_lines:
                        continue
                    seen_lines.add(line)
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if ev.get("eventid") != "cowrie.session.connect":
                        continue
                    if ev.get("src_ip") != bot_ip:
                        continue
                    # Parse ISO timestamp
                    try:
                        from datetime import datetime as _dt
                        import calendar
                        ts_str = ev.get("timestamp", "")
                        dt = _dt.fromisoformat(ts_str.replace("Z", "+00:00"))
                        ev_ts = calendar.timegm(dt.timetuple())
                        if ev_ts > after_ts:
                            return float(ev_ts)
                    except Exception:
                        # If timestamp parsing fails, use now as approximation
                        return time.time()
        except Exception:
            pass
        time.sleep(5)

    return None


# ══════════════════════════════════════════════════════════════
#  GRAPH 3: IDS ACCURACY vs. JITTER
# ══════════════════════════════════════════════════════════════

JITTER_LEVELS_MS = [0, 50, 100, 200, 350, 500, 750, 1000]
RUN_DURATION_SEC = 30    # seconds per jitter level
N_REQUESTS       = 25    # credential attempts per run


def collect_graph3(victim_host: str = "192.168.100.20", victim_port: int = 80,
                   ids_log: str = str(IDS_LOG)):
    """
    Automated jitter sweep for Graph 3.

    For each jitter level:
      1. Clear the portal's attempt log baseline.
      2. Run cred_stuffing.py in jitter mode for RUN_DURATION_SEC.
      3. Check whether IDS fired a 'CREDENTIAL STUFFING' alert.
      4. Run the human baseline to check FPR.
      5. Record TPR/FPR.
    """
    print("=" * 60)
    print(" Graph 3 Data Collection — IDS Accuracy vs. Jitter")
    print(f" Target portal: {victim_host}:{victim_port}")
    print(f" IDS log: {ids_log}")
    print(f" Jitter levels (ms std dev): {JITTER_LEVELS_MS}")
    print(f" Run duration per level: {RUN_DURATION_SEC}s")
    print("=" * 60)
    print()

    # Verify portal is reachable
    if not _portal_reachable(victim_host, victim_port):
        print(f"ERROR: Cannot reach portal at {victim_host}:{victim_port}")
        print("Make sure fake_portal.py is running on the victim VM.")
        sys.exit(1)

    tpr_results  = []
    fpr_results  = []
    run_details  = []

    for jitter_ms in JITTER_LEVELS_MS:
        print(f"\n─── Jitter = {jitter_ms}ms ─────────────────────────────")

        # ── BOT RUN (TPR measurement) ──────────────────────────
        ids_alert_count_before = _count_ids_alerts(ids_log)
        _reset_portal_attempts(victim_host, victim_port)

        print(f"  Running bot (jitter={jitter_ms}ms, {RUN_DURATION_SEC}s)...")
        _run_cred_stuffing(
            host=victim_host, port=victim_port,
            mode="jitter", jitter_ms=jitter_ms,
            duration=RUN_DURATION_SEC
        )

        # Give IDS 5s to process the traffic and fire alert
        time.sleep(5)
        ids_alert_count_after = _count_ids_alerts(ids_log)
        bot_detected = ids_alert_count_after > ids_alert_count_before
        tpr = 100.0 if bot_detected else 0.0
        tpr_results.append(tpr)

        # ── HUMAN BASELINE RUN (FPR measurement) ────────────────
        ids_before_human = _count_ids_alerts(ids_log)
        _reset_portal_attempts(victim_host, victim_port)

        print(f"  Running human baseline (random delays, {RUN_DURATION_SEC}s)...")
        _run_cred_stuffing(
            host=victim_host, port=victim_port,
            mode="human",
            duration=RUN_DURATION_SEC
        )
        time.sleep(5)
        ids_after_human = _count_ids_alerts(ids_log)
        human_flagged = ids_after_human > ids_before_human
        fpr = 100.0 if human_flagged else 0.0
        fpr_results.append(fpr)

        detail = {
            "jitter_ms":      jitter_ms,
            "bot_detected":   bot_detected,
            "human_flagged":  human_flagged,
            "tpr":            tpr,
            "fpr":            fpr,
        }
        run_details.append(detail)
        print(f"  TPR={tpr:.0f}%  FPR={fpr:.0f}%  "
              f"(bot {'✅ detected' if bot_detected else '❌ missed'}  |  "
              f"human {'⚠️  flagged' if human_flagged else '✅ clear'})")

    # ── Smooth results (single-run binary is noisy; average over multiple
    #    runs ideally, but here we accept the binary result and note it)
    print("\n" + "─" * 60)
    print("NOTE: For more accurate results, re-run this script multiple times")
    print("and average the TPR/FPR across runs. Single-run binary results")
    print("are noisy — especially at intermediate jitter levels.")
    print("─" * 60)

    output = {
        "collection_time":   datetime.now().isoformat(),
        "victim_host":       victim_host,
        "run_duration_sec":  RUN_DURATION_SEC,
        "jitter_levels_ms":  JITTER_LEVELS_MS,
        "tpr_percent":       tpr_results,
        "fpr_percent":       fpr_results,
        "run_details":       run_details,
        "notes": (
            "Binary TPR/FPR per jitter level. "
            "Re-run multiple times and average for smoother curves. "
            f"Evasion threshold observed near "
            f"{_find_evasion_threshold(JITTER_LEVELS_MS, tpr_results)}ms jitter."
        )
    }
    with open(GRAPH3_OUT, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n✅  Graph 3 data saved to {GRAPH3_OUT}")
    _print_graph3_summary(JITTER_LEVELS_MS, tpr_results, fpr_results)
    print(f"    Run python3 generate_graphs.py to regenerate the graph.\n")
    return output


def _find_evasion_threshold(jitters: list, tpr: list) -> int:
    """Find the jitter level where TPR first drops below 50%."""
    for j, t in zip(jitters, tpr):
        if t < 50:
            return j
    return jitters[-1]


def _print_graph3_summary(jitters, tpr, fpr):
    print("\n  Jitter (ms) | TPR (%) | FPR (%)")
    print("  " + "-" * 32)
    for j, t, f in zip(jitters, tpr, fpr):
        bar_t = "█" * int(t / 5)
        print(f"  {j:>10}ms | {t:>6.0f}% | {f:>6.0f}%  {bar_t}")


def _portal_reachable(host: str, port: int) -> bool:
    try:
        url = f"http://{host}:{port}/"
        urllib.request.urlopen(url, timeout=3)
        return True
    except Exception:
        return False


def _reset_portal_attempts(host: str, port: int):
    """
    Reset the portal's in-memory attempt log via POST /attempts/reset.
    Also clears the tarpit state so flagged IPs from a previous run
    don't carry over and distort the next jitter level's measurement.

    Requires fake_portal.py to be running with the /attempts/reset endpoint.
    """
    try:
        url = f"http://{host}:{port}/attempts/reset"
        data = json.dumps({"clear_tarpit": True}).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read().decode())
            if result.get("status") == "reset":
                return   # success, no output needed
    except Exception as e:
        print(f"  WARNING: could not reset portal attempts: {e}")


def _count_ids_alerts(log_path: str) -> int:
    """Count 'ALERT' lines in the IDS log."""
    try:
        with open(log_path) as f:
            return sum(1 for line in f if "CREDENTIAL STUFFING" in line)
    except FileNotFoundError:
        return 0


def _run_cred_stuffing(host: str, port: int, mode: str,
                       jitter_ms: int = 0, duration: int = 30):
    """
    Launch cred_stuffing.py as a subprocess for `duration` seconds, then kill it.
    """
    script = os.path.join(DATA_DIR, "cred_stuffing.py")
    if not os.path.exists(script):
        print(f"  WARNING: {script} not found — skipping run")
        return

    cmd = [
        sys.executable, script,
        "--mode", mode,
        "--host", host,
        "--port", str(port),
        "--interval", "500",
        "--jitter",   str(jitter_ms),
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(duration)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception as e:
        print(f"  WARNING: cred_stuffing run failed: {e}")


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Collect real measurement data for Graphs 2 and 3"
    )
    parser.add_argument("--graph2", action="store_true",
                        help="Collect Graph 2 data (persistence paradox, victim VM)")
    parser.add_argument("--graph3", action="store_true",
                        help="Collect Graph 3 data (IDS jitter sweep, bot VM)")
    parser.add_argument("--host",   default="192.168.100.20",
                        help="Victim VM IP (for Graph 3, default: 192.168.100.20)")
    parser.add_argument("--bot-ip", default="192.168.100.11",
                        help="Bot VM IP (for Graph 2 Cowrie detection, default: 192.168.100.11)")
    parser.add_argument("--wipes",  type=int, default=8,
                        help="Number of wipe cycles for Graph 2 (default: 8)")
    parser.add_argument("--ids-log", default=str(IDS_LOG),
                        help=f"Path to IDS log (default: {IDS_LOG})")
    args = parser.parse_args()

    if not args.graph2 and not args.graph3:
        parser.print_help()
        print("\nExamples:")
        print("  # On victim VM, after each Mirai scanner run:")
        print("  python3 collect_graph23_data.py --graph2")
        print()
        print("  # On bot VM, while portal + IDS are running on victim VM:")
        print("  python3 collect_graph23_data.py --graph3 --host 192.168.100.20")
        sys.exit(0)

    if args.graph2:
        collect_graph2(n_wipes=args.wipes, bot_ip=args.bot_ip)

    if args.graph3:
        collect_graph3(victim_host=args.host, ids_log=args.ids_log)