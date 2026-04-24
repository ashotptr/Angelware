"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: IDS Multi-Engine Alert Correlator
 Environment: ISOLATED VM LAB ONLY
====================================================

Reads /tmp/ids.log (and optionally /tmp/ids_flow_alerts.json)
and applies four correlation rules:

  Rule 1 — Duplicate Suppression
    Same engine + same severity within 30 s → one alert.

  Rule 2 — Multi-Engine Correlation (INCIDENT)
    ≥ 3 distinct engines fire against the same source IP
    within a 60 s window → escalate to INCIDENT.

  Rule 3 — Kill-Chain Reconstruction
    MITRE ATT&CK stage ordering: detect when alerts progress
    through Reconnaissance → Initial Access → Execution →
    Persistence → Lateral Movement → Exfiltration.
    Any 3 consecutive stages from one source in 120 s →
    KILL_CHAIN alert.

  Rule 4 — Quiescence Detection
    If a high-vol source suddenly goes silent for ≥ 90 s
    after ≥ 5 HIGH alerts, emit EVASION_SUSPECTED.

Output:
  /tmp/correlated_alerts.json    — deduplicated + correlated events
  /tmp/attack_timeline.json      — per-source timeline for graphs
  /tmp/ir_summary.md             — human-readable IR summary

Usage:
  python3 ids_alert_correlator.py               # watch live log
  python3 ids_alert_correlator.py --once        # single pass + exit
  python3 ids_alert_correlator.py --log PATH    # custom log file
  python3 ids_alert_correlator.py --report      # print summary table
  python3 ids_alert_correlator.py --timeline    # print attack timeline
"""

import argparse
import json
import os
import re
import sys
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

# ── ATT&CK stage mapping per engine ───────────────────────────
ENGINE_STAGE = {
    "E11":   "Reconnaissance",       # RST/SYN scanner
    "mirai": "Reconnaissance",
    "E1":    "Initial Access",        # volumetric DDoS
    "E4":    "Initial Access",        # covert channel contact
    "E3":    "Initial Access",        # DGA C2 lookup
    "E7":    "Initial Access",        # TLS JA3 bot fingerprint
    "E2":    "Execution",             # credential stuffing
    "E5":    "Execution",             # login analytics
    "E6":    "Execution",             # cross-IP fingerprint
    "E9":    "Execution",             # browser automation
    "E12":   "Persistence",           # procwatch
    "E18":   "Persistence",           # FIM / persistence
    "E17":   "Discovery",             # system enumeration
    "E20":   "Lateral Movement",      # lateral movement
    "E19":   "Exfiltration",          # file transfer
    "E21":   "Exfiltration",          # polymorphic payload
    "E22":   "Impact",                # endpoint behavioral
    "E8":    "Discovery",             # adaptive ML catch-all
    "E10":   "Execution",             # username clustering
}

KILL_CHAIN_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Discovery",
    "Lateral Movement",
    "Exfiltration",
    "Impact",
]

# ── Regex to parse IDS log lines ──────────────────────────────
_ALERT_RE = re.compile(
    r"ALERT\s+#?(?P<num>\d+)\s+\[?(?P<sev>HIGH|MEDIUM|LOW)\]?\s+"
    r"Engine:\s*(?P<eng>[^\s]+)\s+@\s+(?P<ts>[^\s]+)\s+--\s*(?P<msg>.*)",
    re.IGNORECASE
)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# ─────────────────────────────────────────────────────────────
# Parsed alert
# ─────────────────────────────────────────────────────────────

def parse_line(line: str) -> dict | None:
    m = _ALERT_RE.search(line)
    if not m:
        return None
    sev = m.group("sev").upper()
    eng = m.group("eng")
    msg = m.group("msg").strip()
    ts_str = m.group("ts")
    try:
        ts = datetime.fromisoformat(ts_str).timestamp()
    except Exception:
        ts = time.time()

    # Extract source IP from message
    ips  = _IP_RE.findall(msg)
    src  = ips[0] if ips else "unknown"

    # Normalise engine ID to E-notation
    if not eng.startswith("E"):
        eng = "E" + eng

    stage = ENGINE_STAGE.get(eng, "Unknown")

    return {
        "alert_num": int(m.group("num")),
        "sev":       sev,
        "engine":    eng,
        "ts":        ts,
        "ts_str":    datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
        "msg":       msg,
        "src_ip":    src,
        "stage":     stage,
    }


# ─────────────────────────────────────────────────────────────
# Correlator
# ─────────────────────────────────────────────────────────────

class AlertCorrelator:
    DEDUP_WINDOW   = 30    # seconds — same engine + sev → suppress
    MULTI_WINDOW   = 60    # seconds — multi-engine per source
    MULTI_THRESH   = 3     # distinct engines to trigger INCIDENT
    KILL_CHAIN_WIN = 120   # seconds — kill-chain reconstruction window
    KILL_STAGES    = 3     # consecutive ATT&CK stages
    QUIESCE_WIN    = 90    # seconds — silence after storm
    QUIESCE_MIN    = 5     # HIGH alerts needed before quiescence matters

    def __init__(self):
        self._raw:    list[dict]                     = []   # all parsed alerts
        self._dedup:  dict[tuple, float]             = {}   # (eng, sev) → last_ts
        self._corr:   list[dict]                     = []   # output: correlated events
        self._src_q:  dict[str, deque]               = defaultdict(lambda: deque(maxlen=100))
        self._src_hi: dict[str, list[float]]         = defaultdict(list)
        self._timeline: dict[str, list[dict]]        = defaultdict(list)

        self.stats = {
            "raw_alerts":       0,
            "suppressed":       0,
            "passed":           0,
            "incidents":        0,
            "kill_chains":      0,
            "evasion_suspicions": 0,
        }

    # ── Rule 1: Duplicate suppression ─────────────────────────
    def _dedup_check(self, a: dict) -> bool:
        key    = (a["engine"], a["sev"])
        last   = self._dedup.get(key, 0)
        if a["ts"] - last < self.DEDUP_WINDOW:
            self.stats["suppressed"] += 1
            return False   # suppress
        self._dedup[key] = a["ts"]
        return True

    # ── Rule 2: Multi-engine correlation ──────────────────────
    def _multi_engine_check(self, src: str, now: float) -> dict | None:
        q      = self._src_q[src]
        cutoff = now - self.MULTI_WINDOW
        recent = [e for e in q if e >= cutoff]
        # Count distinct engines
        engines_seen = set()
        for entry in self._raw:
            if entry["src_ip"] == src and entry["ts"] >= cutoff:
                engines_seen.add(entry["engine"])
        if len(engines_seen) >= self.MULTI_THRESH:
            return {
                "type":    "INCIDENT",
                "sev":     "CRITICAL",
                "src_ip":  src,
                "ts":      now,
                "ts_str":  datetime.fromtimestamp(now).strftime("%H:%M:%S"),
                "engines": sorted(engines_seen),
                "msg":     f"Multi-engine correlation: {len(engines_seen)} engines fired on {src} within {self.MULTI_WINDOW}s",
            }
        return None

    # ── Rule 3: Kill-chain reconstruction ─────────────────────
    def _kill_chain_check(self, src: str, now: float) -> dict | None:
        cutoff = now - self.KILL_CHAIN_WIN
        src_alerts = [a for a in self._raw
                      if a["src_ip"] == src and a["ts"] >= cutoff and a["stage"] != "Unknown"]
        if len(src_alerts) < 2:
            return None

        stages_seen = []
        for a in sorted(src_alerts, key=lambda x: x["ts"]):
            stage = a["stage"]
            if not stages_seen or stages_seen[-1] != stage:
                stages_seen.append(stage)

        # Find longest ordered sub-sequence aligned with KILL_CHAIN_ORDER
        def _lcs_ordered():
            idx = 0
            matched = []
            for stage in KILL_CHAIN_ORDER:
                while idx < len(stages_seen) and stages_seen[idx] != stage:
                    idx += 1
                if idx < len(stages_seen):
                    matched.append(stage)
                    idx += 1
            return matched

        matched = _lcs_ordered()
        if len(matched) >= self.KILL_STAGES:
            return {
                "type":   "KILL_CHAIN",
                "sev":    "CRITICAL",
                "src_ip": src,
                "ts":     now,
                "ts_str": datetime.fromtimestamp(now).strftime("%H:%M:%S"),
                "stages": matched,
                "msg":    f"Kill-chain: {' → '.join(matched)} from {src}",
            }
        return None

    # ── Rule 4: Quiescence detection ──────────────────────────
    def _quiescence_check(self, src: str, now: float) -> dict | None:
        hi_times = self._src_hi[src]
        if len(hi_times) < self.QUIESCE_MIN:
            return None
        last_hi = max(hi_times)
        gap     = now - last_hi
        if self.QUIESCE_WIN <= gap <= self.QUIESCE_WIN * 3:
            return {
                "type":   "EVASION_SUSPECTED",
                "sev":    "HIGH",
                "src_ip": src,
                "ts":     now,
                "ts_str": datetime.fromtimestamp(now).strftime("%H:%M:%S"),
                "gap_s":  round(gap),
                "msg":    f"Source {src} went silent after {len(hi_times)} HIGH alerts ({gap:.0f}s quiet period)",
            }
        return None

    # ── Main ingest ────────────────────────────────────────────
    def ingest(self, a: dict):
        self.stats["raw_alerts"] += 1
        self._raw.append(a)

        if not self._dedup_check(a):
            return

        self.stats["passed"] += 1
        src = a["src_ip"]
        now = a["ts"]

        # Update source queues
        self._src_q[src].append(now)
        if a["sev"] == "HIGH":
            self._src_hi[src].append(now)

        # Emit the base alert
        self._corr.append({**a, "type": "ALERT"})

        # Update timeline
        self._timeline[src].append({
            "ts": a["ts_str"], "engine": a["engine"],
            "sev": a["sev"], "stage": a["stage"], "msg": a["msg"][:60],
        })

        # Rule 2
        inc = self._multi_engine_check(src, now)
        if inc:
            already = any(
                e.get("type") == "INCIDENT" and e.get("src_ip") == src
                and abs(e.get("ts", 0) - now) < self.MULTI_WINDOW
                for e in self._corr
            )
            if not already:
                self._corr.append(inc)
                self.stats["incidents"] += 1
                print(f"[CORRELATOR] ⚡ INCIDENT: {inc['msg']}")

        # Rule 3
        kc = self._kill_chain_check(src, now)
        if kc:
            already = any(
                e.get("type") == "KILL_CHAIN" and e.get("src_ip") == src
                and abs(e.get("ts", 0) - now) < self.KILL_CHAIN_WIN
                for e in self._corr
            )
            if not already:
                self._corr.append(kc)
                self.stats["kill_chains"] += 1
                print(f"[CORRELATOR] 🔗 KILL CHAIN: {kc['msg']}")

        # Rule 4
        ev = self._quiescence_check(src, now)
        if ev:
            already = any(
                e.get("type") == "EVASION_SUSPECTED" and e.get("src_ip") == src
                for e in self._corr
            )
            if not already:
                self._corr.append(ev)
                self.stats["evasion_suspicions"] += 1
                print(f"[CORRELATOR] 🕵 EVASION: {ev['msg']}")

    def flush(self):
        """Write outputs to disk."""
        with open("/tmp/correlated_alerts.json", "w") as f:
            json.dump({
                "generated":  datetime.now().isoformat(),
                "stats":      self.stats,
                "events":     self._corr,
            }, f, indent=2)

        with open("/tmp/attack_timeline.json", "w") as f:
            json.dump({
                "generated": datetime.now().isoformat(),
                "sources":   dict(self._timeline),
            }, f, indent=2)

        self._write_ir_summary()

    def _write_ir_summary(self):
        lines = [
            "# Incident Response Summary",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"IDS Log:   {IDS_LOG}",
            "",
            "## Alert Statistics",
            f"  Raw alerts received:   {self.stats['raw_alerts']}",
            f"  After deduplication:   {self.stats['passed']}",
            f"  Suppressed (dupes):    {self.stats['suppressed']}",
            f"  INCIDENT escalations:  {self.stats['incidents']}",
            f"  Kill-chain detections: {self.stats['kill_chains']}",
            f"  Evasion suspicions:    {self.stats['evasion_suspicions']}",
            "",
            "## Attack Sources",
        ]
        for src, events in self._timeline.items():
            stages = list(dict.fromkeys(e["stage"] for e in events))
            lines.append(f"  {src}  ({len(events)} events)  Stages: {' → '.join(stages)}")

        lines += [
            "",
            "## High-Priority Events",
        ]
        for e in self._corr:
            if e.get("type") in ("INCIDENT", "KILL_CHAIN", "EVASION_SUSPECTED"):
                lines.append(f"  [{e['ts_str']}] {e['type']}: {e['msg']}")

        lines += [
            "",
            "## MITRE ATT&CK Stage Coverage",
        ]
        all_stages = set()
        for evts in self._timeline.values():
            for ev in evts:
                all_stages.add(ev["stage"])
        for stage in KILL_CHAIN_ORDER:
            mark = "✓" if stage in all_stages else "—"
            lines.append(f"  {mark}  {stage}")

        with open("/tmp/ir_summary.md", "w") as f:
            f.write("\n".join(lines) + "\n")

    def print_report(self):
        print("\n" + "=" * 60)
        print("  CORRELATOR REPORT")
        print("=" * 60)
        print(f"  Raw alerts:      {self.stats['raw_alerts']}")
        print(f"  After dedup:     {self.stats['passed']}")
        print(f"  INCIDENTs:       {self.stats['incidents']}")
        print(f"  Kill chains:     {self.stats['kill_chains']}")
        print(f"  Evasion alerts:  {self.stats['evasion_suspicions']}")
        print()
        if self._timeline:
            print("  Attack Sources:")
            for src, evts in self._timeline.items():
                stages = list(dict.fromkeys(e["stage"] for e in evts))
                print(f"    {src:<16} {len(evts):>3} events  {' → '.join(stages[:4])}")
        print("=" * 60)

    def print_timeline(self):
        print("\nATTACK TIMELINE")
        print("-" * 70)
        all_events = []
        for src, evts in self._timeline.items():
            for e in evts:
                all_events.append({**e, "src": src})
        for e in sorted(all_events, key=lambda x: x["ts"]):
            sev_tag = f"[{e['sev'][:3]}]"
            print(f"  {e['ts']}  {sev_tag:<5}  {e['engine']:<6}  "
                  f"{e['src']:<16}  {e['stage']:<20}  {e['msg'][:35]}")


# ─────────────────────────────────────────────────────────────
# Log reader loop
# ─────────────────────────────────────────────────────────────

IDS_LOG   = "/tmp/ids.log"
FLUSH_INT = 10   # seconds between disk flushes

def watch_loop(correlator: AlertCorrelator, once: bool):
    pos = 0
    last_flush = time.time()
    print(f"[CORRELATOR] Watching {IDS_LOG}  (once={once})")
    while True:
        if not os.path.exists(IDS_LOG):
            if once:
                break
            time.sleep(2)
            continue
        with open(IDS_LOG, "rb") as f:
            f.seek(pos)
            chunk = f.read(65536)
            pos   = f.tell()
        if chunk:
            for line in chunk.decode("utf-8", errors="replace").splitlines():
                parsed = parse_line(line)
                if parsed:
                    correlator.ingest(parsed)
        if time.time() - last_flush > FLUSH_INT:
            correlator.flush()
            last_flush = time.time()
        if once:
            break
        time.sleep(1)
    correlator.flush()


def main():
    ap = argparse.ArgumentParser(description="IDS Multi-Engine Alert Correlator")
    ap.add_argument("--once",     action="store_true", help="Single pass then exit")
    ap.add_argument("--report",   action="store_true", help="Print summary table")
    ap.add_argument("--timeline", action="store_true", help="Print attack timeline")
    ap.add_argument("--log",      default=IDS_LOG,     metavar="PATH")
    args = ap.parse_args()

    global IDS_LOG
    IDS_LOG = args.log

    corr = AlertCorrelator()
    watch_loop(corr, once=args.once or args.report or args.timeline)

    if args.report:
        corr.print_report()
    if args.timeline:
        corr.print_timeline()

    if not (args.report or args.timeline):
        print(f"[CORRELATOR] Outputs written:")
        print(f"  /tmp/correlated_alerts.json")
        print(f"  /tmp/attack_timeline.json")
        print(f"  /tmp/ir_summary.md")


if __name__ == "__main__":
    main()
