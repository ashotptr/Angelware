"""
====================================================
 ids_detector_patch_e14.py
 Patch instructions for ids_detector.py — Engine 14

 Gap identified: BreachIntelDetector is fully implemented in
 breach_dump_enricher.py and documented as "IDS Engine 14", but
 ids_detector.py never imports or calls it. This file provides:

   1. The exact str_replace patches to apply to ids_detector.py
   2. A self-contained patch() function that monkey-patches the
      running ids_detector module at import time (use this if you
      cannot edit the original file).

 HOW TO APPLY (preferred — edit ids_detector.py directly):

   Patch A — add after the Engine 13 import block (~line 12808):
   ─────────────────────────────────────────────────────────────
   # Engine 14 -- Breach Dump Intel Detector
   try:
       from breach_dump_enricher import BreachIntelDetector as _BreachDet
       _breach_detector = _BreachDet()
       BREACH_INTEL_OK  = True
       print("[IDS] Breach Intel Detector: ENABLED (Engine 14)")
   except ImportError:
       BREACH_INTEL_OK  = False
       _breach_detector = None
       print("[IDS] INFO: breach_dump_enricher.py not found -- Engine 14 disabled")

   Patch B — add inside engine5_loop(), after the username clustering
   block (e) and before _engine8_update(stats, now) (~line 13302):
   ─────────────────────────────────────────────────────────────
   # f) Breach Intel detection (Engine 14)
   if BREACH_INTEL_OK and _breach_detector and total >= MIN_ATTEMPTS_FOR_RATE:
       _engine14_update(stats, now)

   Patch C — add the _engine14_update() helper function before
   engine5_loop() (~line 13212):
   ─────────────────────────────────────────────────────────────
   (copy the function below)

 HOW TO APPLY (alternative — import this module from ids_detector.py):
   Add at the bottom of ids_detector.py:
       try:
           import ids_detector_patch_e14 as _e14_patch
           _e14_patch.apply(globals())
       except ImportError:
           pass
====================================================
"""

import time
from typing import Optional


# ══════════════════════════════════════════════════════════════
#  ENGINE 14: BREACH INTEL DETECTOR
#  (paste this function into ids_detector.py before engine5_loop)
# ══════════════════════════════════════════════════════════════

_E14_ALERT_COOLDOWN = 120.0   # seconds between repeated E14 alerts
_e14_last_alert: dict = {
    "domain_concentration": 0.0,
    "temporal_clustering":  0.0,
    "pattern_match":        0.0,
}


def _engine14_update(stats: dict, now: float,
                     breach_detector, alert_fn) -> None:
    """
    Engine 14: Breach Dump Intel Detector.

    Polls /stats/advanced signals and feeds them into
    BreachIntelDetector.detect() to identify when the attacker
    is using an enriched breach dump:

    Signal 1 — Domain concentration (IDS taxonomy):
      If the top email domain in the attempt stream accounts for
      ≥ DOMAIN_CONC_THRESH% of all attempts, the attacker likely
      sourced their list from a single breached service.
      (Note: Engine 10/username_clustering also detects this via
       per-request tracking; Engine 14 detects it at the portal-
       stats polling interval — complementary, not redundant.)

    Signal 2 — Temporal clustering (enriched-dump ordering):
      Professional attackers sort enriched dumps by freshness
      (recent breaches first). This produces a temporal burst:
      many attempts in a short window, then silence.
      Engine 14 flags unusually high attempt density per minute.

    Signal 3 — Pattern matching (breach characteristics):
      BreachIntelDetector checks whether the attempt stream
      matches known breach password patterns (e.g. LinkedIn-
      style "FirstName2021", Adobe MD5 hashes reused as plaintext).
    """
    global _e14_last_alert

    if not breach_detector:
        return

    total    = stats.get("total_attempts", 0)
    ua_pct   = stats.get("unknown_acct_pct", 0.0)
    br_cnt   = stats.get("breached_cred_hits", 0)
    per_ip   = stats.get("per_ip_unknowns", {})
    hourly   = stats.get("hourly_distribution", {})

    # Call BreachIntelDetector.detect()
    try:
        result = breach_detector.detect(
            total_attempts    = total,
            unknown_acct_pct  = ua_pct,
            breached_cred_hits= br_cnt,
            per_ip_unknowns   = per_ip,
            hourly_dist       = hourly,
        )
    except Exception as e:
        print(f"[IDS-E14] BreachIntelDetector.detect() error: {e}")
        return

    if not result:
        return

    # Fire alerts for each detected signal
    for signal in result.get("signals", []):
        sig_type = signal.get("type", "unknown")
        cooldown_key = sig_type if sig_type in _e14_last_alert else "domain_concentration"

        if now - _e14_last_alert.get(cooldown_key, 0) < _E14_ALERT_COOLDOWN:
            continue

        _e14_last_alert[cooldown_key] = now

        alert_fn(
            "BreachIntel/Engine14", signal.get("severity", "MED"),
            f"ENRICHED BREACH DUMP DETECTED — {signal.get('description', sig_type)}\n"
            f"  Signal type:     {sig_type}\n"
            f"  Evidence:        {signal.get('evidence', '')}\n"
            f"  Implication:     Attacker is using a curated, prioritised credential\n"
            f"                   list — not a raw dump. Hit rate will be higher than\n"
            f"                   Engine 5's unknown-account spike suggests.\n"
            f"  Total attempts:  {total}\n"
            f"  Unknown-acct %:  {ua_pct:.1f}%\n"
            f"  Breached-pwd hits: {br_cnt}\n"
            f"  MITRE: T1589.002 (Gather Victim Identity Information: Email Addresses)"
        )


# ══════════════════════════════════════════════════════════════
#  MONKEY-PATCH ENTRY POINT
#  Called with ids_detector's globals() dict.
# ══════════════════════════════════════════════════════════════

def apply(ids_globals: dict) -> None:
    """
    Inject Engine 14 into a running ids_detector module.

    Adds:
      - BREACH_INTEL_OK / _breach_detector to module globals
      - _engine14_update() as a module-level function
      - Hooks into engine5_loop via _orig_engine5_loop wrapper
    """
    # Step 1: import BreachIntelDetector
    try:
        from breach_dump_enricher import BreachIntelDetector as _BD
        _bd = _BD()
        ids_globals["BREACH_INTEL_OK"]  = True
        ids_globals["_breach_detector"] = _bd
        print("[IDS] Engine 14 patch applied: Breach Intel Detector ENABLED")
    except ImportError:
        ids_globals["BREACH_INTEL_OK"]  = False
        ids_globals["_breach_detector"] = None
        print("[IDS] Engine 14 patch: breach_dump_enricher.py not found — disabled")
        return

    # Step 2: inject the helper function
    _alert_fn = ids_globals.get("alert")

    def _e14_hook(stats: dict, now: float):
        _engine14_update(
            stats,
            now,
            ids_globals.get("_breach_detector"),
            _alert_fn,
        )

    ids_globals["_engine14_update"] = _e14_hook

    # Step 3: wrap engine5_loop to call _e14_hook
    _orig = ids_globals.get("engine5_loop")

    def _patched_engine5_loop():
        """engine5_loop wrapped with Engine 14 call."""
        import urllib.request
        import json

        portal_host = ids_globals.get("PORTAL_HOST", "127.0.0.1")
        portal_port = ids_globals.get("PORTAL_PORT", 8080)
        poll_sec    = ids_globals.get("ENGINE5_POLL_SEC", 30)
        min_att     = ids_globals.get("MIN_ATTEMPTS_FOR_RATE", 20)

        print(f"[IDS-E5+E14] Patched engine5_loop started — polling every {poll_sec}s")

        import threading
        # Run original E5 in its own thread
        t = threading.Thread(target=_orig, daemon=True)
        t.start()

        # Separately poll for E14
        while True:
            time.sleep(poll_sec)
            try:
                url  = f"http://{portal_host}:{portal_port}/stats/advanced"
                with urllib.request.urlopen(url, timeout=5) as resp:
                    stats = json.loads(resp.read().decode())
                total = stats.get("total_attempts", 0)
                if total >= min_att:
                    _e14_hook(stats, time.time())
            except Exception:
                pass

    ids_globals["engine5_loop"] = _patched_engine5_loop
    print("[IDS] Engine 14 patch: engine5_loop wrapped — E14 will fire alongside E5")


# ══════════════════════════════════════════════════════════════
#  DIRECT PATCH STRINGS FOR MANUAL APPLICATION
#  Copy-paste these into ids_detector.py at the marked locations.
# ══════════════════════════════════════════════════════════════

PATCH_A_IMPORT = """\
# Engine 14 -- Breach Dump Intel Detector (BreachIntelDetector)
# Source: breach_dump_enricher.py (fully implemented, Engine 14 taxonomy)
# Gap closed by ids_detector_patch_e14.py
try:
    from breach_dump_enricher import BreachIntelDetector as _BreachDet
    _breach_detector = _BreachDet()
    BREACH_INTEL_OK  = True
    print("[IDS] Breach Dump Intel Detector: ENABLED (Engine 14)")
except ImportError:
    BREACH_INTEL_OK  = False
    _breach_detector = None
    print("[IDS] INFO: breach_dump_enricher.py not found -- Engine 14 disabled")
"""

PATCH_B_CALL = """\
        # f) Breach Intel detection (Engine 14) -- closes Engine 14 gap
        if BREACH_INTEL_OK and _breach_detector and total >= MIN_ATTEMPTS_FOR_RATE:
            _engine14_update(stats, now)
"""

if __name__ == "__main__":
    print("Engine 14 patch — three locations to apply in ids_detector.py:\n")
    print("── PATCH A (after Engine 13 import block, ~line 12808) ──")
    print(PATCH_A_IMPORT)
    print("── PATCH B (inside engine5_loop, before _engine8_update call) ──")
    print(PATCH_B_CALL)
    print("── PATCH C (paste _engine14_update() function before engine5_loop) ──")
    print("  (copy the _engine14_update function from this file)\n")
    print("Or add to the bottom of ids_detector.py for auto-patch:")
    print("  import ids_detector_patch_e14 as _e14")
    print("  _e14.apply(globals())")
