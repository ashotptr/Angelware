"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Supply Chain Pivot + Session Chaining Detection
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching point (Document 2):
  "Credential stuffing + supply chain attacks: Attackers compromise
   low-value accounts in integrated third-party tools to pivot into
   the primary environment."

  "Credential stuffing may be paired with phishing to complete
   MFA bypass or to socially engineer access elevation."

  "In cloud-native systems, the post-stuffing pivot is often
   API-based. Attackers call backend APIs directly using
   authenticated sessions, bypassing UI controls and audit trails."

This module covers:

Part 1 — SupplyChainPivotSimulator
  Simulates the attack chain:
    a) Attacker obtains low-privilege account (e.g. read-only
       analytics tool integrated via OAuth/SSO)
    b) Uses that trust relationship to probe the primary service
    c) Escalates by abusing service-to-service API tokens

Part 2 — SessionChainingDetector (IDS)
  Detects API calls that originate from:
    - Sessions created at an unusual hour
    - Sessions that immediately call admin/internal APIs
    - Sessions that escalate scope faster than any human workflow
    - Service accounts calling user-facing endpoints

Part 3 — LateralMovementAuditLog
  Structured audit trail for post-stuffing API calls.
  Demonstrates what defenders need to see to catch API-based
  post-compromise activity.
"""

import hashlib
import json
import os
import random
import time
import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional


# ══════════════════════════════════════════════════════════════
#  Part 1: SUPPLY CHAIN PIVOT SIMULATOR
# ══════════════════════════════════════════════════════════════

# Simulated service catalog for the lab environment
# Each service has an API endpoint, trust level, and what
# data/access it can provide to an authenticated caller.

SIMULATED_SERVICES = {
    "analytics":    {
        "name":        "Analytics Partner",
        "api_base":    "http://192.168.100.30/api",   # hypothetical
        "trust_level": "low",
        "provides":    ["read:events", "read:user_ids"],
        "exposes":     "User IDs, session event logs",
    },
    "support_desk": {
        "name":        "Support Desk Tool",
        "api_base":    "http://192.168.100.31/api",
        "trust_level": "medium",
        "provides":    ["read:tickets", "write:user_profile"],
        "exposes":     "User PII, password reset tokens",
    },
    "billing":      {
        "name":        "Billing System",
        "api_base":    "http://192.168.100.32/api",
        "trust_level": "high",
        "provides":    ["read:payment_methods", "write:charges"],
        "exposes":     "Payment card data, billing history",
    },
    "sso_provider": {
        "name":        "SSO / Identity Provider",
        "api_base":    "http://192.168.100.33/api",
        "trust_level": "critical",
        "provides":    ["read:all_users", "write:credentials"],
        "exposes":     "All user credentials, session tokens",
    },
}


class SupplyChainPivotSimulator:
    """
    Simulates an attacker who has compromised a low-privilege
    third-party integration account (e.g., the analytics tool's
    service account) and uses that foothold to escalate.

    This is NOT a real network attack — all API calls are
    simulated/logged locally. The teaching value is in the
    sequence of escalation steps and the detection signals each
    step produces.

    Attack chain modeled:
      Step 1: Attacker creds-stuffs analytics tool (low-value target)
      Step 2: Analytics tool has read:user_ids access to main service
      Step 3: Attacker uses service API token to enumerate real users
      Step 4: Attacker pivots: uses enumerated user list for targeted
              credential stuffing against the PRIMARY service
      Step 5: One hit → attacker accesses billing/PII via the
              compromised primary account

    Lateral movement stages detected by SessionChainingDetector.
    """

    def __init__(self, audit_log=None):
        self.audit_log = audit_log or LateralMovementAuditLog()
        self._session  = None

    def run_simulation(self, start_service: str = "analytics"):
        """
        Run the full pivot simulation with audit logging.
        """
        print(f"\n[PIVOT] {'='*55}")
        print(f"[PIVOT] Supply Chain Pivot Simulation")
        print(f"[PIVOT] Entry point: {SIMULATED_SERVICES[start_service]['name']}")
        print(f"[PIVOT] {'='*55}\n")

        # ── Step 1: Compromise low-value integration account ──
        self._step("Compromise entry-point service",
                   service=start_service,
                   action="credential_stuffing",
                   detail="Credential stuffing against analytics tool login",
                   result="Account compromised: analytics_svc@partner.lab")
        time.sleep(0.5)

        # ── Step 2: Abuse service API token ──────────────────
        svc = SIMULATED_SERVICES[start_service]
        self._step("Extract service API token",
                   service=start_service,
                   action="api_token_harvest",
                   detail=f"Scraped OAuth service token from {svc['api_base']}/config",
                   result=f"Service token grants: {svc['provides']}")
        time.sleep(0.3)

        # ── Step 3: Enumerate primary service users ───────────
        self._step("Enumerate primary service users",
                   service="primary",
                   action="api_enumeration",
                   detail=("Using analytics service token to call "
                           "primary service /api/users?source=analytics "
                           "(service-to-service trust)"),
                   result="Retrieved 1,247 user IDs and email addresses")
        time.sleep(0.3)

        # ── Step 4: Targeted credential stuffing ──────────────
        self._step("Targeted credential stuffing",
                   service="primary",
                   action="credential_stuffing",
                   detail=("Running breach dump against ONLY the 1,247 "
                           "confirmed users → hit rate 4.2% (vs 0.1% blind)"),
                   result="52 valid logins obtained")
        time.sleep(0.3)

        # ── Step 5: Escalate via billing ─────────────────────
        self._step("Access billing system via compromised account",
                   service="billing",
                   action="data_exfiltration",
                   detail=("Using valid session from Step 4, calling "
                           "/api/billing/payment-methods directly "
                           "(API call, no UI controls apply)"),
                   result="Payment card data for 52 accounts accessed")
        time.sleep(0.3)

        # ── Step 6: SSO escalation attempt ────────────────────
        self._step("Attempt SSO privilege escalation",
                   service="sso_provider",
                   action="privilege_escalation",
                   detail=("Attempting to register attacker device via "
                           "SSO provider API using compromised admin token "
                           "found in support_desk tool config"),
                   result="BLOCKED — SessionChainingDetector flagged anomalous "
                          "SSO API call pattern")

        self.audit_log.print_summary()
        self._print_detection_notes()

    def _step(self, name: str, service: str, action: str,
              detail: str, result: str):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[PIVOT] {ts} ── Step: {name}")
        print(f"[PIVOT]         Service: {service}")
        print(f"[PIVOT]         Action:  {action}")
        print(f"[PIVOT]         Detail:  {detail}")
        print(f"[PIVOT]         Result:  {result}\n")

        self.audit_log.record(
            actor="attacker@lab",
            service=service,
            action=action,
            detail=detail,
            result=result,
        )

    def _print_detection_notes(self):
        print(f"[PIVOT] {'='*55}")
        print(f"[PIVOT] Detection opportunities (where defenders can intercept):")
        print(f"")
        notes = [
            ("Step 1", "Engine 2/5: high failure rate on analytics tool "
                       "login endpoint"),
            ("Step 2", "Audit log: service account accessing /config "
                       "endpoint — unusual for analytics service"),
            ("Step 3", "SessionChaining: service token calling user "
                       "enumeration outside analytics workflow"),
            ("Step 4", "Engine 5: login surge, low success rate — but "
                       "targeted so success rate is HIGHER than blind stuffing"),
            ("Step 5", "API audit: billing API called from session created "
                       "at unusual hour; no prior billing page views"),
            ("Step 6", "TokenAbuse: SSO device registration from flagged IP"),
        ]
        for step, note in notes:
            print(f"[PIVOT]   {step}: {note}")
        print(f"[PIVOT] {'='*55}\n")


# ══════════════════════════════════════════════════════════════
#  Part 2: SESSION CHAINING DETECTOR
# ══════════════════════════════════════════════════════════════

class SessionChainingDetector:
    """
    Detects API call patterns that indicate post-stuffing
    automated abuse rather than normal user navigation.

    A real user visiting a billing page:
      GET /  →  GET /dashboard  →  GET /billing  →  POST /billing/update
    A stuffed account doing API-based fraud:
      POST /api/login  →  POST /api/billing/charge  (2 requests, 0.3s apart)

    Signals:
      1. Time-to-first-sensitive-API < HUMAN_MIN_SECONDS
         Humans browse; bots call APIs immediately after login.
      2. No UI page views before API call
         Browser users generate GET requests for HTML pages.
         Bots hit /api endpoints directly.
      3. Session active during off-hours
      4. Sensitive API call from service account token
         (service accounts should only call service-to-service APIs)
    """

    HUMAN_MIN_SECONDS    = 5.0     # minimum realistic time login→sensitive action
    SENSITIVE_PATTERNS   = [
        "/api/billing", "/api/payment", "/api/admin",
        "/api/user/delete", "/api/settings/email",
        "/api/settings/password", "/api/export",
        "/oauth/token", "/sso/",
    ]
    OFF_HOURS_START = 0    # midnight
    OFF_HOURS_END   = 6    # 6am

    def __init__(self):
        self._lock    = threading.Lock()
        # session_id → {created_at, last_seen, ui_views, api_calls, src_ip}
        self._sessions: dict = {}
        self._alerts = 0

    def on_login(self, session_id: str, src_ip: str,
                 is_service_account: bool = False):
        """Record a new login / session creation."""
        with self._lock:
            self._sessions[session_id] = {
                "created_at":         time.time(),
                "src_ip":             src_ip,
                "ui_views":           0,
                "api_calls":          [],
                "is_service_account": is_service_account,
                "alerts":             [],
            }

    def on_request(self, session_id: str, path: str,
                   method: str = "GET",
                   alert_cb=None) -> Optional[str]:
        """
        Record a request for this session and check for anomalies.
        Returns alert string if anomaly detected, else None.
        """
        now = time.time()
        with self._lock:
            sess = self._sessions.get(session_id)
            if not sess:
                return None

            is_ui = method == "GET" and not any(
                p in path for p in self.SENSITIVE_PATTERNS
            )
            is_sensitive = any(p in path for p in self.SENSITIVE_PATTERNS)

            if is_ui:
                sess["ui_views"] += 1
            if is_sensitive:
                sess["api_calls"].append((now, path, method))

            age         = now - sess["created_at"]
            hour        = datetime.now().hour
            ui_views    = sess["ui_views"]
            src_ip      = sess["src_ip"]
            is_svc_acct = sess["is_service_account"]

        alert = None

        if is_sensitive:
            # Signal 1: immediate API call after login
            if age < self.HUMAN_MIN_SECONDS:
                alert = (
                    f"SESSION CHAINING: Sensitive API call {path} "
                    f"only {age:.2f}s after login (src={src_ip})\n"
                    f"  Threshold: {self.HUMAN_MIN_SECONDS}s\n"
                    f"  No human browses this fast — automated post-stuffing abuse\n"
                    f"  MITRE: T1078 (Valid Accounts) + T1106 (Native API)"
                )

            # Signal 2: no UI page views (direct API access)
            elif ui_views == 0:
                alert = (
                    f"SESSION CHAINING: Direct API call to {path} "
                    f"with ZERO prior page views (src={src_ip})\n"
                    f"  Real users navigate the UI first; bots call APIs directly\n"
                    f"  Session age: {age:.1f}s  |  UI views: 0\n"
                    f"  MITRE: T1106 (Native API)"
                )

            # Signal 3: off-hours
            if self.OFF_HOURS_START <= hour < self.OFF_HOURS_END:
                detail = (alert or "") + (
                    f"\n  OFF-HOURS API CALL: {hour:02d}:xx — "
                    f"automated campaign active at night"
                )
                alert = detail

            # Signal 4: service account calling user-facing API
            if is_svc_acct and "/api/user" in path:
                alert = (
                    f"SERVICE ACCOUNT ABUSE: Service token calling "
                    f"user-facing endpoint {path}\n"
                    f"  Service accounts should only call service-to-service APIs\n"
                    f"  Indicates supply chain pivot using harvested service token\n"
                    f"  MITRE: T1078.004 (Cloud Accounts)"
                )

        if alert:
            self._alerts += 1
            if alert_cb:
                alert_cb("SessionChaining", "HIGH", alert)

        return alert

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "active_sessions": len(self._sessions),
                "total_alerts":    self._alerts,
            }


# ══════════════════════════════════════════════════════════════
#  Part 3: LATERAL MOVEMENT AUDIT LOG
# ══════════════════════════════════════════════════════════════

class LateralMovementAuditLog:
    """
    Structured audit trail for post-stuffing API-based activity.

    Teaching point (Document 2):
      "In cloud-native systems, the post-stuffing pivot is often
       API-based. Attackers call backend APIs directly using
       authenticated sessions, bypassing UI controls and audit trails."

    This class is the audit trail that CATCHES that bypass.
    Every API call that matters should run through this log.
    Exportable as JSON for SIEM integration.
    """

    def __init__(self):
        self._lock    = threading.Lock()
        self._entries = []

    def record(self, actor: str, service: str, action: str,
               detail: str, result: str, src_ip: str = "?"):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "actor":     actor,
            "src_ip":    src_ip,
            "service":   service,
            "action":    action,
            "detail":    detail,
            "result":    result,
        }
        with self._lock:
            self._entries.append(entry)

    def export_json(self, path: str = "/tmp/audit_log.json"):
        with self._lock:
            data = list(self._entries)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[AUDIT] Exported {len(data)} entries to {path}")

    def print_summary(self):
        with self._lock:
            entries = list(self._entries)
        print(f"\n[AUDIT] Lateral Movement Audit Log — {len(entries)} events")
        print(f"[AUDIT] {'─'*55}")
        for e in entries:
            ts  = e["timestamp"].split("T")[1][:8]
            print(f"[AUDIT] {ts}  {e['service']:15s}  {e['action']:25s}  "
                  f"{e['result'][:50]}")
        print(f"[AUDIT] {'─'*55}")
        print(f"[AUDIT] Export: python3 supply_chain_sim.py --export\n")

    def get_entries(self) -> list:
        with self._lock:
            return list(self._entries)


# ── Singleton for import by ids_detector.py ──────────────────
_session_detector = SessionChainingDetector()
_audit_log        = LateralMovementAuditLog()


def get_session_detector() -> SessionChainingDetector:
    return _session_detector

def get_audit_log() -> LateralMovementAuditLog:
    return _audit_log


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Supply Chain Pivot Simulation — AUA Research Lab"
    )
    parser.add_argument("--run",    action="store_true",
                        help="Run the full pivot simulation")
    parser.add_argument("--chaining-demo", action="store_true",
                        help="Demo the SessionChainingDetector")
    parser.add_argument("--export", action="store_true",
                        help="Export audit log to /tmp/audit_log.json")
    args = parser.parse_args()

    print("=" * 60)
    print(" Supply Chain Pivot + Session Chaining Detection")
    print(" AUA Botnet Research Lab — ISOLATED VM ONLY")
    print("=" * 60)

    if args.run or (not args.chaining_demo and not args.export):
        sim = SupplyChainPivotSimulator()
        sim.run_simulation()

    if args.chaining_demo:
        print("\n── Session Chaining Detector Demo ───────────────────")
        det = SessionChainingDetector()
        alerts_seen = []

        # Simulate bot session: login → immediate API call, no UI views
        det.on_login("sess_bot", "192.168.100.11")
        time.sleep(0.1)  # only 100ms after login
        alert = det.on_request("sess_bot", "/api/billing/payment-methods",
                                method="POST",
                                alert_cb=lambda e, s, m: alerts_seen.append(m))
        print(f"  Bot session alert: {bool(alert)}")
        if alert:
            print(f"  {alert[:120]}…")

        # Simulate human session: login → browse → then billing
        det.on_login("sess_human", "10.0.0.100")
        time.sleep(0.1)
        det.on_request("sess_human", "/dashboard")
        det.on_request("sess_human", "/account/settings")
        time.sleep(6)  # realistic human browsing time
        alert2 = det.on_request("sess_human", "/api/billing/payment-methods",
                                 method="GET")
        print(f"  Human session alert: {bool(alert2)} (should be False)")

    if args.export:
        _audit_log.export_json()
