"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Post-ATO Phishing Simulation
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching point (from Castle credential stuffing article):
  "In some cases, attackers pivot — using access to reset
   passwords on other platforms or conduct phishing from
   a trusted inbox."
  "Credential stuffing + phishing: After identifying a valid
   login, attackers phish for the MFA token to complete
   the session."

Why this matters:
  A compromised account is not just valuable for what it
  contains — it's a TRUSTED IDENTITY the attacker can
  weaponize against the victim's contacts.

  Three phishing vectors enabled by credential stuffing:

  1. MFA bypass phishing — attacker has password but needs
     the TOTP code; sends a spoofed "unusual sign-in" email
     from a lookalike domain to trick the victim into entering
     their code on a fake page.

  2. Trusted-inbox spear phishing — attacker uses the victim's
     REAL compromised inbox to send malware/credential-harvest
     links to the victim's contacts. Bypass rate is high because
     the email comes from a known, trusted sender.

  3. Account-recovery chain — attacker reads the victim's email
     to find password-reset links for other services, completing
     silent account takeover on downstream platforms.

This module has three parts:

1. PhishingTemplateGenerator (Attack side)
   Generates realistic phishing email templates for MFA bypass
   and trusted-inbox abuse. All emails are logged to files
   in /tmp — no SMTP, no real sending.

2. PhishingDetector (Defense/IDS side — Engine 10)
   Detects post-ATO phishing indicators:
   - Outbound email volume spike from newly-compromised accounts
   - New device + mass outbound email within minutes of login
   - Password-reset link harvesting (reading /reset-password
     emails in the compromised inbox)
   - Link domains in outbound emails that differ from the
     account's normal communication history

3. MFABypassTracker
   Models the real-time window in which an MFA bypass attack
   must succeed (TOTP codes are valid for 30s ± clock drift).
   Shows why "rate-limit OTP verification" is critical and
   why session context (IP, device) must be checked even after
   a correct OTP is supplied.
"""

import argparse
import hashlib
import json
import os
import random
import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional

# ── Configuration ──────────────────────────────────────────────
PHISH_LOG       = "/tmp/phishing_sim_log.json"
MFA_BYPASS_LOG  = "/tmp/mfa_bypass_attempts.json"

# Lookalike domain pairs: (legitimate, lookalike)
LOOKALIKE_DOMAINS = [
    ("example.com",        "examp1e.com"),
    ("myapp.io",           "myapp-security.io"),
    ("bankofamerica.com",  "bankofamerica-secure.com"),
    ("paypal.com",         "paypa1.com"),
    ("google.com",         "google-accounts-verify.com"),
]

# Simulated MFA bypass page URL (lab only — not a real URL)
FAKE_MFA_PAGE = "http://192.168.100.10:8080/verify-mfa"


# ══════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════

def _append_log(path: str, entry: dict):
    entries = []
    if os.path.exists(path):
        try:
            with open(path) as f:
                entries = json.load(f)
        except (json.JSONDecodeError, OSError):
            entries = []
    entries.append(entry)
    with open(path, "w") as f:
        json.dump(entries, f, indent=2)


def _fake_message_id() -> str:
    return hashlib.sha256(
        f"{time.time()}{random.random()}".encode()
    ).hexdigest()[:16].upper()


# ══════════════════════════════════════════════════════════════
#  Part 1: PHISHING TEMPLATE GENERATOR (Attack side)
# ══════════════════════════════════════════════════════════════

class PhishingTemplateGenerator:
    """
    Generates phishing email content for three post-ATO scenarios.

    All output goes to /tmp log files. No SMTP, no real sockets.
    The generator exists to show defenders WHAT the emails look
    like so they can build detection rules for the patterns.

    Teaching goal: email body analysis, lookalike domain detection,
    urgency language patterns, and link obfuscation are the four
    primary signals used by email security gateways to catch these.
    """

    # ── Template 1: MFA Bypass ──────────────────────────────────

    MFA_BYPASS_SUBJECT_POOL = [
        "Unusual sign-in to your account",
        "Action required: Verify your identity",
        "New login from {city}, {country} — was this you?",
        "Security alert: Unrecognized device",
        "Your account has been accessed from a new location",
    ]

    MFA_BYPASS_BODY = """\
Hi {first_name},

We detected a sign-in to your {service} account from an
unrecognized device:

  Device:   {device}
  Location: {city}, {country}
  Time:     {timestamp} UTC

If this was you, no action is needed.

If you did NOT authorize this sign-in, your account may be
compromised. Please verify your identity immediately:

  → {mfa_link}

This link expires in 10 minutes. If you do not verify,
your account will be temporarily locked for your protection.

— The {service} Security Team

────────────────────────────────────────────────
This is an automated message. Do not reply.
Sent by: security@{lookalike_domain}
"""

    # ── Template 2: Trusted-Inbox Spear Phishing ───────────────

    SPEAR_SUBJECT_POOL = [
        "Quick question — can you check this?",
        "Shared a file with you",
        "FWD: Important document",
        "Re: Our meeting next week",
        "Hey — look at this before you leave",
    ]

    SPEAR_BODY = """\
Hey {contact_name},

Hope you're doing well! I wanted to share something with you.

Can you take a look at this document? It's important and
I need your feedback before tomorrow:

  {malicious_link}

Let me know what you think.

{sender_name}
"""

    # ── Template 3: Account Recovery Chain ─────────────────────

    RECOVERY_BODY = """\
[ATTACKER ACTION LOG — SIMULATION ONLY]

After gaining access to {victim_email}, the attacker:

1. Searched inbox for subject:"reset your password"
   Found {n_reset_emails} password reset emails for:
   {reset_services}

2. Clicked active reset links (valid within 24h):
   {clicked_links}

3. Changed passwords on {n_compromised} downstream services.

4. Enrolled attacker-controlled recovery email on each.

Teaching point: A compromised email account is a master key.
Password resets for banking, cloud storage, social media, and
other services all flow through the same inbox.

Defense: Use a dedicated email address (not shared with public
profiles) for high-value account recovery. Enable "require
current password to change recovery email" on all services.
"""

    def __init__(self):
        self._generated = []

    def generate_mfa_bypass(self,
                             victim_email: str,
                             victim_name: str = "User",
                             service: str = "MyApp") -> dict:
        """
        Generate an MFA bypass phishing email.

        The attacker has the victim's password (from credential
        stuffing) but needs the current TOTP code. They trick
        the victim into entering their code on a fake "verify
        your identity" page, then relay it to the real service
        before it expires (30-second TOTP window).
        """
        first_name = victim_name.split()[0]
        lookalike   = random.choice(LOOKALIKE_DOMAINS)[1]
        subject     = random.choice(self.MFA_BYPASS_SUBJECT_POOL)

        cities = [("Moscow", "RU"), ("Lagos", "NG"),
                  ("Bucharest", "RO"), ("Beijing", "CN"),
                  ("São Paulo", "BR")]
        city, country = random.choice(cities)

        devices = ["Chrome on Windows 10", "Firefox on Ubuntu 22",
                   "Curl/7.88.1", "Python-urllib/3.11"]

        subject = subject.format(city=city, country=country)
        body    = self.MFA_BYPASS_BODY.format(
            first_name     = first_name,
            service        = service,
            device         = random.choice(devices),
            city           = city,
            country        = country,
            timestamp      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
            mfa_link       = FAKE_MFA_PAGE,
            lookalike_domain = lookalike,
        )

        email = {
            "type":          "mfa_bypass",
            "ts":            datetime.now().isoformat(),
            "message_id":    _fake_message_id(),
            "from_addr":     f"security@{lookalike}",
            "to_addr":       victim_email,
            "subject":       subject,
            "body":          body,
            "malicious_url": FAKE_MFA_PAGE,
            "lookalike_domain": lookalike,
            "attack_window_sec": 30,   # TOTP validity window
        }

        self._generated.append(email)
        _append_log(PHISH_LOG, email)

        print(f"[PHISH] MFA bypass email generated:")
        print(f"  From:     security@{lookalike}")
        print(f"  To:       {victim_email}")
        print(f"  Subject:  {subject}")
        print(f"  Trap URL: {FAKE_MFA_PAGE}")
        print(f"  Window:   30s TOTP validity — attacker must relay code immediately")
        return email

    def generate_trusted_inbox(self,
                                compromised_email: str,
                                contact_list: list,
                                malicious_url: str = None) -> list:
        """
        Generate spear-phishing emails from a compromised inbox.

        These have extremely high open rates because the sender
        is a real, known person — not a lookalike domain.
        """
        sender_name = compromised_email.split("@")[0].replace(".", " ").title()
        url = malicious_url or f"http://192.168.100.10:8080/malware_{_fake_message_id()}.zip"
        emails = []

        for contact in contact_list:
            contact_name = contact.split("@")[0].replace(".", " ").title()
            subject  = random.choice(self.SPEAR_SUBJECT_POOL)
            body     = self.SPEAR_BODY.format(
                contact_name   = contact_name,
                sender_name    = sender_name,
                malicious_link = url,
            )
            email = {
                "type":          "trusted_inbox_spear",
                "ts":            datetime.now().isoformat(),
                "message_id":    _fake_message_id(),
                "from_addr":     compromised_email,  # REAL sender address
                "to_addr":       contact,
                "subject":       subject,
                "body":          body,
                "malicious_url": url,
                "trust_factor":  "HIGH — sent from real known address",
            }
            emails.append(email)
            _append_log(PHISH_LOG, email)
            print(f"[PHISH] Trusted-inbox email → {contact}  (from: {compromised_email})")

        return emails

    def generate_recovery_chain(self,
                                 victim_email: str,
                                 inbox_contents: list = None) -> dict:
        """
        Simulate account-recovery chain attack.
        inbox_contents: list of (service, has_active_reset) tuples.
        """
        if inbox_contents is None:
            inbox_contents = [
                ("Gmail",        True),
                ("Amazon",       True),
                ("Steam",        False),   # expired link
                ("LinkedIn",     True),
                ("GitHub",       False),
                ("Bank Portal",  True),
            ]

        active   = [(s, v) for s, v in inbox_contents if v]
        inactive = [(s, v) for s, v in inbox_contents if not v]

        report = {
            "type":            "recovery_chain",
            "ts":              datetime.now().isoformat(),
            "victim_email":    victim_email,
            "reset_emails_found": len(inbox_contents),
            "active_resets":   [s for s, _ in active],
            "expired_resets":  [s for s, _ in inactive],
            "n_compromised":   len(active),
        }
        _append_log(PHISH_LOG, report)

        body = self.RECOVERY_BODY.format(
            victim_email    = victim_email,
            n_reset_emails  = len(inbox_contents),
            reset_services  = ", ".join(s for s, _ in inbox_contents),
            clicked_links   = "\n   ".join(
                f"✓ {s}" for s, v in inbox_contents if v
            ) or "   (none)",
            n_compromised   = len(active),
        )
        print(body)
        return report


# ══════════════════════════════════════════════════════════════
#  Part 2: PHISHING DETECTOR (Defense/IDS Engine 10)
# ══════════════════════════════════════════════════════════════

class PhishingDetector:
    """
    IDS Engine 10: Post-ATO phishing activity detection.

    Signals monitored (all observable server-side):

    Signal 1 — Outbound email burst:
      A legitimate user sends 0-5 emails/hour on average.
      An attacker using a compromised inbox to phish contacts
      sends 50-200 emails in a few minutes.
      Alert: >20 outbound emails from one account in 5 minutes.

    Signal 2 — New device + email burst:
      Legitimate users don't typically log in from a new device
      and immediately send mass emails. The combination of
      (new device fingerprint) + (outbound volume spike)
      in the same session is a high-confidence ATO signal.

    Signal 3 — Lookalike domain in outbound links:
      Emails containing links to domains that are edit-distance-1
      from known legitimate domains (e.g. "paypa1.com") are
      almost certainly phishing.

    Signal 4 — MFA OTP submission rate:
      More than 3 OTP attempts per user per minute indicates
      either an MFA brute-force or an MFA relay attack (attacker
      is proxying OTPs in real-time from a phishing page).
    """

    OUTBOUND_BURST_THRESHOLD = 20    # emails per 5-minute window
    OUTBOUND_BURST_WINDOW    = 300   # seconds
    OTP_RATE_THRESHOLD       = 3     # OTP attempts per 60s
    OTP_RATE_WINDOW          = 60    # seconds

    def __init__(self):
        self._lock = threading.Lock()
        # account → deque of outbound timestamps
        self._outbound: dict = defaultdict(lambda: deque(maxlen=500))
        # account → set of device fingerprints seen this session
        self._devices:  dict = defaultdict(set)
        # account → deque of OTP attempt timestamps
        self._otp_attempts: dict = defaultdict(lambda: deque(maxlen=100))
        self._alerts = []

    def record_outbound_email(self, account: str,
                               to_addr: str,
                               body_links: list = None,
                               device_fp: str = None) -> Optional[dict]:
        """
        Called whenever the portal/email system sends an outbound email.
        Returns an alert dict if a detection fires, else None.
        """
        now  = time.time()
        alert = None

        with self._lock:
            self._outbound[account].append(now)
            if device_fp:
                self._devices[account].add(device_fp)

            # Prune window
            cutoff  = now - self.OUTBOUND_BURST_WINDOW
            recent  = [ts for ts in self._outbound[account] if ts > cutoff]

            # Signal 1: outbound burst
            if len(recent) >= self.OUTBOUND_BURST_THRESHOLD:
                alert = {
                    "engine":      "Engine10/OutboundBurst",
                    "severity":    "HIGH",
                    "account":     account,
                    "n_emails":    len(recent),
                    "window_sec":  self.OUTBOUND_BURST_WINDOW,
                    "ts":          datetime.now().isoformat(),
                    "message": (
                        f"POST-ATO PHISHING: {account} sent {len(recent)} "
                        f"outbound emails in {self.OUTBOUND_BURST_WINDOW}s\n"
                        f"  Threshold: {self.OUTBOUND_BURST_THRESHOLD}/window\n"
                        f"  Normal rate: <5/hour\n"
                        f"  Action: Suspend outbound email, flag for review\n"
                        f"  MITRE: T1566.002 (Spearphishing Link)"
                    ),
                }

            # Signal 2: new device + burst
            if (len(self._devices[account]) > 1
                    and len(recent) >= self.OUTBOUND_BURST_THRESHOLD // 2):
                combo_alert = {
                    "engine":      "Engine10/NewDeviceBurst",
                    "severity":    "CRITICAL",
                    "account":     account,
                    "n_devices":   len(self._devices[account]),
                    "n_emails":    len(recent),
                    "ts":          datetime.now().isoformat(),
                    "message": (
                        f"POST-ATO INDICATOR: {account} — new device + "
                        f"{len(recent)} outbound emails in session\n"
                        f"  Device fingerprints this session: "
                        f"{len(self._devices[account])}\n"
                        f"  High-confidence ATO: legitimate users do not "
                        f"send mass email from a brand-new device\n"
                        f"  Action: Force re-authentication + suspend session\n"
                        f"  MITRE: T1078 (Valid Accounts)"
                    ),
                }
                if not alert:
                    alert = combo_alert

            # Signal 3: lookalike domain in links
            if body_links:
                for link in body_links:
                    domain = _extract_domain(link)
                    for legit, lookalike in LOOKALIKE_DOMAINS:
                        if domain and _edit_distance(domain, legit) == 1:
                            alert = {
                                "engine":    "Engine10/LookalikeDomain",
                                "severity":  "HIGH",
                                "account":   account,
                                "domain":    domain,
                                "matches":   legit,
                                "ts":        datetime.now().isoformat(),
                                "message": (
                                    f"PHISHING LINK: outbound email from "
                                    f"{account} contains lookalike domain\n"
                                    f"  Detected: '{domain}'\n"
                                    f"  Matches:  '{legit}' (edit distance 1)\n"
                                    f"  MITRE: T1566.002"
                                ),
                            }
                            break

        if alert:
            self._alerts.append(alert)
            print(f"\n[IDS-{alert['engine']}] {alert['severity']}: "
                  f"{alert['message']}\n")
        return alert

    def record_otp_attempt(self, account: str,
                            src_ip: str) -> Optional[dict]:
        """
        Called on every OTP/TOTP submission attempt.
        High rate = MFA relay attack.
        """
        now = time.time()
        with self._lock:
            self._otp_attempts[account].append(now)
            cutoff = now - self.OTP_RATE_WINDOW
            recent = [ts for ts in self._otp_attempts[account]
                      if ts > cutoff]

        if len(recent) >= self.OTP_RATE_THRESHOLD:
            alert = {
                "engine":    "Engine10/MFARelay",
                "severity":  "CRITICAL",
                "account":   account,
                "src_ip":    src_ip,
                "n_attempts": len(recent),
                "window_sec": self.OTP_RATE_WINDOW,
                "ts":         datetime.now().isoformat(),
                "message": (
                    f"MFA RELAY ATTACK: {len(recent)} OTP attempts "
                    f"from {src_ip} for {account} in {self.OTP_RATE_WINDOW}s\n"
                    f"  Threshold: {self.OTP_RATE_THRESHOLD}/window\n"
                    f"  Attacker is proxying codes from a live phishing page\n"
                    f"  TOTP codes are valid for 30s — attacker must relay immediately\n"
                    f"  Mitigation: lock account after 3 OTP failures per minute;\n"
                    f"  require session context (IP, device) even after valid OTP\n"
                    f"  MITRE: T1111 (Multi-Factor Authentication Interception)"
                ),
            }
            self._alerts.append(alert)
            print(f"\n[IDS-{alert['engine']}] {alert['severity']}: "
                  f"{alert['message']}\n")
            return alert
        return None

    def get_stats(self) -> dict:
        return {
            "total_alerts": len(self._alerts),
            "alert_breakdown": {
                e: sum(1 for a in self._alerts if a["engine"] == e)
                for e in {a["engine"] for a in self._alerts}
            },
        }


# ══════════════════════════════════════════════════════════════
#  Part 3: MFA BYPASS TRACKER
# ══════════════════════════════════════════════════════════════

class MFABypassTracker:
    """
    Models the timing constraints of a real-time MFA relay attack.

    The attack flow:
      1. Attacker submits victim's stolen password to real service.
      2. Real service sends MFA challenge to victim's device.
      3. Attacker's phishing page shows victim a fake "enter your
         verification code" form.
      4. Victim enters their TOTP code on the fake page.
      5. Attacker's server receives the code and immediately
         replays it to the real service.

    The race: TOTP codes expire every 30 seconds (RFC 6238).
    Most implementations accept codes from the previous and next
    time step (window=1), giving a 90-second usable window.
    Network round-trip adds ~200ms overhead, which is negligible.

    Defense layering:
      a) Rate-limit OTP attempts (>3/min = relay attack)
      b) Bind session to IP + device fingerprint even after OTP
      c) Push notifications (FIDO2/WebAuthn) instead of TOTP —
         they are origin-bound and cannot be relayed
      d) Login alerts that notify the victim in real time
    """

    TOTP_STEP     = 30     # seconds per TOTP period
    TOTP_WINDOW   = 1      # accept ±1 period (90s effective window)
    MAX_RELAY_RTT = 5.0    # seconds — max realistic relay latency

    def simulate_relay_attack(self,
                               victim_email: str,
                               secret: str = "SIMULATED_SECRET") -> dict:
        """
        Simulate the timing of a successful MFA relay.
        Returns analysis of the attack window.
        """
        now = time.time()
        period = int(now / self.TOTP_STEP)
        usable_window = self.TOTP_STEP * (2 * self.TOTP_WINDOW + 1)

        result = {
            "victim":           victim_email,
            "simulation_ts":    datetime.now().isoformat(),
            "totp_period_sec":  self.TOTP_STEP,
            "accepted_window_sec": usable_window,
            "relay_rtt_sec":    self.MAX_RELAY_RTT,
            "attack_feasible":  self.MAX_RELAY_RTT < usable_window,
            "current_period":   period,
            "period_expires_in": self.TOTP_STEP - (now % self.TOTP_STEP),
        }

        print(f"\n[MFA-RELAY] Timing analysis for {victim_email}:")
        print(f"  TOTP step:        {self.TOTP_STEP}s")
        print(f"  Accepted window:  ±{self.TOTP_WINDOW} period "
              f"→ {usable_window}s usable")
        print(f"  Max relay RTT:    {self.MAX_RELAY_RTT}s")
        print(f"  Current period expires in: "
              f"{result['period_expires_in']:.1f}s")
        print(f"  Attack feasible:  {result['attack_feasible']} "
              f"(RTT {self.MAX_RELAY_RTT}s << window {usable_window}s)")
        print(f"\n  Defense: FIDO2/WebAuthn (origin-bound) cannot be relayed.")
        print(f"  Even with TOTP, bind session to IP+device post-OTP.")
        return result


# ── Utility functions ──────────────────────────────────────────

def _extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL string."""
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1).lower() if m else None


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein edit distance between two strings."""
    if len(a) > len(b):
        a, b = b, a
    distances = list(range(len(a) + 1))
    for i2, c2 in enumerate(b):
        new_distances = [i2 + 1]
        for i1, c1 in enumerate(a):
            if c1 == c2:
                new_distances.append(distances[i1])
            else:
                new_distances.append(
                    1 + min(distances[i1], distances[i1 + 1],
                            new_distances[-1])
                )
        distances = new_distances
    return distances[-1]


# ── Singleton for IDS integration ────────────────────────────
_detector = PhishingDetector()


def engine10_record_email(account, to_addr, links=None, device_fp=None):
    return _detector.record_outbound_email(account, to_addr, links, device_fp)


def engine10_record_otp(account, src_ip):
    return _detector.record_otp_attempt(account, src_ip)


# ── Demo / entry point ────────────────────────────────────────

def _run_demo():
    gen     = PhishingTemplateGenerator()
    tracker = MFABypassTracker()
    det     = PhishingDetector()

    print("=" * 60)
    print(" Post-ATO Phishing Simulation — AUA Research Lab")
    print("=" * 60)

    # ── Scenario 1: MFA Bypass ────────────────────────────────
    print("\n── Scenario 1: MFA Bypass Email ──────────────────────")
    gen.generate_mfa_bypass(
        "alice@example.com", "Alice Smith", "MyApp"
    )
    print("\n── MFA Relay Timing Analysis ─────────────────────────")
    tracker.simulate_relay_attack("alice@example.com")

    # Simulate rapid OTP submissions (relay attack)
    print("\n── Simulating MFA relay (3 OTPs in 10s) ─────────────")
    for i in range(4):
        alert = det.record_otp_attempt(
            "alice@example.com", "192.168.100.11"
        )
        time.sleep(0.1)

    # ── Scenario 2: Trusted-Inbox Spear Phishing ───────────────
    print("\n── Scenario 2: Trusted-Inbox Spear Phishing ──────────")
    contacts = [
        "bob@example.com",
        "charlie@corp.com",
        "dave@mail.com",
    ]
    emails = gen.generate_trusted_inbox(
        "alice@example.com", contacts
    )

    # Simulate IDS detecting the burst
    print("\n── IDS Engine 10: Detecting outbound email burst ──────")
    for e in emails:
        det.record_outbound_email(
            "alice@example.com",
            e["to_addr"],
            body_links=[e["malicious_url"]],
            device_fp="fp_new_device_aabbccdd",
        )
        time.sleep(0.05)

    # Add more to cross the threshold
    for i in range(20):
        det.record_outbound_email(
            "alice@example.com",
            f"contact{i}@external.com",
            device_fp="fp_new_device_aabbccdd",
        )

    # ── Scenario 3: Recovery Chain ─────────────────────────────
    print("\n── Scenario 3: Account Recovery Chain ────────────────")
    gen.generate_recovery_chain("alice@example.com")

    print(f"\n[PHISH] Log written to: {PHISH_LOG}")
    print(f"[PHISH] Engine 10 stats: {det.get_stats()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Post-ATO Phishing Simulation — AUA Research Lab"
    )
    parser.add_argument("--demo",       action="store_true",
                        help="Run full phishing simulation demo")
    parser.add_argument("--mfa-bypass", action="store_true",
                        help="Generate MFA bypass email only")
    parser.add_argument("--victim",     default="alice@example.com",
                        help="Victim email address")
    args = parser.parse_args()

    print("=" * 60)
    print(" Post-ATO Phishing Simulation")
    print(" AUA Botnet Research Lab — ISOLATED VM ONLY")
    print(" No real emails sent — output logged to /tmp")
    print("=" * 60)

    if args.mfa_bypass:
        g = PhishingTemplateGenerator()
        g.generate_mfa_bypass(args.victim)
        MFABypassTracker().simulate_relay_attack(args.victim)
    else:
        _run_demo()
