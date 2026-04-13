"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Industry-Specific Target Simulations
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching point (from Castle credential stuffing article):
  "Attackers focus their efforts where compromised accounts
   offer tangible value."

  Gaming:    "Rare skins, in-game currencies, and linked
              payment methods turn player accounts into
              digital assets."
  E-commerce: "Attackers use stolen logins to drain gift cards,
               trigger refunds, or place fraudulent orders with
               saved credit cards."
  Streaming:  "Premium accounts are bundled and sold in bulk,
               often through Telegram channels or dark web shops."
  Financial:  "Compromised logins can lead to unauthorized
               transfers, identity theft, or synthetic identity
               creation."
  SaaS (B2B): "Compromised accounts may expose sensitive
               business assets like billing records, internal
               documents, customer PII, or API keys."
  Mobile:     "Castle blocked over 558,000 credential stuffing
               attempts during a 4-day attack on a major U.S.
               on-demand staffing app."

This module provides three things per industry:
  1. SimulatedTarget  — a mock API server (endpoints + accounts)
     that fake_portal.py can import for industry-specific login
  2. IndustryAttacker — credential stuffing + post-compromise
     actions specific to that industry's attack surface
  3. Detection signals unique to each industry

All targets run on fake_portal.py's Flask app under /industry/
sub-paths. No real external connections.
"""

import json
import os
import random
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

# ── Output logs ────────────────────────────────────────────────
LOG_DIR = "/tmp/industry_sim"
os.makedirs(LOG_DIR, exist_ok=True)

# ── Simulated account profiles per vertical ───────────────────

GAMING_ACCOUNTS = {
    "gamer_alice@example.com": {
        "password":        "securePass123!",
        "username":        "AlicePwns99",
        "level":           85,
        "wallet_usd":      42.00,
        "rare_skins":      ["Dragon Lore AK-47", "Butterfly Knife | Fade"],
        "linked_steam_id": "76561198012345678",
        "saved_card_last4": "4242",
        "subscription":    "GamePass Ultimate",
    },
    "pro_bob@example.com": {
        "password":        "letmein",
        "username":        "B0bTheDestroyer",
        "level":           42,
        "wallet_usd":      5.00,
        "rare_skins":      ["M4A4 | Howl"],
        "linked_steam_id": "76561198087654321",
        "saved_card_last4": "1234",
        "subscription":    "Basic",
    },
}

STREAMING_ACCOUNTS = {
    "binge_carol@example.com": {
        "password":    "qwerty123",
        "plan":        "4K Ultra HD",
        "profiles":    4,
        "screens":     4,
        "saved_card_last4": "5678",
        "region":      "US",
    },
    "viewer_dave@example.com": {
        "password":    "password1",
        "plan":        "Standard",
        "profiles":    2,
        "screens":     2,
        "saved_card_last4": "9999",
        "region":      "UK",
    },
}

FINANCIAL_ACCOUNTS = {
    "investor_eve@example.com": {
        "password":    "Summer2023!",
        "account_no":  "ACC-0042-9987",
        "balance_usd": 12450.00,
        "mfa_enabled": True,
        "linked_ach":  "routing_021000021_acct_1234567",
        "recent_txns": 3,
    },
    "saver_frank@example.com": {
        "password":    "monkey",
        "account_no":  "ACC-0017-3322",
        "balance_usd": 830.00,
        "mfa_enabled": False,
        "linked_ach":  "routing_021000021_acct_9876543",
        "recent_txns": 1,
    },
}

SAAS_ACCOUNTS = {
    "dev_grace@corp.com": {
        "password":    "corp2024!",
        "role":        "admin",
        "org":         "WidgetCo",
        "api_keys":    ["sk-live-aabbccddeeff1122", "sk-live-11223344aabbccdd"],
        "billing_plan": "Enterprise",
        "monthly_spend_usd": 4200.00,
        "team_members": 47,
        "integrations": ["Slack", "Salesforce", "GitHub"],
    },
    "ops_harry@startup.io": {
        "password":    "startup",
        "role":        "member",
        "org":         "StartupCo",
        "api_keys":    ["sk-live-xyzxyzxyz123123"],
        "billing_plan": "Pro",
        "monthly_spend_usd": 299.00,
        "team_members": 8,
        "integrations": ["GitHub"],
    },
}


# ══════════════════════════════════════════════════════════════
#  INDUSTRY 1: GAMING
# ══════════════════════════════════════════════════════════════

class GamingAttacker:
    """
    Models the gaming-specific post-compromise attack chain.

    High-value targets:
      - Rare cosmetic items (market-tradeable digital goods)
      - In-wallet currency (direct cash equivalent)
      - Linked payment methods (can buy more currency)
      - Account rank / level (sold as 'boosted' accounts)

    Monetization:
      - Sell rare skins on grey-market platforms ($5–$1000 each)
      - Transfer in-game currency to attacker account
      - Buy digital gift cards with linked payment, redeem elsewhere
      - List entire account for sale by rank/achievement level

    Detection signals unique to gaming:
      - Bulk skin transfer out immediately after login from new IP
      - Gift card purchase + immediate off-platform redemption
      - Login + immediate trade offer to attacker-controlled account
      - Profile name change + email change in same session
    """

    def __init__(self, log_dir: str = LOG_DIR):
        self.log_path = os.path.join(log_dir, "gaming_attacks.json")

    def _log(self, entry: dict):
        entries = []
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path) as f:
                    entries = json.load(f)
            except Exception:
                entries = []
        entries.append(entry)
        with open(self.log_path, "w") as f:
            json.dump(entries, f, indent=2)

    def attack_account(self, email: str) -> dict:
        acct = GAMING_ACCOUNTS.get(email)
        if not acct:
            return {"status": "not_found"}

        print(f"\n[GAMING] ── Attacking {email} ('{acct['username']}') ──")
        actions = []
        total_value = 0.0

        # Action 1: Inventory extraction
        if acct["rare_skins"]:
            skin_values = {
                "Dragon Lore AK-47":   1800.00,
                "Butterfly Knife | Fade": 650.00,
                "M4A4 | Howl":          900.00,
            }
            for skin in acct["rare_skins"]:
                val = skin_values.get(skin, 50.0)
                total_value += val
                action = {
                    "action":    "skin_transfer",
                    "item":      skin,
                    "value_usd": val,
                    "dest":      f"attacker_steam_{random.randint(10000,99999)}",
                }
                actions.append(action)
                print(f"[GAMING]   🎮 Transferred skin: {skin}  "
                      f"(~${val:.2f})")

        # Action 2: Wallet drain
        if acct["wallet_usd"] > 0:
            total_value += acct["wallet_usd"]
            actions.append({
                "action":    "wallet_drain",
                "amount":    acct["wallet_usd"],
                "method":    "convert_to_gift_code",
            })
            print(f"[GAMING]   💰 Drained wallet: ${acct['wallet_usd']:.2f}")

        # Action 3: Buy gift cards with saved card
        if acct.get("saved_card_last4"):
            gift_amount = random.choice([25.0, 50.0, 100.0])
            total_value += gift_amount
            actions.append({
                "action":    "gift_card_purchase",
                "amount":    gift_amount,
                "card_last4": acct["saved_card_last4"],
                "platform":  "Steam",
            })
            print(f"[GAMING]   💳 Bought ${gift_amount:.2f} gift card "
                  f"with card ****{acct['saved_card_last4']}")

        # Action 4: List account for resale
        rank_price = min(acct["level"] * 2.5, 500.0)
        total_value += rank_price
        actions.append({
            "action":      "account_resale_listing",
            "username":    acct["username"],
            "level":       acct["level"],
            "price_usd":   rank_price,
            "platform":    "PlayerAuctions (simulated)",
        })
        print(f"[GAMING]   🏷️  Listed account "
              f"(Lv.{acct['level']}) for ${rank_price:.2f}")

        result = {
            "email":         email,
            "ts":            datetime.now().isoformat(),
            "actions":       actions,
            "total_value_usd": round(total_value, 2),
        }
        self._log(result)
        print(f"[GAMING]   Total extracted value: ${total_value:.2f}")
        return result

    def detect_signals(self, email: str, actions: list) -> list:
        """Return detection signals for defenders."""
        signals = []
        action_types = [a["action"] for a in actions]

        if "skin_transfer" in action_types:
            signals.append(
                "HIGH: Bulk inventory transfer immediately after login from new IP"
            )
        if "gift_card_purchase" in action_types:
            signals.append(
                "HIGH: Gift card purchased + account lacked prior gift card history"
            )
        if "account_resale_listing" in action_types:
            signals.append(
                "MED: Profile name not changed (attacker prefers stealth resale)"
            )
        if len(action_types) >= 3:
            signals.append(
                "HIGH: 3+ high-value actions within 5 minutes of login — ATO pattern"
            )

        return signals


# ══════════════════════════════════════════════════════════════
#  INDUSTRY 2: STREAMING
# ══════════════════════════════════════════════════════════════

class StreamingAttacker:
    """
    Models the streaming-specific attack chain.

    Streaming account economics:
      - A 4K account ($15–$20/month) resells for $2–$4
      - Attackers sell "shared" accounts — multiple buyers
        each paying $0.50–$1 share the same credentials
      - The legitimate user only notices when Netflix
        shows "too many concurrent streams" or sends
        a "new device signed in" notification

    Monetization:
      - Immediate resale on grey-market sites
      - Credential bundling: 100 accounts sold in bulk for $50
      - Profile creation for buyer isolation (prevent detection)
      - Email change (account hijack) for premium buyers willing
        to pay more for "sole access"

    Detection signals unique to streaming:
      - Concurrent streams from more IPs than the plan allows
      - Email changed + password changed in same session
      - New profile created from an IP in a foreign country
      - Login from IP where the user has never streamed before
        + no content browsing (straight to account settings)
    """

    def __init__(self, log_dir: str = LOG_DIR):
        self.log_path = os.path.join(log_dir, "streaming_attacks.json")
        self._concurrent: dict = defaultdict(list)  # email → active IPs

    def _log(self, entry: dict):
        entries = []
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path) as f:
                    entries = json.load(f)
            except Exception:
                entries = []
        entries.append(entry)
        with open(self.log_path, "w") as f:
            json.dump(entries, f, indent=2)

    def attack_account(self, email: str,
                        buyer_ips: list = None) -> dict:
        acct = STREAMING_ACCOUNTS.get(email)
        if not acct:
            return {"status": "not_found"}

        buyer_ips = buyer_ips or [
            f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            for _ in range(acct["screens"])
        ]

        print(f"\n[STREAM] ── Attacking {email} ({acct['plan']}) ──")

        # Resale price model
        plan_prices = {"4K Ultra HD": 3.50, "Standard": 1.50, "Basic": 0.75}
        share_price = plan_prices.get(acct["plan"], 1.00)
        n_buyers    = acct["screens"]
        gross_usd   = n_buyers * share_price

        actions = []

        # Action 1: List "shared slots"
        for i, ip in enumerate(buyer_ips[:n_buyers]):
            actions.append({
                "action":     "sell_shared_slot",
                "buyer_ip":   ip,
                "price_usd":  share_price,
                "profile":    f"Slot {i+1}",
            })
            self._concurrent[email].append(ip)
            print(f"[STREAM]   📺 Slot {i+1} sold for ${share_price:.2f} "
                  f"→ buyer {ip}")

        # Action 2: Check if email change is worthwhile
        # (solo access premium: 3x base price minus churn risk)
        if acct["plan"] == "4K Ultra HD":
            solo_price = 3 * share_price
            actions.append({
                "action":       "offer_sole_access",
                "new_price_usd": solo_price,
                "requires":     "email + password change",
            })
            print(f"[STREAM]   👑 Offering sole access for "
                  f"${solo_price:.2f} (email + pwd change)")

        result = {
            "email":       email,
            "plan":        acct["plan"],
            "n_buyers":    n_buyers,
            "price_each":  share_price,
            "gross_usd":   round(gross_usd, 2),
            "actions":     actions,
            "ts":          datetime.now().isoformat(),
        }
        self._log(result)
        print(f"[STREAM]   Total gross: ${gross_usd:.2f} "
              f"({n_buyers} slots × ${share_price:.2f})")
        return result

    def simulate_concurrent_abuse(self, email: str) -> dict:
        """
        Simulate multiple buyers streaming simultaneously.
        Detectable by concurrent-stream count exceeding plan limit.
        """
        acct = STREAMING_ACCOUNTS.get(email, {})
        max_screens = acct.get("screens", 1)
        active_ips  = self._concurrent.get(email, [])

        print(f"\n[STREAM] Concurrent streams for {email}:")
        for i, ip in enumerate(active_ips):
            label = "✓ within limit" if i < max_screens else "✗ OVER LIMIT"
            print(f"  Stream {i+1}: {ip}  {label}")

        if len(active_ips) > max_screens:
            print(f"[STREAM] DETECTION: {len(active_ips)} concurrent streams "
                  f"on {max_screens}-screen plan → IDS should trigger")
        return {"active": len(active_ips), "limit": max_screens}


# ══════════════════════════════════════════════════════════════
#  INDUSTRY 3: FINANCIAL
# ══════════════════════════════════════════════════════════════

class FinancialAttacker:
    """
    Models the financial platform attack chain.
    Highest-value and highest-risk category.

    Attack vectors:
      1. Direct ACH transfer to money mule account
      2. Add attacker-controlled beneficiary + transfer
      3. Request paper checks sent to attacker address
      4. Change linked email for account recovery control
      5. Open new credit products (identity theft)

    Why it's harder:
      - MFA is more commonly enforced
      - Velocity checks on transfers are standard
      - Regulatory requirements (Regulation E) mean banks
        must investigate unauthorized transfers
      - Large transfers trigger manual review

    Why it still succeeds:
      - Many banks allow password reset via email (which
        the attacker may also control)
      - "Low and slow" — small transfers ($200-$500) below
        automated review thresholds
      - Beneficiary warm-up period — add beneficiary,
        wait 24h, then transfer a small amount, then escalate
      - Synthetic identity: use compromised PII to open new
        credit lines before the real owner notices
    """

    def __init__(self, log_dir: str = LOG_DIR):
        self.log_path = os.path.join(log_dir, "financial_attacks.json")

    def _log(self, entry: dict):
        entries = []
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path) as f:
                    entries = json.load(f)
            except Exception:
                entries = []
        entries.append(entry)
        with open(self.log_path, "w") as f:
            json.dump(entries, f, indent=2)

    def attack_account(self, email: str,
                        mfa_bypassed: bool = False) -> dict:
        acct = FINANCIAL_ACCOUNTS.get(email)
        if not acct:
            return {"status": "not_found"}

        print(f"\n[FINANCE] ── Attacking {email} ──")

        if acct["mfa_enabled"] and not mfa_bypassed:
            print(f"[FINANCE]  ⛔ MFA required — credential stuffing alone insufficient")
            print(f"[FINANCE]  → Must combine with phishing_sim.py MFA relay")
            print(f"[FINANCE]  → OR reset password via compromised recovery email")
            return {
                "status":         "mfa_blocked",
                "email":          email,
                "mfa_enabled":    True,
                "next_step":      "Use phishing_sim.py scenario 1 (MFA bypass)",
            }

        actions = []
        total_exposed = 0.0

        # Tactic 1: Small transfer below review threshold
        safe_transfer = min(450.0, acct["balance_usd"] * 0.1)
        actions.append({
            "action":     "ach_transfer",
            "amount":     safe_transfer,
            "dest_acct":  "mule_acct_routing021000021_9999999",
            "memo":       "Rent payment",
            "strategy":   "below $500 automated review threshold",
        })
        total_exposed += safe_transfer
        print(f"[FINANCE]  💸 ACH transfer: ${safe_transfer:.2f} "
              f"(below review threshold)")

        # Tactic 2: Add beneficiary (warm-up for larger transfer later)
        actions.append({
            "action":   "add_beneficiary",
            "name":     "John Smith (mule)",
            "routing":  "021000021",
            "acct":     "mule_acct_8888888",
            "strategy": "warm up — transfer larger amount in 24h",
        })
        print(f"[FINANCE]  📋 Beneficiary added (24h warm-up period)")

        # Tactic 3: Change recovery email (account control pivot)
        actions.append({
            "action":      "change_recovery_email",
            "new_email":   "attacker-controlled@proton.me",
            "old_email":   email,
            "consequence": "victim cannot recover account via email reset",
        })
        print(f"[FINANCE]  📧 Recovery email changed to attacker address")

        # Expose balance context
        total_exposed += acct["balance_usd"]
        result = {
            "email":          email,
            "balance_exposed": acct["balance_usd"],
            "immediate_loss":  round(safe_transfer, 2),
            "potential_loss":  round(total_exposed, 2),
            "actions":        actions,
            "ts":             datetime.now().isoformat(),
        }
        self._log(result)
        print(f"[FINANCE]  Immediate loss: ${safe_transfer:.2f} | "
              f"Potential loss: ${total_exposed:.2f}")
        return result

    def detection_signals(self) -> list:
        return [
            "HIGH: Beneficiary added + transfer within 24h from new device",
            "HIGH: Recovery email changed same session as new IP login",
            "MED:  Transfer exactly $450 — just below $500 review trigger",
            "MED:  Login from IP with no prior account activity, no browsing",
            "HIGH: Password reset requested immediately after failed login burst",
        ]


# ══════════════════════════════════════════════════════════════
#  INDUSTRY 4: SAAS / B2B
# ══════════════════════════════════════════════════════════════

class SaaSAttacker:
    """
    Models the B2B SaaS platform attack chain.

    SaaS accounts are highly valuable because:
      - Admin access exposes ALL team members' data
      - API keys can trigger compute at the account's expense
      - Customer PII/billing records are extractable
      - Integration tokens (GitHub, Salesforce) provide
        lateral movement into other systems
      - Enterprise plans often include SSO — compromise one
        account, potentially pivot to the entire org's identity

    The article notes: "attackers can also exploit the
    functionality of the SaaS product itself — running jobs,
    generating output, or triggering API usage without paying."

    Attack vectors:
      1. API key extraction + cryptomining at victim's cost
      2. Customer data exfiltration (GDPR liability for victim)
      3. OAuth integration token abuse (pivot to GitHub, Slack)
      4. Invite attacker-controlled account to org (persistence)
      5. Billing manipulation (upgrade plan, add seats)
    """

    def __init__(self, log_dir: str = LOG_DIR):
        self.log_path = os.path.join(log_dir, "saas_attacks.json")

    def _log(self, entry: dict):
        entries = []
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path) as f:
                    entries = json.load(f)
            except Exception:
                entries = []
        entries.append(entry)
        with open(self.log_path, "w") as f:
            json.dump(entries, f, indent=2)

    def attack_account(self, email: str) -> dict:
        acct = SAAS_ACCOUNTS.get(email)
        if not acct:
            return {"status": "not_found"}

        print(f"\n[SAAS] ── Attacking {email} "
              f"({acct['role']} @ {acct['org']}) ──")

        actions = []
        total_exposure_usd = 0.0

        # Action 1: Extract API keys
        for key in acct["api_keys"]:
            actions.append({
                "action":     "api_key_extraction",
                "key_prefix": key[:12] + "…",
                "use":        "Unauthorized API calls billed to victim",
            })
            print(f"[SAAS]   🔑 API key extracted: {key[:12]}…")

        # Action 2: Estimate cryptomining cost to victim
        if acct["role"] == "admin":
            mining_hours = random.randint(12, 72)
            compute_cost = mining_hours * 2.5  # $2.50/hr GPU instance
            total_exposure_usd += compute_cost
            actions.append({
                "action":       "resource_abuse",
                "type":         "LLM API calls / GPU compute",
                "hours":        mining_hours,
                "cost_to_victim_usd": compute_cost,
            })
            print(f"[SAAS]   ⛏️  Resource abuse: {mining_hours}h "
                  f"→ ${compute_cost:.2f} billed to victim")

        # Action 3: Customer data exfiltration
        pii_records = acct["team_members"] * random.randint(100, 500)
        total_exposure_usd += pii_records * 0.005  # $0.005/record market value
        actions.append({
            "action":        "pii_exfiltration",
            "records":       pii_records,
            "types":         ["name", "email", "billing", "usage_data"],
            "gdpr_exposure": "High — victim org is liable for breach",
        })
        print(f"[SAAS]   📦 Exfiltrated ~{pii_records:,} customer records")

        # Action 4: Invite attacker account (persistence)
        actions.append({
            "action":     "invite_attacker_account",
            "email":      "attacker_persist@proton.me",
            "role":       "admin",
            "org":        acct["org"],
            "purpose":    "Persistent access even after victim password change",
        })
        print(f"[SAAS]   👤 Attacker account invited as admin")

        # Action 5: Integration token pivot
        for integration in acct["integrations"]:
            actions.append({
                "action":      "integration_pivot",
                "integration": integration,
                "consequence": f"Lateral movement into {integration} workspace",
            })
            print(f"[SAAS]   🔗 Pivoted to {integration} via OAuth token")

        result = {
            "email":                email,
            "org":                  acct["org"],
            "role":                 acct["role"],
            "api_keys_extracted":   len(acct["api_keys"]),
            "pii_records":          pii_records,
            "cost_to_victim_usd":   round(total_exposure_usd, 2),
            "integrations_pivoted": acct["integrations"],
            "actions":              actions,
            "ts":                   datetime.now().isoformat(),
        }
        self._log(result)
        print(f"[SAAS]   Direct cost to victim: "
              f"${total_exposure_usd:.2f}")
        return result


# ── Entry point ───────────────────────────────────────────────

def run_all_industries():
    print("=" * 60)
    print(" Industry-Specific Target Simulations")
    print(" AUA Botnet Research Lab — ISOLATED VM ONLY")
    print("=" * 60)

    print("\n" + "▓" * 60)
    print("  VERTICAL 1: GAMING")
    print("▓" * 60)
    gaming = GamingAttacker()
    for email in GAMING_ACCOUNTS:
        result = gaming.attack_account(email)
        sigs   = gaming.detect_signals(email, result.get("actions", []))
        print(f"\n  Detection signals:")
        for s in sigs:
            print(f"    ⚠  {s}")

    print("\n" + "▓" * 60)
    print("  VERTICAL 2: STREAMING")
    print("▓" * 60)
    streaming = StreamingAttacker()
    for email in STREAMING_ACCOUNTS:
        streaming.attack_account(email)
    streaming.simulate_concurrent_abuse("binge_carol@example.com")

    print("\n" + "▓" * 60)
    print("  VERTICAL 3: FINANCIAL")
    print("▓" * 60)
    finance = FinancialAttacker()
    # Account with MFA — should block
    finance.attack_account("investor_eve@example.com", mfa_bypassed=False)
    # Account without MFA — should succeed
    finance.attack_account("saver_frank@example.com")
    print("\n  Detection signals:")
    for s in finance.detection_signals():
        print(f"    ⚠  {s}")

    print("\n" + "▓" * 60)
    print("  VERTICAL 4: SAAS / B2B")
    print("▓" * 60)
    saas = SaaSAttacker()
    for email in SAAS_ACCOUNTS:
        saas.attack_account(email)

    print(f"\n[INDUSTRY] All logs written to {LOG_DIR}/")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Industry Target Simulations — AUA Research Lab"
    )
    parser.add_argument("--vertical",
                        choices=["gaming", "streaming", "financial", "saas", "all"],
                        default="all",
                        help="Which industry vertical to simulate")
    parser.add_argument("--email", default=None,
                        help="Target a specific account email")
    args = parser.parse_args()

    if args.vertical == "gaming" or args.vertical == "all":
        g = GamingAttacker()
        targets = ([args.email] if args.email else list(GAMING_ACCOUNTS))
        for e in targets:
            if e in GAMING_ACCOUNTS:
                g.attack_account(e)
    if args.vertical == "streaming" or args.vertical == "all":
        s = StreamingAttacker()
        targets = ([args.email] if args.email else list(STREAMING_ACCOUNTS))
        for e in targets:
            if e in STREAMING_ACCOUNTS:
                s.attack_account(e)
    if args.vertical == "financial" or args.vertical == "all":
        f = FinancialAttacker()
        targets = ([args.email] if args.email else list(FINANCIAL_ACCOUNTS))
        for e in targets:
            if e in FINANCIAL_ACCOUNTS:
                f.attack_account(e)
    if args.vertical == "saas" or args.vertical == "all":
        b = SaaSAttacker()
        targets = ([args.email] if args.email else list(SAAS_ACCOUNTS))
        for e in targets:
            if e in SAAS_ACCOUNTS:
                b.attack_account(e)
