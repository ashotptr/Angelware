"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Post-Hit Monetization Simulator
 Environment: ISOLATED VM LAB ONLY
====================================================

Simulates what attackers do AFTER a credential stuffing
campaign produces valid "hits" (working email:password pairs).

Article mapping (Castle blog, Step 5 — "Monetize and reuse"):
  "Verified credentials are immediately monetized. Some are
   used to make fraudulent purchases, drain stored value, or
   access restricted content. Others are sold or bundled into
   new combo lists marketed as 'verified hits'. In some cases,
   attackers pivot — using access to reset passwords on other
   platforms or conduct phishing from a trusted inbox."

Simulated monetization vectors (all fictitious, lab-only):
  1. Gift card / loyalty balance drain
  2. Stored payment method abuse (simulated fraudulent order)
  3. Account resale listing (logs to /tmp/resale_market.json)
  4. Password pivot — test same credential on other simulated services
  5. Combo-list export — valid creds written to /tmp/verified_hits.txt

IMPORTANT: This module performs NO real transactions, makes NO
real HTTP requests to external services, and holds NO real PII.
All "accounts", "balances", and "orders" are entirely fictional.
"""

import json
import os
import random
import time
import hashlib
from datetime import datetime

# ── Simulated account database ────────────────────────────────
# Mirrors the USERS dict in fake_portal.py but with extended
# profile data that an attacker would extract post-login.

ACCOUNT_DB = {
    "alice@example.com": {
        "name":            "Alice Simulated",
        "gift_card_usd":   25.00,
        "loyalty_points":  1500,
        "saved_card_last4":"4242",
        "subscription":    "Premium",
        "linked_accounts": ["alice_steam_sim", "alice_netflix_sim"],
    },
    "bob@example.com": {
        "name":            "Bob Simulated",
        "gift_card_usd":   10.00,
        "loyalty_points":  320,
        "saved_card_last4":"1234",
        "subscription":    "Basic",
        "linked_accounts": ["bob_gaming_sim"],
    },
    "admin@example.com": {
        "name":            "Admin Simulated",
        "gift_card_usd":   0.00,
        "loyalty_points":  9999,
        "saved_card_last4":"5678",
        "subscription":    "Enterprise",
        "linked_accounts": ["admin_aws_sim", "admin_github_sim"],
    },
}

# ── Simulated "other services" for password pivot ─────────────
OTHER_SERVICES = [
    "gmail_sim", "facebook_sim", "steam_sim",
    "netflix_sim", "amazon_sim", "bank_sim",
]

# ── Output files ──────────────────────────────────────────────
RESALE_LOG  = "/tmp/resale_market.json"
DRAIN_LOG   = "/tmp/drain_log.json"
PIVOT_LOG   = "/tmp/pivot_log.json"
COMBOS_OUT  = "/tmp/verified_hits.txt"


# ── Helpers ───────────────────────────────────────────────────

def _append_json_log(path: str, entry: dict):
    """Append a JSON entry to a log file (creates if missing)."""
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


def _fake_txid() -> str:
    """Generate a fake transaction ID."""
    return hashlib.sha256(
        f"{time.time()}{random.random()}".encode()
    ).hexdigest()[:12].upper()


# ── Monetization actions ──────────────────────────────────────

def drain_balance(email: str, password: str) -> dict:
    """
    Simulate draining a stored gift-card / loyalty balance.

    In real ATO: attacker logs in, navigates to the wallet/rewards
    page, and transfers the balance to their own account or redeems
    it for prepaid codes immediately resold online.
    """
    account = ACCOUNT_DB.get(email, {})
    if not account:
        return {"action": "drain", "email": email,
                "result": "account_not_found"}

    gift_usd    = account.get("gift_card_usd", 0.0)
    loyalty_pts = account.get("loyalty_points", 0)

    result = {
        "action":           "drain",
        "ts":               datetime.now().isoformat(),
        "email":            email,
        "txid":             _fake_txid(),
        "stolen_usd":       round(gift_usd, 2),
        "stolen_points":    loyalty_pts,
        "saved_card_last4": account.get("saved_card_last4", "N/A"),
        "result":           "success" if (gift_usd > 0 or loyalty_pts > 0)
                            else "zero_balance",
    }

    print(f"[MONET] 💸 DRAIN  {email}")
    print(f"         Gift card: ${result['stolen_usd']:.2f}  |  "
          f"Loyalty: {result['stolen_points']} pts  |  txid: {result['txid']}")

    _append_json_log(DRAIN_LOG, result)
    return result


def place_fraudulent_order(email: str) -> dict:
    """
    Simulate placing a fraudulent order with a saved payment method.

    In real ATO: attacker adds a shipping address they control and
    orders high-value / resalable goods (electronics, gift cards,
    gaming credits), billing to the victim's saved card.
    """
    account = ACCOUNT_DB.get(email, {})
    item = random.choice([
        {"item": "PlayStation Store $50 Gift Card",  "price_usd": 50.00},
        {"item": "Steam Wallet $100",                "price_usd": 100.00},
        {"item": "Amazon Gift Card $25",             "price_usd": 25.00},
        {"item": "Wireless Headphones (resale)",     "price_usd": 89.99},
    ])

    result = {
        "action":         "fraudulent_order",
        "ts":             datetime.now().isoformat(),
        "email":          email,
        "txid":           _fake_txid(),
        "item":           item["item"],
        "amount_usd":     item["price_usd"],
        "billed_to_card": f"****{account.get('saved_card_last4','XXXX')}",
        "ship_to":        "555 Attacker St, Anon City, AN 00000",
        "result":         "order_placed",
    }

    print(f"[MONET] 🛒 ORDER  {email}")
    print(f"         {item['item']}  ${item['price_usd']:.2f}  "
          f"→ card ****{account.get('saved_card_last4','XXXX')}")

    _append_json_log(DRAIN_LOG, result)
    return result


def list_for_resale(email: str, password: str) -> dict:
    """
    Simulate listing a verified account on a dark-web / Telegram marketplace.

    In real credential markets: accounts are bundled by service tier
    and sold in bulk.  A streaming premium account ~$2, gaming account
    with rare inventory $5–50, financial logins $50–500.
    """
    account  = ACCOUNT_DB.get(email, {})
    sub_tier = account.get("subscription", "Unknown")
    price_map = {
        "Enterprise": 15.00,
        "Premium":     4.00,
        "Basic":       1.50,
        "Unknown":     0.50,
    }
    price = price_map.get(sub_tier, 0.50)

    result = {
        "action":       "resale_listing",
        "ts":           datetime.now().isoformat(),
        "listing_id":   _fake_txid(),
        "email":        email,
        "password":     password,
        "subscription": sub_tier,
        "price_usd":    price,
        "channel":      "t.me/fakecredstore_sim",   # not a real channel
        "status":       "listed",
    }

    print(f"[MONET] 🏷️  RESALE {email}:{password}  ({sub_tier}) → ${price:.2f}")

    _append_json_log(RESALE_LOG, result)
    return result


def password_pivot(email: str, password: str) -> dict:
    """
    Simulate testing the same credential on other services (password reuse).

    In real ATO: a valid Gmail credential can unlock Google account
    recovery for dozens of other platforms.  This is why a single breach
    on one site can cascade to many others.

    Simulates a 30% hit rate — a realistic password-reuse estimate.
    """
    hits = []
    for service in OTHER_SERVICES:
        time.sleep(random.uniform(0.02, 0.08))  # simulate network latency
        if random.random() < 0.30:
            hits.append(service)
            print(f"[MONET] 🔑 PIVOT  {email} → {service}: VALID (password reuse)")
        else:
            print(f"[MONET]    PIVOT  {email} → {service}: invalid")

    result = {
        "action":          "password_pivot",
        "ts":              datetime.now().isoformat(),
        "email":           email,
        "services_tested": OTHER_SERVICES,
        "hits":            hits,
        "hit_rate":        f"{len(hits)}/{len(OTHER_SERVICES)}",
    }

    if hits:
        print(f"[MONET] 🔓 Pivot successful on {len(hits)} services: {hits}")
    else:
        print(f"[MONET]    No pivot hits for {email}")

    _append_json_log(PIVOT_LOG, result)
    return result


def export_combo_list(hits: list):
    """
    Export verified credentials to a 'combo list' file.

    In real markets: these are sold as 'verified hits' — the output of
    a credential stuffing run filtered to working pairs only, much more
    valuable than raw breach dumps because success is guaranteed.
    """
    if not hits:
        print("[MONET] No hits to export.")
        return

    with open(COMBOS_OUT, "w") as f:
        f.write(f"# Verified hits — AUA Lab simulation\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        f.write(f"# RESEARCH ONLY — ISOLATED VM LAB\n\n")
        for email, pwd in hits:
            f.write(f"{email}:{pwd}\n")

    print(f"[MONET] 📋 Combo list exported → {COMBOS_OUT} "
          f"({len(hits)} verified pairs)")


# ── Main monetization pipeline ────────────────────────────────

def run_monetization(hits: list,
                     do_drain:  bool = True,
                     do_orders: bool = True,
                     do_resale: bool = True,
                     do_pivot:  bool = True,
                     do_export: bool = True) -> dict:
    """
    Run the full post-compromise monetization pipeline on a list of hits.

    Args:
        hits:      list of (email, password) tuples
        do_drain:  drain gift-card and loyalty balances
        do_orders: place fraudulent orders with saved payment methods
        do_resale: list accounts on simulated resale market
        do_pivot:  test same credentials on other simulated services
        do_export: write verified combo list to /tmp/verified_hits.txt

    Returns summary dict.
    """
    print("\n" + "="*60)
    print(" [MONET] Post-Compromise Monetization Pipeline")
    print(f" [MONET] Processing {len(hits)} verified credential(s)")
    print(" [MONET] SIMULATED — ISOLATED VM LAB ONLY")
    print("="*60 + "\n")

    if not hits:
        print("[MONET] No valid hits — nothing to monetize.")
        return {"status": "no_hits"}

    total_usd      = 0.0
    total_pts      = 0
    pivot_services = 0

    for email, password in hits:
        print(f"\n[MONET] ── Processing hit: {email} ──")

        if do_drain:
            r = drain_balance(email, password)
            total_usd += r.get("stolen_usd", 0)
            total_pts += r.get("stolen_points", 0)
            time.sleep(0.1)

        if do_orders and ACCOUNT_DB.get(email, {}).get("saved_card_last4"):
            place_fraudulent_order(email)
            time.sleep(0.1)

        if do_resale:
            list_for_resale(email, password)
            time.sleep(0.1)

        if do_pivot:
            r = password_pivot(email, password)
            pivot_services += len(r.get("hits", []))
            time.sleep(0.1)

    if do_export:
        export_combo_list(hits)

    summary = {
        "hits_processed":     len(hits),
        "total_stolen_usd":   round(total_usd, 2),
        "total_stolen_pts":   total_pts,
        "pivot_service_hits": pivot_services,
        "drain_log":          DRAIN_LOG,
        "resale_log":         RESALE_LOG,
        "pivot_log":          PIVOT_LOG,
        "combo_export":       COMBOS_OUT if do_export else None,
    }

    print("\n" + "="*60)
    print(" [MONET] Monetization Summary")
    print(f"   Hits processed:      {summary['hits_processed']}")
    print(f"   Gift card stolen:    ${summary['total_stolen_usd']:.2f}")
    print(f"   Loyalty pts stolen:  {summary['total_stolen_pts']}")
    print(f"   Pivot service hits:  {summary['pivot_service_hits']}")
    print(f"   Drain log:           {DRAIN_LOG}")
    print(f"   Resale log:          {RESALE_LOG}")
    print(f"   Pivot log:           {PIVOT_LOG}")
    if do_export:
        print(f"   Combo export:        {COMBOS_OUT}")
    print("="*60 + "\n")

    return summary


# ── CLI ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Monetization Simulator — AUA Botnet Research Lab"
    )
    parser.add_argument(
        "--hits", nargs="+", metavar="email:password",
        help="Credential hits to monetize (e.g. admin@example.com:securePass123!)",
        default=["admin@example.com:securePass123!",
                 "alice@example.com:correct_password_1"]
    )
    parser.add_argument("--no-drain",   action="store_true")
    parser.add_argument("--no-orders",  action="store_true")
    parser.add_argument("--no-resale",  action="store_true")
    parser.add_argument("--no-pivot",   action="store_true")
    parser.add_argument("--no-export",  action="store_true")
    args = parser.parse_args()

    print("=" * 60)
    print(" Monetization Simulator — AUA Botnet Research Lab")
    print(" ISOLATED ENVIRONMENT ONLY — NO REAL TRANSACTIONS")
    print("=" * 60)

    parsed_hits = []
    for pair in args.hits:
        if ":" in pair:
            email, _, pwd = pair.partition(":")
            parsed_hits.append((email.strip(), pwd.strip()))

    run_monetization(
        hits      = parsed_hits,
        do_drain  = not args.no_drain,
        do_orders = not args.no_orders,
        do_resale = not args.no_resale,
        do_pivot  = not args.no_pivot,
        do_export = not args.no_export,
    )
