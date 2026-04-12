"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: GeoIP / ASN Simulation Module
 Environment: ISOLATED VM LAB ONLY
====================================================

Simulates production IP-reputation GeoIP/ASN lookups without
requiring external API calls or a MaxMind database.

Article mapping (Castle credential stuffing blog):
  "Unfamiliar geographies: logins from countries where you don't
   have a customer base, or from multiple regions in a short timeframe."
  "Proxy and VPN usage: high usage of known proxy networks."

In production: replace lookup() with ipinfo.io /json,
MaxMind GeoLite2, or IPQualityScore. The returned dict shape is
identical — swapping is one line.

Usage:
  import geoip_sim
  info = geoip_sim.lookup("1.2.3.4")
  result = geoip_sim.score_request("1.2.3.4")
"""

import ipaddress
import hashlib
import time
import threading
from collections import defaultdict

# ── ASN database ──────────────────────────────────────────────
# (cidr, asn, org, country, region, carrier_type)
# carrier_type: "residential" | "mobile" | "datacenter" | "vpn" | "tor"
_ASN_DB = [
    # Lab / RFC1918 — treated as datacenter
    ("192.168.100.0/24", 64512, "AUA-LAB-BOTNET",      "AM", "Yerevan",    "datacenter"),
    ("10.0.0.0/8",       64513, "RFC1918-PRIVATE",      "XX", "Private",    "datacenter"),
    ("172.16.0.0/12",    64514, "RFC1918-PRIVATE",      "XX", "Private",    "datacenter"),
    ("127.0.0.0/8",      64515, "LOOPBACK",             "XX", "Loopback",   "datacenter"),
    # Known VPN providers
    ("5.34.180.0/22",    60781, "LEASEWEBNETWORKS",     "NL", "Amsterdam",  "vpn"),
    ("66.220.144.0/20",  32934, "FACEBOOK-VPN",         "US", "California", "vpn"),
    ("77.247.96.0/22",   51167, "CONTABO",              "DE", "Munich",     "datacenter"),
    ("176.10.99.0/24",   29695, "CACTUSVPN",            "CH", "Zurich",     "vpn"),
    # Tor exit nodes
    ("185.220.100.0/22", 205100,"FLOWSPEC-TOR-EXIT",    "DE", "Frankfurt",  "tor"),
    ("195.176.3.0/24",   559,   "SWITCH-SWISS-TOR",     "CH", "Bern",       "tor"),
    # Major cloud / datacenters
    ("3.0.0.0/8",        16509, "AMAZON-AWS",           "US", "Virginia",   "datacenter"),
    ("13.32.0.0/15",     16509, "AMAZON-AWS",           "US", "Virginia",   "datacenter"),
    ("34.0.0.0/9",       396982,"GOOGLE-CLOUD",         "US", "Iowa",       "datacenter"),
    ("35.0.0.0/8",       396982,"GOOGLE-CLOUD",         "US", "Oregon",     "datacenter"),
    ("40.0.0.0/8",       8075,  "MICROSOFT-AZURE",      "US", "Virginia",   "datacenter"),
    ("52.0.0.0/8",       16509, "AMAZON-AWS",           "US", "Virginia",   "datacenter"),
    ("104.16.0.0/13",    13335, "CLOUDFLARE",           "US", "California", "datacenter"),
    ("138.197.0.0/16",   14061, "DIGITALOCEAN",         "US", "New York",   "datacenter"),
    ("157.230.0.0/16",   14061, "DIGITALOCEAN",         "NL", "Amsterdam",  "datacenter"),
    # Residential ISPs
    ("24.0.0.0/8",       20001, "CHARTER-SPECTRUM",     "US", "Missouri",   "residential"),
    ("68.0.0.0/8",       7922,  "COMCAST",              "US", "California", "residential"),
    ("75.0.0.0/8",       7922,  "COMCAST",              "US", "California", "residential"),
    ("80.0.0.0/6",       5089,  "VIRGIN-MEDIA",         "GB", "London",     "residential"),
    ("95.0.0.0/8",       3320,  "TELEKOM-DE",           "DE", "Munich",     "residential"),
    ("109.0.0.0/8",      2856,  "BT-UK",                "GB", "London",     "residential"),
    ("151.0.0.0/8",      30722, "VODAFONE-IT",          "IT", "Milan",      "residential"),
    ("176.0.0.0/8",      8422,  "NETCOLOGNE-DE",        "DE", "Cologne",    "residential"),
    ("213.0.0.0/8",      3320,  "TELEKOM-DE",           "DE", "Berlin",     "residential"),
    # Mobile carriers
    ("130.244.0.0/16",   20115, "CHARTER-MOBILE",       "US", "Missouri",   "mobile"),
    ("166.171.0.0/16",   22394, "VERIZON-MOBILE",       "US", "New Jersey", "mobile"),
    ("172.56.0.0/14",    21928, "T-MOBILE",             "US", "Washington", "mobile"),
]

_PARSED_DB = [(ipaddress.ip_network(c, strict=False), a, o, cc, r, t)
              for c, a, o, cc, r, t in _ASN_DB]

_TYPE_RISK = {"residential": 5, "mobile": 10, "datacenter": 55,
              "vpn": 75, "tor": 95}
_GEO_RISK  = {
    "US": 0, "GB": 5, "DE": 5, "FR": 5, "CA": 5, "AU": 5,
    "NL": 10, "CH": 10, "SG": 10, "IT": 5, "AM": 10,
    "RU": 30, "CN": 35, "KP": 90, "IR": 80, "XX": 20,
}

_geo_history: dict = defaultdict(list)
_geo_lock = threading.Lock()
MULTI_REGION_WINDOW = 300
MULTI_REGION_THRESH = 3


def lookup(ip: str) -> dict:
    """
    Return ASN/GeoIP metadata dict for an IP.
    Keys: ip, asn, org, country, region, type, risk (0–100),
          vpn, tor, datacenter, residential (all bool).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return _unknown(ip)
    for net, asn, org, cc, region, ctype in _PARSED_DB:
        if addr in net:
            risk = min(100, _TYPE_RISK.get(ctype, 20) + _GEO_RISK.get(cc, 15) // 3)
            return dict(ip=ip, asn=asn, org=org, country=cc, region=region,
                        type=ctype, risk=risk, vpn=ctype == "vpn",
                        tor=ctype == "tor", datacenter=ctype == "datacenter",
                        residential=ctype in ("residential", "mobile"))
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    return dict(ip=ip, asn=45000 + h % 10000, org=f"UNKNOWN-ISP-{h%9999:04d}",
                country="XX", region="Unknown", type="residential",
                risk=15, vpn=False, tor=False, datacenter=False, residential=True)


def _unknown(ip: str) -> dict:
    return dict(ip=ip, asn=0, org="INVALID", country="XX", region="Unknown",
                type="residential", risk=20, vpn=False, tor=False,
                datacenter=False, residential=True)


def score_request(ip: str) -> dict:
    """
    Full GeoIP risk score combining carrier type, geography, and
    multi-region history (proxy pool detection).

    Returns: {score, band, reasons, geo_info}
    Bands: CLEAN (0–20) / SUSPECT (21–40) / LIKELY_BOT (41–60) / HIGH_RISK (61–100)
    """
    geo     = lookup(ip)
    score   = geo["risk"]
    reasons = []

    if geo["tor"]:
        reasons.append(f"Tor exit node (ASN {geo['asn']})")
    elif geo["vpn"]:
        reasons.append(f"Known VPN provider: {geo['org']}")
    elif geo["datacenter"]:
        reasons.append(f"Datacenter/hosting: {geo['org']}")

    geo_r = _GEO_RISK.get(geo["country"], 15)
    if geo_r >= 30:
        reasons.append(f"High-risk geography: {geo['country']} (+{geo_r})")
        score = min(100, score + geo_r // 2)

    # Multi-region detection — impossible for a real user: indicates proxy pool
    now = time.time()
    with _geo_lock:
        hist = _geo_history[ip]
        hist.append((now, geo["country"]))
        hist[:] = [(ts, cc) for ts, cc in hist if now - ts < MULTI_REGION_WINDOW]
        recent_countries = {cc for _, cc in hist}
        if len(recent_countries) >= MULTI_REGION_THRESH:
            score = min(100, score + 30)
            reasons.append(
                f"Multi-region anomaly: {len(recent_countries)} countries from "
                f"same IP in {MULTI_REGION_WINDOW}s — proxy pool rotation"
            )

    band = ("CLEAN" if score <= 20 else "SUSPECT" if score <= 40
            else "LIKELY_BOT" if score <= 60 else "HIGH_RISK")
    return dict(score=score, band=band, reasons=reasons, geo_info=geo)


def is_unexpected_geo(ip: str,
                      expected: set = None) -> bool:
    """True if IP originates from a country not in the expected set."""
    if expected is None:
        expected = {"US", "GB", "DE", "FR", "CA", "AU", "NL", "CH", "IT", "AM"}
    return lookup(ip)["country"] not in expected


if __name__ == "__main__":
    cases = [
        ("192.168.100.11", "Lab bot VM"),
        ("185.220.100.1",  "Tor exit"),
        ("176.10.99.5",    "CactusVPN"),
        ("68.42.10.5",     "Comcast residential"),
        ("172.56.8.200",   "T-Mobile mobile"),
        ("52.90.1.1",      "AWS datacenter"),
        ("1.2.3.4",        "Unknown"),
    ]
    print(f"{'IP':<20} {'Type':<14} {'CC':<5} {'Risk':<6} {'Band'}")
    print("-" * 60)
    for ip, label in cases:
        r = score_request(ip)
        g = r["geo_info"]
        print(f"{ip:<20} {g['type']:<14} {g['country']:<5} "
              f"{r['score']:<6} {r['band']}  [{label}]")
        for reason in r["reasons"]:
            print(f"  → {reason}")
