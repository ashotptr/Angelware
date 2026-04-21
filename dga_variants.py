"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: DGA Variants Library
 Environment: ISOLATED VM LAB ONLY
====================================================

Implements ALL DGA algorithm types documented across
the seven research resources, including:

  Classical types (ericyoc):
    1.  Zodiac-based
    2.  Time-based (improved)
    3.  Seed-based (MD5-chained)
    4.  Dictionary-based
    5.  PRNG-based
    6.  Arithmetic-based
    7.  Permutation-based
    8.  Fibonacci-based
    9.  Base32/Base64-encoded
    10. Wordlist-concatenation
    11. Vowel-Consonant alternating
    12. Morse-Code-mapped
    13. Emoji-mapped
    14. GPS-Coordinate-derived
    15. Musical-Notes-based

  Real-malware DGAs:
    16. Ranbyus  – 14-char LFSR bitwise mutation (banking trojan)
    17. Dyre     – MD5-seeded PRNG, 1000-5000 .com domains/day

  Cybereason variants (structural approximations):
    18. DWORD-hex   – random 32-bit int → hex string
    19. Punycode-like – XN-- encoded gibberish
    20. Word-prefix  – constant prefix + random suffix

Each algorithm exposes:
    generate(seed, count, **kwargs) → list[str]
    ANALYSIS dict  – explanation / usefulness / strengths / weaknesses / deception

Also provides:
    dgas_to_regex(domains)      – frequency-based regex from sample output
    create_yara_rule(...)       – full YARA rule string
    summarize_all()             – tabular overview
    generate_labeled_dataset()  – CSV-ready list for ML training

Usage:
    from dga_variants import ALL_DGA_TYPES, generate_labeled_dataset
    domains, labels = zip(*generate_labeled_dataset(50))
"""

import hashlib
import random
import string
import math
import uuid
import base64
import struct
import time
import re
import os
import csv
from datetime import datetime, timedelta
from collections import Counter
from typing import List, Tuple, Dict

# ── TLD pools (gap items 31, 32, 58) ──────────────────────────
STANDARD_TLDS   = [".com", ".net", ".org", ".info", ".biz", ".edu", ".gov"]
EXOTIC_TLDS     = [".ga", ".im", ".sc", ".xxx", ".tw", ".pro", ".mn",
                   ".me", ".su", ".bit", ".pw", ".cc", ".in", ".co",
                   ".ms", ".mu", ".cx", ".cm", ".de", ".jp", ".eu"]
DDNS_TLDS       = [".duckdns.org", ".chickenkiller.com", ".accesscam.org",
                   ".casacam.net", ".ddnsfree.com", ".mooo.com",
                   ".strangled.net", ".ignorelist.com", ".dontargetme.nl",
                   ".ddns.net", ".dyndns.org"]
OPENNIC_TLDS    = [".geek", ".oss", ".session.geek", ".session.oss"]
RANBYUS_TLDS    = ["in", "me", "cc", "su", "tw", "net", "com", "pw", "org"]

ALL_TLDS        = STANDARD_TLDS + EXOTIC_TLDS + DDNS_TLDS + OPENNIC_TLDS

WORDLIST = [
    "client", "agent", "allow", "disallow", "jsc", "axp", "not",
    "cli", "ali", "user", "click", "july", "table", "city",
    "favor", "dish", "apple", "banana", "cherry", "data", "frame",
    "proxy", "host", "load", "sync", "ping", "push", "pull",
]

MORSE_MAP = {
    'a': '.-',   'b': '-...', 'c': '-.-.',  'd': '-..',
    'e': '.',    'f': '..-.', 'g': '--.',   'h': '....',
    'i': '..',   'j': '.---', 'k': '-.-',   'l': '.-..',
    'm': '--',   'n': '-.',   'o': '---',   'p': '.--.',
    'q': '--.-', 'r': '.-.',  's': '...',   't': '-',
    'u': '..-',  'v': '...-', 'w': '.--',   'x': '-..-',
    'y': '-.--', 'z': '--..',
}

MUSICAL_NOTES  = list("ABCDEFG")
MUSICAL_OCT    = list("12345")

ZODIAC_MONTHS = [
    "january","february","march","april","may","june",
    "july","august","september","october","november","december"
]
ZODIAC_DAYS   = list(range(1, 29))

# ── Per-algorithm analysis metadata (gap items 53, 54) ────────
DGA_ANALYSIS: Dict[str, Dict] = {
    "zodiac": {
        "explanation": "Uses zodiac sign derived from a random day+month combo as input to UUID5 → SHA-256 → character substitution.",
        "usefulness":  "Gives a plausible calendar-based seed; each day+month produces a unique namespace.",
        "strengths":   "Non-trivial to reconstruct without knowing the zodiac function; output looks random.",
        "weaknesses":  "Zodiac-sign pattern has only 12 values; entropy of seed space is low.",
        "deception":   "Attacker can swap the zodiac table or add a secondary PRNG step to obscure the pattern.",
    },
    "time_based": {
        "explanation": "Formats a date offset from today and uses it as the domain body.",
        "usefulness":  "Trivially synchronised between bot and operator; requires no pre-shared key.",
        "strengths":   "Changes daily without communication; date is always available.",
        "weaknesses":  "Date-derived patterns are predictable; sinkholing only requires knowing the algorithm.",
        "deception":   "Add a random offset or a secondary hash to obscure the date embedding.",
    },
    "seed_based": {
        "explanation": "MD5 of a seed string, truncated and updated iteratively for each domain.",
        "usefulness":  "Operator and bot share the seed; MD5 makes the domain body look random.",
        "strengths":   "If seed is kept secret, domains are unpredictable without it.",
        "weaknesses":  "If seed leaks, all past and future domains are known; MD5 is fast to brute-force.",
        "deception":   "Use a slow KDF (bcrypt, scrypt) or a hardware-derived seed instead of a static string.",
    },
    "dictionary": {
        "explanation": "Concatenates random characters from a custom dictionary until the desired length is reached.",
        "usefulness":  "Generated domains look like short words; may bypass simple entropy filters.",
        "strengths":   "High variety; can be tuned to look like legitimate abbreviations.",
        "weaknesses":  "Character-frequency analysis reveals a restricted alphabet.",
        "deception":   "Use a real English word list so domains look like valid English words (wordlist variant).",
    },
    "prng": {
        "explanation": "Seeds Python's random module and generates character streams.",
        "usefulness":  "Simple and fast; works on any platform without external libraries.",
        "strengths":   "Statistically uniform character distribution; hard to distinguish from noise.",
        "weaknesses":  "Python's Mersenne Twister is predictable given enough output; seed must stay secret.",
        "deception":   "Use a CSPRNG or combine with a hardware timestamp for the seed.",
    },
    "arithmetic": {
        "explanation": "Adds a random value to the seed each iteration and converts the result to a string.",
        "usefulness":  "Very lightweight; no cryptographic dependency.",
        "strengths":   "Produces numeric-heavy domains that may look like CDN hostnames.",
        "weaknesses":  "Low entropy; arithmetic pattern is trivially reverse-engineered.",
        "deception":   "Apply modular exponentiation or XOR with a key after each arithmetic step.",
    },
    "permutation": {
        "explanation": "Generates all permutations of a base domain's characters and rotates through them.",
        "usefulness":  "Deterministic given the base; same set of domains every day.",
        "strengths":   "Finite domain set can be pre-registered by the operator.",
        "weaknesses":  "Permutation space is small for short bases; easily enumerated.",
        "deception":   "Shuffle with a time-seeded PRNG before selecting permutations.",
    },
    "fibonacci": {
        "explanation": "Uses Fibonacci numbers as character indices into the alphabet.",
        "usefulness":  "Non-standard mapping that is not obvious from the output.",
        "strengths":   "Fibonacci sequence is infinite; domains don't repeat.",
        "weaknesses":  "Fibonacci growth pattern produces biased character distributions.",
        "deception":   "XOR the Fibonacci index with a secret key before mapping.",
    },
    "base32_base64": {
        "explanation": "Base32 or Base64 encodes the seed and uses the output as the domain body.",
        "usefulness":  "Output is always a valid subset of alphanumeric characters.",
        "strengths":   "Encoding is reversible; operator can trivially compute all domains.",
        "weaknesses":  "Base64 character set is recognisable; '=' padding leaks encoding type.",
        "deception":   "Strip padding, lowercase, and truncate to obscure the encoding.",
    },
    "wordlist": {
        "explanation": "Concatenates two random words from a hardcoded list (like the Crowdstrike variant).",
        "usefulness":  "Produces human-readable, dictionary-word domains that evade pattern detectors.",
        "strengths":   "Low entropy detection score; domains look plausible to casual inspection.",
        "weaknesses":  "Finite word list; if list is extracted, all domain combinations are known.",
        "deception":   "Use a large corpus (100k+ words) and add a numeric suffix.",
    },
    "vowel_consonant": {
        "explanation": "Alternates vowels and consonants to produce pronounceable gibberish.",
        "usefulness":  "Domains pass 'looks like a word' heuristics even though they are fake.",
        "strengths":   "High vowel ratio and low consecutive-consonant run; evades RCC/RRC detectors.",
        "weaknesses":  "Vowel ratio is consistently ~0.4, which is detectable as a statistical signature.",
        "deception":   "Randomise the vowel/consonant ratio per domain generation cycle.",
    },
    "morse_code": {
        "explanation": "Converts random letters to Morse code dot/dash sequences, mapped to 'o'/'e' chars.",
        "usefulness":  "Highly unusual character distribution; not matched by standard entropy thresholds.",
        "strengths":   "Only two distinct characters; very low Shannon entropy — evades H > 3.8 detectors.",
        "weaknesses":  "Two-character alphabet is instantly recognisable in character-frequency analysis.",
        "deception":   "Map dots/dashes to random character pairs chosen at runtime.",
    },
    "emoji": {
        "explanation": "Uses emoji Unicode codepoints as the domain body (internationalized domains).",
        "usefulness":  "Exploits IDN support; the domain looks completely different in a browser vs raw DNS.",
        "strengths":   "Regex and string-matching detection tools that expect ASCII will fail completely.",
        "weaknesses":  "Many registrars reject emoji in domain labels; resolver support is inconsistent.",
        "deception":   "Encode as Punycode (XN--) to appear valid while being meaningless.",
    },
    "coordinate": {
        "explanation": "Converts random GPS coordinates to decimal strings used as domain names.",
        "usefulness":  "Produces numeric-heavy domains that look like CDN or IP-literal labels.",
        "strengths":   "Large coordinate space; hard to enumerate all possibilities.",
        "weaknesses":  "Digit-heavy domains are easy to flag with digit_ratio detection.",
        "deception":   "Apply a hash to the coordinate before using it as a domain body.",
    },
    "musical_notes": {
        "explanation": "Concatenates note+octave pairs (e.g. 'A3B2C4') as the domain body.",
        "usefulness":  "Restricted alphabet (A-G + 1-5) produces low-entropy but non-obvious domains.",
        "strengths":   "Character set is unusual; standard lowercase-only entropy detectors may miss it.",
        "weaknesses":  "Only 35 distinct characters; frequency analysis reveals the pattern immediately.",
        "deception":   "Add a SHA-256 postfix to the note sequence.",
    },
    "ranbyus": {
        "explanation": "Banking trojan DGA using 14-iteration LFSR bitwise mutation on day/year/seed integers. Real Ranbyus algorithm.",
        "usefulness":  "Extremely hard to reverse-engineer from output alone; all state is hidden.",
        "strengths":   "Non-linear state update; no hash function — pure integer arithmetic.",
        "weaknesses":  "If seed and date are known, all domains are computable. TLD selection leaks day-of-month.",
        "deception":   "Rotate seed daily via a secondary out-of-band channel.",
    },
    "dyre": {
        "explanation": "Banking trojan DGA. Date → MD5 hex seed → random.seed() → 1000-5000 domains/day. Real Dyre algorithm.",
        "usefulness":  "Massive domain pool (up to 5000/day) overwhelms takedown efforts.",
        "strengths":   "MD5 of date makes seeds unpredictable across days.",
        "weaknesses":  "Python random module is not cryptographically secure; seed derivable from date.",
        "deception":   "Use HMAC-SHA256 of date with a secret key instead of MD5.",
    },
    "dword_hex": {
        "explanation": "Random 32-bit unsigned integer converted to its 8-char hexadecimal representation (Cybereason variant).",
        "usefulness":  "Ultra-simple, no dependencies; looks like a memory address or process ID.",
        "strengths":   "Short, uniform domains; no discernible pattern without knowing the seed.",
        "weaknesses":  "Only 8 chars of hex; small domain space (~4 billion).",
        "deception":   "Use 64-bit values for a larger space; XOR with a secret mask.",
    },
    "punycode_like": {
        "explanation": "Generates XN--<random>-<constant suffix> format domains that look like internationalised names (Cybereason variant).",
        "usefulness":  "Exploits the Punycode namespace; many tools treat XN-- domains as legitimate.",
        "strengths":   "Most signature-based DGA blocklists do not cover Punycode-format domains.",
        "weaknesses":  "XN-- prefix is a fixed marker; the constant suffix leaks the variant.",
        "deception":   "Rotate the suffix portion and vary the numeric component.",
    },
    "word_prefix": {
        "explanation": "Constant English word prefix ('five', 'pop') + sequential number + random suffix. Cybereason Russian variant.",
        "usefulness":  "Prefix gives the domain a veneer of legitimacy; number advances deterministically.",
        "strengths":   "Passes 'contains real word' heuristics.",
        "weaknesses":  "The constant prefix is an instant signature once discovered.",
        "deception":   "Rotate the prefix word from a list, keyed on the day of week.",
    },
}

# ═══════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════

def _rnd(rng: random.Random, charset: str, length: int) -> str:
    return "".join(rng.choice(charset) for _ in range(length))


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _md5_hex(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def _pick_tld(pool: list, i: int) -> str:
    return pool[i % len(pool)]


# ═══════════════════════════════════════════════════════════════
#  1. ZODIAC-BASED DGA
# ═══════════════════════════════════════════════════════════════

def zodiac_dga(seed: int = 42, count: int = 10,
               min_len: int = 7, max_len: int = 14,
               tlds: list = None) -> List[str]:
    tlds = tlds or STANDARD_TLDS
    rng = random.Random(seed)
    domains = []
    for i in range(count):
        day   = rng.choice(ZODIAC_DAYS)
        month = rng.choice(ZODIAC_MONTHS)
        zsign = _zodiac_sign(day, month)
        raw   = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{zsign}.{rng.choice(['com','net'])}" )).lower().replace("-", "")
        h     = _sha256_hex(raw)
        llen  = rng.randint(min_len, max_len)
        body  = re.sub(r"[aeiou]", lambda _: rng.choice(string.ascii_lowercase + string.digits), h[:llen])
        tld   = _pick_tld(tlds, i)
        domains.append(body[:llen] + tld)
    return domains


def _zodiac_sign(day: int, month: str) -> str:
    m = month.lower()
    if m == "december":    return "sagittarius" if day < 22 else "capricorn"
    if m == "january":     return "capricorn"   if day < 20 else "aquarius"
    if m == "february":    return "aquarius"    if day < 19 else "pisces"
    if m == "march":       return "pisces"      if day < 21 else "aries"
    if m == "april":       return "aries"       if day < 20 else "taurus"
    if m == "may":         return "taurus"      if day < 21 else "gemini"
    if m == "june":        return "gemini"      if day < 21 else "cancer"
    if m == "july":        return "cancer"      if day < 23 else "leo"
    if m == "august":      return "leo"         if day < 23 else "virgo"
    if m == "september":   return "virgo"       if day < 23 else "libra"
    if m == "october":     return "libra"       if day < 23 else "scorpio"
    return                 "scorpio"            if day < 22 else "sagittarius"


# ═══════════════════════════════════════════════════════════════
#  2. TIME-BASED DGA (improved – uses date offset string)
# ═══════════════════════════════════════════════════════════════

def time_based_dga(count: int = 10, min_len: int = 5, max_len: int = 13,
                   tlds: list = None) -> List[str]:
    tlds = tlds or STANDARD_TLDS
    rng = random.Random(int(time.time()) // 86400)
    domains = []
    for i in range(count):
        offset = rng.randint(-30, 30)
        date_s = (datetime.utcnow() + timedelta(days=offset)).strftime("%Y%m%d")
        llen   = rng.randint(min_len, max_len)
        body   = (date_s * 3)[:llen]
        tld    = _pick_tld(tlds, i)
        domains.append(body + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  3. SEED-BASED DGA (MD5-chained)
# ═══════════════════════════════════════════════════════════════

def seed_based_dga(seed: str = "malware2026", count: int = 10,
                   min_len: int = 16, max_len: int = 19,
                   tlds: list = None) -> List[str]:
    tlds = tlds or STANDARD_TLDS
    rng = random.Random(seed)
    cur = seed
    domains = []
    for i in range(count):
        h    = _md5_hex(cur)
        llen = rng.randint(min_len, max_len)
        body = (h * 2)[:llen]
        tld  = _pick_tld(tlds, i)
        domains.append(body + tld)
        cur  = h
    return domains


# ═══════════════════════════════════════════════════════════════
#  4. DICTIONARY-BASED DGA
# ═══════════════════════════════════════════════════════════════

_DICT_CHARS = string.ascii_lowercase[:20]   # restricted alphabet

def dictionary_dga(count: int = 10, min_len: int = 5, max_len: int = 11,
                   tlds: list = None, seed: int = None) -> List[str]:
    tlds = tlds or STANDARD_TLDS
    rng = random.Random(seed or int(time.time()) // 86400)
    domains = []
    for i in range(count):
        llen = rng.randint(min_len, max_len)
        body = _rnd(rng, _DICT_CHARS, llen)
        tld  = _pick_tld(tlds, i)
        domains.append(body + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  5. PRNG-BASED DGA
# ═══════════════════════════════════════════════════════════════

def prng_dga(seed: int = 12345, count: int = 10,
             min_len: int = 8, max_len: int = 17,
             tlds: list = None) -> List[str]:
    tlds = tlds or STANDARD_TLDS
    rng = random.Random(seed)
    chars = string.ascii_lowercase + string.digits
    domains = []
    for i in range(count):
        llen = rng.randint(min_len, max_len)
        body = _rnd(rng, chars, llen)
        tld  = _pick_tld(tlds, i)
        domains.append(body + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  6. ARITHMETIC-BASED DGA
# ═══════════════════════════════════════════════════════════════

def arithmetic_dga(seed: int = 12345, count: int = 10,
                   min_len: int = 5, max_len: int = 15,
                   tlds: list = None) -> List[str]:
    tlds = tlds or STANDARD_TLDS
    rng = random.Random(seed)
    domains = []
    val = seed
    for i in range(count):
        val  = (val + rng.randint(1, 99991)) % (10 ** 15)
        llen = rng.randint(min_len, max_len)
        raw  = str(val)
        body = (raw * 3)[:llen]
        tld  = _pick_tld(tlds, i)
        domains.append(body + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  7. PERMUTATION-BASED DGA
# ═══════════════════════════════════════════════════════════════

def permutation_dga(base: str = "example", count: int = 10,
                    min_len: int = 6, max_len: int = 10,
                    tlds: list = None, seed: int = None) -> List[str]:
    tlds = tlds or STANDARD_TLDS
    import itertools
    chars = list(set(base))
    rng = random.Random(seed or 42)
    perms = list(itertools.permutations(chars, min(len(chars), 6)))
    rng.shuffle(perms)
    domains = []
    for i in range(count):
        p    = perms[i % len(perms)]
        llen = rng.randint(min_len, max_len)
        raw  = "".join(p)
        body = (raw * 3)[:llen]
        tld  = _pick_tld(tlds, i)
        domains.append(body + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  8. FIBONACCI-BASED DGA
# ═══════════════════════════════════════════════════════════════

def fibonacci_dga(count: int = 10, min_len: int = 10, max_len: int = 17,
                  tlds: list = None, seed: int = None) -> List[str]:
    tlds = tlds or STANDARD_TLDS
    rng = random.Random(seed or 42)
    chars = string.ascii_lowercase + string.digits + "XtkcZzVW"
    a, b = 0, 1
    domains = []
    for i in range(count):
        llen = rng.randint(min_len, max_len)
        body = ""
        while len(body) < llen:
            body += chars[a % len(chars)]
            a, b = b, a + b
        tld = _pick_tld(tlds, i)
        domains.append(body[:llen] + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  9. BASE32/BASE64 DGA
# ═══════════════════════════════════════════════════════════════

def base32_base64_dga(seed: str = "myseed", count: int = 10,
                      min_len: int = 7, max_len: int = 10,
                      encoding: str = "base64",
                      tlds: list = None) -> List[str]:
    tlds = tlds or STANDARD_TLDS
    rng = random.Random(seed)
    cur = seed
    domains = []
    for i in range(count):
        raw = cur.encode()
        if encoding == "base64":
            enc = base64.b64encode(raw).decode().lower().replace("=", "").replace("+", "x").replace("/", "y")
        else:
            enc = base64.b32encode(raw).decode().lower().replace("=", "")
        llen = rng.randint(min_len, max_len)
        sfx  = str(rng.randint(1000, 9999))
        body = (enc + sfx)[:llen]
        tld  = _pick_tld(tlds, i)
        domains.append(body + tld)
        cur  = cur[::-1] + str(i)
    return domains


# ═══════════════════════════════════════════════════════════════
#  10. WORDLIST DGA (Crowdstrike / Dridex style)
# ═══════════════════════════════════════════════════════════════

def wordlist_dga(count: int = 10, min_len: int = 7, max_len: int = 20,
                 tlds: list = None, seed: int = None) -> List[str]:
    tlds = tlds or [".net", ".me", ".mn"]
    rng = random.Random(seed or int(time.time()) // 86400)
    domains = []
    for i in range(count):
        w1 = rng.choice(WORDLIST)
        w2 = rng.choice(WORDLIST)
        pad = _rnd(rng, string.ascii_lowercase, rng.randint(0, 4))
        body = (w1 + w2 + pad)[:max_len]
        if len(body) < min_len:
            body += _rnd(rng, string.ascii_lowercase, min_len - len(body))
        tld = _pick_tld(tlds, i)
        domains.append(body.lower() + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  11. VOWEL-CONSONANT DGA (Pykspa-style)
# ═══════════════════════════════════════════════════════════════

_VOWELS     = "aeiou"
_CONSONANTS = "bcdfghjklmnpqrstvwxyz"

def vowel_consonant_dga(count: int = 10, min_len: int = 7, max_len: int = 12,
                        tlds: list = None, seed: int = None) -> List[str]:
    tlds = tlds or [".com", ".net", ".org", ".info", ".cc"]
    rng = random.Random(seed or int(time.time()) // 86400)
    domains = []
    for i in range(count):
        llen = rng.randint(min_len, max_len)
        body = ""
        for j in range(llen):
            body += rng.choice(_VOWELS if j % 2 == 0 else _CONSONANTS)
        tld = _pick_tld(tlds, i)
        domains.append(body + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  12. MORSE CODE DGA
# ═══════════════════════════════════════════════════════════════

def morse_code_dga(count: int = 10, min_len: int = 9, max_len: int = 16,
                   tlds: list = None, seed: int = None) -> List[str]:
    tlds = tlds or STANDARD_TLDS
    rng = random.Random(seed or int(time.time()) // 86400)
    DOT, DASH = "o", "e"
    domains = []
    for i in range(count):
        llen = rng.randint(min_len, max_len)
        body = ""
        while len(body) < llen:
            c  = rng.choice(string.ascii_lowercase)
            m  = MORSE_MAP.get(c, ".")
            for sym in m:
                body += DOT if sym == "." else DASH
        tld = _pick_tld(tlds, i)
        domains.append(body[:llen] + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  13. EMOJI DGA (stored as description strings for DNS compat)
# ═══════════════════════════════════════════════════════════════

_EMOJIS  = ["😀", "😂", "😍", "🤔", "🙌", "👍", "🎉", "🚀", "💡", "🌍"]
_E_NAMES = ["smile","laugh","heart","think","clap","thumb","party","rocket","idea","earth"]

def emoji_dga(count: int = 10, min_len: int = 10, max_len: int = 18,
              tlds: list = None, seed: int = None) -> List[str]:
    """
    Generates Punycode-compatible emoji-encoded domains.
    In real deployments these would be submitted as XN-- labels.
    """
    tlds = tlds or STANDARD_TLDS
    rng = random.Random(seed or int(time.time()) // 86400)
    domains = []
    for i in range(count):
        llen = rng.randint(min_len // 2, max_len // 2)
        body = "".join(rng.choice(_E_NAMES) for _ in range(llen))[:max_len]
        tld  = _pick_tld(tlds, i)
        domains.append(body + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  14. COORDINATE-BASED DGA
# ═══════════════════════════════════════════════════════════════

def coordinate_dga(count: int = 10, min_len: int = 9, max_len: int = 10,
                   tlds: list = None, seed: int = None) -> List[str]:
    tlds = tlds or STANDARD_TLDS
    rng = random.Random(seed or int(time.time()) // 86400)
    domains = []
    while len(domains) < count:
        lat  = round(rng.uniform(-90, 90), 4)
        lon  = round(rng.uniform(-180, 180), 4)
        body = f"{lat}{lon}".replace(".", "").replace("-", "")
        if min_len <= len(body) <= max_len:
            tld = _pick_tld(tlds, len(domains))
            domains.append(body + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  15. MUSICAL NOTES DGA
# ═══════════════════════════════════════════════════════════════

def musical_notes_dga(count: int = 10, min_len: int = 7, max_len: int = 9,
                      tlds: list = None, seed: int = None) -> List[str]:
    tlds = tlds or STANDARD_TLDS
    rng = random.Random(seed or int(time.time()) // 86400)
    domains = []
    for i in range(count):
        llen = rng.randint(min_len, max_len)
        body = ""
        while len(body) < llen:
            note = rng.choice(MUSICAL_NOTES)
            oct_ = rng.choice(MUSICAL_OCT)
            body += (note + oct_).lower()
        tld = _pick_tld(tlds, i)
        domains.append(body[:llen] + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  16. RANBYUS – LFSR bitwise mutation (real banking trojan DGA)
# ═══════════════════════════════════════════════════════════════

def ranbyus_dga(day: int = None, month: int = None, year: int = None,
                seed_hex: str = "deadbeef", count: int = 10) -> List[str]:
    """
    Exact Ranbyus DGA — matches the ericyoc ranbyus_dga_example.ipynb source.

    State variables day/month/year/seed are all mutated each character step:
      day   = (day >> 15) ^ 16 * (day & 0x1FFF ^ 4 * (seed ^ day))
      year  = ((year & 0xFFFFFFF0) << 17) ^ ((year ^ (7*year)) >> 11)
      month = 14 * (month & 0xFFFFFFFE) ^ ((month ^ (4*month)) >> 8)
      seed  = (seed >> 6) ^ ((day + 8*seed) << 8) & 0x3FFFF00
    Character: chr(((day ^ month ^ year) % 25) + 97)
    TLD: selected by tld_index, starting at day and incrementing per domain.
    """
    now   = datetime.utcnow()
    day   = day   or now.day
    month = month or now.month
    year  = year  or now.year
    seed  = int(seed_hex, 16)

    # State carries over between domains (not reset per domain — exact original behaviour)
    d, mo, y, s = day, month, year, seed
    tld_index   = day
    domains     = []

    for _ in range(count):
        domain = ""
        for _ in range(14):
            d  = (d >> 15) ^ 16 * (d & 0x1FFF ^ 4 * (s ^ d))
            y  = ((y & 0xFFFFFFF0) << 17) ^ ((y ^ (7 * y)) >> 11)
            mo = 14 * (mo & 0xFFFFFFFE) ^ ((mo ^ (4 * mo)) >> 8)
            s  = (s >> 6) ^ ((d + 8 * s) << 8) & 0x3FFFF00
            x  = ((d ^ mo ^ y) % 25) + 97
            domain += chr(x)
        tld = RANBYUS_TLDS[tld_index % 8]   # exact original uses % 8 on 9-element list
        domains.append(f"{domain}.{tld}")
        tld_index += 1

    return domains


# ═══════════════════════════════════════════════════════════════
#  17. DYRE – MD5-seed PRNG (real banking trojan DGA)
# ═══════════════════════════════════════════════════════════════

def dyre_dga(year: int = None, month: int = None, day: int = None,
             count: int = None, tld: str = ".com") -> List[str]:
    """
    Authentic Dyre DGA.
    Date → MD5 hex → seed Python random → generate 1000-5000 domains.
    """
    now   = datetime.utcnow()
    year  = year  or now.year
    month = month or now.month
    day   = day   or now.day

    date_str = f"{year}-{month:02d}-{day:02d}"
    md5_seed  = int(_md5_hex(date_str), 16) % (2 ** 31)
    rng       = random.Random(md5_seed)
    n         = count or rng.randint(1000, 5000)
    chars     = string.ascii_lowercase

    domains = []
    for _ in range(n):
        llen   = rng.randint(10, 25)
        domain = "".join(rng.choice(chars) for _ in range(llen))
        domains.append(domain + tld)
    return domains


def is_dyre_domain(domain: str, year: int = None, month: int = None, day: int = None) -> bool:
    generated = set(dyre_dga(year, month, day))
    return domain.split(":")[0] in generated


# ═══════════════════════════════════════════════════════════════
#  18. DWORD-HEX DGA (Cybereason variant)
# ═══════════════════════════════════════════════════════════════

def dword_hex_dga(count: int = 10,
                  tlds: list = None, seed: int = None) -> List[str]:
    """Random 32-bit int → 8-char hex domain (Cybereason DWORD variant)."""
    tlds = tlds or [".com", ".net", ".info"]
    rng  = random.Random(seed or int(time.time()) // 86400)
    domains = []
    for i in range(count):
        val  = rng.randint(0, 0xFFFFFFFF)
        body = f"{val:08X}".lower()
        tld  = _pick_tld(tlds, i)
        domains.append(body + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  19. PUNYCODE-LIKE DGA (Cybereason variant)
# ═══════════════════════════════════════════════════════════════

_PUNY_SUFFIX = "SJGB60AIGHL2I8JC3B0A2A97FTBLL0CZA"

def punycode_like_dga(count: int = 10,
                      tlds: list = None, seed: int = None) -> List[str]:
    """XN--ZALGO<random>-<constant suffix>.COM  (Cybereason XN-- variant)."""
    tlds = tlds or [".com"]
    rng  = random.Random(seed or int(time.time()) // 86400)
    domains = []
    for i in range(count):
        num  = rng.randint(100000, 999999)
        body = f"XN--ZALGO{num:06d}-{_PUNY_SUFFIX}".lower()
        tld  = _pick_tld(tlds, i)
        domains.append("www." + body + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  20. WORD-PREFIX DGA (Cybereason Russian variant)
# ═══════════════════════════════════════════════════════════════

_PREFIX_WORDS = ["five", "pop", "six", "cloud", "proxy", "api", "cdn"]

def word_prefix_dga(count: int = 10, min_len: int = 7, max_len: int = 14,
                    tlds: list = None, seed: int = None) -> List[str]:
    """Constant prefix word + sequential number + random suffix."""
    tlds = tlds or [".ru", ".com"]
    rng  = random.Random(seed or int(time.time()) // 86400)
    prefix = rng.choice(_PREFIX_WORDS)
    domains = []
    for i in range(count):
        num  = i + 1
        sfx  = _rnd(rng, string.ascii_lowercase, rng.randint(4, 8))
        body = f"{prefix}{num}{sfx}"[:max_len]
        tld  = _pick_tld(tlds, i)
        domains.append(body + tld)
    return domains


# ═══════════════════════════════════════════════════════════════
#  21. DDNS-AS-DGA  (Symmi pattern – random subdomain.ddns.net)
# ═══════════════════════════════════════════════════════════════

def ddns_subdomain_dga(count: int = 10, min_len: int = 8, max_len: int = 14,
                       ddns_provider: str = ".ddns.net",
                       seed: int = None) -> List[str]:
    """
    Symmi / Kraken pattern: random subdomains under a free DDNS provider.
    Zero registration cost; instant DNS propagation; hard to take down
    because the DDNS service itself is legitimate.
    """
    rng = random.Random(seed or int(time.time()) // 86400)
    chars = string.ascii_lowercase + string.digits
    domains = []
    for _ in range(count):
        llen = rng.randint(min_len, max_len)
        body = _rnd(rng, chars, llen)
        domains.append(body + ddns_provider)
    return domains


# ═══════════════════════════════════════════════════════════════
#  REGISTRY: map name → generator function
# ═══════════════════════════════════════════════════════════════

ALL_DGA_TYPES = {
    "zodiac":          zodiac_dga,
    "time_based":      time_based_dga,
    "seed_based":      seed_based_dga,
    "dictionary":      dictionary_dga,
    "prng":            prng_dga,
    "arithmetic":      arithmetic_dga,
    "permutation":     permutation_dga,
    "fibonacci":       fibonacci_dga,
    "base32_base64":   base32_base64_dga,
    "wordlist":        wordlist_dga,
    "vowel_consonant": vowel_consonant_dga,
    "morse_code":      morse_code_dga,
    "emoji":           emoji_dga,
    "coordinate":      coordinate_dga,
    "musical_notes":   musical_notes_dga,
    "ranbyus":         ranbyus_dga,
    "dyre":            dyre_dga,
    "dword_hex":       dword_hex_dga,
    "punycode_like":   punycode_like_dga,
    "word_prefix":     word_prefix_dga,
    "ddns_subdomain":  ddns_subdomain_dga,
}


# ═══════════════════════════════════════════════════════════════
#  REGEX EXTRACTION  (ericyoc dgas_to_regex approach)
# ═══════════════════════════════════════════════════════════════

def dgas_to_regex(domains: List[str]) -> str:
    """
    Derive a detecting regex from a sample of DGA domains.
    Method: character-frequency analysis across all domain bodies,
    separated into letter / digit / special buckets.
    High-frequency chars (count > 1) form the alternation groups.
    """
    bodies = [d.split(".")[0] for d in domains]
    freq   = Counter("".join(bodies))

    letters  = sorted(c for c in freq if c.isalpha()  and freq[c] > 1)
    digits   = sorted(c for c in freq if c.isdigit()  and freq[c] > 1)
    specials = sorted(c for c in freq if not c.isalpha() and not c.isdigit())

    parts = []
    if letters:
        parts.append("[" + "|".join(letters) + "]+")
    if digits:
        parts.append("[" + "|".join(digits)  + "]+")
    if specials:
        esc = "".join(re.escape(c) for c in specials)
        parts.append(f"[^{esc}]{{0,2}}")

    regex = "|".join(parts) + "{1,3}" if parts else "[a-z0-9]+"
    return regex


# ═══════════════════════════════════════════════════════════════
#  YARA RULE GENERATION  (ericyoc create_yara_rule)
# ═══════════════════════════════════════════════════════════════

def create_yara_rule(regex: str,
                     rule_name: str = "dga_domain_detection",
                     description: str = "Detects DGA-generated domain names",
                     dga_type: str = "unknown") -> str:
    """
    Generate a YARA rule from a DGA regex pattern.
    The rule fires when the regex matches a string in memory.
    """
    rule = f"""rule {rule_name} {{
    meta:
        description = "{description}"
        dga_type    = "{dga_type}"
        author      = "Angelware AUA Lab"
        date        = "{datetime.utcnow().strftime('%Y-%m-%d')}"
    strings:
        $dga_pattern = /{regex}/ nocase
    condition:
        $dga_pattern
}}
"""
    return rule


def generate_all_yara_rules(domains_per_type: int = 50,
                            output_path: str = "/tmp/dga_rules.yar") -> str:
    """Generate one YARA rule per DGA type and write them to a .yar file."""
    rules = []
    for name, fn in ALL_DGA_TYPES.items():
        try:
            domains = fn(count=min(domains_per_type, 50))
        except Exception:
            continue
        regex = dgas_to_regex(domains)
        rule  = create_yara_rule(
            regex,
            rule_name   = f"dga_{name}",
            description = DGA_ANALYSIS.get(name, {}).get("explanation", f"DGA type: {name}"),
            dga_type    = name,
        )
        rules.append(rule)
    combined = "\n".join(rules)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as fh:
        fh.write(combined)
    print(f"[YARA] {len(rules)} rules written to {output_path}")
    return combined


# ═══════════════════════════════════════════════════════════════
#  LABELED DATASET GENERATION
# ═══════════════════════════════════════════════════════════════

def generate_labeled_dataset(domains_per_type: int = 100,
                             output_csv: str = None) -> List[Tuple[str, str]]:
    """
    Generate a labeled dataset of DGA domains for ML training.
    Returns list of (domain, label) tuples where label is the DGA type name.
    Optionally writes a CSV.
    """
    rows: List[Tuple[str, str]] = []

    for name, fn in ALL_DGA_TYPES.items():
        try:
            if name == "dyre":
                # Dyre generates 1000-5000 per call; limit to domains_per_type
                domains = fn(count=domains_per_type)
            else:
                domains = fn(count=domains_per_type)
            for d in domains[:domains_per_type]:
                rows.append((d, name))
        except Exception as e:
            print(f"[DATASET] {name}: {e}")

    if output_csv:
        os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
        with open(output_csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["domain", "label"])
            w.writerows(rows)
        print(f"[DATASET] {len(rows)} rows written to {output_csv}")

    return rows


# ═══════════════════════════════════════════════════════════════
#  TABULAR SUMMARY  (ericyoc summarize_dga_functions)
# ═══════════════════════════════════════════════════════════════

def summarize_all():
    """Print a tabular overview of all DGA types with analysis."""
    col_w = [22, 45, 35, 35]
    hdr   = ["DGA Type", "Explanation", "Strengths", "Weaknesses"]
    sep   = "+" + "+".join("-" * w for w in col_w) + "+"

    def _trunc(s, n):
        return (s or "—")[:n-1].ljust(n-1)

    print(sep)
    print("|" + "|".join(_trunc(h, w) for h, w in zip(hdr, col_w)) + "|")
    print(sep)
    for name, info in DGA_ANALYSIS.items():
        row = [
            name,
            info.get("explanation", ""),
            info.get("strengths", ""),
            info.get("weaknesses", ""),
        ]
        print("|" + "|".join(_trunc(r, w) for r, w in zip(row, col_w)) + "|")
    print(sep)
    print(f"\nTotal DGA types implemented: {len(ALL_DGA_TYPES)}")


# ═══════════════════════════════════════════════════════════════
#  DEMO
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--summary":
        summarize_all()
    elif len(sys.argv) > 1 and sys.argv[1] == "--yara":
        generate_all_yara_rules(output_path="/tmp/dga_rules.yar")
    elif len(sys.argv) > 1 and sys.argv[1] == "--dataset":
        rows = generate_labeled_dataset(50, "/tmp/dga_dataset.csv")
        print(f"Generated {len(rows)} labeled domains.")
    else:
        print("=" * 60)
        print(" DGA Variants Library — AUA Botnet Research Lab")
        print("=" * 60)
        for name, fn in ALL_DGA_TYPES.items():
            try:
                samples = fn(count=3)
                print(f"\n  [{name}]")
                for s in samples:
                    print(f"    {s}")
                regex = dgas_to_regex(fn(count=20))
                print(f"    regex: {regex[:60]}")
            except Exception as e:
                print(f"  [{name}] ERROR: {e}")
        print("\nRun with --summary | --yara | --dataset")
