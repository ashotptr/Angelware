"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Unstructured P2P C&C + Push Mechanism
 Environment: ISOLATED VM LAB ONLY
====================================================

Implements the unstructured P2P C&C mechanisms described in:
  Wang, Aslam, Zou — "Peer-to-Peer Botnets" §1.4.1

Fills the following gaps NOT covered by p2p_node.py
(which is DHT/structured only):

  1. UNSTRUCTURED P2P C&C (Gnutella-style)
     No DHT. Queries are FLOODED across the network with a
     TTL. Every ultrapeer forwards queries. A query hit
     returns the address holding the command.

  2. PUSH MECHANISM
     Botmaster injects a command into entry-point bots.
     Each bot forwards to all peers — no periodic polling,
     no DHT lookup. The command propagates like a flood.

  3. PULL vs PUSH COMPARISON
     Side-by-side timing and detectability analysis showing
     the detection/efficiency tradeoff (§1.4.1):
       PULL:  periodic polling is easy to detect by timing
              (IDS Engine 2 in ids_detector.py triggers on
               periodic same-key queries)
       PUSH:  one-shot forwarding, no polling pattern —
              harder to detect but slower and lossy

  4. IN-BAND vs OUT-OF-BAND FORWARDING
     IN-BAND:  command disguised as a normal P2P query
               — flows through existing overlay traffic
               — virtually undetectable by DPI alone
     OUT-OF-BAND: bot contacts targets directly via a
               separate channel (non-P2P traffic)
               — faster but reveals bot identity to DPI

  5. POPULAR FILE WATCHWORD TRICK
     Bots advertise ownership of a set of popular fake files.
     When forwarding a command, a bot searches for those files
     — the responding peers are likely bots.
     Increases command reach in mixed (legitimate + bot) networks.

CLI:
  python3 p2p_unstructured.py --demo
  python3 p2p_unstructured.py --mode pull   [--ttl N]
  python3 p2p_unstructured.py --mode push
  python3 p2p_unstructured.py --mode inband
  python3 p2p_unstructured.py --mode outofband
  python3 p2p_unstructured.py --mode watchword
  python3 p2p_unstructured.py --compare
"""

import argparse
import hashlib
import json
import os
import random
import sys
import time
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple

# ──────────────────────────────────────────────────────────────────
#  CONSTANTS — chosen to match Gnutella empirical values (§1.5.2)
# ──────────────────────────────────────────────────────────────────

N_ULTRAPEERS       = 60      # ultrapeer count (top-level overlay)
N_LEAVES_PER_ULTRA = 8       # leaf peers per ultrapeer
ULTRAPEER_DEGREE   = 6       # connections between ultrapeers
BOT_FRACTION       = 0.25    # fraction of network that is bots
DEFAULT_TTL        = 7       # query TTL (LimeWire default)
POLL_INTERVAL      = 30      # pull: seconds between polls

# Watchword: set of popular fake file hashes bots advertise
WATCHWORD_FILES = [
    "a3f8c2e1d4b5",  "9c7e4a2b3d1f",  "e5f2a8c3b7d4",
    "b6d1e9f3a2c5",  "c4a7e2f1b8d3",  "d2b5f9a4c1e7",
]

LOG = "/tmp/botnet_lab_unstructured.log"


# ──────────────────────────────────────────────────────────────────
#  NETWORK TOPOLOGY — Two-Tier Gnutella-Like Overlay
# ──────────────────────────────────────────────────────────────────

class UltraPeer:
    """
    Represents one ultrapeer in the Gnutella two-tier topology.

    Ultrapeers forward all queries (leaf peers cannot).
    Each ultrapeer maintains a table of file hashes available
    on its leaf peers (Bloom filter in real Gnutella).

    In a parasite botnet, some ultrapeers are compromised.
    In a bot-only/leeching botnet, separate logic applies.
    """
    __slots__ = ("uid", "is_bot", "neighbors", "leaves",
                 "file_index", "received_cmd", "online",
                 "query_log")

    def __init__(self, uid: int, is_bot: bool = False):
        self.uid          = uid
        self.is_bot       = is_bot
        self.neighbors: List[int] = []   # neighboring ultrapeer UIDs
        self.leaves: List["LeafPeer"]  = []
        self.file_index: Set[str] = set()
        self.received_cmd = set()
        self.online       = True
        self.query_log: List[tuple] = []  # (ts, key, origin_uid)


class LeafPeer:
    """
    Leaf peers in the Gnutella two-tier overlay.
    They connect to exactly one ultrapeer (their "local server").
    They cannot forward queries.
    """
    __slots__ = ("lid", "ultrapeer_uid", "is_bot",
                 "shared_files", "received_cmd")

    def __init__(self, lid: int, ultrapeer_uid: int, is_bot: bool = False):
        self.lid             = lid
        self.ultrapeer_uid   = ultrapeer_uid
        self.is_bot          = is_bot
        self.shared_files: Set[str] = set()
        self.received_cmd    = set()


class GnutellaOverlay:
    """
    Simulates a two-tier Gnutella-style unstructured P2P network.

    Architecture (§1.2 Table 1.2):
      - Partially decentralized (Gnutella after 2001)
      - Unstructured: no mapping between content and location
      - Two tiers: ultrapeers (forward queries) + leaf peers

    Used by both unstructured botnet C&C demonstrations.
    """

    def __init__(self,
                 n_ultra: int = N_ULTRAPEERS,
                 n_leaves: int = N_LEAVES_PER_ULTRA,
                 bot_fraction: float = BOT_FRACTION):
        self.ultrapeers: Dict[int, UltraPeer] = {}
        self.leaves: Dict[int, LeafPeer] = {}
        self.bot_ultra_ids: List[int] = []
        self.bot_leaf_ids:  List[int] = []
        self._build(n_ultra, n_leaves, bot_fraction)

    def _build(self, n_ultra, n_leaves, bot_fraction):
        n_bot_ultra = int(n_ultra * bot_fraction)
        bot_uids    = set(random.sample(range(n_ultra), n_bot_ultra))

        for uid in range(n_ultra):
            is_bot = uid in bot_uids
            up = UltraPeer(uid, is_bot=is_bot)
            if is_bot:
                self.bot_ultra_ids.append(uid)
            self.ultrapeers[uid] = up

        # Wire ultrapeer-to-ultrapeer connections
        for uid, up in self.ultrapeers.items():
            candidates = [x for x in self.ultrapeers
                          if x != uid and x not in up.neighbors]
            up.neighbors = random.sample(
                candidates, min(ULTRAPEER_DEGREE, len(candidates))
            )

        # Create leaf peers
        lid = 0
        for uid, up in self.ultrapeers.items():
            n_bot_leaves = int(n_leaves * bot_fraction)
            for i in range(n_leaves):
                is_bot = (i < n_bot_leaves) and up.is_bot
                lp = LeafPeer(lid, uid, is_bot=is_bot)
                if is_bot:
                    self.bot_leaf_ids.append(lid)
                up.leaves.append(lp)
                self.leaves[lid] = lp
                lid += 1

        # Build ultrapeer file indexes from leaf inventories
        for up in self.ultrapeers.values():
            for lp in up.leaves:
                # Bots also advertise watchword files
                if lp.is_bot:
                    lp.shared_files.update(WATCHWORD_FILES[:2])
                for fh in lp.shared_files:
                    up.file_index.add(fh)

    def total_bots(self) -> int:
        return len(self.bot_ultra_ids) + len(self.bot_leaf_ids)

    def total_nodes(self) -> int:
        return len(self.ultrapeers) + len(self.leaves)

    def summary(self) -> str:
        return (f"Overlay: {len(self.ultrapeers)} ultrapeers + "
                f"{len(self.leaves)} leaf peers | "
                f"bots: {self.total_bots()} / {self.total_nodes()} "
                f"({100*self.total_bots()/self.total_nodes():.1f}%)")


# ──────────────────────────────────────────────────────────────────
#  1. PULL MECHANISM — Query Flooding (§1.4.1)
# ──────────────────────────────────────────────────────────────────

class PullC2:
    """
    Teaching point (§1.4.1 Pull Mechanism):
      Bots periodically query the Gnutella overlay for a
      predetermined file key.  The botmaster publishes the
      command on a bot, which declares it has that 'file'.
      When a querying bot gets a query-hit, it fetches the
      command from the declared address.

    Detection (§1.6.1):
      IDS can detect bots by observing:
        - Periodic queries for the SAME cryptic hash key
        - Queries that never result in actual downloads
        - High query rate but no upload activity

    This is analogous to Trojan.Peacomm / Stormnet (§1.4.1):
      "Each bot periodically queries a search key calculated
       by a built-in algorithm that takes the current date..."
    """

    COMMAND_FILE_KEY = "3d1f9a2c7b4e"   # pre-shared key in bot code

    def __init__(self, overlay: GnutellaOverlay, ttl: int = DEFAULT_TTL):
        self.overlay    = overlay
        self.ttl        = ttl
        self._query_log: List[dict] = []

    def botmaster_publish(self, command: str) -> dict:
        """Botmaster picks a random bot and declares it has COMMAND_FILE_KEY."""
        if not self.overlay.bot_ultra_ids:
            return {"error": "no_bots"}
        publisher_uid = random.choice(self.overlay.bot_ultra_ids)
        publisher     = self.overlay.ultrapeers[publisher_uid]
        publisher.file_index.add(self.COMMAND_FILE_KEY)
        # Store command in the publisher's 'file'
        publisher.received_cmd.add(command)
        print(f"[PULL] Botmaster published command '{command}' "
              f"on ultrapeer {publisher_uid}")
        print(f"[PULL] Key: {self.COMMAND_FILE_KEY} "
              f"(hard-coded in bot binary — §1.4.1 detection risk)")
        return {"publisher": publisher_uid, "key": self.COMMAND_FILE_KEY}

    def bot_poll(self, querier_uid: int, command: str) -> Optional[str]:
        """
        One bot (ultrapeer) floods a query for COMMAND_FILE_KEY.
        Query hops through the overlay with TTL decrement.
        Returns the command if a query-hit is received.
        """
        visited: Set[int] = {querier_uid}
        queue   = deque([(querier_uid, self.ttl)])
        ts      = time.time()

        while queue:
            uid, ttl = queue.popleft()
            up = self.overlay.ultrapeers.get(uid)
            if not up or not up.online:
                continue
            up.query_log.append((ts, self.COMMAND_FILE_KEY, querier_uid))

            # Check if this ultrapeer can answer the query
            if self.COMMAND_FILE_KEY in up.file_index:
                # Query hit — return command
                cmd_val = command if command in up.received_cmd else None
                if cmd_val:
                    self._query_log.append({
                        "querier": querier_uid, "responder": uid,
                        "key": self.COMMAND_FILE_KEY, "ts": ts
                    })
                    return cmd_val

            if ttl <= 1:
                continue
            # Forward to neighboring ultrapeers (flood)
            for nid in up.neighbors:
                if nid not in visited:
                    visited.add(nid)
                    queue.append((nid, ttl - 1))

        return None

    def run_poll_round(self, command: str) -> dict:
        """All bot ultrapeers poll. Shows detection pattern."""
        found    = 0
        not_found = 0
        query_times = []

        for uid in self.overlay.bot_ultra_ids:
            t0 = time.time()
            result = self.bot_poll(uid, command)
            query_times.append(time.time() - t0)
            if result:
                self.overlay.ultrapeers[uid].received_cmd.add(command)
                found += 1
            else:
                not_found += 1

        avg_q = sum(query_times) / len(query_times) if query_times else 0
        print(f"[PULL] Poll round: {found} bots received command, "
              f"{not_found} missed | avg query time: {avg_q*1000:.1f}ms")
        print(f"[PULL] ⚠ IDS detection risk: all {len(self.overlay.bot_ultra_ids)}"
              f" bot ultrapeers queried the SAME key within {avg_q*len(self.overlay.bot_ultra_ids):.2f}s")
        print(f"[PULL] Defense: IDS Engine 2 periodic-query detection "
              f"(ids_detector.py) fires on this pattern")
        return {"found": found, "not_found": not_found,
                "avg_query_ms": round(avg_q * 1000, 2)}


# ──────────────────────────────────────────────────────────────────
#  2. PUSH MECHANISM — Command Forwarding (§1.4.1)
# ──────────────────────────────────────────────────────────────────

class PushC2:
    """
    Teaching point (§1.4.1 Push Mechanism):
      Botmaster injects command directly into a small number of
      bots (entry points). Those bots forward to ALL their
      neighbors — including non-bots in a mixed network.
      Each receiving bot that IS a bot will further forward.

    Design issues addressed (§1.4.1):
      1. WHICH peers to forward to?
         Option A: current neighbors (simple but slow in sparse bots)
         Option B: peers who respond to watchword file queries
                   (see WatchwordPushC2)
      2. IN-BAND or OUT-OF-BAND?
         In-band: command disguised as normal query — undetectable
         Out-of-band: direct TCP to target — fast but bot-revealing
    """

    def __init__(self, overlay: GnutellaOverlay):
        self.overlay     = overlay
        self.entry_count = 3   # bots that receive command first

    def inject(self, command: str, mode: str = "inband") -> dict:
        """
        Inject command into the overlay via push.

        mode='inband'    — command travels as a fake query message
                           (mixed with normal overlay traffic — §1.4.1)
        mode='outofband' — bot contacts target directly
                           (faster, but out-of-band traffic is
                            detectable by DPI — §1.4.1)
        """
        if not self.overlay.bot_ultra_ids:
            return {"error": "no_bots"}

        entry_points = random.sample(
            self.overlay.bot_ultra_ids,
            min(self.entry_count, len(self.overlay.bot_ultra_ids))
        )
        reached: Set[int] = set(entry_points)
        direct_contacts: List[Tuple[int, int]] = []  # (src, dst) out-of-band

        # Mark entry points as having received command
        for uid in entry_points:
            self.overlay.ultrapeers[uid].received_cmd.add(command)

        # BFS push through neighbor bots
        frontier = deque(entry_points)
        while frontier:
            uid = frontier.popleft()
            up  = self.overlay.ultrapeers[uid]
            for nid in up.neighbors:
                peer = self.overlay.ultrapeers.get(nid)
                if not peer or not peer.online:
                    continue
                if nid not in reached:
                    if mode == "outofband":
                        direct_contacts.append((uid, nid))
                    peer.received_cmd.add(command)
                    reached.add(nid)
                    if peer.is_bot:
                        frontier.append(nid)

        hit_rate = len(reached) / len(self.overlay.bot_ultra_ids) * 100
        n_nonbot = sum(1 for uid in reached
                       if not self.overlay.ultrapeers[uid].is_bot)

        print(f"\n[PUSH/{mode.upper()}] Command '{command}' forwarded")
        print(f"[PUSH/{mode.upper()}] Reached bots: "
              f"{len(reached) - n_nonbot}/{len(self.overlay.bot_ultra_ids)} "
              f"({hit_rate:.1f}%)")
        print(f"[PUSH/{mode.upper()}] Non-bot peers that also saw command: "
              f"{n_nonbot} (collateral — harmless but wastes bandwidth)")

        if mode == "outofband":
            print(f"[PUSH/OUTOFBAND] ⚠ Direct TCP connections created: "
                  f"{len(direct_contacts)}")
            print(f"[PUSH/OUTOFBAND] Each direct connection reveals the "
                  f"initiating bot's IP to DPI — detectability HIGH")
        else:
            print(f"[PUSH/INBAND] Command disguised as P2P query — "
                  f"indistinguishable from normal overlay traffic")
            print(f"[PUSH/INBAND] Detectability: LOW (needs behavioral "
                  f"analysis, not just DPI)")

        return {"mode": mode, "reached": len(reached),
                "bot_hit_rate": round(hit_rate, 1),
                "nonbot_leakage": n_nonbot,
                "direct_connections": len(direct_contacts)}


# ──────────────────────────────────────────────────────────────────
#  3. WATCHWORD / POPULAR FILE TRICK (§1.4.1)
# ──────────────────────────────────────────────────────────────────

class WatchwordPushC2:
    """
    Teaching point (§1.4.1 Watchword):
      In a mixed network (bots + legitimate peers), a bot trying
      to push a command to its neighbors cannot be sure which
      neighbors are actually bots.

      Solution: bots advertise ownership of a set of pre-agreed
      POPULAR FILE NAMES (watchwords). When a bot wants to forward
      a command, it first searches for those popular files.
      The peers who respond are very likely bots (since only bots
      advertise the watchwords).

      Risk: this gives defenders a clue — searching for the same
      unusual combination of files is a bot-detection signature.
    """

    def __init__(self, overlay: GnutellaOverlay, ttl: int = DEFAULT_TTL):
        self.overlay     = overlay
        self.ttl         = ttl

    def setup_watchwords(self):
        """Give all bots the watchword file entries in their index."""
        bot_count = 0
        for uid in self.overlay.bot_ultra_ids:
            up = self.overlay.ultrapeers[uid]
            up.file_index.update(WATCHWORD_FILES)
            bot_count += 1
        print(f"[WATCHWORD] {bot_count} bot ultrapeers now advertise "
              f"{len(WATCHWORD_FILES)} watchword files")
        print(f"[WATCHWORD] Watchwords: {WATCHWORD_FILES[:3]}...")

    def find_bots_via_watchword(self, sender_uid: int) -> List[int]:
        """
        Bot searches for WATCHWORD_FILES.  Peers who respond to
        *all* watchwords are highly likely to be bots.
        Returns list of suspected bot UIDs.
        """
        # Flood query for one watchword
        target_key = random.choice(WATCHWORD_FILES)
        responders: Set[int] = set()
        visited    = {sender_uid}
        queue      = deque([(sender_uid, self.ttl)])

        while queue:
            uid, ttl = queue.popleft()
            up = self.overlay.ultrapeers.get(uid)
            if not up or not up.online:
                continue
            if target_key in up.file_index:
                responders.add(uid)
            if ttl <= 1:
                continue
            for nid in up.neighbors:
                if nid not in visited:
                    visited.add(nid)
                    queue.append((nid, ttl - 1))

        # Filter: peers that respond to ALL watchwords = likely bots
        confirmed_bots = [
            uid for uid in responders
            if WATCHWORD_FILES[0] in self.overlay.ultrapeers[uid].file_index
            and WATCHWORD_FILES[1] in self.overlay.ultrapeers[uid].file_index
        ]
        return confirmed_bots

    def push_via_watchword(self, command: str) -> dict:
        """
        1. Sender searches for watchword-responding peers (likely bots)
        2. Sends command ONLY to those peers (higher bot hit rate,
           less collateral to legitimate peers)
        """
        if not self.overlay.bot_ultra_ids:
            return {"error": "no_bots"}

        sender_uid = random.choice(self.overlay.bot_ultra_ids)
        bot_targets = self.find_bots_via_watchword(sender_uid)

        # Forward command to confirmed targets
        for uid in bot_targets:
            up = self.overlay.ultrapeers.get(uid)
            if up and up.online:
                up.received_cmd.add(command)

        real_bots_hit = sum(
            1 for uid in bot_targets
            if self.overlay.ultrapeers[uid].is_bot
        )
        false_positives = len(bot_targets) - real_bots_hit
        hit_rate = (real_bots_hit / len(self.overlay.bot_ultra_ids) * 100
                    if self.overlay.bot_ultra_ids else 0)

        print(f"\n[WATCHWORD] Sender bot: ultrapeer {sender_uid}")
        print(f"[WATCHWORD] Watchword query found {len(bot_targets)} "
              f"candidate bots")
        print(f"[WATCHWORD] Real bots hit: {real_bots_hit} "
              f"({hit_rate:.1f}% of all bots)")
        print(f"[WATCHWORD] False positives (non-bots): {false_positives}")
        print(f"[WATCHWORD] ⚠ Defender can search for same watchword files "
              f"to identify bot peers — detection risk MEDIUM")

        return {"bot_targets_found": len(bot_targets),
                "real_bots_hit": real_bots_hit,
                "false_positives": false_positives,
                "hit_rate": round(hit_rate, 1)}


# ──────────────────────────────────────────────────────────────────
#  4. PULL vs PUSH COMPARISON
# ──────────────────────────────────────────────────────────────────

def run_comparison(n_ultra: int = 60, bot_fraction: float = 0.25):
    """
    Side-by-side comparison of pull and push mechanisms,
    showing the detection/efficiency tradeoff from §1.4.1.
    """
    print("\n" + "=" * 60)
    print("  Pull vs Push C&C Comparison — §1.4.1 Tradeoff")
    print("=" * 60)

    overlay = GnutellaOverlay(n_ultra, N_LEAVES_PER_ULTRA, bot_fraction)
    print(overlay.summary())
    print()

    command = "syn_flood"
    results = {}

    # --- PULL ---
    print("── PULL MECHANISM ─────────────────────────────────────")
    pull = PullC2(overlay)
    pull.botmaster_publish(command)
    r_pull = pull.run_poll_round(command)
    results["pull"] = r_pull

    # --- PUSH (in-band) ---
    print("\n── PUSH MECHANISM (in-band) ────────────────────────────")
    push_ib = PushC2(overlay)
    r_push_ib = push_ib.inject(command, mode="inband")
    results["push_inband"] = r_push_ib

    # --- PUSH (out-of-band) ---
    print("\n── PUSH MECHANISM (out-of-band) ────────────────────────")
    push_ob = PushC2(overlay)
    r_push_ob = push_ob.inject(command, mode="outofband")
    results["push_outofband"] = r_push_ob

    # --- WATCHWORD PUSH ---
    print("\n── WATCHWORD PUSH ──────────────────────────────────────")
    ww = WatchwordPushC2(overlay)
    ww.setup_watchwords()
    r_ww = ww.push_via_watchword(command)
    results["watchword_push"] = r_ww

    # Summary table
    print("\n" + "=" * 60)
    print("  Summary Table")
    print("=" * 60)
    row = "{:<20} {:>12} {:>14} {:>12}"
    print(row.format("Mechanism", "Bot Hit %", "Direct Conns", "Detectability"))
    print("-" * 60)
    print(row.format("Pull (poll)",
                     f"{r_pull['found']}/{len(overlay.bot_ultra_ids)}",
                     "0",
                     "HIGH (timing)"))
    print(row.format("Push in-band",
                     f"{r_push_ib['bot_hit_rate']}%",
                     "0",
                     "LOW (DPI)"))
    print(row.format("Push out-of-band",
                     f"{r_push_ob['bot_hit_rate']}%",
                     str(r_push_ob['direct_connections']),
                     "HIGH (DPI)"))
    print(row.format("Watchword push",
                     f"{r_ww['hit_rate']}%",
                     "0",
                     "MEDIUM"))
    print()
    print("Teaching point (§1.4.1):")
    print("  Botmasters face an inherent tradeoff:")
    print("  - Pull polling is efficient but timing is detectable")
    print("  - Push in-band is stealthy but requires existing neighbor bots")
    print("  - Out-of-band push reveals bot identity via DPI")
    print("  - Watchword improves targeting but creates a detection signature")

    return results


# ──────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────────────────────────

def _run_mode(mode: str, ttl: int):
    overlay = GnutellaOverlay()
    print(overlay.summary())
    command = "syn_flood"

    if mode == "pull":
        pull = PullC2(overlay, ttl=ttl)
        pull.botmaster_publish(command)
        pull.run_poll_round(command)

    elif mode == "push":
        push = PushC2(overlay)
        push.inject(command, mode="inband")

    elif mode == "inband":
        push = PushC2(overlay)
        push.inject(command, mode="inband")

    elif mode == "outofband":
        push = PushC2(overlay)
        push.inject(command, mode="outofband")

    elif mode == "watchword":
        ww = WatchwordPushC2(overlay, ttl=ttl)
        ww.setup_watchwords()
        ww.push_via_watchword(command)

    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)


if __name__ == "__main__":
    print("=" * 60)
    print(" Unstructured P2P C&C Simulator — AUA CS 232/337 Lab")
    print(" ISOLATED VM ONLY")
    print("=" * 60)

    parser = argparse.ArgumentParser(
        description="Unstructured P2P C&C Mechanisms (§1.4.1)"
    )
    parser.add_argument("--demo",    action="store_true")
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--mode",    default="push",
                        choices=["pull","push","inband","outofband","watchword"])
    parser.add_argument("--ttl",     type=int, default=DEFAULT_TTL,
                        help=f"Query TTL (default: {DEFAULT_TTL})")
    parser.add_argument("--bots",    type=float, default=BOT_FRACTION,
                        help="Bot fraction (default: 0.25)")
    args = parser.parse_args()

    if args.compare or args.demo:
        run_comparison(bot_fraction=args.bots)
    else:
        _run_mode(args.mode, args.ttl)
