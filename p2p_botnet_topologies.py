"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: P2P Botnet Construction Topologies
 Environment: ISOLATED VM LAB ONLY
====================================================

Implements the three P2P botnet construction types from:
  Wang, Aslam, Zou — "Peer-to-Peer Botnets" (book chapter §1.3)

The chapter classifies P2P botnets by how they are built:

  1. PARASITE P2P BOTNET (§1.3.1)
     Targets hosts already inside an existing P2P network
     (e.g. Gnutella). No separate bootstrap step is needed —
     the botnet rides the existing overlay protocol. Scale is
     capped by the size of the host network.

  2. LEECHING P2P BOTNET (§1.3.3)
     Recruits victims from anywhere on the internet, then
     bootstraps them into an existing P2P network (e.g. Overnet)
     which is re-used for C&C. Larger scale but inherits the
     bootstrap vulnerability.

  3. BOT-ONLY P2P BOTNET (§1.3.3)
     Runs an entirely independent network (no legitimate peers).
     Most flexible; botmaster designs the protocol. This is
     what kademlia_p2p.c / p2p_node.py implement.

  4. HYBRID P2P BOTNET — bootstrap evasion (§1.3.2, Wang et al.)
     When bot A infects host B, A passes its peer list to B and
     B adds A to its list. No hard-coded seed addresses needed.
     The botnet bootstraps through the infection chain itself.

This module simulates all four types in memory and compares:
  - Bootstrap vulnerability exposure
  - Scale ceiling
  - C&C channel coupling
  - Resilience to bootstrap disruption

CLI:
  python3 p2p_botnet_topologies.py --demo               (all types)
  python3 p2p_botnet_topologies.py --type parasite       (single type)
  python3 p2p_botnet_topologies.py --type leeching
  python3 p2p_botnet_topologies.py --type bot_only
  python3 p2p_botnet_topologies.py --type hybrid
  python3 p2p_botnet_topologies.py --disrupt --type leeching
  python3 p2p_botnet_topologies.py --compare
"""

import argparse
import hashlib
import json
import os
import random
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

# ──────────────────────────────────────────────────────────────────
#  CONSTANTS
# ──────────────────────────────────────────────────────────────────

LEGIT_NETWORK_SIZE   = 500    # legitimate peers in simulated host P2P network
BOT_INFECTION_RATE   = 0.08   # fraction of legit peers infected (parasite)
LEECHING_BOTS        = 80     # bots recruited from internet (leeching)
BOOTSTRAP_LIST_SIZE  = 8      # hard-coded seeds per bot
K_NEIGHBORS          = 8      # peer list size per node

LOG_PATH = "/tmp/botnet_lab_topologies.log"


# ──────────────────────────────────────────────────────────────────
#  SHARED NODE PRIMITIVES
# ──────────────────────────────────────────────────────────────────

class SimNode:
    """
    In-memory simulation of a P2P network node.

    Attributes:
      nid         : unique node identifier (int)
      is_bot      : True if compromised
      peer_list   : known neighbor node IDs
      is_seed     : True if this node is a bootstrap seed
      received_cmd: set of commands successfully received
      online      : False if removed by defender
    """
    __slots__ = ("nid", "is_bot", "peer_list", "is_seed",
                 "received_cmd", "online", "is_ultrapeer")

    def __init__(self, nid: int, is_bot: bool = False, is_seed: bool = False):
        self.nid          = nid
        self.is_bot       = is_bot
        self.peer_list    = []          # list of nid ints
        self.is_seed      = is_seed
        self.received_cmd = set()
        self.online       = True
        self.is_ultrapeer = False


def _make_random_graph(nodes: List[SimNode], k: int = K_NEIGHBORS):
    """Wire nodes into a random k-regular-ish graph."""
    for n in nodes:
        candidates = [x.nid for x in nodes if x.nid != n.nid]
        n.peer_list = random.sample(candidates, min(k, len(candidates)))


def _print_sep(title: str = ""):
    line = "=" * 58
    if title:
        print(f"\n{line}")
        print(f"  {title}")
        print(line)
    else:
        print(line)


# ──────────────────────────────────────────────────────────────────
#  1. PARASITE P2P BOTNET
# ──────────────────────────────────────────────────────────────────

class ParasiteBotnet:
    """
    Teaching point (§1.3.1):
      Attacker targets hosts already inside an existing P2P network
      (e.g. Gnutella). After infection the bot communicates using
      the pre-existing P2P protocol — no extra bootstrap step is
      required, because the botnet is embedded in the overlay.

    Advantages:
      - Zero bootstrap vulnerability (no hard-coded seed list)
      - Indistinguishable from normal P2P traffic at protocol level
      - Immediate C&C access on infection

    Disadvantages:
      - Scale hard-capped at the size of the host P2P network
      - Passive infection spread (file-sharing worms, trojans in
        shared directories) — harder to control timing
      - Defenders can crawl the same overlay to find bots

    Real-world examples: Gnuman, VBS.Gnutella, SdDrop
    """

    def __init__(self, network_size: int = LEGIT_NETWORK_SIZE,
                 infection_rate: float = BOT_INFECTION_RATE):
        self.network_size   = network_size
        self.infection_rate = infection_rate
        self._nodes: Dict[int, SimNode] = {}
        self._bots:  List[SimNode]      = []

    def build(self) -> dict:
        """
        Simulate infection spreading inside an existing P2P network.

        Step 1: Create the legitimate P2P overlay (Gnutella-like)
        Step 2: Randomly designate a fraction as 'infected'
                (representing passive worm spread via shared dirs)
        Step 3: Bots communicate using the existing protocol —
                no bootstrap needed
        """
        print("\n[PARASITE] Building host P2P network...")
        # Create legitimate peers
        all_nodes = [SimNode(i) for i in range(self.network_size)]
        _make_random_graph(all_nodes, K_NEIGHBORS)
        for n in all_nodes:
            self._nodes[n.nid] = n

        # Infect a fraction via passive worm spread
        n_infected = int(self.network_size * self.infection_rate)
        infected   = random.sample(all_nodes, n_infected)
        for n in infected:
            n.is_bot = True
            self._bots.append(n)

        print(f"[PARASITE] Host network: {self.network_size} peers")
        print(f"[PARASITE] Infected:     {len(self._bots)} bots "
              f"({100*len(self._bots)/self.network_size:.1f}%)")
        print(f"[PARASITE] Bootstrap:    NONE — bots use existing "
              f"P2P protocol directly")
        print(f"[PARASITE] Scale ceiling: {self.network_size} "
              f"(capped by host network)")
        return self._summary()

    def inject_command(self, command: str = "syn_flood") -> dict:
        """
        Botmaster publishes a command as a fake 'file' in the
        shared overlay (pull mechanism — §1.4.1).  Bots searching
        for a pre-agreed file name retrieve the command payload.
        No direct contact with botmaster needed.
        """
        key = hashlib.sha1(command.encode()).hexdigest()[:8]
        print(f"\n[PARASITE] Injecting command '{command}' "
              f"via DHT key {key}...")
        # Botmaster stores command on a random bot
        seed_bot = random.choice(self._bots)
        seed_bot.received_cmd.add(command)

        # Propagation: query flooding through neighbor bots
        reached = {seed_bot.nid}
        frontier = deque([seed_bot])
        while frontier:
            n = frontier.popleft()
            for pid in n.peer_list:
                peer = self._nodes.get(pid)
                if peer and peer.is_bot and pid not in reached:
                    peer.received_cmd.add(command)
                    reached.add(pid)
                    frontier.append(peer)

        hit_rate = len(reached) / len(self._bots) * 100
        print(f"[PARASITE] Command reached {len(reached)}/{len(self._bots)} "
              f"bots ({hit_rate:.1f}%)")
        print(f"[PARASITE] Defender insight: no central server to seize —"
              f" but the same overlay can be crawled to enumerate bots")
        return {"reached": len(reached), "total": len(self._bots),
                "hit_rate": round(hit_rate, 1)}

    def defender_crawl(self) -> dict:
        """
        Defenders can crawl the shared overlay (same as any P2P
        researcher) to enumerate bots using behavioral signatures:
          - Periodic queries for the same cryptic hash key
          - Queries that never result in actual file downloads
        """
        print(f"\n[PARASITE] Defender crawling overlay for bots...")
        found = [n for n in self._nodes.values()
                 if n.is_bot and n.online]
        # Simulate detection accuracy (bots exhibit periodic
        # identical query patterns — §1.6.1)
        detected = [n for n in found
                    if random.random() < 0.70]  # 70% detection rate
        print(f"[PARASITE] Crawler found {len(detected)} of "
              f"{len(found)} bots (70% behavioral sig accuracy)")
        print(f"[PARASITE] Defense: crawl the same overlay the "
              f"botnet uses — no separate infiltration needed")
        return {"real_bots": len(found), "detected": len(detected)}

    def _summary(self) -> dict:
        return {"type": "parasite", "network_size": self.network_size,
                "bot_count": len(self._bots),
                "bootstrap_exposure": "NONE",
                "scale_ceiling": self.network_size}


# ──────────────────────────────────────────────────────────────────
#  2. LEECHING P2P BOTNET
# ──────────────────────────────────────────────────────────────────

class LeechingBotnet:
    """
    Teaching point (§1.3.3):
      Bots are recruited from anywhere on the internet (email,
      IM, drive-by download) and then bootstrap into an existing
      P2P protocol for C&C communication (e.g. Trojan.Peacomm
      bootstrapping onto Overnet).

    This gives internet-scale recruitment (no host-network size cap)
    but introduces a bootstrap vulnerability: the hard-coded seed
    list is a single point of failure defenders can exploit.

    Real-world examples: Trojan.Peacomm, Stormnet
    """

    def __init__(self, bot_count: int = LEECHING_BOTS,
                 seeds: int = BOOTSTRAP_LIST_SIZE):
        self.bot_count  = bot_count
        self.n_seeds    = seeds
        self._bots:  List[SimNode] = []
        self._seeds: List[SimNode] = []
        self._nodes: Dict[int, SimNode] = {}
        self._healthy = True

    def build(self) -> dict:
        """
        Step 1: Recruit bots from internet (any infected machine)
        Step 2: Each bot's binary contains hard-coded seed IPs
                (bootstrap list)
        Step 3: Bot contacts seeds to join the existing P2P network
        Step 4: Once joined, C&C runs over the existing protocol
        """
        print("\n[LEECHING] Building leeching P2P botnet...")

        # Create seed nodes (the bootstrap vulnerability)
        for i in range(self.n_seeds):
            s = SimNode(i, is_bot=True, is_seed=True)
            self._seeds.append(s)
            self._nodes[i] = s

        # Recruit bots from the internet
        for i in range(self.n_seeds, self.n_seeds + self.bot_count):
            b = SimNode(i, is_bot=True)
            # Each bot hard-codes the bootstrap seed list
            b.peer_list = [s.nid for s in self._seeds]
            self._bots.append(b)
            self._nodes[i] = b

        # After bootstrap: bots exchange peer lists and build mesh
        for b in self._bots:
            extra = random.sample(
                [x.nid for x in self._bots if x.nid != b.nid],
                min(K_NEIGHBORS - len(b.peer_list), len(self._bots) - 1)
            )
            b.peer_list.extend(extra)

        print(f"[LEECHING] Bot count:   {self.bot_count} "
              f"(internet-scale, no ceiling)")
        print(f"[LEECHING] Seeds:       {self.n_seeds} hard-coded IPs "
              f"in each bot binary")
        print(f"[LEECHING] BOOTSTRAP VULNERABILITY: if defender "
              f"obtains the binary and extracts seed IPs,")
        print(f"           they can shut down all {self.n_seeds} seeds "
              f"and halt growth of the botnet.")

        return self._summary()

    def disrupt_bootstrap(self) -> dict:
        """
        Defense: Defender reverses the bot binary, extracts the
        hard-coded seed IPs, and takes them down or null-routes them.
        New infections cannot join the botnet — it stops growing.

        This is the most cost-effective defense against leeching
        botnets (§1.6.3): you don't need to find all bots, just the
        small bootstrap list.
        """
        print(f"\n[LEECHING] === Bootstrap Disruption Attack ===")
        print(f"[LEECHING] Defender reversed the bot binary.")
        print(f"[LEECHING] Extracted {self.n_seeds} hard-coded seed IPs.")
        print(f"[LEECHING] Taking down all seed nodes...")

        for s in self._seeds:
            s.online = False

        # New infection attempt — all seeds offline
        new_bot = SimNode(99999, is_bot=True)
        new_bot.peer_list = [s.nid for s in self._seeds]

        can_join = any(self._nodes[pid].online
                       for pid in new_bot.peer_list
                       if pid in self._nodes)

        self._healthy = can_join

        print(f"[LEECHING] Seed nodes offline: "
              f"{self.n_seeds}/{self.n_seeds}")
        print(f"[LEECHING] New infection bootstrap: "
              f"{'SUCCESS' if can_join else 'FAILED — botnet cannot grow'}")
        print(f"[LEECHING] Existing {self.bot_count} bots still operational "
              f"(already joined before seeds went down)")
        print(f"[LEECHING] Teaching point: bootstrap disruption stops "
              f"GROWTH, not the existing botnet")

        return {"seeds_taken_down": self.n_seeds,
                "new_bots_can_join": can_join,
                "existing_bots_intact": self.bot_count}

    def _summary(self) -> dict:
        return {"type": "leeching", "bot_count": self.bot_count,
                "seed_count": self.n_seeds,
                "bootstrap_exposure": f"HIGH — {self.n_seeds} hard-coded seeds",
                "scale_ceiling": "NONE (internet-wide)"}


# ──────────────────────────────────────────────────────────────────
#  3. BOT-ONLY P2P BOTNET
# ──────────────────────────────────────────────────────────────────

class BotOnlyBotnet:
    """
    Teaching point (§1.3.3):
      Runs an entirely independent network with no legitimate peers.
      Botmaster designs the protocol (or adapts an existing one like
      Kademlia). Maximum flexibility.

    This is what kademlia_p2p.c / p2p_node.py implement.
    For the full implementation, run:
      python3 p2p_node.py --demo

    This class provides a lightweight in-memory simulation for
    comparison purposes.
    """

    def __init__(self, bot_count: int = 50, use_hardcoded_seeds: bool = True):
        self.bot_count          = bot_count
        self.use_hardcoded_seeds = use_hardcoded_seeds
        self._bots: List[SimNode] = []
        self._nodes: Dict[int, SimNode] = {}

    def build(self) -> dict:
        print("\n[BOT-ONLY] Building independent Kademlia-style botnet...")
        seeds = [SimNode(i, is_bot=True, is_seed=True)
                 for i in range(BOOTSTRAP_LIST_SIZE)]
        for s in seeds:
            self._nodes[s.nid] = s

        for i in range(BOOTSTRAP_LIST_SIZE, self.bot_count):
            b = SimNode(i, is_bot=True)
            if self.use_hardcoded_seeds:
                b.peer_list = [s.nid for s in seeds]
            b.is_bot = True
            self._bots.append(b)
            self._nodes[i] = b

        _make_random_graph(list(self._nodes.values()), K_NEIGHBORS)

        print(f"[BOT-ONLY] Bot count:   {self.bot_count}")
        print(f"[BOT-ONLY] Protocol:    custom Kademlia DHT")
        print(f"[BOT-ONLY] No legitimate peers — purely bot traffic")
        print(f"[BOT-ONLY] Bootstrap:   "
              f"{'hard-coded seeds (see hybrid for evasion)' if self.use_hardcoded_seeds else 'peer-list passing (hybrid mode)'}")
        return {"type": "bot_only", "bot_count": self.bot_count,
                "protocol": "custom_kademlia",
                "bootstrap_exposure": "HIGH (hard-coded seeds)" if self.use_hardcoded_seeds else "LOW (peer-list passing)"}


# ──────────────────────────────────────────────────────────────────
#  4. HYBRID BOTNET — BOOTSTRAP EVASION (Wang et al.)
# ──────────────────────────────────────────────────────────────────

class HybridBotnet:
    """
    Teaching point (§1.3.2, Wang et al. 2007):
      The advanced hybrid P2P botnet eliminates the bootstrap
      vulnerability by piggybacking peer-list exchange onto the
      infection process itself:

        1. Bot A infects host B.
        2. A passes its current peer_list to B.
        3. B adds A to its peer list.
        4. Any two bots that discover each other (via internet
           scanning) exchange peer lists.

      No hard-coded seed IPs in the binary. Defenders cannot
      disrupt the botnet simply by taking down a known seed list.

    Both pull and push C&C mechanisms are used:
      - PUSH: bot forwards command to everyone in its peer list
      - PULL: bots with private IPs or behind firewalls poll
              for commands periodically

    Reference: Wang, Sparks, Zou, HotBots 2007
    """

    def __init__(self, bot_count: int = 50):
        self.bot_count  = bot_count
        self._bots: List[SimNode] = []
        self._nodes: Dict[int, SimNode] = {}
        self._growth_log: List[dict] = []

    def build_via_infection_chain(self) -> dict:
        """
        Simulate botnet construction without any hard-coded seeds.

        Patient zero (bot 0) infects bot 1, passes its peer list,
        both bots' lists update. Bot 1 infects bot 2, etc.
        Each infected bot later scans for additional hosts and
        exchanges peer lists with them.
        """
        print("\n[HYBRID] Building hybrid botnet via infection-chain "
              "peer-list passing...")
        print("[HYBRID] NO hard-coded bootstrap seeds in the binary.")

        # Patient zero
        pz = SimNode(0, is_bot=True)
        self._bots.append(pz)
        self._nodes[0] = pz
        self._growth_log.append({"step": 0, "action": "patient_zero",
                                  "bot_count": 1})

        for i in range(1, self.bot_count):
            # Pick a random existing bot as the infector
            infector = random.choice(self._bots)
            victim   = SimNode(i, is_bot=True)

            # KEY MECHANISM: infector passes its peer_list to victim
            victim.peer_list = list(infector.peer_list)  # copy
            victim.peer_list.append(infector.nid)         # add infector

            # Infector adds victim to its own list
            infector.peer_list.append(victim.nid)
            if len(infector.peer_list) > K_NEIGHBORS * 2:
                infector.peer_list = infector.peer_list[-K_NEIGHBORS * 2:]

            self._bots.append(victim)
            self._nodes[i] = victim

            # Simulate random discovery: two existing bots find each
            # other and exchange lists (§1.3.2 second mechanism)
            if len(self._bots) > 5 and random.random() < 0.3:
                a, b = random.sample(self._bots, 2)
                merged = list(set(a.peer_list + b.peer_list) -
                              {a.nid, b.nid})
                a.peer_list = merged[:K_NEIGHBORS * 2]
                b.peer_list = merged[:K_NEIGHBORS * 2]

            if i % 10 == 0:
                self._growth_log.append(
                    {"step": i, "action": "infection_chain",
                     "bot_count": len(self._bots)}
                )

        # Trim all peer lists to K_NEIGHBORS
        for b in self._bots:
            random.shuffle(b.peer_list)
            b.peer_list = b.peer_list[:K_NEIGHBORS]

        # Verify: no node has an empty peer list except patient zero
        isolated = sum(1 for b in self._bots if not b.peer_list)

        print(f"[HYBRID] Botnet built: {len(self._bots)} bots")
        print(f"[HYBRID] Isolated nodes (no peers): {isolated}")
        print(f"[HYBRID] Binary contains NO bootstrap IPs")
        print(f"[HYBRID] Defender cannot disrupt bootstrap — "
              f"there is no bootstrap list to seize")
        return self._summary(isolated)

    def disrupt_bootstrap_attempt(self) -> dict:
        """
        Show that bootstrap disruption defense fails against the
        hybrid design: there are no seeds to take down.
        """
        print(f"\n[HYBRID] === Attempted Bootstrap Disruption ===")
        print(f"[HYBRID] Defender reverses bot binary...")
        print(f"[HYBRID] Scanning binary for hard-coded IPs...")
        print(f"[HYBRID] RESULT: No hard-coded IP addresses found.")
        print(f"[HYBRID] Bootstrap disruption defense: INEFFECTIVE")
        print(f"[HYBRID] The botnet grows through the infection chain "
              f"itself — every bot IS a de-facto seed for the next victim.")
        return {"defense": "bootstrap_disruption",
                "effective": False,
                "reason": "No hard-coded seeds; peer lists passed at infection time"}

    def inject_command_push(self, command: str = "syn_flood") -> dict:
        """
        Hybrid botnet uses PUSH mechanism:
        Botmaster injects command into a few bots (the entry points).
        Each bot forwards to all peers in its peer list.
        """
        print(f"\n[HYBRID] Injecting command '{command}' via PUSH...")
        # Botmaster pushes to 3 entry-point bots
        entry_points = random.sample(self._bots, min(3, len(self._bots)))
        reached = set()

        for ep in entry_points:
            ep.received_cmd.add(command)
            reached.add(ep.nid)

        # Each bot forwards to all peers (push flood)
        frontier = deque(entry_points)
        while frontier:
            n = frontier.popleft()
            for pid in n.peer_list:
                peer = self._nodes.get(pid)
                if peer and pid not in reached:
                    peer.received_cmd.add(command)
                    reached.add(pid)
                    frontier.append(peer)

        hit_rate = len(reached) / len(self._bots) * 100
        print(f"[HYBRID] PUSH command reached {len(reached)}/{len(self._bots)} "
              f"bots ({hit_rate:.1f}%)")
        return {"mechanism": "push", "reached": len(reached),
                "total": len(self._bots), "hit_rate": round(hit_rate, 1)}

    def _summary(self, isolated: int = 0) -> dict:
        return {"type": "hybrid", "bot_count": len(self._bots),
                "bootstrap_exposure": "NONE (peer-list passing)",
                "scale_ceiling": "NONE (internet-wide)",
                "isolated_nodes": isolated,
                "c2_mechanisms": ["push", "pull"]}


# ──────────────────────────────────────────────────────────────────
#  COMPARISON TABLE
# ──────────────────────────────────────────────────────────────────

def run_comparison():
    """
    Build all four botnet types and compare their properties.
    Reproduces the conceptual comparison from §1.3.3 Table.
    """
    _print_sep("P2P Botnet Construction Type Comparison")
    print("(Wang, Aslam, Zou — §1.3)")
    print()

    results = {}

    p = ParasiteBotnet(network_size=200, infection_rate=0.08)
    results["parasite"] = p.build()

    l = LeechingBotnet(bot_count=80, seeds=8)
    results["leeching"] = l.build()

    b = BotOnlyBotnet(bot_count=50)
    results["bot_only"] = b.build()

    h = HybridBotnet(bot_count=60)
    results["hybrid"] = h.build_via_infection_chain()

    _print_sep("Comparison Summary")
    col = "{:<14} {:<10} {:<34} {:<24}"
    print(col.format("Type", "Scale", "Bootstrap Exposure", "Scale Ceiling"))
    print("-" * 82)
    for t, r in results.items():
        bc  = r.get("bot_count", r.get("network_size", "?"))
        exp = r["bootstrap_exposure"]
        sc  = str(r.get("scale_ceiling", "?"))
        print(col.format(t, str(bc), exp[:33], sc[:23]))

    print()
    _print_sep("Key Findings")
    print("""
  PARASITE:  No bootstrap step needed; rides existing overlay.
             Scale capped by host network. Defender crawls same
             overlay to enumerate bots.

  LEECHING:  Internet-scale recruitment but hard-coded seeds are
             a single point of failure. Taking down seeds stops
             new infections (growth halts, existing bots survive).

  BOT-ONLY:  Maximum protocol flexibility. Same bootstrap
             vulnerability as leeching unless hybrid mode used.
             This is what kademlia_p2p.c implements.

  HYBRID:    Eliminates bootstrap vulnerability by passing the
             peer list through the infection chain. Most resilient
             construction method. Bootstrap disruption defense
             is entirely ineffective.
""")
    return results


# ──────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────────────────────────

def _run_type(botnet_type: str, disrupt: bool):
    if botnet_type == "parasite":
        b = ParasiteBotnet()
        b.build()
        b.inject_command()
        b.defender_crawl()

    elif botnet_type == "leeching":
        b = LeechingBotnet()
        b.build()
        if disrupt:
            b.disrupt_bootstrap()
        else:
            print("[LEECHING] Tip: run with --disrupt to demo "
                  "bootstrap disruption defense")

    elif botnet_type == "bot_only":
        b = BotOnlyBotnet()
        b.build()

    elif botnet_type == "hybrid":
        b = HybridBotnet()
        b.build_via_infection_chain()
        if disrupt:
            b.disrupt_bootstrap_attempt()
        b.inject_command_push()

    else:
        print(f"Unknown type: {botnet_type}")
        sys.exit(1)


if __name__ == "__main__":
    print("=" * 60)
    print(" P2P Botnet Topologies — AUA CS 232/337 Research Lab")
    print(" ISOLATED VM ONLY")
    print("=" * 60)

    parser = argparse.ArgumentParser(
        description="P2P Botnet Construction Topology Simulator"
    )
    parser.add_argument("--demo",    action="store_true",
                        help="Run all four types in sequence")
    parser.add_argument("--compare", action="store_true",
                        help="Side-by-side comparison table")
    parser.add_argument("--type",    default="hybrid",
                        choices=["parasite","leeching","bot_only","hybrid"],
                        help="Which topology to run (default: hybrid)")
    parser.add_argument("--disrupt", action="store_true",
                        help="Demo bootstrap disruption defense")
    args = parser.parse_args()

    if args.compare:
        run_comparison()
    elif args.demo:
        for t in ["parasite", "leeching", "bot_only", "hybrid"]:
            _run_type(t, disrupt=(t in ["leeching","hybrid"]))
            print()
        run_comparison()
    else:
        _run_type(args.type, args.disrupt)
