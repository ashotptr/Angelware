"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: P2P Botnet Performance Metrics
 Environment: ISOLATED VM LAB ONLY
====================================================

Implements the formal measurement framework from:
  Wang, Aslam, Zou — "Peer-to-Peer Botnets" §1.5
  "Measuring P2P Botnets along three dimensions"

ALL metrics from the chapter are implemented here:

  EFFECTIVENESS (§1.5.1)
    - Botnet size (concurrent + total)
    - Network crawler simulation (upper-bound estimation)
    - Scale estimation method used in Gnutella/Storm analysis

  EFFICIENCY (§1.5.2)
    - Hop distance distribution between node pairs (Fig. 1.3a)
    - Betweenness centrality — identifies relay-critical nodes
    - Command delivery probability at given TTL

  ROBUSTNESS (§1.5.3)
    - Degree distribution (Fig. 1.3b)
    - Clustering coefficient / CCDF (Fig. 1.3c)
    - Wang et al. formal metrics (eq. 1.1, 1.2):
        C(p) = bots in largest component / remaining bots
        D(p) = average degree of largest component /
               average degree of original botnet
    - TARGETED vs RANDOM removal comparison
      (key finding: balanced-degree networks are MORE
       resilient to targeted removal than scale-free ones)

Graphs are saved to /tmp/botnet_lab_p2p_metrics/

CLI:
  python3 p2p_metrics.py --all
  python3 p2p_metrics.py --metric effectiveness
  python3 p2p_metrics.py --metric efficiency
  python3 p2p_metrics.py --metric robustness
  python3 p2p_metrics.py --metric removal    [--removal-mode targeted|random|both]
  python3 p2p_metrics.py --graph             (generate all matplotlib figures)
"""

import argparse
import collections
import json
import math
import os
import random
import sys
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple

# Optional matplotlib — gracefully degraded if not installed
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
    _MPL = True
except ImportError:
    _MPL = False

OUT_DIR = "/tmp/botnet_lab_p2p_metrics"


# ──────────────────────────────────────────────────────────────────
#  GRAPH PRIMITIVES  (adjacency list, matching §1.3 Gnutella data)
# ──────────────────────────────────────────────────────────────────

def _build_botnet_graph(n: int = 450,
                        k_min: int = 10, k_max: int = 100,
                        topology: str = "gnutella") -> Dict[int, List[int]]:
    """
    Build a synthetic botnet overlay graph.

    topology='gnutella'  — degree range 10-100, balanced (§1.5.3 Fig. 1.3b)
    topology='scale_free'— power-law degree distribution (Barabási–Albert)
    topology='random'    — Erdos-Renyi random graph

    Returns adjacency list dict.
    """
    adj: Dict[int, List[int]] = {i: [] for i in range(n)}

    if topology == "gnutella":
        # Gnutella-like: each node picks a degree in [k_min, k_max]
        for i in range(n):
            k = random.randint(k_min, min(k_max, n - 1))
            candidates = [j for j in range(n)
                          if j != i and j not in adj[i]]
            neighbors = random.sample(candidates, min(k, len(candidates)))
            for nb in neighbors:
                if nb not in adj[i]:
                    adj[i].append(nb)
                if i not in adj[nb]:
                    adj[nb].append(i)

    elif topology == "scale_free":
        # Barabási–Albert preferential attachment
        m = 5   # edges per new node
        adj = {0: [], 1: [0], 0: [1]}
        adj = {i: [] for i in range(n)}
        for i in range(2):
            adj[i] = [j for j in range(2) if j != i]
        degree_sum = [2] * 2
        for i in range(2, n):
            adj[i] = []
            total_degree = sum(len(adj[j]) for j in range(i))
            if total_degree == 0:
                targets = random.sample(range(i), min(m, i))
            else:
                probs = [len(adj[j]) / total_degree for j in range(i)]
                targets = _weighted_sample(range(i), probs, min(m, i))
            for t in targets:
                adj[i].append(t)
                adj[t].append(i)

    elif topology == "random":
        p = 2 * k_min / n  # Erdos-Renyi edge probability
        for i in range(n):
            for j in range(i + 1, n):
                if random.random() < p:
                    adj[i].append(j)
                    adj[j].append(i)

    return adj


def _weighted_sample(population, weights, k):
    chosen = []
    available = list(range(len(population)))
    weights = list(weights)
    for _ in range(k):
        if not available:
            break
        total = sum(weights[i] for i in available)
        if total == 0:
            break
        r = random.random() * total
        acc = 0
        for idx in available:
            acc += weights[idx]
            if acc >= r:
                chosen.append(list(population)[idx])
                available.remove(idx)
                break
    return chosen


# ──────────────────────────────────────────────────────────────────
#  §1.5.1  EFFECTIVENESS — Botnet Size Estimation
# ──────────────────────────────────────────────────────────────────

class BotnetSizeEstimator:
    """
    Teaching point (§1.5.1):
      Botnet size is not a cleanly defined term. Two definitions:
        1. Total population (all infected machines)
        2. Concurrent online count

      Gnutella analysis method (§1.5.1):
        Cruiser crawler captured ~450,000 peers in one snapshot.
        Upper bound = 450,000 × n (n = avg leaves per ultrapeer).
        Overestimated because leaf peers connect to multiple
        ultrapeers — upper bound, not exact.

      Storm botnet (§1.5.1):
        Concurrent online estimated at 5,000–40,000.
        Total infection estimates: 100k–10 million.
    """

    def __init__(self, topology: Dict[int, List[int]],
                 online_fraction: float = 0.60):
        self.adj              = topology
        self.n                = len(topology)
        self.online_fraction  = online_fraction
        self._online: Set[int] = set()

    def simulate_churn(self):
        """Mark a random fraction of nodes as concurrently online."""
        self._online = set(
            random.sample(list(self.adj.keys()),
                          int(self.n * self.online_fraction))
        )

    def crawl_estimate(self, n_leaves_per_ultra: int = 5) -> dict:
        """
        Estimate total botnet size using Gnutella crawler method (§1.5.1).
        Returns the upper-bound estimate and concurrent count.
        """
        self.simulate_churn()
        crawled        = len(self._online)       # crawler only reaches online nodes
        upper_bound    = crawled * n_leaves_per_ultra
        concurrent     = len(self._online)

        print(f"\n[SIZE] Botnet Size Estimation (§1.5.1)")
        print(f"[SIZE] Total nodes in network:  {self.n}")
        print(f"[SIZE] Concurrent online ({self.online_fraction*100:.0f}%): {concurrent}")
        print(f"[SIZE] Crawler reachable:       {crawled}")
        print(f"[SIZE] Upper-bound estimate:    {upper_bound} "
              f"(crawled × {n_leaves_per_ultra} avg leaves)")
        print(f"[SIZE] Note: upper bound overestimates — leaf peers may")
        print(f"[SIZE]       connect to multiple ultrapeers")
        print(f"[SIZE] Storm baseline: 5k–40k concurrent, 100k–10M total")

        return {"total_nodes": self.n, "concurrent_online": concurrent,
                "crawled": crawled, "upper_bound_estimate": upper_bound}


# ──────────────────────────────────────────────────────────────────
#  §1.5.2  EFFICIENCY — Distance + Betweenness
# ──────────────────────────────────────────────────────────────────

class EfficiencyMetrics:
    """
    Teaching point (§1.5.2):
      Efficiency = how fast all bots receive a command.

      For unstructured P2P (Gnutella-like):
        Key metric: HOP DISTANCE between ultrapeer pairs.
        - The chapter found most pairs are within 5 hops (Fig. 1.3a)
        - LimeWire default TTL = 7 → nearly all bots reachable
        - TTL must exceed the graph diameter for complete delivery

      BETWEENNESS CENTRALITY:
        - Nodes with high betweenness control most traffic flow
        - Commands issued FROM high-betweenness nodes spread fastest
        - Removing high-betweenness nodes maximally disrupts the
          botnet (targeted removal strategy — §1.6.3)
    """

    def __init__(self, adj: Dict[int, List[int]], sample_size: int = 150):
        self.adj         = adj
        self.n           = len(adj)
        self.sample_size = sample_size   # BFS sample for large graphs
        self._distances: Dict[Tuple[int,int], int] = {}
        self._betweenness: Dict[int, float] = {}

    def _bfs_distances(self, src: int) -> Dict[int, int]:
        """BFS shortest path distances from src."""
        dist   = {src: 0}
        queue  = deque([src])
        while queue:
            u = queue.popleft()
            for v in self.adj.get(u, []):
                if v not in dist:
                    dist[v] = dist[u] + 1
                    queue.append(v)
        return dist

    def compute_distance_distribution(self) -> dict:
        """
        Sample pairwise BFS distances and build distribution (Fig. 1.3a).
        Returns {distance: fraction_of_pairs}.
        """
        print(f"\n[EFFICIENCY] Computing distance distribution "
              f"(sample {self.sample_size} nodes)...")
        nodes   = random.sample(list(self.adj.keys()),
                                min(self.sample_size, self.n))
        counter = defaultdict(int)
        total   = 0

        for src in nodes:
            dists = self._bfs_distances(src)
            for dst, d in dists.items():
                if dst != src:
                    counter[d] += 1
                    total += 1

        dist_distr = {d: counter[d] / total
                      for d in sorted(counter.keys())} if total else {}

        avg_dist = sum(d * f for d, f in dist_distr.items())
        max_dist = max(dist_distr.keys()) if dist_distr else 0

        print(f"[EFFICIENCY] Distance distribution:")
        for d in sorted(dist_distr.keys()):
            bar = "█" * int(dist_distr[d] * 40)
            print(f"  d={d}  {dist_distr[d]:5.3f}  {bar}")
        print(f"[EFFICIENCY] Average distance: {avg_dist:.2f} hops")
        print(f"[EFFICIENCY] Diameter (max):   {max_dist} hops")
        print(f"[EFFICIENCY] At TTL=7 (LimeWire default): "
              f"~{sum(f for d,f in dist_distr.items() if d<=7)*100:.1f}% "
              f"of pairs are reachable")

        return {"distribution": dist_distr,
                "avg_distance": round(avg_dist, 3),
                "diameter": max_dist}

    def compute_betweenness(self, sample: int = 80) -> Dict[int, float]:
        """
        Approximate betweenness centrality via sampled BFS.
        Brandes algorithm on a random sample of source nodes.

        High-betweenness nodes:
          - Are critical relay points for command dissemination
          - Should be selected as entry points for fast command spread
          - Removal maximally disrupts connectivity (targeted defense §1.6.3)
        """
        print(f"\n[EFFICIENCY] Computing betweenness centrality "
              f"(sample={sample} sources)...")
        bet: Dict[int, float] = defaultdict(float)
        sources = random.sample(list(self.adj.keys()),
                                min(sample, self.n))

        for s in sources:
            # Brandes BFS
            stack = []
            pred  = defaultdict(list)
            sigma = defaultdict(int)
            sigma[s] = 1
            dist  = {s: 0}
            queue = deque([s])
            while queue:
                v = queue.popleft()
                stack.append(v)
                for w in self.adj.get(v, []):
                    if w not in dist:
                        dist[w] = dist[v] + 1
                        queue.append(w)
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]
                        pred[w].append(v)
            delta = defaultdict(float)
            while stack:
                w = stack.pop()
                for v in pred[w]:
                    if sigma[w]:
                        delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
                if w != s:
                    bet[w] += delta[w]

        # Normalize
        factor = 1.0 / max(1, (self.n - 1) * (self.n - 2))
        for k in bet:
            bet[k] *= factor

        top10 = sorted(bet.items(), key=lambda x: -x[1])[:10]
        print(f"[EFFICIENCY] Top-10 highest betweenness nodes:")
        for uid, b in top10:
            deg = len(self.adj.get(uid, []))
            print(f"  Node {uid:4d}: betweenness={b:.5f}  degree={deg}")
        print(f"[EFFICIENCY] These nodes control most traffic flow.")
        print(f"[EFFICIENCY] Strategy: issue commands FROM these nodes "
              f"for fastest dissemination.")
        print(f"[EFFICIENCY] Defense §1.6.3: REMOVE these nodes to "
              f"maximize botnet disruption.")

        self._betweenness = dict(bet)
        return self._betweenness

    def command_delivery_probability(self, ttl: int = 7) -> dict:
        """Fraction of node pairs reachable within TTL hops."""
        nodes  = random.sample(list(self.adj.keys()),
                               min(100, self.n))
        pairs  = 0
        within = 0
        for src in nodes:
            dists = self._bfs_distances(src)
            for d in dists.values():
                pairs  += 1
                if d <= ttl:
                    within += 1

        prob = within / pairs if pairs else 0
        print(f"\n[EFFICIENCY] Command delivery at TTL={ttl}: "
              f"{prob*100:.1f}% of pairs reachable")
        return {"ttl": ttl, "delivery_probability": round(prob, 4)}


# ──────────────────────────────────────────────────────────────────
#  §1.5.3  ROBUSTNESS — Degree, Clustering, C(p), D(p)
# ──────────────────────────────────────────────────────────────────

class RobustnessMetrics:
    """
    Teaching point (§1.5.3):
      Robustness measures how resilient a botnet is when nodes
      are removed — by network failures, user reboots, or
      deliberate defender action.

      DEGREE DISTRIBUTION (Fig. 1.3b):
        Most Gnutella nodes have 10–100 connections (balanced).
        Balanced degree → resilient to targeted removal because
        there are no dominant high-degree hubs to attack.

      CLUSTERING COEFFICIENT (Fig. 1.3c):
        Low clustering in Gnutella (neighborhood not well
        interconnected) → vulnerable to RANDOM removal because
        the network fragments easily without local redundancy.

      WANG et al. FORMAL METRICS (eq. 1.1, 1.2):
        After removing fraction p of highest-degree bots:
          C(p) = |bots in largest connected component| / |remaining bots|
          D(p) = avg degree of largest component / avg degree of original

        C(p) close to 1 → botnet stays cohesive under removal
        D(p) close to 1 → remaining botnet as well-connected as original

      TARGETED vs RANDOM REMOVAL (key finding §1.5.3):
        For BALANCED-degree networks (Gnutella): targeted removal
        is LESS effective than random, because removing the
        top-degree nodes doesn't disproportionately fragment.
        For SCALE-FREE networks: targeted removal is catastrophic.
    """

    def __init__(self, adj: Dict[int, List[int]]):
        self.adj     = adj
        self.n       = len(adj)
        self._orig_avg_degree = self._avg_degree(set(adj.keys()))

    # ── Degree distribution ───────────────────────────────────────

    def degree_distribution(self) -> dict:
        degrees = [len(nb) for nb in self.adj.values()]
        counter = defaultdict(int)
        for d in degrees:
            counter[d] += 1
        total = len(degrees)
        dist  = {d: counter[d]/total for d in sorted(counter.keys())}

        avg_deg = sum(degrees) / total if total else 0
        min_deg = min(degrees) if degrees else 0
        max_deg = max(degrees) if degrees else 0

        print(f"\n[ROBUSTNESS] Degree Distribution (§1.5.3 Fig. 1.3b)")
        print(f"  Nodes: {self.n} | avg_degree: {avg_deg:.1f} "
              f"| range: [{min_deg}, {max_deg}]")
        # Histogram bins
        bins = {}
        for d in degrees:
            b = (d // 20) * 20
            bins[b] = bins.get(b, 0) + 1
        for b in sorted(bins.keys()):
            bar = "█" * min(int(bins[b] / total * 60), 60)
            print(f"  [{b:3d}-{b+19:3d}]: {bar} ({bins[b]})")

        if max_deg > 0 and avg_deg > 0:
            cv = math.sqrt(sum((d - avg_deg)**2 for d in degrees) / total) / avg_deg
            print(f"  CV (coefficient of variation): {cv:.3f} "
                  f"({'balanced' if cv < 0.5 else 'skewed — scale-free signature'})")
        return {"avg_degree": round(avg_deg,2),
                "min": min_deg, "max": max_deg,
                "distribution": dict(list(dist.items())[:20])}

    # ── Clustering coefficient ────────────────────────────────────

    def clustering_coefficient(self, sample: int = 200) -> dict:
        """
        Local clustering coefficient for sampled nodes.
        c_i = (edges among neighbors of i) / (k_i*(k_i-1)/2)

        Low clustering → network fragments under random removal.
        High clustering → more locally redundant paths.
        """
        nodes = random.sample(list(self.adj.keys()),
                              min(sample, self.n))
        ccs = []
        for u in nodes:
            nb  = set(self.adj.get(u, []))
            k   = len(nb)
            if k < 2:
                ccs.append(0.0)
                continue
            edges_among = sum(
                1 for v in nb
                for w in self.adj.get(v, [])
                if w in nb and w != v
            ) // 2
            max_edges = k * (k - 1) // 2
            ccs.append(edges_among / max_edges if max_edges else 0.0)

        avg_cc  = sum(ccs) / len(ccs) if ccs else 0
        # CCDF
        sorted_cc = sorted(ccs)
        ccdf = {round(v, 2): 1 - i/len(sorted_cc)
                for i, v in enumerate(sorted_cc)}

        print(f"\n[ROBUSTNESS] Clustering Coefficient (§1.5.3 Fig. 1.3c)")
        print(f"  Average CC: {avg_cc:.4f}")
        if avg_cc < 0.1:
            print(f"  LOW clustering → vulnerable to random node removal")
            print(f"  (neighborhood not well interconnected)")
        else:
            print(f"  HIGH clustering → more locally redundant paths")
        return {"avg_clustering": round(avg_cc, 4), "ccdf": ccdf}

    # ── C(p) and D(p) — Wang et al. formal metrics ────────────────

    def _connected_component_size(self, active: Set[int]) -> int:
        """Largest connected component among active nodes."""
        if not active:
            return 0
        visited = set()
        best    = 0
        for start in active:
            if start in visited:
                continue
            component = set()
            queue     = deque([start])
            while queue:
                u = queue.popleft()
                if u in visited or u not in active:
                    continue
                visited.add(u)
                component.add(u)
                for v in self.adj.get(u, []):
                    if v not in visited and v in active:
                        queue.append(v)
            best = max(best, len(component))
        return best

    def _avg_degree(self, active: Set[int]) -> float:
        if not active:
            return 0.0
        total = sum(
            sum(1 for nb in self.adj.get(u, []) if nb in active)
            for u in active
        )
        return total / len(active)

    def compute_cp_dp(self, p_steps: int = 10,
                      removal_mode: str = "targeted") -> dict:
        """
        Compute C(p) and D(p) as defined in Wang et al. eq. 1.1–1.2.

        p = fraction of top-degree bots removed.
        removal_mode: 'targeted' = remove highest-degree first
                      'random'   = remove uniformly at random

        Returns series of (p, C(p), D(p)) tuples.
        """
        print(f"\n[ROBUSTNESS] Wang et al. C(p)/D(p) metrics "
              f"({removal_mode} removal, §1.5.3 eq. 1.1–1.2)")

        active  = set(self.adj.keys())
        orig_sz = len(active)

        # Pre-sort by degree for targeted removal
        by_degree = sorted(active, key=lambda u: -len(self.adj.get(u,[])))

        series = []
        steps  = [i / p_steps for i in range(p_steps + 1)]

        for p in steps:
            n_remove = int(p * orig_sz)

            if removal_mode == "targeted":
                remaining = set(by_degree[n_remove:])
            else:
                to_remove = random.sample(list(active), n_remove)
                remaining = active - set(to_remove)

            if not remaining:
                series.append({"p": p, "C_p": 0.0, "D_p": 0.0})
                continue

            lcc_size = self._connected_component_size(remaining)
            cp       = lcc_size / len(remaining) if remaining else 0
            avg_deg  = self._avg_degree(remaining)
            dp       = avg_deg / self._orig_avg_degree if self._orig_avg_degree else 0

            series.append({"p": round(p,2),
                           "C_p": round(cp, 4),
                           "D_p": round(dp, 4)})

        print(f"  {'p':>6}  {'C(p)':>8}  {'D(p)':>8}  Interpretation")
        print("  " + "-" * 52)
        for s in series[::2]:
            interp = ("botnet intact" if s["C_p"] > 0.8
                      else "botnet fragmented" if s["C_p"] < 0.4
                      else "partial disruption")
            print(f"  {s['p']:6.2f}  {s['C_p']:8.4f}  "
                  f"{s['D_p']:8.4f}  {interp}")

        return {"removal_mode": removal_mode, "series": series}

    def compare_targeted_vs_random(self) -> dict:
        """
        The chapter's key finding (§1.5.3):
          Gnutella-like balanced-degree networks are:
            - VULNERABLE to random node removal (low clustering)
            - RESILIENT to targeted removal (balanced degree, no hubs)

          Scale-free networks are the opposite:
            - Resilient to random removal (hubs hold the network)
            - Catastrophically vulnerable to targeted removal
        """
        print("\n" + "=" * 60)
        print("  Targeted vs Random Node Removal Comparison (§1.5.3)")
        print("=" * 60)

        r_targeted = self.compute_cp_dp(removal_mode="targeted")
        r_random   = self.compute_cp_dp(removal_mode="random")

        # Find p where C(p) drops below 0.5
        def _fragmentation_p(series):
            for s in series:
                if s["C_p"] < 0.5:
                    return s["p"]
            return 1.0

        p_tgt = _fragmentation_p(r_targeted["series"])
        p_rnd = _fragmentation_p(r_random["series"])

        print(f"\n[ROBUSTNESS] Fragmentation threshold (C(p) < 0.5):")
        print(f"  Targeted removal: p = {p_tgt:.2f} "
              f"({p_tgt*100:.0f}% of bots must be removed)")
        print(f"  Random removal:   p = {p_rnd:.2f} "
              f"({p_rnd*100:.0f}% of bots must be removed)")
        if p_tgt >= p_rnd:
            print(f"\n  FINDING: Targeted removal is LESS effective than "
                  f"random for this topology.")
            print(f"  This matches Gnutella analysis (§1.5.3): balanced "
                  f"degree means no critical hubs to target.")
        else:
            print(f"\n  FINDING: Targeted removal is MORE effective — "
                  f"scale-free/hub structure detected.")

        return {"targeted": r_targeted, "random": r_random,
                "targeted_fragmentation_p": p_tgt,
                "random_fragmentation_p": p_rnd}


# ──────────────────────────────────────────────────────────────────
#  MATPLOTLIB FIGURES — reproduce §1.5 Fig. 1.3(a)(b)(c)
# ──────────────────────────────────────────────────────────────────

def generate_graphs(adj: Dict[int, List[int]],
                    eff: EfficiencyMetrics,
                    rob: RobustnessMetrics,
                    out_dir: str = OUT_DIR):
    if not _MPL:
        print("[GRAPH] matplotlib not available — install with: "
              "pip3 install matplotlib --break-system-packages")
        return

    os.makedirs(out_dir, exist_ok=True)

    fig, axes = plt.subplots(1, 3, figsize=(15, 4))
    fig.suptitle("P2P Botnet Metrics — §1.5 Fig. 1.3 Reproduction\n"
                 "AUA CS 232/337 Research Lab", fontsize=11)

    # ── Fig. 1.3(a): Distance distribution ───────────────────────
    dist_data = eff.compute_distance_distribution()
    dd        = dist_data["distribution"]
    ax        = axes[0]
    ax.bar(list(dd.keys()), list(dd.values()), color="#4472C4",
           edgecolor="#1a3a6b", width=0.7)
    ax.set_xlabel("Distance (hops)")
    ax.set_ylabel("Fraction of pairs")
    ax.set_title("(a) Distance distribution")
    ax.axvline(7, color="red", linestyle="--", linewidth=1,
               label="LimeWire TTL=7")
    ax.legend(fontsize=8)
    ax.set_xlim(0, 12)

    # ── Fig. 1.3(b): Node degree distribution ────────────────────
    degrees = [len(nb) for nb in adj.values()]
    ax      = axes[1]
    ax.hist(degrees, bins=30, color="#ED7D31", edgecolor="#7f3a00",
            density=True, log=True)
    ax.set_xlabel("Node degree")
    ax.set_ylabel("Probability density (log)")
    ax.set_title("(b) Degree distribution")
    ax.set_xscale("log")

    # ── Fig. 1.3(c): Clustering coefficient CCDF ─────────────────
    cc_data  = rob.clustering_coefficient()
    sorted_c = sorted(cc_data["ccdf"].keys())
    ccdf_v   = [cc_data["ccdf"][c] for c in sorted_c]
    ax       = axes[2]
    ax.plot(sorted_c, ccdf_v, color="#70AD47", linewidth=1.5)
    ax.set_xlabel("Node clustering coefficient")
    ax.set_ylabel("CCDF")
    ax.set_title("(c) CCDF of node clustering")
    ax.set_xscale("log")
    ax.set_yscale("log")

    plt.tight_layout()
    path = os.path.join(out_dir, "p2p_metrics_fig1_3.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\n[GRAPH] Fig. 1.3 reproduction saved: {path}")

    # ── C(p)/D(p) comparison graph ───────────────────────────────
    fig2, ax2 = plt.subplots(1, 2, figsize=(10, 4))
    fig2.suptitle("Wang et al. C(p)/D(p) — Targeted vs Random Removal\n"
                  "AUA CS 232/337 Research Lab", fontsize=11)

    r_tgt = rob.compute_cp_dp(removal_mode="targeted")
    r_rnd = rob.compute_cp_dp(removal_mode="random")

    for r, label, color in [
        (r_tgt, "Targeted", "#E24B4A"),
        (r_rnd, "Random",   "#4472C4"),
    ]:
        ps  = [s["p"]   for s in r["series"]]
        cps = [s["C_p"] for s in r["series"]]
        dps = [s["D_p"] for s in r["series"]]
        ax2[0].plot(ps, cps, label=label, color=color, linewidth=1.8)
        ax2[1].plot(ps, dps, label=label, color=color, linewidth=1.8)

    ax2[0].set_xlabel("p (fraction removed)")
    ax2[0].set_ylabel("C(p) — connected ratio")
    ax2[0].set_title("C(p) eq. 1.1")
    ax2[0].legend(); ax2[0].set_ylim(0, 1.05)

    ax2[1].set_xlabel("p (fraction removed)")
    ax2[1].set_ylabel("D(p) — degree ratio")
    ax2[1].set_title("D(p) eq. 1.2")
    ax2[1].legend(); ax2[1].set_ylim(0, 1.05)

    plt.tight_layout()
    path2 = os.path.join(out_dir, "p2p_metrics_removal.png")
    plt.savefig(path2, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[GRAPH] C(p)/D(p) comparison saved: {path2}")


# ──────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────────────────────────

def _run_effectiveness(adj):
    est = BotnetSizeEstimator(adj)
    est.crawl_estimate()

def _run_efficiency(adj):
    eff = EfficiencyMetrics(adj)
    eff.compute_distance_distribution()
    eff.compute_betweenness()
    eff.command_delivery_probability(ttl=7)

def _run_robustness(adj):
    rob = RobustnessMetrics(adj)
    rob.degree_distribution()
    rob.clustering_coefficient()
    rob.compute_cp_dp(removal_mode="targeted")
    rob.compute_cp_dp(removal_mode="random")

def _run_removal(adj, mode):
    rob = RobustnessMetrics(adj)
    if mode == "both":
        rob.compare_targeted_vs_random()
    else:
        rob.compute_cp_dp(removal_mode=mode)


if __name__ == "__main__":
    print("=" * 60)
    print(" P2P Botnet Metrics — AUA CS 232/337 Research Lab")
    print(" ISOLATED VM ONLY")
    print("=" * 60)

    parser = argparse.ArgumentParser(
        description="P2P Botnet Performance Metrics (§1.5)"
    )
    parser.add_argument("--all",     action="store_true")
    parser.add_argument("--graph",   action="store_true")
    parser.add_argument("--metric",  default="robustness",
                        choices=["effectiveness","efficiency",
                                 "robustness","removal"])
    parser.add_argument("--removal-mode", default="both",
                        choices=["targeted","random","both"])
    parser.add_argument("--topology", default="gnutella",
                        choices=["gnutella","scale_free","random"])
    parser.add_argument("--nodes",  type=int, default=250)
    args = parser.parse_args()

    print(f"\nBuilding {args.topology} topology with {args.nodes} nodes...")
    adj = _build_botnet_graph(args.nodes, topology=args.topology)
    print(f"Graph ready: {len(adj)} nodes, "
          f"avg degree {sum(len(v) for v in adj.values())/len(adj):.1f}")

    if args.graph or args.all:
        eff = EfficiencyMetrics(adj)
        rob = RobustnessMetrics(adj)
        generate_graphs(adj, eff, rob)

    if args.all:
        _run_effectiveness(adj)
        _run_efficiency(adj)
        _run_robustness(adj)
        rob = RobustnessMetrics(adj)
        rob.compare_targeted_vs_random()
    elif args.metric == "effectiveness":
        _run_effectiveness(adj)
    elif args.metric == "efficiency":
        _run_efficiency(adj)
    elif args.metric == "robustness":
        _run_robustness(adj)
    elif args.metric == "removal":
        _run_removal(adj, args.removal_mode)
