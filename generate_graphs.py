"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Week 7 Quantitative Research & Graphs
 Generates the 3 research graphs for the final report
====================================================

Graph 1: DPI vs Port Blocking effectiveness (TTD by attack vector)
Graph 2: Persistence Paradox (MTBI vs credential hardening)
Graph 3: IDS accuracy vs bot jitter level

DATA PIPELINE (updated):
  Each graph function now checks for a corresponding JSON data file
  before falling back to simulated values:

    graph1_measured_data.json  ← written by: firewall_dpi.py --measure
    graph2_measured_data.json  ← written by: collect_graph23_data.py --graph2
    graph3_measured_data.json  ← written by: collect_graph23_data.py --graph3

  If a data file exists, real measurements are used and the graph title
  is annotated "REAL DATA". If not, simulated data is used and the title
  is annotated "SIMULATED — replace with real measurements".

  To collect real data, run the attacks first, then:
    sudo python3 firewall_dpi.py --measure --duration 120
    python3 collect_graph23_data.py --graph2   (on victim VM, after Mirai runs)
    python3 collect_graph23_data.py --graph3   (on bot VM)
"""

import json
import math
import os
import random
import statistics
import time

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    PLT_OK = True
except ImportError:
    PLT_OK = False
    print("[GRAPHS] matplotlib not found. pip3 install matplotlib")


# ── Data file paths ────────────────────────────────────────────
DATA_DIR = os.path.dirname(os.path.abspath(__file__))
GRAPH1_DATA = os.path.join(DATA_DIR, "graph1_measured_data.json")
GRAPH2_DATA = os.path.join(DATA_DIR, "graph2_measured_data.json")
GRAPH3_DATA = os.path.join(DATA_DIR, "graph3_measured_data.json")


# ══════════════════════════════════════════════════════════════
#  DATA LOADERS — real data first, simulated fallback
# ══════════════════════════════════════════════════════════════

def load_graph1_data():
    """
    Load Graph 1 data from firewall_dpi.py --measure output.
    Returns (techniques, port_block_rates, dpi_rates, is_real).

    Expected JSON shape (written by firewall_dpi.py):
    {
      "graph1_data": {
        "port_blocking": {
          "SYN_Flood": 0,        // TTD seconds (0 = instant, inf = never)
          "UDP_Flood": 0,
          "Slowloris": 0,
          "GitHub_Poll": "inf",
          "DGA": "measure"
        },
        "dpi": {
          "SYN_Flood": 1.2,
          "Slowloris": 18.4,
          "GitHub_Poll": 42.7,
          ...
        }
      }
    }
    We convert TTD → detection_rate% for the bar chart:
      TTD=0     → 100% (instant block)
      TTD=inf   → 0%   (never detected)
      TTD=N sec → scale inversely against a 120s measurement window
    """
    VECTORS = ["SYN Flood\n(port 80)", "UDP Flood\n(port 53)",
               "Slowloris\n(port 80)", "GitHub Poll\n(port 443)",
               "DGA Domains\n(port 53)"]
    VECTOR_KEYS = ["SYN_Flood", "UDP_Flood", "Slowloris", "GitHub_Poll", "DGA"]
    WINDOW = 120.0  # seconds

    def ttd_to_rate(ttd) -> float:
        """Convert Time-to-Detect (seconds) to detection rate %."""
        if ttd is None or ttd == "measure" or ttd == "inf":
            return 0.0
        try:
            t = float(ttd)
        except (ValueError, TypeError):
            return 0.0
        if t == float('inf') or t < 0:
            return 0.0
        if t == 0:
            return 100.0
        # Detected within window: rate proportional to remaining window
        rate = max(0.0, (1.0 - t / WINDOW) * 100.0)
        return round(rate, 1)

    if os.path.exists(GRAPH1_DATA):
        try:
            with open(GRAPH1_DATA) as f:
                raw = json.load(f)
            pb  = raw["graph1_data"]["port_blocking"]
            dpi = raw["graph1_data"]["dpi"]

            port_block = [ttd_to_rate(pb.get(k))  for k in VECTOR_KEYS]
            dpi_rate   = [ttd_to_rate(dpi.get(k)) for k in VECTOR_KEYS]

            # If DPI measured, it is > 0 for volumetric vectors regardless of TTD formula
            # (they are always detected — use measured rate if available)
            print(f"[GRAPHS] Graph 1: using REAL data from {GRAPH1_DATA}")
            return VECTORS, port_block, dpi_rate, True
        except Exception as e:
            print(f"[GRAPHS] Could not parse {GRAPH1_DATA}: {e} — using simulated data")

    # Simulated fallback
    print(f"[GRAPHS] Graph 1: {GRAPH1_DATA} not found — using SIMULATED data")
    port_block = [92, 88, 90,  8, 82]
    dpi_rate   = [95, 91, 93, 74, 89]
    return VECTORS, port_block, dpi_rate, False


def load_graph2_data():
    """
    Load Graph 2 data from collect_graph23_data.py --graph2 output.
    Returns (wipes, mtbi_default, is_real).

    Expected JSON shape:
    {
      "wipes": [1, 2, 3, 4, 5, 6, 7, 8],
      "mtbi_default_minutes": [2.1, 3.4, 2.8, 1.9, 3.1, 2.5, 2.2, 3.8],
      "hardened_reinfected": false,
      "notes": "..."
    }
    """
    if os.path.exists(GRAPH2_DATA):
        try:
            with open(GRAPH2_DATA) as f:
                raw = json.load(f)
            wipes = raw["wipes"]
            mtbi  = raw["mtbi_default_minutes"]
            print(f"[GRAPHS] Graph 2: using REAL data from {GRAPH2_DATA}")
            return wipes, mtbi, True
        except Exception as e:
            print(f"[GRAPHS] Could not parse {GRAPH2_DATA}: {e} — using simulated data")

    print(f"[GRAPHS] Graph 2: {GRAPH2_DATA} not found — using SIMULATED data")
    wipes = list(range(1, 9))
    mtbi  = [2.1, 3.4, 2.8, 1.9, 3.1, 2.5, 2.2, 3.8]
    return wipes, mtbi, False


def load_graph3_data():
    """
    Load Graph 3 data from collect_graph23_data.py --graph3 output.
    Returns (jitter_levels, tpr, fpr, is_real).

    Expected JSON shape:
    {
      "jitter_levels_ms": [0, 50, 100, 200, 350, 500, 750, 1000],
      "tpr_percent":      [98, 95, 88, 76, 62, 54, 49, 44],
      "fpr_percent":      [2,   3,  4,  5,  7,  8,  9, 11],
      "notes": "..."
    }
    """
    if os.path.exists(GRAPH3_DATA):
        try:
            with open(GRAPH3_DATA) as f:
                raw = json.load(f)
            jitter = raw["jitter_levels_ms"]
            tpr    = raw["tpr_percent"]
            fpr    = raw["fpr_percent"]
            print(f"[GRAPHS] Graph 3: using REAL data from {GRAPH3_DATA}")
            return jitter, tpr, fpr, True
        except Exception as e:
            print(f"[GRAPHS] Could not parse {GRAPH3_DATA}: {e} — using simulated data")

    print(f"[GRAPHS] Graph 3: {GRAPH3_DATA} not found — using SIMULATED data")
    jitter = [0, 50, 100, 200, 350, 500, 750, 1000]
    tpr    = [98, 95, 88, 76, 62, 54, 49, 44]
    fpr    = [2,   3,  4,  5,  7,  8,  9, 11]
    return jitter, tpr, fpr, False


# ══════════════════════════════════════════════════════════════
#  GRAPH GENERATION
# ══════════════════════════════════════════════════════════════

STYLE = {
    "attack":   "#E74C3C",
    "defense":  "#2980B9",
    "accent":   "#27AE60",
    "warning":  "#F39C12",
    "bg":       "#FAFAFA",
    "grid":     "#DDDDDD",
    "simulated":"#AAAAAA",
}


def _data_label(is_real: bool) -> str:
    return "REAL DATA" if is_real else "SIMULATED DATA — replace with real measurements"


def graph1_dpi_vs_portblocking(save_path: str):
    techniques, port_block, dpi_rate, is_real = load_graph1_data()
    x     = range(len(techniques))
    width = 0.35

    fig, ax = plt.subplots(figsize=(11, 6), facecolor=STYLE["bg"])
    ax.set_facecolor(STYLE["bg"])

    bars1 = ax.bar([i - width/2 for i in x], port_block, width,
                   label="Port Blocking", color=STYLE["warning"],
                   alpha=0.85, edgecolor="white")
    bars2 = ax.bar([i + width/2 for i in x], dpi_rate, width,
                   label="Deep Packet Inspection (DPI)", color=STYLE["defense"],
                   alpha=0.85, edgecolor="white")

    for bar in bars1:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{bar.get_height():.0f}%", ha="center", va="bottom",
                fontsize=9, color="#333")
    for bar in bars2:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{bar.get_height():.0f}%", ha="center", va="bottom",
                fontsize=9, color="#333")

    ax.set_xticks(list(x))
    ax.set_xticklabels(techniques, fontsize=10)
    ax.set_ylabel("Detection Rate (%)", fontsize=12)
    ax.set_ylim(0, 115)

    data_note = _data_label(is_real)
    title_color = "#1A5276" if is_real else STYLE["simulated"]
    ax.set_title(
        f"Graph 1: Port Blocking vs. DPI Detection Rate\nby Attack Vector\n"
        f"[{data_note}]",
        fontsize=12, fontweight="bold", pad=12, color=title_color
    )
    ax.legend(fontsize=10)
    ax.grid(axis="y", color=STYLE["grid"], linestyle="--", linewidth=0.8)

    # Annotation: port blocking is useless against HTTPS (GitHub polling)
    github_idx = 3  # index of "GitHub Poll" bar
    ax.annotate("Port blocking\nuseless vs HTTPS",
                xy=(github_idx - width/2, port_block[github_idx] + 2),
                xytext=(github_idx - 0.7, 25),
                arrowprops=dict(arrowstyle="->", color=STYLE["attack"]),
                color=STYLE["attack"], fontsize=8)

    if not is_real:
        ax.text(0.5, 0.02,
                "⚠  Simulated data — run: sudo python3 firewall_dpi.py --measure --duration 120",
                transform=ax.transAxes, ha="center", va="bottom",
                fontsize=8, color=STYLE["attack"],
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#FFF3CD", alpha=0.8))

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[GRAPHS] Saved: {save_path}")


def graph2_persistence_paradox(save_path: str):
    wipes, mtbi_default, is_real = load_graph2_data()

    fig, ax = plt.subplots(figsize=(10, 6), facecolor=STYLE["bg"])
    ax.set_facecolor(STYLE["bg"])

    ax.bar([w - 0.2 for w in wipes], mtbi_default, 0.4,
           color=STYLE["attack"], alpha=0.85,
           label="Default Credentials (admin:admin)", edgecolor="white")
    ax.bar([w + 0.2 for w in wipes], [9500] * len(wipes), 0.4,
           color=STYLE["accent"], alpha=0.85,
           label="Hardened Credentials (never re-infected)", edgecolor="white")

    # Annotate the measured MTBI values on the bars
    for w, m in zip(wipes, mtbi_default):
        ax.text(w - 0.2, m + 100, f"{m:.1f}m",
                ha="center", va="bottom", fontsize=8, color=STYLE["attack"])

    ax.set_xlabel("System Wipe Attempt #", fontsize=12)
    ax.set_ylabel("Mean Time Between Infections (minutes)", fontsize=12)

    data_note    = _data_label(is_real)
    title_color  = "#1A5276" if is_real else STYLE["simulated"]
    avg_mtbi     = statistics.mean(mtbi_default)
    ax.set_title(
        f"Graph 2: Persistence Paradox — System Ephemerality vs. Credential Hardening\n"
        f"Default credential MTBI avg: {avg_mtbi:.1f} min  |  [{data_note}]",
        fontsize=11, fontweight="bold", pad=12, color=title_color
    )
    ax.set_xticks(wipes)
    ax.set_ylim(0, 10500)
    ax.legend(fontsize=10)
    ax.grid(axis="y", color=STYLE["grid"], linestyle="--", linewidth=0.8)

    ax.annotate(f"Default devices: MTBI avg={avg_mtbi:.1f} min\nWipes buy minutes, not security",
                xy=(wipes[3], mtbi_default[3]),
                xytext=(wipes[3] + 0.5, 1800),
                arrowprops=dict(arrowstyle="->", color=STYLE["attack"]),
                color=STYLE["attack"], fontsize=9)
    ax.text(1.3, 9700,
            "Hardened: never re-infected\n(shown as 9500 min proxy)",
            color=STYLE["accent"], fontsize=9)

    if not is_real:
        ax.text(0.5, 0.02,
                "⚠  Simulated data — run: python3 collect_graph23_data.py --graph2",
                transform=ax.transAxes, ha="center", va="bottom",
                fontsize=8, color=STYLE["attack"],
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#FFF3CD", alpha=0.8))

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[GRAPHS] Saved: {save_path}")


def graph3_ids_accuracy(save_path: str):
    jitter_levels, tpr, fpr, is_real = load_graph3_data()

    fig, ax = plt.subplots(figsize=(10, 6), facecolor=STYLE["bg"])
    ax.set_facecolor(STYLE["bg"])

    ax.plot(jitter_levels, tpr, "o-", color=STYLE["defense"], linewidth=2.5,
            markersize=7, label="True Positive Rate (TPR) — bot correctly detected")
    ax.plot(jitter_levels, fpr, "s--", color=STYLE["warning"], linewidth=2,
            markersize=6, label="False Positive Rate (FPR) — human flagged as bot")

    # Shade the evasion zone (>500ms jitter)
    ax.axvspan(500, max(jitter_levels), alpha=0.08, color=STYLE["attack"],
               label="Bot evasion zone (>500ms jitter)")
    ax.axhline(y=50, color=STYLE["attack"], linestyle=":", linewidth=1.5, alpha=0.7)
    ax.text(max(jitter_levels) * 0.72, 52, "50% threshold\n(coin flip)",
            color=STYLE["attack"], fontsize=9, ha="center")

    # Annotate crossover / evasion threshold
    evasion_idx = next((i for i, j in enumerate(jitter_levels) if j >= 500), -1)
    if evasion_idx >= 0:
        ax.annotate(f"Evasion threshold\n~{jitter_levels[evasion_idx]}ms jitter\nTPR={tpr[evasion_idx]}%",
                    xy=(jitter_levels[evasion_idx], tpr[evasion_idx]),
                    xytext=(jitter_levels[evasion_idx] + 80, tpr[evasion_idx] + 12),
                    arrowprops=dict(arrowstyle="->", color=STYLE["defense"]),
                    color=STYLE["defense"], fontsize=9)

    ax.set_xlabel("Bot Timing Jitter (std dev, milliseconds)", fontsize=12)
    ax.set_ylabel("Rate (%)", fontsize=12)
    ax.set_ylim(0, 108)

    data_note   = _data_label(is_real)
    title_color = "#1A5276" if is_real else STYLE["simulated"]
    ax.set_title(
        f"Graph 3: IDS Accuracy vs. Bot Jitter Level (CV-Based Behavioral Detector)\n"
        f"[{data_note}]",
        fontsize=12, fontweight="bold", pad=12, color=title_color
    )
    ax.legend(fontsize=10)
    ax.grid(color=STYLE["grid"], linestyle="--", linewidth=0.8)

    if not is_real:
        ax.text(0.5, 0.02,
                "⚠  Simulated data — run: python3 collect_graph23_data.py --graph3",
                transform=ax.transAxes, ha="center", va="bottom",
                fontsize=8, color=STYLE["attack"],
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#FFF3CD", alpha=0.8))

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[GRAPHS] Saved: {save_path}")


# ══════════════════════════════════════════════════════════════
#  DATA STATUS REPORT
# ══════════════════════════════════════════════════════════════

def print_data_status():
    """Print which data files exist and what collection is still needed."""
    print("\n" + "=" * 60)
    print(" Graph Data Status")
    print("=" * 60)
    checks = [
        (GRAPH1_DATA, "Graph 1",
         "sudo python3 firewall_dpi.py --measure --duration 120"),
        (GRAPH2_DATA, "Graph 2",
         "python3 collect_graph23_data.py --graph2  (victim VM, after Mirai runs)"),
        (GRAPH3_DATA, "Graph 3",
         "python3 collect_graph23_data.py --graph3  (bot VM)"),
    ]
    all_real = True
    for path, label, cmd in checks:
        if os.path.exists(path):
            mtime = time.strftime("%Y-%m-%d %H:%M",
                                  time.localtime(os.path.getmtime(path)))
            print(f"  ✅  {label}: REAL DATA  ({os.path.basename(path)}, {mtime})")
        else:
            print(f"  ❌  {label}: MISSING — collect with:")
            print(f"       {cmd}")
            all_real = False
    print()
    if all_real:
        print("  All three graphs will use real measured data.")
    else:
        print("  Graphs with missing data will use simulated placeholder values.")
        print("  These are marked [SIMULATED DATA] in the graph titles.")
    print("=" * 60 + "\n")


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Generate research graphs — AUA Botnet Lab"
    )
    parser.add_argument("--out", default=None,
                        help="Output directory (default: ./graphs/)")
    parser.add_argument("--status", action="store_true",
                        help="Print data file status and exit")
    args = parser.parse_args()

    if args.status:
        print_data_status()
        sys.exit(0)

    if not PLT_OK:
        print("Install matplotlib: pip3 install matplotlib")
        sys.exit(1)

    out_dir = args.out or os.path.join(DATA_DIR, "graphs")
    os.makedirs(out_dir, exist_ok=True)

    print_data_status()
    print("Generating research graphs...\n")

    graph1_dpi_vs_portblocking(os.path.join(out_dir, "graph1_dpi_vs_portblocking.png"))
    graph2_persistence_paradox(os.path.join(out_dir, "graph2_persistence_paradox.png"))
    graph3_ids_accuracy(os.path.join(out_dir, "graph3_ids_accuracy.png"))

    print(f"\nAll graphs saved to {out_dir}/")
