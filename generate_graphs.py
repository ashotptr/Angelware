"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Week 7 Quantitative Research & Graphs
 Generates the 3 research graphs for the final report
====================================================

Graph 1: DPI vs Port Blocking effectiveness
Graph 2: Persistence Paradox (MTBI vs credential hardening)
Graph 3: IDS accuracy vs bot jitter level
"""

import math
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


# ══════════════════════════════════════════════════════════════
#  DATA SIMULATION
#  In your real Week 7 testing, replace these with MEASURED data
# ══════════════════════════════════════════════════════════════

def simulate_dpi_vs_portblocking():
    """
    Graph 1: Detection rate of two defenses against Phase 2 GitHub polling.
    Port blocking (block port 80/8080): catches ~35% (some bots use non-standard ports)
    Deep Packet Inspection: catches ~78% (misses well-obfuscated requests)
    Neither catches 100% — this IS the research finding.
    """
    techniques = ["SYN Flood\n(port 80)", "UDP Flood\n(port 53)", "Slowloris\n(port 80)", "GitHub Polling\n(port 443)", "DGA Domains\n(port 53)"]
    port_block  = [92, 88, 90, 8, 82]    # port blocking detection rate %
    dpi_rate    = [95, 91, 93, 74, 89]   # DPI detection rate %
    return techniques, port_block, dpi_rate


def simulate_persistence_paradox():
    """
    Graph 2: Mean Time Between Infections (minutes) after system wipe.
    Default credentials: re-infected almost immediately (MTBI ~3 minutes)
    Hardened credentials: MTBI grows unbounded — graph shows 10,000 minutes as proxy for "never"
    """
    wipes = list(range(1, 9))  # wipe attempt 1 through 8
    mtbi_default   = [2.1, 3.4, 2.8, 1.9, 3.1, 2.5, 2.2, 3.8]   # minutes — near-zero
    mtbi_hardened  = [None] * 8  # never re-infected after hardening (shown as N/A bar)
    return wipes, mtbi_default


def simulate_ids_accuracy():
    """
    Graph 3: IDS True Positive Rate and False Positive Rate vs bot jitter.
    As the bot introduces more timing jitter, the CV-based detector struggles.
    TPR drops from ~98% at zero jitter to ~45% at 1000ms stddev jitter.
    FPR stays low because human baseline has naturally high CV.
    """
    jitter_levels = [0, 50, 100, 200, 350, 500, 750, 1000]  # ms stddev
    tpr = [98, 95, 88, 76, 62, 54, 49, 44]   # True Positive Rate (%)
    fpr = [2,   3,  4,  5,  7,  8,  9, 11]   # False Positive Rate (%)
    return jitter_levels, tpr, fpr


# ══════════════════════════════════════════════════════════════
#  GRAPH GENERATION
# ══════════════════════════════════════════════════════════════

STYLE = {
    "attack":   "#E74C3C",
    "defense":  "#2980B9",
    "accent":   "#27AE60",
    "warning":  "#F39C12",
    "bg":       "#FAFAFA",
    "grid":     "#DDDDDD"
}

def graph1_dpi_vs_portblocking(save_path):
    techniques, port_block, dpi_rate = simulate_dpi_vs_portblocking()
    x = range(len(techniques))
    width = 0.35

    fig, ax = plt.subplots(figsize=(11, 6), facecolor=STYLE["bg"])
    ax.set_facecolor(STYLE["bg"])

    bars1 = ax.bar([i - width/2 for i in x], port_block, width,
                   label="Port Blocking", color=STYLE["warning"], alpha=0.85, edgecolor="white")
    bars2 = ax.bar([i + width/2 for i in x], dpi_rate, width,
                   label="Deep Packet Inspection (DPI)", color=STYLE["defense"], alpha=0.85, edgecolor="white")

    # Annotate bars
    for bar in bars1:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{bar.get_height()}%", ha="center", va="bottom", fontsize=9, color="#333")
    for bar in bars2:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f"{bar.get_height()}%", ha="center", va="bottom", fontsize=9, color="#333")

    ax.set_xticks(list(x))
    ax.set_xticklabels(techniques, fontsize=10)
    ax.set_ylabel("Detection Rate (%)", fontsize=12)
    ax.set_ylim(0, 110)
    ax.set_title("Graph 1: Port Blocking vs. DPI Detection Rate\nby Attack Vector", fontsize=13, fontweight="bold", pad=15)
    ax.legend(fontsize=10)
    ax.grid(axis="y", color=STYLE["grid"], linestyle="--", linewidth=0.8)
    ax.axhline(y=8, color=STYLE["attack"], linestyle=":", linewidth=1.5, alpha=0.7)
    ax.text(3.5, 10, "Port blocking\nuseless vs HTTPS", color=STYLE["attack"], fontsize=8, ha="center")

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[GRAPHS] Saved: {save_path}")


def graph2_persistence_paradox(save_path):
    wipes, mtbi_default = simulate_persistence_paradox()

    fig, ax = plt.subplots(figsize=(10, 6), facecolor=STYLE["bg"])
    ax.set_facecolor(STYLE["bg"])

    ax.bar([w - 0.2 for w in wipes], mtbi_default, 0.4,
           color=STYLE["attack"], alpha=0.85, label="Default Credentials (admin:admin)", edgecolor="white")
    ax.bar([w + 0.2 for w in wipes], [9500]*len(wipes), 0.4,
           color=STYLE["accent"], alpha=0.85, label="Hardened Credentials (never re-infected)", edgecolor="white")

    ax.set_xlabel("System Wipe Attempt #", fontsize=12)
    ax.set_ylabel("Mean Time Between Infections (minutes)", fontsize=12)
    ax.set_title("Graph 2: Persistence Paradox\nSystem Ephemerality vs. Credential Hardening", fontsize=13, fontweight="bold", pad=15)
    ax.set_xticks(wipes)
    ax.set_ylim(0, 10500)
    ax.legend(fontsize=10)
    ax.grid(axis="y", color=STYLE["grid"], linestyle="--", linewidth=0.8)

    # Annotation
    ax.annotate("Default devices: MTBI ~2-4 min\nWipes buy minutes, not security",
                xy=(4, 3.1), xytext=(4.5, 1500),
                arrowprops=dict(arrowstyle="->", color=STYLE["attack"]),
                color=STYLE["attack"], fontsize=9)
    ax.text(1.5, 9700, "Hardened: never re-infected\n(shown as 9500 min proxy)", color=STYLE["accent"], fontsize=9)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[GRAPHS] Saved: {save_path}")


def graph3_ids_accuracy(save_path):
    jitter_levels, tpr, fpr = simulate_ids_accuracy()

    fig, ax = plt.subplots(figsize=(10, 6), facecolor=STYLE["bg"])
    ax.set_facecolor(STYLE["bg"])

    ax.plot(jitter_levels, tpr, "o-", color=STYLE["defense"], linewidth=2.5,
            markersize=7, label="True Positive Rate (TPR) — bot correctly detected")
    ax.plot(jitter_levels, fpr, "s--", color=STYLE["warning"], linewidth=2,
            markersize=6, label="False Positive Rate (FPR) — human flagged as bot")

    # Shade the evasion zone
    ax.axvspan(500, 1000, alpha=0.08, color=STYLE["attack"], label="Bot evasion zone (>500ms jitter)")
    ax.axhline(y=50, color=STYLE["attack"], linestyle=":", linewidth=1.5, alpha=0.7)
    ax.text(800, 52, "50% threshold\n(coin flip)", color=STYLE["attack"], fontsize=9, ha="center")

    ax.set_xlabel("Bot Timing Jitter (std dev, milliseconds)", fontsize=12)
    ax.set_ylabel("Rate (%)", fontsize=12)
    ax.set_title("Graph 3: IDS Accuracy vs. Bot Jitter Level\n(CV-Based Behavioral Detector)", fontsize=13, fontweight="bold", pad=15)
    ax.set_ylim(0, 105)
    ax.legend(fontsize=10)
    ax.grid(color=STYLE["grid"], linestyle="--", linewidth=0.8)

    # Annotate key point
    ax.annotate(f"Evasion threshold\n~500ms jitter\nTPR={tpr[5]}%",
                xy=(500, tpr[5]), xytext=(600, 70),
                arrowprops=dict(arrowstyle="->", color=STYLE["defense"]),
                color=STYLE["defense"], fontsize=9)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[GRAPHS] Saved: {save_path}")


if __name__ == "__main__":
    import os
    out_dir = "/home/claude/botnet_lab/graphs"
    os.makedirs(out_dir, exist_ok=True)

    if not PLT_OK:
        print("Install matplotlib: pip3 install matplotlib")
    else:
        print("Generating research graphs...\n")
        graph1_dpi_vs_portblocking(f"{out_dir}/graph1_dpi_vs_portblocking.png")
        graph2_persistence_paradox(f"{out_dir}/graph2_persistence_paradox.png")
        graph3_ids_accuracy(f"{out_dir}/graph3_ids_accuracy.png")
        print(f"\nAll graphs saved to {out_dir}/")
        print("\nNOTE: Replace simulated data with REAL MEASURED values from Week 7 testing.")
        print("      These are template graphs showing expected shapes and structure.")
