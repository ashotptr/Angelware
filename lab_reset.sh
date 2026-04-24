#!/bin/bash
# ====================================================
#  AUA CS 232/337 — Botnet Research Lab
#  lab_reset.sh — Clean State Reset Between Runs
#
#  Run from the C2 VM between full lab runs to ensure
#  a deterministic starting state.
#
#  What it resets:
#    LOCAL (C2 VM):
#      - Kill all lab Python/C processes
#      - Clear all log files in /tmp/
#      - Remove state files (tarpit JSON, pcap, graphs)
#      - Flush iptables custom chains, re-apply isolation
#    REMOTE (bot and victim VMs via SSH):
#      - Kill all lab processes
#      - Clear all /tmp/*.log files
#      - Stop Cowrie
#      - Flush tarpit state
#      - Re-randomise bot_agent MAC seed (simulate new bot)
#
#  Usage:
#    sudo ./lab_reset.sh              # full reset
#    sudo ./lab_reset.sh --local      # only local C2 VM
#    sudo ./lab_reset.sh --logs-only  # only clear logs
#    sudo ./lab_reset.sh --status     # show what is running
# ====================================================

set -euo pipefail

C2_IP="192.168.100.10"
BOT1_IP="192.168.100.11"
BOT2_IP="192.168.100.12"
VICTIM_IP="192.168.100.20"
LAB_USER="vboxuser"
SSH_PASS="${LAB_SSH_PASS:-pass}"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=5"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${BLU}[RESET $(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GRN}[OK]${NC} $*"; }
warn() { echo -e "${YLW}[WARN]${NC} $*"; }

LOCAL_ONLY=0
LOGS_ONLY=0
STATUS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --local)      LOCAL_ONLY=1; shift ;;
        --logs-only)  LOGS_ONLY=1;  shift ;;
        --status)     STATUS=1;     shift ;;
        *) shift ;;
    esac
done

rsh() {
    local ip="$1"; shift
    if command -v sshpass &>/dev/null; then
        sshpass -p "$SSH_PASS" ssh $SSH_OPTS "${LAB_USER}@${ip}" "$@" 2>/dev/null || true
    else
        ssh $SSH_OPTS "${LAB_USER}@${ip}" "$@" 2>/dev/null || true
    fi
}

# ─────────────────────────────────────────────────────────────
# Status mode
# ─────────────────────────────────────────────────────────────
show_status() {
    echo ""
    echo -e "${BLU}════ LAB STATUS ════${NC}"

    echo -e "\n${YLW}Local processes:${NC}"
    for proc in c2_server covert_bot fake_portal ids_detector \
                kademlia_p2p cred_stuffing slowloris cryptojack_sim \
                bot_agent mirai_scanner p2p_node; do
        pids=$(pgrep -f "$proc" 2>/dev/null | tr '\n' ' ') || true
        [[ -n "$pids" ]] && echo "  RUNNING: $proc  PIDs=$pids" || true
    done

    echo -e "\n${YLW}Local log files:${NC}"
    for f in /tmp/ids.log /tmp/c2_server.log /tmp/dead_drop.log \
              /tmp/ids.log /tmp/tarpit_state.json /tmp/lab_capture.pcap; do
        [[ -f "$f" ]] && echo "  $f  ($(du -sh "$f" 2>/dev/null | cut -f1))" || true
    done

    echo ""
}

# ─────────────────────────────────────────────────────────────
# Local reset
# ─────────────────────────────────────────────────────────────

PROCS=(
    c2_server.py  covert_bot.py  fake_portal.py  ids_detector.py
    ids_alert_correlator.py  lab_dashboard.py
    kademlia_p2p  cred_stuffing  slowloris  cryptojack_sim
    bot_agent  mirai_scanner  p2p_node.py  dga.py  firewall_dpi.py
    sandbox_evasion  persistence_sim  lateral_movement  file_transfer
    polymorphic_engine  ids_engine_endpoint  procwatch_engine
    tcpdump
)

LOG_FILES=(
    /tmp/ids.log          /tmp/ids_flow_alerts.json
    /tmp/c2_server.log    /tmp/dead_drop.log
    /tmp/portal.log       /tmp/tcpdump.log
    /tmp/bot1.log         /tmp/bot2.log
    /tmp/covert_bot.log   /tmp/mirai_scan.log
    /tmp/p2p_seed.log     /tmp/p2p_bot1.log
    /tmp/p2p_bot2.log
    /tmp/correlated_alerts.json  /tmp/attack_timeline.json
    /tmp/ir_summary.md    /tmp/lab_dashboard_snapshot.json
)

STATE_FILES=(
    /tmp/tarpit_state.json     /tmp/lab_capture.pcap
    /tmp/lab_tcpdump.pid       /tmp/lab_tcpdump.pid
    graph1_measured_data.json  graph2_measured_data.json
    graph3_measured_data.json
)

reset_local() {
    log "Killing all lab processes (local)..."
    for proc in "${PROCS[@]}"; do
        pkill -f "$proc" 2>/dev/null && log "  killed $proc" || true
    done
    sleep 1
    ok "Processes killed"

    if [[ $LOGS_ONLY -eq 0 ]]; then
        log "Flushing custom iptables chains..."
        iptables -F LAB_EGRESS 2>/dev/null && \
            iptables -D OUTPUT -j LAB_EGRESS 2>/dev/null || true
        iptables -X LAB_EGRESS 2>/dev/null || true
        ok "iptables chains flushed"
    fi

    log "Clearing log files (local)..."
    for f in "${LOG_FILES[@]}"; do
        [[ -f "$f" ]] && > "$f" && log "  cleared $f" || true
    done

    if [[ $LOGS_ONLY -eq 0 ]]; then
        log "Removing state files (local)..."
        for f in "${STATE_FILES[@]}"; do
            [[ -f "$f" ]] && rm -f "$f" && log "  removed $f" || true
        done
    fi

    # Clear graph output dir
    [[ -d /tmp/botnet_graphs ]] && rm -f /tmp/botnet_graphs/*.png && \
        log "  cleared /tmp/botnet_graphs/*.png" || true
    [[ -d /tmp/c2_analysis ]]  && rm -f /tmp/c2_analysis/* && \
        log "  cleared /tmp/c2_analysis/*" || true

    ok "Local reset complete"
}

# ─────────────────────────────────────────────────────────────
# Remote VM reset
# ─────────────────────────────────────────────────────────────
reset_remote() {
    local ip="$1" role="$2"
    if ! nc -z -w2 "$ip" 22 2>/dev/null; then
        warn "$ip unreachable — skipping"
        return
    fi

    log "Resetting $ip (role=$role)..."

    # Kill all lab processes
    rsh "$ip" "sudo pkill -f bot_agent;     true"
    rsh "$ip" "sudo pkill -f mirai_scanner; true"
    rsh "$ip" "sudo pkill -f kademlia_p2p;  true"
    rsh "$ip" "sudo pkill -f covert_bot;    true"
    rsh "$ip" "sudo pkill -f ids_detector;  true"
    rsh "$ip" "sudo pkill -f fake_portal;   true"
    rsh "$ip" "sudo pkill -f cred_stuffing; true"
    rsh "$ip" "sudo pkill -f slowloris;     true"
    rsh "$ip" "sudo pkill -f cryptojack;    true"
    rsh "$ip" "sudo pkill -f tcpdump;       true"

    # Clear logs
    rsh "$ip" "for f in /tmp/*.log /tmp/ids_flow_alerts.json; do [ -f \"\$f\" ] && > \"\$f\"; done; true"

    # Cowrie
    if [[ "$role" == "victim" ]]; then
        rsh "$ip" "cowrie stop 2>/dev/null; true"
        rsh "$ip" "cd ~/lab && python3 tarpit_state.py clear 2>/dev/null; true"
        rsh "$ip" "sudo python3 ~/lab/firewall_dpi.py --teardown 2>/dev/null; true"
        ok "  $ip Cowrie stopped, tarpit cleared"
    fi

    # Flush local iptables chains
    rsh "$ip" "sudo iptables -F LAB_EGRESS 2>/dev/null; \
               sudo iptables -D OUTPUT -j LAB_EGRESS 2>/dev/null; \
               sudo iptables -X LAB_EGRESS 2>/dev/null; true"

    ok "$ip reset complete"
}

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
if [[ $STATUS -eq 1 ]]; then
    show_status
    exit 0
fi

echo ""
echo -e "${YLW}╔══════════════════════════════════════════════╗${NC}"
echo -e "${YLW}║   AUA Lab Reset — clean state between runs  ║${NC}"
echo -e "${YLW}╚══════════════════════════════════════════════╝${NC}"
echo ""

reset_local

if [[ $LOCAL_ONLY -eq 0 ]]; then
    reset_remote "$BOT1_IP"   "bot"
    reset_remote "$BOT2_IP"   "bot"
    reset_remote "$VICTIM_IP" "victim"
fi

echo ""
echo -e "${GRN}════ RESET COMPLETE ════${NC}"
echo "  Run: sudo ./run_full_lab.sh    (or --phase 1/2/3)"
echo ""
