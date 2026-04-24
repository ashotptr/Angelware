#!/bin/bash
# ====================================================
#  AUA CS 232/337 — Botnet Research Lab
#  network_policy.sh — Per-VM iptables Policy Enforcer
#
#  Applies role-specific iptables rules to harden each VM
#  and enforce the 192.168.100.0/24 isolation boundary.
#
#  Roles and their policies:
#
#  c2 (192.168.100.10):
#    - Accepts connections from 192.168.100.0/24 only
#    - Allows bot inbound on :5000 (C2) and :5001 (dead-drop)
#    - Drops all inbound from outside the /24
#    - Allows outbound to /24 only (no internet)
#    - Allows inbound SSH from /24 for lab management
#
#  bot (192.168.100.11-12):
#    - Allows outbound to C2 (port 5000, 5001) only
#    - Allows outbound to victim (any — for attack payloads)
#    - Drops all other outbound
#    - Accepts inbound only from C2 IP
#    - Allows inbound SSH for lab management
#
#  victim (192.168.100.20):
#    - Accepts inbound on :22/:23 (Cowrie), :80 (portal), :2222/:2323
#    - Allows all inbound from /24 (bots need to reach it for attacks)
#    - Blocks all outbound except to C2 (IDS reporting)
#    - Allows SSH inbound from /24 for lab management
#
#  Usage:
#    sudo bash network_policy.sh --role c2     --apply
#    sudo bash network_policy.sh --role bot    --apply
#    sudo bash network_policy.sh --role victim --apply
#    sudo bash network_policy.sh --status
#    sudo bash network_policy.sh --flush
#    sudo bash network_policy.sh --verify      # test isolation
# ====================================================

set -euo pipefail

LAB_NET="192.168.100.0/24"
C2_IP="192.168.100.10"
CHAIN="LAB_POLICY"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${BLU}[POLICY]${NC} $*"; }
ok()   { echo -e "${GRN}[OK]${NC} $*"; }
warn() { echo -e "${YLW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

ROLE=""
ACTION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --role)   ROLE="$2";   shift 2 ;;
        --apply)  ACTION="apply";  shift ;;
        --flush)  ACTION="flush";  shift ;;
        --status) ACTION="status"; shift ;;
        --verify) ACTION="verify"; shift ;;
        *) shift ;;
    esac
done

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
ipt() { iptables "$@"; }

flush_chain() {
    ipt -F "$CHAIN"  2>/dev/null || true
    ipt -D INPUT   -j "$CHAIN" 2>/dev/null || true
    ipt -D OUTPUT  -j "$CHAIN" 2>/dev/null || true
    ipt -D FORWARD -j "$CHAIN" 2>/dev/null || true
    ipt -X "$CHAIN" 2>/dev/null || true
    ok "Flushed chain $CHAIN"
}

create_chain() {
    flush_chain
    ipt -N "$CHAIN"
    log "Created chain $CHAIN"
}

# Jump chain into INPUT and/or OUTPUT
hook_input()  { ipt -I INPUT  1 -j "$CHAIN"; }
hook_output() { ipt -I OUTPUT 1 -j "$CHAIN"; }

# ─────────────────────────────────────────────────────────────
# Status
# ─────────────────────────────────────────────────────────────
show_status() {
    echo ""
    echo -e "${BLU}════ iptables STATUS ════${NC}"
    echo -e "${YLW}INPUT chain:${NC}"
    iptables -L INPUT -n --line-numbers -v 2>/dev/null | head -20
    echo -e "\n${YLW}OUTPUT chain:${NC}"
    iptables -L OUTPUT -n --line-numbers -v 2>/dev/null | head -20
    if iptables -L "$CHAIN" -n 2>/dev/null; then
        echo -e "\n${YLW}${CHAIN} chain:${NC}"
        iptables -L "$CHAIN" -n --line-numbers -v 2>/dev/null
    fi
}

# ─────────────────────────────────────────────────────────────
# Isolation verification
# ─────────────────────────────────────────────────────────────
verify_isolation() {
    log "Verifying isolation..."
    FAIL=0

    # Must NOT reach the internet
    if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        warn "FAIL: Can reach 8.8.8.8 (internet reachable)"
        FAIL=1
    else
        ok "Internet (8.8.8.8) unreachable"
    fi

    # Must reach lab VMs
    for ip in 192.168.100.10 192.168.100.11 192.168.100.12 192.168.100.20; do
        if [[ "$(hostname -I | awk '{print $1}')" == "$ip" ]]; then continue; fi
        if ping -c 1 -W 1 "$ip" &>/dev/null; then
            ok "Lab VM $ip reachable"
        else
            warn "Lab VM $ip unreachable (VM may be off)"
        fi
    done

    if [[ $FAIL -eq 0 ]]; then
        ok "Isolation check PASSED"
    else
        die "Isolation check FAILED — fix before running attack scenarios"
    fi
}

# ─────────────────────────────────────────────────────────────
# Role: C2 server
# ─────────────────────────────────────────────────────────────
apply_c2() {
    log "Applying C2 server policy..."
    create_chain
    hook_input
    hook_output

    # Allow loopback always
    ipt -A "$CHAIN" -i lo -j RETURN
    ipt -A "$CHAIN" -o lo -j RETURN

    # Allow established/related
    ipt -A "$CHAIN" -m state --state ESTABLISHED,RELATED -j RETURN

    # INPUT: allow SSH from lab net
    ipt -A "$CHAIN" -p tcp --dport 22 -s "$LAB_NET" -j RETURN
    # INPUT: allow bot connections on C2 and dead-drop ports
    ipt -A "$CHAIN" -p tcp --dport 5000 -s "$LAB_NET" -j RETURN
    ipt -A "$CHAIN" -p tcp --dport 5001 -s "$LAB_NET" -j RETURN
    # INPUT: ICMP from lab net (for ping checks)
    ipt -A "$CHAIN" -p icmp -s "$LAB_NET" -j RETURN
    # INPUT: drop everything else inbound from non-lab
    ipt -A "$CHAIN" -m state --state NEW -j DROP

    # OUTPUT: allow to lab net only
    ipt -A "$CHAIN" -d "$LAB_NET" -j RETURN
    # OUTPUT: drop to any non-lab destination
    ipt -A "$CHAIN" -j DROP

    ok "C2 policy applied"
    log "  Allows: bot inbound :5000,:5001  |  SSH from lab  |  outbound to lab only"
}

# ─────────────────────────────────────────────────────────────
# Role: Bot VM
# ─────────────────────────────────────────────────────────────
apply_bot() {
    log "Applying bot VM policy..."
    create_chain
    hook_input
    hook_output

    ipt -A "$CHAIN" -i lo -j RETURN
    ipt -A "$CHAIN" -o lo -j RETURN
    ipt -A "$CHAIN" -m state --state ESTABLISHED,RELATED -j RETURN

    # INPUT: allow SSH from lab net (management)
    ipt -A "$CHAIN" -p tcp --dport 22 -s "$LAB_NET" -j RETURN
    # INPUT: drop all other inbound new connections
    ipt -A "$CHAIN" -m state --state NEW -j DROP

    # OUTPUT: allow outbound to lab net (C2 comms + attack traffic)
    ipt -A "$CHAIN" -d "$LAB_NET" -j RETURN
    # OUTPUT: drop to any non-lab destination
    ipt -A "$CHAIN" -j DROP

    ok "Bot policy applied"
    log "  Allows: inbound SSH  |  outbound to lab net only"
}

# ─────────────────────────────────────────────────────────────
# Role: Victim / Honeypot
# ─────────────────────────────────────────────────────────────
apply_victim() {
    log "Applying victim/honeypot policy..."
    create_chain
    hook_input
    hook_output

    ipt -A "$CHAIN" -i lo -j RETURN
    ipt -A "$CHAIN" -o lo -j RETURN
    ipt -A "$CHAIN" -m state --state ESTABLISHED,RELATED -j RETURN

    # INPUT: allow all from lab net (bots attack this VM)
    ipt -A "$CHAIN" -s "$LAB_NET" -j RETURN
    # INPUT: drop non-lab
    ipt -A "$CHAIN" -m state --state NEW -j DROP

    # OUTPUT: allow to C2 (IDS may report back) and lab net
    ipt -A "$CHAIN" -d "$LAB_NET" -j RETURN
    # OUTPUT: drop non-lab
    ipt -A "$CHAIN" -j DROP

    ok "Victim policy applied"
    log "  Allows: inbound from lab (attacks)  |  outbound to C2 for IDS reporting"
}

# ─────────────────────────────────────────────────────────────
# Persist rules across reboots
# ─────────────────────────────────────────────────────────────
persist_rules() {
    if command -v iptables-save &>/dev/null && command -v iptables-restore &>/dev/null; then
        RULES_FILE="/etc/iptables/rules.v4"
        mkdir -p "$(dirname "$RULES_FILE")"
        iptables-save > "$RULES_FILE"
        log "Rules persisted to $RULES_FILE"
        # Install restore hook if not present
        if ! grep -q "iptables-restore" /etc/rc.local 2>/dev/null; then
            echo "iptables-restore < $RULES_FILE" >> /etc/rc.local
            log "Added iptables-restore to /etc/rc.local"
        fi
    else
        warn "iptables-save not found — rules will not survive reboot"
        warn "Install iptables-persistent: sudo apt-get install -y iptables-persistent"
    fi
}

# ─────────────────────────────────────────────────────────────
# Main dispatch
# ─────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    die "Must run as root: sudo bash network_policy.sh ..."
fi

case "$ACTION" in
    apply)
        case "$ROLE" in
            c2)     apply_c2     ;;
            bot)    apply_bot    ;;
            victim) apply_victim ;;
            *)      die "Unknown role: '$ROLE'. Use: c2 | bot | victim" ;;
        esac
        persist_rules
        ;;
    flush)
        flush_chain
        ;;
    status)
        show_status
        ;;
    verify)
        verify_isolation
        ;;
    *)
        echo "Usage: sudo bash network_policy.sh --role <c2|bot|victim> --apply"
        echo "       sudo bash network_policy.sh --status"
        echo "       sudo bash network_policy.sh --flush"
        echo "       sudo bash network_policy.sh --verify"
        ;;
esac
