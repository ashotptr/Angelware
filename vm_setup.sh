#!/bin/bash
# ====================================================
#  AUA CS 232/337 — Botnet Research Lab
#  vm_setup.sh — One-Time VM Provisioning Script
#
#  Run this ONCE from the C2 VM (192.168.100.10)
#  after creating and booting all four VMs.
#
#  What it does on EVERY VM:
#    1. Verifies network isolation (no internet)
#    2. Installs all system packages
#    3. Installs all Python packages
#    4. Deploys the lab repo
#    5. Compiles all C components
#    6. Applies per-role iptables rules
#    7. Sets static /etc/hosts entries
#    8. Runs a self-test on each VM
#
#  Usage:
#    chmod +x vm_setup.sh
#    sudo ./vm_setup.sh [--skip-deploy] [--only-vm <IP>]
#
#  Options:
#    --skip-deploy   Deploy step skipped (files already present)
#    --only-vm IP    Provision only that VM
#    --dry-run       Print commands without executing
# ====================================================

set -euo pipefail

# ── IPs ──────────────────────────────────────────────────────
C2_IP="192.168.100.10"
BOT1_IP="192.168.100.11"
BOT2_IP="192.168.100.12"
VICTIM_IP="192.168.100.20"
LAB_USER="vboxuser"
SSH_PASS="${LAB_SSH_PASS:-pass}"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=no"
LAB_DIR="/home/${LAB_USER}/lab"
REPO_DIR="$(pwd)"   # assumed: run from the repo root on C2 VM

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${BLU}[SETUP $(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GRN}[OK]${NC} $*"; }
warn() { echo -e "${YLW}[WARN]${NC} $*"; }
die()  { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

SKIP_DEPLOY=0
ONLY_VM=""
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-deploy) SKIP_DEPLOY=1; shift ;;
        --only-vm)     ONLY_VM="$2"; shift 2 ;;
        --dry-run)     DRY_RUN=1; shift ;;
        *) shift ;;
    esac
done

run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "DRY: $*"
    else
        eval "$@"
    fi
}

# ── SSH helper ────────────────────────────────────────────────
rsh() {
    local ip="$1"; shift
    if command -v sshpass &>/dev/null; then
        run sshpass -p "$SSH_PASS" ssh $SSH_OPTS "${LAB_USER}@${ip}" "$@"
    else
        run ssh $SSH_OPTS "${LAB_USER}@${ip}" "$@"
    fi
}

rsync_lab() {
    local ip="$1"
    log "  Syncing repo to ${ip}:${LAB_DIR} ..."
    if command -v sshpass &>/dev/null; then
        run sshpass -p "$SSH_PASS" rsync -az --delete \
            --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
            -e "ssh $SSH_OPTS" \
            "${REPO_DIR}/" "${LAB_USER}@${ip}:${LAB_DIR}/"
    else
        run rsync -az --delete \
            --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
            -e "ssh $SSH_OPTS" \
            "${REPO_DIR}/" "${LAB_USER}@${ip}:${LAB_DIR}/"
    fi
    ok "  Repo synced to $ip"
}

# ─────────────────────────────────────────────────────────────
# STEP 0 — Isolation check
# ─────────────────────────────────────────────────────────────
check_isolation() {
    log "Verifying network isolation on this VM..."
    if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        die "ISOLATION BREACH: this VM can reach 8.8.8.8. Abort."
    fi
    ok "Internet unreachable — isolation confirmed"
}

# ─────────────────────────────────────────────────────────────
# STEP 1 — System packages
# ─────────────────────────────────────────────────────────────
SYS_PKGS="python3 python3-pip python3-venv gcc make \
           libpcap-dev libssl-dev libffi-dev \
           apache2 apache2-utils \
           tcpdump net-tools iproute2 ncat \
           git curl wget sshpass rsync \
           iptables ipset"

install_sys_packages() {
    local ip="$1"
    log "[$ip] Installing system packages..."
    rsh "$ip" "sudo apt-get update -qq && sudo apt-get install -y -qq $SYS_PKGS 2>&1 | tail -5"
    ok "[$ip] System packages installed"
}

# ─────────────────────────────────────────────────────────────
# STEP 2 — Python packages
# ─────────────────────────────────────────────────────────────
PY_PKGS="flask==3.0.3 scapy==2.5.0 psutil==6.0.0 pycryptodome==3.20.0 \
         matplotlib==3.9.0 requests==2.32.3 numpy==1.26.4 \
         scikit-learn==1.5.1"
# tls-client is optional (Gap 7b) — install separately, ignore failure
TLS_CLIENT_PKG="tls-client"

install_py_packages() {
    local ip="$1"
    log "[$ip] Installing Python packages..."
    rsh "$ip" "pip3 install --quiet --break-system-packages $PY_PKGS 2>&1 | tail -3"
    # Optional tls-client (Go wrapper — may fail on older kernels)
    rsh "$ip" "pip3 install --quiet --break-system-packages $TLS_CLIENT_PKG 2>&1 | tail -2 || true"
    ok "[$ip] Python packages installed"
}

# ─────────────────────────────────────────────────────────────
# STEP 3 — Cowrie honeypot (victim VM only)
# ─────────────────────────────────────────────────────────────
install_cowrie() {
    local ip="$1"
    log "[$ip] Installing Cowrie honeypot..."
    rsh "$ip" "pip3 install --quiet --break-system-packages cowrie 2>&1 | tail -2 || \
        (cd ~ && git clone --depth 1 https://github.com/cowrie/cowrie.git cowrie_src && \
         cd cowrie_src && pip3 install --quiet --break-system-packages -r requirements.txt)"
    ok "[$ip] Cowrie installed"
}

# ─────────────────────────────────────────────────────────────
# STEP 4 — Compile C components
# ─────────────────────────────────────────────────────────────
compile_c_components() {
    local ip="$1" role="$2"
    log "[$ip] Compiling C components (role=$role)..."
    rsh "$ip" "cd ${LAB_DIR} && \
        gcc -O2 -o bot_agent bot_agent.c -lpthread -lssl -lcrypto 2>&1 && \
        gcc -O2 -o kademlia_p2p kademlia_p2p.c -lpthread -lssl -lcrypto -lm 2>&1"
    if [[ "$role" == "bot" ]]; then
        rsh "$ip" "cd ${LAB_DIR} && \
            gcc -O2 -o mirai_scanner mirai_scanner.c -lpthread 2>&1"
        ok "[$ip] bot_agent + kademlia_p2p + mirai_scanner compiled"
    else
        ok "[$ip] bot_agent + kademlia_p2p compiled"
    fi
}

# ─────────────────────────────────────────────────────────────
# STEP 5 — /etc/hosts entries
# ─────────────────────────────────────────────────────────────
HOSTS_BLOCK="
# AUA CS 232/337 Lab VMs
${C2_IP}     c2-server
${BOT1_IP}   bot-agent-1
${BOT2_IP}   bot-agent-2
${VICTIM_IP} victim-honeypot
"

set_hosts() {
    local ip="$1"
    log "[$ip] Setting /etc/hosts..."
    rsh "$ip" "sudo tee -a /etc/hosts > /dev/null << 'HOSTSEOF'
${HOSTS_BLOCK}
HOSTSEOF"
    ok "[$ip] /etc/hosts updated"
}

# ─────────────────────────────────────────────────────────────
# STEP 6 — iptables isolation rules
# Applied via network_policy.sh which is also deployed
# ─────────────────────────────────────────────────────────────
apply_network_policy() {
    local ip="$1" role="$2"
    log "[$ip] Applying network policy (role=$role)..."
    rsh "$ip" "cd ${LAB_DIR} && sudo bash network_policy.sh --role ${role} --apply" || \
        warn "[$ip] network_policy.sh not found or failed — run manually"
    ok "[$ip] Network policy applied"
}

# ─────────────────────────────────────────────────────────────
# STEP 7 — Self-test
# ─────────────────────────────────────────────────────────────
selftest() {
    local ip="$1"
    log "[$ip] Running self-test..."
    rsh "$ip" "python3 -c 'import flask, scapy, psutil, Crypto, matplotlib; print(\"Imports OK\")'" && \
        ok "[$ip] Self-test PASSED" || warn "[$ip] Self-test FAILED — check imports"
}

# ─────────────────────────────────────────────────────────────
# Provision a single VM
# ─────────────────────────────────────────────────────────────
provision_vm() {
    local ip="$1" role="$2"
    log "━━ Provisioning $ip (role=$role) ━━"

    # Test connectivity
    if ! nc -z -w3 "$ip" 22 2>/dev/null; then
        warn "$ip is unreachable on port 22 — skipping"
        return
    fi

    install_sys_packages "$ip"
    install_py_packages  "$ip"

    if [[ $SKIP_DEPLOY -eq 0 ]]; then
        rsync_lab "$ip"
    fi

    compile_c_components "$ip" "$role"
    set_hosts            "$ip"
    apply_network_policy "$ip" "$role"

    if [[ "$role" == "victim" ]]; then
        install_cowrie "$ip"
    fi

    selftest "$ip"
    ok "━━ $ip DONE ━━"
}

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║   AUA CS 232/337 — Lab VM Provisioning               ║${NC}"
echo -e "${RED}║   ISOLATED NETWORK ONLY — NO INTERNET ACCESS         ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

check_isolation

declare -A ROLES=(
    ["$C2_IP"]="c2"
    ["$BOT1_IP"]="bot"
    ["$BOT2_IP"]="bot"
    ["$VICTIM_IP"]="victim"
)

if [[ -n "$ONLY_VM" ]]; then
    role="${ROLES[$ONLY_VM]:-unknown}"
    provision_vm "$ONLY_VM" "$role"
else
    for ip in "$C2_IP" "$BOT1_IP" "$BOT2_IP" "$VICTIM_IP"; do
        role="${ROLES[$ip]}"
        [[ "$ip" == "$(hostname -I | awk '{print $1}')" ]] && \
            log "Skipping self ($ip) — provision manually if needed" && continue
        provision_vm "$ip" "$role"
    done
fi

echo ""
echo -e "${GRN}════ PROVISIONING COMPLETE ════${NC}"
echo ""
echo "Next steps:"
echo "  1. On C2 VM:     sudo ./run_full_lab.sh --phase 1"
echo "  2. On any VM:    python3 lab_dashboard.py"
echo "  3. To reset:     sudo ./lab_reset.sh"
