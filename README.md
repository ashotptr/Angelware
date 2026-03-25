# Botnet Attack-Defense Research Lab
## AUA CS 232 / CS 337 — Cybersecurity Spring 2026

> **CRITICAL: ALL components run in an isolated virtual machine network (192.168.100.0/24) with ZERO external internet connectivity. Verify isolation before running any offensive module.**

---

## Directory Structure

```
botnet_lab/
├── c2_server/
│   └── c2_server.py          # Phase 1 Flask C2 (star topology)
├── bot_agent/
│   ├── bot_agent.c           # Main C bot agent (heartbeat + DDoS)
│   ├── mirai_scanner.c       # Mirai-inspired IoT propagation scanner
│   ├── slowloris.py          # Slowloris HTTP exhaustion attack
│   └── dga.py                # Domain Generation Algorithm module
├── ids_detector/
│   └── ids_detector.py       # 3-engine IDS (volumetric, behavioral, DNS)
├── honeypot_config/
│   └── fake_portal.py        # Credential stuffing target (Flask /login)
├── scripts/
│   └── generate_graphs.py    # Week 7: produces 3 research graphs
└── README.md
```

---

## VM Network Setup

### Step 1 — Create 4 VMs in VirtualBox

| VM Name         | IP Address       | RAM  | Role                          |
|----------------|------------------|------|-------------------------------|
| c2-server       | 192.168.100.10   | 1GB  | Flask C2, botmaster console   |
| bot-agent-1     | 192.168.100.11   | 1GB  | C bot, DDoS modules           |
| bot-agent-2     | 192.168.100.12   | 1GB  | Secondary bot, P2P peer       |
| victim-honeypot | 192.168.100.20   | 1GB  | Attack target + Cowrie        |

### Step 2 — Network Isolation (CRITICAL)

In VirtualBox settings for EVERY VM:
- Settings → Network → Adapter 1 → **Host-Only Adapter** (vboxnet0)
- **NOT Bridged, NOT NAT**

Verify isolation from any VM:
```bash
ping 8.8.8.8   # MUST timeout — if this works, your setup is wrong
ping 192.168.100.10   # MUST work
```

### Step 3 — Configure Static IPs (each VM)

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```
```yaml
network:
  version: 2
  ethernets:
    eth0:
      addresses: [192.168.100.XX/24]   # replace XX with VM's IP
      nameservers:
        addresses: [192.168.100.1]
```
```bash
sudo netplan apply
```

---

## Package Installation (Run on ALL VMs)

```bash
sudo apt update && sudo apt install -y \
    python3 python3-pip gcc make libpcap-dev \
    nmap wireshark-common tcpdump net-tools apache2

pip3 install flask scapy psutil requests pycryptodome matplotlib
```

### Victim/Honeypot VM only:
```bash
# Install Cowrie honeypot
pip3 install cowrie
# OR follow: https://cowrie.readthedocs.io/en/latest/INSTALL.html

# Cowrie config: /etc/cowrie/cowrie.cfg
# Set: listen_port = 2222 (fake SSH), listen_endpoints = tcp:2223 (fake Telnet)
```

---

## Compile C Components

```bash
# Bot agent (on bot-agent-1 and bot-agent-2)
gcc -o bot_agent bot_agent.c -lpthread
gcc -o mirai_scanner mirai_scanner.c -lpthread
```

---

## Running the Lab (Weekly Schedule)

### Week 1: Star Topology C2

**C2 Server VM (192.168.100.10):**
```bash
python3 c2_server.py
```

**Bot Agent VMs (192.168.100.11 and .12):**
```bash
sudo ./bot_agent
```

Verify in C2 console: you should see heartbeat check-ins from both bots.

Push a task from any machine:
```bash
curl -X POST http://192.168.100.10:5000/task \
     -H "Content-Type: application/json" \
     -d '{"bot_id":"all","type":"idle"}'
```

View registered bots:
```bash
curl http://192.168.100.10:5000/bots
```

---

### Week 2: DDoS Payloads

**Start IDS first (victim VM):**
```bash
sudo python3 ids_detector.py
```

**SYN Flood (from bot VM):**
```bash
# Push task via C2
curl -X POST http://192.168.100.10:5000/task \
     -H "Content-Type: application/json" \
     -d '{"bot_id":"all","type":"syn_flood","target_ip":"192.168.100.20","duration":15}'
```

**Slowloris (from bot VM):**
```bash
python3 slowloris.py  # targets 192.168.100.20:80
```
Monitor Apache workers:
```bash
# On victim VM: watch Apache exhaust its threads
watch -n1 "sudo ss -tn | grep :80 | wc -l"
```

---

### Week 3: DGA Module

```bash
python3 dga.py  # observe NXDOMAIN burst + entropy analysis
```

Watch the IDS detect the DGA burst on the victim VM.

---

### Week 5: Cowrie Honeypot

```bash
# Start Cowrie on victim VM
cowrie start
# Logs in: ~/.cowrie/var/log/cowrie/cowrie.json

# Start Mirai scanner on bot VM
sudo ./mirai_scanner
```

Monitor Cowrie log in real time:
```bash
tail -f ~/.cowrie/var/log/cowrie/cowrie.json | python3 -m json.tool
```

---

### Week 7: Quantitative Testing + Graphs

```bash
# After running all attack scenarios and recording data:
pip3 install matplotlib
python3 scripts/generate_graphs.py
# Graphs saved to botnet_lab/graphs/
```

**Replace simulated data in generate_graphs.py with your REAL MEASURED values.**

---

## Ethics & Safety Checklist

Before any session:
- [ ] All VM adapters confirmed as Host-Only (vboxnet0)
- [ ] `ping 8.8.8.8` fails from every VM
- [ ] VMs snapshotted in clean state
- [ ] Professor pre-approval documentation on file
- [ ] GitHub repository set to **Private**
- [ ] No offensive code on host machine — VM only

---

## Key Files to Understand First

| File | Why |
|------|-----|
| `c2_server.py` | Start here — shows the full C2 architecture before complexity |
| `ids_detector.py` | Read the three engine docstrings — the math is explained inline |
| `dga.py` | `shannon_entropy()` and `generate_daily_domains()` are the core research functions |
| `generate_graphs.py` | Replace `simulate_*` functions with real data before Week 8 |

---

*AUA CS 232 / CS 337 Cybersecurity Spring 2026*
