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

### Phase 1 — Host-Only Network Setup

In VirtualBox, go to **File > Tools > Network Manager**.

Click **Create** (generates a network like `vboxnet0`).

- **Adapter tab**: Set IPv4 Address to `192.168.100.1` and Mask to `255.255.255.0`.
- **DHCP Server tab**: Uncheck "Enable Server".

Click **Apply**.

---

### Phase 2 — Create Base VM

Click **New**. Name it `Ubuntu-Base`. Select your Ubuntu Server ISO. Check **"Skip Unattended Installation"**.

- Hardware: 1024 MB RAM, 2 Processors.
- Hard Disk: 20 GB. Finish.

Select `Ubuntu-Base`, go to **Settings > Network > Adapter 1**. Change "Attached to" from NAT to **Host-Only Adapter** (select your network from Phase 1).

Start the VM, install Ubuntu Server, and at the final terminal login screen run:

```bash
sudo shutdown now
```

---

### Phase 3 — Clone VMs

Right-click `Ubuntu-Base` and select **Clone**.

- **MAC Address Policy**: Select *Generate new MAC addresses for all network adapters*.
- **Clone Type**: Select *Full Clone*.

Create 4 clones with these **exact names**:

| VM Name         | IP Address       | RAM  | Role                          |
|----------------|------------------|------|-------------------------------|
| c2-server       | 192.168.100.10   | 1GB  | Flask C2, botmaster console   |
| bot-agent-1     | 192.168.100.11   | 1GB  | C bot, DDoS modules           |
| bot-agent-2     | 192.168.100.12   | 1GB  | Secondary bot, P2P peer       |
| victim-honeypot | 192.168.100.20   | 1GB  | Attack target + Cowrie        |

---

### Phase 4 — Configure & Install (Repeat for EACH of the 4 VMs)

#### Step 1 — Temporarily Give Internet Access

In VirtualBox, go to **VM Settings > Network > Adapter 1**. Change to **NAT**.

Start the VM and log in. Find the interface name (e.g., `enp0s3`) using `ip a`.

#### Step 2 — Set Netplan to DHCP

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Replace contents exactly with:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
```

```bash
sudo netplan apply
ping -c 4 8.8.8.8   # verify internet access
```

#### Step 3 — Install Packages

```bash
sudo apt update
sudo apt install -y openssh-server python3 python3-pip gcc make libpcap-dev nmap wireshark-common tcpdump net-tools apache2
pip3 install flask scapy psutil requests pycryptodome matplotlib
```

**(Victim VM only):**

```bash
pip3 install cowrie
# OR follow: https://cowrie.readthedocs.io/en/latest/INSTALL.html

# Cowrie config: /etc/cowrie/cowrie.cfg
# Set: listen_port = 2222 (fake SSH), listen_endpoints = tcp:2223 (fake Telnet)
```

#### Step 4 — Set Static IP & Re-isolate

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Replace with your static IP (use `.10` for c2, `.11` for bot1, `.12` for bot2, `.20` for victim):

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      addresses: [192.168.100.XX/24]
      nameservers:
        addresses: [192.168.100.1]
```

```bash
sudo netplan apply
sudo shutdown now
```

In VirtualBox **VM Settings > Network > Adapter 1**, change back to **Host-Only Adapter**.

Start the VM.

#### Verify Isolation (CRITICAL)

```bash
ping 8.8.8.8            # MUST timeout — if this works, your setup is wrong
ping 192.168.100.10     # MUST work
```

---

### Phase 5 — SSH Connection

Open PowerShell on your Windows host.

```bash
ssh vboxuser@192.168.100.XX   # replace XX with the VM's specific IP
```

Type `yes` to accept the fingerprint and enter your password.

*(Optional but recommended)* Set the hostname so you don't get confused between terminal windows:

```bash
sudo hostnamectl set-hostname <vm-name>
bash   # reload prompt
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
curl -X POST http://192.168.100.10:5000/task -H "Content-Type: application/json" -d '{"bot_id":"all","type":"idle"}'
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
or
(sudo PYTHONPATH="/home/vboxuser/.local/lib/python3.12/site-packages" python3 ids_detector.py)
```

**SYN Flood (from bot VM):**
```bash
# Push task via C2
curl -X POST http://192.168.100.10:5000/task -H "Content-Type: application/json" -d '{"bot_id":"all","type":"syn_flood","target_ip":"192.168.100.20","duration":15}'
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
mkdir -p ~/.local/lib/python3.12/site-packages/cowrie/data/honeyfs/etc
echo "root:x:0:0:root:/root:/bin/bash" > ~/.local/lib/python3.12/site-packages/cowrie/data/honeyfs/etc/passwd
echo "root:x:0:" > ~/.local/lib/python3.12/site-packages/cowrie/data/honeyfs/etc/group
mkdir -p etc
echo "[honeypot]" > etc/cowrie.cfg
mkdir -p ~/.local/lib/python3.12/etc
echo "[honeypot]" > ~/.local/lib/python3.12/etc/cowrie.cfg
echo "[honeypot]" > ~/cowrie.cfg
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


password for all: pass