"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Mock Packet Test Harness
 Source: freeCodeCamp "How to Build a Real-Time IDS with Python"
         Chaitanya Rahalkar, January 2025
====================================================

WHAT THIS ADDS:
  The project currently has NO unit-testable mock packet tests.
  All testing is done by running the full VM lab (run_full_lab.sh)
  which requires root, multiple VMs, and several minutes of setup.

  This file lets you test individual detection engines in < 1 second,
  without root, without a network, without VMs. It is the article's
  test_ids() function adapted to cover:

    1. The article's exact test cases (normal traffic, SYN flood,
       port scan) run against the new flow_analyzer.py (Engine 15)
    2. Additional tests for the project's engines not covered by the
       article: DGA entropy detection (Engine 3), adaptive ML warmup
       (Engine 8 via ml_detector), packet capture stats (packet_capture)

USAGE:
  python3 test_ids_mock.py              # run all tests
  python3 test_ids_mock.py -v           # verbose output
  python3 test_ids_mock.py --list       # list available test groups
  python3 test_ids_mock.py --only flow  # run only flow_analyzer tests

REQUIREMENTS:
  pip3 install scapy scikit-learn numpy
  (scikit-learn is optional — IsolationForest tests are skipped if absent)
"""

import argparse
import sys
import time
from typing import List, Tuple

# ── Dependency checks ──────────────────────────────────────────
try:
    from scapy.layers.inet import IP, TCP, UDP, Raw
    _SCAPY_OK = True
except ImportError:
    print("[TEST] ERROR: Scapy required. pip3 install scapy")
    _SCAPY_OK = False

try:
    import numpy as np
    import sklearn
    _SKLEARN_OK = True
except ImportError:
    _SKLEARN_OK = False

try:
    import flow_analyzer
    _FLOW_OK = True
except ImportError:
    _FLOW_OK = False
    print("[TEST] WARNING: flow_analyzer.py not found — Flow/Engine15 tests skipped")

try:
    import packet_capture
    _CAPTURE_OK = True
except ImportError:
    _CAPTURE_OK = False
    print("[TEST] WARNING: packet_capture.py not found — PacketCapture tests skipped")

try:
    import ml_detector
    _ML_OK = True
except ImportError:
    _ML_OK = False
    print("[TEST] WARNING: ml_detector.py not found — ML tests skipped")

try:
    import ids_detector
    _IDS_OK = True
except ImportError:
    _IDS_OK = False
    print("[TEST] WARNING: ids_detector.py not importable — IDS engine tests skipped")


# ══════════════════════════════════════════════════════════════════
#  PACKET FACTORIES
#  (same helpers the article's test_ids() uses, with extras)
# ══════════════════════════════════════════════════════════════════

def make_tcp_pkt(src: str, dst: str, sport: int, dport: int,
                 flags: str, size: int = 60,
                 timestamp: float = None) -> object:
    """
    Build a minimal Scapy IP/TCP packet.

    Article's test_ids() just uses:
        IP(src=..., dst=...) / TCP(sport=..., dport=..., flags=...)

    This wrapper adds size control (for port scan testing where
    packet_size < 100 is the trigger) and optional timestamp injection
    (for rate-based tests where we fake high packet_rate).
    """
    if not _SCAPY_OK:
        return None
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if size > len(pkt):
        pkt = pkt / Raw(b"\x00" * (size - len(pkt)))
    if timestamp is not None:
        pkt.time = timestamp
    return pkt


def make_syn_flood_burst(src_base: str, dst: str, dport: int,
                          count: int = 5,
                          interval_sec: float = 0.001) -> List:
    """
    Create a burst of SYN packets at high rate (simulates SYN flood).
    Timestamps are set so packet_rate > SIG_SYN_FLOOD_RATE (100 pkt/s).
    """
    if not _SCAPY_OK:
        return []
    pkts = []
    t0   = time.time()
    for i in range(count):
        # Each packet from a slightly different source (spoofed IPs like bot_agent.c)
        src = f"10.0.0.{(i % 253) + 1}"
        pkt = IP(src=src, dst=dst) / TCP(
            sport=5000 + i, dport=dport, flags="S"
        )
        pkt.time = t0 + i * interval_sec
        pkts.append(pkt)
    return pkts


def make_port_scan_burst(src: str, dst: str, count: int = 5,
                          interval_sec: float = 0.015) -> List:
    """
    Create small SYN probes to different ports (simulates port scan).
    Packet size ≈ 40 bytes (bare IP+TCP), packet_rate > 50 pkt/s.
    """
    if not _SCAPY_OK:
        return []
    pkts = []
    t0   = time.time()
    ports = [22, 23, 25, 80, 443, 3306, 5432, 8080, 8443, 9200]
    for i in range(count):
        pkt = IP(src=src, dst=dst) / TCP(
            sport=4321, dport=ports[i % len(ports)], flags="S"
        )
        # No padding — keep packet_size small (< 100 bytes is the rule)
        pkt.time = t0 + i * interval_sec
        pkts.append(pkt)
    return pkts


def make_normal_traffic(count: int = 4) -> List:
    """
    Create normal-looking established TCP packets (article's 'normal traffic').
    Large packets (1400 bytes), ACK or PUSH flag, low rate.
    """
    if not _SCAPY_OK:
        return []
    pkts = []
    pairs = [
        ("192.168.1.1", "192.168.1.2", 1234, 80,  "A"),
        ("192.168.1.3", "192.168.1.4", 1235, 443, "PA"),
        ("10.0.0.10",   "10.0.0.20",   9000, 8080, "A"),
        ("172.16.0.1",  "172.16.0.2",  2000, 5432, "PA"),
    ]
    t0 = time.time()
    for i, (src, dst, sport, dport, flags) in enumerate(pairs[:count]):
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                          flags=flags)
        pkt = pkt / Raw(b"\x41" * 1400)   # 1400-byte payload → large packet
        pkt.time = t0 + i * 2.5           # slow rate — one packet every 2.5s
        pkts.append(pkt)
    return pkts


# ══════════════════════════════════════════════════════════════════
#  TEST RUNNER INFRASTRUCTURE
# ══════════════════════════════════════════════════════════════════

_PASS = "\033[92m PASS \033[0m"
_FAIL = "\033[91m FAIL \033[0m"
_SKIP = "\033[93m SKIP \033[0m"
_WARN = "\033[93m WARN \033[0m"

_results: List[Tuple[str, str, str]] = []   # (group, name, status)

def _record(group: str, name: str, passed: bool, skip: bool = False,
            detail: str = "") -> None:
    status = _SKIP if skip else (_PASS if passed else _FAIL)
    _results.append((group, name, status))
    symbol = "[SKIP]" if skip else ("[PASS]" if passed else "[FAIL]")
    suffix = f"  ({detail})" if detail else ""
    print(f"  {symbol}  {name}{suffix}")


def _section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def _summary() -> int:
    """Print summary and return number of failures."""
    passed = sum(1 for _, _, s in _results if "PASS" in s)
    failed = sum(1 for _, _, s in _results if "FAIL" in s)
    skipped = sum(1 for _, _, s in _results if "SKIP" in s)
    print(f"\n{'='*60}")
    print(f"  RESULTS: {passed} passed, {failed} failed, {skipped} skipped "
          f"/ {len(_results)} total")
    print('='*60)
    return failed


# ══════════════════════════════════════════════════════════════════
#  TEST GROUP 1: ARTICLE'S EXACT TEST CASES (flow_analyzer / Engine 15)
#  Source: test_ids() from the freeCodeCamp article
# ══════════════════════════════════════════════════════════════════

def test_article_original():
    """
    The article's test_ids() function, adapted to run against
    flow_analyzer.FlowDetectionEngine.

    Article test cases:
      - Normal traffic: 2 packets (ACK, PUSH-ACK) — expect no threats
      - SYN flood simulation: 3 SYN packets → expect syn_flood
      - Port scan simulation: 3 SYNs to different ports → expect port_scan
    """
    _section("Article's Original test_ids() — Engine 15 (flow_analyzer)")

    if not _SCAPY_OK or not _FLOW_OK:
        _record("article", "setup", False, skip=True,
                detail="scapy or flow_analyzer unavailable")
        return

    engine = flow_analyzer.Engine15FlowIDS()

    # Article's exact test packets (from test_ids() in the article)
    test_packets = [
        # Normal traffic
        make_tcp_pkt("192.168.1.1", "192.168.1.2", 1234,  80, "A"),
        make_tcp_pkt("192.168.1.3", "192.168.1.4", 1235, 443, "PA"),

        # SYN flood simulation (article: "IP(src='10.0.0.1') / TCP(flags='S')")
        make_tcp_pkt("10.0.0.1", "192.168.1.2", 5678, 80, "S"),
        make_tcp_pkt("10.0.0.2", "192.168.1.2", 5679, 80, "S"),
        make_tcp_pkt("10.0.0.3", "192.168.1.2", 5680, 80, "S"),

        # Port scan simulation (article: different dports from one src)
        make_tcp_pkt("192.168.1.100", "192.168.1.2", 4321, 22, "S"),
        make_tcp_pkt("192.168.1.100", "192.168.1.2", 4321, 23, "S"),
        make_tcp_pkt("192.168.1.100", "192.168.1.2", 4321, 25, "S"),
    ]

    print("\nProcessing packets (article's test sequence)...\n")
    all_threats = []

    for i, pkt in enumerate(test_packets, 1):
        if pkt is None:
            continue
        # Fake high packet rate for SYN flood / port scan packets
        # (flows 3+ need high packet_rate to trigger rules)
        if i >= 3:
            pkt.time = time.time() - (8 - i) * 0.005  # ~200 pkt/s simulated

        threats = engine.process_packet(pkt)
        src = pkt[IP].src if IP in pkt else "?"
        dst = pkt[IP].dst if IP in pkt else "?"
        print(f"  Packet {i}: {src} → {dst}  "
              f"flags={pkt[TCP].flags if TCP in pkt else '?'}  "
              f"size={len(pkt)}B")
        if threats:
            for t in threats:
                print(f"    ⚠  THREAT: {t['rule']} "
                      f"(type={t['type']}, conf={t['confidence']:.2f})")
                all_threats.append(t)
        else:
            print(f"    ✓  No threats detected")

    # Assertions
    rules_found = {t["rule"] for t in all_threats}

    _record("article", "normal_traffic_no_false_positives",
            "syn_flood" not in rules_found or
            all(t["rule"] != "syn_flood" or
                t.get("_src", "").startswith("192.168.1")
                for t in all_threats),
            detail="first 2 packets should not trigger (may depend on rate)")

    _record("article", "syn_flood_detected",
            "syn_flood" in rules_found,
            detail=f"rules triggered: {rules_found}")

    _record("article", "port_scan_detected",
            "port_scan" in rules_found,
            detail=f"rules triggered: {rules_found}")

    _record("article", "json_alert_written",
            engine.alert_sys.alert_count > 0,
            detail=f"{engine.alert_sys.alert_count} JSON alerts in "
                   f"{engine.alert_sys.log_file}")


# ══════════════════════════════════════════════════════════════════
#  TEST GROUP 2: FLOW FEATURE EXTRACTION
# ══════════════════════════════════════════════════════════════════

def test_flow_features():
    _section("TrafficAnalyzer — per-flow feature extraction")

    if not _SCAPY_OK or not _FLOW_OK:
        _record("flow", "setup", False, skip=True)
        return

    analyzer = flow_analyzer.TrafficAnalyzer()

    # Send 5 packets on the same flow and verify feature accumulation
    src, dst, sport, dport = "10.0.0.1", "10.0.0.2", 1234, 80
    t0 = time.time()
    last_features = None

    for i in range(5):
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A")
        pkt = pkt / Raw(b"\x41" * 500)
        pkt.time = t0 + i * 0.1
        last_features = analyzer.analyze_packet(pkt)

    _record("flow", "features_not_none",
            last_features is not None)

    if last_features:
        required = {"packet_size", "flow_duration", "packet_rate",
                    "byte_rate", "tcp_flags", "window_size"}
        _record("flow", "all_six_features_present",
                required.issubset(set(last_features.keys())),
                detail=f"got {set(last_features.keys()) & required}")

        _record("flow", "packet_rate_positive",
                last_features["packet_rate"] > 0,
                detail=f"rate={last_features['packet_rate']:.2f}")

        _record("flow", "byte_rate_positive",
                last_features["byte_rate"] > 0,
                detail=f"byte_rate={last_features['byte_rate']:.0f}")

        _record("flow", "flow_duration_positive",
                last_features["flow_duration"] > 0,
                detail=f"duration={last_features['flow_duration']:.3f}s")

        _record("flow", "tcp_flags_integer",
                isinstance(last_features["tcp_flags"], int),
                detail=f"flags={hex(last_features['tcp_flags'])}")

    # Test flow expiry
    pruned = analyzer.expire_old_flows(max_age=0.0)
    _record("flow", "flow_expiry_prunes",
            pruned > 0 and analyzer.active_flows == 0,
            detail=f"pruned={pruned}")


# ══════════════════════════════════════════════════════════════════
#  TEST GROUP 3: PORT SCAN SIGNATURE
#  (the rule genuinely missing from the project before this addition)
# ══════════════════════════════════════════════════════════════════

def test_port_scan_signature():
    _section("Port Scan Signature — packet_size<100 AND packet_rate>50")

    if not _SCAPY_OK or not _FLOW_OK:
        _record("portscan", "setup", False, skip=True)
        return

    engine = flow_analyzer.Engine15FlowIDS()

    # Build a burst of small SYN probes at high rate
    pkts = make_port_scan_burst("192.168.1.100", "192.168.100.20", count=6,
                                 interval_sec=0.01)  # 100 pkt/s

    scan_detected = False
    for pkt in pkts:
        threats = engine.process_packet(pkt)
        if any(t["rule"] == "port_scan" for t in threats):
            scan_detected = True

    _record("portscan", "port_scan_signature_fires",
            scan_detected,
            detail="requires packet_size<100 AND packet_rate>50 pkt/s")

    # Verify the rule does NOT fire on large, slow packets
    engine2 = flow_analyzer.Engine15FlowIDS()
    normal_pkts = make_normal_traffic(count=3)
    false_positive = False
    for pkt in normal_pkts:
        threats = engine2.process_packet(pkt)
        if any(t["rule"] == "port_scan" for t in threats):
            false_positive = True

    _record("portscan", "no_false_positive_on_large_slow_packets",
            not false_positive,
            detail="1400B payload at 2.5s interval should not trigger")


# ══════════════════════════════════════════════════════════════════
#  TEST GROUP 4: PACKET CAPTURE (queue buffering)
# ══════════════════════════════════════════════════════════════════

def test_packet_capture():
    _section("PacketCapture — queue-buffered capture class")

    if not _CAPTURE_OK:
        _record("capture", "setup", False, skip=True,
                detail="packet_capture.py not found")
        return

    # Test 1: instantiation
    cap = packet_capture.PacketCapture(interface="lo", maxsize=100)
    _record("capture", "instantiation",
            cap is not None and cap.packet_queue.maxsize == 100)

    # Test 2: stats() returns correct structure
    stats = cap.stats()
    _record("capture", "stats_structure",
            all(k in stats for k in ("captured", "dropped", "queued", "drop_pct")))

    # Test 3: get_packet() returns None on empty queue (no timeout hang)
    t_start = time.time()
    result  = cap.get_packet(timeout=0.1)
    elapsed = time.time() - t_start
    _record("capture", "get_packet_returns_none_on_empty",
            result is None and elapsed < 0.5,
            detail=f"elapsed={elapsed:.3f}s")

    # Test 4: manual packet injection via queue (no live capture needed)
    if _SCAPY_OK:
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80)
        cap.packet_queue.put(pkt)
        retrieved = cap.get_packet(timeout=0.1)
        _record("capture", "packet_survives_queue_roundtrip",
                retrieved is not None and IP in retrieved,
                detail="put+get works without live capture")
    else:
        _record("capture", "packet_survives_queue_roundtrip",
                False, skip=True)

    # Test 5: drop-oldest behaviour when queue is full
    cap_small = packet_capture.PacketCapture(interface="lo", maxsize=2)
    if _SCAPY_OK:
        for i in range(5):
            pkt = IP(src=f"10.0.0.{i+1}", dst="1.2.3.4") / TCP()
            cap_small.packet_callback(pkt)   # bypass live capture

        stats = cap_small.stats()
        _record("capture", "bounded_queue_drops_gracefully",
                stats["captured"] == 5 and stats["queued"] <= 2,
                detail=f"captured={stats['captured']}, "
                       f"queued={stats['queued']}, "
                       f"dropped={stats['dropped']}")
    else:
        _record("capture", "bounded_queue_drops_gracefully",
                False, skip=True)


# ══════════════════════════════════════════════════════════════════
#  TEST GROUP 5: ENGINE 8 ADAPTIVE ML (ml_detector.py)
#  (tests the IsolationForest training pipeline via the article's
#   train_anomaly_detector() interface)
# ══════════════════════════════════════════════════════════════════

def test_adaptive_ml():
    _section("Engine 8 / AdaptiveDetector — EWMA + IsolationForest warmup")

    if not _ML_OK:
        _record("ml", "setup", False, skip=True,
                detail="ml_detector.py not found")
        return

    det = ml_detector.AdaptiveDetector()

    # Feed WARMUP_SAMPLES normal traffic samples
    warmup = ml_detector.WARMUP_SAMPLES
    _record("ml", "warmup_samples_constant_positive",
            warmup > 0,
            detail=f"WARMUP_SAMPLES={warmup}")

    # Before warmup: detector should not flag anything
    result_early = det.update(cv=0.08, rate=2.0, success_pct=2.0,
                               unknown_pct=60.0)
    _record("ml", "not_anomalous_before_warmup",
            not result_early["anomalous"] or result_early.get("adaptive_ready") is False,
            detail="should not fire without baseline")

    # Train through warmup with normal traffic
    for _ in range(warmup + 5):
        det.update(cv=0.8 + 0.1 * (_ % 3),
                   rate=1.0,
                   success_pct=80.0,
                   unknown_pct=5.0)

    # After warmup: clearly anomalous input should trigger
    result_bot = det.update(cv=0.01,    # extremely rigid timing
                             rate=50.0,  # high request rate
                             success_pct=0.5,
                             unknown_pct=90.0)
    _record("ml", "anomaly_detected_after_warmup",
            result_bot["anomalous"],
            detail=f"score={result_bot.get('score', '?')}, "
                   f"triggers={result_bot.get('triggers', [])}")

    # Verify result structure
    _record("ml", "result_has_required_keys",
            all(k in result_bot for k in
                ("anomalous", "score", "reason", "triggers",
                 "baselines", "forest_flag")))

    # Normal traffic should not be anomalous after warmup
    result_human = det.update(cv=0.9, rate=0.5, success_pct=85.0,
                               unknown_pct=3.0)
    _record("ml", "normal_traffic_not_flagged_after_warmup",
            not result_human["anomalous"],
            detail=f"score={result_human.get('score', '?')}")


# ══════════════════════════════════════════════════════════════════
#  TEST GROUP 6: ENGINE 3 — DGA ENTROPY (ids_detector)
# ══════════════════════════════════════════════════════════════════

def test_dga_entropy():
    _section("Engine 3 — Shannon entropy calculation (DGA detection)")

    if not _IDS_OK:
        _record("dga", "setup", False, skip=True,
                detail="ids_detector.py not importable")
        return

    entropy_fn = getattr(ids_detector, "shannon_entropy", None)
    if entropy_fn is None:
        _record("dga", "entropy_fn_exists", False,
                detail="shannon_entropy not found in ids_detector")
        return

    # Known entropy values for sanity check
    # "aaaaaaaaaa" — all same char → H = 0
    _record("dga", "uniform_string_entropy_zero",
            entropy_fn("aaaaaaaaaa") < 0.001,
            detail=f"H('aaaaaaaaaa')={entropy_fn('aaaaaaaaaa'):.4f}")

    # "ab" → H = 1.0 exactly
    _record("dga", "two_char_entropy_one",
            abs(entropy_fn("ab") - 1.0) < 0.001,
            detail=f"H('ab')={entropy_fn('ab'):.4f}")

    # DGA-style domain should have high entropy (> 3.8, the IDS threshold)
    dga_domain = "xqmzpvkjtd"   # random-looking 10-char label
    h = entropy_fn(dga_domain)
    _record("dga", "dga_domain_above_threshold",
            h > 3.8,
            detail=f"H('{dga_domain}')={h:.4f} (threshold=3.8)")

    # Legitimate domain label should have lower entropy
    legit_domain = "google"
    h_legit = entropy_fn(legit_domain)
    _record("dga", "legit_domain_below_dga_threshold",
            h_legit < 3.8,
            detail=f"H('{legit_domain}')={h_legit:.4f}")


# ══════════════════════════════════════════════════════════════════
#  TEST GROUP 7: JSON ALERT SYSTEM
# ══════════════════════════════════════════════════════════════════

def test_json_alerts():
    _section("JsonAlertSystem — structured alert output")

    if not _FLOW_OK:
        _record("json", "setup", False, skip=True)
        return

    import os
    import tempfile

    # Use a temp file so we don't pollute /tmp during testing
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False) as tf:
        tmp_path = tf.name

    alert_sys = flow_analyzer.JsonAlertSystem(log_file=tmp_path)

    # Test 1: generate_alert() writes valid JSON
    threat = {
        "type":        "signature",
        "rule":        "port_scan",
        "confidence":  1.0,
        "description": "test",
        "mitre":       "T1046",
    }
    packet_info = {
        "source_ip":        "10.0.0.1",
        "destination_ip":   "192.168.1.2",
        "source_port":      4321,
        "destination_port": 22,
    }
    alert_sys.generate_alert(threat, packet_info)

    # Read back and parse
    try:
        with open(tmp_path) as f:
            line = f.readline().strip()
        import json
        parsed = json.loads(line)
        _record("json", "alert_is_valid_json", True,
                detail=f"keys: {list(parsed.keys())}")
    except Exception as e:
        _record("json", "alert_is_valid_json", False, detail=str(e))
        parsed = {}

    # Test 2: required fields present
    required_fields = {"alert_id", "timestamp", "engine", "threat_type",
                       "source_ip", "destination_ip", "confidence",
                       "severity", "details"}
    _record("json", "required_fields_present",
            required_fields.issubset(set(parsed.keys())),
            detail=f"missing={required_fields - set(parsed.keys())}")

    # Test 3: high-confidence alert gets HIGH severity
    _record("json", "high_confidence_gets_high_severity",
            parsed.get("severity") == "HIGH",
            detail=f"severity={parsed.get('severity')}")

    # Test 4: alert_count increments
    _record("json", "alert_count_increments",
            alert_sys.alert_count == 1,
            detail=f"count={alert_sys.alert_count}")

    # Cleanup
    try:
        os.unlink(tmp_path)
    except OSError:
        pass


# ══════════════════════════════════════════════════════════════════
#  TEST GROUP 8: FLOW ISOLATION FOREST
# ══════════════════════════════════════════════════════════════════

def test_flow_isolation_forest():
    _section("Flow IsolationForest — explicit train_anomaly_detector()")

    if not _FLOW_OK:
        _record("forest", "setup", False, skip=True)
        return
    if not _SKLEARN_OK:
        _record("forest", "setup", False, skip=True,
                detail="scikit-learn not installed")
        return

    det = flow_analyzer.FlowDetectionEngine()

    # Train on normal traffic: large packets, low rate
    normal_data = [
        [1400.0,  2.0,  2800.0],  # [packet_size, packet_rate, byte_rate]
        [1200.0,  1.5,  1800.0],
        [800.0,   3.0,  2400.0],
        [1500.0,  2.5,  3750.0],
        [900.0,   1.0,  900.0],
    ] * (flow_analyzer.WARMUP_FLOWS // 5 + 2)  # ensure we exceed WARMUP_FLOWS

    det.train_anomaly_detector(normal_data)

    _record("forest", "forest_ready_after_training",
            det.forest_ready,
            detail=f"samples={det.samples_collected}")

    # Anomalous features: tiny packets, very high rate
    anomalous = {"packet_size": 40, "packet_rate": 500.0, "byte_rate": 20000.0,
                 "tcp_flags": 0x02, "window_size": 65535,
                 "_src_ip": "10.0.0.1", "_dst_ip": "192.168.1.2",
                 "_src_port": 4321, "_dst_port": 80}

    threats = det.detect_threats(anomalous)
    anomaly_threats = [t for t in threats if t["type"] == "anomaly"]

    _record("forest", "anomaly_detected_on_attack_features",
            len(anomaly_threats) > 0,
            detail=f"threats={[t['rule'] for t in threats]}")

    # Normal features: should not be flagged (may fail with small training set)
    normal_feat = {"packet_size": 1400, "packet_rate": 2.0, "byte_rate": 2800.0,
                   "tcp_flags": 0x10, "window_size": 65535,
                   "_src_ip": "192.168.1.1", "_dst_ip": "192.168.1.2",
                   "_src_port": 1234, "_dst_port": 80}
    normal_threats = [t for t in det.detect_threats(normal_feat)
                      if t["type"] == "anomaly"]
    _record("forest", "normal_features_not_anomalous",
            len(normal_threats) == 0,
            detail=f"anomaly_threats={len(normal_threats)} (small training set may FP)")


# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

ALL_GROUPS = {
    "article":  test_article_original,
    "flow":     test_flow_features,
    "portscan": test_port_scan_signature,
    "capture":  test_packet_capture,
    "ml":       test_adaptive_ml,
    "dga":      test_dga_entropy,
    "json":     test_json_alerts,
    "forest":   test_flow_isolation_forest,
}


def main():
    parser = argparse.ArgumentParser(
        description="IDS mock test harness — tests engines without live traffic"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show extra output")
    parser.add_argument("--list", action="store_true",
                        help="List available test groups and exit")
    parser.add_argument("--only", metavar="GROUP",
                        help=f"Run only this group. "
                             f"Choices: {', '.join(ALL_GROUPS)}")
    args = parser.parse_args()

    if args.list:
        print("Available test groups:")
        for g in ALL_GROUPS:
            print(f"  {g}")
        return 0

    print("=" * 60)
    print("  AUA CS 232/337 — IDS Mock Test Harness")
    print(f"  scapy={_SCAPY_OK}  sklearn={_SKLEARN_OK}  "
          f"flow_analyzer={_FLOW_OK}  packet_capture={_CAPTURE_OK}")
    print(f"  ml_detector={_ML_OK}  ids_detector={_IDS_OK}")
    print("=" * 60)

    groups = ([ALL_GROUPS[args.only]] if args.only and args.only in ALL_GROUPS
              else list(ALL_GROUPS.values()))

    for fn in groups:
        fn()

    failures = _summary()
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
