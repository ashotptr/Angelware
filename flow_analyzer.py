"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Flow Analyzer + Engine 15 (Flow-Level Detection)
 Source: freeCodeCamp "How to Build a Real-Time IDS with Python"
         Chaitanya Rahalkar, January 2025
====================================================

WHAT THIS ADDS (things genuinely absent from the project):

1. TrafficAnalyzer — per-flow feature extraction
   -----------------------------------------------
   Tracks (src_ip, dst_ip, src_port, dst_port) flows and extracts:
     packet_size, flow_duration, packet_rate, byte_rate,
     tcp_flags, window_size
   No existing engine in ids_detector.py does per-flow tracking.
   Engines 1–14 all work with per-IP counters only.

2. Port scan signature (article rule, missing from the project)
   ------------------------------------------------------------
   Rule: packet_size < 100 AND packet_rate > 50 req/s
   Engine 11 detects port scans via RST-burst and SYN-burst at the
   IP level. This rule fires at the *flow* level — it detects a scan
   of a *specific port* from a *specific source* before the RST
   pattern accumulates, giving earlier warning.
   These two detectors are complementary, not redundant.

3. Flow-level IsolationForest
   --------------------------
   Engine 8 (ml_detector.py) trains an IsolationForest on
   login-analytics features [cv, rate, success_pct, unknown_pct] —
   application-layer signals derived from HTTP POST behaviour.
   This engine trains a separate IsolationForest on raw network
   flow features [packet_size, packet_rate, byte_rate] — the exact
   feature vector in the article, operating at L3/L4.
   The two forests watch different protocol layers and can fire
   independently.

4. JSON alert output (ids_flow_alerts.json)
   -----------------------------------------
   The existing alert() function in ids_detector.py writes plain-text
   to /tmp/ids.log. This adds a PARALLEL JSON log —
   /tmp/ids_flow_alerts.json — one JSON object per line, suitable for
   ingestion into a SIEM or log aggregator. Plain-text log is
   unaffected (no regression).

INTEGRATION:
  ids_detector_e15_integration.py auto-patches ids_detector.py to
  import this module and call process_flow_packet(pkt) inside
  packet_handler(). Without the patch, this file runs standalone.

STANDALONE USAGE:
  python3 flow_analyzer.py        # runs the built-in demo
"""

import json
import logging
import math
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ── Optional sklearn import (mirrors ml_detector.py approach) ────
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    _SKLEARN_OK = True
except ImportError:
    _SKLEARN_OK = False

try:
    from scapy.layers.inet import IP, TCP, UDP
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False


# ══════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════

# Signature thresholds (from article)
SIG_PORT_SCAN_PKT_SIZE   = 100    # bytes — small probe packets
SIG_PORT_SCAN_RATE       = 50.0   # packets/s — rapid port probing
SIG_SYN_FLOOD_FLAGS      = 0x02   # SYN-only flag value
SIG_SYN_FLOOD_RATE       = 100.0  # packets/s — volumetric

# Anomaly detection thresholds (from article)
ANOMALY_SCORE_THRESHOLD  = -0.5   # IsolationForest score below this → flag

# Flow tracking
FLOW_EXPIRY_SEC          = 120.0  # flows older than this are pruned
FLOW_MIN_PACKETS         = 3      # minimum packets before we extract features
WARMUP_FLOWS             = 30     # flows before IsolationForest activates

# Alert cooldown per flow key (avoid repeated alerts on the same flow)
ALERT_COOLDOWN_SEC       = 30.0

# JSON alert log
JSON_ALERT_LOG           = "/tmp/ids_flow_alerts.json"

# Engine identifier
ENGINE_ID   = 15
ENGINE_NAME = "Engine15/FlowAnalysis"


# ══════════════════════════════════════════════════════════════════
#  JSON ALERT SYSTEM
#  (parallel to ids_detector.py plain-text alerts — no regression)
# ══════════════════════════════════════════════════════════════════

class JsonAlertSystem:
    """
    Writes structured JSON alerts to a file, one object per line.

    Format (NDJSON / JSON Lines):
      {"timestamp": "...", "engine": "...", "threat_type": "signature",
       "rule": "port_scan", "source_ip": "...", "destination_ip": "...",
       "confidence": 1.0, "details": {...}}

    This is a parallel output channel alongside the existing plain-text
    /tmp/ids.log written by ids_detector.py. Both can be active at once.
    The JSON file is suitable for SIEM ingestion (Splunk, Elastic, etc.)

    Matches the article's AlertSystem.generate_alert() interface closely,
    but adapted to work without the logging module so it stays orthogonal
    to ids_detector.py's existing logging setup.
    """

    def __init__(self, log_file: str = JSON_ALERT_LOG):
        self.log_file  = log_file
        self._lock     = threading.Lock()
        self._count    = 0
        # One-time initialise the file
        try:
            with open(self.log_file, "a") as _:
                pass
        except OSError as e:
            print(f"[{ENGINE_NAME}] WARNING: Cannot open JSON log {log_file}: {e}")

    def generate_alert(self, threat: dict, packet_info: dict) -> None:
        """
        Write a structured alert.  Mirrors the article's generate_alert().

        Args:
            threat:      dict with 'type', 'rule'/'score', 'confidence'
            packet_info: dict with 'source_ip', 'destination_ip',
                         'source_port', 'destination_port'
        """
        with self._lock:
            self._count += 1
            alert = {
                "alert_id":       self._count,
                "timestamp":      datetime.now().isoformat(),
                "engine":         ENGINE_NAME,
                "threat_type":    threat.get("type", "unknown"),
                "rule":           threat.get("rule", ""),
                "source_ip":      packet_info.get("source_ip", ""),
                "destination_ip": packet_info.get("destination_ip", ""),
                "source_port":    packet_info.get("source_port", 0),
                "destination_port": packet_info.get("destination_port", 0),
                "confidence":     round(threat.get("confidence", 0.0), 4),
                "details":        threat,
            }

            # Article escalation: log separately if high confidence
            if threat.get("confidence", 0.0) > 0.8:
                alert["severity"] = "HIGH"
            else:
                alert["severity"] = "MED"

            try:
                with open(self.log_file, "a") as fh:
                    fh.write(json.dumps(alert) + "\n")
            except OSError:
                pass

    @property
    def alert_count(self) -> int:
        with self._lock:
            return self._count


# ══════════════════════════════════════════════════════════════════
#  TRAFFIC ANALYZER
#  Per-flow feature extraction (article's TrafficAnalyzer, enhanced)
# ══════════════════════════════════════════════════════════════════

FlowKey = Tuple[str, str, int, int]   # (src_ip, dst_ip, src_port, dst_port)

class TrafficAnalyzer:
    """
    Extracts per-flow feature vectors from raw Scapy packets.

    Flow key: (src_ip, dst_ip, src_port, dst_port) — same as article.
    Maintains rolling flow state and emits feature dicts suitable for
    both signature rules and the IsolationForest.

    Features extracted (article's exact set):
      packet_size   : bytes in this packet
      flow_duration : seconds since first packet in flow
      packet_rate   : packets/s over flow lifetime
      byte_rate     : bytes/s over flow lifetime
      tcp_flags     : integer flag field (0x02 = SYN, 0x04 = RST, etc.)
      window_size   : TCP window size

    Enhancement over article: automatic flow expiry prunes stale flows
    to prevent unbounded memory growth during long lab runs.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # flow_key → { packet_count, byte_count, start_time, last_time }
        self.flow_stats: Dict[FlowKey, dict] = {}

    def analyze_packet(self, packet) -> Optional[dict]:
        """
        Process one Scapy packet.  Returns a feature dict, or None if
        the packet does not carry IP+TCP layers.
        """
        if not _SCAPY_OK:
            return None
        if IP not in packet or TCP not in packet:
            return None

        ip_src   = packet[IP].src
        ip_dst   = packet[IP].dst
        port_src = packet[TCP].sport
        port_dst = packet[TCP].dport

        flow_key = (ip_src, ip_dst, port_src, port_dst)
        pkt_len  = len(packet)
        now      = float(packet.time) if hasattr(packet, "time") else time.time()

        with self._lock:
            if flow_key not in self.flow_stats:
                self.flow_stats[flow_key] = {
                    "packet_count": 0,
                    "byte_count":   0,
                    "start_time":   now,
                    "last_time":    now,
                }
            stats = self.flow_stats[flow_key]
            stats["packet_count"] += 1
            stats["byte_count"]   += pkt_len
            stats["last_time"]     = now

        return self._extract_features(packet, stats)

    def _extract_features(self, packet, stats: dict) -> dict:
        """Article's extract_features(), unchanged."""
        duration = max(stats["last_time"] - stats["start_time"], 1e-6)
        return {
            "packet_size":   len(packet),
            "flow_duration": duration,
            "packet_rate":   stats["packet_count"] / duration,
            "byte_rate":     stats["byte_count"]   / duration,
            "tcp_flags":     int(packet[TCP].flags),
            "window_size":   packet[TCP].window,
            # Extra context for alert messages (not in article)
            "_src_ip":       packet[IP].src,
            "_dst_ip":       packet[IP].dst,
            "_src_port":     packet[TCP].sport,
            "_dst_port":     packet[TCP].dport,
        }

    def expire_old_flows(self, max_age: float = FLOW_EXPIRY_SEC) -> int:
        """
        Remove flows not updated within max_age seconds.
        Call periodically (e.g. every 60s) to bound memory use.
        Returns number of flows pruned.
        """
        now    = time.time()
        cutoff = now - max_age
        pruned = 0
        with self._lock:
            to_del = [k for k, v in self.flow_stats.items()
                      if v["last_time"] < cutoff]
            for k in to_del:
                del self.flow_stats[k]
                pruned += 1
        return pruned

    @property
    def active_flows(self) -> int:
        with self._lock:
            return len(self.flow_stats)


# ══════════════════════════════════════════════════════════════════
#  DETECTION ENGINE
#  Signature + flow-level IsolationForest (article's DetectionEngine)
# ══════════════════════════════════════════════════════════════════

class FlowDetectionEngine:
    """
    Hybrid signature + anomaly detector operating on flow features.

    Signature rules (from the article):
      syn_flood  : SYN flag set AND packet_rate > 100 pkt/s
      port_scan  : packet_size < 100 bytes AND packet_rate > 50 pkt/s
                   ← THIS IS NEW; Engine 11 detects scans differently
                      (RST/SYN burst at IP level, not flow rate+size).

    Anomaly (IsolationForest on flow features):
      Feature vector: [packet_size, packet_rate, byte_rate]
      Same as the article. Distinct from Engine 8's feature vector
      [cv, rate, success_pct, unknown_pct] which is application-layer.
      These two forests fire on different evidence and are independent.

    Auto-training:
      The first WARMUP_FLOWS feature vectors are collected as normal-
      traffic baseline. After that, the forest is trained and anomaly
      scoring activates. The forest retrains every WARMUP_FLOWS new
      samples (same strategy as ml_detector.py Engine 8).
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Signature rules (article's load_signature_rules())
        self.signature_rules = {
            "syn_flood": {
                "condition": lambda f: (
                    f["tcp_flags"] == SIG_SYN_FLOOD_FLAGS and
                    f["packet_rate"] > SIG_SYN_FLOOD_RATE
                ),
                "description": (
                    f"SYN flag + packet_rate > {SIG_SYN_FLOOD_RATE} pkt/s"
                ),
                "mitre": "T1498.001 (Network Flood)",
            },
            # ← PORT SCAN: genuinely new. Not present anywhere in the project.
            "port_scan": {
                "condition": lambda f: (
                    f["packet_size"] < SIG_PORT_SCAN_PKT_SIZE and
                    f["packet_rate"] > SIG_PORT_SCAN_RATE
                ),
                "description": (
                    f"packet_size < {SIG_PORT_SCAN_PKT_SIZE}B + "
                    f"packet_rate > {SIG_PORT_SCAN_RATE} pkt/s "
                    f"(probe packet pattern)"
                ),
                "mitre": "T1046 (Network Service Discovery)",
            },
        }

        # IsolationForest state (article's train_anomaly_detector())
        self._training_data: List[List[float]] = []
        self._forest: Optional[object]         = None
        self._forest_sample_count              = 0
        self._forest_ready                     = False

        # Per-flow alert cooldown to prevent alert storms
        self._alerted: Dict[str, float] = {}   # rule+flow_key → last alert ts

    def _maybe_train(self) -> None:
        """Auto-train / retrain IsolationForest on accumulated data."""
        if not _SKLEARN_OK:
            return
        n = len(self._training_data)
        if n < WARMUP_FLOWS:
            return
        if n % WARMUP_FLOWS != 0 and self._forest_ready:
            return   # retrain every WARMUP_FLOWS new samples

        X = np.array(self._training_data[-500:])   # rolling window of 500
        self._forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100,
        ).fit(X)
        self._forest_ready = True

    def train_anomaly_detector(self, normal_traffic_data: list) -> None:
        """
        Article's train_anomaly_detector() — explicit training entry point.
        Also used by test_ids_mock.py.

        Args:
            normal_traffic_data: list of [packet_size, packet_rate, byte_rate]
        """
        if not _SKLEARN_OK:
            print(f"[{ENGINE_NAME}] sklearn not available; "
                  "pip install scikit-learn to enable IsolationForest")
            return
        X = np.array(normal_traffic_data)
        self._forest = IsolationForest(contamination=0.1, random_state=42)
        self._forest.fit(X)
        self._forest_ready = True
        print(f"[{ENGINE_NAME}] IsolationForest trained on "
              f"{len(normal_traffic_data)} samples")

    def detect_threats(self, features: dict) -> List[dict]:
        """
        Article's detect_threats() — evaluate features against all rules.

        Returns a list of threat dicts:
          [{'type': 'signature', 'rule': 'port_scan', 'confidence': 1.0,
            'description': '...', 'mitre': '...'}, ...]
        """
        threats = []

        # ── Signature-based detection (article, verbatim logic) ──
        for rule_name, rule in self.signature_rules.items():
            try:
                if rule["condition"](features):
                    threats.append({
                        "type":        "signature",
                        "rule":        rule_name,
                        "confidence":  1.0,
                        "description": rule["description"],
                        "mitre":       rule["mitre"],
                        "packet_rate": round(features["packet_rate"], 2),
                        "packet_size": features["packet_size"],
                        "tcp_flags":   hex(features["tcp_flags"]),
                    })
            except Exception:
                pass

        # ── Anomaly-based detection (article, verbatim logic) ────
        with self._lock:
            vec = [
                features["packet_size"],
                features["packet_rate"],
                features["byte_rate"],
            ]
            self._training_data.append(vec)
            self._forest_sample_count += 1
            self._maybe_train()

            if self._forest_ready and _SKLEARN_OK:
                feature_vector = np.array([vec])
                # Article's exact threshold: anomaly_score < -0.5
                anomaly_score = float(
                    self._forest.score_samples(feature_vector)[0]
                )
                if anomaly_score < ANOMALY_SCORE_THRESHOLD:
                    threats.append({
                        "type":       "anomaly",
                        "rule":       "isolation_forest_flow",
                        "score":      round(anomaly_score, 4),
                        "confidence": min(1.0, abs(anomaly_score)),
                        "description": (
                            f"Flow features outside learned normal distribution. "
                            f"IF score={anomaly_score:.4f} "
                            f"(threshold: {ANOMALY_SCORE_THRESHOLD})"
                        ),
                        "mitre": "T1595 (Active Reconnaissance)",
                    })

        return threats

    @property
    def forest_ready(self) -> bool:
        return self._forest_ready

    @property
    def samples_collected(self) -> int:
        return self._forest_sample_count


# ══════════════════════════════════════════════════════════════════
#  ENGINE 15 — TOP-LEVEL WRAPPER
#  (article's IntrusionDetectionSystem, adapted as a module-level
#   engine that plugs into ids_detector.py's packet_handler())
# ══════════════════════════════════════════════════════════════════

class Engine15FlowIDS:
    """
    Wrapper tying TrafficAnalyzer + FlowDetectionEngine + JsonAlertSystem.

    Designed to be called from ids_detector.py's packet_handler():

        # In ids_detector.py (added by ids_detector_e15_integration.py):
        try:
            import flow_analyzer as _e15
            _e15_engine = _e15.Engine15FlowIDS()
            E15_OK = True
        except ImportError:
            E15_OK = False

        def packet_handler(pkt):
            process_volumetric(pkt)
            ...
            if E15_OK:
                _e15_engine.process_packet(pkt)   # ← new line

    Also usable standalone for testing and as a teaching example
    (article's IntrusionDetectionSystem class, section "Putting It
    All Together").
    """

    def __init__(self, json_log: str = JSON_ALERT_LOG):
        self.analyzer  = TrafficAnalyzer()
        self.detector  = FlowDetectionEngine()
        self.alert_sys = JsonAlertSystem(log_file=json_log)

        # Alert cooldown state (per rule+src_ip to prevent storms)
        self._cooldown: Dict[str, float] = {}
        self._cooldown_lock = threading.Lock()

        # Maintenance: prune old flows every 60 s
        self._pruner = threading.Thread(
            target=self._prune_loop,
            daemon=True,
            name="e15-flow-pruner",
        )
        self._pruner.start()

    def process_packet(self, packet) -> List[dict]:
        """
        Main entry point — called once per captured packet.

        Returns the list of threats detected (empty list if none).
        Threat dicts are also written to the JSON alert log.
        """
        features = self.analyzer.analyze_packet(packet)
        if not features:
            return []

        threats = self.detector.detect_threats(features)

        for threat in threats:
            cooldown_key = f"{threat['rule']}-{features['_src_ip']}"
            now = time.time()

            with self._cooldown_lock:
                last = self._cooldown.get(cooldown_key, 0.0)
                if now - last < ALERT_COOLDOWN_SEC:
                    continue
                self._cooldown[cooldown_key] = now

            packet_info = {
                "source_ip":        features["_src_ip"],
                "destination_ip":   features["_dst_ip"],
                "source_port":      features["_src_port"],
                "destination_port": features["_dst_port"],
            }
            self.alert_sys.generate_alert(threat, packet_info)

            # Also call ids_detector.py's alert() if we're integrated
            _ids_alert = globals().get("_ids_alert_fn")
            if _ids_alert:
                rule = threat.get("rule", "unknown")
                desc = threat.get("description", "")
                mitre = threat.get("mitre", "")
                _ids_alert(
                    ENGINE_NAME,
                    "HIGH" if threat.get("confidence", 0) >= 1.0 else "MED",
                    f"FLOW-LEVEL {rule.upper().replace('_', ' ')} detected\n"
                    f"  Source:      {features['_src_ip']}:{features['_src_port']}\n"
                    f"  Destination: {features['_dst_ip']}:{features['_dst_port']}\n"
                    f"  Packet rate: {features['packet_rate']:.1f} pkt/s\n"
                    f"  Packet size: {features['packet_size']} bytes\n"
                    f"  Byte rate:   {features['byte_rate']:.0f} B/s\n"
                    f"  TCP flags:   {hex(features['tcp_flags'])}\n"
                    f"  Rule:        {desc}\n"
                    f"  Confidence:  {threat.get('confidence', 0):.2f}\n"
                    f"  JSON log:    {self.alert_sys.log_file}\n"
                    f"  MITRE: {mitre}",
                )

        return threats

    def _prune_loop(self) -> None:
        """Background thread: prune expired flows every 60 seconds."""
        while True:
            time.sleep(60)
            pruned = self.analyzer.expire_old_flows()
            if pruned > 0:
                print(f"[{ENGINE_NAME}] Pruned {pruned} expired flows "
                      f"({self.analyzer.active_flows} active)")

    def register_alert_fn(self, fn) -> None:
        """
        Register ids_detector.py's alert() function so this engine
        writes to the main alert log in addition to the JSON file.

        Called by ids_detector_e15_integration.py after import.
        """
        globals()["_ids_alert_fn"] = fn

    def status(self) -> dict:
        return {
            "engine":           ENGINE_NAME,
            "active_flows":     self.analyzer.active_flows,
            "samples_collected": self.detector.samples_collected,
            "forest_ready":     self.detector.forest_ready,
            "json_alerts_fired": self.alert_sys.alert_count,
            "json_log":         self.alert_sys.log_file,
            "sklearn_available": _SKLEARN_OK,
        }


# ── Module-level singleton (imported by ids_detector.py) ─────────
_engine = None

def get_engine() -> Engine15FlowIDS:
    """Return or create the module-level singleton."""
    global _engine
    if _engine is None:
        _engine = Engine15FlowIDS()
    return _engine


def process_flow_packet(packet) -> List[dict]:
    """
    Module-level entry point for ids_detector.py packet_handler().

    Usage in ids_detector.py (one line):
        import flow_analyzer as _e15_mod
        ...
        def packet_handler(pkt):
            ...
            _e15_mod.process_flow_packet(pkt)   # Engine 15
    """
    return get_engine().process_packet(packet)


# ══════════════════════════════════════════════════════════════════
#  STANDALONE DEMO
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print(f" {ENGINE_NAME} — standalone demo")
    print("=" * 60)

    if not _SCAPY_OK:
        print("[ERROR] Scapy not installed. pip3 install scapy")
        raise SystemExit(1)

    from scapy.all import IP, TCP, Ether

    engine = Engine15FlowIDS()
    print(f"\nEngine status: {engine.status()}\n")

    # Build synthetic packets that match the two signature rules
    def make_pkt(src, dst, sport, dport, flags, size=60):
        """Create a minimal Scapy IP/TCP packet with controlled size."""
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
        # Pad to requested size
        current = len(pkt)
        if size > current:
            from scapy.all import Raw
            pkt = pkt / Raw(b"\x00" * (size - current))
        return pkt

    print("--- Simulating port scan (small packets, high rate) ---")
    for i in range(5):
        pkt = make_pkt("10.0.0.1", "192.168.100.20",
                       4000 + i, 22 + i * 100,
                       flags="S", size=40)
        # Fake a high packet_rate by setting packet time manually
        pkt.time = time.time() - 0.01 * i
        threats = engine.process_packet(pkt)
        if threats:
            for t in threats:
                print(f"  THREAT: {t['rule']} "
                      f"(conf={t['confidence']:.2f})")

    print("\n--- Simulating SYN flood (SYN flag + high rate) ---")
    for i in range(5):
        pkt = make_pkt("10.0.0.2", "192.168.100.20",
                       5000 + i, 80,
                       flags="S", size=60)
        pkt.time = time.time() - 0.005 * i
        threats = engine.process_packet(pkt)
        if threats:
            for t in threats:
                print(f"  THREAT: {t['rule']} "
                      f"(conf={t['confidence']:.2f})")

    print(f"\nFinal status: {engine.status()}")
    print(f"JSON alerts written to: {JSON_ALERT_LOG}")

    # Show JSON output
    try:
        with open(JSON_ALERT_LOG) as f:
            lines = f.readlines()
        if lines:
            print(f"\nSample JSON alert ({len(lines)} total):")
            print(json.dumps(json.loads(lines[-1]), indent=2))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
