"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Queue-Buffered Packet Capture
 Source: freeCodeCamp "How to Build a Real-Time IDS with Python"
         Chaitanya Rahalkar, January 2025
====================================================

Adds the PacketCapture class from the article.

WHY THIS IS USEFUL FOR THE PROJECT:
  ids_detector.py calls sniff() directly with per-engine callbacks.
  Under a SYN flood or UDP flood (the exact attacks this lab generates),
  slow callbacks (Engine 5's urllib call, Engine 8's IsolationForest
  inference, Engine 12's psutil process scan) can cause Scapy to fall
  behind the kernel receive buffer and silently drop packets.

  This class decouples capture from processing via a bounded queue:
    capture thread  →  queue  →  processing thread(s)

  The kernel never blocks. If the queue fills, the oldest packets are
  dropped gracefully (maxsize) rather than stalling capture. This is
  especially important for measuring Engine 1 (volumetric) accuracy
  in Graph 3 — missed SYN packets produce false negatives.

INTEGRATION WITH ids_detector.py:
  See ids_detector_e15_integration.py — it patches ids_detector.py
  to optionally use this class. The existing sniff() path is kept as
  fallback; nothing regresses if this file is absent.

STANDALONE USAGE:
  from packet_capture import PacketCapture
  cap = PacketCapture(maxsize=10000)
  cap.start_capture("lo")
  try:
      while True:
          pkt = cap.get_packet(timeout=1.0)
          if pkt:
              your_handler(pkt)
  except KeyboardInterrupt:
      cap.stop()
"""

import queue
import threading
from typing import Optional

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.all import sniff
    _SCAPY_OK = True
except Exception:
    _SCAPY_OK = False


class PacketCapture:
    """
    Thread-safe, queue-buffered wrapper around Scapy's sniff().

    The article's original implementation used an unbounded queue.Queue.
    This version adds:
      - maxsize parameter: bounded queue prevents unbounded memory growth
        during SYN/UDP floods (the lab's primary stress scenario)
      - dropped_count: observable metric for performance tuning
      - get_packet(): convenience method with timeout that returns None
        instead of raising queue.Empty (cleaner consumer loop)
      - stats(): snapshot of capture health

    These additions are non-breaking; the original article interface
    (packet_queue.get(timeout=1), stop_capture event, capture_thread)
    is preserved exactly.
    """

    def __init__(self, interface: str = "lo", maxsize: int = 5000):
        """
        Args:
            interface: Network interface to capture on.
                       Default 'lo' matches ids_detector.py MONITOR_INTERFACE.
                       Change to 'enp0s3' on the real VM.
            maxsize:   Maximum packets held in queue before dropping.
                       5000 is empirically safe for 1 Gbit lab traffic.
                       Set 0 for unbounded (original article behaviour).
        """
        self.interface     = interface
        self.packet_queue  = queue.Queue(maxsize=maxsize)
        self.stop_capture  = threading.Event()
        self.capture_thread: Optional[threading.Thread] = None

        # Observability counters
        self._captured_count = 0
        self._dropped_count  = 0
        self._lock           = threading.Lock()

    # ── Article interface (unchanged) ────────────────────────────

    def packet_callback(self, packet) -> None:
        """
        Called by Scapy for every captured packet.
        Filters to IP/TCP or IP/UDP (same as the article).
        """
        if not _SCAPY_OK:
            return
        if IP in packet and (TCP in packet or UDP in packet):
            with self._lock:
                self._captured_count += 1
            try:
                # put_nowait: never block the sniff thread
                self.packet_queue.put_nowait(packet)
            except queue.Full:
                # Queue full → drop oldest packet, insert new one
                # This keeps the queue fresh (recent traffic > stale traffic)
                with self._lock:
                    self._dropped_count += 1
                try:
                    self.packet_queue.get_nowait()   # discard oldest
                    self.packet_queue.put_nowait(packet)
                except queue.Empty:
                    pass

    def start_capture(self, interface: str = None) -> None:
        """
        Start capturing packets in a background daemon thread.
        Matches article signature: start_capture(interface="eth0")
        """
        if not _SCAPY_OK:
            print("[PacketCapture] ERROR: Scapy not installed. "
                  "Run: pip3 install scapy")
            return

        iface = interface or self.interface

        def capture_thread():
            sniff(
                iface=iface,
                prn=self.packet_callback,
                store=False,                          # don't hold packets in Scapy memory
                stop_filter=lambda _: self.stop_capture.is_set(),
            )

        self.capture_thread = threading.Thread(
            target=capture_thread,
            daemon=True,
            name=f"packet-capture-{iface}",
        )
        self.capture_thread.start()
        print(f"[PacketCapture] Capturing on {iface} "
              f"(queue maxsize={self.packet_queue.maxsize})")

    def stop(self) -> None:
        """
        Signal the capture thread to stop and wait for it to finish.
        Matches article signature.
        """
        self.stop_capture.set()
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5.0)
        print(f"[PacketCapture] Stopped. "
              f"Captured={self._captured_count}  "
              f"Dropped={self._dropped_count}")

    # ── Extended interface (additions beyond the article) ────────

    def get_packet(self, timeout: float = 1.0) -> Optional[object]:
        """
        Convenience method: returns a packet or None on timeout.
        Avoids try/except queue.Empty boilerplate in consumer loops.

        Usage:
            pkt = cap.get_packet(timeout=0.5)
            if pkt:
                process(pkt)
        """
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def stats(self) -> dict:
        """
        Snapshot of capture health for monitoring and test assertions.

        Returns:
            {
                'captured': int,   # total packets enqueued
                'dropped':  int,   # packets dropped due to full queue
                'queued':   int,   # packets currently in queue
                'drop_pct': float, # drop rate (0-100)
            }
        """
        with self._lock:
            cap = self._captured_count
            drp = self._dropped_count
        return {
            "captured": cap,
            "dropped":  drp,
            "queued":   self.packet_queue.qsize(),
            "drop_pct": round(100.0 * drp / max(1, cap), 2),
        }

    def drain(self) -> list:
        """
        Drain all pending packets from the queue and return them as a list.
        Useful in test_ids_mock.py to process a batch of synthetic packets.
        """
        packets = []
        while True:
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets

    def __repr__(self) -> str:
        s = self.stats()
        return (
            f"PacketCapture(iface={self.interface!r}, "
            f"captured={s['captured']}, dropped={s['dropped']}, "
            f"queued={s['queued']})"
        )


if __name__ == "__main__":
    # Quick self-test: run for 5 seconds and report stats
    import time
    print("PacketCapture self-test — capturing on loopback for 5s")
    print("Generate some traffic: ping 127.0.0.1 -c 20")
    cap = PacketCapture(interface="lo", maxsize=1000)
    cap.start_capture()
    time.sleep(5)
    cap.stop()
    print(f"Stats: {cap.stats()}")
