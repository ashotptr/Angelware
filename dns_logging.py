"""
====================================================
 AUA CS 232/337 — Botnet Research Project
 Component: Structured Logging System
 Environment: ISOLATED VM LAB ONLY
====================================================

Mirrors Spinnekop:
  internal/logging/logging_srv.go  (Initialize, setupLogging)
  internal/logging/helpers.go      (Info, Debug, Warn, Error,
                                    WithComponent, WithFields,
                                    ForRequest, DNSLogger)

Features:
  - Log levels:  DEBUG, INFO, WARN, ERROR
  - Formats:     TEXT (human-readable key=value) | JSON (machine-parseable)
  - Outputs:     STDOUT | STDERR | any file path
  - Sub-loggers: get_logger(component), for_request(client_ip, request_id)
  - Prefix:      "[*]" matching Spinnekop's prefixWriter

Usage:
  import dns_logging as log

  log.initialize(level="DEBUG", fmt="TEXT", output="STDOUT")

  log.info("Server started", address="0.0.0.0:53", workers=4)
  log.debug("Packet received", size=45, client="192.168.1.1")
  log.warn("Non-standard class", client="10.0.0.1", qclass=67)
  log.error("Failed to bind", port=53, reason="permission denied")

  dns_log = log.get_logger("dns_handler")
  dns_log.info("Query received", domain="www.example.com", type="A")

  req_log = log.for_request("192.168.1.5", 1234)
  req_log.debug("Processing", step="parse")
"""

import json
import sys
import threading
from datetime import datetime
from typing import Any, Dict, IO, Optional

# ── Level constants ───────────────────────────────────────────

LEVEL_DEBUG = 10
LEVEL_INFO  = 20
LEVEL_WARN  = 30
LEVEL_ERROR = 40

_LEVEL_NAMES: Dict[int, str] = {
    LEVEL_DEBUG: "DEBUG",
    LEVEL_INFO:  "INFO",
    LEVEL_WARN:  "WARN",
    LEVEL_ERROR: "ERROR",
}
_NAME_TO_LEVEL: Dict[str, int] = {v: k for k, v in _LEVEL_NAMES.items()}

# ── Global state ──────────────────────────────────────────────

_global_logger: Optional["Logger"] = None
_init_lock = threading.Lock()


# ═════════════════════════════════════════════════════════════
#  Logger class
# ═════════════════════════════════════════════════════════════

class Logger:
    """
    Structured logger.

    TEXT format:
      [*] time=2024-01-20T10:30:00.123 level=INFO msg='Server started' address='0.0.0.0:53'

    JSON format:
      {"time": "2024-01-20T10:30:00.123", "level": "INFO",
       "msg": "Server started", "address": "0.0.0.0:53"}
    """

    def __init__(self,
                 level:     int  = LEVEL_DEBUG,
                 fmt:       str  = "TEXT",
                 output:    IO   = None,
                 component: str  = "",
                 extra:     Optional[Dict[str, Any]] = None):
        self._level     = level
        self._fmt       = fmt.upper()
        self._output    = output if output is not None else sys.stdout
        self._component = component
        self._extra:    Dict[str, Any] = extra or {}
        self._lock      = threading.Lock()

    # ── Public API ───────────────────────────────────────────

    def debug(self, msg: str, **fields) -> None:
        self._emit(LEVEL_DEBUG, msg, fields)

    def info(self, msg: str, **fields) -> None:
        self._emit(LEVEL_INFO, msg, fields)

    def warn(self, msg: str, **fields) -> None:
        self._emit(LEVEL_WARN, msg, fields)

    def error(self, msg: str, **fields) -> None:
        self._emit(LEVEL_ERROR, msg, fields)

    def with_component(self, component: str) -> "Logger":
        """Return a child logger bound to a component name."""
        return Logger(self._level, self._fmt, self._output,
                      component=component, extra=dict(self._extra))

    def with_fields(self, **fields) -> "Logger":
        """Return a child logger with additional static fields."""
        return Logger(self._level, self._fmt, self._output,
                      component=self._component,
                      extra={**self._extra, **fields})

    def for_request(self, client_ip: str, request_id: int) -> "Logger":
        """
        Return a request-scoped logger.
        Mirrors Spinnekop logging.ForRequest().
        """
        return self.with_fields(client=client_ip, request_id=request_id)

    # ── DNS-specific convenience methods ─────────────────────
    # Mirrors Spinnekop logging.DNSLogger

    def query_received(self, client: str, domain: str,
                       qtype: str, qclass: int) -> None:
        self.info("DNS query received",
                  client=client, domain=domain, type=qtype, qclass=qclass)

    def non_standard_class(self, client: str, domain: str, qclass: int) -> None:
        self.warn("Non-standard DNS class detected",
                  client=client, domain=domain, qclass=qclass,
                  alert="possible_dns_tunneling")

    def response_sent(self, client: str, rcode: int, answers: int) -> None:
        self.debug("DNS response sent",
                   client=client, rcode=rcode, answers=answers)

    # ── Internal ─────────────────────────────────────────────

    def _emit(self, level: int, msg: str, fields: Dict[str, Any]) -> None:
        if level < self._level:
            return

        all_fields: Dict[str, Any] = {}
        if self._component:
            all_fields["component"] = self._component
        all_fields.update(self._extra)
        all_fields.update(fields)

        ts = datetime.now().isoformat(timespec="milliseconds")
        level_name = _LEVEL_NAMES.get(level, str(level))

        if self._fmt == "JSON":
            record = {"time": ts, "level": level_name, "msg": msg, **all_fields}
            line = json.dumps(record, default=str)
        else:
            # TEXT: time=... level=... msg=... k=v ...
            parts = [f"time={ts}", f"level={level_name}", f"msg={msg!r}"]
            for k, v in all_fields.items():
                parts.append(f"{k}={v!r}")
            line = " ".join(parts)

        with self._lock:
            try:
                print(f"[*] {line}", file=self._output, flush=True)
            except Exception:
                pass   # never crash the server due to a logging failure


# ═════════════════════════════════════════════════════════════
#  Module-level API
# ═════════════════════════════════════════════════════════════

def initialize(level:  str = "DEBUG",
               fmt:    str = "TEXT",
               output: str = "STDOUT") -> Logger:
    """
    Initialize the global logger.  Call once at startup.
    Mirrors Spinnekop logging.Initialize().

    Args:
        level:  DEBUG | INFO | WARN | ERROR
        fmt:    TEXT | JSON
        output: STDOUT | STDERR | /path/to/file.log
    """
    global _global_logger
    with _init_lock:
        lvl = _NAME_TO_LEVEL.get(level.upper(), LEVEL_DEBUG)
        out_upper = output.upper()
        if out_upper == "STDOUT":
            out_io: IO = sys.stdout
        elif out_upper == "STDERR":
            out_io = sys.stderr
        else:
            try:
                out_io = open(output, "a", buffering=1)
            except OSError as e:
                print(f"[logging] WARNING: could not open log file '{output}': {e}",
                      file=sys.stderr)
                out_io = sys.stdout

        _global_logger = Logger(level=lvl, fmt=fmt.upper(), output=out_io)
        return _global_logger


def get_logger(component: str = "") -> Logger:
    """Return the global logger, optionally scoped to a component."""
    global _global_logger
    if _global_logger is None:
        _global_logger = Logger()          # lazy default
    if component:
        return _global_logger.with_component(component)
    return _global_logger


def for_request(client_ip: str, request_id: int) -> Logger:
    """Shortcut: request-scoped logger from the global instance."""
    return get_logger().for_request(client_ip, request_id)


# ── Module-level convenience shortcuts ───────────────────────

def debug(msg: str, **fields) -> None:
    get_logger().debug(msg, **fields)

def info(msg: str, **fields) -> None:
    get_logger().info(msg, **fields)

def warn(msg: str, **fields) -> None:
    get_logger().warn(msg, **fields)

def error(msg: str, **fields) -> None:
    get_logger().error(msg, **fields)


# ── Initialize from a config dict ────────────────────────────

def initialize_from_config(cfg: dict) -> Logger:
    """
    Initialize from a loaded YAML/dict config block.
    Expects: cfg["logging"] = {level, format, output, ...}
    """
    log_cfg = cfg.get("logging", {})
    return initialize(
        level  = log_cfg.get("level",  "DEBUG"),
        fmt    = log_cfg.get("format", "TEXT"),
        output = log_cfg.get("output", "STDOUT"),
    )


# ── Self-test ─────────────────────────────────────────────────

if __name__ == "__main__":
    initialize(level="DEBUG", fmt="TEXT", output="STDOUT")
    info("Logger initialized", version="1.0")
    debug("Debug message", key="value", count=42)
    warn("Warning example", alert="test_warning")
    error("Error example", code=500)

    dns = get_logger("dns_handler")
    dns.query_received("192.168.1.1", "www.example.com.", "A", 1)
    dns.non_standard_class("10.0.0.1", "weird.example.com.", 67)
    dns.response_sent("192.168.1.1", 0, 1)

    req = for_request("10.0.0.5", 54321)
    req.info("Processing request", step="analyze")

    print("\n--- JSON format ---")
    initialize(level="INFO", fmt="JSON", output="STDOUT")
    info("JSON mode", address="0.0.0.0:53", workers=4)
