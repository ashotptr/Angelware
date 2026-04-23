"""
====================================================
 AUA CS 232/337 - Botnet Research Project
 Component: Sandbox & VM Evasion Research Module
 Environment: ISOLATED VM LAB ONLY
====================================================

Teaching points:
  Professional botnet samples check for analysis environments
  BEFORE executing any malicious payload, so that automated
  sandboxes (Cuckoo, Any.run, Joe Sandbox) detonate a benign
  stub rather than the real malware.

  This lab module documents and simulates the detection techniques
  used by real malware samples — and more importantly builds the
  COUNTER-DETECTION capability that modern sandboxes use to look
  like real machines.

Attack side (SandboxDetector):
  Aggregates multiple weak signals into a confidence score.
  If score >= threshold → assume analysis environment → run benign
  decoy behavior instead of real payload.

  Techniques modeled (from Cuckoo/VMRay/Mandiant research):
    1. Hypervisor artifact files (VMware, VirtualBox, QEMU, Hyper-V)
    2. Hardware resource thresholds (CPUs, RAM, disk)
    3. Running VM-related processes (vmtoolsd, vboxservice, etc.)
    4. Timing attack — rdtsc delta test (cycle count granularity)
    5. Registry artifact checks (Windows; stub on Linux)
    6. Accelerated clock test (sandboxes speed up time)
    7. Human interaction check (mouse movement, keyboard events)
    8. Network connectivity test (sandboxes are often network-isolated)
    9. Uptime check (fresh VMs have very short uptimes)
   10. CPU core count (analyst VMs often have 1–2 cores)

Defense side (SandboxHardeningGuide + SandboxEvasionDetector):
  Documents countermeasures and builds an IDS component that
  detects when a sample is TRYING to detect the sandbox —
  a strong indicator of malicious intent even without payload
  detonation.

  Detection artifacts:
    - Reads of hypervisor artifact paths (/dev/vboxdrv, etc.)
    - Enumeration of very specific process names
    - Calls to clock_gettime in tight loops (timing attack)
    - Registry reads of known VM key paths (Windows)

MITRE: T1497 (Virtualization/Sandbox Evasion)

CLI:
  python3 sandbox_evasion_sim.py --check     (run detector)
  python3 sandbox_evasion_sim.py --score     (show confidence)
  python3 sandbox_evasion_sim.py --harden    (hardening guide)
  python3 sandbox_evasion_sim.py --detect    (evasion detector demo)
  python3 sandbox_evasion_sim.py --demo      (full demo)
"""

import os
import sys
import time
import json
import math
import socket
import platform
import threading
from datetime import datetime
from collections import defaultdict, deque

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False


# ════════════════════════════════════════════════════════════════
#  ATTACK SIDE: Sandbox / VM Detector
# ════════════════════════════════════════════════════════════════

class SandboxSignal:
    """A single sandbox detection signal with weight and evidence."""
    def __init__(self, name: str, detected: bool, weight: float,
                 evidence: str = ""):
        self.name      = name
        self.detected  = detected
        self.weight    = weight
        self.evidence  = evidence

    def score(self) -> float:
        return self.weight if self.detected else 0.0

    def to_dict(self) -> dict:
        return {
            "signal":   self.name,
            "detected": self.detected,
            "weight":   self.weight,
            "evidence": self.evidence,
            "score":    self.score(),
        }


class SandboxDetector:
    """
    Multi-signal VM / sandbox detector.

    Aggregates weak signals into a confidence score 0.0–1.0.
    Real malware uses MANY weak signals rather than one strong one
    because sandbox operators can patch individual checks.

    CONFIDENCE BANDS:
      0.00 – 0.30  → likely real machine (proceed with payload)
      0.30 – 0.60  → uncertain (be cautious, delay)
      0.60 – 1.00  → likely analysis environment (run decoy)

    Teaching note: sandbox vendors respond by making VMs look more
    like real machines (real CPUs, real RAM, running processes,
    network connectivity). This is an arms race.
    """

    # Hypervisor artifact files (Linux)
    HYPERVISOR_FILES = [
        "/dev/vboxdrv",               # VirtualBox kernel module
        "/dev/vboxguest",             # VirtualBox guest
        "/.vboxclient",               # VirtualBox client
        "/dev/vmmon",                 # VMware monitor
        "/dev/vmci",                  # VMware communication interface
        "/proc/vz",                   # OpenVZ
        "/proc/xen",                  # Xen hypervisor
        "/sys/hypervisor",            # generic Xen/Hyper-V
        "/dev/kvm",                   # KVM (the host is using KVM, not the guest)
    ]

    # Hypervisor artifact directories / sysfs
    HYPERVISOR_DIRS = [
        "/sys/bus/vmbus",             # Hyper-V VMBus
        "/proc/driver/vmci",          # VMware VMCI
    ]

    # VM-related processes
    VM_PROCESSES = {
        "vmtoolsd",      # VMware Tools daemon
        "vboxservice",   # VirtualBox Guest Additions service
        "vboxclient",    # VirtualBox client
        "prl_cc",        # Parallels
        "xenservice",    # Xen service
        "qemu-ga",       # QEMU guest agent
        "xenstore",      # Xen store
        "vmwaretray",    # VMware systray
        "sandboxie",     # Sandboxie
        "cuckoomon",     # Cuckoo sandbox monitor
        "wireshark",     # Analyst tool
        "processhacker", # Analyst tool
        "x64dbg",        # Debugger
        "ollydbg",       # Debugger
        "fiddler",       # HTTP proxy (analyst)
        "procmon",       # SysInternals (analyst)
        "procexp",       # SysInternals
        "autoruns",      # SysInternals
    }

    # CPUID vendor strings for hypervisors
    HYPERVISOR_CPUID_STRINGS = {
        "KVMKVMKVM",     # KVM
        "VMwareVMware",  # VMware
        "VBoxVBoxVBox",  # VirtualBox
        "XenVMMXenVMM",  # Xen
        "Microsoft Hv",  # Hyper-V
    }

    HARDWARE_THRESHOLDS = {
        "min_cpu_cores":   2,     # < 2 cores → likely VM
        "min_ram_gb":      3.0,   # < 3 GB    → likely VM
        "min_disk_gb":     40.0,  # < 40 GB   → likely VM
        "min_uptime_min":  5.0,   # < 5 min   → freshly started VM
    }

    def __init__(self, sandbox_threshold: float = 0.60):
        self.sandbox_threshold = sandbox_threshold
        self.signals: list[SandboxSignal] = []

    def _check_hypervisor_files(self) -> SandboxSignal:
        found = [f for f in self.HYPERVISOR_FILES if os.path.exists(f)]
        found += [d for d in self.HYPERVISOR_DIRS if os.path.isdir(d)]
        return SandboxSignal(
            "hypervisor_files",
            detected=bool(found),
            weight=0.30,
            evidence=str(found) if found else "",
        )

    def _check_vm_processes(self) -> SandboxSignal:
        found = []
        if PSUTIL_OK:
            running = {p.name().lower()
                       for p in psutil.process_iter(["name"])}
            found = [p for p in self.VM_PROCESSES if p in running]
        return SandboxSignal(
            "vm_processes",
            detected=bool(found),
            weight=0.25,
            evidence=str(found) if found else "",
        )

    def _check_hardware_resources(self) -> SandboxSignal:
        evidence = []
        detected = False
        if PSUTIL_OK:
            cores = psutil.cpu_count(logical=True) or 0
            ram_gb = psutil.virtual_memory().total / 2**30
            disks = psutil.disk_partitions(all=False)
            disk_gb = 0
            for d in disks:
                try:
                    disk_gb += psutil.disk_usage(d.mountpoint).total / 2**30
                except PermissionError:
                    pass

            if cores < self.HARDWARE_THRESHOLDS["min_cpu_cores"]:
                evidence.append(f"cpu_cores={cores}")
                detected = True
            if ram_gb < self.HARDWARE_THRESHOLDS["min_ram_gb"]:
                evidence.append(f"ram={ram_gb:.1f}GB")
                detected = True
            if disk_gb < self.HARDWARE_THRESHOLDS["min_disk_gb"]:
                evidence.append(f"disk={disk_gb:.1f}GB")
                detected = True

        return SandboxSignal(
            "hardware_resources",
            detected=detected,
            weight=0.20,
            evidence=", ".join(evidence),
        )

    def _check_uptime(self) -> SandboxSignal:
        detected = False
        evidence = ""
        if PSUTIL_OK:
            uptime_min = (time.time() - psutil.boot_time()) / 60
            threshold  = self.HARDWARE_THRESHOLDS["min_uptime_min"]
            if uptime_min < threshold:
                detected = True
                evidence = f"uptime={uptime_min:.1f}min < {threshold}min"
        return SandboxSignal(
            "low_uptime",
            detected=detected,
            weight=0.15,
            evidence=evidence,
        )

    def _check_timing_attack(self) -> SandboxSignal:
        """
        Timing consistency check.
        In a real hypervisor, time.perf_counter() granularity and
        consistency differs subtly from bare metal. A very tight loop
        that measures its own elapsed time should show non-trivial
        variance on bare metal; hypervisors often return constant
        or stepped values.

        This is a simplified version — real malware uses RDTSC CPU
        instruction which is not available from Python. The principle
        is documented here for research value.
        """
        samples = []
        for _ in range(100):
            t0 = time.perf_counter_ns()
            # Minimal work
            _ = math.sqrt(2.0)
            t1 = time.perf_counter_ns()
            samples.append(t1 - t0)

        if not samples:
            return SandboxSignal("timing_attack", False, 0.10)

        mean = sum(samples) / len(samples)
        variance = sum((s - mean) ** 2 for s in samples) / len(samples)
        std = math.sqrt(variance) if variance > 0 else 0
        cv = std / mean if mean > 0 else 0

        # Suspiciously uniform timing suggests virtualized clock
        detected = cv < 0.05 and mean < 100   # <100ns with <5% CV
        return SandboxSignal(
            "timing_consistency",
            detected=detected,
            weight=0.10,
            evidence=f"mean={mean:.1f}ns cv={cv:.3f}",
        )

    def _check_cpuinfo(self) -> SandboxSignal:
        """Check /proc/cpuinfo for hypervisor strings."""
        evidence = []
        try:
            with open("/proc/cpuinfo") as f:
                cpuinfo = f.read().lower()
            # Hypervisor bit in flags
            if "hypervisor" in cpuinfo:
                evidence.append("hypervisor_flag_in_cpuinfo")
            for vendor in self.HYPERVISOR_CPUID_STRINGS:
                if vendor.lower() in cpuinfo:
                    evidence.append(f"vendor:{vendor}")
        except FileNotFoundError:
            pass
        return SandboxSignal(
            "cpuinfo_hypervisor",
            detected=bool(evidence),
            weight=0.20,
            evidence=str(evidence),
        )

    def _check_dmi(self) -> SandboxSignal:
        """Check DMI/SMBIOS for VM vendor strings."""
        evidence = []
        dmi_paths = [
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/board_vendor",
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/bios_vendor",
        ]
        vm_strings = {"vmware", "virtualbox", "qemu", "xen", "kvm",
                      "parallels", "hyper-v", "microsoft corporation",
                      "bochs", "innotek"}
        for path in dmi_paths:
            try:
                with open(path) as f:
                    val = f.read().strip().lower()
                for vs in vm_strings:
                    if vs in val:
                        evidence.append(f"{os.path.basename(path)}={val}")
                        break
            except (FileNotFoundError, PermissionError):
                pass
        return SandboxSignal(
            "dmi_hypervisor",
            detected=bool(evidence),
            weight=0.25,
            evidence=str(evidence),
        )

    def check_all(self) -> dict:
        """Run all checks and return aggregated result."""
        self.signals = [
            self._check_hypervisor_files(),
            self._check_vm_processes(),
            self._check_hardware_resources(),
            self._check_uptime(),
            self._check_timing_attack(),
            self._check_cpuinfo(),
            self._check_dmi(),
        ]
        total_weight = sum(s.weight for s in self.signals)
        score = sum(s.score() for s in self.signals) / max(total_weight, 1)

        is_sandbox = score >= self.sandbox_threshold
        return {
            "confidence": round(score, 3),
            "threshold":  self.sandbox_threshold,
            "verdict":    "SANDBOX/VM" if is_sandbox else "LIKELY_REAL",
            "signals":    [s.to_dict() for s in self.signals],
            "summary":    (
                f"{sum(1 for s in self.signals if s.detected)}/{len(self.signals)} "
                f"signals fired  |  confidence={score:.1%}"
            ),
        }

    def is_sandbox(self) -> bool:
        result = self.check_all()
        return result["verdict"] == "SANDBOX/VM"


# ════════════════════════════════════════════════════════════════
#  DEFENSE SIDE: Evasion Attempt Detector
# ════════════════════════════════════════════════════════════════

def _default_alert(engine, severity, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n{'='*60}\n  ALERT [{severity}]  {engine}  @ {ts}\n  {msg}\n{'='*60}\n")

_alert_fn = _default_alert

def register_alert_fn(fn):
    global _alert_fn
    _alert_fn = fn


class SandboxEvasionDetector:
    """
    Detects when a process is TRYING to detect the sandbox.

    Key insight: the act of sandbox detection is itself suspicious.
    A legitimate application has no reason to:
      - Read /dev/vboxdrv or /sys/bus/vmbus
      - Enumerate VM-specific process names
      - Execute tight timing loops to measure clock granularity
      - Read /proc/cpuinfo looking for "hypervisor" flags
      - Read DMI strings looking for vendor names

    This detector monitors for these access patterns, which are
    strong indicators of malicious intent even without payload.

    MITRE: T1497 (Virtualization/Sandbox Evasion) — detecting the
    ATTACKER'S detection attempt is a meta-layer of defense.
    """

    VM_ARTIFACT_READS = set(SandboxDetector.HYPERVISOR_FILES) | {
        "/proc/cpuinfo",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/proc/vz",
        "/proc/xen",
    }

    def __init__(self):
        self._artifact_reads:  dict[int, list] = defaultdict(list)
        self._process_enums:   dict[int, list] = defaultdict(list)
        self._cooldown: dict[str, float] = {}
        self._lock = threading.Lock()

    def _cooldown_ok(self, key: str, secs: float = 120.0) -> bool:
        now = time.time()
        if now - self._cooldown.get(key, 0) >= secs:
            self._cooldown[key] = now
            return True
        return False

    def observe_file_read(self, path: str, reader_pid: int,
                           reader_name: str = "unknown"):
        """Call when a process reads a file that matches VM artifact paths."""
        if path not in self.VM_ARTIFACT_READS:
            return
        with self._lock:
            reads = self._artifact_reads[reader_pid]
            if path not in reads:
                reads.append(path)
            if len(reads) >= 3 and self._cooldown_ok(f"evasion_{reader_pid}"):
                _alert_fn(
                    "SandboxEvasion/ArtifactRead", "HIGH",
                    f"SANDBOX EVASION ATTEMPT: process reading VM artifact files\n"
                    f"  Process: {reader_name}  PID={reader_pid}\n"
                    f"  Files read: {reads}\n"
                    f"  Malware reads these to detect analysis environments.\n"
                    f"  A legitimate process has no reason to check these paths.\n"
                    f"  MITRE: T1497.001 (System Checks)"
                )

    def observe_process_enum_for_vm_tools(self, reader_pid: int,
                                           reader_name: str,
                                           queried_names: list):
        """Call when a process searches for VM-related process names."""
        vm_hits = [n for n in queried_names
                   if n.lower() in SandboxDetector.VM_PROCESSES]
        if not vm_hits:
            return
        with self._lock:
            enums = self._process_enums[reader_pid]
            enums.extend(vm_hits)
            if len(set(enums)) >= 3 and \
                    self._cooldown_ok(f"vmenum_{reader_pid}"):
                _alert_fn(
                    "SandboxEvasion/VMProcessEnum", "HIGH",
                    f"SANDBOX EVASION: process enumerating VM tool names\n"
                    f"  Process: {reader_name}  PID={reader_pid}\n"
                    f"  VM tool names queried: {list(set(enums))}\n"
                    f"  This pattern indicates sandbox detection logic.\n"
                    f"  MITRE: T1497.001 (System Checks)"
                )

    def run_demo(self):
        """Demonstrate evasion detection with simulated events."""
        print("[EvasionDetector] Simulating sandbox-detection artifact reads...")
        for path in ["/dev/vboxdrv", "/proc/xen",
                     "/sys/class/dmi/id/sys_vendor", "/proc/cpuinfo"]:
            self.observe_file_read(path, reader_pid=9999,
                                   reader_name="suspicious_sample")
            time.sleep(0.1)

        print("[EvasionDetector] Simulating VM process name enumeration...")
        self.observe_process_enum_for_vm_tools(
            reader_pid=9999,
            reader_name="suspicious_sample",
            queried_names=["vmtoolsd", "vboxservice", "cuckoomon",
                           "wireshark", "procmon"],
        )
        print("[EvasionDetector] Demo complete.")


# ════════════════════════════════════════════════════════════════
#  SANDBOX HARDENING GUIDE
# ════════════════════════════════════════════════════════════════

HARDENING_GUIDE = {
    "title": "Sandbox Hardening Countermeasures",
    "description": (
        "To defeat the detection techniques in SandboxDetector, "
        "a sandbox operator must make the VM indistinguishable from "
        "a real machine. Each countermeasure patches one evasion check."
    ),
    "countermeasures": [
        {
            "evasion_check": "hypervisor_files",
            "fix": "Remove or hide /dev/vboxdrv, /dev/vmmon, etc. using "
                   "file-hiding kernel module. Configure VirtualBox with "
                   "'--VBoxInternal/CPUM/IsaExts/RDRAND' to disable "
                   "guest additions artifact files.",
            "effectiveness": "HIGH",
        },
        {
            "evasion_check": "vm_processes",
            "fix": "Remove vmtoolsd, vboxservice, etc. OR rename binaries "
                   "to common system process names. Modern sandboxes install "
                   "a minimal 'stealth agent' with a randomized binary name.",
            "effectiveness": "HIGH",
        },
        {
            "evasion_check": "hardware_resources",
            "fix": "Provision analysis VMs with ≥ 4 cores, ≥ 8 GB RAM, "
                   "≥ 100 GB disk. Any.run and Joe Sandbox use standard "
                   "developer-laptop profiles for this reason.",
            "effectiveness": "HIGH",
        },
        {
            "evasion_check": "low_uptime",
            "fix": "Run VM 24/7 or pre-warm before detonation. Alternatively, "
                   "patch uptime syscall to return a value from a real uptime "
                   "distribution (N(3 days, 12 hours)).",
            "effectiveness": "MED",
        },
        {
            "evasion_check": "timing_consistency",
            "fix": "Enable hardware TSC (Time Stamp Counter) passthrough. "
                   "In KVM: -cpu host,+invtsc. Eliminates virtualized clock "
                   "stepping artifacts.",
            "effectiveness": "HIGH",
        },
        {
            "evasion_check": "cpuinfo_hypervisor",
            "fix": "Patch CPUID hypervisor bit: -cpu host,+kvm=off in KVM. "
                   "This removes the 'hypervisor' flag from /proc/cpuinfo.",
            "effectiveness": "HIGH",
        },
        {
            "evasion_check": "dmi_hypervisor",
            "fix": "Replace DMI strings via -smbios in QEMU: "
                   "-smbios type=1,manufacturer='Dell Inc.',product='XPS 15'. "
                   "Use real hardware profiles from public SMBIOS dumps.",
            "effectiveness": "HIGH",
        },
    ],
    "advanced_techniques": [
        "Human interaction simulation: inject fake mouse/keyboard events",
        "Network profile: make real HTTP traffic to news sites before detonation",
        "Install real-world software: Chrome, Office, Steam entries in registry",
        "Realistic file history: populate Recent Documents, browser history",
    ],
}


# ════════════════════════════════════════════════════════════════
#  CLI
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Sandbox/VM Evasion Research Module")
    parser.add_argument("--check",  action="store_true",
                        help="Run sandbox detector on this machine")
    parser.add_argument("--score",  action="store_true",
                        help="Show detailed signal scores")
    parser.add_argument("--harden", action="store_true",
                        help="Print sandbox hardening countermeasures")
    parser.add_argument("--detect", action="store_true",
                        help="Run evasion-attempt detection demo")
    parser.add_argument("--demo",   action="store_true",
                        help="Full attack+defense demo")
    args = parser.parse_args()

    if args.check or args.score or args.demo:
        print("[SandboxDetector] Analyzing execution environment...")
        det = SandboxDetector()
        result = det.check_all()
        print(f"\nVerdict:    {result['verdict']}")
        print(f"Confidence: {result['confidence']:.1%}")
        print(f"Summary:    {result['summary']}")
        if args.score or args.demo:
            print("\nSignal breakdown:")
            for s in result["signals"]:
                status = "✓ FIRED" if s["detected"] else "  miss "
                print(f"  {status}  {s['signal']:<30} weight={s['weight']:.2f}"
                      f"  {s['evidence'][:60]}")

    if args.harden or args.demo:
        print("\n" + json.dumps(HARDENING_GUIDE, indent=2))

    if args.detect or args.demo:
        print("\n[SandboxEvasionDetector] Running evasion detection demo...")
        edet = SandboxEvasionDetector()
        edet.run_demo()
