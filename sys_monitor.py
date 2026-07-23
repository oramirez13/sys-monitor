#!/usr/bin/env python3
"""
Sys Monitor - Cross-platform process security scanner.

Scans active system processes and flags suspicious activity based on
process names, executable paths, and network connections.

Supports Linux and Windows with platform-specific detection rules.
"""

import argparse
import json
import os
import platform
import sys
from datetime import datetime
from pathlib import Path

import psutil

# ANSI color codes for terminal output
CYAN = "\033[96m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Default config file path
DEFAULT_CONFIG = Path(__file__).parent / "config.json"


def load_config(config_path=None):
    """Load detection configuration from a JSON file."""
    path = Path(config_path) if config_path else DEFAULT_CONFIG

    if not path.exists():
        print(f"{YELLOW}[!] Config file not found: {path}{RESET}")
        print(f"{YELLOW}[!] Using built-in defaults.{RESET}")
        return get_default_config()

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"{YELLOW}[!] Error reading config: {e}{RESET}")
        print(f"{YELLOW}[!] Using built-in defaults.{RESET}")
        return get_default_config()


def get_default_config():
    """Return hardcoded defaults when no config file is available."""
    return {
        "trusted_paths_linux": [
            "/usr/bin", "/bin", "/usr/sbin", "/sbin",
            "/usr/local/bin", "/usr/lib", "/usr/libexec", "/lib",
        ],
        "trusted_paths_windows": [
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
        ],
        "suspicious_names_linux": [
            "mimikatz", "metasploit", "nc", "netcat",
            "socat", "nmap", "hydra", "john", "hashcat",
        ],
        "suspicious_names_windows": [
            "mimikatz.exe", "psexec.exe", "procdump.exe",
            "nc.exe", "ncat.exe", "netcat.exe",
        ],
        "critical_windows_processes": [
            "lsass.exe", "svchost.exe", "wininit.exe",
            "services.exe", "csrss.exe",
        ],
        "suspicious_ports": [4444, 5555, 6666, 1337, 31337, 1234, 9999],
    }


def is_linux():
    """Check if the current platform is Linux."""
    return platform.system().lower() == "linux"


def is_windows():
    """Check if the current platform is Windows."""
    return platform.system().lower() == "windows"


def print_banner():
    """Print the tool header."""
    print(f"{CYAN}=== Sys Monitor - Process Security Scanner ==={RESET}")
    print(f"{CYAN}Platform: {platform.system()} {platform.release()}{RESET}")
    print()


def is_trusted_path(executable_path, trusted_paths):
    """Check if an executable path starts with any trusted directory."""
    for trusted in trusted_paths:
        if executable_path.lower().startswith(trusted.lower()):
            return True
    return False


def check_suspicious_connections(pid, suspicious_ports):
    """Check if a process has active connections on suspicious ports."""
    alerts = []
    try:
        connections = psutil.net_connections(kind="inet")
        for conn in connections:
            if conn.pid != pid:
                continue
            if conn.raddr and conn.raddr.port in suspicious_ports:
                alerts.append(
                    f"Connection to suspicious port {conn.raddr.port} "
                    f"({conn.raddr.ip})"
                )
            if conn.status == "ESTABLISHED" and conn.raddr:
                if conn.raddr.port in suspicious_ports:
                    alerts.append(
                        f"Active connection on port {conn.raddr.port}"
                    )
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return alerts


def scan_process_linux(process, config):
    """Analyze a single process on Linux. Returns (is_suspicious, reason)."""
    try:
        # Skip our own process
        if process.pid == os.getpid():
            return False, ""

        name = process.name().lower()
        exe_path = process.exe()
        trusted_paths = config.get("trusted_paths_linux", [])
        suspicious_names = set(config.get("suspicious_names_linux", []))

        # Check by process name
        if name in suspicious_names:
            return True, f"Sensitive tool detected: {name}"

        # Check by executable path (only if not in trusted or home dirs)
        if not is_trusted_path(exe_path, trusted_paths):
            user_home = os.path.expanduser("~")
            if not exe_path.startswith(user_home):
                return True, f"Uncommon executable path: {exe_path}"

        # Check orphan process (parent is init but not in system paths)
        if process.ppid() == 1:
            if not is_trusted_path(exe_path, trusted_paths):
                return True, "Orphan process outside system directories"

    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return False, ""

    return False, ""


def scan_process_windows(process, config):
    """Analyze a single process on Windows. Returns (is_suspicious, reason)."""
    try:
        name = process.name().lower()
        exe_path = process.exe()
        suspicious_names = set(config.get("suspicious_names_windows", []))
        critical_procs = set(config.get("critical_windows_processes", []))
        trusted_paths = config.get("trusted_paths_windows", [])

        # Check by process name (hacking tools only)
        if name in suspicious_names:
            return True, f"Hacking tool detected: {name}"

        # Check masquerading: critical process running from wrong path
        if name in critical_procs:
            if not is_trusted_path(exe_path, trusted_paths):
                return True, f"Critical process from fake path: {exe_path}"

        # Check execution from temp or downloads folders
        lower_path = exe_path.lower()
        if "appdata\\local\\temp" in lower_path:
            return True, f"Executable in temp folder: {exe_path}"
        if "\\downloads\\" in lower_path:
            return True, f"Executable in Downloads folder: {exe_path}"

    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass

    return False, ""


def scan(config, verbose=False, check_network=False):
    """Run the full system scan and return list of alerts."""
    print_banner()

    alerts = []
    suspicious_ports = config.get("suspicious_ports", [])

    process_iter_attrs = ["pid", "name"]
    for process in psutil.process_iter(process_iter_attrs):
        if is_linux():
            suspicious, reason = scan_process_linux(process, config)
        else:
            suspicious, reason = scan_process_windows(process, config)

        if suspicious:
            alerts.append(f"[!] PID {process.pid} ({process.name()}) - {reason}")

        # Optional: check network connections for each process
        if check_network and not suspicious:
            net_alerts = check_suspicious_connections(process.pid, suspicious_ports)
            for net_reason in net_alerts:
                alerts.append(
                    f"[!] PID {process.pid} ({process.name()}) - {net_reason}"
                )

    return alerts


def save_report(alerts, output_path):
    """Save scan results to a file with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"Sys Monitor Report - {timestamp}\n")
        f.write(f"Platform: {platform.system()} {platform.release()}\n")
        f.write("=" * 50 + "\n\n")

        if not alerts:
            f.write("No suspicious processes detected with basic rules.\n")
        else:
            f.write(f"Total alerts: {len(alerts)}\n\n")
            for alert in alerts:
                f.write(alert + "\n")

    print(f"\n{GREEN}[+] Report saved to: {output_path}{RESET}")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Sys Monitor - Process security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python sys_monitor.py\n"
            "  python sys_monitor.py --output report.txt\n"
            "  python sys_monitor.py --network --verbose\n"
            "  python sys_monitor.py --config my_config.json\n"
        ),
    )
    parser.add_argument(
        "-o", "--output",
        help="Save report to file (text format)",
        default=None,
    )
    parser.add_argument(
        "-n", "--network",
        help="Also check for suspicious network connections",
        action="store_true",
    )
    parser.add_argument(
        "-v", "--verbose",
        help="Show detailed information during scan",
        action="store_true",
    )
    parser.add_argument(
        "-c", "--config",
        help="Path to custom config.json file",
        default=None,
    )
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    config = load_config(args.config)

    alerts = scan(config, verbose=args.verbose, check_network=args.network)

    if not alerts:
        print(
            f"{GREEN}[+] No suspicious processes detected "
            f"with the basic rules.{RESET}"
        )
    else:
        print(f"{YELLOW}[!] Possible findings detected:{RESET}")
        print(f"{YELLOW}Total alerts: {len(alerts)}{RESET}")
        print()
        for alert in alerts:
            print(f"{RED}{alert}{RESET}")

    if args.output:
        save_report(alerts, args.output)

    # Return exit code based on findings
    sys.exit(1 if alerts else 0)


if __name__ == "__main__":
    main()
