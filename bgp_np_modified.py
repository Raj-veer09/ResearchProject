"""
IEPIS - Fig.2 Dynamic Monitor (IC-SU)
----------------------------------------
Event-driven monitor: maintains state between scan cycles and emits ONLY
new/ended processes and connections (deltas), not full snapshots.

Attributes follow the Fig. 2 naming convention, joined by PID where applicable.

Dependencies:
    pip install psutil

Usage:
    python fig2_monitor.py                          # 2s interval, stdout
    python fig2_monitor.py --interval 1             # 1s interval
    python fig2_monitor.py --output events.jsonl    # append events to file
    python fig2_monitor.py --emit-ended             # also emit process/conn end events
"""

import os
import sys
import json
import time
import socket
import hashlib
import logging
import argparse
import platform
import datetime
import subprocess

import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [Monitor] %(levelname)s %(message)s")
log = logging.getLogger("fig2_monitor")

OS_PLATFORM = platform.system()


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────
def get_process_hash(exe_path: str) -> str | None:
    if not exe_path or not os.path.isfile(exe_path):
        return None
    try:
        sha256 = hashlib.sha256()
        with open(exe_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError):
        return None


def get_certificate_status(exe_path: str) -> str:
    if not exe_path or not os.path.isfile(exe_path):
        return "unknown"

    if OS_PLATFORM == "Windows":
        try:
            ps_cmd = f'(Get-AuthenticodeSignature -LiteralPath "{exe_path}").Status'
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=10
            )
            status = result.stdout.strip()
            if status == "Valid":
                return "signed"
            elif status == "NotSigned":
                return "unsigned"
            elif status in ("HashMismatch", "NotTrusted", "Invalid"):
                return "invalid"
            return "unknown"
        except Exception:
            return "unknown"
    else:
        trusted_prefixes = ("/usr/bin", "/bin", "/sbin", "/usr/sbin", "/usr/lib", "/usr/libexec")
        if any(exe_path.startswith(p) for p in trusted_prefixes):
            return "signed"
        elif exe_path.startswith("/tmp") or exe_path.startswith("/dev/shm") or exe_path.startswith("/var/tmp"):
            return "unsigned"
        return "unknown"


def resolve_fqdn(ip: str) -> str | None:
    if not ip:
        return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def get_service_name(port: int | None) -> str | None:
    if not port:
        return None
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return None


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────
# Snapshot collectors
# ─────────────────────────────────────────────────────────
def scan_processes_light() -> dict[int, dict]:
    """
    Fast baseline scan — PID + name only.
    """
    current = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            info = proc.info
            current[info["pid"]] = {"Internal_Process_Name": info.get("name")}
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return current


def get_process_detail(pid: int) -> dict | None:
    """
    Full attribute extraction for a SINGLE pid.
    Includes hardware resource usage and parent process introspection.
    """
    try:
        proc = psutil.Process(pid)

        # Initialize CPU percent in non-blocking mode
        proc.cpu_percent(interval=None)

        with proc.oneshot():
            name = proc.name()
            username = proc.username()
            exe_path = proc.exe() if proc.exe() else ""
            num_threads = proc.num_threads()
            ppid = proc.ppid()

            try:
                cmdline = proc.cmdline()
            except Exception:
                cmdline = []

            # --- NEW: Resource Usage Extraction ---
            try:
                memory_usage = proc.memory_info().rss
                cpu_usage = proc.cpu_percent(interval=None)
            except Exception:
                memory_usage = 0
                cpu_usage = 0.0

            try:
                # Tracks cumulative process I/O (Disk + Network bytes)
                io_counters = proc.io_counters()
                bytes_read = io_counters.read_bytes
                bytes_written = io_counters.write_bytes
            except Exception:
                bytes_read = 0
                bytes_written = 0

            # --- NEW: Parent Process Introspection ---
            try:
                parent = proc.parent()
                parent_name = parent.name() if parent else None
                parent_exe = parent.exe() if parent else None
            except Exception:
                parent_name = None
                parent_exe = None

        return {
            "Internal_Process_PID": pid,
            "Internal_Process_Name": name,
            "Internal_Process_Ownership": username,
            "Internal_Process_Hash": get_process_hash(exe_path),
            "Internal_Process_Certificate_status": get_certificate_status(exe_path),
            "Internal_Machine_Threads": num_threads,
            "Internal_Process_CommandLine": " ".join(cmdline) if cmdline else None,

            # Newly Added Parent Attributes
            "Internal_Process_Parent_PID": ppid,
            "Parent_Process_Name": parent_name,
            "Parent_Process_Address": parent_exe,

            # Newly Added Resource Attributes
            "CPU_Usage_Percent": cpu_usage,
            "Memory_Usage_Bytes": memory_usage,
            "Process_Bytes_Read": bytes_read,
            "Process_Bytes_Written": bytes_written
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def scan_connections() -> dict[tuple, dict]:
    """
    Returns {conn_key: record} for all current connections.
    """
    current = {}
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        log.warning("net_connections requires elevated privileges (run as admin/root).")
        connections = []

    for conn in connections:
        try:
            laddr = conn.laddr
            raddr = conn.raddr

            local_ip = laddr.ip if laddr else None
            local_port = laddr.port if laddr else None
            remote_ip = raddr.ip if raddr else None
            remote_port = raddr.port if raddr else None

            key = (conn.pid, local_ip, local_port, remote_ip, remote_port, conn.status)

            out_fqdn = resolve_fqdn(remote_ip)
            out_service = get_service_name(remote_port)
            in_fqdn = resolve_fqdn(local_ip)
            in_service = get_service_name(local_port)

            current[key] = {
                "Network_Owning_PID": conn.pid,
                "Network_Connection_State": conn.status,

                "Out_Process_FQDN": out_fqdn,
                "Out_Process_DNS": out_fqdn,
                "Out_Process_Port": remote_port,
                "Out_Process_Service": out_service,

                "In_Process_FQDN": in_fqdn,
                "In_Process_DNS": in_fqdn,
                "In_Process_Port": local_port,
                "In_Process_Service": in_service,
            }
        except Exception as e:
            log.debug(f"Skipping connection: {e}")
            continue

    return current


# ─────────────────────────────────────────────────────────
# Event emission
# ─────────────────────────────────────────────────────────
def emit(event: dict, output_path: str | None):
    line = json.dumps(event, default=str)
    if output_path:
        with open(output_path, "a") as f:
            f.write(line + "\n")
    else:
        print(line)


# ─────────────────────────────────────────────────────────
# Main monitoring loop
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="IEPIS Fig.2 Dynamic Monitor")
    parser.add_argument("--interval", type=float, default=2.0, help="Scan interval in seconds (default: 2)")
    parser.add_argument("--output", type=str, default=None, help="Append JSONL events to this file")
    parser.add_argument("--emit-ended", action="store_true", help="Also emit process_ended / connection_ended events")
    args = parser.parse_args()

    log.info(f"Starting dynamic monitor | platform={OS_PLATFORM} | interval={args.interval}s")

    known_processes = scan_processes_light()
    known_connections = {}

    try:
        connections = psutil.net_connections(kind="inet")
        for conn in connections:
            laddr = conn.laddr
            raddr = conn.raddr
            key = (
                conn.pid,
                laddr.ip if laddr else None, laddr.port if laddr else None,
                raddr.ip if raddr else None, raddr.port if raddr else None,
                conn.status
            )
            known_connections[key] = {}
    except psutil.AccessDenied:
        pass

    log.info(f"Baseline (fast): {len(known_processes)} processes, {len(known_connections)} connections")

    try:
        while True:
            time.sleep(args.interval)

            current_processes_light = scan_processes_light()
            current_connections = scan_connections()

            new_pids = set(current_processes_light.keys()) - set(known_processes.keys())
            for pid in new_pids:
                full_record = get_process_detail(pid)
                if full_record:
                    emit({
                        "event": "new_process",
                        "timestamp": now_iso(),
                        "data": full_record
                    }, args.output)

            if args.emit_ended:
                ended_pids = set(known_processes.keys()) - set(current_processes_light.keys())
                for pid in ended_pids:
                    emit({
                        "event": "process_ended",
                        "timestamp": now_iso(),
                        "data": {"Internal_Process_PID": pid,
                                 "Internal_Process_Name": known_processes[pid].get("Internal_Process_Name")}
                    }, args.output)

            new_conn_keys = set(current_connections.keys()) - set(known_connections.keys())
            for key in new_conn_keys:
                record = dict(current_connections[key])
                pid = record.get("Network_Owning_PID")
                if pid in current_processes_light:
                    record["Internal_Process_Name"] = current_processes_light[pid].get("Internal_Process_Name")
                emit({
                    "event": "new_connection",
                    "timestamp": now_iso(),
                    "data": record
                }, args.output)

            if args.emit_ended:
                ended_conn_keys = set(known_connections.keys()) - set(current_connections.keys())
                for key in ended_conn_keys:
                    record = known_connections[key]
                    if not record:
                        pid, l_ip, l_port, r_ip, r_port, status = key
                        record = {
                            "Network_Owning_PID": pid,
                            "Network_Connection_State": status,
                            "In_Process_Port": l_port,
                            "Out_Process_Port": r_port,
                        }
                    emit({
                        "event": "connection_ended",
                        "timestamp": now_iso(),
                        "data": record
                    }, args.output)

            if new_pids or new_conn_keys or (args.emit_ended and (ended_pids or ended_conn_keys)):
                log.info(f"+{len(new_pids)} proc, +{len(new_conn_keys)} conn"
                         + (f" | -{len(ended_pids)} proc, -{len(ended_conn_keys)} conn" if args.emit_ended else ""))

            known_processes = current_processes_light
            known_connections = current_connections

    except KeyboardInterrupt:
        log.info("Monitor stopped by user.")


if __name__ == "__main__":
    main()