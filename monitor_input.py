"""
IEPIS - Fig.2 Dynamic Monitor (IC-SU)
----------------------------------------
Event-driven monitor: maintains state between scan cycles and emits ONLY
new/ended processes and connections (deltas), not full snapshots.

Dependencies:
    pip install psutil

Usage:
    python monitor_input.py                         # 2s interval, stdout
    python monitor_input.py --interval 1             # 1s interval
    python monitor_input.py --output events.jsonl    # append events to file
    python monitor_input.py --emit-ended             # also emit process/conn end events
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

# ----------------------------------------------------------
# Cache expensive operations (hashing & signature checking)
# ----------------------------------------------------------
HASH_CACHE = {}
CERT_CACHE = {}


# ─────────────────────────────────────────────────────────
# Helpers (same as fig2_extractor.py)
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
# Snapshot collectors — return dicts keyed for diffing
# ─────────────────────────────────────────────────────────
def scan_processes_light() -> dict[int, dict]:
    """
    Fast baseline scan — PID + name only, NO hash/cert checks.
    Used only for the initial baseline so startup is fast.
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

    Uses caching so multiple instances of the same executable
    don't repeatedly compute SHA256 and certificate status.
    """
    try:
        proc = psutil.Process(pid)

        with proc.oneshot():
            name = proc.name()
            username = proc.username()

            try:
                exe_path = proc.exe()
            except Exception:
                exe_path = ""

            num_threads = proc.num_threads()
            ppid = proc.ppid()

            try:
                cmdline = proc.cmdline()
            except Exception:
                cmdline = []

        if exe_path in HASH_CACHE:
            process_hash = HASH_CACHE[exe_path]
        else:
            process_hash = get_process_hash(exe_path)
            HASH_CACHE[exe_path] = process_hash

        if exe_path in CERT_CACHE:
            cert_status = CERT_CACHE[exe_path]
        else:
            cert_status = get_certificate_status(exe_path)
            CERT_CACHE[exe_path] = cert_status

        return {
            "Internal_Process_PID": pid,
            "Internal_Process_Name": name,
            "Internal_Process_Ownership": username,
            "Internal_Process_Hash": process_hash,
            "Internal_Process_Certificate_status": cert_status,
            "Internal_Machine_Threads": num_threads,
            "Internal_Process_Parent_PID": ppid,
            "Internal_Process_CommandLine": " ".join(cmdline) if cmdline else None,
        }

    except (psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess):
        return None
    
    
def scan_connections() -> dict[tuple, dict]:
    """
    Returns {conn_key: record} for all current connections.

    conn_key =
    (pid, local_ip, local_port, remote_ip, remote_port, status)

    Used for detecting new/ended connections between scan cycles.
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

            key = (
                conn.pid,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                conn.status,
            )

            out_fqdn = resolve_fqdn(remote_ip)
            out_service = get_service_name(remote_port)

            in_fqdn = resolve_fqdn(local_ip)
            in_service = get_service_name(local_port)

            protocol = "TCP"
            if conn.type == socket.SOCK_DGRAM:
                protocol = "UDP"

            current[key] = {
                "Network_Owning_PID": conn.pid,
                "Network_Connection_State": conn.status,
                "Network_Protocol": protocol,

                "Network_Out_Process_IP": remote_ip,
                "Network_Out_Process_FQDN": out_fqdn,
                "Network_Out_Process_Port": remote_port,
                "Network_Out_Process_Service": out_service,

                "Network_In_Process_IP": local_ip,
                "Network_In_Process_FQDN": in_fqdn,
                "Network_In_Process_Port": local_port,
                "Network_In_Process_Service": in_service,
            }

        except Exception as e:
            log.debug(f"Skipping connection: {e}")
            continue

    return current


def emit(event: dict, output_path: str | None):
    """
    Emit one JSON event.

    If an output file is supplied, append to the JSONL file.
    Otherwise print to stdout.
    """
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
    parser = argparse.ArgumentParser(description="IEPIS Dynamic Monitor")
    parser.add_argument("--interval", type=float, default=2.0, help="Scan interval in seconds (default: 2)")
    parser.add_argument("--output", type=str, default=None, help="Append JSONL events to this file")
    parser.add_argument("--emit-ended", action="store_true", help="Also emit process_ended / connection_ended events")
    args = parser.parse_args()

    log.info(f"Starting dynamic monitor | platform={OS_PLATFORM} | interval={args.interval}s")

    # ----------------------------------------------------------
    # Initial Process Inventory
    # ----------------------------------------------------------

    known_processes = scan_processes_light()

    log.info(f"Collecting initial inventory of {len(known_processes)} running processes...")

    for pid in sorted(known_processes.keys()):

        record = get_process_detail(pid)

        if record:

            emit(
                {
                    "event": "new_process",
                    "timestamp": now_iso(),
                    "data": record,
                },
                args.output,
            )

    known_connections = {}

    try:
        connections = psutil.net_connections(kind="inet")

        for conn in connections:

            laddr = conn.laddr
            raddr = conn.raddr

            key = (
                conn.pid,
                laddr.ip if laddr else None,
                laddr.port if laddr else None,
                raddr.ip if raddr else None,
                raddr.port if raddr else None,
                conn.status,
            )

            known_connections[key] = {}

    except psutil.AccessDenied:
        pass

    log.info(
        f"Initial inventory completed "
        f"({len(known_processes)} processes, "
        f"{len(known_connections)} active connections)"
    )

    try:
        while True:
            time.sleep(args.interval)

            # Lightweight scans every cycle (fast — just pid/name and connection tuples)
            current_processes_light = scan_processes_light()
            current_connections = scan_connections()

            # ── New processes — only fully inspect (hash/cert) the NEW ones ──
            new_pids = set(current_processes_light.keys()) - set(known_processes.keys())
            for pid in new_pids:
                full_record = get_process_detail(pid)
                if full_record:
                    emit({
                        "event": "new_process",
                        "timestamp": now_iso(),
                        "data": full_record
                    }, args.output)

            # ── Ended processes ──
            if args.emit_ended:
                ended_pids = set(known_processes.keys()) - set(current_processes_light.keys())
                for pid in ended_pids:
                    emit({
                        "event": "process_ended",
                        "timestamp": now_iso(),
                        "data": {"Internal_Process_PID": pid,
                                 "Internal_Process_Name": known_processes[pid].get("Internal_Process_Name")}
                    }, args.output)

            # ── New connections ──

            new_conn_keys = set(current_connections.keys()) - set(known_connections.keys())

            for key in new_conn_keys:

                record = dict(current_connections[key])

                pid = record.get("Network_Owning_PID")

                if pid is not None:

                    proc_record = get_process_detail(pid)

                    if proc_record:

                        record.update(proc_record)

                emit(
                    {
                        "event": "new_connection",
                        "timestamp": now_iso(),
                        "data": record,
                    },
                    args.output,
                )

            # ── Ended connections ──
            if args.emit_ended:
                ended_conn_keys = set(known_connections.keys()) - set(current_connections.keys())
                for key in ended_conn_keys:
                    record = known_connections[key]
                    if not record:
                        # Baseline placeholder — reconstruct minimal info from the key tuple
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