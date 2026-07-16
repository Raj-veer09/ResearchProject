"""
IEPIS - Fig.2 Dynamic Monitor (IC-SU) - Hybrid Version
------------------------------------------------------
Hybrid event-driven monitor:

- WMI-based process creation events (Windows) for reliable capture of short-lived processes.
- Polling-based process termination detection (cross-platform).
- Polling-based network connection monitoring with enhanced timing metadata.

Emits ONLY new/ended processes and connections (deltas), not full snapshots.
Queues telemetry in a SQLite database for downstream AI classification.

Dependencies:
    pip install psutil
    pip install wmi
    pip install pywin32   # for pythoncom / COM initialization

Usage:
    python monitor_input_hybrid.py                         # 2s interval, 0.5s network polling
    python monitor_input_hybrid.py --interval 1            # 1s interval
    python monitor_input_hybrid.py --output events.jsonl   # append events to file
    python monitor_input_hybrid.py --emit-ended            # also emit process_ended / connection_ended events
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
import threading
import sqlite3

import psutil

try:
    import wmi
    HAS_WMI = True
except ImportError:
    HAS_WMI = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [Monitor] %(levelname)s %(message)s")
log = logging.getLogger("fig2_monitor")

OS_PLATFORM = platform.system()
DB_DEFAULT_PATH = "iepis_queue.db"

# Thread lock for SQLite writes
DB_LOCK = threading.Lock()

# ----------------------------------------------------------
# Cache expensive operations (hashing & signature checking)
# ----------------------------------------------------------
HASH_CACHE = {}
CERT_CACHE = {}

# ----------------------------------------------------------
# DNS cache
# ----------------------------------------------------------
DNS_CACHE = {}


# ─────────────────────────────────────────────────────────
# Database Helpers
# ─────────────────────────────────────────────────────────
def setup_database(db_path: str):
    """Initialize the SQLite database and table structure."""
    with DB_LOCK:
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS event_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT UNIQUE,
                    payload TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("DELETE FROM event_queue")
            conn.commit()


def queue_row_db(db_path: str, row: dict):
    """Generate a fingerprint and insert into SQLite, ignoring duplicates."""
    # Create the exact fingerprint used by the classifier to ensure uniqueness
    key = (
        row.get("pid"),
        row.get("process_hash_sha256"),
        row.get("network_protocol"),
        row.get("network_out_process_ip"),
        row.get("network_out_process_port"),
        row.get("network_connection_state"),
        row.get("command_line"),
    )
    
    fingerprint = hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()
    payload = json.dumps(row, default=str)

    with DB_LOCK:
        try:
            with sqlite3.connect(db_path, timeout=10) as conn:
                # INSERT OR IGNORE automatically drops exact duplicates based on the UNIQUE fingerprint
                conn.execute(
                    "INSERT OR IGNORE INTO event_queue (fingerprint, payload) VALUES (?, ?)", 
                    (fingerprint, payload)
                )
                conn.commit()
        except sqlite3.Error as e:
            log.error(f"Database insertion error: {e}")


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

    if ip in DNS_CACHE:
        return DNS_CACHE[ip]

    try:
        fqdn = socket.gethostbyaddr(ip)[0]
    except Exception:
        fqdn = None

    DNS_CACHE[ip] = fqdn
    return fqdn


def get_service_name(port: int | None) -> str | None:
    if not port:
        return None
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return None


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ─────────────────────────────────────────────────────────
# Snapshot collectors
# ─────────────────────────────────────────────────────────
def scan_processes_light() -> dict[int, dict]:
    current = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            info = proc.info
            current[info["pid"]] = {"Internal_Process_Name": info.get("name")}
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return current


def get_process_detail(pid: int) -> dict | None:
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
            "Internal_Process_Executable_Path": exe_path,
        }

    except (psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess):
        return None


def scan_connections() -> dict[tuple, dict]:
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
    line = json.dumps(event, default=str)

    if output_path:
        with open(output_path, "a") as f:
            f.write(line + "\n")
    else:
        print(line)


def _normalize_monitor_to_classifier_row(proc: dict | None, conn: dict | None, is_orphan: bool = False) -> dict:
    """
    Convert monitor internal process/connection dicts to the classifier's flat row schema.
    """
    row = {}

    if proc:
        row["pid"] = proc.get("Internal_Process_PID")
        row["process_name"] = proc.get("Internal_Process_Name")
        row["process_owner"] = proc.get("Internal_Process_Ownership")
        row["process_hash_sha256"] = proc.get("Internal_Process_Hash")
        row["cert_status"] = proc.get("Internal_Process_Certificate_status")
        row["thread_count"] = proc.get("Internal_Machine_Threads")
        row["parent_pid"] = proc.get("Internal_Process_Parent_PID")
        row["command_line"] = proc.get("Internal_Process_CommandLine")
        row["process_executable_path"] = proc.get("Internal_Process_Executable_Path")
    elif conn and conn.get("Network_Owning_PID") is not None:
        row["pid"] = conn.get("Network_Owning_PID")

    if conn:
        row["has_connection"] = True
        row["network_protocol"] = conn.get("Network_Protocol")
        row["network_connection_state"] = conn.get("Network_Connection_State")
        row["network_out_process_ip"] = conn.get("Network_Out_Process_IP")
        row["network_out_process_fqdn"] = conn.get("Network_Out_Process_FQDN")
        row["network_out_process_port"] = conn.get("Network_Out_Process_Port")
        row["network_out_process_service"] = conn.get("Network_Out_Process_Service")
        row["network_in_process_ip"] = conn.get("Network_In_Process_IP")
        row["network_in_process_fqdn"] = conn.get("Network_In_Process_FQDN")
        row["network_in_process_port"] = conn.get("Network_In_Process_Port")
        row["network_in_process_service"] = conn.get("Network_In_Process_Service")
    else:
        row["has_connection"] = False

    row["is_orphan_connection"] = bool(is_orphan)

    return row


def _queue_monitor_row(db_path: str, proc: dict | None, conn: dict | None, is_orphan: bool = False):
    row = _normalize_monitor_to_classifier_row(proc, conn, is_orphan=is_orphan)
    if row.get("pid") is None:
        return
    queue_row_db(db_path, row)


# ─────────────────────────────────────────────────────────
# WMI-based process creation watcher (Windows only)
# ─────────────────────────────────────────────────────────
def wmi_process_creation_loop(
    known_processes: dict[int, dict],
    emitted_pids: set[int],
    known_processes_lock: threading.Lock,
    output_path: str | None,
    db_path: str,
    stop_event: threading.Event,
):
    import pythoncom
    pythoncom.CoInitializeEx(pythoncom.COINIT_MULTITHREADED)

    try:
        if OS_PLATFORM != "Windows":
            return
        if not HAS_WMI:
            return

        c = wmi.WMI()
        watcher = c.Win32_Process.watch_for("creation")

        while not stop_event.is_set():
            try:
                new_proc = watcher(timeout_ms=100)
            except Exception as e:
                if "timed out" in str(e).lower():
                    continue
                break

            if stop_event.is_set() or not new_proc:
                continue

            try:
                pid = int(new_proc.ProcessId)
            except Exception:
                continue

            time.sleep(0.2)
            record = get_process_detail(pid)

            if record:
                with known_processes_lock:
                    if pid in emitted_pids:
                        continue
                    emitted_pids.add(pid)
                    known_processes[pid] = {"Internal_Process_Name": record.get("Internal_Process_Name")}

                emit({"event": "new_process", "timestamp": now_iso(), "data": record}, output_path)
                _queue_monitor_row(db_path, record, None, is_orphan=False)
    finally:
        pythoncom.CoUninitialize()


# ─────────────────────────────────────────────────────────
# Main monitoring loop
# ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="IEPIS Dynamic Monitor")
    parser.add_argument("--interval", type=float, default=2.0, help="Scan interval in seconds (default: 2)")
    parser.add_argument("--output", type=str, default=None, help="Append JSONL events to this file")
    parser.add_argument("--db-file", type=str, default=DB_DEFAULT_PATH,
                        help="SQLite queue database file (default: iepis_queue.db)")
    parser.add_argument("--emit-ended", action="store_true", help="Also emit process_ended / connection_ended events")
    args = parser.parse_args()

    net_interval = 0.5 if args.interval == 2.0 else args.interval

    log.info(
        f"Starting dynamic monitor | platform={OS_PLATFORM} | "
        f"process_interval={args.interval}s | network_interval={net_interval}s | db_file={args.db_file}"
    )

    setup_database(args.db_file)

    known_processes_lock = threading.Lock()
    emitted_pids: set[int] = set()
    known_processes: dict[int, dict] = {}
    stop_event = threading.Event()

    wmi_thread = threading.Thread(
        target=wmi_process_creation_loop,
        args=(known_processes, emitted_pids, known_processes_lock, args.output, args.db_file, stop_event),
        daemon=True,
    )
    wmi_thread.start()

    initial_snapshot = scan_processes_light()
    for pid in sorted(initial_snapshot.keys()):
        record = get_process_detail(pid)
        if record:
            with known_processes_lock:
                if pid in emitted_pids:
                    continue
                emitted_pids.add(pid)
                known_processes[pid] = {"Internal_Process_Name": record.get("Internal_Process_Name")}
            emit({"event": "new_process", "timestamp": now_iso(), "data": record}, args.output)
            _queue_monitor_row(args.db_file, record, None, is_orphan=False)

    known_connections = {}
    try:
        for conn in psutil.net_connections(kind="inet"):
            laddr = conn.laddr
            raddr = conn.raddr
            key = (conn.pid, laddr.ip if laddr else None, laddr.port if laddr else None,
                   raddr.ip if raddr else None, raddr.port if raddr else None, conn.status)
            known_connections[key] = {"data": {}, "first_seen": now_utc(), "last_seen": now_utc()}
    except psutil.AccessDenied:
        pass

    last_reconcile = time.time()
    reconcile_interval = 5.0

    try:
        while True:
            time.sleep(net_interval)

            current_processes_light = scan_processes_light()
            current_keys = set(current_processes_light.keys())

            with known_processes_lock:
                known_keys = set(known_processes.keys())
                ended_pids = known_keys - current_keys
                for pid in ended_pids:
                    emitted_pids.discard(pid)

            now_time = time.time()
            if now_time - last_reconcile >= reconcile_interval:
                with known_processes_lock:
                    known_keys = set(known_processes.keys())
                missed_pids = current_keys - known_keys

                for pid in missed_pids:
                    full_record = get_process_detail(pid)
                    if full_record:
                        with known_processes_lock:
                            if pid in emitted_pids:
                                continue
                            emitted_pids.add(pid)
                            known_processes[pid] = {"Internal_Process_Name": full_record.get("Internal_Process_Name")}
                        emit({"event": "new_process", "timestamp": now_iso(), "data": full_record}, args.output)
                        _queue_monitor_row(args.db_file, full_record, None, is_orphan=False)

                last_reconcile = now_time

            with known_processes_lock:
                known_processes.clear()
                known_processes.update(current_processes_light)

            current_connections = scan_connections()
            current_conn_keys = set(current_connections.keys())
            known_conn_keys = set(known_connections.keys())
            now_ts = now_utc()

            new_conn_keys = current_conn_keys - known_conn_keys
            for key in new_conn_keys:
                record = dict(current_connections[key])
                pid = record.get("Network_Owning_PID")
                if pid is not None:
                    proc_record = get_process_detail(pid)
                    if proc_record:
                        record.update(proc_record)

                known_connections[key] = {"data": record, "first_seen": now_ts, "last_seen": now_ts}
                emit({"event": "new_connection", "timestamp": now_iso(), "data": record}, args.output)
                
                proc_fields = {k: v for k, v in record.items() if k.startswith("Internal_")} if any(k.startswith("Internal_") for k in record.keys()) else None
                _queue_monitor_row(args.db_file, proc_fields, record, is_orphan=False)

            for key in current_conn_keys & known_conn_keys:
                meta = known_connections.get(key)
                if meta:
                    meta["last_seen"] = now_ts
                    if not meta["data"]:
                        meta["data"] = current_connections[key]

            if args.emit_ended:
                ended_conn_keys = known_conn_keys - current_conn_keys
                for key in ended_conn_keys:
                    known_connections.pop(key, None)
            else:
                ended_conn_keys = set()

    except KeyboardInterrupt:
        log.info("Monitor stopped by user.")
        stop_event.set()
        try:
            wmi_thread.join(timeout=2.0)
        except Exception:
            pass

if __name__ == "__main__":
    main()