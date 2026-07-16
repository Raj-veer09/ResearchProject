# response_engine_v5.py

"""
IEPIS - Response Engine v5 (ZeroMQ Subscriber, Policy-Based, Dry-Run, Alert-Aware)
----------------------------------------------------------------------------------
Consumes MALICIOUS events published by AI_model_classification_realtime.py via
ZeroMQ PUB/SUB, applies process and connection policies, executes actions
(Kill, Quarantine, Firewall) and logs incidents into SQLite incident_log.

Transport semantics:
- ZeroMQ PUB/SUB provides best-effort, at-most-once delivery.
- A PAIR-based startup handshake is used to reduce the chance of losing the
  first message, but messages may still be lost if the classifier or subscriber
  is unavailable.
"""

import json
import argparse
import logging
import sqlite3
import subprocess
import ipaddress
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, Any

import psutil
import zmq

DB_DEFAULT_PATH = "iepis_queue.db"
PUB_ENDPOINT_DEFAULT = "tcp://127.0.0.1:5555"
SYNC_ENDPOINT_DEFAULT = "tcp://127.0.0.1:5556"

ENABLE_PROCESS_TERMINATION = False
ENABLE_FIREWALL_BLOCK = False
ENABLE_QUARANTINE = False
ENABLE_ALERTING = False

QUARANTINE_DIR = Path("quarantine")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ResponseEngine] %(levelname)s %(message)s"
)
log = logging.getLogger("iepis_response")


# ─────────────────────────────────────────────────────────
# SQLite Helpers
# ─────────────────────────────────────────────────────────

def setup_incident_log(db_path: str):
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incident_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                pid INTEGER,
                process_name TEXT,
                parent_pid INTEGER,
                process_executable_path TEXT,
                process_hash_sha256 TEXT,
                remote_ip TEXT,
                classification TEXT,
                confidence TEXT,
                action TEXT,
                executed INTEGER,
                status TEXT,
                reason TEXT,
                threat_intel TEXT
            )
        """)
        conn.commit()


def log_incident(db_path: str, incident: Dict[str, Any]):
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO incident_log
            (timestamp, pid, process_name, parent_pid, process_executable_path,
             process_hash_sha256, remote_ip, classification, confidence,
             action, executed, status, reason, threat_intel)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident["timestamp"],
                incident["pid"],
                incident["process_name"],
                incident["parent_pid"],
                incident["process_executable_path"],
                incident["process_hash_sha256"],
                incident["remote_ip"],
                incident["classification"],
                incident["confidence"],
                incident["action"],
                1 if incident["executed"] else 0,
                incident["status"],
                incident["reason"],
                incident["threat_intel"],
            )
        )
        conn.commit()


# ─────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────

def validate_public_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_reserved:
        return None
    return ip


def is_trusted_windows_binary(path: str, cert_status: str) -> bool:
    if not path:
        return False
    return cert_status.lower() == "signed" and path.lower().startswith("c:\\windows")


# ─────────────────────────────────────────────────────────
# Actions
# ─────────────────────────────────────────────────────────

def kill_process_tree(pid: int) -> bool:
    if not ENABLE_PROCESS_TERMINATION:
        log.info(f"[DRY RUN] Would kill process tree for PID {pid}")
        return False

    try:
        root = psutil.Process(pid)
    except psutil.NoSuchProcess:
        log.warning(f"PID {pid} does not exist.")
        return False

    children = root.children(recursive=True)
    procs = children + [root]

    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass

    gone, alive = psutil.wait_procs(procs, timeout=5)
    for p in alive:
        try:
            p.kill()
        except Exception:
            pass

    return True


def quarantine_file(path: str, reason: str, threat_intel: str, cert_status: str) -> bool:
    if not path:
        return False

    if is_trusted_windows_binary(path, cert_status):
        log.info(f"[Quarantine] Skipping trusted Windows binary: {path}")
        return False

    if not ENABLE_QUARANTINE:
        log.info(f"[DRY RUN] Would quarantine file: {path}")
        return False

    try:
        QUARANTINE_DIR.mkdir(exist_ok=True)
        src = Path(path)
        if not src.exists():
            return False

        dst = QUARANTINE_DIR / src.name
        src.rename(dst)

        meta = {
            "original_path": path,
            "quarantined_path": str(dst),
            "timestamp": datetime.now(UTC).isoformat(),
            "reason": reason,
            "threat_intel": threat_intel,
            "cert_status": cert_status,
        }

        with open(QUARANTINE_DIR / (src.name + ".meta.json"), "w") as f:
            json.dump(meta, f, indent=2)

        return True

    except Exception as e:
        log.error(f"Quarantine error: {e}")
        return False


def block_ip(ip: str, reason: str) -> bool:
    ip = validate_public_ip(ip)
    if not ip:
        return False

    if not ENABLE_FIREWALL_BLOCK:
        log.info(f"[DRY RUN] Would block IP {ip}")
        return False

    rule_name = f"IEPIS_Block_{ip}"

    try:
        ps_cmd = (
            f"New-NetFirewallRule -DisplayName '{rule_name}' "
            f"-Direction Outbound -RemoteAddress {ip} -Action Block"
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except Exception as e:
        log.error(f"Firewall error: {e}")
        return False


def alert_user(pid, process_name, classification, confidence, reason, threat_intel):
    msg = (
        f"[ALERT] PID={pid}, process={process_name}, classification={classification}, "
        f"confidence={confidence}, reason={reason}, threat_intel={threat_intel}"
    )
    if not ENABLE_ALERTING:
        log.info(f"[DRY RUN] Would alert user: {msg}")
        return
    log.warning(msg)


# ─────────────────────────────────────────────────────────
# Policy Engine
# ─────────────────────────────────────────────────────────

def decide_process_actions(classification: str, confidence: str):
    classification = classification.upper()
    confidence = confidence.upper()

    if classification != "MALICIOUS":
        return []

    if confidence == "LOW":
        return ["alert"]
    if confidence == "MEDIUM":
        return ["alert"]
    if confidence == "HIGH":
        return ["kill_tree", "quarantine"]

    return []


def decide_connection_actions(classification: str, confidence: str, remote_ip: str | None):
    classification = classification.upper()
    confidence = confidence.upper()

    if classification != "MALICIOUS":
        return []

    remote_ip = validate_public_ip(remote_ip)
    if not remote_ip:
        return []

    if confidence == "LOW":
        return ["alert"]
    if confidence == "MEDIUM":
        return ["alert", "block_ip"]
    if confidence == "HIGH":
        return ["alert", "block_ip"]

    return []


# ─────────────────────────────────────────────────────────
# Core Processing
# ─────────────────────────────────────────────────────────

def process_record(db_path: str, record: Dict[str, Any]):
    pid = record.get("pid")
    process_name = record.get("process_name")
    parent_pid = record.get("parent_pid")
    exe_path = record.get("process_executable_path")
    process_hash = record.get("process_hash_sha256")
    remote_ip_raw = record.get("network_out_process_ip")

    classification = record.get("AI__Model_classification")
    confidence = record.get("AI__Model_confidence")
    reason = record.get("AI__Model_Reason")
    threat_intel = record.get("AI__Threat_Intel_Finding")
    cert_status = record.get("cert_status")

    timestamp = datetime.now(UTC).isoformat()
    remote_ip_valid = validate_public_ip(remote_ip_raw)

    process_actions = decide_process_actions(classification, confidence)
    connection_actions = decide_connection_actions(classification, confidence, remote_ip_raw)

    if not process_actions and not connection_actions:
        incident = {
            "timestamp": timestamp,
            "pid": pid,
            "process_name": process_name,
            "parent_pid": parent_pid,
            "process_executable_path": exe_path,
            "process_hash_sha256": process_hash,
            "remote_ip": remote_ip_valid,
            "classification": classification,
            "confidence": confidence,
            "action": "none",
            "executed": False,
            "status": "NO_ACTION",
            "reason": reason,
            "threat_intel": threat_intel,
        }
        log_incident(db_path, incident)
        return

    kill_ok = False

    # Process actions
    for action in process_actions:
        executed = False
        status = "DRY_RUN_OR_FAILED"

        if action == "alert":
            alert_user(pid, process_name, classification, confidence, reason, threat_intel)
            executed = ENABLE_ALERTING
            status = "ALERT_SENT" if executed else "ALERT_DRY_RUN"

        elif action == "kill_tree":
            kill_ok = kill_process_tree(pid)
            executed = kill_ok
            status = "OK" if executed else status

        elif action == "quarantine":
            if kill_ok or not ENABLE_PROCESS_TERMINATION:
                executed = quarantine_file(exe_path, reason, threat_intel, cert_status)
                status = "OK" if executed else status
            else:
                status = "SKIPPED_KILL_FAILED"

        incident = {
            "timestamp": timestamp,
            "pid": pid,
            "process_name": process_name,
            "parent_pid": parent_pid,
            "process_executable_path": exe_path,
            "process_hash_sha256": process_hash,
            "remote_ip": remote_ip_valid,
            "classification": classification,
            "confidence": confidence,
            "action": action,
            "executed": executed,
            "status": status,
            "reason": reason,
            "threat_intel": threat_intel,
        }
        log_incident(db_path, incident)

    # Connection actions
    for action in connection_actions:
        executed = False
        status = "DRY_RUN_OR_FAILED"

        if action == "alert":
            alert_user(pid, process_name, classification, confidence, reason, threat_intel)
            executed = ENABLE_ALERTING
            status = "ALERT_SENT" if executed else "ALERT_DRY_RUN"

        elif action == "block_ip":
            executed = block_ip(remote_ip_raw, reason)
            status = "OK" if executed else status

        incident = {
            "timestamp": timestamp,
            "pid": pid,
            "process_name": process_name,
            "parent_pid": parent_pid,
            "process_executable_path": exe_path,
            "process_hash_sha256": process_hash,
            "remote_ip": remote_ip_valid,
            "classification": classification,
            "confidence": confidence,
            "action": action,
            "executed": executed,
            "status": status,
            "reason": reason,
            "threat_intel": threat_intel,
        }
        log_incident(db_path, incident)


# ─────────────────────────────────────────────────────────
# ZeroMQ Subscriber (Poller-based)
# ─────────────────────────────────────────────────────────

def subscriber_loop(db_path: str, pub_endpoint: str, sync_endpoint: str):
    QUARANTINE_DIR.mkdir(exist_ok=True)
    setup_incident_log(db_path)

    context = zmq.Context()

    sub = context.socket(zmq.SUB)
    sub.connect(pub_endpoint)
    sub.setsockopt_string(zmq.SUBSCRIBE, "")

    sync = context.socket(zmq.PAIR)
    sync.connect(sync_endpoint)

    log.info(f"Response Engine v5 started | db={db_path} | sub={pub_endpoint} | sync={sync_endpoint}")
    print(f"[ResponseEngine] Sending READY to classifier...")
    sync.send_string("READY")

    poller = zmq.Poller()
    poller.register(sub, zmq.POLLIN)

    try:
        while True:
            events = dict(poller.poll(1000))  # 1 second timeout

            if sub in events:
                try:
                    msg = sub.recv_string()
                    record = json.loads(msg)
                    process_record(db_path, record)
                except json.JSONDecodeError:
                    log.error(f"Invalid JSON received: {msg[:200]!r}")
                except Exception as e:
                    log.error(f"Processing error: {e}")

    except KeyboardInterrupt:
        log.info("Response engine stopped.")

    finally:
        sub.close()
        sync.close()
        context.term()
        log.info("Response Engine shutdown complete.")


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IEPIS Response Engine v5 (ZeroMQ Subscriber)")
    parser.add_argument("--db-file", default=DB_DEFAULT_PATH)
    parser.add_argument("--pub-endpoint", default=PUB_ENDPOINT_DEFAULT)
    parser.add_argument("--sync-endpoint", default=SYNC_ENDPOINT_DEFAULT)
    args = parser.parse_args()

    subscriber_loop(args.db_file, args.pub_endpoint, args.sync_endpoint)


if __name__ == "__main__":
    main()
