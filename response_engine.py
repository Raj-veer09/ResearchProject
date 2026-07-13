# response_engine_v5.py

"""
IEPIS - Response Engine v5 (Continuous, Policy-Based, Dry-Run, Alert-Aware)
---------------------------------------------------------------------------
Consumes classified_queue from iepis_queue.db (populated by csv_to_classified_queue.py).

Final policy:

BENIGN / UNKNOWN / ERROR
    → No automated action (logged as NO_ACTION)

MALICIOUS + LOW
    → Alert only (ALERT_SENT)

MALICIOUS + MEDIUM
    → Alert (ALERT_SENT)
    → Block public IP (if present)

MALICIOUS + HIGH
    → Kill process tree
    → If kill successful: Quarantine executable (unless trusted Windows binary)
    → Block public IP (if present)

All actions are DISABLED by default via configuration flags (dry-run mode).
"""

import json
import time
import argparse
import logging
import sqlite3
import subprocess
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

import psutil

DB_DEFAULT_PATH = "iepis_queue.db"
POLL_INTERVAL_DEFAULT = 0.5
MICRO_BATCH_SIZE = 20

ENABLE_PROCESS_TERMINATION = False
ENABLE_FIREWALL_BLOCK = False
ENABLE_QUARANTINE = False
ENABLE_ALERTING = False  # alerts are logged regardless; this flag controls real alert side-effects

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


def fetch_unprocessed_records(db_path: str, limit: int) -> List[Dict[str, Any]]:
    rows = []
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, payload, classification, confidence, reason, threat_intel
            FROM classified_queue
            WHERE processed = 0
            ORDER BY id ASC
            LIMIT ?
            """,
            (limit,)
        )
        for cid, payload_str, classification, confidence, reason, threat_intel in cursor.fetchall():
            try:
                payload = json.loads(payload_str)
            except json.JSONDecodeError:
                payload = {}

            payload["__classified_id"] = cid
            payload["AI__Model_classification"] = classification
            payload["AI__Model_confidence"] = confidence
            payload["AI__Model_Reason"] = reason
            payload["AI__Threat_Intel_Finding"] = threat_intel

            rows.append(payload)
    return rows


def mark_processed(db_path: str, ids: List[int]):
    if not ids:
        return
    with sqlite3.connect(db_path) as conn:
        placeholders = ",".join(["?"] * len(ids))
        conn.execute(
            f"UPDATE classified_queue SET processed = 1 WHERE id IN ({placeholders})",
            ids
        )
        conn.commit()


def log_incident(
    db_path: str,
    timestamp: str,
    pid: int | None,
    process_name: str,
    parent_pid: int | None,
    exe_path: str,
    process_hash: str,
    remote_ip: str | None,
    classification: str,
    confidence: str,
    action: str,
    executed: bool,
    status: str,
    reason: str,
    threat_intel: str,
):
    setup_incident_log(db_path)
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
                timestamp,
                pid,
                process_name,
                parent_pid,
                exe_path,
                process_hash,
                remote_ip,
                classification,
                confidence,
                action,
                1 if executed else 0,
                status,
                reason,
                threat_intel,
            )
        )
        conn.commit()


# ─────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────

def is_trusted_windows_binary(path: str, cert_status: str) -> bool:
    if not path:
        return False
    path_lower = path.lower()
    return cert_status.lower() == "signed" and path_lower.startswith(r"c:\windows")


def validate_public_ip(ip: str) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_reserved:
        return None
    return ip


# ─────────────────────────────────────────────────────────
# Actions (Dry-Run Capable)
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
    procs = children + [root]  # children first, parent last
    log.info(f"Killing process tree (children first): {[p.pid for p in procs]}")

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
        log.info("[Quarantine] No executable path provided.")
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
            log.warning(f"Executable not found: {path}")
            return False

        dst = QUARANTINE_DIR / src.name
        src.rename(dst)

        meta = {
            "original_path": path,
            "quarantined_path": str(dst),
            "timestamp": datetime.utcnow().isoformat(),
            "reason": reason,
            "threat_intel": threat_intel,
            "cert_status": cert_status,
        }

        meta_path = QUARANTINE_DIR / (src.name + ".meta.json")
        with meta_path.open("w") as f:
            json.dump(meta, f, indent=2)

        return True

    except Exception as e:
        log.error(f"Quarantine error: {e}")
        return False


def firewall_rule_exists(ip: str) -> bool:
    rule_name = f"IEPIS_Block_{ip}"
    ps_cmd = f"Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue"
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
        )
        return bool(result.stdout.strip())
    except Exception:
        return False


def block_ip(ip: str, reason: str) -> bool:
    ip = validate_public_ip(ip)
    if not ip:
        log.info("[Firewall] IP is invalid or non-public; skipping.")
        return False

    rule_name = f"IEPIS_Block_{ip}"

    if not ENABLE_FIREWALL_BLOCK:
        log.info(f"[DRY RUN] Would block IP {ip} via New-NetFirewallRule | reason={reason}")
        return False

    if firewall_rule_exists(ip):
        log.info(f"[Firewall] Rule already exists for IP {ip}; skipping.")
        return False

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


def alert_user(pid: int | None, process_name: str, classification: str, confidence: str, reason: str, threat_intel: str):
    msg = (
        f"[ALERT] PID={pid}, process={process_name}, classification={classification}, "
        f"confidence={confidence}, reason={reason}, threat_intel={threat_intel}"
    )
    log.warning(msg)
    if ENABLE_ALERTING:
        # Placeholder for future integration (GUI popup, email, webhook, etc.)
        pass


# ─────────────────────────────────────────────────────────
# Policy Engine (Process + Connection)
# ─────────────────────────────────────────────────────────

def decide_process_actions(classification: str, confidence: str) -> List[str]:
    classification = (classification or "").upper()
    confidence = (confidence or "").upper()

    if classification != "MALICIOUS":
        return []

    if confidence == "LOW":
        return ["alert"]

    if confidence == "MEDIUM":
        return ["alert"]

    if confidence == "HIGH":
        return ["kill_tree", "quarantine"]

    return []


def decide_connection_actions(classification: str, confidence: str, remote_ip: str) -> List[str]:
    classification = (classification or "").upper()
    confidence = (confidence or "").upper()

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
    cid = record["__classified_id"]

    pid = None
    try:
        pid = int(record.get("pid"))
    except Exception:
        pass

    process_name = record.get("process_name") or ""
    parent_pid = record.get("parent_pid")
    exe_path = record.get("process_executable_path") or ""
    process_hash = record.get("process_hash_sha256") or ""
    remote_ip_raw = record.get("network_out_process_ip") or ""

    classification = record.get("AI__Model_classification") or ""
    confidence = record.get("AI__Model_confidence") or ""
    reason = record.get("AI__Model_Reason") or ""
    threat_intel = record.get("AI__Threat_Intel_Finding") or ""
    cert_status = record.get("cert_status") or ""

    process_actions = decide_process_actions(classification, confidence)
    connection_actions = decide_connection_actions(classification, confidence, remote_ip_raw)

    timestamp = datetime.utcnow().isoformat()

    if not process_actions and not connection_actions:
        log.info(
            f"No actions for classified_id={cid}, PID={pid}, name={process_name}: "
            f"classification={classification}, confidence={confidence}"
        )
        log_incident(
            db_path,
            timestamp,
            pid,
            process_name,
            parent_pid,
            exe_path,
            process_hash,
            validate_public_ip(remote_ip_raw),
            classification,
            confidence,
            "none",
            False,
            "NO_ACTION",
            reason,
            threat_intel,
        )
        return

    log.info(
        f"Policy decision for classified_id={cid}, PID={pid}, name={process_name}: "
        f"classification={classification}, confidence={confidence}, "
        f"process_actions={process_actions}, connection_actions={connection_actions}"
    )

    # Process actions
    kill_ok = False
    for action in process_actions:
        executed = False
        status = "DRY_RUN_OR_FAILED"

        if action == "alert":
            alert_user(pid, process_name, classification, confidence, reason, threat_intel)
            executed = True  # alert considered executed
            status = "ALERT_SENT"

        elif action == "kill_tree" and pid is not None:
            kill_ok = kill_process_tree(pid)
            executed = kill_ok
            status = "OK" if executed else status

        elif action == "quarantine":
            if kill_ok or not ENABLE_PROCESS_TERMINATION:
                executed = quarantine_file(exe_path, reason, threat_intel, cert_status)
                status = "OK" if executed else status
            else:
                log.info("[Quarantine] Skipping because kill_tree did not succeed.")
                executed = False
                status = "SKIPPED_KILL_FAILED"

        log_incident(
            db_path,
            timestamp,
            pid,
            process_name,
            parent_pid,
            exe_path,
            process_hash,
            validate_public_ip(remote_ip_raw),
            classification,
            confidence,
            action,
            executed,
            status,
            reason,
            threat_intel,
        )

    # Connection actions
    for action in connection_actions:
        executed = False
        status = "DRY_RUN_OR_FAILED"

        if action == "alert":
            alert_user(pid, process_name, classification, confidence, reason, threat_intel)
            executed = True
            status = "ALERT_SENT"

        elif action == "block_ip":
            executed = block_ip(remote_ip_raw, reason)
            status = "OK" if executed else status

        log_incident(
            db_path,
            timestamp,
            pid,
            process_name,
            parent_pid,
            exe_path,
            process_hash,
            validate_public_ip(remote_ip_raw),
            classification,
            confidence,
            action,
            executed,
            status,
            reason,
            threat_intel,
        )


def response_loop(db_path: str, poll_interval: float):
    QUARANTINE_DIR.mkdir(exist_ok=True)
    setup_incident_log(db_path)

    log.info(f"Response Engine v5 started | db={db_path}")

    while True:
        records = fetch_unprocessed_records(db_path, MICRO_BATCH_SIZE)

        if not records:
            time.sleep(poll_interval)
            continue

        ids = [r["__classified_id"] for r in records]

        for rec in records:
            process_record(db_path, rec)

        mark_processed(db_path, ids)

        time.sleep(poll_interval)


def main():
    parser = argparse.ArgumentParser(description="IEPIS Response Engine v5 (Policy-Based, Continuous, Dry-Run)")
    parser.add_argument("--db-file", default=DB_DEFAULT_PATH)
    parser.add_argument("--poll-interval", type=float, default=POLL_INTERVAL_DEFAULT)
    args = parser.parse_args()

    try:
        response_loop(args.db_file, args.poll_interval)
    except KeyboardInterrupt:
        log.info("Response engine stopped.")


if __name__ == "__main__":
    main()
