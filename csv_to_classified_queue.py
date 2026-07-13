# csv_to_classified_queue.py

"""
IEPIS - Corrected CSV → SQLite Bridge (v2)
------------------------------------------
Reads results_stream.csv produced by classifier_batch.py
and writes each row into the classified_queue table in iepis_queue.db.

Fixes:
1. Fingerprint hashing now matches monitor_input_hybrid.py exactly.
2. classified_queue table is created once at startup, not per insert.
3. INSERT OR IGNORE prevents duplicates.
4. Efficient continuous polling loop.
"""

import os
import csv
import json
import time
import argparse
import logging
import sqlite3
import hashlib
from pathlib import Path
from typing import Dict, Any

DB_DEFAULT_PATH = "iepis_queue.db"
RESULTS_STREAM_DEFAULT = "results_stream.csv"
POLL_INTERVAL_DEFAULT = 1.0

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CSVBridge] %(levelname)s %(message)s"
)
log = logging.getLogger("iepis_csv_bridge")


# ─────────────────────────────────────────────────────────
# SQLite Setup
# ─────────────────────────────────────────────────────────

def setup_classified_queue(db_file: str):
    """Create classified_queue table once at startup."""
    with sqlite3.connect(db_file) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS classified_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE,
                payload TEXT,
                classification TEXT,
                confidence TEXT,
                reason TEXT,
                threat_intel TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed INTEGER DEFAULT 0
            )
        """)
        conn.commit()


# ─────────────────────────────────────────────────────────
# Fingerprint (MUST match monitor_input_hybrid.py)
# ─────────────────────────────────────────────────────────

def compute_fingerprint(row: Dict[str, Any]) -> str:
    """
    EXACT same fingerprint logic as monitor_input_hybrid.py:
    SHA-256 hash of JSON(key)
    """
    key = (
        row.get("pid"),
        row.get("process_hash_sha256"),
        row.get("network_protocol"),
        row.get("network_out_process_ip"),
        row.get("network_out_process_port"),
        row.get("network_connection_state"),
        row.get("command_line"),
    )

    return hashlib.sha256(
        json.dumps(key, sort_keys=True).encode()
    ).hexdigest()


# ─────────────────────────────────────────────────────────
# Insert Row
# ─────────────────────────────────────────────────────────

def insert_row(db_file: str, row: Dict[str, Any]):
    """Insert a classified row into SQLite using fingerprint deduplication."""
    fingerprint = compute_fingerprint(row)
    payload = json.dumps(row, default=str)

    classification = row.get("AI__Model_classification", "")
    confidence = row.get("AI__Model_confidence", "")
    reason = row.get("AI__Model_Reason", "")
    threat_intel = row.get("AI__Threat_Intel_Finding", "")

    try:
        with sqlite3.connect(db_file) as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO classified_queue
                (fingerprint, payload, classification, confidence, reason, threat_intel, processed)
                VALUES (?, ?, ?, ?, ?, ?, 0)
                """,
                (fingerprint, payload, classification, confidence, reason, threat_intel)
            )
            conn.commit()
    except sqlite3.Error as e:
        log.error(f"DB insert error: {e}")


# ─────────────────────────────────────────────────────────
# Continuous Bridge Loop
# ─────────────────────────────────────────────────────────

def bridge_loop(results_path: Path, db_file: str, poll_interval: float):
    log.info(
        f"Starting CSV→SQLite bridge | results_stream={results_path} | db={db_file} | poll_interval={poll_interval}s"
    )

    # Ensure table exists once
    setup_classified_queue(db_file)

    # Wait for CSV to appear
    while not results_path.exists():
        log.info(f"Waiting for {results_path} to be created...")
        time.sleep(poll_interval)

    last_size = 0

    while True:
        try:
            current_size = results_path.stat().st_size

            # No new data
            if current_size == last_size:
                time.sleep(poll_interval)
                continue

            # Read entire CSV (INSERT OR IGNORE prevents duplicates)
            with results_path.open("r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    insert_row(db_file, row)

            last_size = current_size
            time.sleep(poll_interval)

        except KeyboardInterrupt:
            log.info("CSV bridge stopped by user.")
            break
        except Exception as e:
            log.error(f"Bridge loop error: {e}")
            time.sleep(poll_interval)


def main():
    parser = argparse.ArgumentParser(description="IEPIS CSV → SQLite Bridge (Corrected)")
    parser.add_argument("--db-file", default=DB_DEFAULT_PATH, help="SQLite DB file")
    parser.add_argument("--results-stream", default=RESULTS_STREAM_DEFAULT, help="CSV file produced by classifier_batch.py")
    parser.add_argument("--poll-interval", type=float, default=POLL_INTERVAL_DEFAULT, help="Seconds between CSV checks")
    args = parser.parse_args()

    try:
        bridge_loop(Path(args.results_stream), args.db_file, args.poll_interval)
    except KeyboardInterrupt:
        log.info("Bridge stopped.")


if __name__ == "__main__":
    main()
