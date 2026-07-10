"""
IEPIS - Data Cleaner + Web-Search-Grounded LLM Classifier (Batch Mode)
-------------------------------------------------------------
Step 1: Parse telemetry from the SQLite queue populated by monitor_input_hybrid.py
Step 2: Clean + format the joined, tabular data
Step 3: Send the ENTIRE batch (default 10) to Claude in a single prompt.
Step 4: Claude returns a JSON array of classifications.
Step 5: Safely write to CSV and delete processed rows from DB.
"""

import os
import json
import time
import argparse
import logging
import re
import sqlite3
from pathlib import Path

import pandas as pd
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ANTHROPIC_API_KEY")
client = Anthropic(api_key=API_KEY) if API_KEY else None

logging.basicConfig(
    filename="iepis_audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("IEPIS")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("anthropic").setLevel(logging.WARNING)

# Changed default batch size to 10 for bulk LLM processing
DEFAULT_BATCH_SIZE = 10
DEFAULT_DB_FILE = "iepis_queue.db"
DEFAULT_RESULTS_FILE = "results_stream.csv"
DEFAULT_POLL_INTERVAL = 2.0

###########################################################################
# Queue Consumer (SQLite DB Integration)
###########################################################################

class DBQueueConsumer:

    def __init__(
        self,
        db_file: str,
        batch_size: int = DEFAULT_BATCH_SIZE,
        poll_interval: float = DEFAULT_POLL_INTERVAL
    ):
        self.db_file = db_file
        self.batch_size = batch_size
        self.poll_interval = poll_interval
        
        self._ensure_db()

    def _ensure_db(self):
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS event_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT UNIQUE,
                    payload TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def get_next_batch(self):
        batch_rows = []
        batch_ids = []
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, payload FROM event_queue ORDER BY id ASC LIMIT ?", 
                    (self.batch_size,)
                )
                rows = cursor.fetchall()

                for row_id, payload_str in rows:
                    try:
                        batch_rows.append(json.loads(payload_str))
                        batch_ids.append(row_id)
                    except json.JSONDecodeError:
                        logger.warning(f"Skipping and deleting invalid JSON at DB row id={row_id}")
                        conn.execute("DELETE FROM event_queue WHERE id = ?", (row_id,))
                        conn.commit()
                        
        except sqlite3.Error as e:
            logger.error(f"Database read error: {e}")

        return batch_rows, batch_ids

    def delete_processed_rows(self, batch_ids: list):
        if not batch_ids:
            return
            
        try:
            with sqlite3.connect(self.db_file) as conn:
                placeholders = ",".join(["?"] * len(batch_ids))
                conn.execute(
                    f"DELETE FROM event_queue WHERE id IN ({placeholders})", 
                    batch_ids
                )
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to delete processed rows from DB: {e}")

    def wait_for_batch(self):
        while True:
            batch, batch_ids = self.get_next_batch()

            if batch:
                return batch, batch_ids

            print("[Queue] Waiting for data...")
            time.sleep(self.poll_interval)


###########################################################################
# CSV helpers
###########################################################################

RESULT_COLUMNS = [
    "pid", "process_name", "process_owner", "process_hash_sha256", "cert_status", 
    "thread_count", "parent_pid", "command_line", "process_executable_path",
    "has_connection", "network_protocol", "network_connection_state",
    "network_out_process_ip", "network_out_process_fqdn", "network_out_process_port", "network_out_process_service",
    "network_in_process_ip", "network_in_process_fqdn", "network_in_process_port", "network_in_process_service",
    "is_orphan_connection", "AI__Model_classification", "AI__Model_confidence", 
    "AI__Threat_Intel_Finding", "AI__Model_Reason"
]

def append_results(df, output_file):
    file_exists = os.path.exists(output_file)
    df.to_csv(
        output_file,
        mode="a",
        index=False,
        header=not file_exists,
        columns=RESULT_COLUMNS
    )

# ─────────────────────────────────────────────────────────
# STEP 4: Build prompt
# ─────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are a cybersecurity analyst for an endpoint intrusion detection system (IEPIS).
You will be given a BATCH of JOINED telemetry records. Each record represents a process and/or its associated network connection.

---
## MANDATORY ANALYSIS PROCEDURE

STEP 1 — Perform Threat Intelligence Verification
Before classifying the records, ALWAYS perform web searches for suspicious indicators across the batch.
Check available artifacts like SHA-256 hashes, Destination IPs, FQDNs, Command lines, and Certificates.
Consult reputable public threat intelligence sources.

STEP 2 — Classify EACH Record
Use ONLY these labels:
BENIGN: Normal operating-system activity or expected application behavior.
MALICIOUS: Threat intelligence confirms maliciousness OR multiple behavioral indicators strongly suggest malicious activity.

---
## OUTPUT QUALITY REQUIREMENTS
• Write like a SOC analyst.
• Prefer concise factual findings over long explanations.
• Target approximately 60–90 words for the threat intel finding and reason per record.

You MUST return your answer as a JSON ARRAY of objects. 
Each object must correspond to the "Record Index" provided in the prompt.

Return ONLY valid JSON in this exact format:
[
  {
    "index": 0,
    "classification": "BENIGN" | "MALICIOUS",
    "confidence": "LOW" | "MEDIUM" | "HIGH",
    "threat_intel_finding": "...",
    "reason": "..."
  },
  {
    "index": 1,
    "classification": "...",
    "confidence": "...",
    "threat_intel_finding": "...",
    "reason": "..."
  }
]

Do NOT return nested JSON inside those fields. Do NOT return Markdown outside the JSON array.
"""

def build_batch_prompt(df):
    """Builds a single prompt containing all records in the batch."""
    lines = [
        f"Analyze the following batch of {len(df)} telemetry records.",
        "Return a JSON array containing your analysis for EACH record, matching the 'Record Index'.",
        "====================================================="
    ]
    
    for i, row in df.iterrows():
        lines.extend([
            f"Record Index: {i}",
            "-------------------",
            f"Process Name          : {row.get('process_name', 'unknown')} (PID: {row.get('pid', 'unknown')})",
            f"Owner                 : {row.get('process_owner', 'unknown')}",
            f"Process Hash (SHA-256): {row.get('process_hash_sha256', 'unknown')}",
            f"Certificate Status    : {row.get('cert_status', 'unknown')}",
            f"Command Line          : {row.get('command_line', 'unknown')}",
            f"Is Orphan Connection  : {row.get('is_orphan_connection', False)}",
            f"Protocol              : {row.get('network_protocol', 'unknown')}",
            f"Connection State      : {row.get('network_connection_state', 'unknown')}",
            f"Outbound IP           : {row.get('network_out_process_ip', 'unknown')}:{row.get('network_out_process_port', 'unknown')}",
            f"Outbound FQDN         : {row.get('network_out_process_fqdn', 'unknown')}",
            "====================================================="
        ])
    return "\n".join(lines)


def query_llm_batch(prompt, batch_size, max_retries=5):
    """Sends the entire batch to Claude and parses the returned JSON array."""
    if not client:
        logger.error("ANTHROPIC_API_KEY not set.")
        return []

    for attempt in range(max_retries):
        try:
            response = client.messages.create(
                model="claude-sonnet-4-6", # Reverted to your original model string
                max_tokens=8192,
                temperature=0,
                system=SYSTEM_PROMPT,
                tools=[{"type": "web_search_20250305", "name": "web_search"}],
                messages=[{"role": "user", "content": prompt}]
            )

            final_text = None
            for block in response.content:
                if block.type == "text":
                    final_text = block.text

            if not final_text:
                raise ValueError("No text response from model.")

            text = final_text.strip()
            text = re.sub(r"```json\s*", "", text)
            text = re.sub(r"```\s*", "", text)
            
            # Match JSON Array instead of single object
            m = re.search(r"\[.*\]", text, re.DOTALL)
            if not m:
                raise json.JSONDecodeError("No JSON array found", text, 0)

            result_array = json.loads(m.group())
            return result_array

        except Exception as e:
            err_str = str(e)
            if "429" in err_str or "rate_limit" in err_str:
                wait = (2 ** attempt) * 15
                print(f"    [RATE LIMIT] attempt {attempt+1}/{max_retries} — waiting {wait}s...")
                time.sleep(wait)
                continue

            print(f"    [WARN] LLM parsing failed: {err_str}")
            return []

    return []

###########################################################################
# Batch Classification
###########################################################################

def classify_batch(batch_rows):
    df = pd.DataFrame(batch_rows)
    if df.empty:
        return df

    # Reset index so it matches exactly 0 to len(df)-1
    df = df.reset_index(drop=True)
    total = len(df)

    print(f"\nSending batch of {total} records to LLM in a single prompt...")
    
    prompt = build_batch_prompt(df)
    results_array = query_llm_batch(prompt, total)

    # Initialize columns with error state in case LLM drops records
    df["AI__Model_classification"] = "ERROR"
    df["AI__Model_confidence"] = "LOW"
    df["AI__Threat_Intel_Finding"] = "Failed to process in batch."
    df["AI__Model_Reason"] = "LLM failed to return data for this record."

    # Map the returned array back to the dataframe using the 'index' key
    if results_array:
        for item in results_array:
            idx = item.get("index")
            if idx is not None and 0 <= idx < total:
                df.at[idx, "AI__Model_classification"] = item.get("classification", "UNKNOWN")
                df.at[idx, "AI__Model_confidence"] = item.get("confidence", "LOW")
                df.at[idx, "AI__Threat_Intel_Finding"] = item.get("threat_intel_finding", "")
                df.at[idx, "AI__Model_Reason"] = item.get("reason", "")

    # CRITICAL FIX: Ensure all expected columns exist before returning the DataFrame.
    # If a batch has only processes and no network connections, this prevents a KeyError 
    # when Pandas tries to write the network columns to the CSV.
    for col in RESULT_COLUMNS:
        if col not in df.columns:
            df[col] = None

    return df

###########################################################################
# Consumer Loop
###########################################################################

def consume_queue(db_file, results_file, batch_size, poll_interval):
    consumer = DBQueueConsumer(
        db_file=db_file,
        batch_size=batch_size,
        poll_interval=poll_interval,
    )

    print("\n" + "=" * 70)
    print("Database Queue Consumer Started (BATCH MODE)")
    print("=" * 70)
    print(f"Database File : {db_file}")
    print(f"Results File  : {results_file}")
    print(f"Batch Size    : {batch_size}")
    print(f"Poll Interval : {poll_interval}s")
    print("=" * 70)

    while True:
        batch_rows, batch_ids = consumer.wait_for_batch()
        
        if not batch_rows:
            time.sleep(poll_interval)
            continue

        try:
            # 1. Classify the ENTIRE batch at once
            classified_df = classify_batch(batch_rows)

            # 2. Write results to CSV
            append_results(classified_df, results_file)

            # 3. Remove processed items from Queue Database
            consumer.delete_processed_rows(batch_ids)

            print(f"Successfully processed and removed batch of {len(batch_rows)} records.")
            
            # Brief pause to respect API limits between bulk calls
            time.sleep(5)

        except KeyboardInterrupt:
            raise
        except Exception as e:
            logger.exception(e)
            print("\n" + "=" * 60)
            print("Batch failed. Queue state preserved in Database.")
            print("=" * 60)
            print(e)
            time.sleep(poll_interval)

# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IEPIS Bulk Queue Consumer")
    parser.add_argument("--db-file", default=DEFAULT_DB_FILE, help="SQLite queue file")
    parser.add_argument("--results-stream", default=DEFAULT_RESULTS_FILE, help="CSV file for AI results")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Number of records per LLM prompt")
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL, help="Seconds between DB checks")
    
    args = parser.parse_args()

    try:
        consume_queue(
            db_file=args.db_file,
            results_file=args.results_stream,
            batch_size=args.batch_size,
            poll_interval=args.poll_interval,
        )
    except KeyboardInterrupt:
        print("\n" + "=" * 60)
        print("Queue consumer stopped.")
        print("=" * 60)

if __name__ == "__main__":
    main()