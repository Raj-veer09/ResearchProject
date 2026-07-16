"""
IEPIS - Real-Time Data Cleaner + Web-Search-Grounded LLM Classifier (ZeroMQ Publisher)
-------------------------------------------------------------------------------------
Reads normalized telemetry rows from SQLite event_queue, sends each row to Claude
for web-search-grounded classification, writes an audit .log file, and publishes
ONLY MALICIOUS events via ZeroMQ PUB to the response engine.

Transport semantics:
- ZeroMQ PUB/SUB is best-effort, at-most-once.
- A simple PAIR-based startup handshake is used to reduce the chance of losing
  the first message, but delivery is not guaranteed if the subscriber is down.

Dependencies:
    pip install pandas anthropic python-dotenv pyzmq

Usage:
    python AI_model_classification_realtime.py --db-file iepis_queue.db
"""

import os
import json
import time
import argparse
import logging
import time
import re
import argparse
import sqlite3
import logging

import zmq
import pandas as pd
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ANTHROPIC_API_KEY")
client = Anthropic(api_key=API_KEY) if API_KEY else None

DB_DEFAULT_PATH = "iepis_queue.db"
PUB_ENDPOINT_DEFAULT = "tcp://127.0.0.1:5555"
SYNC_ENDPOINT_DEFAULT = "tcp://127.0.0.1:5556"
MICRO_BATCH_SIZE = 10

logging.basicConfig(
    filename="iepis_audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger("IEPIS")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("anthropic").setLevel(logging.WARNING)


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

Examples include:

• Reverse shells
• LOLBin abuse
• Encoded PowerShell
• Process masquerading
• Known malicious hashes
• Connections to known C2 infrastructure
• Hidden/orphan processes communicating externally

---

Classification Rules

1. Never invent information.
2. Unknown means unavailable — not malicious.
3. Evaluate ALL telemetry together.
4. Multiple weak indicators together may justify MALICIOUS.
5. If evidence is mixed but insufficient, classify BENIGN.
6. Always explain WHY.
7. If threat intelligence directly identifies an indicator as malicious, explicitly mention that finding.

---

Threat Intelligence Finding

Write this field EXACTLY using the following structure.

## Hash Lookup

...

## IP Lookup

...

## Domain Lookup

...

## Other Intelligence

...

## References Consulted

• ...
• ...
• ...

Rules

• Mention only searches actually performed.
• If unavailable write "Not Available."
• If no threat intelligence exists write "No malicious match found."
• If a match exists, state:
  - what was found
  - where it was found
• Avoid lengthy background explanations.
• Prefer concise intelligence summaries.
• Focus on findings rather than descriptions.
• One to three short sentences per section.
• Include the most important intelligence finding.
• Target approximately 60–90 words for most records.
• Up to 120 words only when a confirmed malicious match exists.

---

Reason

Write this field EXACTLY using the following structure.

## Indicators Observed

• ...

• ...

• ...

• ...

## Assessment

Write ONE concise paragraph explaining why those indicators support the final classification.

Rules

• Do not repeat the Threat Intelligence section.
• Mention strongest indicators first.
• Maximum 6 indicators.
• Each indicator should be short and factual.
• Focus only on evidence that influenced the final decision.
• Mention the strongest threat-intelligence finding if relevant.
• Keep the assessment concise.
• Target approximately 60–100 words.

---

OUTPUT QUALITY REQUIREMENTS

• Write like a SOC analyst.
• Prefer concise factual findings over long explanations.
• Target approximately 60–90 words for the threat intel finding and reason per record.

You MUST return your answer as a JSON ARRAY of objects. 
Each object must correspond to the "Record Index" provided in the prompt.

Return ONLY valid JSON.

{
"classification": "BENIGN" | "MALICIOUS",
"confidence": "LOW" | "MEDIUM" | "HIGH",
"threat_intel_finding": "...",
"reason": "..."
}

Both threat_intel_finding and reason MUST remain plain strings.

Do NOT return nested JSON.
Do NOT return Markdown.
Do NOT return explanations outside the JSON.

CRITICAL FORMATTING RULES

* Both threat_intel_finding and reason MUST be plain strings only.
* No nested JSON objects or arrays inside these fields.
* No markdown code fences anywhere in the response.
* The outer response must be a single valid JSON object and nothing else.
* Use \\n for newlines inside string fields if needed.
"""


def build_prompt(row: dict) -> str:
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


def query_llm(prompt: str, row: dict, max_retries: int = 5) -> dict:
    if not client:
        return {
            "classification": "ERROR",
            "confidence": "LOW",
            "threat_intel_finding": "",
            "reason": "ANTHROPIC_API_KEY not set."
        }

    for attempt in range(max_retries):
        start_time = time.time()
        try:
            response = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=2500,
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
                logger.error(
                    f"""
============================================================
PID: {row.get('pid')}
Process: {row.get('process_name')}

Status: ERROR

Error:
No text response from model.
============================================================
"""
                )
                return {
                    "classification": "ERROR",
                    "confidence": "LOW",
                    "threat_intel_finding": "",
                    "reason": "No text response from model."
                }

            text = final_text.strip()
            text = re.sub(r"```json\s*", "", text)
            text = re.sub(r"```\s*", "", text)
            text = text.strip()

            m = re.search(r"\{.*\}", text, re.DOTALL)
            if not m:
                print(f"    [WARN] No JSON found in response. Raw tail: {text[-200:]!r}")
                raise json.JSONDecodeError("No JSON object found", text, 0)

            result = json.loads(m.group())
            processing_time = round(time.time() - start_time, 2)

            identifier = (
                row.get("process_name")
                or row.get("network_out_process_fqdn")
                or row.get("network_out_process_ip")
                or "UNKNOWN"
            )

            logger.info(
                f"""
============================================================
Identifier: {identifier}

Telemetry Summary
-----------------
PID: {row.get('pid')}
Process: {row.get('process_name')}
Owner: {row.get('process_owner')}
Hash: {row.get('process_hash_sha256')}
Certificate: {row.get('cert_status')}

Has Connection: {row.get('has_connection')}
Orphan Connection: {row.get('is_orphan_connection')}

Executable Path:
{row.get('process_executable_path')}

Destination IP:
{row.get('network_out_process_ip')}

Destination FQDN:
{row.get('network_out_process_fqdn')}

Destination Port:
{row.get('network_out_process_port')}

Protocol:
{row.get('network_protocol')}

Connection State:
{row.get('network_connection_state')}

AI Classification
-----------------
Classification: {result.get('classification')}
Confidence: {result.get('confidence')}

Threat Intel
------------
{result.get('threat_intel_finding', '')}

Reason
------
{result.get('reason', '')}

Processing Time: {processing_time}s

Status: SUCCESS
============================================================
"""
            )

            return result

        except Exception as e:
            err_str = str(e)
            identifier = (
                row.get("process_name")
                or row.get("network_out_process_fqdn")
                or row.get("network_out_process_ip")
                or "UNKNOWN"
            )

            if "429" in err_str or "rate_limit" in err_str:
                logger.warning(
                    f"""
============================================================
Identifier: {identifier}

PID: {row.get('pid')}
Process: {row.get('process_name')}

Status: RATE_LIMIT

Attempt:
{attempt + 1}/{max_retries}

Error:
{err_str}
============================================================
"""
                )
                wait = (2 ** attempt) * 15
                print(f"    [RATE LIMIT] attempt {attempt+1}/{max_retries} — waiting {wait}s...")
                time.sleep(wait)
                continue

            if isinstance(e, json.JSONDecodeError):
                print(f"    [WARN] JSON parse failed: {e}")
                logger.warning(
                    f"""
============================================================
Identifier: {identifier}

PID: {row.get('pid')}
Process: {row.get('process_name')}

Status: JSON_PARSE_FAILURE

Error:
{e}
============================================================
"""
                )
                return {
                    "classification": "UNKNOWN",
                    "confidence": "LOW",
                    "threat_intel_finding": "",
                    "reason": "LLM response was not valid JSON"
                }

            logger.error(
                f"""
============================================================
Identifier: {identifier}

PID: {row.get('pid')}
Process: {row.get('process_name')}

Status: ERROR

Error:
{err_str}
============================================================
"""
            )
            return {
                "classification": "ERROR",
                "confidence": "LOW",
                "threat_intel_finding": "",
                "reason": err_str
            }

    logger.error(
        f"""
============================================================
PID: {row.get('pid')}
Process: {row.get('process_name')}

Status: ERROR

Error:
Exceeded {max_retries} retries due to rate limiting.
============================================================
"""
    )
    return {
        "classification": "ERROR",
        "confidence": "LOW",
        "threat_intel_finding": "",
        "reason": f"Exceeded {max_retries} retries due to rate limiting."
    }


def fetch_event_batch(db_path: str, limit: int) -> list[dict]:
    rows: list[dict] = []
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, payload
            FROM event_queue
            ORDER BY id ASC
            LIMIT ?
            """,
            (limit,)
        )
        for eid, payload_str in cursor.fetchall():
            try:
                payload = json.loads(payload_str)
            except json.JSONDecodeError:
                payload = {}
            payload["__event_id"] = eid
            rows.append(payload)
    return rows


def delete_event_batch(db_path: str, ids: list[int]):
    if not ids:
        return
    with sqlite3.connect(db_path) as conn:
        placeholders = ",".join(["?"] * len(ids))
        conn.execute(
            f"DELETE FROM event_queue WHERE id IN ({placeholders})",
            ids
        )
        conn.commit()


def normalize_row_for_classifier(raw: dict) -> dict:
    """
    Raw payload from monitor_input_hybrid.py is already in the classifier schema
    via _normalize_monitor_to_classifier_row, so we mostly pass through.
    """
    row = dict(raw)
    return row


def main():
    parser = argparse.ArgumentParser(description="IEPIS Real-Time Classifier + ZeroMQ Publisher")
    parser.add_argument("--db-file", default=DB_DEFAULT_PATH)
    parser.add_argument("--pub-endpoint", default=PUB_ENDPOINT_DEFAULT)
    parser.add_argument("--sync-endpoint", default=SYNC_ENDPOINT_DEFAULT)
    parser.add_argument("--batch-size", type=int, default=MICRO_BATCH_SIZE)
    args = parser.parse_args()

    context = zmq.Context()

    pub = context.socket(zmq.PUB)
    pub.bind(args.pub_endpoint)

    sync = context.socket(zmq.PAIR)
    sync.bind(args.sync_endpoint)

    logger.info(f"Classifier started | db={args.db_file} | pub={args.pub_endpoint} | sync={args.sync_endpoint}")
    print(f"[Classifier] Waiting for response engine READY on {args.sync_endpoint}...")

    try:
        sync.setsockopt(zmq.RCVTIMEO, 5000)
        msg = sync.recv_string()
        if msg != "READY":
            print(f"[Classifier] Unexpected sync message: {msg!r}")
        else:
            print("[Classifier] Response engine READY, starting classification loop.")
    except zmq.error.Again:
        print("[Classifier] No READY received within timeout; continuing anyway (messages may be lost if subscriber is not yet connected).")

    while True:
        batch = fetch_event_batch(args.db_file, args.batch_size)
        if not batch:
            time.sleep(0.5)
            continue

        ids = [row["__event_id"] for row in batch]

        for raw in batch:
            row = normalize_row_for_classifier(raw)
            prompt = build_prompt(row)
            result = query_llm(prompt, row)

            classification = result.get("classification", "UNKNOWN")
            confidence = result.get("confidence", "LOW")
            threat_intel = result.get("threat_intel_finding", "")
            reason = result.get("reason", "")

            row["AI__Model_classification"] = classification
            row["AI__Model_confidence"] = confidence
            row["AI__Threat_Intel_Finding"] = threat_intel
            row["AI__Model_Reason"] = reason

            # Publish ONLY MALICIOUS events
            if classification == "MALICIOUS":
                message = json.dumps(row, default=str)
                pub.send_string(message)
                logger.info(f"Published MALICIOUS event PID={row.get('pid')} process={row.get('process_name')}")

        delete_event_batch(args.db_file, ids)


if __name__ == "__main__":
    main()
