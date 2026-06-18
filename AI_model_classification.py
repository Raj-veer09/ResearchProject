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
    pip install pandas anthropic

Usage:
    python AI_model_classification.py --input events.jsonl --clean-output clean_data.csv --output results.csv
    python AI_model_classification.py --test-only
"""

import os
import json
import argparse
import pandas as pd
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv() 

API_KEY =  os.getenv("ANTHROPIC_API_KEY")
client = Anthropic(api_key=API_KEY) if API_KEY else None


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
    process_by_pid = {}      # pid -> process record (latest seen)
    connections_by_pid = {}  # pid -> list of connection records

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

    # Build joined rows
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
        "pid"                  : pid,
        "process_name"         : clean_str(proc.get("Internal_Process_Name")),
        "process_owner"        : clean_str(proc.get("Internal_Process_Ownership")),
        "process_hash_sha256"  : clean_str(proc.get("Internal_Process_Hash")),
        "cert_status"          : clean_str(proc.get("Internal_Process_Certificate_status")),
        "thread_count"         : proc.get("Internal_Machine_Threads"),
        "parent_pid"           : proc.get("Internal_Process_Parent_PID"),
        "command_line"         : clean_str(proc.get("Internal_Process_CommandLine")),

        "has_connection"       : bool(conn),
        "network_protocol"          : clean_str(conn.get("Network_Protocol")),
        "network_connection_state"  : clean_str(conn.get("Network_Connection_State")),
        "network_out_process_ip"        : clean_str(conn.get("Network_Out_Process_IP")),
        "network_out_process_fqdn"      : clean_str(conn.get("Network_Out_Process_FQDN")),
        "network_out_process_dns"       : clean_str(conn.get("Network_Out_Process_DNS")),
        "network_out_process_port"      : conn.get("Network_Out_Process_Port"),
        "network_out_process_service"   : clean_str(conn.get("Network_Out_Process_Service")),
        "network_in_process_ip"         : clean_str(conn.get("Network_In_Process_IP")),
        "network_in_process_fqdn"       : clean_str(conn.get("Network_In_Process_FQDN")),
        "network_in_process_dns"        : clean_str(conn.get("Network_In_Process_DNS")),
        "network_in_process_port"       : conn.get("Network_In_Process_Port"),
        "network_in_process_service"    : clean_str(conn.get("Network_In_Process_Service")),

        "is_orphan_connection" : is_orphan_connection,
    }


def clean_str(val):
    if val is None:
        return None
    val = str(val).strip()
    return val if val else None


def _clean_dataframe(df):
    """Fill missing values, dedupe, and tidy types for tabular storage."""
    text_cols = ["process_name", "process_owner", "cert_status", "command_line",
                 "network_connection_state", "network_out_process_fqdn", "network_out_process_service", "network_in_process_service"]
    for c in text_cols:
        if c in df.columns:
            df[c] = df[c].fillna("unknown")

    num_cols = ["pid", "thread_count", "parent_pid", "network_out_process_port", "network_in_process_port"]
    for c in num_cols:
        if c in df.columns:
            df[c] = df[c].fillna(0).astype(int)

    df["process_hash_sha256"] = df["process_hash_sha256"].fillna("unknown")

    df = df.drop_duplicates(subset=["pid", "network_out_process_fqdn", "network_out_process_port", "network_connection_state"])
    df = df.sort_values(by=["pid"]).reset_index(drop=True)
    return df


# ─────────────────────────────────────────────────────────
# STEP 4: Build prompt — REQUIRE web search before classification
# ─────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a cybersecurity analyst for an endpoint intrusion detection system (IEPIS).
You will be given JOINED telemetry for one process and (if present) its associated network connection
from a monitored Windows/Linux endpoint.

NOTE: This table is built ONLY from "new_process" and "new_connection" events (i.e. things that just
appeared). "Ended" events are excluded since there is nothing new to classify when something stops.

MANDATORY PROCEDURE - follow these steps in order:

STEP 1 - VERIFY VIA WEB SEARCH (required, do not skip):
Before forming any opinion, you MUST use the web_search tool to check the provided indicators against
public threat intelligence sources. Specifically:
  - If a process_hash_sha256 is provided (not "unknown"), search for that exact SHA-256 hash to check
    if it is a known-malicious file (e.g. on VirusTotal, MalwareBazaar, or similar threat databases).
  - If an out_fqdn or IP address is provided (not "unknown"), search for that domain/IP to check its
    reputation (known C2 infrastructure, known-malicious, or known-benign/legitimate service).
  - If the process_name is a well-known legitimate tool (e.g. svchost.exe, Code.exe, mysqld.exe),
    you may search to confirm normal/expected behavior patterns for that tool.
  - If search results are inconclusive or return nothing, explicitly note that no threat intel match
    was found - this is still useful information (absence of a known-bad match lowers suspicion,
    but does NOT by itself guarantee benign-ness for unknown/novel threats).

STEP 2 - CLASSIFY based on BOTH the telemetry fields AND your search findings, using ONLY two labels:
- BENIGN: normal, expected activity, and/or threat intel confirms legitimacy, OR no strong evidence
  of malicious intent even if some details are unknown/unclear
- MALICIOUS: threat intel confirms a malicious indicator, OR the behavioral pattern is a well-known
  attack technique (e.g. encoded reverse-shell commands, connections to known C2 ports/infrastructure,
  unsigned binaries in staging locations combined with suspicious network behavior, orphan connections
  to known-bad destinations)

There is no third "uncertain" label. When evidence is genuinely weak or mixed, default to BENIGN and
say so plainly in your reason — but if multiple independent red flags align (e.g. unsigned + temp path
+ suspicious destination), classify MALICIOUS even without a direct threat-intel hash/IP match.

Rules:
1. Base your decision on the provided fields AND your web search findings - do not assume unprovided info.
2. If a field is "unknown", treat it as missing - do not assume the worst or best from absence alone.
3. is_orphan_connection = true means this network connection has no matching process record in this
   capture window (PID seen on the network side only) - treat this as an elevated-suspicion signal,
   since hidden/unassociated processes are a known evasion technique.
4. ALWAYS state in your reason whether a web search was performed and what (if anything) it found.
5. Respond ONLY in this exact JSON format as your FINAL message - no explanation outside the JSON:

{
  "classification": "BENIGN" | "MALICIOUS",
  "confidence": "LOW" | "MEDIUM" | "HIGH",
  "threat_intel_checked": true | false,
  "threat_intel_finding": "brief summary of what the web search found, or 'no match found'",
  "reason": "one to two concise sentences explaining the final decision"
}"""


def build_prompt(row):
    """Build a prompt from a joined row (process + optional connection)."""
    lines = [
        "Analyze this JOINED process + connection record (SHA-256 hash provided where available):",
        "",
        f"Process Name         : {row['process_name']}",
        f"PID                  : {row['pid']}",
        f"Owner                : {row['process_owner']}",
        f"Parent PID           : {row['parent_pid']}",
        f"Process Hash (SHA-256): {row['process_hash_sha256']}",
        f"Certificate Status   : {row['cert_status']}",
        f"Thread Count         : {row['thread_count']}",
        f"Command Line         : {row['command_line']}",
        "",
        f"Has Network Connection : {row['has_connection']}",
        f"Is Orphan Connection   : {row['is_orphan_connection']}  (PID seen on network but not in process records)",
        f"Connection State       : {row['network_connection_state']}",
        f"Outbound FQDN/IP       : {row['network_out_process_fqdn']}",
        f"Outbound Port          : {row['network_out_process_port']}",
        f"Outbound Service       : {row['network_out_process_service']}",
        f"Inbound Port           : {row['network_in_process_port']}",
        f"Inbound Service        : {row['network_in_process_service']}",
    ]
    return "\n".join(lines)


def query_llm(prompt):
    """
    Send one joined record to Claude with web_search enabled.
    Claude is required (via system prompt) to search before classifying.
    """
    if not client:
        return {"classification": "ERROR", "confidence": "LOW", "threat_intel_checked": False,
                "threat_intel_finding": "", "reason": "ANTHROPIC_API_KEY not set."}
    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1500,
            system=SYSTEM_PROMPT,
            tools=[{"type": "web_search_20250305", "name": "web_search"}],
            messages=[{"role": "user", "content": prompt}]
        )

        final_text = None
        for block in response.content:
            if block.type == "text":
                final_text = block.text

        if not final_text:
            return {"classification": "ERROR", "confidence": "LOW", "threat_intel_checked": False,
                     "threat_intel_finding": "", "reason": "No text response from model."}

        text = final_text.strip().replace("```json", "").replace("```", "").strip()

        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            text = text[start:end+1]

        return json.loads(text)

    except json.JSONDecodeError:
        return {"classification": "UNKNOWN", "confidence": "LOW", "threat_intel_checked": False,
                "threat_intel_finding": "", "reason": "LLM response was not valid JSON"}
    except Exception as e:
        return {"classification": "ERROR", "confidence": "LOW", "threat_intel_checked": False,
                "threat_intel_finding": "", "reason": str(e)}


# ─────────────────────────────────────────────────────────
# STEP 5: Classify all rows
# ─────────────────────────────────────────────────────────

def classify_dataframe(df):
    classifications, confidences, ti_checked, ti_findings, reasons = [], [], [], [], []

    total = len(df)
    for idx, row in df.iterrows():
        print(f"  [{idx+1}/{total}] PID {row['pid']} | {row['process_name']} -> searching + classifying...")
        prompt = build_prompt(row)
        result = query_llm(prompt)
        classifications.append(result.get("classification", "UNKNOWN"))
        confidences.append(result.get("confidence", "LOW"))
        ti_findings.append(result.get("threat_intel_finding", ""))
        reasons.append(result.get("reason", ""))

    df = df.copy()
    df["AI__Model_classification"]     = classifications
    df["AI__Model_confidence"]         = confidences
    df["AI__Threat_Intel_Finding"]   = ti_findings
    df["AI__Model_Reason"]             = reasons
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
            "network_connection_state": "ESTABLISHED", "network_out_process_fqdn": "lb-140-82-114-5-iad.github.com",
            "network_out_process_port": 443, "network_out_process_service": "https", "network_in_process_port": 54587, "network_in_process_service": "unknown"
        })
    },
    {
        "label": "PowerShell connecting to known Metasploit reverse-shell port on suspicious IP",
        "expected": "MALICIOUS",
        "row": pd.Series({
            "pid": 1234, "process_name": "powershell.exe", "process_owner": "unknown",
            "parent_pid": 0, "process_hash_sha256": "unknown", "cert_status": "unknown",
            "thread_count": 0, "command_line": "unknown",
            "has_connection": True, "is_orphan_connection": False,
            "network_connection_state": "ESTABLISHED", "network_out_process_fqdn": "185.220.101.45",
            "network_out_process_port": 4444, "network_out_process_service": "unknown", "network_in_process_port": 49200, "network_in_process_service": "unknown"
        })
    },
    {
        "label": "Normal system process svchost",
        "expected": "BENIGN",
        "row": pd.Series({
            "pid": 888, "process_name": "svchost.exe", "process_owner": "SYSTEM",
            "parent_pid": 640,
            "process_hash_sha256": "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
            "cert_status": "signed", "thread_count": 12,
            "command_line": "C:\\Windows\\System32\\svchost.exe -k NetworkService",
            "has_connection": False, "is_orphan_connection": False,
            "network_connection_state": "unknown", "network_out_process_fqdn": "unknown", "network_out_process_port": 0,
            "network_out_process_service": "unknown", "network_in_process_port": 0, "network_in_process_service": "unknown"
        })
    },
    {
        "label": "MySQL server listening on its standard port",
        "expected": "BENIGN",
        "row": pd.Series({
            "pid": 6272, "process_name": "mysqld.exe", "process_owner": "unknown",
            "parent_pid": 0, "process_hash_sha256": "unknown", "cert_status": "unknown",
            "thread_count": 0, "command_line": "unknown",
            "has_connection": True, "is_orphan_connection": False,
            "network_connection_state": "LISTEN", "network_out_process_fqdn": "unknown", "network_out_process_port": 0,
            "network_out_process_service": "unknown", "network_in_process_port": 3306, "network_in_process_service": "mysql"
        })
    },
    {
        "label": "Orphan connection - PID seen only on network side, connecting to Tor",
        "expected": "MALICIOUS",
        "row": pd.Series({
            "pid": 9999, "process_name": "unknown", "process_owner": "unknown",
            "parent_pid": 0, "process_hash_sha256": "unknown", "cert_status": "unknown",
            "thread_count": 0, "command_line": "unknown",
            "has_connection": True, "is_orphan_connection": True,
            "network_connection_state": "ESTABLISHED", "network_out_process_fqdn": "tor-exit-node.anonymizer.net",
            "network_out_process_port": 9001, "network_out_process_service": "unknown", "network_in_process_port": 55000, "network_in_process_service": "unknown"
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
        result = query_llm(prompt)
        got = result.get("classification", "UNKNOWN")
        expected = tc["expected"]
        ok = got == expected
        if ok:
            passed += 1

        print(f"\n[{i}] {tc['label']}")
        print(f"    Expected         : {expected}")
        print(f"    Got               : {got} ({result.get('confidence','?')} confidence)")
        print(f"    Threat intel used : {result.get('threat_intel_checked')}")
        print(f"    Finding           : {result.get('threat_intel_finding','')}")
        print(f"    Reason            : {result.get('reason','')}")
        print(f"    Status            : {'PASS' if ok else 'FAIL'}")

        results.append({"test_case": tc["label"], "expected": expected, "got": got, "pass": ok})

    accuracy = passed / len(TEST_CASES) * 100
    print(f"\n{'='*60}\nResults: {passed}/{len(TEST_CASES)} passed | Accuracy: {accuracy:.1f}%\n{'='*60}\n")
    return {"accuracy": accuracy, "passed": passed, "details": results}


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IEPIS LLM Classifier (joined + web-search-grounded)")
    parser.add_argument("--input", type=str, help="Input JSONL file from fig2_monitor.py")
    parser.add_argument("--clean-output", type=str, default="clean_data.csv",
                         help="Where to save the cleaned, joined tabular data")
    parser.add_argument("--output", type=str, default="results.csv", help="Output CSV with classifications")
    parser.add_argument("--test-only", action="store_true")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test_only:
        run_prompt_tests()
        return

    if not args.input:
        print("[ERROR] Provide --input events.jsonl or use --test-only")
        return

    print(f"\n[Step 1-2] Loading and joining: {args.input}")
    df = load_and_join(args.input)
    if df.empty:
        return

    print(f"[Step 1-2] {len(df)} joined rows "
          f"({df['has_connection'].sum()} with connections, "
          f"{df['is_orphan_connection'].sum()} orphan connections)")

    df.to_csv(args.clean_output, index=False)
    print(f"[Step 3] Clean joined data saved to: {args.clean_output}")
    print("\n[Step 3] Preview:")
    preview_cols = ["pid", "process_name", "cert_status", "has_connection",
                    "network_protocol", "network_out_process_ip",
                    "network_out_process_fqdn", "network_out_process_port",
                    "is_orphan_connection"]
    print(df[preview_cols].to_string(index=True))

    print(f"\n[Step 4-5] Classifying {len(df)} records via Claude (with web search)...")
    df = classify_dataframe(df)

    df.to_csv(args.output, index=False)
    print(f"\n[Step 5] Final classified results saved to: {args.output}")

    print("\n[Summary] Classification breakdown:")
    print(df["AI__Model_classification"].value_counts().to_string())

    print("\n[Summary] Suspicious/Malicious records:")
    flagged = df[df["AI__Model_classification"].isin(["MALICIOUS"])][
        ["pid","process_name","network_out_process_fqdn",
         "AI__Model_classification","AI__Threat_Intel_Finding","AI__Model_Reason"]
    ]
    print("  None found." if flagged.empty else flagged.to_string(index=False))

    if args.test:
        run_prompt_tests()


if __name__ == "__main__":
    main()