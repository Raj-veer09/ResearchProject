import json
import os
import time
import pandas as pd
import argparse


def process_line_to_csv(line, proc_csv, conn_csv):
    """Parses a single JSON line and appends it directly to the appropriate CSV."""
    if not line.strip():
        return

    try:
        record = json.loads(line)
        event_type = record.get("event")

        # Flatten the data payload
        row = {
            "Timestamp": record.get("timestamp"),
            "Event_Type": event_type
        }
        row.update(record.get("data", {}))

        # Convert the single row to a DataFrame
        df = pd.DataFrame([row])

        # Route and append directly to the CSV
        if event_type in ["new_process", "process_ended"]:
            # mode='a' appends to the file instead of overwriting it
            # header=not os.path.exists checks if the file is new so it only writes headers once
            df.to_csv(proc_csv, mode='a', header=not os.path.exists(proc_csv), index=False)

        elif event_type in ["new_connection", "connection_ended"]:
            df.to_csv(conn_csv, mode='a', header=not os.path.exists(conn_csv), index=False)

    except json.JSONDecodeError:
        pass


def live_tail_and_extract(input_file):
    """Continuously listens to the JSONL file and processes new lines as they appear."""
    proc_csv = "processes_table.csv"
    conn_csv = "connections_table.csv"

    print(f"Listening to '{input_file}' for live events...")
    print(f"Data will be continuously appended to '{proc_csv}' and '{conn_csv}'.")
    print("Press Ctrl+C to stop.\n")

    # Open the file in read mode
    with open(input_file, 'r') as f:
        while True:
            # Attempt to read a new line
            line = f.readline()

            if not line:
                # If there is no new line, the script sleeps for half a second
                # This prevents it from consuming 100% of your CPU while waiting
                time.sleep(0.5)
                continue

            # If a line exists, process it and print a quick status update to the terminal
            process_line_to_csv(line, proc_csv, conn_csv)

            event_name = json.loads(line).get('event')
            timestamp = json.loads(line).get('timestamp')
            print(f"[LIVE UPDATE] Added '{event_name}' at {timestamp}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live JSONL to CSV Extractor")
    parser.add_argument("--input", type=str, default="events.jsonl", help="Path to the JSONL input file")
    args = parser.parse_args()

    # If the monitor script hasn't created the file yet, wait patiently for it
    if not os.path.exists(args.input):
        print(f"Waiting for '{args.input}' to be created by the monitor script...")
        while not os.path.exists(args.input):
            time.sleep(1)

    try:
        live_tail_and_extract(args.input)
    except KeyboardInterrupt:
        print("\nLive extraction stopped by user.")