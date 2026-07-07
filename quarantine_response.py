"""
IEPIS - Quarantine & Alert Response Module
-------------------------------------------
Add-on module.

Policy:
- MALICIOUS + HIGH confidence
    -> attempt to terminate the offending process (if still running)
       and move/rename its executable into a quarantine folder.
- MALICIOUS + LOW or MEDIUM confidence
    -> raise a user-facing alert (console + log + optional desktop
       notification). No file/process action is taken.
- Anything else (BENIGN, ERROR, UNKNOWN, etc.)
    -> no-op.

Usage (inside AI_model_classification.py):

    from quarantine_response import handle_response

    result = query_llm(prompt, row)
    handle_response(row, result)   # <-- new line

Dependencies:
    pip install psutil
    pip install win10toast   # optional, Windows desktop notifications only
"""

import os
import shutil
import time
import logging
import platform
import datetime

import psutil

OS_PLATFORM = platform.system()

# ----------------------------------------------------------
# Configuration
# ----------------------------------------------------------
QUARANTINE_DIR = os.path.join(os.getcwd(), "quarantine")
ALERT_LOG_PATH = os.path.join(os.getcwd(), "iepis_alerts.log")

# Set to False if you'd rather quarantine the file without trying to
# kill the process first (not recommended — the file is often locked
# by the running process and the move will fail).
TERMINATE_BEFORE_QUARANTINE = False

os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Dedicated logger — separate from the "IEPIS" logger already
# configured in AI_model_classification.py, so we don't touch that
# logging setup at all.
response_logger = logging.getLogger("IEPIS.Response")
if not response_logger.handlers:
    _handler = logging.FileHandler(ALERT_LOG_PATH)
    _handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    response_logger.addHandler(_handler)
    response_logger.setLevel(logging.INFO)
    response_logger.propagate = False


# ─────────────────────────────────────────────────────────
# Process termination
# ─────────────────────────────────────────────────────────
def _try_terminate_process(pid: int, timeout: float = 3.0) -> bool:
    """Gracefully terminate, then force-kill, a running process by PID."""
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except psutil.TimeoutExpired:
            proc.kill()
        response_logger.info(f"Terminated PID {pid}.")
        return True
    except psutil.NoSuchProcess:
        return True  # already gone, nothing to do
    except Exception as e:
        response_logger.warning(f"Could not terminate PID {pid}: {e}")
        return False


# ─────────────────────────────────────────────────────────
# File quarantine
# ─────────────────────────────────────────────────────────
def _quarantine_file(exe_path: str, pid, process_name: str) -> str | None:
    """
    Move the executable into QUARANTINE_DIR with a timestamped,
    defanged filename (.locked suffix) so it can't be accidentally
    re-launched by double-click / extension association.
    """
    if not exe_path or exe_path == "unknown" or not os.path.isfile(exe_path):
        response_logger.warning(
            f"Quarantine skipped for PID {pid} ({process_name}): "
            f"executable path unavailable or not found ('{exe_path}')."
        )
        return None

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    original_name = os.path.basename(exe_path)
    quarantined_name = f"QUARANTINED_{timestamp}_{original_name}.locked"
    dest_path = os.path.join(QUARANTINE_DIR, quarantined_name)

    def _attempt_move():
        shutil.move(exe_path, dest_path)
        response_logger.info(
            f"Quarantined file: '{exe_path}' -> '{dest_path}' (PID {pid}, {process_name})"
        )
        return dest_path

    try:
        return _attempt_move()
    except PermissionError:
        # File may still be locked briefly after process termination.
        time.sleep(1.5)
        try:
            return _attempt_move()
        except Exception as e:
            response_logger.error(
                f"Failed to quarantine '{exe_path}' for PID {pid} ({process_name}): {e}"
            )
            return None
    except Exception as e:
        response_logger.error(
            f"Failed to quarantine '{exe_path}' for PID {pid} ({process_name}): {e}"
        )
        return None


# ─────────────────────────────────────────────────────────
# User-facing alerting (LOW / MEDIUM confidence)
# ─────────────────────────────────────────────────────────
def _send_alert(row, result):
    pid = row.get("pid", "unknown")
    process_name = row.get("process_name", "unknown")
    confidence = result.get("confidence", "UNKNOWN")
    reason = result.get("reason", "") or ""
    fqdn = row.get("network_out_process_fqdn", "unknown")
    ip = row.get("network_out_process_ip", "unknown")

    message = (
        f"[IEPIS ALERT] Possible malicious activity detected (confidence={confidence})\n"
        f"  Process : {process_name} (PID {pid})\n"
        f"  Target  : {fqdn} ({ip})\n"
        f"  Reason  : {reason[:200]}"
    )

    print("\n" + "!" * 60)
    print(message)
    print("!" * 60 + "\n")

    response_logger.info(message.replace("\n", " | "))

    # Best-effort desktop notification — never fatal if unavailable.
    try:
        if OS_PLATFORM == "Windows":
            from win10toast import ToastNotifier
            ToastNotifier().show_toast(
                "IEPIS Alert",
                f"Suspicious process: {process_name} (PID {pid}) - confidence {confidence}",
                duration=10,
                threaded=True,
            )
        elif OS_PLATFORM == "Darwin":
            os.system(
                f'osascript -e \'display notification "{process_name} (PID {pid})" '
                f'with title "IEPIS Alert - {confidence} confidence"\''
            )
        elif OS_PLATFORM == "Linux":
            os.system(
                f'notify-send "IEPIS Alert ({confidence} confidence)" '
                f'"Suspicious process: {process_name} (PID {pid})"'
            )
    except Exception as e:
        response_logger.debug(f"Desktop notification unavailable: {e}")


# ─────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────
def handle_response(row, result):
    """
    Call once per classified row, immediately after query_llm() returns.

    MALICIOUS + HIGH        -> terminate process (optional) + quarantine file
    MALICIOUS + LOW/MEDIUM  -> alert only
    everything else         -> no-op
    """
    classification = str(result.get("classification", "")).upper()
    confidence = str(result.get("confidence", "")).upper()

    if classification != "MALICIOUS":
        return

    pid = row.get("pid")
    exe_path = row.get("process_executable_path")
    process_name = row.get("process_name", "unknown")

    if confidence == "HIGH":
        response_logger.info(
            f"HIGH-confidence MALICIOUS verdict for PID {pid} ({process_name}). "
            f"Initiating quarantine."
        )

        if TERMINATE_BEFORE_QUARANTINE and pid:
            try:
                _try_terminate_process(int(pid))
            except (TypeError, ValueError):
                pass

        dest = _quarantine_file(exe_path, pid, process_name)

        if dest:
            print(f"[IEPIS] Quarantined '{process_name}' (PID {pid}) -> {dest}")
        else:
            print(
                f"[IEPIS] WARNING: Could not quarantine '{process_name}' (PID {pid}); "
                f"falling back to alert."
            )
            _send_alert(row, result)

    elif confidence in ("LOW", "MEDIUM"):
        _send_alert(row, result)

    else:
        # MALICIOUS but confidence missing/unrecognized — err toward alerting.
        response_logger.warning(
            f"MALICIOUS verdict for PID {pid} ({process_name}) with "
            f"unrecognized confidence '{confidence}'. Alerting."
        )
        _send_alert(row, result)