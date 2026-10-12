import os
import json
import uuid
import sys
from datetime import datetime


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Data lives outside the project folder so dev-server file watching
# doesn't reload the app every time the DB is written.
DATA_DIR = os.path.join(os.path.expanduser("~"), ".sentinel")
os.makedirs(DATA_DIR, exist_ok=True)

HISTORY_DB = os.path.join(DATA_DIR, "history.json")


# ============================================================
# STORAGE
# ============================================================

def load_history():
    if not os.path.exists(HISTORY_DB):
        return []
    try:
        with open(HISTORY_DB, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


def save_history(history):
    with open(HISTORY_DB, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=4)


# ============================================================
# EVENTS
# ============================================================

def add_event(action, file_name, detection_name, severity, original_path):
    history = load_history()
    event = {
        "id": str(uuid.uuid4())[:8],
        "action": action,                  # "restored" or "deleted"
        "file_name": file_name,
        "detection_name": detection_name,
        "severity": severity,
        "original_path": original_path,
        "date": datetime.now().isoformat()
    }
    history.insert(0, event)              # newest first
    save_history(history)
    return event


def list_history():
    return load_history()


def clear_history():
    count = len(load_history())
    save_history([])
    return {"success": True, "cleared": count}


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: history.py <command> [args]"}))
        sys.exit(1)

    command = sys.argv[1]

    if command == "add":
        if len(sys.argv) < 7:
            print(json.dumps({
                "error": "Usage: history.py add <action> <file_name> <detection_name> <severity> <original_path>"
            }))
            sys.exit(1)
        print(json.dumps(add_event(
            action=sys.argv[2],
            file_name=sys.argv[3],
            detection_name=sys.argv[4],
            severity=sys.argv[5],
            original_path=sys.argv[6]
        )))

    elif command == "list":
        print(json.dumps(list_history()))

    elif command == "clear":
        print(json.dumps(clear_history()))

    else:
        print(json.dumps({"error": f"Unknown command: {command}"}))
        sys.exit(1)
