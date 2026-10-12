import os
import json
import uuid
import sys
from datetime import datetime

import history


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Data lives outside the project folder so dev-server file watching
# doesn't reload the app every time the DB is written.
DATA_DIR = os.path.join(os.path.expanduser("~"), ".sentinel")
os.makedirs(DATA_DIR, exist_ok=True)

QUARANTINE_DB = os.path.join(DATA_DIR, "quarantine.json")


def load_db():
    if not os.path.exists(QUARANTINE_DB):
        return []
    try:
        with open(QUARANTINE_DB, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


def save_db(db):
    with open(QUARANTINE_DB, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=4)


def record_history(action, entry):
    try:
        history.add_event(
            action,
            entry.get("file_name", "Unknown"),
            entry.get("detection_name", "Unknown"),
            entry.get("severity", "Unknown"),
            entry.get("original_path", "")
        )
    except Exception:
        pass


def log_threat(file_path, detection):
    db = load_db()
    qid = str(uuid.uuid4())[:8]
    entry = {
        "id": qid,
        "original_path": file_path,
        "quarantine_path": file_path,
        "file_name": os.path.basename(file_path),
        "detection_name": detection.get("name", "Unknown"),
        "severity": detection.get("severity", "Unknown"),
        "hash": detection.get("hash", ""),
        "date": datetime.now().isoformat()
    }
    db.append(entry)
    save_db(db)
    return entry


def list_quarantine():
    return load_db()


def restore_file(qid):
    db = load_db()
    for i, entry in enumerate(db):
        if entry["id"] == qid:
            db.pop(i)
            save_db(db)
            record_history("restored", entry)
            return {"success": True, "message": "Cleared from quarantine log"}
    return {"success": False, "error": "Not found in quarantine log"}


def delete_file(qid):
    db = load_db()
    for i, entry in enumerate(db):
        if entry["id"] == qid:
            db.pop(i)
            save_db(db)
            record_history("deleted", entry)
            return {"success": True, "message": "Removed from quarantine log"}
    return {"success": False, "error": "Not found in quarantine log"}


def delete_all():
    db = load_db()
    for entry in db:
        record_history("deleted", entry)
    count = len(db)
    save_db([])
    return {"success": True, "deleted": count, "errors": []}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: quarantine.py <command> [args]"}))
        sys.exit(1)

    command = sys.argv[1]

    if command == "log":
        if len(sys.argv) < 4:
            print(json.dumps({"error": "Usage: quarantine.py log <file_path> <detection_json>"}))
            sys.exit(1)
        file_path = sys.argv[2]
        detection = json.loads(sys.argv[3])
        print(json.dumps(log_threat(file_path, detection)))

    elif command == "list":
        print(json.dumps(list_quarantine()))

    elif command == "restore":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "No quarantine ID provided"}))
            sys.exit(1)
        print(json.dumps(restore_file(sys.argv[2])))

    elif command == "delete":
        if len(sys.argv) < 3:
            print(json.dumps({"error": "No quarantine ID provided"}))
            sys.exit(1)
        print(json.dumps(delete_file(sys.argv[2])))

    elif command == "delete-all":
        print(json.dumps(delete_all()))

    else:
        print(json.dumps({"error": f"Unknown command: {command}"}))
        sys.exit(1)