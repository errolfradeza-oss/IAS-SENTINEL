import os
import hashlib
import json
import subprocess
import sys


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SIGNATURE_FILE = os.path.join(BASE_DIR, "signatures.json")


# ============================================================
# SIGNATURE DATABASE
# ============================================================

def load_signatures():
    try:
        with open(SIGNATURE_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
        return data.get("signatures", {})
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}


# ============================================================
# HASHING
# ============================================================

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(1024 * 1024)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError):
        return None


# ============================================================
# GET FILES
# ============================================================

def get_files(folder):
    files = []
    for root, directories, filenames in os.walk(folder):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            files.append(file_path)
    return files


# ============================================================
# LOG THREAT TO QUARANTINE.PY
# ============================================================

def log_threat(file_path, detection):
    try:
        result = subprocess.run(
            [
                sys.executable,
                os.path.join(BASE_DIR, "quarantine.py"),
                "log",
                file_path,
                json.dumps(detection)
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            return {"error": result.stderr or "quarantine.py failed"}
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# SCAN FOLDER
# ============================================================

def scan_folder(folder):
    signatures = load_signatures()
    files = get_files(folder)

    results = []
    logged = []

    files_scanned = 0

    for file_path in files:
        file_hash = calculate_sha256(file_path)

        if file_hash:
            if file_hash in signatures:
                detection = signatures[file_hash]

                threat_info = {
                    "file": file_path,
                    "hash": file_hash,
                    "name": detection.get("name", "Unknown"),
                    "severity": detection.get("severity", "Unknown")
                }
                results.append(threat_info)

                detection_copy = detection.copy()
                detection_copy["hash"] = file_hash
                q_result = log_threat(file_path, detection_copy)

                if "error" not in q_result:
                    logged.append(q_result)
                else:
                    threat_info["log_error"] = q_result["error"]

        files_scanned += 1

    return {
        "files_scanned": files_scanned,
        "threats_found": len(results),
        "threats": results,
        "quarantined": logged
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("python scanner.py <folder>")
        sys.exit(1)

    folder = sys.argv[1]
    result = scan_folder(folder)
    print(json.dumps(result, indent=4))