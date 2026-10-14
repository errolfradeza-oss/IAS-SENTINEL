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
QUARANTINE_FILE = os.path.join(BASE_DIR, "quarantine.py")


# ============================================================
# SIGNATURE DATABASE
# ============================================================

def load_signatures():
    try:
        with open(SIGNATURE_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        return data.get("signatures", {})

    except (FileNotFoundError, json.JSONDecodeError) as error:
        print(
            f"Signature database error: {error}",
            file=sys.stderr
        )
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


def get_files(path, scan_errors=None):
    if scan_errors is None:
        scan_errors = []

    path = os.path.abspath(path)

    # If the selected path is an individual file
    if os.path.isfile(path):
        return [path]

    # If the selected path is a folder
    if os.path.isdir(path):
        files = []

        def handle_error(error):
            scan_errors.append(str(error))

        for root, dirs, filenames in os.walk(
            path,
            onerror=handle_error,
            followlinks=False
        ):
            # Avoid following directory symlinks
            dirs[:] = [
                directory for directory in dirs
                if not os.path.islink(os.path.join(root, directory))
            ]

            for filename in filenames:
                file_path = os.path.join(root, filename)

                if os.path.isfile(file_path):
                    files.append(file_path)

        return files

    raise FileNotFoundError(
        f"Selected file or folder does not exist: {path}"
    )



# ============================================================
# LOG THREAT TO QUARANTINE.PY
# ============================================================

def log_threat(file_path, detection):
    try:
        result = subprocess.run(
            [
                sys.executable,
                QUARANTINE_FILE,
                "log",
                file_path,
                json.dumps(detection)
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return {
                "error": result.stderr.strip()
                or "quarantine.py failed"
            }

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {
                "error": "Invalid JSON returned by quarantine.py"
            }

    except (OSError, subprocess.TimeoutExpired) as error:
        return {"error": str(error)}


# ============================================================
# SCAN FILE OR FOLDER
# ============================================================

def scan_path(path):
    path = os.path.abspath(os.path.expanduser(path))

    if not os.path.isfile(path) and not os.path.isdir(path):
        raise FileNotFoundError(
            f"File or folder not found: {path}"
        )

    signatures = load_signatures()
    files = get_files(path)

    results = []
    logged = []

    files_scanned = 0
    files_skipped = 0

    for file_path in files:
        file_hash = calculate_sha256(file_path)

        if file_hash is None:
            files_skipped += 1
            continue

        files_scanned += 1

        if file_hash not in signatures:
            continue

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

        quarantine_result = log_threat(
            file_path,
            detection_copy
        )

        if "error" not in quarantine_result:
            logged.append(quarantine_result)
        else:
            threat_info["log_error"] = quarantine_result["error"]

    return {
        "scan_path": path,
        "scan_type": "file" if os.path.isfile(path) else "folder",
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "threats_found": len(results),
        "threats": results,
        "quarantined": logged
    }


# ============================================================
# COMMAND LINE ENTRY POINT
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            json.dumps({
                "error": "A file or folder path is required."
            })
        )
        sys.exit(1)

    try:
        result = scan_path(sys.argv[1])
        print(json.dumps(result, indent=4))

    except (FileNotFoundError, OSError) as error:
        print(
            json.dumps({"error": str(error)}),
            file=sys.stderr
        )
        sys.exit(1)