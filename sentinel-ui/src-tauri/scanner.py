import os
import hashlib
import json


# ============================================================
# CONFIG
# ============================================================

SIGNATURE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "signatures.json"
)


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

            file_path = os.path.join(
                root,
                filename
            )

            files.append(file_path)

    return files


# ============================================================
# SCAN FOLDER
# ============================================================

def scan_folder(folder):

    signatures = load_signatures()

    files = get_files(folder)

    results = []

    files_scanned = 0

    for file_path in files:

        file_hash = calculate_sha256(file_path)

        if file_hash:

            if file_hash in signatures:

                detection = signatures[file_hash]

                results.append({
                    "file": file_path,
                    "hash": file_hash,
                    "name": detection.get("name", "Unknown"),
                    "severity": detection.get("severity", "Unknown")
                })

        files_scanned += 1

    return {
        "files_scanned": files_scanned,
        "threats_found": len(results),
        "threats": results
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