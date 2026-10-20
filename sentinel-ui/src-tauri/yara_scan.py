
import json
import os
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import yara

RULES_DIR = Path(__file__).parent / "yara_rules"
RULE_FILES = sorted(
    list(RULES_DIR.glob("*.yar")) +
    list(RULES_DIR.glob("*.yara"))
)

WORKERS = min(4, max(1, (os.cpu_count() or 2) - 1))
FILE_TIMEOUT = 10


def report_progress(done, total, path):
    """Send machine-readable progress to stderr for the Rust parent."""
    print(
        json.dumps({
            "type": "progress",
            "done": done,
            "total": total,
            "path": str(path),
        }),
        file=sys.stderr,
        flush=True,
    )


def scan_file(rules, item):
    path = Path(item)

    try:
        matches = rules.match(str(path), timeout=FILE_TIMEOUT)

        detections = [
            {
                "path": str(path),
                "name": match.rule,
                "severity": str(match.meta.get("severity", "Medium")),
                "engine": "YARA",
            }
            for match in matches
        ]

        return detections

    except (OSError, yara.Error, ValueError) as exc:
        print(
            f"YARA warning: {path}: {exc}",
            file=sys.stderr,
            flush=True,
        )
        return []


def main():
    try:
        paths = json.loads(sys.stdin.read())

        if not isinstance(paths, list):
            raise ValueError("Expected a JSON array of file paths")

        if not RULE_FILES:
            print(json.dumps({
                "error": "No YARA rules found",
                "detections": [],
            }))
            return

        # Compile the rules only once per scan.
        rules = yara.compile(
            filepaths={
                f"rule_{i}": str(rule)
                for i, rule in enumerate(RULE_FILES)
            }
        )

        total = len(paths)
        detections = []

        if total == 0:
            print(json.dumps({"detections": []}))
            return

        # Report each completed file, regardless of whether it matched.
        with ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = {
                executor.submit(scan_file, rules, path): path
                for path in paths
            }

            done = 0

            for future in as_completed(futures):
                path = futures[future]

                try:
                    detections.extend(future.result())
                except Exception as exc:
                    print(
                        f"YARA worker warning: {path}: {exc}",
                        file=sys.stderr,
                        flush=True,
                    )

                done += 1
                report_progress(done, total, path)

        print(json.dumps({"detections": detections}), flush=True)

    except Exception as exc:
        print(
            json.dumps({
                "error": str(exc),
                "detections": [],
            }),
            flush=True,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
