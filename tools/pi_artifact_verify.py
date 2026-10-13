"""Audit all permanent Pi CI archives without GitHub or decryption keys.

Run after crashes or periodically to detect accidental corruption and report
incomplete GitHub cleanup. This tool never executes binaries or deletes files.
"""

import argparse
import json
from pathlib import Path
import re

try:
    from .pi_artifact_store import ARCHIVE_ROOT, _private_dir, read_verified_archive
except ImportError:
    from pi_artifact_store import ARCHIVE_ROOT, _private_dir, read_verified_archive


def verify_all_archives(root: Path) -> dict:
    _private_dir(root.parent)
    _private_dir(root)
    verified = []
    corrupt = []
    cleanup_needed = []
    partial_stages = []
    bytes_verified = 0
    for item in sorted(root.iterdir()):
        match = re.fullmatch(r"run-([1-9][0-9]*)", item.name)
        if match:
            run_id = int(match.group(1))
            try:
                manifest = read_verified_archive(root, run_id)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError, json.JSONDecodeError):
                corrupt.append(run_id)
                continue
            verified.append(run_id)
            bytes_verified += sum(entry["bytes"] for entry in manifest["files"].values())
            if not (item / "github-cleanup.json").exists():
                cleanup_needed.append(run_id)
        elif re.fullmatch(r"\.stage-[1-9][0-9]*-[A-Za-z0-9_-]+", item.name):
            partial_stages.append(item.name)
    return {
        "verified_runs": verified,
        "corrupt_runs": corrupt,
        "github_cleanup_pending": cleanup_needed,
        "incomplete_staging_directories": partial_stages,
        "bytes_verified": bytes_verified,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    result = verify_all_archives(ARCHIVE_ROOT)
    print(json.dumps(result, indent=2))
    return 1 if result["corrupt_runs"] or result["incomplete_staging_directories"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
