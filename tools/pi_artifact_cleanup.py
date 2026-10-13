"""Delete public GitHub transfer artifacts only after verified durable Pi storage.

Can be re-run after interruption: `python3 tools/pi_artifact_cleanup.py RUN_ID`.
This touches only two known synthetic ciphertext artifact IDs for that run.
It does not delete Actions jobs, logs, run records or Sigstore attestations.
"""

import argparse
import json

try:
    from .pi_artifact_store import (ARCHIVE_ROOT, PLATFORMS,
                                     read_verified_archive, record_github_cleanup)
except ImportError:
    from pi_artifact_store import (ARCHIVE_ROOT, PLATFORMS,
                                   read_verified_archive, record_github_cleanup)


REPO = "SUAS-STEM/ci-relay-lab"


def cleanup_github_artifacts(gh, root, run_id: int) -> dict:
    """Require intact, persisted local copies before any GitHub DELETE call."""
    manifest = read_verified_archive(root, run_id)
    expected = manifest["artifact_ids"]
    if set(expected) != set(PLATFORMS) or any(type(v) is not int or v <= 0 for v in expected.values()):
        raise RuntimeError("Unsafe stored GitHub artifact IDs")

    def remaining():
        catalog = json.loads(gh("api", f"repos/{REPO}/actions/runs/{run_id}/artifacts"))
        entries = catalog.get("artifacts", [])
        if not isinstance(entries, list):
            raise RuntimeError("Unexpected GitHub artifacts response")
        allowed = {f"encrypted-diagnostics-{p}": expected[p] for p in PLATFORMS}
        if len(entries) > len(allowed):
            raise RuntimeError("Unexpected additional public artifacts; refusing deletion")
        seen = set()
        for item in entries:
            if item.get("name") not in allowed or item.get("id") != allowed[item["name"]]:
                raise RuntimeError("Remote artifact does not match securely stored identity")
            if item["name"] in seen:
                raise RuntimeError("Duplicate remote artifact name")
            seen.add(item["name"])
        return entries

    for item in remaining():
        gh("api", "-X", "DELETE", f"repos/{REPO}/actions/artifacts/{item['id']}")
    if remaining():
        raise RuntimeError("GitHub still retains one or more encrypted artifacts")
    record_github_cleanup(root, run_id, expected)
    return {"run_id": run_id, "verified_on_pi": True,
            "github_artifacts_deleted": list(expected.values())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id", type=int)
    args = parser.parse_args()
    import subprocess

    def gh(*arguments):
        return subprocess.run(["gh", *arguments], check=True, text=True,
                              capture_output=True, timeout=45).stdout

    print(json.dumps(cleanup_github_artifacts(gh, ARCHIVE_ROOT, args.run_id), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
