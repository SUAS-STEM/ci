"""Pi-side, manual synthetic GitHub Actions dispatch and result retrieval.

Only sends two validated numbers and a random trace ID. This does not read,
register with, or forward anything from a private repository.
"""

import argparse
import json
from pathlib import Path
import secrets
import subprocess
import time

from check_fixture import parse_request


REPO = "SUAS-STEM/ci-relay-lab"
WORKFLOW = "fixture.yml"
OUTPUT_FILE = Path(__file__).resolve().parents[1] / ".ci-relay-lab-last-run.json"


def gh(*args: str) -> str:
    result = subprocess.run(
        ["gh", *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    return result.stdout


def locate_run(trace_id: str) -> int | None:
    runs = json.loads(gh(
        "run", "list", "--repo", REPO, "--workflow", WORKFLOW,
        "--limit", "25", "--json", "databaseId,displayTitle,event,headBranch",
    ))
    matches = [
        run for run in runs
        if run["displayTitle"] == f"fixture-{trace_id}"
        and run["event"] == "workflow_dispatch"
        and run["headBranch"] == "main"
    ]
    if len(matches) > 1:
        raise RuntimeError("Duplicate synthetic trace ID unexpectedly found")
    return matches[0]["databaseId"] if matches else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--left", default="17")
    parser.add_argument("--right", default="-3")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--show-logs", action="store_true")
    args = parser.parse_args()

    trace_id = "test-" + secrets.token_hex(6)
    parse_request(trace_id, args.left, args.right)
    if not 30 <= args.timeout <= 3600:
        parser.error("--timeout must be 30 to 3600 seconds")

    print(f"Dispatching public-only synthetic fixture trace={trace_id}", flush=True)
    gh(
        "workflow", "run", WORKFLOW, "--repo", REPO, "--ref", "main",
        "-f", f"trace_id={trace_id}",
        "-f", f"left={args.left}", "-f", f"right={args.right}",
    )

    run_id = None
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        run_id = locate_run(trace_id)
        if run_id is not None:
            print(f"Run ID: {run_id}", flush=True)
            break
        time.sleep(5)
    if run_id is None:
        raise TimeoutError("Dispatched run not found by exact trace ID")

    details = {}
    while time.monotonic() < deadline:
        details = json.loads(gh(
            "run", "view", str(run_id), "--repo", REPO,
            "--json", "status,conclusion,jobs,url",
        ))
        if details["status"] == "completed":
            break
        time.sleep(8)

    result = {
        "trace_id": trace_id,
        "repository": REPO,
        "run_id": run_id,
        "url": details.get("url"),
        "status": details.get("status"),
        "conclusion": details.get("conclusion"),
        "jobs": [
            {"name": job["name"], "conclusion": job.get("conclusion")}
            for job in details.get("jobs", [])
        ],
    }
    OUTPUT_FILE.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)

    if args.show_logs and details.get("status") == "completed":
        lines = gh("run", "view", str(run_id), "--repo", REPO, "--log").splitlines()
        print(f"\n--- Public synthetic run logs (last {min(100, len(lines))} lines) ---")
        print("\n".join(lines[-100:]), flush=True)

    if details.get("status") != "completed":
        raise TimeoutError(f"Timed out waiting for run {run_id}; see {result['url']}")
    return 0 if details.get("conclusion") == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
