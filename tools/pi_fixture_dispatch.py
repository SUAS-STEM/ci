"""Pi-side, manual synthetic GitHub Actions dispatch and result retrieval.

Only sends two validated numbers and a random trace ID. This does not read,
register with, or forward anything from a private repository.
"""

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import time

try:
    from .check_fixture import parse_request
except ImportError:
    from check_fixture import parse_request


REPO = "SUAS-STEM/ci-relay-lab"
WORKFLOW = "fixture.yml"
OUTPUT_FILE = Path(__file__).resolve().parents[1] / ".ci-relay-lab-last-run.json"
IDENTITY_FILE = Path.home() / ".config" / "ci-relay-lab" / "identity.txt"
AGE_EXE = Path(__file__).resolve().parents[1] / ".age-bin" / "age"
PUBLIC_KEY = Path(__file__).resolve().parents[1] / "keys" / "pi-logs.agepub"
PLATFORMS = ("ubuntu-24.04", "windows-2025")
MAX_ARTIFACT_BYTES = 20 * 1024 * 1024


def gh(*args: str) -> str:
    result = subprocess.run(
        ["gh", *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    return result.stdout


def locate_run(trace_id: str, expected_sha: str) -> int | None:
    runs = json.loads(gh(
        "run", "list", "--repo", REPO, "--workflow", WORKFLOW,
        "--limit", "50", "--json",
        "databaseId,displayTitle,event,headBranch,headSha",
    ))
    matches = [
        run for run in runs
        if run["displayTitle"] == f"fixture-{trace_id}"
        and run["event"] == "workflow_dispatch"
        and run["headBranch"] == "main"
    ]
    if len(matches) > 1:
        raise RuntimeError("Duplicate synthetic trace ID unexpectedly found")
    if not matches:
        return None
    if matches[0]["headSha"] != expected_sha:
        raise RuntimeError("Dispatched workflow ran unapproved source commit")
    return matches[0]["databaseId"]


def verify_local_key() -> None:
    """Fail if private identity is exposed or the public recipient is changed."""
    root = Path(__file__).resolve().parents[1]
    if not IDENTITY_FILE.is_file() or IDENTITY_FILE.is_symlink():
        raise RuntimeError("Missing regular Pi-only identity")
    if IDENTITY_FILE.parent.is_symlink():
        raise RuntimeError("Refusing symlinked Pi identity directory")
    st = IDENTITY_FILE.stat()
    parent = IDENTITY_FILE.parent.stat()
    if st.st_uid != os.getuid() or parent.st_uid != os.getuid():
        raise RuntimeError("Unexpected owner for Pi identity")
    if stat.S_IMODE(st.st_mode) != 0o600 or stat.S_IMODE(parent.st_mode) != 0o700:
        raise RuntimeError("Pi identity permissions must be 0600 in 0700 directory")
    if not PUBLIC_KEY.is_file() or PUBLIC_KEY.is_symlink():
        raise RuntimeError("Expected a regular pinned public recipient key")
    derived = subprocess.run(
        [str(AGE_EXE.parent / "age-keygen"), "-y", str(IDENTITY_FILE)],
        capture_output=True, text=True, check=True, timeout=15,
    ).stdout.strip()
    if not secrets.compare_digest(derived, PUBLIC_KEY.read_text().strip()):
        raise RuntimeError("Public recipient doesn't match Pi's private identity")


def validate_run_details(details: dict, expected_sha: str) -> None:
    if details.get("headSha") != expected_sha:
        raise RuntimeError("Completed workflow commit did not match dispatched commit")
    if details.get("event") != "workflow_dispatch" or details.get("headBranch") != "main":
        raise RuntimeError("Unrecognized run origin")
    jobs = details.get("jobs", [])
    if sorted(job["name"] for job in jobs) != sorted(PLATFORMS):
        raise RuntimeError("Missing, duplicated, or unexpected matrix job")


def retrieve_private_logs(run_id: int, trace_id: str, show: bool,
                          expected_sha: str, job_conclusions: dict) -> dict[str, str]:
    if not AGE_EXE.is_file():
        raise RuntimeError("Pi-only decryption identity or age utility is unavailable")
    verify_local_key()
    # This directory is ephemeral; decrypted logs are held only in memory.
    with tempfile.TemporaryDirectory(prefix="ci-relay-logs-") as directory:
        gh("run", "download", str(run_id), "--repo", REPO, "--dir", directory)
        private_logs = {}
        for platform in PLATFORMS:
            artifact = Path(directory) / f"encrypted-diagnostics-{platform}" / "encrypted-log.age"
            if not artifact.is_file():
                raise RuntimeError(f"Missing ciphertext artifact from {platform}")
            if artifact.is_symlink() or not 100 < artifact.stat().st_size <= MAX_ARTIFACT_BYTES:
                raise RuntimeError(f"Invalid encrypted artifact type/size for {platform}")
            decrypted = subprocess.run(
                [str(AGE_EXE), "--decrypt", "-i", str(IDENTITY_FILE), str(artifact)],
                check=True, capture_output=True, timeout=30,
            ).stdout.decode("utf-8", errors="replace")
            header = f"trace={trace_id}\ncommit={expected_sha}\nrun={run_id}\nplatform={platform}\n"
            if not decrypted.startswith(header):
                raise RuntimeError(f"Encrypted report provenance mismatch for {platform}")
            if job_conclusions.get(platform) == "success" and f"PASS trace={trace_id}" not in decrypted:
                raise RuntimeError(f"Successful job missing synthetic result: {platform}")
            if "=== Expected diagnostic failure (privacy test) (exit=47; expected=47) ===" not in decrypted:
                raise RuntimeError(f"Expected synthetic failure not captured for {platform}")
            canaries = re.findall(r"SYNTHETIC_CANARY_[0-9a-f]{40}", decrypted)
            if len(canaries) != 2 or canaries[0] != canaries[1]:
                raise RuntimeError(f"Encrypted canary invalid for {platform}")
            private_logs[platform] = decrypted

        # Checking public logs is part of the end-to-end privacy fixture. This
        # must not replace proper private CI isolation for sensitive workloads.
        publicly_visible = gh("run", "view", str(run_id), "--repo", REPO, "--log")
        for platform, body in private_logs.items():
            canary = re.search(r"SYNTHETIC_CANARY_[0-9a-f]{40}", body).group(0)
            if canary in publicly_visible or f"PASS trace={trace_id}" in publicly_visible:
                raise RuntimeError(f"PLAINTEXT FOUND IN PUBLIC WORKFLOW LOGS ({platform})")
        print("Verified synthetic canaries and test output are absent from public logs")

        if show:
            for platform, body in private_logs.items():
                print(f"\n--- Decrypted {platform} log (Pi only) ---\n{body}")
        return {platform: "decrypted and no public-canary leak detected"
                for platform in private_logs}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--left", default="17")
    parser.add_argument("--right", default="-3")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--show-logs", action="store_true",
                        help="Show decrypted diagnostic logs locally on Pi")
    args = parser.parse_args()

    trace_id = "test-" + secrets.token_hex(6)
    parse_request(trace_id, args.left, args.right)
    if not 30 <= args.timeout <= 3600:
        parser.error("--timeout must be 30 to 3600 seconds")

    verify_local_key()
    local_sha = subprocess.run(["git", "rev-parse", "HEAD"],
                               check=True, capture_output=True, text=True,
                               cwd=OUTPUT_FILE.parent).stdout.strip()
    remote_sha = gh("api", f"repos/{REPO}/git/ref/heads/main", "--jq", ".object.sha").strip()
    if local_sha != remote_sha:
        raise RuntimeError("Local test code isn't the current public main commit")

    print(f"Dispatching public-only synthetic fixture trace={trace_id}", flush=True)
    gh(
        "workflow", "run", WORKFLOW, "--repo", REPO, "--ref", "main",
        "-f", f"trace_id={trace_id}",
        "-f", f"left={args.left}", "-f", f"right={args.right}",
    )

    run_id = None
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        run_id = locate_run(trace_id, remote_sha)
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
            "--json", "status,conclusion,jobs,url,headSha,event,headBranch",
        ))
        if details["status"] == "completed":
            break
        time.sleep(8)

    validate_run_details(details, remote_sha)
    result = {
        "trace_id": trace_id,
        "repository": REPO,
        "run_id": run_id,
        "head_sha": remote_sha,
        "url": details.get("url"),
        "status": details.get("status"),
        "conclusion": details.get("conclusion"),
        "jobs": [
            {"name": job["name"], "conclusion": job.get("conclusion")}
            for job in details.get("jobs", [])
        ],
    }
    write_status(result)
    print(json.dumps(result, indent=2), flush=True)

    if details.get("status") == "completed":
        result["encrypted_logs"] = retrieve_private_logs(
            run_id, trace_id, args.show_logs, remote_sha,
            {job["name"]: job.get("conclusion") for job in details["jobs"]},
        )
        write_status(result)

    if details.get("status") != "completed":
        raise TimeoutError(f"Timed out waiting for run {run_id}; see {result['url']}")
    return 0 if details.get("conclusion") == "success" else 1


def write_status(result: dict) -> None:
    # Atomic, private local status; never a publicly uploaded artifact.
    path = OUTPUT_FILE.with_name(OUTPUT_FILE.name + ".tmp")
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)
    path.replace(OUTPUT_FILE)


if __name__ == "__main__":
    raise SystemExit(main())
