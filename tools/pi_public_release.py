"""Pi-only: public synthetic encrypted CI -> PRIVATE GitHub Release.

No Actions artifacts, no public runner credentials for the private repository,
and no confidential source. The PUBLIC job log temporarily carries ciphertext.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

from .ephemeral_age import ephemeral_identity
from .binary_envelope import unwrap_binary
from .log_transport import parse_job_log
from .check_fixture import parse_request
from .pi_fixture_dispatch import check_decrypted_report_binding

PUBLIC_REPO = "SUAS-STEM/ci-relay-lab"
PRIVATE_REPO = "SUAS-STEM/ci-release-vault"
WORKFLOW = "fixture.yml"
TEST_WORKFLOW = "temporary-public-log-test.yml"
TEST_BRANCH = "security/signed-artifact-provenance"
AGE = Path(__file__).resolve().parents[1] / ".age-bin" / "age"
PLATFORMS = ("ubuntu-24.04", "windows-2025")
ASSETS = {"ubuntu-24.04": "linux-x86_64-synthetic_adder",
          "windows-2025": "windows-x86_64-synthetic_adder.exe"}


def gh(*args):
    p = subprocess.run(["gh", *args], check=True, capture_output=True,
                       timeout=90)
    return p.stdout.decode("utf-8-sig", errors="strict").strip()


def github_job_log(job_id: int) -> str:
    p = subprocess.run(["gh", "api", "--allow-escape-sequences",
                        f"repos/{PUBLIC_REPO}/actions/jobs/{job_id}/logs"],
                       check=True, capture_output=True, timeout=90)
    if len(p.stdout) > 4_000_000:
        raise RuntimeError("Encrypted job log exceeds safe transfer limit")
    return p.stdout.decode("utf-8-sig")


def decrypt(identity, ciphertext: bytes) -> bytes:
    return subprocess.run(
        [str(AGE), "-d", "-i", identity.identity_path],
        input=ciphertext, capture_output=True, check=True, timeout=30,
        pass_fds=(identity.fd,),
    ).stdout


def validate_job(run_id: int, source_sha: str, branch: str, workflow: str):
    run = json.loads(gh("api", f"repos/{PUBLIC_REPO}/actions/runs/{run_id}"))
    if (run.get("head_sha") != source_sha or run.get("head_branch") != branch
            or run.get("event") != "workflow_dispatch"
            or run.get("path") != ".github/workflows/" + workflow
            or run.get("actor", {}).get("login") != "eschan145"
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run.get("repository", {}).get("full_name") != PUBLIC_REPO
            or run.get("run_attempt") != 1):
        raise RuntimeError("Public CI result was not from the approved successful workflow")
    jobs = json.loads(gh("api", f"repos/{PUBLIC_REPO}/actions/runs/{run_id}/jobs?per_page=100"))
    listed = jobs.get("jobs")
    if not isinstance(listed, list) or len(listed) != 2 or {j["name"] for j in listed} != set(PLATFORMS):
        raise RuntimeError("Unexpected Windows/Linux CI job set")
    if any(j.get("conclusion") != "success" or j.get("status") != "completed" for j in listed):
        raise RuntimeError("A CI platform failed")
    return run, {j["name"]: j["id"] for j in listed}


def publish_from_logs(identity, trace: str, run_id: int, source_sha: str,
                      test_branch: bool = False):
    branch = TEST_BRANCH if test_branch else "main"
    workflow = TEST_WORKFLOW if test_branch else WORKFLOW
    run, jobs = validate_job(run_id, source_sha, branch, workflow)

    binaries = {}
    checksums = {}
    for platform, job_id in jobs.items():
        public_log = github_job_log(job_id)
        ciphertexts = parse_job_log(public_log, platform)
        report = decrypt(identity, ciphertexts["log"]).decode("utf-8", errors="strict")
        check_decrypted_report_binding(
            report, trace, source_sha, run_id, platform, identity.recipient_digest,
        )
        if (f"PASS trace={trace}" not in report
                or "Expected diagnostic failure (privacy test) (exit=47; expected=47)" not in report):
            raise RuntimeError("Encrypted synthetic run did not verify")
        canaries = re.findall(r"SYNTHETIC_CANARY_[0-9a-f]{40}", report)
        if len(canaries) != 2 or canaries[0] != canaries[1]:
            raise RuntimeError("Encrypted synthetic canary was missing")
        if canaries[0] in public_log or f"PASS trace={trace}" in public_log:
            raise RuntimeError("Unexpected plaintext test output in public logs")
        envelope = decrypt(identity, ciphertexts["binary"])
        binary = unwrap_binary(envelope, trace, source_sha, run_id,
                               platform, identity.recipient_digest)
        if binary is None or not 1024 < len(binary) < 8_000_000:
            raise RuntimeError("CI did not produce a compiled executable")
        if not binary.startswith(b"MZ" if platform == "windows-2025" else b"\x7fELF"):
            raise RuntimeError("Compiled synthetic executable has incorrect format")
        binaries[ASSETS[platform]] = binary
        checksums[ASSETS[platform]] = hashlib.sha256(binary).hexdigest()

    repo = json.loads(gh("repo", "view", PRIVATE_REPO, "--json", "isPrivate"))
    if repo.get("isPrivate") is not True:
        raise RuntimeError("Refusing to publish into a public release repository")
    tag = f"ci-public{'-test' if test_branch else ''}-{run_id}-1"
    notes = (
        "PUBLIC SYNTHETIC ENCRYPTED CI -- no proprietary source.\n"
        f"source-repo={PUBLIC_REPO}\nsource-commit={source_sha}\n"
        f"source-run={run_id}\nsource-attempt=1\n"
        f"source-workflow=.github/workflows/{workflow}\n"
    )
    with tempfile.TemporaryDirectory(prefix="ci-private-release-", dir="/tmp") as folder:
        output = Path(folder)
        os.chmod(output, 0o700)
        for name, data in binaries.items():
            (output / name).write_bytes(data)
            (output / (name + ".sha256")).write_text(
                checksums[name] + "  " + name + "\n", encoding="ascii"
            )
        for item in output.iterdir():
            item.chmod(0o600)
        # The Pi's GitHub auth stays on Pi. Do not give it to any public job.
        gh("release", "create", tag, "--repo", PRIVATE_REPO, "--target", "main",
           "--draft", "--latest=false", "--title", f"Public encrypted CI {run_id}",
           "--notes", notes)
        gh("release", "upload", tag, "--repo", PRIVATE_REPO,
           *(str(item) for item in sorted(output.iterdir())))
        retrieved = output / "checked"
        retrieved.mkdir(mode=0o700)
        gh("release", "download", tag, "--repo", PRIVATE_REPO, "--dir", str(retrieved))
        for name, digest in checksums.items():
            if hashlib.sha256((retrieved / name).read_bytes()).hexdigest() != digest:
                raise RuntimeError("Private GitHub release download mismatched original build")
        gh("release", "edit", tag, "--repo", PRIVATE_REPO,
           "--draft=false", "--latest=false")
    # Protected private release retained. A separate tested command stores a
    # permanent copy on Pi; do not delete the private GitHub Release.
    print(f"PRIVATE_RELEASE_OK https://github.com/{PRIVATE_REPO}/releases/tag/{tag}", flush=True)
    return tag


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--left", default="17")
    parser.add_argument("--right", default="-3")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    import secrets
    trace = "test-" + secrets.token_hex(6)
    parse_request(trace, args.left, args.right)
    if not 60 <= args.timeout <= 1800:
        parser.error("timeout out of range")
    with ephemeral_identity() as identity:
        source_sha = gh("api", f"repos/{PUBLIC_REPO}/git/ref/heads/main",
                        "--jq", ".object.sha")
        gh("workflow", "run", WORKFLOW, "--repo", PUBLIC_REPO, "--ref", "main",
           "-f", f"trace_id={trace}", "-f", f"left={args.left}",
           "-f", f"right={args.right}", "-f", f"age_recipient={identity.recipient}")
        deadline = time.monotonic() + args.timeout
        run_id = None
        while time.monotonic() < deadline:
            runs = json.loads(gh("run", "list", "--repo", PUBLIC_REPO,
                                 "--workflow", WORKFLOW, "--limit", "30",
                                 "--json", "databaseId,displayTitle,headSha"))
            matches = [r for r in runs if r["displayTitle"] == f"fixture-{trace}"
                       and r["headSha"] == source_sha]
            if len(matches) == 1:
                run_id = matches[0]["databaseId"]
                break
            if len(matches) > 1:
                raise RuntimeError("Duplicate public CI trace")
            time.sleep(5)
        if run_id is None:
            raise TimeoutError("Public CI run not discovered")
        while time.monotonic() < deadline:
            info = json.loads(gh("api", f"repos/{PUBLIC_REPO}/actions/runs/{run_id}"))
            if info["status"] == "completed":
                break
            time.sleep(8)
        tag = publish_from_logs(identity, trace, run_id, source_sha)
        print(f"Build and encrypted delivery succeeded: {tag}")


if __name__ == "__main__":
    main()
