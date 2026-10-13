"""Fail-closed *toy-project only* guard for a PUBLIC GitHub Actions worker.

The guard is defense in depth against accidentally forwarding private source.
It cannot protect private code deliberately placed on a public runner.
"""

import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_FILES = frozenset({
    ".github/workflows/fixture.yml",
    ".github/workflows/security-review.yml",
    ".github/workflows/signature-probe.yml",
    ".gitignore",
    "CMakeLists.txt",
    "README.md",
    "SECURITY.md",
    "keys/pi-logs.agepub",
    "src/synthetic_adder.cpp",
    "tests/test_check_fixture.py",
    "tests/test_artifact_verification.py",
    "tests/test_public_guard.py",
    "tools/check_fixture.py",
    "tools/artifact_verification.py",
    "tools/install_age.py",
    "tools/pi_fixture_dispatch.py",
    "tools/public_guard.py",
    "tools/run_encrypted_fixture.py",
})

# Known benign toy program; no private source or arbitrary repositories.
PUBLIC_FIXTURE_HASHES = {
    "src/synthetic_adder.cpp": "23c233de65d78fff841c5e2f00deafc3c0a0e3a51a68d53c9fca0308d6463fa2",
    "CMakeLists.txt": "6644c79516314b982566d0099a395a603006942f70f7c0b15ca517b676c6f8f2",
    "keys/pi-logs.agepub": "6b537057a431a010a459b416a9befd50bdd7eb3b4f01afdaf570a93a671fc6e6",
}


def public_text_digest(data: bytes) -> str:
    """Hash equivalent Git text checkouts consistently on Unix and Windows."""
    if b"\r" in data.replace(b"\r\n", b""):
        raise ValueError("Unexpected bare carriage return in public toy source")
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def check_paths(paths: set[str]) -> None:
    unexpected = paths - ALLOWED_FILES
    required = {"src/synthetic_adder.cpp", "CMakeLists.txt", "keys/pi-logs.agepub"}
    if unexpected or not required.issubset(paths):
        raise ValueError("Source tree is not the approved public-only fixture")


def check_tree(root: Path) -> None:
    raw = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root,
        capture_output=True, check=True, timeout=15,
    ).stdout
    paths = {name.decode("utf-8") for name in raw.split(b"\0") if name}
    check_paths(paths)
    for name in paths:
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("Refusing tracked symlink or non-file")
        if path.stat().st_size > 200_000:
            raise ValueError("Unexpectedly large public fixture file")
    for name, expected in PUBLIC_FIXTURE_HASHES.items():
        if public_text_digest((root / name).read_bytes()) != expected:
            raise ValueError("Toy source hash changed; explicit review required")
    # Deliberately examine key files instead of hiding detected contents.
    key_content = (root / "keys/pi-logs.agepub").read_text().strip()
    if not re.fullmatch(r"age1[ac-hj-np-z02-9]{58}", key_content):
        raise ValueError("Only an age public recipient may be committed")
    if "PRIVATE KEY" in key_content.upper():
        raise ValueError("Private key must never be published")

    # Catch obvious accidental private-key material in documentation and the
    # public sample. This is not a complete secret scanner; GitHub push
    # protection and human review are separate mandatory controls.
    for name in ("README.md", "SECURITY.md", "src/synthetic_adder.cpp",
                 "CMakeLists.txt"):
        payload = (root / name).read_bytes()
        if b"\0" in payload or (b"AGE-" + b"SECRET-KEY-") in payload:
            raise ValueError("Public documentation/source contains secret-like material")
        if re.search(rb"-----BEGIN [A-Z ]{0,36}PRIVATE KEY-----", payload):
            raise ValueError("Public documentation/source contains key material")


def check_runner_context(environ: dict[str, str]) -> None:
    required = {
        "GITHUB_REPOSITORY": "SUAS-STEM/ci-relay-lab",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_ACTOR": "eschan145",
    }
    for variable, expected in required.items():
        if environ.get(variable) != expected:
            raise ValueError("Non-approved public-only Actions execution context")
    if not re.fullmatch(r"[0-9a-f]{40}", environ.get("GITHUB_SHA", "")):
        raise ValueError("Invalid public-only workflow commit")


def main() -> int:
    try:
        tree_only = sys.argv[1:] == ["--tree-only"]
        if sys.argv[1:] and not tree_only:
            raise ValueError("Unsupported guard arguments")
        if not tree_only:
            check_runner_context(os.environ)
        check_tree(ROOT)
        if not tree_only:
            sha = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=ROOT,
                check=True, text=True, capture_output=True, timeout=15,
            ).stdout.strip()
            if sha != os.environ["GITHUB_SHA"]:
                raise ValueError("Checked-out source does not match workflow SHA")
    except (ValueError, OSError, subprocess.SubprocessError):
        # Public GH logs should never disclose offending filenames or content.
        print("PUBLIC FIXTURE SECURITY GATE REJECTED INPUT", file=sys.stderr)
        return 1
    print("Public fixture guard passed; only pinned toy C++ source is permitted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
