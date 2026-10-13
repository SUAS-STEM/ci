"""Verify signed provenance before Pi decryption of synthetic CI artifacts."""

import hashlib
import json
from pathlib import Path
import re


REPO = "SUAS-STEM/ci-relay-lab"
SIGNER = REPO + "/.github/workflows/fixture.yml"
MAX_BYTES = 20 * 1024 * 1024
PLATFORMS = ("ubuntu-24.04", "windows-2025")


def validate_catalog(catalog: dict, run_id: int) -> None:
    items = catalog.get("artifacts")
    if not isinstance(items, list) or len(items) != 2:
        raise ValueError("Unexpected artifact count")
    if {i.get("name") for i in items} != {"encrypted-diagnostics-" + n for n in PLATFORMS}:
        raise ValueError("Unexpected artifact names")
    if len({i.get("id") for i in items}) != 2:
        raise ValueError("Duplicated artifact IDs")
    for item in items:
        size = item.get("size_in_bytes")
        if item.get("expired") is not False or type(size) is not int or not 100 < size < MAX_BYTES:
            raise ValueError("Unexpected artifact size/expiration")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(item.get("digest", ""))):
            raise ValueError("Missing artifact ZIP digest")
        workflow = item.get("workflow_run") or {}
        if workflow and workflow.get("id") != run_id:
            raise ValueError("Incorrect artifact run")


def validate_verified_record(records: list, expected_digest: str) -> None:
    if not isinstance(records, list):
        raise ValueError("Missing verified provenance")
    for record in records:
        verified = record.get("verificationResult", {})
        statement = verified.get("statement", {})
        if not verified.get("signature", {}).get("certificate") or not verified.get("verifiedTimestamps"):
            continue
        if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
            continue
        if any(subject.get("digest", {}).get("sha256") == expected_digest
               for subject in statement.get("subject", [])):
            return
    raise ValueError("No verified attestation binds this ciphertext")


def verify_signed_ciphertext(gh, path: Path, source_sha: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Invalid commit SHA")
    if path.is_symlink() or not path.is_file() or not 100 < path.stat().st_size < MAX_BYTES:
        raise ValueError("Invalid ciphertext")
    with path.open("rb") as stream:
        if stream.read(22) != b"age-encryption.org/v1\n":
            raise ValueError("Invalid age header")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    result = json.loads(gh(
        "attestation", "verify", str(path), "--repo", REPO,
        "--signer-workflow", SIGNER, "--source-digest", source_sha,
        "--source-ref", "refs/heads/main", "--deny-self-hosted-runners",
        "--format", "json",
    ))
    validate_verified_record(result, digest)
    return digest
