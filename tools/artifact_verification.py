"""Verify signed provenance before Pi decryption of synthetic CI artifacts."""

import hashlib
import hmac
from io import BytesIO
import json
from pathlib import Path
import re
import stat
import zipfile


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


def extract_ciphertext_zip(blob: bytes, metadata: dict) -> bytes:
    """Legacy single-log synthetic archive validator (tests only)."""
    return extract_ciphertext_bundle(blob, metadata, ("encrypted-log.age",))["encrypted-log.age"]


def extract_ciphertext_bundle(blob: bytes, metadata: dict,
                              expected_names=("encrypted-log.age", "encrypted-binary.age")) -> dict[str, bytes]:
    """Validate the exact GitHub artifact ZIP before extracting any bytes.

    No blind unzip, no paths supplied by an untrusted archive, and a tight
    decompressed size cap. GitHub API's published digest covers the ZIP bytes.
    """
    if not 100 < len(blob) < MAX_BYTES or len(blob) != metadata.get("size_in_bytes"):
        raise ValueError("Artifact ZIP size differs from authenticated metadata")
    published = str(metadata.get("digest", ""))
    computed = "sha256:" + hashlib.sha256(blob).hexdigest()
    if not hmac.compare_digest(published, computed):
        raise ValueError("Artifact ZIP digest mismatch")
    try:
        with zipfile.ZipFile(BytesIO(blob)) as archive:
            members = archive.infolist()
            if len(members) != len(expected_names) or {m.filename for m in members} != set(expected_names):
                raise ValueError("Unexpected file or path in encrypted artifact")
            if sum(member.file_size for member in members) >= MAX_BYTES:
                raise ValueError("Total archive expansion exceeds limit")
            result = {}
            for member in members:
                mode = (member.external_attr >> 16) & 0xFFFF
                if member.is_dir() or (mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                    raise ValueError("Artifact member cannot be a symlink or special file")
                if not 100 < member.file_size < MAX_BYTES:
                    raise ValueError("Encrypted artifact decompressed size invalid")
                with archive.open(member, "r") as source:
                    ciphertext = source.read(MAX_BYTES + 1)
                if len(ciphertext) != member.file_size or len(ciphertext) >= MAX_BYTES:
                    raise ValueError("Encrypted artifact exceeds extraction limit")
                if not ciphertext.startswith(b"age-encryption.org/v1\n"):
                    raise ValueError("ZIP did not contain an age ciphertext")
                result[member.filename] = ciphertext
            return result
    except (zipfile.BadZipFile, EOFError, RuntimeError) as exc:
        raise ValueError("Invalid ciphertext ZIP archive") from exc


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
