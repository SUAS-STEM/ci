"""Durable Pi-only storage for verified, PUBLIC synthetic CI diagnostics.

The Pi is the long-term store; Actions ciphertext artifacts are transfer
buffers. Nothing is deleted remotely until a complete fsync'd local archive
has been committed and independently read back. This does not encrypt the Pi's
SSD: sensitive storage requires filesystem/full-disk encryption separately.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile


ARCHIVE_ROOT = Path.home() / "ci-artifacts" / "ci-relay-lab"
PLATFORMS = ("ubuntu-24.04", "windows-2025")
MAX_LOG_BYTES = 20 * 1024 * 1024


def _private_dir(directory: Path, create: bool = False) -> None:
    if create:
        directory.mkdir(mode=0o700)
    info = directory.lstat()
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError("Refusing non-directory or symlink in artifact store")
    if info.st_uid != os.getuid() or (info.st_mode & 0o777) != 0o700:
        raise RuntimeError("Pi archive directories must be user-owned and 0700")


def _prepare_root(root: Path) -> None:
    # Fixed, Pi-local path. No CLI-supplied archive root or external web path.
    for path in (root.parent, root):
        if not path.exists() and not path.is_symlink():
            _private_dir(path, create=True)
        else:
            _private_dir(path)


def _sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _validate_identity(run_id: int, trace: str, sha: str, recipient_sha: str) -> None:
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("Invalid run ID")
    if not re.fullmatch(r"test-[0-9a-f]{12}", trace):
        raise ValueError("Invalid synthetic trace")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(r"[0-9a-f]{64}", recipient_sha):
        raise ValueError("Invalid commit or recipient hash")


def archive_run(
    root: Path, run_id: int, trace: str, sha: str, recipient_sha: str,
    logs: dict[str, str], artifact_ids: dict[str, int],
) -> Path:
    """Make an immutable, verified run directory. Never overwrite a run."""
    _validate_identity(run_id, trace, sha, recipient_sha)
    if set(logs) != set(PLATFORMS) or set(artifact_ids) != set(PLATFORMS):
        raise ValueError("Both synthetic platforms are required")
    if any(type(v) is not int or v <= 0 for v in artifact_ids.values()):
        raise ValueError("Invalid GitHub artifact ID")
    if len(set(artifact_ids.values())) != len(PLATFORMS):
        raise ValueError("Duplicate GitHub artifact IDs")
    payloads = {f"{p}.log": logs[p].encode("utf-8", errors="strict") for p in PLATFORMS}
    if any(not 1 < len(value) < MAX_LOG_BYTES for value in payloads.values()):
        raise ValueError("Unexpected size of decrypted diagnostics")
    manifest = {
        "schema": 1,
        "repository": "SUAS-STEM/ci-relay-lab",
        "run_id": run_id, "trace": trace, "commit": sha,
        "recipient_sha256": recipient_sha,
        "artifact_ids": artifact_ids,
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                  for name, data in payloads.items()},
        "verified": "age+sigstore+run-binding+no-public-canary",
    }
    _prepare_root(root)
    destination = root / f"run-{run_id}"
    if destination.exists() or destination.is_symlink():
        if read_verified_archive(root, run_id) != manifest:
            raise RuntimeError("Refusing to replace different local run data")
        return destination

    staging = Path(tempfile.mkdtemp(prefix=f".stage-{run_id}-", dir=root))
    try:
        _private_dir(staging)
        for name, data in payloads.items():
            _write_new(staging / name, data)
        _write_new(staging / "manifest.json", _json_bytes(manifest))
        _sync_directory(staging)
        # Never overwrite a previous run, even under concurrent invocations.
        if destination.exists() or destination.is_symlink():
            raise RuntimeError("Another process archived this run concurrently")
        staging.rename(destination)
        _sync_directory(root)
    finally:
        if staging.exists():
            for item in staging.iterdir():
                item.unlink()
            staging.rmdir()
    if read_verified_archive(root, run_id) != manifest:
        raise RuntimeError("Durable archive readback did not match verified inputs")
    return destination


def read_verified_archive(root: Path, run_id: int) -> dict:
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("Invalid run ID")
    _private_dir(root.parent)
    _private_dir(root)
    run = root / f"run-{run_id}"
    _private_dir(run)
    if sorted(item.name for item in run.iterdir() if item.name != "github-cleanup.json") != [
        "manifest.json", "ubuntu-24.04.log", "windows-2025.log"
    ]:
        raise RuntimeError("Archive contains missing or unexpected files")
    manifest_path = run / "manifest.json"
    for name in ("manifest.json", "ubuntu-24.04.log", "windows-2025.log"):
        path = run / name
        info = path.lstat()
        if not path.is_file() or path.is_symlink() or info.st_uid != os.getuid() or (info.st_mode & 0o777) != 0o600:
            raise RuntimeError("Untrusted local artifact file")
    manifest = json.loads(manifest_path.read_text("utf-8"))
    _validate_identity(manifest["run_id"], manifest["trace"], manifest["commit"],
                       manifest["recipient_sha256"])
    if manifest["run_id"] != run_id or manifest.get("repository") != "SUAS-STEM/ci-relay-lab":
        raise RuntimeError("Local run identity mismatch")
    if set(manifest.get("artifact_ids", {})) != set(PLATFORMS):
        raise RuntimeError("Missing verified remote artifact identifiers")
    if set(manifest.get("files", {})) != {f"{p}.log" for p in PLATFORMS}:
        raise RuntimeError("Missing verified local artifact hashes")
    for name, description in manifest["files"].items():
        data = (run / name).read_bytes()
        if not 1 < len(data) < MAX_LOG_BYTES or len(data) != description["bytes"]:
            raise RuntimeError("Local artifact size mismatch")
        if hashlib.sha256(data).hexdigest() != description["sha256"]:
            raise RuntimeError("Local artifact checksum mismatch")
    return manifest


def record_github_cleanup(root: Path, run_id: int, artifact_ids: dict[str, int]) -> None:
    manifest = read_verified_archive(root, run_id)
    if manifest["artifact_ids"] != artifact_ids:
        raise RuntimeError("Cleanup receipt refers to the wrong artifacts")
    run = root / f"run-{run_id}"
    receipt = run / "github-cleanup.json"
    payload = _json_bytes({"run_id": run_id, "deleted_artifact_ids": artifact_ids,
                           "confirmed_absent_from_github": True})
    tmp = run / (".cleanup-" + os.urandom(8).hex())
    try:
        _write_new(tmp, payload)
        os.replace(tmp, receipt)
        _sync_directory(run)
    finally:
        if tmp.exists():
            tmp.unlink()
