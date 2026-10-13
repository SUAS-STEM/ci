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
import stat
import subprocess
import tempfile

try:
    from .ephemeral_age import is_age_recipient
except ImportError:
    from ephemeral_age import is_age_recipient


ARCHIVE_ROOT = Path.home() / "ci-artifacts" / "ci-relay-lab"
PLATFORMS = ("ubuntu-24.04", "windows-2025")
MAX_LOG_BYTES = 20 * 1024 * 1024
BINARY_FILENAMES = {"ubuntu-24.04": "ubuntu-24.04.bin",
                    "windows-2025": "windows-2025.exe"}
MAX_BINARY_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024
MAX_RECEIPT_BYTES = 4 * 1024
AGE_EXE = Path(__file__).resolve().parents[1] / ".age-bin" / "age"
ARCHIVE_RECIPIENT_FILE = Path.home() / ".config" / "ci-relay-lab" / "archive-recipient.agepub"


def configured_archive_recipient(path: Path = ARCHIVE_RECIPIENT_FILE) -> str | None:
    """Read an optional *public* offline recovery recipient; no secret on Pi.

    Missing is legacy plaintext compatibility, malformed/unsafe configuration
    fails closed instead of silently writing plaintext to the Pi's SSD.
    """
    if not path.exists() and not path.is_symlink():
        return None
    with _open_verified_file(path, 512) as source:
        recipient = source.read().decode("ascii").strip()
    if not is_age_recipient(recipient):
        raise RuntimeError("Invalid offline archive recovery public recipient")
    return recipient


def _encrypt_for_offline_recipient(data: bytes, recipient: str) -> bytes:
    if not is_age_recipient(recipient) or not AGE_EXE.is_file():
        raise RuntimeError("Offline archive encryption unavailable; refusing plaintext fallback")
    result = subprocess.run(
        [str(AGE_EXE), "-r", recipient, "-"],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=40, check=True,
    )
    ciphertext = result.stdout
    if not ciphertext.startswith(b"age-encryption.org/v1\n"):
        raise RuntimeError("Offline encryption did not produce age ciphertext")
    return ciphertext


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


def _open_verified_file(path: Path, maximum: int):
    """Open an owned regular archive member without symlink/race traversal."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise RuntimeError("Cannot safely open Pi archive member") from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= maximum):
            raise RuntimeError("Untrusted file type, permissions or size in Pi archive")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _read_json_member(path: Path, limit: int) -> dict:
    with _open_verified_file(path, limit) as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise RuntimeError("Malformed archived JSON metadata")
    return value


def _verified_file_digest(path: Path, size: int, digest: str,
                          maximum: int) -> None:
    if (type(size) is not int or not 0 < size <= maximum
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
        raise RuntimeError("Invalid archived file size or checksum metadata")
    with _open_verified_file(path, maximum) as source:
        if os.fstat(source.fileno()).st_size != size:
            raise RuntimeError("Pi archive size mismatch")
        checksum = hashlib.sha256()
        total = 0
        while chunk := source.read(min(1024 * 1024, maximum + 1 - total)):
            total += len(chunk)
            if total > maximum:
                raise RuntimeError("Pi archive unexpectedly exceeds size limit")
            checksum.update(chunk)
    if total != size or checksum.hexdigest() != digest:
        raise RuntimeError("Pi archive hash or size mismatch")


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
    binaries: dict[str, bytes | None] | None = None,
    archive_recipient: str | None = None,
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
    schema = 1 if binaries is None else 2
    binary_status = None
    if binaries is not None:
        if set(binaries) != set(PLATFORMS):
            raise ValueError("Both synthetic binary statuses are required")
        binary_status = {}
        for platform in PLATFORMS:
            data = binaries[platform]
            if data is None:
                binary_status[platform] = "missing"
            elif type(data) is bytes and 0 < len(data) <= MAX_BINARY_BYTES:
                payloads[BINARY_FILENAMES[platform]] = data
                binary_status[platform] = "present"
            else:
                raise ValueError("Invalid compiled synthetic binary bytes")
    if archive_recipient is not None:
        if binaries is None:
            raise ValueError("Encrypted permanent archives require explicit binary status")
        if not is_age_recipient(archive_recipient):
            raise ValueError("Invalid offline recovery age recipient")
        payloads = {name + ".age": _encrypt_for_offline_recipient(data, archive_recipient)
                    for name, data in payloads.items()}
        schema = 3
    manifest = {
        "schema": schema,
        "repository": "SUAS-STEM/ci-relay-lab",
        "run_id": run_id, "trace": trace, "commit": sha,
        "recipient_sha256": recipient_sha,
        "artifact_ids": artifact_ids,
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                  for name, data in payloads.items()},
        "verified": "age+sigstore+run-binding+no-public-canary",
    }
    if binary_status is not None:
        manifest["binary_status"] = binary_status
    if archive_recipient is not None:
        manifest["storage_encryption"] = {
            "format": "age-x25519",
            "recipient_sha256": hashlib.sha256(archive_recipient.encode("ascii")).hexdigest(),
        }
    _prepare_root(root)
    destination = root / f"run-{run_id}"
    if destination.exists() or destination.is_symlink():
        if archive_recipient is not None:
            raise RuntimeError("Refusing to overwrite an existing encrypted archive")
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
    entries = {item.name for item in run.iterdir()}
    expected_names = {"manifest.json", "ubuntu-24.04.log", "windows-2025.log"}
    manifest_path = run / "manifest.json"
    cleanup_receipt = None
    if "github-cleanup.json" in entries:
        cleanup_receipt = _read_json_member(run / "github-cleanup.json", MAX_RECEIPT_BYTES)
    manifest = _read_json_member(manifest_path, MAX_MANIFEST_BYTES)
    if manifest.get("schema") in (2, 3):
        status = manifest.get("binary_status")
        if not isinstance(status, dict) or set(status) != set(PLATFORMS) or any(
            value not in ("present", "missing") for value in status.values()
        ):
            raise RuntimeError("Malformed synthetic compiled-binary status")
        expected_names.update(BINARY_FILENAMES[p] for p in PLATFORMS
                              if status[p] == "present")
    elif manifest.get("schema") != 1:
        raise RuntimeError("Unsupported Pi archive manifest schema")
    if manifest.get("schema") == 3:
        storage = manifest.get("storage_encryption")
        if (not isinstance(storage, dict)
                or storage.get("format") != "age-x25519"
                or not isinstance(storage.get("recipient_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", storage["recipient_sha256"])):
            raise RuntimeError("Invalid at-rest archive encryption metadata")
        expected_names = {name + ".age" if name != "manifest.json" else name
                          for name in expected_names}
    if entries - {"github-cleanup.json"} != expected_names:
        raise RuntimeError("Archive contains missing or unexpected files")
    _validate_identity(manifest["run_id"], manifest["trace"], manifest["commit"],
                       manifest["recipient_sha256"])
    if manifest["run_id"] != run_id or manifest.get("repository") != "SUAS-STEM/ci-relay-lab":
        raise RuntimeError("Local run identity mismatch")
    if set(manifest.get("artifact_ids", {})) != set(PLATFORMS):
        raise RuntimeError("Missing verified remote artifact identifiers")
    if cleanup_receipt is not None and cleanup_receipt != {
        "run_id": run_id,
        "deleted_artifact_ids": manifest["artifact_ids"],
        "confirmed_absent_from_github": True,
    }:
        raise RuntimeError("Local cleanup receipt does not match verified run")
    if set(manifest.get("files", {})) != expected_names - {"manifest.json"}:
        raise RuntimeError("Missing verified local artifact hashes")
    for name, description in manifest["files"].items():
        if not isinstance(description, dict):
            raise RuntimeError("Malformed archive file metadata")
        base_name = name.removesuffix(".age")
        maximum = MAX_BINARY_BYTES if base_name in BINARY_FILENAMES.values() else MAX_LOG_BYTES
        if manifest.get("schema") == 3:
            maximum += 4096
        _verified_file_digest(run / name, description.get("bytes"),
                              description.get("sha256"), maximum)
        if manifest.get("schema") == 3:
            with _open_verified_file(run / name, maximum) as source:
                if source.read(22) != b"age-encryption.org/v1\n":
                    raise RuntimeError("Expected sealed age file in encrypted Pi archive")
    return manifest


def pending_github_cleanup(root: Path) -> list[int]:
    """Enumerate intact Pi archives without cleanup receipts.

    Unrecognized entries and crashed staging directories are never trusted or
    processed. A damaged archive fails closed rather than authorizing deletion.
    """
    _private_dir(root.parent)
    _private_dir(root)
    pending = []
    for child in root.iterdir():
        match = re.fullmatch(r"run-([1-9][0-9]*)", child.name)
        if match is None:
            continue
        run_id = int(match.group(1))
        read_verified_archive(root, run_id)
        if not (child / "github-cleanup.json").exists():
            pending.append(run_id)
    return sorted(pending)


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
