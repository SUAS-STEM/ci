"""Bind a PUBLIC synthetic compiled binary to one CI run before age encryption.

Never execute a retrieved binary on the Pi. Its contents are archived as data.
"""

import hashlib
import re


MAX_BINARY_BYTES = 8 * 1024 * 1024
MAGIC = b"CI-RELAY-PUBLIC-BINARY-V1\n"


def wrap_binary(binary: bytes | None, trace: str, commit: str, run_id: int,
                platform: str, recipient_digest: str) -> bytes:
    if binary is not None and not 0 < len(binary) <= MAX_BINARY_BYTES:
        raise ValueError("Invalid size for synthetic binary")
    if not re.fullmatch(r"test-[0-9a-f]{12}", trace):
        raise ValueError("Invalid synthetic trace")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Invalid synthetic commit")
    if not re.fullmatch(r"[0-9a-f]{64}", recipient_digest):
        raise ValueError("Invalid synthetic recipient")
    if platform not in ("ubuntu-24.04", "windows-2025") or type(run_id) is not int or run_id <= 0:
        raise ValueError("Invalid synthetic runner")
    payload = binary if binary is not None else b""
    fields = (
        f"trace={trace}\ncommit={commit}\nrun={run_id}\nplatform={platform}\n"
        f"recipient_sha256={recipient_digest}\n"
        f"status={'present' if binary is not None else 'missing'}\n"
        f"bytes={len(payload)}\nsha256={hashlib.sha256(payload).hexdigest()}\n"
    ).encode("ascii")
    return MAGIC + fields + b"\n" + payload


def unwrap_binary(data: bytes, trace: str, commit: str, run_id: int,
                  platform: str, recipient_digest: str) -> bytes | None:
    if len(data) > MAX_BINARY_BYTES + 1024 or not data.startswith(MAGIC):
        raise ValueError("Invalid synthetic binary envelope")
    header, separator, payload = data[len(MAGIC):].partition(b"\n\n")
    if not separator or len(header) > 512:
        raise ValueError("Invalid synthetic binary envelope header")
    try:
        decoded = header.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid binary envelope metadata encoding") from exc
    fields = decoded.split("\n")
    if len(fields) != 8 or any("=" not in line for line in fields):
        raise ValueError("Invalid synthetic binary envelope metadata")
    parsed = dict(line.split("=", 1) for line in fields)
    if len(parsed) != 8 or set(parsed) != {
        "trace", "commit", "run", "platform", "recipient_sha256", "status", "bytes", "sha256"
    }:
        raise ValueError("Malformed binary provenance")
    if (parsed["trace"] != trace or parsed["commit"] != commit
            or parsed["run"] != str(run_id) or parsed["platform"] != platform
            or parsed["recipient_sha256"] != recipient_digest):
        raise ValueError("Binary artifact is from another run or recipient")
    if parsed["bytes"] != str(len(payload)) or not re.fullmatch(r"[0-9a-f]{64}", parsed["sha256"]):
        raise ValueError("Binary length or hash metadata invalid")
    if hashlib.sha256(payload).hexdigest() != parsed["sha256"]:
        raise ValueError("Binary payload hash does not match")
    if parsed["status"] == "missing" and not payload:
        return None
    if parsed["status"] == "present" and 0 < len(payload) <= MAX_BINARY_BYTES:
        return payload
    raise ValueError("Invalid binary presence status")
