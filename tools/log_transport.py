"""Transfer PUBLIC synthetic CI ciphertext using job logs, not Actions artifacts.

Only encrypted age ciphertext is emitted. Job logs themselves are public until
deleted; NEVER use this transport for private source or confidential builds.
"""

import base64
import hashlib
import os
from pathlib import Path
import re


MARKER = "CI_RELAY_ENCRYPTED_V1:"
KINDS = {"log": "encrypted-log.age", "binary": "encrypted-binary.age"}
MAX_CIPHERTEXT = 500_000  # public proof only; avoids massive GitHub job logs


def format_encrypted_line(platform: str, kind: str, ciphertext: bytes) -> str:
    if platform not in ("ubuntu-24.04", "windows-2025") or kind not in KINDS:
        raise ValueError("Unsupported public synthetic ciphertext source")
    if (not 100 < len(ciphertext) < MAX_CIPHERTEXT
            or not ciphertext.startswith(b"age-encryption.org/v1\n")):
        raise ValueError("Invalid encrypted synthetic transport payload")
    digest = hashlib.sha256(ciphertext).hexdigest()
    return f"{MARKER}{platform}:{kind}:{digest}:{base64.b64encode(ciphertext).decode('ascii')}"


def parse_job_log(log: str, platform: str) -> dict[str, bytes]:
    if platform not in ("ubuntu-24.04", "windows-2025"):
        raise ValueError("Unrecognized platform")
    if len(log) > 4_000_000:
        raise ValueError("Unexpectedly long CI job log")
    result = {}
    for line in log.splitlines():
        if MARKER not in line:
            continue
        payload = line.split(MARKER, 1)[1].strip()
        match = re.fullmatch(r"([a-z0-9.-]+):(log|binary):([0-9a-f]{64}):([A-Za-z0-9+/]+={0,2})", payload)
        if not match:
            raise ValueError("Invalid public ciphertext job log framing")
        claimed_platform, kind, digest, encoded = match.groups()
        if claimed_platform != platform or kind in result:
            raise ValueError("Duplicate or cross-platform encrypted report")
        ciphertext = base64.b64decode(encoded, validate=True)
        if (not 100 < len(ciphertext) < MAX_CIPHERTEXT
                or not ciphertext.startswith(b"age-encryption.org/v1\n")
                or hashlib.sha256(ciphertext).hexdigest() != digest):
            raise ValueError("Malformed or altered encrypted CI job log")
        result[kind] = ciphertext
    if set(result) != set(KINDS):
        raise ValueError("Missing encrypted log or binary from CI job log")
    return result


def emit_encrypted_logs() -> None:
    runner = os.environ.get("RUNNER_OS")
    platform = ("ubuntu-24.04" if runner == "Linux" else
                "windows-2025" if runner == "Windows" else None)
    if platform is None:
        raise RuntimeError("Unsupported CI runner platform")
    root = Path(__file__).resolve().parents[1]
    for kind, filename in KINDS.items():
        print(format_encrypted_line(platform, kind, (root / filename).read_bytes()),
              flush=True)


if __name__ == "__main__":
    emit_encrypted_logs()
