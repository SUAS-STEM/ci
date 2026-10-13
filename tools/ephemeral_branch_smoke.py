"""Temporary public-only branch QA; intentionally uses no Pi credentials."""

import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / ".age-bin" / ("age-keygen.exe" if os.name == "nt" else "age-keygen")


def main() -> None:
    identity = subprocess.run([str(EXE)], capture_output=True, check=True,
                              timeout=15).stdout.decode("ascii")
    match = re.search(r"^# public key: (age1[ac-hj-np-z02-9]{58})$",
                      identity, re.MULTILINE)
    if not match:
        raise RuntimeError("Synthetic QA public recipient missing")
    env = os.environ.copy()
    env.update({"AGE_RECIPIENT": match.group(1), "TRACE_ID": "test-ephemeral-smoke",
                "LEFT": "17", "RIGHT": "-3"})
    subprocess.run([sys.executable, "-m", "tools.run_encrypted_fixture"],
                   cwd=ROOT, env=env, check=True, timeout=300)
    ciphertext = (ROOT / "encrypted-log.age").read_bytes()
    if not ciphertext.startswith(b"age-encryption.org/v1\n") or b"SYNTHETIC_CANARY_" in ciphertext:
        raise RuntimeError("Synthetic ephemeral encryption verification failed")
    print("Synthetic matrix smoke passed (no Pi key or private source used)")


if __name__ == "__main__":
    main()
