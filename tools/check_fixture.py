"""Verify only the synthetic C++ program built from this public repository."""

import os
from pathlib import Path
import re
import subprocess


def parse_request(trace_id: str, left: str, right: str) -> tuple[int, int]:
    if re.fullmatch(r"[a-zA-Z0-9-]{6,24}", trace_id) is None:
        raise ValueError("trace_id must be 6-24 letters, numbers or hyphens")
    for value in (left, right):
        if re.fullmatch(r"-?(0|[1-9][0-9]{0,3})", value) is None:
            raise ValueError("Operands must be decimal integers between -9999 and 9999")
    return int(left), int(right)


def find_executable(build_dir: Path) -> Path:
    candidates = [
        p for p in build_dir.rglob("synthetic_adder*")
        if p.is_file() and p.name in ("synthetic_adder", "synthetic_adder.exe")
    ]
    if len(candidates) != 1:
        raise RuntimeError(f"Expected one compiled synthetic_adder; found {len(candidates)}")
    return candidates[0]


def main() -> None:
    trace_id = os.environ["TRACE_ID"]
    left, right = parse_request(trace_id, os.environ["LEFT"], os.environ["RIGHT"])
    binary = find_executable(Path("build"))
    output = subprocess.check_output(
        [str(binary.resolve()), str(left), str(right)],
        text=True,
        timeout=10,
    ).strip()
    expected = str(left + right)
    if output != expected:
        raise AssertionError(f"Expected {expected}, received {output!r}")
    print(f"PASS trace={trace_id} inputs=({left},{right}) result={output}")
    print("SOURCE=public synthetic_adder.cpp; PRIVATE_SOURCE=none")


if __name__ == "__main__":
    main()
