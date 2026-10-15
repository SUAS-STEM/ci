"""Portable OFFLINE reference checker for the public fixture and regression tests.

Do NOT invoke this imported Python module after untrusted compilation. The
real post-build checker runs as inline workflow-owned PowerShell before the
GitHub Release credential is restored. This reference is only for pre-build
diagnostics and local regression testing.
"""

import os
from pathlib import Path
import re
import subprocess
import sys

from .public_guard import ROOT, check_tree


def _git(root, *args):
    result = subprocess.run(["git", *args], cwd=root, check=True,
                            capture_output=True, timeout=30)
    return result.stdout


def check_checkout(root: Path, expected_sha: str):
    if not isinstance(expected_sha, str) or not re.fullmatch(r"[a-f0-9]{40}", expected_sha):
        raise ValueError("Missing immutable public checkout revision")
    if _git(root, "rev-parse", "HEAD").decode("ascii").strip() != expected_sha:
        raise ValueError("Unexpected checked-out public workflow revision")
    # Git status catches ordinary untracked files but can hide ignored Python
    # bytecode, or be fooled by Git index assume-unchanged bits.
    if _git(root, "status", "--porcelain=v1", "--untracked-files=all", "-z"):
        raise ValueError("Public checkout changed during MSVC compilation")
    raw = _git(root, "ls-files", "-z")
    names = [entry.decode("utf-8") for entry in raw.split(b"\0") if entry]
    if not names or len(names) > 100 or len(names) != len(set(names)):
        raise ValueError("Unexpected PUBLIC tracked file inventory")
    tracked = set(names)
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root)
        if relative.parts[0] in (".git", ".age-bin"):
            continue
        if candidate.is_symlink():
            raise ValueError("Unexpected PUBLIC checkout symlink")
        if candidate.is_file() and relative.as_posix() not in tracked:
            raise ValueError("Unexpected ignored/untracked PUBLIC checkout file")
    for name in names:
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts
                or "\\" in name or not name.isascii()):
            raise ValueError("Unexpected PUBLIC tracked path")
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError("Modified PUBLIC relay file type")
        # Compare actual file bytes to the object committed at HEAD.
        # `git status` alone can be fooled by git index 'assume-unchanged'.
        blob = _git(root, "show", "HEAD:" + name)
        local = path.read_bytes()
        # GitHub Windows checkout may materialize normalized LF text as CRLF.
        if local != blob and local.replace(b"\r\n", b"\n") != blob:
            raise ValueError("Modified PUBLIC relay bytes")
    # The existing public allowlist protects against a newly tracked private
    # source in an otherwise internally consistent commit.
    check_tree(root)


def main():
    try:
        check_checkout(ROOT, os.environ.get("GITHUB_SHA", ""))
    except (ValueError, OSError, UnicodeError, subprocess.SubprocessError):
        # No private path or input content should appear in PUBLIC logs.
        print("PUBLIC RELAY INTEGRITY CHECK FAILED", file=sys.stderr)
        return 1
    print("PUBLIC relay checkout unchanged since reviewed workflow revision")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
