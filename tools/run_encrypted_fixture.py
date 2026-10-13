"""Capture *all sample subprocess stdout/stderr* and encrypt via age.

Only runs the fixed toy project in this public repository. Deliberate failing
commands verify that even their diagnostics remain inside the ciphertext.
"""

import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

from tools.check_fixture import parse_request


ROOT = Path(__file__).resolve().parents[1]
PUBKEY_FILE = ROOT / "keys" / "pi-logs.agepub"
AGE_EXE = ROOT / ".age-bin" / ("age.exe" if os.name == "nt" else "age")
OUTPUT = ROOT / "encrypted-log.age"
SAFE_ENV_KEYS = frozenset({
    "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
    "TMPDIR", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
    "LOCALAPPDATA", "APPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
    "PROGRAMW6432", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    "OS", "LANG", "LC_ALL", "PYTHONIOENCODING",
})


def sanitized_build_environment(source: dict[str, str]) -> dict[str, str]:
    """Don't pass hosted-runner auth tokens/config to a build subprocess."""
    return {key: value for key, value in source.items()
            if key.upper() in SAFE_ENV_KEYS}


def main() -> int:
    trace = os.environ["TRACE_ID"]
    left = os.environ["LEFT"]
    right = os.environ["RIGHT"]
    parse_request(trace, left, right)
    if not PUBKEY_FILE.is_file() or not AGE_EXE.is_file():
        raise RuntimeError("Encryption prerequisites unavailable: fail closed")
    recipient = PUBKEY_FILE.read_text().strip()
    if not recipient.startswith("age1") or len(recipient) != 62:
        raise RuntimeError("Invalid pinned public recipient key")

    # Log data never appears on stdout/stderr; a subprocess failure only changes
    # the encrypted report and (after encryption succeeds) the runner exit status.
    chunks = []
    failed = False
    base_env = sanitized_build_environment(os.environ)

    def capture(label: str, command: list[str], expected: int = 0, env=None) -> None:
        nonlocal failed
        try:
            result = subprocess.run(
                command, cwd=ROOT, env=base_env if env is None else env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=120, check=False,
            )
            output = result.stdout
            code = result.returncode
        except subprocess.TimeoutExpired as error:
            output = error.stdout or b""
            code = -1
        except OSError as error:
            # Exception messages can include sensitive paths or arbitrary
            # argument text. Record only the exception class in ciphertext.
            output = f"{type(error).__name__}\n".encode()
            code = -127
        chunks.append(
            (f"\n=== {label} (exit={code}; expected={expected}) ===\n").encode()
            + output[:2 * 1024 * 1024]
        )
        if code != expected:
            failed = True

    canary = "SYNTHETIC_CANARY_" + secrets.token_hex(20)
    platform = os.environ["RUNNER_OS"]
    platform_name = "windows-2025" if platform == "Windows" else "ubuntu-24.04" if platform == "Linux" else "invalid"
    run_id = os.environ["GITHUB_RUN_ID"]
    sha = os.environ["GITHUB_SHA"]
    if platform_name == "invalid" or not run_id.isdecimal() or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError("Unrecognized GitHub runner context")
    chunks.append(f"trace={trace}\ncommit={sha}\nrun={run_id}\nplatform={platform_name}\ncanary={canary}\n".encode())
    capture("Python input validation", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])
    capture("CMake configure", ["cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Release"])
    capture("C++ compile", ["cmake", "--build", "build", "--config", "Release", "--parallel", "2"])
    capture("CTest", ["ctest", "--test-dir", "build", "-C", "Release", "--output-on-failure"])
    env = dict(base_env)
    env.update({"TRACE_ID": trace, "LEFT": left, "RIGHT": right})
    capture("Synthetic numerical check", [sys.executable, "-m", "tools.check_fixture"], env=env)
    # This is a fixed, harmless, intentional failure: its stderr is encrypted,
    # and the workflow still succeeds when the exit code matches 47.
    capture(
        "Expected diagnostic failure (privacy test)",
        [sys.executable, "-c", "import os,sys; sys.stderr.write(os.environ['SYNTHETIC_CANARY']+' expected error\\n'); sys.exit(47)"],
        expected=47,
        env={**base_env, "SYNTHETIC_CANARY": canary},
    )
    payload = b"".join(chunks)
    result = subprocess.run(
        [str(AGE_EXE), "-r", recipient, "-o", str(OUTPUT), "-"],
        input=payload,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError("Encryption failed: no logs may be uploaded")
    print("Captured diagnostics encrypted using Pi's public key; plaintext not printed")
    if failed:
        print("One or more synthetic checks failed; details only in encrypted artifact")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # GitHub displays uncaught tracebacks publicly; do not echo internal
        # paths, exception messages, or plaintext diagnostics on failures.
        print("Encrypted test wrapper failed (no private diagnostics printed)",
              file=sys.stderr)
        raise SystemExit(1)
