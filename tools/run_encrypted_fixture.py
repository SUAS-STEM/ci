"""Capture *all sample subprocess stdout/stderr* and encrypt via age.

Only runs the fixed toy project in this public repository. Deliberate failing
commands verify that even their diagnostics remain inside the ciphertext.
"""

import os
from pathlib import Path
import hashlib
import re
import secrets
import subprocess
import sys

from tools.check_fixture import parse_request
from tools.check_fixture import find_executable
from tools.ephemeral_age import is_age_recipient
from tools.binary_envelope import wrap_binary, MAX_BINARY_BYTES


ROOT = Path(__file__).resolve().parents[1]
AGE_EXE = ROOT / ".age-bin" / ("age.exe" if os.name == "nt" else "age")
OUTPUT = ROOT / "encrypted-log.age"
BINARY_OUTPUT = ROOT / "encrypted-binary.age"
BLOCKED_ENV_PREFIXES = (
    "GITHUB_", "ACTIONS_", "RUNNER_", "INPUT_", "GH_", "AWS_",
    "AZURE_", "GOOGLE_", "NPM_", "PIP_", "DOCKER_",
)
BLOCKED_ENV_WORDS = ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL",
                     "AUTH", "PRIVATE", "API_KEY", "ACCESS_KEY")


def sanitized_build_environment(source: dict[str, str]) -> dict[str, str]:
    """Strip credential-like variables but preserve Visual Studio discovery.

    The public *toy* project must not be mistaken for an isolation boundary.
    Private/untrusted source must not be run on public GitHub hosted runners.
    """
    return {
        key: value for key, value in source.items()
        if not key.upper().startswith(BLOCKED_ENV_PREFIXES)
        and not any(word in key.upper() for word in BLOCKED_ENV_WORDS)
    }


def main() -> int:
    trace = os.environ["TRACE_ID"]
    left = os.environ["LEFT"]
    right = os.environ["RIGHT"]
    parse_request(trace, left, right)
    if not AGE_EXE.is_file():
        raise RuntimeError("Encryption prerequisites unavailable: fail closed")
    recipient = os.environ["AGE_RECIPIENT"]
    if not is_age_recipient(recipient):
        raise RuntimeError("Invalid per-run public recipient key")

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
    digest = hashlib.sha256(recipient.encode("ascii")).hexdigest()
    chunks.append(f"trace={trace}\ncommit={sha}\nrun={run_id}\nplatform={platform_name}\nrecipient_sha256={digest}\ncanary={canary}\n".encode())
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
    # Also deliver the *public toy executable*, not just test logs. If the
    # build failed, encrypt a provenance-bound 'missing' envelope instead.
    # Neither binary is executed on the Pi after retrieval.
    binary = None
    try:
        executable = find_executable(ROOT / "build")
        if 0 < executable.stat().st_size <= MAX_BINARY_BYTES:
            binary = executable.read_bytes()
        else:
            failed = True
    except (OSError, RuntimeError):
        failed = True
    binary_payload = wrap_binary(binary, trace, sha, int(run_id),
                                 platform_name, digest)
    for output, content in ((OUTPUT, payload), (BINARY_OUTPUT, binary_payload)):
        result = subprocess.run(
            [str(AGE_EXE), "-r", recipient, "-o", str(output), "-"],
            input=content,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError("Encryption failed: no logs or binaries may be uploaded")
    print("Captured toy diagnostics and binary encrypted; plaintext not printed")
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
