"""Token-minimized encrypted PUBLIC MSVC runner with three independent steps.

bootstrap: exposes only PUBLIC release upload token; creates per-run age identity.
compile: no GH_TOKEN/GITHUB_TOKEN, decrypts and compiles synthetic source.
publish: reads only encrypted output/status; uploads with PUBLIC-only token.

Not an enclave: the entire GitHub-hosted runner remains a trust boundary.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib.request import Request, urlopen

from . import opaque_runner as relay

MAX_SOURCE_CIPHER = 25 * 1024 * 1024
PUBLIC_URL = "https://github.com/SUAS-STEM/ci-relay-lab/releases/download/"
FORBIDDEN_COMPILE_VARIABLES = (
    "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_RUNTIME_URL", "GITHUB_ENV", "GITHUB_OUTPUT",
    "GITHUB_PATH", "GITHUB_STEP_SUMMARY", "GITHUB_STATE",
)


def context():
    nonce = os.environ.get("CI_NONCE", "")
    sha = os.environ.get("CI_PRIVATE_SHA", "")
    recipient = os.environ.get("CI_OUTPUT_RECIPIENT", "")
    commitment = os.environ.get("CI_BUNDLE_SHA256", "")
    if (os.environ.get("GITHUB_REPOSITORY") != relay.PUBLIC_REPO
            or re.fullmatch(r"[0-9a-f]{24}", nonce) is None
            or re.fullmatch(r"[a-f0-9]{40}", sha) is None
            or relay.RECIPIENT.fullmatch(recipient) is None
            or re.fullmatch(r"[a-f0-9]{64}", commitment) is None):
        raise ValueError("Invalid encrypted MSVC job origin")
    root = Path(os.environ["RUNNER_TEMP"])
    return nonce, sha, recipient, commitment, root


def original(nonce, root):
    return root / ("ci-opaque-" + nonce)


def staged(nonce, root):
    return root / ("ci-opaque-ciphertext-" + nonce)


def bootstrap():
    nonce, sha, recipient, _commitment, root = context()
    if not os.environ.get("GH_TOKEN"):
        raise RuntimeError("Only the public key publisher requires a GitHub token")
    work = original(nonce, root)
    work.mkdir(mode=0o700)
    keyfile = work / "recipient-key.txt"
    result = subprocess.run([str(relay.KEYGEN), "-o", str(keyfile)],
                            capture_output=True, text=True, check=True, timeout=30)
    match = re.search(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}",
                      result.stderr)
    if match is None:
        raise RuntimeError("Public runner identity generation failed")
    (work / "recipient.agepub").write_text(match.group() + "\n", encoding="ascii")
    proof = relay.github_runner_oidc(
        relay.oidc_audience(nonce, sha, recipient, match.group()))
    (work / "recipient.oidc").write_text(proof + "\n", encoding="ascii")
    relay.gh("release", "upload", "ci-opaque-" + nonce, "--repo",
             relay.PUBLIC_REPO, str(work / "recipient.agepub"),
             str(work / "recipient.oidc"))
    print("Authenticated one-time public encryption recipient published", flush=True)


def download_source(tag, target):
    """Read anonymous GitHub PUBLIC encrypted asset; no Actions token required."""
    if relay.MARKER.fullmatch(tag) is None:
        raise ValueError("Invalid public transfer identifier")
    request = Request(PUBLIC_URL + tag + "/source.age",
                      headers={"User-Agent": "ci-relay-lab/opaque-msvc"})
    with urlopen(request, timeout=55) as response:
        if response.status != 200:
            raise RuntimeError("Public ciphertext download failed")
        # Explicit size ceiling; bounded reads even with absent Content-Length.
        size = response.headers.get("Content-Length")
        if size is not None and int(size) > MAX_SOURCE_CIPHER:
            raise RuntimeError("Encrypted MSVC source exceeds maximum")
        blob = response.read(MAX_SOURCE_CIPHER + 1)
    if not 0 < len(blob) <= MAX_SOURCE_CIPHER:
        raise RuntimeError("Encrypted source missing or oversized")
    if target.exists() or target.is_symlink():
        raise RuntimeError("Unsafe source download destination")
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(blob)


def encrypt_binary_file(source, target, recipient, *, timeout=90):
    """Stream an MSVC executable into age without copying it into RAM.

    A failed/timed-out encryption must never leave a publishable partial
    ciphertext. Use a new owner-only output path and clean it on all errors.
    """
    if (relay.RECIPIENT.fullmatch(recipient) is None
            or not source.is_file() or source.is_symlink()
            or target.exists() or target.is_symlink()):
        raise RuntimeError("Invalid streaming MSVC encryption input/output")
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or not 1024 < info.st_size < 100 * 1024 * 1024:
        raise RuntimeError("Compiled MSVC binary outside approved size limit")
    with source.open("rb") as binary:
        if binary.read(2) != b"MZ":
            raise RuntimeError("Compiled MSVC output is not a Windows PE executable")
        binary.seek(0)
        digest = hashlib.file_digest(binary, "sha256").hexdigest()
        binary.seek(0)
        output_fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(output_fd, "wb") as ciphertext:
                subprocess.run([str(relay.AGE), "-r", recipient],
                               stdin=binary, stdout=ciphertext,
                               stderr=subprocess.PIPE, check=True,
                               timeout=timeout)
        except BaseException:
            target.unlink(missing_ok=True)
            raise
    if not target.is_file() or target.stat().st_size <= 0:
        target.unlink(missing_ok=True)
        raise RuntimeError("MSVC encryption produced no ciphertext")
    return digest


def compile_private():
    nonce, sha, recipient, commitment, root = context()
    # Public GitHub token is supplied ONLY to bootstrap/publish workflow steps.
    # Strip GitHub runtime/ID tokens before running PowerShell too.
    if any(os.environ.get(name) for name in FORBIDDEN_COMPILE_VARIABLES):
        raise RuntimeError("Refusing GitHub credential or control path in plaintext compilation phase")
    work = original(nonce, root)
    keyfile = work / "recipient-key.txt"
    pubfile = work / "recipient.agepub"
    if not keyfile.is_file() or not pubfile.is_file():
        raise RuntimeError("Ephemeral runner bootstrap is missing")
    output = staged(nonce, root)
    output.mkdir(mode=0o700)
    try:
        # GitHub may take time to expose a published prerelease asset publicly.
        ciphertext = work / "source.age"
        import time
        for attempt in range(150):
            try:
                download_source("ci-opaque-" + nonce, ciphertext)
                break
            except Exception as error:
                if ciphertext.exists() or ciphertext.is_symlink():
                    raise
                if attempt == 149:
                    raise RuntimeError("Encrypted private source never became visible") from error
                time.sleep(4)
        unsealed = subprocess.run(
            [str(relay.AGE), "-d", "-i", str(keyfile), str(ciphertext)],
            capture_output=True, timeout=40, check=True).stdout
        relay.verify_bundle_commitment(unsealed, commitment)
        inputs = relay.read_packet(unsealed, nonce, sha)
        ciphertext.unlink()
        relay.unpack_into(inputs, work)
        # The parent Python transport may hold a PUBLIC-repo-only token to
        # stream ciphertext. Strip its credentials and ALL known Actions
        # control variables before spawning an arbitrary PowerShell script.
        # This is process-environment hygiene, NOT isolation from a malicious
        # same-user process on the GitHub-hosted runner.
        env = relay.isolated_build_environment()
        # No public/private repository token is present in the Python
        # transport OR its PowerShell child during compilation. The complete
        # byte-for-byte combined log is encrypted now and only published in
        # the following separate token-bearing step, after workspace cleanup.
        returncode, log = relay.capture_private_build(work, env)
        with (output / "result-log.age").open("wb") as writer:
            writer.write(subprocess.run(
                [str(relay.AGE), "-r", recipient], input=log,
                capture_output=True, check=True, timeout=70).stdout)
        binary_sha = "0" * 64
        exe = work / "ci-out" / "program.exe"
        if returncode == 0:
            binary_sha = encrypt_binary_file(
                exe, output / "result-exe.age", recipient, timeout=70)
        status = {"nonce": nonce, "source_commit": sha, "exit_code": returncode,
                  "log_sha256": hashlib.sha256(log).hexdigest(),
                  "binary_sha256": binary_sha}
        (output / "result-status.age").write_bytes(subprocess.run(
            [str(relay.AGE), "-r", recipient],
            input=json.dumps(status, sort_keys=True).encode("ascii"),
            capture_output=True, check=True, timeout=35).stdout)
        (output / "result-status.json").write_text(
            json.dumps(status, sort_keys=True), encoding="ascii")
        shutil.copyfile(pubfile, output / "recipient.agepub")
        print("MSVC work finished; only encrypted output retained for upload",
              flush=True)
    finally:
        # Destroy decrypted source/build script and ephemeral decryption key
        # before returning to a step allowed PUBLIC release-write access.
        shutil.rmtree(work, ignore_errors=False)


def publish():
    nonce, sha, recipient, _commitment, root = context()
    if not os.environ.get("GH_TOKEN"):
        raise RuntimeError("PUBLIC release upload credential not configured")
    output = staged(nonce, root)
    status = json.loads((output / "result-status.json").read_text("ascii"))
    pub_recipient = (output / "recipient.agepub").read_text("ascii").strip()
    if relay.RECIPIENT.fullmatch(pub_recipient) is None:
        raise RuntimeError("Invalid prior ephemeral public recipient")
    aud = relay.oidc_result_audience(
        nonce, sha, recipient, pub_recipient, status)
    proof = output / "result.oidc"
    proof.write_text(relay.github_runner_oidc(aud) + "\n", encoding="ascii")
    files = [output / "result-log.age", output / "result-status.age", proof]
    if status["exit_code"] == 0:
        files.append(output / "result-exe.age")
    if not all(p.is_file() and not p.is_symlink() for p in files):
        raise RuntimeError("Missing verified encrypted Windows results")
    relay.gh("release", "upload", "ci-opaque-" + nonce, "--repo",
             relay.PUBLIC_REPO, *(str(file) for file in files))
    shutil.rmtree(output)
    print("Encrypted MSVC results returned; public logs omit private diagnostics",
          flush=True)
    if status["exit_code"] != 0:
        raise RuntimeError("Private encrypted build failed; private coordinator has the log")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("bootstrap", "compile", "publish"))
    args = parser.parse_args()
    if args.phase == "bootstrap":
        bootstrap()
    elif args.phase == "compile":
        compile_private()
    else:
        publish()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Token-isolated encrypted MSVC stage failed; see private-side diagnostics",
              file=sys.stderr)
        raise SystemExit(1)
