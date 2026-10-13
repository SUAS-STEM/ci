"""PUBLIC runner of encrypted synthetic/MSVC build packets.

Only publicly visible workflow/job metadata and generic status messages are
printed. The source, the user's .ps1 and compiler output are not printed.
This is NOT protection against privileged runner infrastructure access.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
AGE = ROOT / ".age-bin" / ("age.exe" if os.name == "nt" else "age")
KEYGEN = ROOT / ".age-bin" / ("age-keygen.exe" if os.name == "nt" else "age-keygen")
PUBLIC_REPO = "SUAS-STEM/ci-relay-lab"
MARKER = re.compile(r"ci-opaque-[0-9a-f]{24}\Z")
RECIPIENT = re.compile(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}\Z")
MAX_PACKET = 25 * 1024 * 1024
MAX_SOURCE = 60 * 1024 * 1024


def gh(*args):
    return subprocess.run(["gh", *args], check=True, capture_output=True,
                          text=True, timeout=80).stdout


def read_packet(blob, nonce, source_commit):
    if len(blob) > MAX_SOURCE or not blob.startswith(b"PK\x03\x04"):
        raise ValueError("Invalid decrypted build bundle")
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        members = archive.infolist()
        if not 2 <= len(members) <= 300:
            raise ValueError("Unexpected bundle file count")
        files = {}
        total = 0
        for member in members:
            name = member.filename
            path = Path(name)
            if (name.startswith("/") or "\\" in name or ".." in path.parts
                    or path.is_absolute() or not name.isascii()
                    or not (name in ("manifest.json", "build.ps1", "CMakeLists.txt")
                            or any(name.startswith(folder) for folder in
                                   ("src/", "include/", "cmake/", "vendor/")))
                    or name in files or member.is_dir()
                    or ((member.external_attr >> 16) & 0o170000) == 0o120000
                    or member.file_size > 3 * 1024 * 1024):
                raise ValueError("Invalid encrypted archive member")
            total += member.file_size
            if total > MAX_SOURCE:
                raise ValueError("Encrypted archive too large")
            files[name] = archive.read(member)
    if "manifest.json" not in files or "build.ps1" not in files:
        raise ValueError("Required private source/build script missing")
    manifest = json.loads(files.pop("manifest.json"))
    if (manifest.get("nonce") != nonce
            or manifest.get("source_commit") != source_commit
            or manifest.get("output") != "ci-out/program.exe"):
        raise ValueError("Build package provenance mismatch")
    return files


def unpack_into(files, work):
    for name, content in files.items():
        dest = work.joinpath(*name.split("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() or dest.is_symlink():
            raise ValueError("Duplicate or unsafe extracted input")
        dest.write_bytes(content)


def _install_and_build(nonce, source_commit, recipient, keyfile, work):
    tag = "ci-opaque-" + nonce
    incoming = work / "source.age"
    for _ in range(150):
        try:
            gh("release", "download", tag, "--repo", PUBLIC_REPO,
               "--pattern", "source.age", "--dir", str(work))
            break
        except subprocess.CalledProcessError:
            time.sleep(4)
    if not incoming.is_file() or incoming.stat().st_size > MAX_PACKET:
        raise RuntimeError("Encrypted build input was not received")
    decrypted = subprocess.run(
        [str(AGE), "-d", "-i", str(keyfile), str(incoming)],
        check=True, capture_output=True, timeout=30,
    ).stdout
    files = read_packet(decrypted, nonce, source_commit)
    incoming.unlink()
    unpack_into(files, work)
    env = dict(os.environ)
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_RUNTIME_URL"):
        env.pop(key, None)
    env["CI"] = "true"
    proc = subprocess.run(
        ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(work / "build.ps1")],
        cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=1200,
    )
    if len(proc.stdout) > 64 * 1024 * 1024:
        raise RuntimeError("Encrypted build log exceeds size limit")
    # Preserve the exact combined output byte stream, including errors.
    log = proc.stdout
    encrypted = subprocess.run([str(AGE), "-r", recipient],
                               input=log, capture_output=True,
                               check=True, timeout=30).stdout
    (work / "result-log.age").write_bytes(encrypted)
    status = json.dumps({"nonce": nonce, "source_commit": source_commit,
                         "exit_code": proc.returncode,
                         "log_sha256": hashlib.sha256(log).hexdigest()},
                        sort_keys=True).encode("ascii")
    (work / "result-status.age").write_bytes(
        subprocess.run([str(AGE), "-r", recipient], input=status,
                       capture_output=True, check=True, timeout=30).stdout)
    output = work / "ci-out" / "program.exe"
    if proc.returncode == 0:
        if (not output.is_file() or output.is_symlink()
                or not 1024 < output.stat().st_size < 100 * 1024 * 1024
                or not output.read_bytes().startswith(b"MZ")):
            raise RuntimeError("Expected compiled Windows executable missing")
        with output.open("rb") as source:
            binary = source.read()
        ciphertext = subprocess.run([str(AGE), "-r", recipient], input=binary,
                                    capture_output=True, check=True, timeout=50).stdout
        (work / "result-exe.age").write_bytes(ciphertext)
    return proc.returncode


def main():
    nonce = os.environ["CI_NONCE"]
    sha = os.environ["CI_PRIVATE_SHA"]
    recipient = os.environ["CI_OUTPUT_RECIPIENT"]
    if (not re.fullmatch(r"[0-9a-f]{24}", nonce)
            or not re.fullmatch(r"[0-9a-f]{40}", sha)
            or RECIPIENT.fullmatch(recipient) is None
            or os.environ.get("GITHUB_REPOSITORY") != PUBLIC_REPO):
        raise ValueError("Unsafe encrypted build metadata")
    runner = Path(os.environ["RUNNER_TEMP"]) / ("ci-opaque-" + nonce)
    runner.mkdir(mode=0o700)
    print("Opaque bootstrap: workspace ready", flush=True)
    identity = runner / "recipient-key.txt"
    produced = subprocess.run([str(KEYGEN), "-o", str(identity)],
                              check=True, capture_output=True, text=True, timeout=30)
    print("Opaque bootstrap: key generator succeeded", flush=True)
    match = re.search(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", produced.stderr)
    if match is None:
        raise RuntimeError("Unable to create one-time encryption identity")
    print("Opaque bootstrap: recipient syntax verified", flush=True)
    pub = runner / "recipient.agepub"
    pub.write_text(match.group() + "\n", encoding="ascii")
    tag = "ci-opaque-" + nonce
    gh("release", "upload", tag, "--repo", PUBLIC_REPO, str(pub))
    print("One-time public encryption recipient advertised; awaiting encrypted input", flush=True)
    build_rc = _install_and_build(nonce, sha, recipient, identity, runner)
    uploads = [str(runner / "result-log.age"), str(runner / "result-status.age")]
    if build_rc == 0:
        uploads.append(str(runner / "result-exe.age"))
    gh("release", "upload", tag, "--repo", PUBLIC_REPO, *uploads)
    print("Encrypted MSVC result transferred; raw build logs suppressed", flush=True)
    if build_rc:
        raise RuntimeError("Encrypted MSVC build failed; private coordinator has diagnostics")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Public workflow logs should not echo private filenames, command
        # arguments, source identifiers, stdout or stderr.
        print("Encrypted build worker failed; inspect private diagnostics if delivered", file=sys.stderr)
        raise SystemExit(1)
