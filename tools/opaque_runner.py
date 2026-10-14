"""PUBLIC runner of encrypted synthetic/MSVC build packets.

Only publicly visible workflow/job metadata and generic status messages are
printed. The source, the user's .ps1 and compiler output are not printed.
This is NOT protection against privileged runner infrastructure access.
"""

import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
import zipfile

ROOT = Path(__file__).resolve().parents[1]
AGE = ROOT / ".age-bin" / ("age.exe" if os.name == "nt" else "age")
KEYGEN = ROOT / ".age-bin" / ("age-keygen.exe" if os.name == "nt" else "age-keygen")
PUBLIC_REPO = "SUAS-STEM/ci-relay-lab"
MARKER = re.compile(r"ci-opaque-[0-9a-f]{24}\Z")
RECIPIENT = re.compile(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}\Z")
MAX_PACKET = 25 * 1024 * 1024
MAX_SOURCE = 60 * 1024 * 1024
MAX_LOG = 64 * 1024 * 1024
WINDOWS_DEVICES = frozenset(("CON", "PRN", "AUX", "NUL",
                             *(f"COM{i}" for i in range(1, 10)),
                             *(f"LPT{i}" for i in range(1, 10))))
SOURCE_DIRS = ("src", "include", "cmake", "vendor")


def safe_bundle_name(name):
    """Reject Windows reserved names, ADS, hidden paths and traversal.

    Git tracks case-sensitive names on Linux, but the target MSVC runner uses
    case-insensitive Windows paths. Only a restricted portable path subset is
    accepted to prevent overwritten inputs or alternate data streams.
    """
    if not isinstance(name, str) or not name.isascii() or len(name) > 240:
        return False
    parts = name.split("/")
    if not 1 <= len(parts) <= 12:
        return False
    if not (name in ("manifest.json", "build.ps1", "CMakeLists.txt")
            or (len(parts) >= 2 and parts[0] in SOURCE_DIRS)):
        return False
    for part in parts:
        if (not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", part)
                or part.endswith(".")
                or part.split(".", 1)[0].upper() in WINDOWS_DEVICES):
            return False
    return True


def oidc_audience(nonce, private_sha, private_recipient, worker_recipient):
    """Must match the independently validated PRIVATE coordinator encoding."""
    if (not re.fullmatch(r"[0-9a-f]{24}", nonce)
            or not re.fullmatch(r"[0-9a-f]{40}", private_sha)
            or RECIPIENT.fullmatch(private_recipient) is None
            or RECIPIENT.fullmatch(worker_recipient) is None):
        raise ValueError("Invalid OIDC audience input")
    fields = ("ci-opaque-v1", nonce, private_sha,
              private_recipient, worker_recipient)
    return "ci-opaque-v1:" + hashlib.sha256(
        "\x00".join(fields).encode("ascii")).hexdigest()


def oidc_result_audience(nonce, private_sha, private_recipient,
                         worker_recipient, status):
    """GitHub-sign exact MSVC result hashes and exit status for this run."""
    # Validate all recipient/commit/nonce fields with the same input proof.
    oidc_audience(nonce, private_sha, private_recipient, worker_recipient)
    if (not isinstance(status, dict)
            or status.get("nonce") != nonce
            or status.get("source_commit") != private_sha
            or type(status.get("exit_code")) is not int
            or not -(2**31) <= status["exit_code"] <= 2**32 - 1
            or not isinstance(status.get("log_sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}", status["log_sha256"]) is None
            or not isinstance(status.get("binary_sha256"), str)
            or re.fullmatch(r"[a-f0-9]{64}", status["binary_sha256"]) is None):
        raise ValueError("Invalid authenticated MSVC result status")
    fields = ("ci-opaque-result-v1", nonce, private_sha, private_recipient,
              worker_recipient, str(status["exit_code"]),
              status["log_sha256"], status["binary_sha256"])
    return "ci-opaque-result-v1:" + hashlib.sha256(
        "\x00".join(fields).encode("ascii")).hexdigest()


def github_runner_oidc(audience):
    """Obtain GitHub-signed runner OIDC proof without exposing bearer token."""
    endpoint = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    parsed = urlsplit(endpoint)
    if (not endpoint.startswith("https://") or not bearer
            or parsed.hostname is None
            or not parsed.hostname.endswith(".actions.githubusercontent.com")
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.fragment or len(endpoint) > 2048):
        raise RuntimeError("GitHub Actions OIDC issuer unavailable")
    separator = "&" if "?" in endpoint else "?"
    address = endpoint + separator + "audience=" + quote(audience, safe="")
    with urlopen(Request(address, headers={"Authorization": "Bearer " + bearer}),
                 timeout=20) as response:
        result = json.load(response)
    proof = result.get("value") if isinstance(result, dict) else None
    if (not isinstance(proof, str) or len(proof) > 16000
            or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", proof)):
        raise RuntimeError("Missing or malformed runner identity proof")
    return proof


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
        windows_names = set()
        total = 0
        for member in members:
            name = member.filename
            normalized = name.casefold()
            if (not safe_bundle_name(name)
                    or normalized in windows_names or member.is_dir()
                    or ((member.external_attr >> 16) & 0o170000) == 0o120000
                    or member.file_size > 3 * 1024 * 1024):
                raise ValueError("Invalid encrypted archive member")
            total += member.file_size
            if total > MAX_SOURCE:
                raise ValueError("Encrypted archive too large")
            windows_names.add(normalized)
            files[name] = archive.read(member)
    if "manifest.json" not in files or "build.ps1" not in files:
        raise ValueError("Required private source/build script missing")
    manifest = json.loads(files.pop("manifest.json"))
    if (manifest.get("nonce") != nonce
            or manifest.get("source_commit") != source_commit
            or not isinstance(manifest.get("commitment_salt"), str)
            or re.fullmatch(r"[0-9a-f]{64}", manifest["commitment_salt"]) is None
            or manifest.get("output") != "ci-out/program.exe"):
        raise ValueError("Build package provenance mismatch")
    return files


def unpack_into(files, work):
    for name, content in files.items():
        if not safe_bundle_name(name) or name in ("manifest.json",):
            raise ValueError("Refusing unsafe private build input path")
        dest = work.joinpath(*name.split("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() or dest.is_symlink():
            raise ValueError("Duplicate or unsafe extracted input")
        dest.write_bytes(content)


def capture_private_build(work, env, *, command=None, timeout=1200):
    """Capture exact combined MSVC output privately, including timeouts.

    Drain the child pipe into a private file as it executes. Kill the child
    once its combined output exceeds MAX_LOG, rather than waiting for a
    potentially disk-filling build to exit. Never echo the output publicly.
    """
    log = work / "msvc-private-output.bin"
    if log.exists() or log.is_symlink():
        raise RuntimeError("Private diagnostic output path is not clean")
    command = command or ["pwsh", "-NoLogo", "-NoProfile",
                          "-NonInteractive", "-File", str(work / "build.ps1")]
    descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        process = subprocess.Popen(command, cwd=work, env=env,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, bufsize=0)
        oversized = threading.Event()
        reader_error = []

        def drain():
            length = 0
            try:
                while True:
                    chunk = process.stdout.read(65536)
                    if not chunk:
                        break
                    if length + len(chunk) > MAX_LOG:
                        # Keep the original bounded prefix verbatim. Never
                        # publish a truncated log as a successful build.
                        output.write(chunk[:max(0, MAX_LOG - length)])
                        oversized.set()
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                        break
                    output.write(chunk)
                    length += len(chunk)
                output.flush()
            except (OSError, ValueError) as error:
                reader_error.append(error)
                try:
                    process.kill()
                except OSError:
                    pass

        reader = threading.Thread(target=drain, name="private-msvc-log-drain",
                                  daemon=True)
        reader.start()
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait(timeout=10)
            returncode = 124
        finally:
            reader.join(timeout=10)
            if reader.is_alive():
                process.stdout.close()
                raise RuntimeError("Private compiler log drain did not terminate")
            process.stdout.close()
        if reader_error:
            raise RuntimeError("Private compiler log capture failed") from reader_error[0]
        if oversized.is_set():
            raise RuntimeError("Encrypted build log exceeds size limit")
        if timed_out:
            returncode = 124
    return returncode, log.read_bytes()


def trusted_source_asset(release, tag):
    """Require the right encrypted prerelease and published source digest."""
    if (release.get("tag_name") != tag or release.get("draft") is not False
            or release.get("prerelease") is not True
            or release.get("body", "").strip() not in (
                "Short-lived encrypted synthetic build transfer; no plaintext source.",
                "Short-lived encrypted synthetic MSVC test; no plaintext inputs.")):
        raise ValueError("Untrusted encrypted transfer Release")
    found = [item for item in release.get("assets", [])
             if item.get("name") == "source.age"]
    if not found:
        return None
    if len(found) != 1:
        raise ValueError("Duplicate encrypted source upload")
    item = found[0]
    if (item.get("state") != "uploaded" or type(item.get("size")) is not int
            or not 0 < item["size"] < MAX_PACKET
            or not isinstance(item.get("digest"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]) is None):
        raise ValueError("Invalid encrypted source upload digest or size")
    return item


def receive_encrypted_source(tag, work, *, retries=150):
    """Download source into a fresh staging directory; never accept partials."""
    destination = work / "source.age"
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("Encrypted input was already present")
    for _ in range(retries):
        release = json.loads(gh("api", f"repos/{PUBLIC_REPO}/releases/tags/{tag}"))
        item = trusted_source_asset(release, tag)
        if item is not None:
            with tempfile.TemporaryDirectory(prefix=".cipher-in-", dir=work) as temp:
                staged = Path(temp) / "source.age"
                try:
                    gh("release", "download", tag, "--repo", PUBLIC_REPO,
                       "--pattern", "source.age", "--dir", str(temp))
                except subprocess.CalledProcessError:
                    time.sleep(4)
                    continue
                if (staged.is_symlink() or not staged.is_file()
                        or staged.stat().st_size != item["size"]):
                    raise ValueError("Incomplete encrypted source download")
                with staged.open("rb") as handle:
                    digest = "sha256:" + hashlib.file_digest(handle, "sha256").hexdigest()
                if digest != item["digest"]:
                    raise ValueError("Encrypted source does not match GitHub asset digest")
                staged.replace(destination)
                return destination
        time.sleep(4)
    raise TimeoutError("Encrypted build input was not received")


def verify_bundle_commitment(data, expected_sha256):
    """Require the exact privately committed plaintext ZIP, not just its nonce.

    Without this, a public Release asset writer could encrypt a different
    source bundle to the authenticated runner key and spoof the public nonce
    and source commit fields. The expected digest comes from workflow dispatch.
    """
    if (not isinstance(expected_sha256, str)
            or re.fullmatch(r"[a-f0-9]{64}", expected_sha256) is None
            or not isinstance(data, bytes)
            or not hmac.compare_digest(hashlib.sha256(data).hexdigest(),
                                        expected_sha256)):
        raise ValueError("Decrypted source differs from private build commitment")


def _install_and_build(nonce, source_commit, recipient, keyfile, work):
    tag = "ci-opaque-" + nonce
    incoming = receive_encrypted_source(tag, work)
    decrypted = subprocess.run(
        [str(AGE), "-d", "-i", str(keyfile), str(incoming)],
        check=True, capture_output=True, timeout=30,
    ).stdout
    verify_bundle_commitment(decrypted, os.environ["CI_BUNDLE_SHA256"])
    files = read_packet(decrypted, nonce, source_commit)
    incoming.unlink()
    unpack_into(files, work)
    env = dict(os.environ)
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_RUNTIME_URL"):
        env.pop(key, None)
    env["CI"] = "true"
    # Preserve exactly what the PowerShell process emitted, including errors.
    # Errors and timeouts still return an encrypted log and status file.
    returncode, log = capture_private_build(work, env)
    encrypted = subprocess.run([str(AGE), "-r", recipient],
                               input=log, capture_output=True,
                               check=True, timeout=30).stdout
    (work / "result-log.age").write_bytes(encrypted)
    binary_digest = "0" * 64
    output = work / "ci-out" / "program.exe"
    if returncode == 0:
        if (not output.is_file() or output.is_symlink()
                or not 1024 < output.stat().st_size < 100 * 1024 * 1024
                or not output.read_bytes().startswith(b"MZ")):
            raise RuntimeError("Expected compiled Windows executable missing")
        with output.open("rb") as source:
            binary = source.read()
        binary_digest = hashlib.sha256(binary).hexdigest()
        ciphertext = subprocess.run([str(AGE), "-r", recipient], input=binary,
                                    capture_output=True, check=True, timeout=50).stdout
        (work / "result-exe.age").write_bytes(ciphertext)
    status = {"nonce": nonce, "source_commit": source_commit,
              "exit_code": returncode,
              "log_sha256": hashlib.sha256(log).hexdigest(),
              "binary_sha256": binary_digest}
    (work / "result-status.age").write_bytes(
        subprocess.run([str(AGE), "-r", recipient],
                       input=json.dumps(status, sort_keys=True).encode("ascii"),
                       capture_output=True, check=True, timeout=30).stdout)
    return returncode, status


def main():
    nonce = os.environ["CI_NONCE"]
    sha = os.environ["CI_PRIVATE_SHA"]
    recipient = os.environ["CI_OUTPUT_RECIPIENT"]
    bundle_digest = os.environ["CI_BUNDLE_SHA256"]
    if (not re.fullmatch(r"[0-9a-f]{24}", nonce)
            or not re.fullmatch(r"[0-9a-f]{40}", sha)
            or not re.fullmatch(r"[0-9a-f]{64}", bundle_digest)
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
    audience = oidc_audience(nonce, sha, recipient, match.group())
    attestation = runner / "recipient.oidc"
    attestation.write_text(github_runner_oidc(audience) + "\n", encoding="ascii")
    tag = "ci-opaque-" + nonce
    gh("release", "upload", tag, "--repo", PUBLIC_REPO,
       str(pub), str(attestation))
    print("GitHub-signed one-time public encryption recipient advertised", flush=True)
    build_rc, status = _install_and_build(nonce, sha, recipient, identity, runner)
    # This second independently signed proof authenticates the returned MSVC
    # log and executable hashes, not merely the initial public input key.
    result_proof = runner / "result.oidc"
    result_proof.write_text(github_runner_oidc(oidc_result_audience(
        nonce, sha, recipient, match.group(), status)) + "\n", encoding="ascii")
    uploads = [str(runner / "result-log.age"), str(runner / "result-status.age"),
               str(result_proof)]
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
