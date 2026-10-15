"""PUBLIC compiler children must not inherit the transport GitHub token.

Unit tests use a synthetic ZIP and real local age keys when available, but
NEVER dispatch GitHub Actions or access private user source.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools import opaque_runner as relay
from tools import opaque_staged_runner as worker

NONCE = "a" * 24
SHA = "b" * 40
SALT = "c" * 64


def zip_bundle():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("manifest.json", json.dumps({
            "nonce": NONCE, "source_commit": SHA,
            "commitment_salt": SALT, "output": "ci-out/program.exe",
        }))
        archive.writestr("CMakeLists.txt", b"cmake_minimum_required(VERSION 3.16)\n")
        archive.writestr("src/synthetic_adder.cpp", b"int main(){return 0;}\n")
        archive.writestr("build.ps1", b"Write-Host synthetic\n")
    return output.getvalue()


@unittest.skipUnless(relay.AGE.is_file() and relay.KEYGEN.is_file(),
                     "Requires local pinned age and age-keygen executables")
class StagedMSVCWorkflowTests(unittest.TestCase):
    def test_stream_msvc_binary_to_age_without_reading_it_into_python_memory(self):
        with tempfile.TemporaryDirectory(prefix="opaque-streamed-pe-") as scratch:
            root = Path(scratch)
            identity = root / "return-key"
            result = subprocess.run([str(relay.KEYGEN), "-o", str(identity)],
                                    capture_output=True, text=True, check=True,
                                    timeout=15)
            recipient = re.search(
                r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}",
                result.stderr).group()
            source = root / "msvc.exe"
            output = root / "encrypted.age"
            binary = b"MZ" + (b"sample-pe-test-data" * 150000)
            source.write_bytes(binary)
            with patch.object(Path, "read_bytes",
                              side_effect=AssertionError("Whole-file read is forbidden")):
                digest = worker.encrypt_binary_file(source, output, recipient)
            self.assertEqual(digest, hashlib.sha256(binary).hexdigest())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            plaintext = subprocess.run(
                [str(relay.AGE), "-d", "-i", str(identity), str(output)],
                check=True, capture_output=True, timeout=20).stdout
            self.assertEqual(plaintext, binary)
            with self.assertRaisesRegex(RuntimeError, "input/output"):
                worker.encrypt_binary_file(source, output, recipient)
            self.assertEqual(output.stat().st_size > 0, True)

    def test_failed_streaming_encryption_removes_partial_ciphertext(self):
        with tempfile.TemporaryDirectory(prefix="opaque-streamed-fail-") as scratch:
            root = Path(scratch)
            source = root / "msvc.exe"
            source.write_bytes(b"MZ" + b"x" * 1400)
            target = root / "partial.age"

            def fail_after_writing(*_args, **kwargs):
                kwargs["stdout"].write(b"partial-private-encrypted-result")
                raise subprocess.CalledProcessError(1, _args[0])

            with patch.object(worker.subprocess, "run", side_effect=fail_after_writing):
                with self.assertRaises(subprocess.CalledProcessError):
                    worker.encrypt_binary_file(source, target, "age1" + "q" * 58)
            self.assertFalse(target.exists())
            with self.assertRaisesRegex(RuntimeError, "input/output"):
                worker.encrypt_binary_file(source, target, "invalid-public-key")
            self.assertFalse(target.exists())

    def test_three_phase_authenticated_ciphertext_roundtrip(self):
        source = zip_bundle()
        with tempfile.TemporaryDirectory(prefix="staged-opaque-test-") as scratch:
            root = Path(scratch)
            private = root / "private"
            private.mkdir()
            keyfile = private / "return-key"
            result = subprocess.run([str(relay.KEYGEN), "-o", str(keyfile)],
                                    capture_output=True, text=True, check=True)
            return_recipient = re.search(
                r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}",
                result.stderr).group()

            env = dict(os.environ)
            # Simulate the actual trusted launcher, which removes Actions
            # control paths as well as tokens before starting Python.
            for name in worker.FORBIDDEN_COMPILE_VARIABLES:
                env.pop(name, None)
            env.update({
                "CI_NONCE": NONCE,
                "CI_PRIVATE_SHA": SHA,
                "CI_OUTPUT_RECIPIENT": return_recipient,
                "CI_BUNDLE_SHA256": hashlib.sha256(source).hexdigest(),
                "GITHUB_REPOSITORY": relay.PUBLIC_REPO,
                "RUNNER_TEMP": str(root),
            })
            transfers = {}
            def fake_public_gh(*args):
                self.assertEqual(args[:2], ("release", "upload"))
                for path in args[5:]:
                    file = Path(path)
                    self.assertTrue(file.is_file())
                    transfers[file.name] = file.read_bytes()
                return ""
            def fake_download(tag, target):
                self.assertEqual(tag, "ci-opaque-" + NONCE)
                pub = transfers["recipient.agepub"].decode("ascii").strip()
                cipher = subprocess.run([str(relay.AGE), "-r", pub],
                                        input=source, capture_output=True,
                                        check=True).stdout
                target.write_bytes(cipher)
            def fake_build(work, run_env, *, on_chunk=None):
                for name in ("GH_TOKEN", "GITHUB_TOKEN",
                             "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GITHUB_ENV",
                             "GITHUB_PATH", "ACTIONS_RUNTIME_TOKEN",
                             "VSS_NUGET_EXTERNAL_FEED_ENDPOINTS",
                             "MY_API_KEY", "CUSTOM_PASSWORD",
                             "CI_OUTPUT_RECIPIENT", "CI_BUNDLE_SHA256"):
                    self.assertNotIn(name, run_env)
                self.assertEqual(run_env["CI"], "true")
                self.assertTrue((work / "build.ps1").is_file())
                self.assertTrue((work / "CMakeLists.txt").is_file())
                exe = work / "ci-out" / "program.exe"
                exe.parent.mkdir(exist_ok=True)
                exe.write_bytes(b"MZ" + b"sample binary" * 130)
                return 0, b"public MSVC log remains private\r\n"
            with (patch.object(relay, "gh", side_effect=fake_public_gh),
                  patch.object(relay, "github_runner_oidc",
                               return_value="signed.synthetic.jwt"),
                  patch.object(worker, "download_source", side_effect=fake_download),
                  patch.object(relay, "capture_private_build", side_effect=fake_build)):
                with patch.dict(os.environ, {**env, "GH_TOKEN": "PUBLIC_ONLY"} , clear=True):
                    worker.bootstrap()
                self.assertIn("recipient.agepub", transfers)
                self.assertIn("recipient.oidc", transfers)

                with patch.dict(os.environ, {
                        **env,
                        "VSS_NUGET_EXTERNAL_FEED_ENDPOINTS": "private-feed-secret",
                        "MY_API_KEY": "private-key-secret",
                        "CUSTOM_PASSWORD": "another-secret",
                    }, clear=True):
                    worker.compile_private()
                self.assertFalse(worker.original(NONCE, root).exists())
                self.assertTrue(worker.staged(NONCE, root).exists())
                self.assertFalse((worker.staged(NONCE, root) / "build.ps1").exists())
                self.assertFalse((worker.staged(NONCE, root) / "recipient-key.txt").exists())

                with patch.dict(os.environ, {**env, "GH_TOKEN": "PUBLIC_ONLY"}, clear=True):
                    worker.publish()
            self.assertFalse(worker.staged(NONCE, root).exists())
            self.assertEqual(set(transfers), {
                "recipient.agepub", "recipient.oidc", "result-log.age",
                "result-status.age", "result-exe.age", "result.oidc",
            })
            def decrypt(data):
                return subprocess.run(
                    [str(relay.AGE), "-d", "-i", str(keyfile)], input=data,
                    capture_output=True, check=True).stdout
            log = decrypt(transfers["result-log.age"])
            binary = decrypt(transfers["result-exe.age"])
            status = json.loads(decrypt(transfers["result-status.age"]))
            self.assertEqual(log, b"public MSVC log remains private\r\n")
            self.assertTrue(binary.startswith(b"MZ"))
            self.assertEqual(status["log_sha256"], hashlib.sha256(log).hexdigest())
            self.assertEqual(status["binary_sha256"], hashlib.sha256(binary).hexdigest())
            self.assertNotIn(b"public MSVC log", b"".join(transfers.values()))

    def test_refuse_implicit_github_token_during_compilation(self):
        with tempfile.TemporaryDirectory() as scratch:
            env = {
                "CI_NONCE": NONCE, "CI_PRIVATE_SHA": SHA,
                "CI_OUTPUT_RECIPIENT": "age1" + "q" * 58,
                "CI_BUNDLE_SHA256": "b" * 64,
                "GITHUB_REPOSITORY": relay.PUBLIC_REPO,
                "RUNNER_TEMP": scratch,
                "GITHUB_TOKEN": "SHOULD_NOT_EXIST",
            }
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(RuntimeError, "Refusing GitHub credential"):
                    worker.compile_private()
            env.pop("GITHUB_TOKEN")
            env["GH_TOKEN"] = "MUST_NOT_BE_PRESENT_DURING_COMPILATION"
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(RuntimeError, "Refusing GitHub credential"):
                    worker.compile_private()
            env.pop("GH_TOKEN")
            for secret_variable in (
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
                "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RUNTIME_URL", "GITHUB_ENV",
                "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STEP_SUMMARY",
            ):
                env[secret_variable] = "MUST_BE_SCRUBBED"
                with self.subTest(variable=secret_variable):
                    with patch.dict(os.environ, env, clear=True):
                        with self.assertRaisesRegex(RuntimeError, "Refusing GitHub credential"):
                            worker.compile_private()
                del env[secret_variable]

    def test_actual_workflow_compile_step_has_no_github_token(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/secure-opaque-build.yml").read_text()
        compile_step = workflow.split("- name: Compile without repository credentials", 1)[1]
        compile_step = compile_step.split("- name: Publish only ciphertext", 1)[0]
        self.assertNotIn("GH_TOKEN:", compile_step)
        self.assertNotIn("github.token", compile_step)
        for name in worker.FORBIDDEN_COMPILE_VARIABLES:
            self.assertIn(name, compile_step)
        self.assertIn("python -m tools.opaque_staged_runner compile", compile_step)


if __name__ == "__main__":
    unittest.main()
