"""The public MSVC worker must reject malformed encrypted source packets."""

import io
import json
from pathlib import Path
import os
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from tools.opaque_runner import (read_packet, RECIPIENT, MARKER,
                                 capture_private_build, oidc_audience,
                                 oidc_result_audience,
                                 github_runner_oidc, trusted_source_asset,
                                 receive_encrypted_source, safe_bundle_name,
                                 verify_bundle_commitment)


class OpaquePacketTests(unittest.TestCase):
    NONCE = "a" * 24
    SHA = "b" * 40

    def packet(self, filename="src/sample.cpp", content=b"int main(){}", nonce=None):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("manifest.json", json.dumps({
                "nonce": nonce or self.NONCE,
                "source_commit": self.SHA,
                "commitment_salt": "e" * 64,
                "output": "ci-out/program.exe",
            }))
            archive.writestr("build.ps1", b"Write-Output 'test'")
            archive.writestr(filename, content)
        return output.getvalue()

    def test_valid_private_packet(self):
        files = read_packet(self.packet(), self.NONCE, self.SHA)
        self.assertEqual(files["src/sample.cpp"], b"int main(){}")

    def test_privately_committed_zip_hash_blocks_substitution(self):
        import hashlib
        original = self.packet()
        digest = hashlib.sha256(original).hexdigest()
        self.assertIsNone(verify_bundle_commitment(original, digest))
        malicious = self.packet(content=b"int main(){return 42;}")
        self.assertNotEqual(original, malicious)
        self.assertEqual(read_packet(malicious, self.NONCE, self.SHA)[
            "src/sample.cpp"], b"int main(){return 42;}")
        with self.assertRaisesRegex(ValueError, "private build commitment"):
            verify_bundle_commitment(malicious, digest)
        with self.assertRaisesRegex(ValueError, "private build commitment"):
            verify_bundle_commitment(original, "not-a-sha256")

    def test_cmake_root_file_is_permitted(self):
        files = read_packet(self.packet("CMakeLists.txt"), self.NONCE, self.SHA)
        self.assertIn("CMakeLists.txt", files)

    def test_reject_path_traversal(self):
        for name in ("../secret", "src/../../secret", "/tmp/secret", "src\\secret"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                read_packet(self.packet(name), self.NONCE, self.SHA)

    def test_reject_sensitive_or_unexpected_member(self):
        for name in (".git/config", ".github/workflows/private.yml", ".env",
                     "PRIVATE_TOKEN.txt", "README.md"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                read_packet(self.packet(name), self.NONCE, self.SHA)

    def test_reject_windows_reserved_ads_and_unsafe_names(self):
        invalid = ("src/CON.txt", "src/AUX", "include/COM1.h", "vendor/Lpt9.lib",
                   "src/source.cpp:payload", "src/trailing.", "src/.hidden",
                   "src/foo bar.cpp", "src/foo\\bar.cpp", "src/foo//bar.cpp",
                   "src/a?b.h", "src/clock$", "src/directory/../escape.h")
        for name in invalid:
            with self.subTest(name=name):
                self.assertFalse(safe_bundle_name(name))
                with self.assertRaisesRegex(ValueError, "Invalid encrypted"):
                    read_packet(self.packet(name), self.NONCE, self.SHA)
        for name in ("CMakeLists.txt", "src/_internal.cc",
                     "include/core-v2/header.hpp", "vendor/lib3/archive.lib"):
            with self.subTest(name=name):
                self.assertTrue(safe_bundle_name(name))

    def test_reject_archive_names_colliding_on_windows(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("manifest.json", json.dumps({
                "nonce": self.NONCE, "source_commit": self.SHA,
                "output": "ci-out/program.exe"}))
            archive.writestr("build.ps1", b"exit 0")
            archive.writestr("src/Main.cpp", b"int x;")
            archive.writestr("src/main.cpp", b"int y;")
        with self.assertRaisesRegex(ValueError, "Invalid encrypted"):
            read_packet(output.getvalue(), self.NONCE, self.SHA)

    def test_wrong_nonce_or_commit_fails_closed(self):
        with self.assertRaises(ValueError):
            read_packet(self.packet(), "c" * 24, self.SHA)
        with self.assertRaises(ValueError):
            read_packet(self.packet(), self.NONCE, "d" * 40)

    def test_invalid_recipient_and_release_tag(self):
        self.assertIsNotNone(RECIPIENT.fullmatch("age1" + "q" * 58))
        self.assertIsNone(RECIPIENT.fullmatch("AGE-SECRET-KEY-" + "q" * 50))
        self.assertIsNotNone(MARKER.fullmatch("ci-opaque-" + self.NONCE))

    def test_oidc_recipient_audience_binds_every_input(self):
        a, b = "age1" + "q" * 58, "age1" + "p" * 58
        original = oidc_audience(self.NONCE, self.SHA, a, b)
        self.assertRegex(original, r"^ci-opaque-v1:[0-9a-f]{64}$")
        for case in (("c" * 24, self.SHA, a, b),
                     (self.NONCE, "d" * 40, a, b),
                     (self.NONCE, self.SHA, "age1" + "x" * 58, b),
                     (self.NONCE, self.SHA, a, "age1" + "z" * 58)):
            self.assertNotEqual(oidc_audience(*case), original)

    def test_oidc_result_audience_binds_log_executable_and_exit(self):
        a, b = "age1" + "q" * 58, "age1" + "p" * 58
        status = {"nonce": self.NONCE, "source_commit": self.SHA,
                  "exit_code": 0, "log_sha256": "c" * 64,
                  "binary_sha256": "d" * 64}
        original = oidc_result_audience(self.NONCE, self.SHA, a, b, status)
        self.assertRegex(original, r"^ci-opaque-result-v1:[0-9a-f]{64}$")
        for key, changed in (("log_sha256", "e" * 64),
                             ("binary_sha256", "f" * 64),
                             ("exit_code", 1)):
            modified = dict(status, **{key: changed})
            self.assertNotEqual(original,
                                oidc_result_audience(self.NONCE, self.SHA,
                                                     a, b, modified))
        with self.assertRaises(ValueError):
            oidc_result_audience(self.NONCE, self.SHA, a, b,
                                 dict(status, binary_sha256="INVALID"))

    def test_oidc_request_uses_github_endpoint(self):
        import tools.opaque_runner as module

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self):
                return b'{"value":"header.payload.signature"}'

        captured = {}

        def fake_urlopen(req, timeout):
            captured["url"] = req.full_url
            captured["auth"] = req.get_header("Authorization")
            captured["timeout"] = timeout
            return FakeResponse()

        variables = {
            "ACTIONS_ID_TOKEN_REQUEST_URL":
                "https://pipelines.actions.githubusercontent.com/test?x=1",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "test-oidc-request-bearer",
        }
        with patch.dict(os.environ, variables), patch.object(module, "urlopen", fake_urlopen):
            self.assertEqual(github_runner_oidc("ci-opaque-v1:test"),
                             "header.payload.signature")
        self.assertIn("audience=ci-opaque-v1%3Atest", captured["url"])
        self.assertEqual(captured["auth"], "Bearer test-oidc-request-bearer")
        self.assertEqual(captured["timeout"], 20)

    def test_oidc_request_refuses_non_github_hosts(self):
        import tools.opaque_runner as module
        for endpoint in ("http://pipelines.actions.githubusercontent.com/token",
                         "https://evil.example/token",
                         "https://pipelines.actions.githubusercontent.com.evil.com/token",
                         "https://pipelines.actions.githubusercontent.com:666/token"):
            with self.subTest(endpoint=endpoint), patch.dict(os.environ, {
                    "ACTIONS_ID_TOKEN_REQUEST_URL": endpoint,
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "sample",
                }), patch.object(module, "urlopen") as request:
                with self.assertRaises(RuntimeError):
                    github_runner_oidc("ci-opaque-v1:test")
                request.assert_not_called()

    def test_capture_real_combined_stdout_and_stderr_unmodified(self):
        with tempfile.TemporaryDirectory() as temp:
            command = [sys.executable, "-c",
                       "import sys;sys.stdout.buffer.write(b'first\\r\\n');"
                       "sys.stdout.flush();sys.stderr.buffer.write(b'error\\r\\n');"
                       "sys.stderr.flush()"]
            status, log = capture_private_build(Path(temp), os.environ.copy(),
                                                command=command, timeout=5)
            self.assertEqual(status, 0)
            self.assertEqual(log, b"first\r\nerror\r\n")

    def test_timeout_retains_private_partial_log(self):
        with tempfile.TemporaryDirectory() as temp:
            command = [sys.executable, "-c",
                       "import sys,time;sys.stdout.buffer.write(b'partial\\r\\n');"
                       "sys.stdout.flush();time.sleep(4)"]
            status, log = capture_private_build(Path(temp), os.environ.copy(),
                                                command=command, timeout=0.4)
            self.assertEqual(status, 124)
            self.assertEqual(log, b"partial\r\n")

    def test_refuse_unbounded_output_and_unsafe_path(self):
        with tempfile.TemporaryDirectory() as temp:
            command = [sys.executable, "-c", "print('a' * 20000)"]
            with patch("tools.opaque_runner.MAX_LOG", 100):
                with self.assertRaisesRegex(RuntimeError, "exceeds size"):
                    capture_private_build(Path(temp), os.environ.copy(),
                                          command=command, timeout=5)
            # Even a runaway child cannot fill the disk while we wait for it.
            self.assertLessEqual((Path(temp) / "msvc-private-output.bin").stat().st_size,
                                 100)
            with self.assertRaisesRegex(RuntimeError, "not clean"):
                capture_private_build(Path(temp), os.environ.copy(),
                                      command=command, timeout=5)

    def test_failed_build_preserves_unmodified_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            command = [sys.executable, "-c",
                       "import sys;sys.stdout.buffer.write(b'compiler failed\\r\\n');"
                       "sys.stdout.flush();sys.exit(23)"]
            returncode, log = capture_private_build(Path(temp), os.environ.copy(),
                                                   command=command, timeout=5)
            self.assertEqual(returncode, 23)
            self.assertEqual(log, b"compiler failed\r\n")

    def test_ciphertext_source_requires_expected_prerelease_digest(self):
        import hashlib
        tag = "ci-opaque-" + self.NONCE
        ciphertext = b"synthetic authenticated ciphertext"
        release = {
            "tag_name": tag, "draft": False, "prerelease": True,
            "body": "Short-lived encrypted synthetic MSVC test; no plaintext inputs.",
            "assets": [{"id": 15, "name": "source.age", "state": "uploaded",
                        "size": len(ciphertext),
                        "digest": "sha256:" + hashlib.sha256(ciphertext).hexdigest()}],
        }
        self.assertEqual(trusted_source_asset(release, tag)["size"], len(ciphertext))
        release["draft"] = True
        with self.assertRaisesRegex(ValueError, "Untrusted"):
            trusted_source_asset(release, tag)
        release["draft"] = False
        release["assets"][0]["digest"] = "unverified"
        with self.assertRaisesRegex(ValueError, "digest"):
            trusted_source_asset(release, tag)
        release["assets"][0]["digest"] = "sha256:" + hashlib.sha256(ciphertext).hexdigest()
        release["assets"].append(dict(release["assets"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            trusted_source_asset(release, tag)

    def test_ciphertext_download_checks_sha_before_accepting(self):
        import hashlib
        tag = "ci-opaque-" + self.NONCE
        ciphertext = b"synthetic authenticated ciphertext"
        release = {
            "tag_name": tag, "draft": False, "prerelease": True,
            "body": "Short-lived encrypted synthetic MSVC test; no plaintext inputs.",
            "assets": [{"id": 15, "name": "source.age", "state": "uploaded",
                        "size": len(ciphertext),
                        "digest": "sha256:" + hashlib.sha256(ciphertext).hexdigest()}],
        }

        def mock_gh(*args):
            if args[0] == "api":
                return json.dumps(release)
            if args[:2] == ("release", "download"):
                (Path(args[-1]) / "source.age").write_bytes(ciphertext)
                return ""
            raise AssertionError("Unexpected GitHub operation")

        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            with patch("tools.opaque_runner.gh", side_effect=mock_gh):
                local = receive_encrypted_source(tag, work, retries=1)
            self.assertEqual(local.read_bytes(), ciphertext)
            local.unlink()
            release["assets"][0]["digest"] = "sha256:" + "e" * 64
            with patch("tools.opaque_runner.gh", side_effect=mock_gh):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    receive_encrypted_source(tag, work, retries=1)
            self.assertFalse(local.exists())
            self.assertFalse(list(work.glob(".cipher-in-*")))


if __name__ == "__main__":
    unittest.main()
