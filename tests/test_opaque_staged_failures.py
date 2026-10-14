"""Local failure-path proofs for token-isolated encrypted MSVC stages.

These do not contact GitHub or start hosted runners. They ensure that private
diagnostics are still delivered encrypted when MSVC fails, while plaintext
build inputs and the one-use decryption identity are destroyed before upload.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import opaque_runner as relay
from tools import opaque_staged_runner as worker
from tests.test_opaque_staged_runner import NONCE, SHA, zip_bundle


@unittest.skipUnless(relay.AGE.is_file() and relay.KEYGEN.is_file(),
                     "Requires pinned local age executables")
class StagedMSVCFailureTests(unittest.TestCase):
    def private_identity(self, root):
        key = root / "private-return-key"
        result = subprocess.run([str(relay.KEYGEN), "-o", str(key)],
                                capture_output=True, text=True, check=True)
        recipient = re.search(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}",
                              result.stderr).group()
        return key, recipient

    def environment(self, root, recipient, bundle):
        env = {k: v for k, v in os.environ.items()
               if k not in ("GH_TOKEN", "GITHUB_TOKEN")}
        env.update({"CI_NONCE": NONCE, "CI_PRIVATE_SHA": SHA,
                    "CI_OUTPUT_RECIPIENT": recipient,
                    "CI_BUNDLE_SHA256": hashlib.sha256(bundle).hexdigest(),
                    "GITHUB_REPOSITORY": relay.PUBLIC_REPO,
                    "RUNNER_TEMP": str(root)})
        return env

    def run_bootstrap(self, env, uploaded):
        def send(*args):
            self.assertEqual(args[:2], ("release", "upload"))
            for filename in args[5:]:
                asset = Path(filename)
                uploaded[asset.name] = asset.read_bytes()
            return ""

        with (patch.dict(os.environ, {**env, "GH_TOKEN": "public-only"}, clear=True),
              patch.object(relay, "gh", side_effect=send),
              patch.object(relay, "github_runner_oidc",
                           return_value="signed.synthetic.jwt")):
            worker.bootstrap()
        return send

    def decrypt(self, key, blob):
        return subprocess.run([str(relay.AGE), "-d", "-i", str(key)],
                              input=blob, capture_output=True, check=True).stdout

    def test_failed_msvc_sends_encrypted_verbatim_log_and_signed_status(self):
        bundle = zip_bundle()
        with tempfile.TemporaryDirectory(prefix="msvc-private-failure-") as temp:
            root = Path(temp)
            private_key, private_recipient = self.private_identity(root)
            env = self.environment(root, private_recipient, bundle)
            uploaded = {}
            uploader = self.run_bootstrap(env, uploaded)

            def source_download(tag, destination):
                self.assertEqual(tag, "ci-opaque-" + NONCE)
                worker_recipient = uploaded["recipient.agepub"].decode().strip()
                encrypted = subprocess.run([str(relay.AGE), "-r", worker_recipient],
                                           input=bundle, capture_output=True,
                                           check=True).stdout
                destination.write_bytes(encrypted)

            diagnostics = b"error C2065: 'synthetic': undeclared identifier\r\n"

            def failing_build(work, child_env, *, on_chunk=None):
                for forbidden in ("GH_TOKEN", "GITHUB_TOKEN",
                                  "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GITHUB_ENV"):
                    self.assertNotIn(forbidden, child_env)
                self.assertTrue((work / "build.ps1").is_file())
                return 1, diagnostics

            with (patch.dict(os.environ, env, clear=True),
                  patch.object(worker, "download_source", side_effect=source_download),
                  patch.object(relay, "capture_private_build", side_effect=failing_build)):
                worker.compile_private()
            self.assertFalse(worker.original(NONCE, root).exists())
            outbound = worker.staged(NONCE, root)
            self.assertFalse((outbound / "result-exe.age").exists())
            self.assertFalse((outbound / "build.ps1").exists())
            self.assertFalse((outbound / "recipient-key.txt").exists())

            with (patch.dict(os.environ, {**env, "GH_TOKEN": "public-only"}, clear=True),
                  patch.object(relay, "gh", side_effect=uploader),
                  patch.object(relay, "github_runner_oidc",
                               return_value="signed.failure.jwt")):
                with self.assertRaisesRegex(RuntimeError, "Private encrypted build failed"):
                    worker.publish()
            self.assertFalse(outbound.exists())
            self.assertEqual(set(uploaded), {
                "recipient.agepub", "recipient.oidc", "result-log.age",
                "result-status.age", "result.oidc"})
            self.assertNotIn(diagnostics, b"".join(uploaded.values()))
            self.assertEqual(self.decrypt(private_key, uploaded["result-log.age"]),
                             diagnostics)
            status = json.loads(self.decrypt(private_key, uploaded["result-status.age"]))
            self.assertEqual(status["exit_code"], 1)
            self.assertEqual(status["log_sha256"], hashlib.sha256(diagnostics).hexdigest())
            self.assertEqual(status["binary_sha256"], "0" * 64)

    def test_wrong_private_bundle_commitment_never_executes_script(self):
        bundle = zip_bundle()
        with tempfile.TemporaryDirectory(prefix="msvc-bundle-mismatch-") as temp:
            root = Path(temp)
            _private_key, private_recipient = self.private_identity(root)
            env = self.environment(root, private_recipient, bundle)
            env["CI_BUNDLE_SHA256"] = "b" * 64
            uploaded = {}
            self.run_bootstrap(env, uploaded)

            def source_download(_tag, destination):
                worker_recipient = uploaded["recipient.agepub"].decode().strip()
                ciphertext = subprocess.run([str(relay.AGE), "-r", worker_recipient],
                                            input=bundle, capture_output=True,
                                            check=True).stdout
                destination.write_bytes(ciphertext)

            with (patch.dict(os.environ, env, clear=True),
                  patch.object(worker, "download_source", side_effect=source_download),
                  patch.object(relay, "capture_private_build") as build):
                with self.assertRaisesRegex(ValueError, "private build commitment"):
                    worker.compile_private()
            build.assert_not_called()
            self.assertFalse(worker.original(NONCE, root).exists())
            self.assertNotIn("result-log.age", uploaded)
            self.assertNotIn("result-status.age", uploaded)


if __name__ == "__main__":
    unittest.main()
