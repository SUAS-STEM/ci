import os
from pathlib import Path
import unittest

from tools import public_guard


class PublicGuardTest(unittest.TestCase):
    def test_ci_workflow_uses_no_actions_artifact_storage(self):
        workflow = (public_guard.ROOT / ".github/workflows/fixture.yml").read_text()
        for forbidden in ("actions/upload-artifact", "actions/download-artifact",
                          "upload-artifact@", "download-artifact@",
                          "gh run download", "gh api repos/", "artifact-metadata: write"):
            self.assertNotIn(forbidden, workflow)
        self.assertIn("python -m tools.log_transport", workflow)
        self.assertIn("contents: read", workflow)

    def test_public_runner_never_gets_private_release_writer(self):
        workflow = (public_guard.ROOT / ".github/workflows/fixture.yml").read_text()
        for forbidden in ("GH_TOKEN:", "secrets.", "contents: write",
                          "SUAS-STEM/ci-release-vault", "gh release upload"):
            self.assertNotIn(forbidden, workflow)

    def test_current_public_tree_passes(self):
        public_guard.check_tree(public_guard.ROOT)

    def test_reject_private_source_in_any_new_path(self):
        with self.assertRaises(ValueError):
            public_guard.check_paths(set(public_guard.ALLOWED_FILES) | {"gcs/private_build.cpp"})

    def test_reject_symlinked_source(self):
        self.assertFalse((public_guard.ROOT / "src" / "synthetic_adder.cpp").is_symlink())

    def test_no_proprietary_material_in_public_documentation(self):
        public_guard.check_tree(public_guard.ROOT)

    def test_reject_untrusted_branch(self):
        environment = {
            "GITHUB_REPOSITORY": "SUAS-STEM/ci-relay-lab",
            "GITHUB_REF": "refs/heads/attacker",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_ACTOR": "eschan145",
            "GITHUB_SHA": "a" * 40,
        }
        with self.assertRaises(ValueError):
            public_guard.check_runner_context(environment)

    def test_reject_different_repo(self):
        environment = {
            "GITHUB_REPOSITORY": "SUAS-STEM/gcs",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_ACTOR": "eschan145",
            "GITHUB_SHA": "a" * 40,
        }
        with self.assertRaises(ValueError):
            public_guard.check_runner_context(environment)

    def test_no_static_recipient_is_committed(self):
        self.assertNotIn("keys/pi-logs.agepub", public_guard.ALLOWED_FILES)
        self.assertIn("tools/ephemeral_age.py", public_guard.ALLOWED_FILES)

    def test_windows_crlf_checkout_preserves_public_fixture_hash(self):
        original = (public_guard.ROOT / "src/synthetic_adder.cpp").read_bytes()
        windows_bytes = original.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        self.assertEqual(public_guard.public_text_digest(original),
                         public_guard.public_text_digest(windows_bytes))

    def test_bare_carriage_return_is_rejected(self):
        with self.assertRaises(ValueError):
            public_guard.public_text_digest(b"hello\rworld")


if __name__ == "__main__":
    unittest.main()
