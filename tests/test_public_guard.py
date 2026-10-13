import os
from pathlib import Path
import unittest

from tools import public_guard


class PublicGuardTest(unittest.TestCase):
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

    def test_age_recipient_is_pinned(self):
        self.assertIn("keys/pi-logs.agepub", public_guard.PUBLIC_FIXTURE_HASHES)

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
