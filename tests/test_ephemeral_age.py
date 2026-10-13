"""Per-run age identity tests; all plaintext is synthetic test content."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.ephemeral_age import ephemeral_identity, is_age_recipient
from tools.pi_fixture_dispatch import check_decrypted_report_binding


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "memfd_create"),
                     "sealed Pi-side Linux anonymous keys only")
class EphemeralIdentityTest(unittest.TestCase):
    def test_identity_never_has_a_named_storage_file(self):
        with ephemeral_identity() as identity:
            self.assertTrue(is_age_recipient(identity.recipient))
            self.assertTrue(identity.identity_path.startswith("/proc/self/fd/"))
            self.assertFalse(os.path.exists("/tmp/ci-relay-ephemeral-secret"))
        with self.assertRaises(OSError):
            os.fstat(identity.fd)

    def test_per_run_keys_are_unique_and_not_interchangeable(self):
        exe = str(Path(__file__).resolve().parents[1] / ".age-bin" / "age")
        data = b"PUBLIC SYNTHETIC KEY SEPARATION TEST\n"
        with ephemeral_identity() as a, ephemeral_identity() as b:
            self.assertNotEqual(a.recipient, b.recipient)
            with tempfile.TemporaryDirectory() as d:
                path = Path(d) / "fixture.age"
                subprocess.run([exe, "-r", a.recipient, "-o", str(path), "-"],
                               input=data, capture_output=True, check=True)
                decrypted = subprocess.run(
                    [exe, "-d", "-i", a.identity_path, str(path)],
                    pass_fds=(a.fd,), capture_output=True,
                )
                wrong = subprocess.run(
                    [exe, "-d", "-i", b.identity_path, str(path)],
                    pass_fds=(b.fd,), capture_output=True,
                )
                self.assertEqual(decrypted.returncode, 0)
                self.assertEqual(decrypted.stdout, data)
                self.assertNotEqual(wrong.returncode, 0)

    def test_reject_fake_public_recipient(self):
        self.assertFalse(is_age_recipient("age1malformed"))
        self.assertFalse(is_age_recipient("not-a-key"))

    def test_signed_plaintext_replay_binding_rejects_other_run(self):
        with ephemeral_identity() as identity:
            valid = ("trace=test-abc123\ncommit=" + "a" * 40
                     + "\nrun=123\nplatform=windows-2025\nrecipient_sha256="
                     + identity.recipient_digest + "\nsynthetic-output\n")
            check_decrypted_report_binding(valid, "test-abc123", "a" * 40, 123,
                                           "windows-2025", identity.recipient_digest)
            for args in (
                ("test-other", "a" * 40, 123, "windows-2025", identity.recipient_digest),
                ("test-abc123", "b" * 40, 123, "windows-2025", identity.recipient_digest),
                ("test-abc123", "a" * 40, 124, "windows-2025", identity.recipient_digest),
                ("test-abc123", "a" * 40, 123, "ubuntu-24.04", identity.recipient_digest),
                ("test-abc123", "a" * 40, 123, "windows-2025", "f" * 64),
            ):
                with self.subTest(args=args), self.assertRaises(RuntimeError):
                    check_decrypted_report_binding(valid, *args)
