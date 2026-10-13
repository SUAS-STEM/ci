"""Encrypted public GitHub job log transfer integrity tests."""

import hashlib
import unittest

from tools.log_transport import format_encrypted_line, parse_job_log


class LogTransportTests(unittest.TestCase):
    PLATFORM = "ubuntu-24.04"
    LOG = b"age-encryption.org/v1\n" + b"a" * 180
    BIN = b"age-encryption.org/v1\n" + b"b" * 200

    def good(self):
        return ("2026-10-13T17:01:01Z " + format_encrypted_line(self.PLATFORM, "log", self.LOG)
                + "\n2026-10-13T17:01:02Z " + format_encrypted_line(self.PLATFORM, "binary", self.BIN))

    def test_valid_git_hub_timestamped_log(self):
        self.assertEqual(parse_job_log(self.good(), self.PLATFORM),
                         {"log": self.LOG, "binary": self.BIN})

    def test_missing_or_duplicate_ciphertext_fails_closed(self):
        with self.assertRaises(ValueError):
            parse_job_log(self.good().splitlines()[0], self.PLATFORM)
        with self.assertRaises(ValueError):
            parse_job_log(self.good() + "\n" + self.good(), self.PLATFORM)

    def test_changed_payload_fails_closed(self):
        tampered = self.good().replace("YW", "WW", 1)
        with self.assertRaises(ValueError):
            parse_job_log(tampered, self.PLATFORM)

    def test_other_platform_rejected(self):
        with self.assertRaises(ValueError):
            parse_job_log(self.good(), "windows-2025")

    def test_no_plaintext_canary_printed(self):
        self.assertNotIn("SYNTHETIC_CANARY", self.good())


if __name__ == "__main__":
    unittest.main()
