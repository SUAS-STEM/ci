import tempfile
from pathlib import Path
import unittest

from tools import artifact_verification as av


class VerificationTests(unittest.TestCase):
    def test_no_attestation_is_rejected(self):
        with self.assertRaises(ValueError):
            av.validate_verified_record([], "a" * 64)

    def test_mismatching_signed_digest_is_rejected(self):
        record = {"verificationResult": {
            "signature": {"certificate": {"issuer": "test"}},
            "verifiedTimestamps": [{"time": 1}],
            "statement": {
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"digest": {"sha256": "a" * 64}}],
            },
        }}
        with self.assertRaises(ValueError):
            av.validate_verified_record([record], "b" * 64)
        av.validate_verified_record([record], "a" * 64)

    def test_reject_unexpected_artifact(self):
        with self.assertRaises(ValueError):
            av.validate_catalog({"artifacts": [{"name": "evil"}]}, 123)

    def test_reject_plaintext_and_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "test.age"
            source.write_bytes(b"X" * 200)
            with self.assertRaises(ValueError):
                av.verify_signed_ciphertext(lambda *args: "[]", source, "a" * 40)
            link = Path(folder) / "link.age"
            link.symlink_to(source)
            with self.assertRaises(ValueError):
                av.verify_signed_ciphertext(lambda *args: "[]", link, "a" * 40)


if __name__ == "__main__":
    unittest.main()
