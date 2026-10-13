import tempfile
import hashlib
from io import BytesIO
from pathlib import Path
import unittest
import zipfile

from tools import artifact_verification as av


class VerificationTests(unittest.TestCase):
    @staticmethod
    def make_archive(filename="encrypted-log.age", data=None):
        if data is None:
            data = b"age-encryption.org/v1\n" + b"X" * 200
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(filename, data)
        blob = buffer.getvalue()
        metadata = {"size_in_bytes": len(blob),
                    "digest": "sha256:" + hashlib.sha256(blob).hexdigest()}
        return blob, metadata, data

    def test_verified_archive_extracts_exact_ciphertext(self):
        blob, metadata, ciphertext = self.make_archive()
        self.assertEqual(av.extract_ciphertext_zip(blob, metadata), ciphertext)

    def test_modified_artifact_zip_is_rejected(self):
        blob, metadata, _ = self.make_archive()
        changed = bytearray(blob)
        changed[45] ^= 1
        with self.assertRaises(ValueError):
            av.extract_ciphertext_zip(bytes(changed), metadata)

    def test_zip_slip_filename_is_rejected(self):
        blob, metadata, _ = self.make_archive("../../outside.age")
        with self.assertRaises(ValueError):
            av.extract_ciphertext_zip(blob, metadata)

    def test_zip_bomb_is_rejected_before_decompression(self):
        blob, metadata, _ = self.make_archive(data=b"age-encryption.org/v1\n" + b"0" * av.MAX_BYTES)
        with self.assertRaises(ValueError):
            av.extract_ciphertext_zip(blob, metadata)

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
