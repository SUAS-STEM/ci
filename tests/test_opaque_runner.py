"""The public MSVC worker must reject malformed encrypted source packets."""

import io
import json
from pathlib import Path
import unittest
import zipfile

from tools.opaque_runner import read_packet, RECIPIENT, MARKER


class OpaquePacketTests(unittest.TestCase):
    NONCE = "a" * 24
    SHA = "b" * 40

    def packet(self, filename="src/sample.cpp", content=b"int main(){}", nonce=None):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("manifest.json", json.dumps({
                "nonce": nonce or self.NONCE,
                "source_commit": self.SHA,
                "output": "ci-out/program.exe",
            }))
            archive.writestr("build.ps1", b"Write-Output 'test'")
            archive.writestr(filename, content)
        return output.getvalue()

    def test_valid_private_packet(self):
        files = read_packet(self.packet(), self.NONCE, self.SHA)
        self.assertEqual(files["src/sample.cpp"], b"int main(){}")

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

    def test_wrong_nonce_or_commit_fails_closed(self):
        with self.assertRaises(ValueError):
            read_packet(self.packet(), "c" * 24, self.SHA)
        with self.assertRaises(ValueError):
            read_packet(self.packet(), self.NONCE, "d" * 40)

    def test_invalid_recipient_and_release_tag(self):
        self.assertIsNotNone(RECIPIENT.fullmatch("age1" + "q" * 58))
        self.assertIsNone(RECIPIENT.fullmatch("AGE-SECRET-KEY-" + "q" * 50))
        self.assertIsNotNone(MARKER.fullmatch("ci-opaque-" + self.NONCE))


if __name__ == "__main__":
    unittest.main()
