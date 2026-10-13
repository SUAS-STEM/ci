"""Synthetic binary wrapping must reject substitution between CI runs."""

import unittest

from tools.binary_envelope import wrap_binary, unwrap_binary


class BinaryEnvelopeTests(unittest.TestCase):
    TRACE = "test-abcdef123456"
    COMMIT = "a" * 40
    RECIPIENT = "b" * 64
    PLATFORM = "windows-2025"
    RUN = 12345

    def wrap(self, content):
        return wrap_binary(content, self.TRACE, self.COMMIT, self.RUN,
                           self.PLATFORM, self.RECIPIENT)

    def unwrap(self, data, **kwargs):
        defaults = dict(trace=self.TRACE, commit=self.COMMIT, run_id=self.RUN,
                        platform=self.PLATFORM, recipient_digest=self.RECIPIENT)
        defaults.update(kwargs)
        return unwrap_binary(data, **defaults)

    def test_present_executable_roundtrip(self):
        body = b"MZ\x00\x01 PUBLIC SYNTHETIC BINARY"
        self.assertEqual(self.unwrap(self.wrap(body)), body)

    def test_failed_build_has_explicit_missing_executable(self):
        self.assertIsNone(self.unwrap(self.wrap(None)))

    def test_binary_bitflip_rejected(self):
        damaged = bytearray(self.wrap(b"SYNTHETIC"))
        damaged[-1] ^= 1
        with self.assertRaises(ValueError):
            self.unwrap(bytes(damaged))

    def test_cross_run_replay_rejected(self):
        blob = self.wrap(b"SYNTHETIC")
        for changes in (dict(trace="test-012345abcdef"), dict(run_id=self.RUN + 1),
                        dict(commit="c" * 40), dict(platform="ubuntu-24.04"),
                        dict(recipient_digest="d" * 64)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.unwrap(blob, **changes)


if __name__ == "__main__":
    unittest.main()
