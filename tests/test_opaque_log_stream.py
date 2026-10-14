"""Encrypted log streaming is bounded, ordered, and private by construction."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import unittest

from tools import opaque_runner as relay
from tools.opaque_log_stream import EncryptedLogUploader, CHUNK_BYTES


@unittest.skipUnless(relay.AGE.is_file() and relay.KEYGEN.is_file(),
                     "Requires pinned age toolchain")
class EncryptedStreamTests(unittest.TestCase):
    def test_live_chunks_are_ciphertext_and_reconstruct_exact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "private.key"
            created = subprocess.run([str(relay.KEYGEN), "-o", str(key)],
                                     capture_output=True, check=True, text=True)
            recipient = re.search(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}",
                                  created.stderr).group()
            uploaded = []
            def gh(*args):
                self.assertEqual(args[:2], ("release", "upload"))
                path = Path(args[-1])
                uploaded.append((path.name, path.read_bytes()))
                return b""
            sender = EncryptedLogUploader(relay.AGE, recipient, gh,
                                          "ci-opaque-" + "a" * 24, root,
                                          flush_seconds=0.05)
            raw = b"private compiler diagnostic\r\n" * 6000
            self.assertNotIn(b"private compiler diagnostic", b"")
            sender.feed(raw[:CHUNK_BYTES - 1])
            sender.feed(raw[CHUNK_BYTES - 1:CHUNK_BYTES * 2 + 42])
            sender.feed(raw[CHUNK_BYTES * 2 + 42:])
            self.assertTrue(sender.finish())
            self.assertGreaterEqual(len(uploaded), 2)
            self.assertEqual([name for name, _ in uploaded],
                             [f"stream-{i:06d}.age" for i in range(len(uploaded))])
            result = bytearray()
            for _, blob in uploaded:
                self.assertNotIn(b"private compiler diagnostic", blob)
                plain = subprocess.run([str(relay.AGE), "-d", "-i", str(key)],
                                       input=blob, capture_output=True,
                                       check=True).stdout
                self.assertLessEqual(len(plain), CHUNK_BYTES)
                result.extend(plain)
            self.assertEqual(bytes(result), raw)
            self.assertFalse(list(root.glob("stream-*.age")))

    def test_emits_partial_log_before_final_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "key"
            created = subprocess.run([str(relay.KEYGEN), "-o", str(key)],
                                     capture_output=True, check=True, text=True)
            recipient = re.search(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}",
                                  created.stderr).group()
            chunks = []
            def send(*args):
                chunks.append(Path(args[-1]).read_bytes())
            sender = EncryptedLogUploader(relay.AGE, recipient, send,
                                          "ci-opaque-" + "b" * 24,
                                          root, flush_seconds=0.04)
            sender.feed(b"the private process is still running\r\n")
            deadline = time.monotonic() + 4
            while not chunks and time.monotonic() < deadline:
                time.sleep(0.03)
            self.assertTrue(chunks, "Incremental encrypted log never arrived")
            self.assertTrue(sender.thread.is_alive(), "Uploader must remain live")
            self.assertTrue(sender.finish())

    def test_continuous_small_output_still_flushes_before_build_finishes(self):
        """A producer that never goes silent must not postpone live preview."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "key"
            created = subprocess.run([str(relay.KEYGEN), "-o", str(key)],
                                     capture_output=True, check=True, text=True)
            recipient = re.search(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}",
                                  created.stderr).group()
            sent = []

            def gh(*args):
                sent.append((time.monotonic(), Path(args[-1]).read_bytes()))

            sender = EncryptedLogUploader(relay.AGE, recipient, gh,
                                          "ci-opaque-" + "d" * 24, root,
                                          flush_seconds=0.09)
            started = time.monotonic()
            raw = b""
            for _ in range(25):
                entry = b"MSVC still compiling\r\n"
                raw += entry
                sender.feed(entry)
                time.sleep(0.017)
            self.assertTrue(sent, "Continuous output starved the time-based flush")
            self.assertTrue(any(at < time.monotonic() for at, _ in sent))
            self.assertLess(sent[0][0] - started, 0.39,
                            "First encrypted chunk did not arrive in time")
            self.assertTrue(sender.thread.is_alive())
            self.assertTrue(sender.finish())
            recovered = bytearray()
            for _, ciphertext in sent:
                plaintext = subprocess.run(
                    [str(relay.AGE), "-d", "-i", str(key)],
                    input=ciphertext, capture_output=True, check=True,
                ).stdout
                recovered.extend(plaintext)
            self.assertEqual(bytes(recovered), raw)

    def test_network_upload_failure_falls_back_to_final_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "key"
            created = subprocess.run([str(relay.KEYGEN), "-o", str(key)],
                                     capture_output=True, check=True, text=True)
            recipient = re.search(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}",
                                  created.stderr).group()
            sender = EncryptedLogUploader(relay.AGE, recipient,
                                          lambda *args: (_ for _ in ()).throw(
                                              RuntimeError("temporary network error")),
                                          "ci-opaque-" + "c" * 24,
                                          root, flush_seconds=0.03)
            sender.feed(b"something happened")
            self.assertFalse(sender.finish())
            self.assertIsNotNone(sender.failed)


if __name__ == "__main__":
    unittest.main()
