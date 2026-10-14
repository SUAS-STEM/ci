"""Best-effort incremental encrypted MSVC diagnostics via public Release assets.

A public hosted MSVC job encrypts chunks to the private coordinator's ephemeral
age recipient, then uploads only ciphertext. There is no plaintext log in the
PUBLIC Action. The final full log and signed SHA-256 proof remain authoritative.

Streaming is best effort: any failure falls back to final verified log delivery.
"""
import os
from pathlib import Path
import queue
import subprocess
import threading
import time

CHUNK_BYTES = 128 * 1024
FLUSH_SECONDS = 6
MAX_CHUNKS = 768


class EncryptedLogUploader:
    def __init__(self, age, recipient, gh, tag, folder,
                 *, flush_seconds=FLUSH_SECONDS):
        self.age = Path(age)
        self.recipient = recipient
        self.gh = gh
        self.tag = tag
        self.folder = Path(folder)
        self.flush_seconds = flush_seconds
        self.pending = queue.Queue(maxsize=4)
        self.failed = None
        self.count = 0
        self._closed = False
        self.thread = threading.Thread(target=self._upload,
                                       name="opaque-encrypted-log-uploader",
                                       daemon=True)
        self.thread.start()

    def feed(self, chunk):
        """Called by the pipe drainer. Never buffer unlimited MSVC output."""
        if self._closed or self.failed:
            return
        if not isinstance(chunk, bytes):
            raise TypeError("MSVC log chunks must be raw bytes")
        try:
            self.pending.put(chunk, timeout=3)
        except queue.Full:
            self.failed = RuntimeError("Encrypted live log upload backpressure")

    def _send(self, plaintext):
        if not plaintext:
            return
        if self.count >= MAX_CHUNKS:
            raise RuntimeError("Too many encrypted log segments")
        name = f"stream-{self.count:06d}.age"
        encrypted = subprocess.run([str(self.age), "-r", self.recipient],
                                   input=plaintext, capture_output=True,
                                   check=True, timeout=30).stdout
        target = self.folder / name
        if target.exists() or target.is_symlink():
            raise RuntimeError("Live log ciphertext filename already exists")
        descriptor = os.open(target, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encrypted)
        try:
            self.gh("release", "upload", self.tag,
                    "--repo", "SUAS-STEM/ci-relay-lab", str(target))
        finally:
            target.unlink(missing_ok=True)
        self.count += 1

    def _upload(self):
        buffer = bytearray()
        try:
            while True:
                try:
                    item = self.pending.get(timeout=self.flush_seconds)
                except queue.Empty:
                    item = b""
                if item is None:
                    break
                buffer.extend(item)
                while len(buffer) >= CHUNK_BYTES:
                    self._send(bytes(buffer[:CHUNK_BYTES]))
                    del buffer[:CHUNK_BYTES]
                if not item and buffer:
                    self._send(bytes(buffer))
                    buffer.clear()
            if buffer:
                self._send(bytes(buffer))
        except Exception as error:
            self.failed = error

    def finish(self):
        self._closed = True
        if self.thread.is_alive():
            try:
                self.pending.put(None, timeout=15)
            except queue.Full:
                self.failed = RuntimeError("Live log uploader did not drain")
        self.thread.join(timeout=90)
        if self.thread.is_alive():
            self.failed = RuntimeError("Live log uploader timed out")
        return self.failed is None
