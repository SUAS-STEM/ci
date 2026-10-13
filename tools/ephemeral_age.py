"""Pi-only age recipient identity held in a sealed Linux anonymous memfd.

The key is generated per dispatch and never written to a named filesystem
path, git repository, GitHub input, Actions log, or uploaded artifact.
The private key disappears from the file descriptor when the process exits.
The dispatcher blocks core dumps/same-user ptrace and pins the memfd's pages
against swapping. This still cannot resist a compromised Pi/root or memory
read access during active use.
"""

from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
from typing import Iterator


AGE_KEYGEN = Path(__file__).resolve().parents[1] / ".age-bin" / "age-keygen"


@dataclass(frozen=True)
class EphemeralIdentity:
    fd: int
    recipient: str

    @property
    def recipient_digest(self) -> str:
        return hashlib.sha256(self.recipient.encode("ascii")).hexdigest()

    @property
    def identity_path(self) -> str:
        return f"/proc/self/fd/{self.fd}"


def is_age_recipient(value: str) -> bool:
    return re.fullmatch(r"age1[ac-hj-np-z02-9]{58}", value) is not None


def restrict_process_inspection() -> None:
    """Fail closed unless this Linux process disables dumps and user ptrace."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    # Linux PR_SET_DUMPABLE=4, 0 prevents same-UID procfs reads and ptrace.
    if libc.prctl(4, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Cannot disable process dumpability")


@contextmanager
def locked_fd_pages(fd: int) -> Iterator[None]:
    """Read-only mapping of secret pages locked into RAM (no swap)."""
    size = os.fstat(fd).st_size
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    # PROT_READ=1, MAP_SHARED=1; mapping never exposes writable key pages.
    address = libc.mmap(None, size, 1, 1, fd, 0)
    if address == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_errno(), "Unable to map ephemeral identity")
    try:
        if libc.mlock(address, size) != 0:
            raise OSError(ctypes.get_errno(), "Cannot lock ephemeral identity in RAM")
        try:
            yield
        finally:
            libc.munlock(address, size)
    finally:
        libc.munmap(address, size)


@contextmanager
def ephemeral_identity() -> Iterator[EphemeralIdentity]:
    """Generate, seal, use, and close a one-run private key without a disk file."""
    if not hasattr(os, "memfd_create") or os.name != "posix":
        raise RuntimeError("A Linux memfd is required for ephemeral CI keys")
    if not AGE_KEYGEN.is_file():
        raise RuntimeError("Pinned age-keygen binary not installed on Pi")
    import fcntl

    restrict_process_inspection()

    fd = os.memfd_create(
        "synthetic-ci-ephemeral-age-key",
        flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
    )
    try:
        # Directly send age-keygen's stdout into the anonymous kernel memfd;
        # avoid ever copying the secret key into a Python bytes object.
        subprocess.run(
            [str(AGE_KEYGEN)], stdout=fd, stderr=subprocess.PIPE,
            check=True, timeout=15,
        )
        if not 70 < os.fstat(fd).st_size < 4096:
            raise RuntimeError("Unexpected ephemeral age identity size")
        fcntl.fcntl(
            fd, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL,
        )
        with locked_fd_pages(fd):
            recipient = subprocess.run(
                [str(AGE_KEYGEN), "-y", f"/proc/self/fd/{fd}"],
                capture_output=True, check=True, timeout=15,
                pass_fds=(fd,),
            ).stdout.decode("ascii").strip()
            if not is_age_recipient(recipient):
                raise RuntimeError("Invalid ephemeral public age recipient")
            yield EphemeralIdentity(fd=fd, recipient=recipient)
    finally:
        os.close(fd)
