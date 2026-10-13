"""Install pinned age binaries for this public-only test (Linux/Windows/Pi)."""

import hashlib
import io
import os
from pathlib import Path
import platform
import stat
import tarfile
import urllib.request
import zipfile


VERSION = "v1.3.2"
ARCHIVES = {
    ("Linux", "x86_64"): (
        "age-v1.3.2-linux-amd64.tar.gz",
        "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10",
    ),
    ("Linux", "aarch64"): (
        "age-v1.3.2-linux-arm64.tar.gz",
        "6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4",
    ),
    ("Windows", "AMD64"): (
        "age-v1.3.2-windows-amd64.zip",
        "f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7",
    ),
}


def main() -> None:
    filename, expected = ARCHIVES[(platform.system(), platform.machine())]
    destination = Path(__file__).resolve().parents[1] / ".age-bin"
    executable = "age.exe" if platform.system() == "Windows" else "age"
    # Intentionally verify the *release archive* on every invocation. Never
    # trust an old executable merely because a matching filename exists.
    url = f"https://github.com/FiloSottile/age/releases/download/{VERSION}/{filename}"
    with urllib.request.urlopen(url, timeout=90) as stream:
        content = stream.read(30 * 1024 * 1024 + 1)
    if len(content) > 30 * 1024 * 1024:
        raise ValueError("Download exceeds size limit")
    if hashlib.sha256(content).hexdigest() != expected:
        raise ValueError("Pinned age release checksum mismatch")

    destination.mkdir(exist_ok=True)
    for binary_name in ("age", "age-keygen"):
        target = f"{binary_name}.exe" if platform.system() == "Windows" else binary_name
        if filename.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                candidates = [item for item in archive.namelist()
                              if item.replace("\\", "/").split("/")[-1] == target]
                if len(candidates) != 1:
                    raise ValueError(f"Expected precisely one {target}")
                binary = archive.read(candidates[0])
        else:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
                candidates = [item for item in archive.getmembers()
                              if item.isfile() and item.name.split("/")[-1] == target]
                if len(candidates) != 1:
                    raise ValueError(f"Expected precisely one {target}")
                binary = archive.extractfile(candidates[0]).read()
        path = destination / target
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_bytes(binary)
        if os.name != "nt":
            tmp.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        tmp.replace(path)
    print(f"Installed verified age {VERSION} binaries")


if __name__ == "__main__":
    main()
