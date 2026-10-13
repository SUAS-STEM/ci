"""Pi-only direct GitHub Release publishing with safe retry after partial uploads.

Never upload Actions artifacts, expose tokens to public runners, or clobber
existing release assets. The supplied gh function is the Pi's trusted CLI.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


PRIVATE_REPO = "SUAS-STEM/ci-release-vault"
ASSET_NAMES = ("linux-x86_64-synthetic_adder",
               "windows-x86_64-synthetic_adder.exe")
MAX_EXE_BYTES = 8 * 1024 * 1024


def expected_files(binaries: dict[str, bytes]) -> dict[str, bytes]:
    if set(binaries) != set(ASSET_NAMES):
        raise RuntimeError("Both expected toy executables required")
    assets = {}
    for name in ASSET_NAMES:
        data = binaries[name]
        if type(data) is not bytes or not 1024 < len(data) < MAX_EXE_BYTES:
            raise RuntimeError("Refusing unexpected toy executable size or type")
        magic = b"MZ" if name.endswith(".exe") else b"\x7fELF"
        if not data.startswith(magic):
            raise RuntimeError("Incorrect platform executable format")
        assets[name] = data
        assets[name + ".sha256"] = (
            hashlib.sha256(data).hexdigest() + "  " + name + "\n"
        ).encode("ascii")
    return assets


def _release(gh, tag: str):
    try:
        return json.loads(gh("api", f"repos/{PRIVATE_REPO}/releases/tags/{tag}"))
    except subprocess.CalledProcessError as error:
        # A genuine not-found is the ONLY acceptable reason to create a draft.
        # Network/auth/rate-limit/API errors must never be treated as absence.
        diagnostic = error.stderr or b""
        if isinstance(diagnostic, str):
            diagnostic = diagnostic.encode()
        if b"HTTP 404" in diagnostic:
            return None
        raise


def _validate_release(release: dict, tag: str, notes: str,
                      assets: dict[str, bytes]) -> set[str]:
    if release.get("tag_name") != tag or release.get("body") != notes:
        raise RuntimeError("Refusing release with mismatched tag or source provenance")
    if release.get("prerelease") is not False:
        raise RuntimeError("Unexpected pre-release status")
    if release.get("target_commitish") != "main":
        raise RuntimeError("Private release targets unexpected source revision")
    available = release.get("assets")
    if not isinstance(available, list):
        raise RuntimeError("GitHub release asset catalog missing")
    if len(available) > len(assets):
        raise RuntimeError("Unexpected extra private release assets")
    seen = set()
    for item in available:
        name = item.get("name")
        if name in seen or name not in assets:
            raise RuntimeError("Duplicate or unexpected private release asset")
        expected = assets[name]
        if (item.get("state") != "uploaded"
                or item.get("size") != len(expected)
                or item.get("digest") != "sha256:" + hashlib.sha256(expected).hexdigest()):
            raise RuntimeError("Existing private release asset differs from verified build")
        seen.add(name)
    if release.get("draft") is False and seen != set(assets):
        raise RuntimeError("Published release is incomplete")
    if release.get("draft") not in (True, False):
        raise RuntimeError("Unexpected release draft status")
    return seen


def publish_private_release(gh, tag: str, notes: str,
                            binaries: dict[str, bytes]) -> bool:
    """Create/resume and verify one private Release. Returns True if created."""
    if not re.fullmatch(r"ci-public(?:-test)?-[1-9][0-9]{4,14}-1", tag):
        raise RuntimeError("Refusing invalid public encrypted CI release tag")
    if not isinstance(notes, str) or not notes.startswith(
        "PUBLIC SYNTHETIC ENCRYPTED CI -- no proprietary source.\n"
    ) or len(notes) > 700:
        raise RuntimeError("Unexpected release provenance")
    files = expected_files(binaries)
    repo = json.loads(gh("repo", "view", PRIVATE_REPO, "--json", "isPrivate"))
    if repo.get("isPrivate") is not True:
        raise RuntimeError("Refusing release destination that is not PRIVATE")

    existing = _release(gh, tag)
    created = existing is None
    if existing is None:
        gh("release", "create", tag, "--repo", PRIVATE_REPO, "--target", "main",
           "--draft", "--latest=false",
           "--title", f"Public encrypted CI {tag.rsplit('-', 2)[-2]}",
           "--notes", notes)
        existing = _release(gh, tag)
        if existing is None:
            raise RuntimeError("Private release creation was not confirmed")
    present = _validate_release(existing, tag, notes, files)

    with tempfile.TemporaryDirectory(prefix="ci-private-release-") as folder:
        root = Path(folder)
        os.chmod(root, 0o700)
        for name, blob in files.items():
            p = root / name
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(blob)
        missing = sorted(set(files) - present)
        if missing:
            if existing.get("draft") is not True:
                raise RuntimeError("Cannot repair assets in published release")
            gh("release", "upload", tag, "--repo", PRIVATE_REPO,
               *(str(root / name) for name in missing))
        complete = _release(gh, tag)
        if complete is None or _validate_release(complete, tag, notes, files) != set(files):
            raise RuntimeError("Private draft release missing or unverified assets")
        fetched = root / "downloaded"
        fetched.mkdir(mode=0o700)
        gh("release", "download", tag, "--repo", PRIVATE_REPO, "--dir", str(fetched))
        if {p.name for p in fetched.iterdir()} != set(files):
            raise RuntimeError("Downloaded private release has unexpected assets")
        for name, expected in files.items():
            p = fetched / name
            if p.is_symlink() or not p.is_file() or p.stat().st_size != len(expected):
                raise RuntimeError("Downloaded private release asset was unsafe")
            with p.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").digest() != hashlib.sha256(expected).digest():
                    raise RuntimeError("Downloaded private release failed hash verification")
        before_publish = _release(gh, tag)
        if (before_publish is None
                or before_publish.get("id") != complete.get("id")
                or _validate_release(before_publish, tag, notes, files) != set(files)):
            raise RuntimeError("Private release changed during verification")
        if complete["draft"]:
            gh("release", "edit", tag, "--repo", PRIVATE_REPO,
               "--draft=false", "--latest=false")
        final = _release(gh, tag)
        if (final is None or final.get("draft") is not False
                or final.get("id") != complete.get("id")
                or _validate_release(final, tag, notes, files) != set(files)):
            raise RuntimeError("Private release was not durably published")
    return created
