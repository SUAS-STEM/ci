"""Safely remove only expired ciphertext-only PUBLIC transfer Releases.

This intentionally runs using PUBLIC_REPO's own scoped GITHUB_TOKEN on a
low-frequency schedule, avoiding private credentials and Pi state. Dry run
is the default for local inspection. Never reads or modifies a private repo.
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
import re
import subprocess

PUBLIC = "SUAS-STEM/ci-relay-lab"
PUBLIC_ID = 1416396230
TAG_PATTERN = re.compile(r"ci-opaque-[0-9a-f]{24}\Z")
NOTES = frozenset((
    "Short-lived encrypted synthetic build transfer; no plaintext source.",
    "Short-lived encrypted synthetic MSVC test; no plaintext inputs.",
))
ASSETS = frozenset(("recipient.agepub", "recipient.oidc", "source.age", "result-log.age",
                    "result-status.age", "result-exe.age", "result.oidc"))


def gh(*args):
    return subprocess.run(["gh", *args], capture_output=True,
                          text=True, check=True, timeout=90).stdout


def published_prereleases():
    result = []
    for page in range(1, 12):
        batch = json.loads(gh("api", f"repos/{PUBLIC}/releases?per_page=100&page={page}"))
        if not isinstance(batch, list) or len(batch) > 100:
            raise RuntimeError("Malformed public GitHub Releases API response")
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise RuntimeError("Too many GitHub Releases to scan safely")


def _parse_time(value):
    if not isinstance(value, str):
        raise RuntimeError("Release creation time is missing")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise RuntimeError("Release creation time lacks timezone")
    return parsed.astimezone(timezone.utc)


def eligible(release, *, now, min_age_hours):
    """Fail closed: exactly our own expired ciphertext-only prereleases."""
    tag = release.get("tag_name")
    if (not isinstance(tag, str) or TAG_PATTERN.fullmatch(tag) is None
            or release.get("draft") is not False
            or release.get("prerelease") is not True
            or type(release.get("id")) is not int
            or not isinstance(release.get("body"), str)
            or release["body"].strip() not in NOTES):
        return False
    if _parse_time(release.get("created_at")) > now - timedelta(hours=min_age_hours):
        return False
    entries = release.get("assets")
    if not isinstance(entries, list) or len(entries) > len(ASSETS):
        return False
    seen = set()
    for item in entries:
        name = item.get("name")
        if (name not in ASSETS or name in seen
                or type(item.get("id")) is not int
                or item.get("state") != "uploaded"
                or type(item.get("size")) is not int
                or not 0 < item["size"] < 150 * 1024 * 1024
                or not isinstance(item.get("digest"), str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]) is None):
            return False
        if (name.endswith(".oidc") and item["size"] > 16000
                or name.endswith(".agepub") and item["size"] > 256):
            return False
        seen.add(name)
    return True


def snapshot(release):
    """Detect unexpected asset/provenance changes between listing and delete."""
    return (release.get("id"), release.get("tag_name"),
            release.get("created_at"), release.get("body"),
            release.get("draft"), release.get("prerelease"),
            tuple(sorted((a.get("id"), a.get("name"), a.get("size"),
                          a.get("digest")) for a in release.get("assets", []))))


def has_running_public_job(tag):
    """Never remove the ciphertext while a legitimate job still executes."""
    nonce = tag.removeprefix("ci-opaque-")
    for page in range(1, 5):
        result = json.loads(gh(
            "api", f"repos/{PUBLIC}/actions/runs?per_page=100&page={page}"
        ))
        runs = result.get("workflow_runs")
        if not isinstance(runs, list):
            raise RuntimeError("Cannot verify current public CI run status")
        for run in runs:
            if run.get("display_title") == "opaque-" + nonce:
                if run.get("status") != "completed":
                    return True
        if len(runs) < 100:
            return False
    raise RuntimeError("Public CI run listing exceeded safety scan limit")


def cleanup(*, apply=False, min_age_hours=24, now=None):
    if min_age_hours < 6:
        raise ValueError("Must allow at least six hours for active CI transfers")
    if now is None:
        now = datetime.now(timezone.utc)
    repo = json.loads(gh("api", f"repos/{PUBLIC}"))
    if (repo.get("id") != PUBLIC_ID or repo.get("full_name") != PUBLIC
            or repo.get("private") is not False):
        raise RuntimeError("Refusing cleanup outside the trusted PUBLIC repository")
    deleted = []
    candidates = [entry for entry in published_prereleases()
                  if eligible(entry, now=now, min_age_hours=min_age_hours)]
    for original in candidates:
        tag = original["tag_name"]
        # Recheck immediately before any deletion to prevent race/swap.
        latest = json.loads(gh("api", f"repos/{PUBLIC}/releases/tags/{tag}"))
        if (not eligible(latest, now=now, min_age_hours=min_age_hours)
                or snapshot(latest) != snapshot(original)):
            raise RuntimeError("Public encrypted prerelease changed while verifying")
        if has_running_public_job(tag):
            print("SKIP active public MSVC job:", tag)
            continue
        if apply:
            gh("release", "delete", tag, "--repo", PUBLIC,
               "--cleanup-tag", "--yes")
            print("DELETED expired public encrypted prerelease:", tag)
        else:
            print("DRY-RUN expired public encrypted prerelease:", tag)
        deleted.append(tag)
    print(f"Encrypted transfer cleanup: {len(deleted)} eligible, apply={apply}")
    return deleted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="Actually delete only eligible expired ciphertext prereleases")
    parser.add_argument("--min-age-hours", type=int, default=24,
                        help="Conservative default 24h; hard minimum 6h")
    args = parser.parse_args()
    cleanup(apply=args.apply, min_age_hours=args.min_age_hours)


if __name__ == "__main__":
    main()
