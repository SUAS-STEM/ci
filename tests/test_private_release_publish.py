"""Private GitHub Release publication is idempotent and fail-closed."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.private_release_publish import (
    PRIVATE_REPO, _release, publish_private_release, expected_files,
)


TAG = "ci-public-38454705459-1"
NOTES = (
    "PUBLIC SYNTHETIC ENCRYPTED CI -- no proprietary source.\n"
    "source-repo=SUAS-STEM/ci-relay-lab\n"
    "source-commit=" + "a" * 40 + "\n"
    "source-run=38454705459\nsource-attempt=1\n"
    "source-workflow=.github/workflows/fixture.yml\n"
)
BINARIES = {
    "linux-x86_64-synthetic_adder": b"\x7fELF" + b"x" * 1500,
    "windows-x86_64-synthetic_adder.exe": b"MZ" + b"y" * 1600,
}


class FakeGitHub:
    def __init__(self):
        self.release = None
        self.files = {}
        self.calls = []
        self.fail_next_upload = False
        self.bad_download = False
        self.private = True
        self.fail_lookup = False

    def __call__(self, *args):
        self.calls.append(args)
        if args == ("repo", "view", PRIVATE_REPO, "--json", "isPrivate"):
            return json.dumps({"isPrivate": self.private})
        if args == ("api", f"repos/{PRIVATE_REPO}/releases/tags/{TAG}"):
            if self.fail_lookup:
                raise subprocess.CalledProcessError(1, args, stderr=b"HTTP 503: Unavailable")
            if self.release is None:
                raise subprocess.CalledProcessError(1, args, stderr=b"HTTP 404: Not Found")
            return json.dumps(self.release)
        if args[:2] == ("release", "create"):
            if self.release is not None:
                raise AssertionError("Attempt to overwrite existing release")
            self.release = {
                "id": 42, "tag_name": TAG, "draft": True, "prerelease": False,
                "target_commitish": "main", "body": args[args.index("--notes") + 1],
                "assets": [],
            }
            return ""
        if args[:2] == ("release", "upload"):
            for path in args[5:]:
                file = Path(path)
                if not file.exists():
                    continue
                if self.fail_next_upload:
                    self.fail_next_upload = False
                    raise subprocess.CalledProcessError(1, args, stderr=b"HTTP 502: Gateway")
                if file.name in self.files:
                    raise AssertionError("Attempted to overwrite uploaded asset")
                content = file.read_bytes()
                self.files[file.name] = content
                self.release["assets"].append({
                    "id": len(self.files) + 100, "name": file.name,
                    "state": "uploaded", "size": len(content),
                    "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
                })
            return ""
        if args[:2] == ("release", "download"):
            directory = Path(args[-1])
            for name, blob in self.files.items():
                (directory / name).write_bytes(
                    b"tampered" if self.bad_download and name.endswith(".exe")
                    else blob
                )
            return ""
        if args[:2] == ("release", "edit"):
            self.release["draft"] = False
            return ""
        raise AssertionError(f"Unexpected GitHub request: {args}")


class PrivateReleasePublishTests(unittest.TestCase):
    def test_new_release_is_checked_and_published(self):
        api = FakeGitHub()
        self.assertTrue(publish_private_release(api, TAG, NOTES, BINARIES))
        self.assertIs(api.release["draft"], False)
        self.assertEqual(api.files, expected_files(BINARIES))
        self.assertEqual(len([x for x in api.calls if x[:2] == ("release", "upload")]), 1)

    def test_retry_existing_verified_published_release(self):
        api = FakeGitHub()
        publish_private_release(api, TAG, NOTES, BINARIES)
        self.assertFalse(publish_private_release(api, TAG, NOTES, BINARIES))
        self.assertEqual(len([x for x in api.calls if x[:2] == ("release", "create")]), 1)
        self.assertEqual(len([x for x in api.calls if x[:2] == ("release", "upload")]), 1)

    def test_resume_partial_draft(self):
        api = FakeGitHub()
        api.fail_next_upload = True
        with self.assertRaises(subprocess.CalledProcessError):
            publish_private_release(api, TAG, NOTES, BINARIES)
        self.assertTrue(api.release["draft"])
        self.assertTrue(publish_private_release(api, TAG, NOTES, BINARIES) is False)
        self.assertFalse(api.release["draft"])

    def test_resume_only_missing_files_in_partial_draft(self):
        api = FakeGitHub()
        api.fail_next_upload = True
        with self.assertRaises(subprocess.CalledProcessError):
            publish_private_release(api, TAG, NOTES, BINARIES)
        all_files = expected_files(BINARIES)
        name = "linux-x86_64-synthetic_adder"
        blob = all_files[name]
        api.files[name] = blob
        api.release["assets"].append({
            "id": 1001, "name": name, "state": "uploaded", "size": len(blob),
            "digest": "sha256:" + hashlib.sha256(blob).hexdigest(),
        })
        self.assertFalse(publish_private_release(api, TAG, NOTES, BINARIES))
        self.assertEqual(api.files, all_files)
        uploaded = [args for args in api.calls if args[:2] == ("release", "upload")][-1]
        self.assertNotIn(name, [Path(path).name for path in uploaded])

    def test_existing_mismatched_asset_must_fail_closed(self):
        api = FakeGitHub()
        publish_private_release(api, TAG, NOTES, BINARIES)
        api.release["assets"][0]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(RuntimeError, "differs"):
            publish_private_release(api, TAG, NOTES, BINARIES)

    def test_unexpected_asset_or_provenance_is_rejected(self):
        api = FakeGitHub()
        publish_private_release(api, TAG, NOTES, BINARIES)
        api.release["body"] = "forged"
        with self.assertRaisesRegex(RuntimeError, "source provenance"):
            publish_private_release(api, TAG, NOTES, BINARIES)
        api.release["body"] = NOTES
        api.release["assets"].append({
            "name": "private-key.txt", "id": 123456, "state": "uploaded",
            "size": 1, "digest": "sha256:" + "b" * 64,
        })
        with self.assertRaisesRegex(RuntimeError, "extra private release"):
            publish_private_release(api, TAG, NOTES, BINARIES)

    def test_tampered_download_does_not_publish(self):
        api = FakeGitHub()
        api.bad_download = True
        with self.assertRaisesRegex(RuntimeError, "asset was unsafe|hash verification"):
            publish_private_release(api, TAG, NOTES, BINARIES)
        self.assertTrue(api.release["draft"])

    def test_api_errors_not_treated_as_release_absence(self):
        api = FakeGitHub()
        api.fail_lookup = True
        with self.assertRaises(subprocess.CalledProcessError):
            publish_private_release(api, TAG, NOTES, BINARIES)
        self.assertIsNone(api.release)

    def test_never_publish_to_public_repo(self):
        api = FakeGitHub()
        api.private = False
        with self.assertRaisesRegex(RuntimeError, "not PRIVATE"):
            publish_private_release(api, TAG, NOTES, BINARIES)
        self.assertIsNone(api.release)

    def test_invalid_tag_or_binary_rejected_before_api(self):
        api = FakeGitHub()
        with self.assertRaises(RuntimeError):
            publish_private_release(api, "ci-public-bad-tag", NOTES, BINARIES)
        with self.assertRaises(RuntimeError):
            publish_private_release(api, TAG, NOTES, {
                **BINARIES, "private-source.cpp": b"not allowed",
            })
        self.assertEqual(api.calls, [])


if __name__ == "__main__":
    unittest.main()
