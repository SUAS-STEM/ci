"""Fail-closed tests for low-cost PUBLIC ciphertext cleanup (never GCS)."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import opaque_prerelease_cleanup as gc


class FakePublicAPI:
    NONCE = "a" * 24
    TAG = "ci-opaque-" + NONCE

    def __init__(self):
        self.now = datetime(2026, 10, 13, 22, tzinfo=timezone.utc)
        blob = b"age-encrypted-test-ciphertext"
        self.release = {
            "id": 177, "tag_name": self.TAG, "draft": False,
            "prerelease": True,
            "created_at": (self.now - timedelta(hours=30)).isoformat(),
            "body": "Short-lived encrypted synthetic build transfer; no plaintext source.",
            "assets": [{"id": 123, "name": "source.age", "state": "uploaded",
                        "size": len(blob), "digest": "sha256:" + hashlib.sha256(blob).hexdigest()}],
        }
        self.repo = {"id": gc.PUBLIC_ID, "full_name": gc.PUBLIC, "private": False}
        self.running = False
        self.calls = []
        self.mutate_on_recheck = False

    def gh(self, *args):
        self.calls.append(args)
        if args == ("api", f"repos/{gc.PUBLIC}"):
            return json.dumps(self.repo)
        if args == ("api", f"repos/{gc.PUBLIC}/releases?per_page=100&page=1"):
            return json.dumps([self.release])
        if args == ("api", f"repos/{gc.PUBLIC}/releases/tags/{self.TAG}"):
            current = dict(self.release)
            if self.mutate_on_recheck:
                current["body"] = "replaced provenance"
            return json.dumps(current)
        if args == ("api", f"repos/{gc.PUBLIC}/actions/runs?per_page=100&page=1"):
            return json.dumps({"workflow_runs": ([{
                "display_title": "opaque-" + self.NONCE,
                "status": "in_progress" if self.running else "completed",
            }] if self.running else [])})
        if args == ("release", "delete", self.TAG, "--repo", gc.PUBLIC,
                    "--cleanup-tag", "--yes"):
            return ""
        raise AssertionError("Unexpected GitHub API command: " + repr(args))


class ExpiredEncryptedTransferTests(unittest.TestCase):
    def setUp(self):
        self.api = FakePublicAPI()
        self.stub = patch.object(gc, "gh", side_effect=self.api.gh)
        self.stub.start()
        self.addCleanup(self.stub.stop)

    def test_expired_ciphertext_only_release_eligible(self):
        self.assertTrue(gc.eligible(self.api.release, now=self.api.now,
                                    min_age_hours=24))

    def test_never_delete_fresh_or_wrongly_named_or_plaintext_assets(self):
        self.api.release["created_at"] = (self.api.now - timedelta(hours=3)).isoformat()
        self.assertEqual(gc.cleanup(apply=True, now=self.api.now), [])
        self.api.release["created_at"] = (self.api.now - timedelta(hours=30)).isoformat()
        for field, value in (("tag_name", "opaque-unrelated"),
                             ("prerelease", False), ("draft", True),
                             ("body", "somebody else's release")):
            previous = self.api.release[field]
            self.api.release[field] = value
            with self.subTest(field=field):
                self.assertFalse(gc.eligible(self.api.release, now=self.api.now,
                                             min_age_hours=24))
            self.api.release[field] = previous
        self.api.release["assets"][0]["name"] = "source.cpp"
        self.assertFalse(gc.eligible(self.api.release, now=self.api.now,
                                     min_age_hours=24))
        self.assertFalse(any(a[:2] == ("release", "delete") for a in self.api.calls))

    def test_invalid_digest_prevents_destructive_cleanup(self):
        self.api.release["assets"][0]["digest"] = "not-verified"
        self.assertFalse(gc.eligible(self.api.release, now=self.api.now,
                                     min_age_hours=24))
        self.assertEqual(gc.cleanup(apply=True, now=self.api.now), [])

    def test_only_dry_run_without_explicit_apply(self):
        self.assertEqual(gc.cleanup(now=self.api.now), [self.api.TAG])
        self.assertFalse(any(a[:2] == ("release", "delete") for a in self.api.calls))

    def test_only_delete_expired_nonrunning_exact_release(self):
        self.assertEqual(gc.cleanup(apply=True, now=self.api.now), [self.api.TAG])
        self.assertEqual(sum(a[:2] == ("release", "delete") for a in self.api.calls), 1)

    def test_running_public_action_is_not_interrupted(self):
        self.api.running = True
        self.assertEqual(gc.cleanup(apply=True, now=self.api.now), [])
        self.assertFalse(any(a[:2] == ("release", "delete") for a in self.api.calls))

    def test_release_changed_during_recheck_fails_closed(self):
        self.api.mutate_on_recheck = True
        with self.assertRaisesRegex(RuntimeError, "changed while verifying"):
            gc.cleanup(apply=True, now=self.api.now)
        self.assertFalse(any(a[:2] == ("release", "delete") for a in self.api.calls))

    def test_only_trusted_public_repository_id_may_delete(self):
        self.api.repo["id"] = 1234
        with self.assertRaisesRegex(RuntimeError, "trusted PUBLIC"):
            gc.cleanup(apply=True, now=self.api.now)
        self.assertFalse(any(a[:2] == ("release", "delete") for a in self.api.calls))

    def test_daily_workflow_is_public_only_and_no_artifacts(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/opaque-prerelease-cleanup.yml").read_text()
        self.assertIn("schedule:", workflow)
        self.assertIn("'17 11 * * *'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("--apply --min-age-hours 24", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("download-artifact", workflow)


if __name__ == "__main__":
    unittest.main()
