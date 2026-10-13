"""Safety tests for permanent Pi storage and post-save GitHub cleanup."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from tools.pi_artifact_store import archive_run, read_verified_archive
from tools.pi_artifact_cleanup import cleanup_github_artifacts


@unittest.skipUnless(os.name == "posix", "Pi-only protected directory behavior")
class DurableArchiveTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-pi-artifacts-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "private" / "ci-relay-lab"
        self.run = 987654321
        self.trace = "test-abcdef123456"
        self.sha = "a" * 40
        self.recipient = "f" * 64
        self.logs = {
            "ubuntu-24.04": "synthetic linux output\n",
            "windows-2025": "synthetic windows output\n",
        }
        self.ids = {"ubuntu-24.04": 10001, "windows-2025": 10002}

    def store(self):
        return archive_run(self.root, self.run, self.trace, self.sha,
                           self.recipient, self.logs, self.ids)

    def test_permanent_archive_is_private_durable_and_idempotent(self):
        path = self.store()
        self.assertEqual(path, self.store())
        manifest = read_verified_archive(self.root, self.run)
        self.assertEqual(manifest["artifact_ids"], self.ids)
        for p in (self.root.parent, self.root, path):
            self.assertEqual(p.stat().st_mode & 0o777, 0o700)
        for name in ("manifest.json", "ubuntu-24.04.log", "windows-2025.log"):
            self.assertEqual((path / name).stat().st_mode & 0o777, 0o600)

    def test_corruption_prevents_remote_deletion(self):
        path = self.store()
        (path / "windows-2025.log").write_text("modified", encoding="utf-8")
        calls = []
        with self.assertRaises(RuntimeError):
            cleanup_github_artifacts(lambda *args: calls.append(args), self.root, self.run)
        self.assertEqual(calls, [])

    def test_refuses_symlinked_archive(self):
        path = self.store()
        file = path / "ubuntu-24.04.log"
        file.unlink()
        file.symlink_to(path / "windows-2025.log")
        with self.assertRaises(RuntimeError):
            read_verified_archive(self.root, self.run)

    def test_refuses_changed_existing_run(self):
        self.store()
        self.logs["ubuntu-24.04"] = "different output"
        with self.assertRaises(RuntimeError):
            self.store()

    def test_deletes_both_remote_only_after_verified_local_copy(self):
        self.store()
        remote = {
            p: {"id": aid, "name": "encrypted-diagnostics-" + p}
            for p, aid in self.ids.items()
        }
        events = []

        def gh(*args):
            if args[0] == "api" and len(args) == 2:
                events.append("listed")
                return json.dumps({"artifacts": list(remote.values())})
            if args[:3] == ("api", "-X", "DELETE"):
                target = int(args[3].rsplit("/", 1)[1])
                events.append("deleted")
                for key, value in list(remote.items()):
                    if value["id"] == target:
                        del remote[key]
                        return ""
            raise AssertionError("Unexpected GitHub API call")

        result = cleanup_github_artifacts(gh, self.root, self.run)
        self.assertTrue(result["verified_on_pi"])
        self.assertFalse(remote)
        self.assertEqual(events, ["listed", "deleted", "deleted", "listed"])
        receipt = json.loads((self.root / f"run-{self.run}" /
                              "github-cleanup.json").read_text())
        self.assertTrue(receipt["confirmed_absent_from_github"])
        self.assertEqual(events.count("deleted"), 2)
        # Retrying is safe and does not delete unrelated remote artifacts.
        cleanup_github_artifacts(gh, self.root, self.run)
        self.assertEqual(events.count("deleted"), 2)

    def test_remote_artifact_replacement_is_rejected(self):
        self.store()
        seen = []

        def gh(*args):
            seen.append(args)
            return json.dumps({"artifacts": [{
                "id": 999999, "name": "encrypted-diagnostics-ubuntu-24.04",
            }]})

        with self.assertRaises(RuntimeError):
            cleanup_github_artifacts(gh, self.root, self.run)
        self.assertEqual(len(seen), 1)

    def test_remote_failure_leaves_verified_local_data(self):
        self.store()

        def gh(*args):
            raise ConnectionError("simulated GitHub outage")

        with self.assertRaises(ConnectionError):
            cleanup_github_artifacts(gh, self.root, self.run)
        self.assertEqual(read_verified_archive(self.root, self.run)["run_id"], self.run)
        self.assertFalse((self.root / f"run-{self.run}" /
                          "github-cleanup.json").exists())


if __name__ == "__main__":
    unittest.main()
