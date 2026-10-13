"""Safety tests for permanent Pi storage and post-save GitHub cleanup."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.pi_artifact_store import (archive_run, read_verified_archive,
                                     pending_github_cleanup,
                                     configured_archive_recipient,
                                     require_archive_encryption)
from tools.pi_artifact_cleanup import (cleanup_github_artifacts,
                                        cleanup_all_pending)
from tools.ephemeral_age import ephemeral_identity
from tools.pi_artifact_store import AGE_EXE
from tools.pi_artifact_verify import verify_all_archives


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

    def test_full_archive_audit_finds_verified_and_cleanup_pending(self):
        self.store()
        result = verify_all_archives(self.root)
        self.assertEqual(result["verified_runs"], [self.run])
        self.assertEqual(result["corrupt_runs"], [])
        self.assertEqual(result["github_cleanup_pending"], [self.run])
        self.assertEqual(result["incomplete_staging_directories"], [])
        self.assertEqual(result["bytes_verified"], sum(len(s.encode()) for s in self.logs.values()))

    def test_audit_detects_corruption_without_deleting_anything(self):
        run = self.store()
        (run / "windows-2025.log").write_bytes(b"corrupted")
        result = verify_all_archives(self.root)
        self.assertEqual(result["corrupt_runs"], [self.run])
        self.assertTrue(run.exists())

    def test_audit_reports_interrupted_staging_files(self):
        self.store()
        (self.root / ".stage-1234567-example").mkdir(mode=0o700)
        result = verify_all_archives(self.root)
        self.assertEqual(result["incomplete_staging_directories"], [
            ".stage-1234567-example",
        ])

    def test_compiled_linux_and_windows_outputs_are_durable(self):
        binaries = {"ubuntu-24.04": b"\x7fELFsynthetic",
                    "windows-2025": b"MZsynthetic"}
        path = archive_run(self.root, self.run, self.trace, self.sha,
                           self.recipient, self.logs, self.ids, binaries=binaries)
        manifest = read_verified_archive(self.root, self.run)
        self.assertEqual(manifest["schema"], 2)
        for name, value in (("ubuntu-24.04.bin", binaries["ubuntu-24.04"]),
                            ("windows-2025.exe", binaries["windows-2025"])):
            self.assertEqual((path / name).read_bytes(), value)
            self.assertEqual((path / name).stat().st_mode & 0o777, 0o600)

    def test_modified_binary_cannot_trigger_remote_deletion(self):
        path = archive_run(self.root, self.run, self.trace, self.sha,
                           self.recipient, self.logs, self.ids,
                           binaries={"ubuntu-24.04": b"\x7fELFsynthetic",
                                     "windows-2025": b"MZsynthetic"})
        (path / "windows-2025.exe").write_bytes(b"tampered")
        calls = []
        with self.assertRaises(RuntimeError):
            cleanup_github_artifacts(lambda *args: calls.append(args),
                                     self.root, self.run)
        self.assertEqual(calls, [])

    def test_optional_offline_key_encrypts_all_stored_payloads(self):
        binaries = {"ubuntu-24.04": b"\x7fELFsynthetic",
                    "windows-2025": b"MZsynthetic"}
        with ephemeral_identity() as recovery:
            path = archive_run(
                self.root, self.run, self.trace, self.sha, self.recipient,
                self.logs, self.ids, binaries=binaries,
                archive_recipient=recovery.recipient,
            )
            manifest = read_verified_archive(self.root, self.run)
            self.assertEqual(manifest["schema"], 3)
            self.assertTrue(manifest["storage_encryption"]["recipient_sha256"])
            for name, expected in (
                ("ubuntu-24.04.log.age", self.logs["ubuntu-24.04"].encode()),
                ("windows-2025.log.age", self.logs["windows-2025"].encode()),
                ("ubuntu-24.04.bin.age", binaries["ubuntu-24.04"]),
                ("windows-2025.exe.age", binaries["windows-2025"]),
            ):
                ciphertext = (path / name).read_bytes()
                self.assertTrue(ciphertext.startswith(b"age-encryption.org/v1\n"))
                self.assertNotIn(expected, ciphertext)
                result = subprocess.run(
                    [str(AGE_EXE), "-d", "-i", recovery.identity_path,
                     str(path / name)], capture_output=True, check=True,
                    pass_fds=(recovery.fd,), timeout=15,
                )
                self.assertEqual(result.stdout, expected)
            self.assertFalse((path / "windows-2025.exe").exists())
            self.assertFalse((path / "ubuntu-24.04.log").exists())
            with self.assertRaises(RuntimeError):
                archive_run(self.root, self.run, self.trace, self.sha,
                            self.recipient, self.logs, self.ids, binaries=binaries,
                            archive_recipient=recovery.recipient)

    def test_wrong_offline_key_cannot_decrypt_archive(self):
        binaries = {"ubuntu-24.04": b"\x7fELFtest", "windows-2025": b"MZtest"}
        with ephemeral_identity() as recovery, ephemeral_identity() as wrong:
            archive = archive_run(self.root, self.run, self.trace, self.sha,
                                  self.recipient, self.logs, self.ids,
                                  binaries=binaries,
                                  archive_recipient=recovery.recipient)
            result = subprocess.run(
                [str(AGE_EXE), "-d", "-i", wrong.identity_path,
                 str(archive / "windows-2025.exe.age")],
                capture_output=True, pass_fds=(wrong.fd,), timeout=15,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_encrypted_copy_can_authorize_remote_cleanup_without_offline_key(self):
        binaries = {"ubuntu-24.04": b"\x7fELFtest", "windows-2025": b"MZtest"}
        with ephemeral_identity() as recovery:
            archive_run(self.root, self.run, self.trace, self.sha,
                        self.recipient, self.logs, self.ids,
                        binaries=binaries, archive_recipient=recovery.recipient)
        self.assertEqual(pending_github_cleanup(self.root), [self.run])
        remote = {p: {"name": f"encrypted-diagnostics-{p}", "id": n}
                  for p, n in self.ids.items()}

        def gh(*args):
            if len(args) == 2:
                return json.dumps({"artifacts": list(remote.values())})
            aid = int(args[-1].rsplit("/", 1)[-1])
            for name in list(remote):
                if remote[name]["id"] == aid:
                    del remote[name]
                    return ""
            raise AssertionError("Unexpected GitHub deletion")

        cleanup_github_artifacts(gh, self.root, self.run)
        self.assertFalse(remote)
        self.assertEqual(pending_github_cleanup(self.root), [])

    def test_offline_recipient_rejects_bad_permissions_and_malformed_data(self):
        path = Path(self.temp.name) / "offline-public-key"
        self.assertIsNone(configured_archive_recipient(path))
        path.write_text("age1invalid\n", encoding="ascii")
        path.chmod(0o600)
        with self.assertRaises(RuntimeError):
            configured_archive_recipient(path)
        with ephemeral_identity() as recovery:
            path.write_text(recovery.recipient + "\n", encoding="ascii")
            self.assertEqual(configured_archive_recipient(path), recovery.recipient)
            path.chmod(0o644)
            with self.assertRaises(RuntimeError):
                configured_archive_recipient(path)

    def test_encryption_requirement_prevents_missing_key_plaintext_downgrade(self):
        path = Path(self.temp.name) / "archive-recipient.agepub"
        with self.assertRaises(RuntimeError):
            require_archive_encryption(path)
        with ephemeral_identity() as recovery:
            path.write_text(recovery.recipient + "\n", encoding="ascii")
            path.chmod(0o600)
            require_archive_encryption(path)
            require_archive_encryption(path)  # idempotent
            self.assertEqual(configured_archive_recipient(path), recovery.recipient)
            path.unlink()
            with self.assertRaisesRegex(RuntimeError, "refusing plaintext downgrade"):
                configured_archive_recipient(path)
            path.write_text(recovery.recipient + "\n", encoding="ascii")
            path.chmod(0o600)
            self.assertEqual(configured_archive_recipient(path), recovery.recipient)
            marker = path.with_name("archive-encryption-required")
            marker.write_text("invalid", encoding="ascii")
            with self.assertRaises(RuntimeError):
                configured_archive_recipient(path)

    def test_encryption_requirement_rejects_corrupt_marker_and_unsafe_permissions(self):
        path = Path(self.temp.name) / "archive-recipient.agepub"
        with ephemeral_identity() as recovery:
            path.write_text(recovery.recipient + "\n", encoding="ascii")
            path.chmod(0o600)
            require_archive_encryption(path)
            marker = path.with_name("archive-encryption-required")
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            marker.chmod(0o644)
            with self.assertRaises(RuntimeError):
                configured_archive_recipient(path)
            path.unlink()
            path.symlink_to(Path(self.temp.name) / "missing")
            with self.assertRaises(RuntimeError):
                configured_archive_recipient(path)

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

    def test_refuses_symlinked_remote_cleanup_receipt(self):
        path = self.store()
        (path / "github-cleanup.json").symlink_to(path / "manifest.json")
        with self.assertRaises(RuntimeError):
            read_verified_archive(self.root, self.run)

    def test_find_pending_ignores_partial_stages_and_verified_completed_runs(self):
        self.store()
        (self.root / ".stage-999999-crashed").mkdir(mode=0o700)
        self.assertEqual(pending_github_cleanup(self.root), [self.run])
        receipt = self.root / f"run-{self.run}" / "github-cleanup.json"
        receipt.write_text(
            json.dumps({"run_id": self.run, "deleted_artifact_ids": self.ids,
                        "confirmed_absent_from_github": True}), encoding="utf-8")
        receipt.chmod(0o600)
        self.assertEqual(pending_github_cleanup(self.root), [])

    def test_malformed_receipt_cannot_silently_suppress_cleanup(self):
        path = self.store()
        (path / "github-cleanup.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            pending_github_cleanup(self.root)

    def test_oversized_manifest_rejected_before_json_load(self):
        path = self.store()
        (path / "manifest.json").write_bytes(b"{" + b" " * 18000 + b"}")
        with self.assertRaises(RuntimeError):
            read_verified_archive(self.root, self.run)

    def test_oversized_local_log_rejected_before_read(self):
        path = self.store()
        with (path / "ubuntu-24.04.log").open("wb") as dest:
            dest.truncate(22 * 1024 * 1024)
        with self.assertRaises(RuntimeError):
            read_verified_archive(self.root, self.run)

    def test_non_regular_file_rejected(self):
        path = self.store()
        member = path / "ubuntu-24.04.log"
        member.unlink()
        member.mkdir()
        with self.assertRaises((RuntimeError, OSError)):
            read_verified_archive(self.root, self.run)

    def test_oversized_cleanup_receipt_rejected(self):
        path = self.store()
        (path / "github-cleanup.json").write_bytes(b"{" + b" " * 9000 + b"}")
        with self.assertRaises(RuntimeError):
            read_verified_archive(self.root, self.run)

    def test_pending_cleanup_after_pi_restart(self):
        self.store()
        events = []
        catalog = {"artifacts": [
            {"name": "encrypted-diagnostics-" + name, "id": ident}
            for name, ident in self.ids.items()
        ]}

        def gh(*args):
            events.append(args)
            if len(args) == 2:
                return json.dumps(catalog)
            ident = int(args[-1].rsplit('/', 1)[1])
            catalog["artifacts"] = [
                item for item in catalog["artifacts"] if item["id"] != ident
            ]
            return ""

        self.assertEqual(cleanup_all_pending(gh, self.root)["completed"], [self.run])
        self.assertEqual(cleanup_all_pending(gh, self.root), {
            "completed": [], "failed": [],
        })
        self.assertEqual(len([event for event in events if "DELETE" in event]), 2)

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
