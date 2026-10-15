"""Reject tampered PUBLIC relay files before reintroducing upload token."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.opaque_checkout_integrity import check_checkout

WORKFLOW = (Path(__file__).resolve().parents[1] /
            ".github/workflows/secure-opaque-build.yml")


def workflow_script(step_name, next_name=None):
    """Read exactly one inline workflow-owned PowerShell script."""
    contents = WORKFLOW.read_text(encoding="utf-8")
    section = contents.split("      - name: " + step_name + "\n", 1)[1]
    if next_name is not None:
        section = section.split("      - name: " + next_name + "\n", 1)[0]
    else:
        section = section.split("      # Source, build.ps1,", 1)[0]
    body = section.split("        run: |\n", 1)[1]
    return "\n".join(
        line[10:] if line.startswith("          ") else line
        for line in body.splitlines()
    ) + "\n"


class WorkflowTrustBoundaryTests(unittest.TestCase):
    def test_first_integrity_verifier_is_embedded_in_workflow_not_checkout(self):
        script = workflow_script(
            "Verify PUBLIC relay implementation unchanged after compiling",
            "Publish only ciphertext and GitHub-signed build status")
        self.assertIn("'${{ github.sha }}'", script)
        self.assertIn("git ls-tree -r --full-tree", script)
        self.assertIn("SHA1]::HashData", script)
        self.assertIn("Unexpected public line ending", script)
        self.assertIn("Untracked or ignored public checkout file", script)
        self.assertNotIn("python -m", script.lower())
        self.assertNotIn("Invoke-Expression", script)

    def test_token_bearing_publisher_does_not_execute_checkout_code(self):
        script = workflow_script("Publish only ciphertext and GitHub-signed build status")
        self.assertIn("api.github.com/repos/SUAS-STEM/ci-relay-lab", script)
        self.assertIn("uploads.github.com/repos/SUAS-STEM/ci-relay-lab", script)
        self.assertIn("ACTIONS_ID_TOKEN_REQUEST_URL", script)
        self.assertIn("ci-opaque-result-v1", script)
        self.assertNotIn("python ", script.lower())
        self.assertNotIn("Invoke-Expression", script)
        self.assertNotIn("gh release", script.lower())

    def test_python_bytecode_generation_disabled_during_worker_job(self):
        self.assertIn("PYTHONDONTWRITEBYTECODE: '1'", WORKFLOW.read_text())
        self.assertNotIn("actions/upload-artifact", WORKFLOW.read_text())
        self.assertNotIn("actions/download-artifact", WORKFLOW.read_text())


@unittest.skipUnless(os.name == "nt" and shutil.which("pwsh"),
                     "Runs real inline PowerShell verification on Windows only")
class WindowsInlineIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ci-relay-win-gate-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "tools").mkdir()
        for index in range(32):
            (self.root / "tools" / f"public_test_{index:02}.py").write_bytes(
                f"# reviewed fixture {index}\n".encode("ascii"))
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True)
        subprocess.run(["git", "-c", "user.email=ci@example.invalid",
                        "-c", "user.name=CI", "commit", "-qm", "Fixture"],
                       cwd=self.root, check=True)
        self.sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, text=True).strip()
        age = self.root / ".age-bin"
        age.mkdir()
        for filename in ("age.exe", "age-keygen.exe"):
            (age / filename).write_bytes(b"fake binary; not executed")
        self.script = self.root.parent / (self.root.name + "-gate.ps1")
        self.script.write_text(workflow_script(
            "Verify PUBLIC relay implementation unchanged after compiling",
            "Publish only ciphertext and GitHub-signed build status"
        ).replace("${{ github.sha }}", self.sha), encoding="utf-8")
        self.addCleanup(self.script.unlink, missing_ok=True)

    def invoke(self):
        return subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(self.script)],
            cwd=self.root, env={**os.environ, "GITHUB_WORKSPACE": str(self.root)},
            capture_output=True, text=True, timeout=30)

    def test_original_and_windows_crlf_pass(self):
        self.assertEqual(self.invoke().returncode, 0)
        (self.root / "tools" / "public_test_00.py").write_bytes(
            b"# reviewed fixture 0\r\n")
        self.assertEqual(self.invoke().returncode, 0)

    def test_changed_and_assume_unchanged_file_rejected(self):
        victim = self.root / "tools" / "public_test_00.py"
        victim.write_bytes(b"# malicious replacement\n")
        subprocess.run(["git", "update-index", "--assume-unchanged",
                        "tools/public_test_00.py"], cwd=self.root, check=True)
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_untracked_ignored_bytecode_rejected(self):
        cache = self.root / "tools" / "__pycache__"
        cache.mkdir()
        (cache / "public_test_01.cpython-313.pyc").write_bytes(b"injected")
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_token_bearing_publisher_is_valid_powershell(self):
        publisher = self.root.parent / (self.root.name + "-publisher.ps1")
        publisher.write_text(workflow_script(
            "Publish only ciphertext and GitHub-signed build status"),
            encoding="utf-8")
        self.addCleanup(publisher.unlink, missing_ok=True)
        quoted = str(publisher).replace("'", "''")
        parser = (
            "$tokens=$null; $errors=$null; "
            "[System.Management.Automation.Language.Parser]::ParseFile("
            f"'{quoted}', [ref]$tokens, [ref]$errors) | Out-Null; "
            "if ($errors.Count -gt 0) { exit 1 }"
        )
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", parser],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)


class CheckoutIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="public-integrity-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "tools" / "public_worker.py"
        self.source.parent.mkdir()
        self.source.write_bytes(b"print('approved worker')\n")
        self.execute("init", "-q", "-b", "main")
        self.execute("add", "-A")
        self.execute("-c", "user.email=ci@example.invalid", "-c",
                     "user.name=CI", "commit", "-qm", "Approved public worker")
        self.sha = self.execute("rev-parse", "HEAD").strip()
        self.guard = patch("tools.opaque_checkout_integrity.check_tree")
        self.guard.start()
        self.addCleanup(self.guard.stop)

    def execute(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True,
                              capture_output=True, text=True, timeout=15).stdout

    def test_exact_committed_worker_passes(self):
        check_checkout(self.root, self.sha)

    def test_wrong_public_commit_rejected(self):
        with self.assertRaisesRegex(ValueError, "revision"):
            check_checkout(self.root, "a" * 40)

    def test_modified_tracked_worker_rejected(self):
        self.source.write_bytes(b"print('stolen token')\n")
        with self.assertRaisesRegex(ValueError, "changed|bytes"):
            check_checkout(self.root, self.sha)

    def test_untracked_injection_rejected(self):
        (self.root / "tools" / "malicious_import.py").write_text("steal_tokens()")
        with self.assertRaisesRegex(ValueError, "changed"):
            check_checkout(self.root, self.sha)

    def test_ignored_bytecode_injection_rejected(self):
        (self.root / ".git" / "info" / "exclude").write_text("*.pyc\n")
        (self.root / "tools" / "public_worker.pyc").write_bytes(b"malicious")
        with self.assertRaisesRegex(ValueError, "ignored/untracked"):
            check_checkout(self.root, self.sha)

    def test_assume_unchanged_cannot_hide_injected_worker(self):
        self.execute("update-index", "--assume-unchanged", "tools/public_worker.py")
        self.source.write_bytes(b"print('stolen token')\n")
        with self.assertRaisesRegex(ValueError, "bytes"):
            check_checkout(self.root, self.sha)

    def test_symlink_replacement_rejected(self):
        target = self.root / "injected.py"
        target.write_bytes(b"print('approved worker')\n")
        self.source.unlink()
        self.source.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "changed|type"):
            check_checkout(self.root, self.sha)


if __name__ == "__main__":
    unittest.main()
