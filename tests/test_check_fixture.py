import unittest

from tools.check_fixture import parse_request
from tools import run_encrypted_fixture
from tools import pi_public_release as dispatcher
from unittest.mock import patch


class InputValidationTest(unittest.TestCase):
    def test_encrypt_wrapper_imports(self):
        self.assertTrue(callable(run_encrypted_fixture.main))

    def test_normal(self):
        self.assertEqual(parse_request("test-1234", "12", "-8"), (12, -8))

    def test_reject_bad_trace(self):
        with self.assertRaises(ValueError):
            parse_request("../../unsafe", "1", "2")

    def test_reject_payload_as_code(self):
        with self.assertRaises(ValueError):
            parse_request("trace-123", "$(curl dangerous.invalid)", "2")

    def test_reject_out_of_range(self):
        with self.assertRaises(ValueError):
            parse_request("trace-123", "99999", "2")


class HostileDispatchTest(unittest.TestCase):
    SHA = "a" * 40

    def test_reject_wrong_commit(self):
        import json
        record = {"head_sha": "b" * 40, "head_branch": "main",
                  "event": "workflow_dispatch", "path": ".github/workflows/fixture.yml",
                  "actor": {"login": "eschan145"}, "status": "completed",
                  "conclusion": "success", "repository": {"full_name": dispatcher.PUBLIC_REPO},
                  "run_attempt": 1}
        with patch.object(dispatcher, "gh", return_value=json.dumps(record)):
            with self.assertRaisesRegex(RuntimeError, "not from the approved"):
                dispatcher.validate_job(123, self.SHA, "main", "fixture.yml")

    def test_reject_untrusted_runner_actor(self):
        import json
        record = {"head_sha": self.SHA, "head_branch": "main",
                  "event": "workflow_dispatch", "path": ".github/workflows/fixture.yml",
                  "actor": {"login": "unauthorized"}, "status": "completed",
                  "conclusion": "success", "repository": {"full_name": dispatcher.PUBLIC_REPO},
                  "run_attempt": 1}
        with patch.object(dispatcher, "gh", return_value=json.dumps(record)):
            with self.assertRaisesRegex(RuntimeError, "not from the approved"):
                dispatcher.validate_job(123, self.SHA, "main", "fixture.yml")

    def test_reject_wrong_run_origin(self):
        import json
        details = {"head_sha": self.SHA, "event": "pull_request", "head_branch": "main",
                   "path": ".github/workflows/fixture.yml", "actor": {"login": "eschan145"},
                   "status": "completed", "conclusion": "success",
                   "repository": {"full_name": dispatcher.PUBLIC_REPO}, "run_attempt": 1}
        with patch.object(dispatcher, "gh", return_value=json.dumps(details)):
            with self.assertRaisesRegex(RuntimeError, "not from the approved"):
                dispatcher.validate_job(123, self.SHA, "main", "fixture.yml")

    def test_reject_missing_matrix_job(self):
        import json
        details = {"head_sha": self.SHA, "event": "workflow_dispatch", "head_branch": "main",
                   "path": ".github/workflows/fixture.yml", "actor": {"login": "eschan145"},
                   "status": "completed", "conclusion": "success",
                   "repository": {"full_name": dispatcher.PUBLIC_REPO}, "run_attempt": 1}
        with patch.object(dispatcher, "gh", side_effect=(json.dumps(details),
                  json.dumps({"jobs": [{"name": "ubuntu-24.04", "id": 1,
                                        "status": "completed", "conclusion": "success"}]}))):
            with self.assertRaisesRegex(RuntimeError, "job set"):
                dispatcher.validate_job(123, self.SHA, "main", "fixture.yml")

    def test_build_subprocess_environment_scrubs_runner_tokens(self):
        hostile_env = {
            "GITHUB_TOKEN": "never-export-me", "ACTIONS_RUNTIME_TOKEN": "nope",
            "MY_SECRET": "not-for-children", "PATH": "/usr/bin", "HOME": "/tmp",
            "VSINSTALLDIR": "C:\\VisualStudio", "VisualStudioVersion": "17.0",
        }
        actual = run_encrypted_fixture.sanitized_build_environment(hostile_env)
        self.assertEqual(actual, {"PATH": "/usr/bin", "HOME": "/tmp",
                                  "VSINSTALLDIR": "C:\\VisualStudio", "VisualStudioVersion": "17.0"})


if __name__ == "__main__":
    unittest.main()
