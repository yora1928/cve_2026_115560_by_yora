import unittest
from unittest.mock import MagicMock
import requests

from cve_checker import validate_url, same_origin, check_http, assess_cve


class CheckerTests(unittest.TestCase):
    def test_url_validation(self):
        self.assertTrue(validate_url("https://example.com/path"))
        self.assertTrue(validate_url("http://localhost:8080"))
        self.assertFalse(validate_url("ftp://example.com"))
        self.assertFalse(validate_url("not-a-url"))

    def test_same_origin(self):
        self.assertTrue(same_origin("https://example.com/a", "https://example.com/upload"))
        self.assertFalse(same_origin("https://example.com", "https://other.example/upload"))

    def test_http_200(self):
        session = MagicMock()
        response = MagicMock()
        response.status_code = 200
        response.reason = "OK"
        response.headers = {"X-Powered-By": "PHP"}
        response.text = "hello"
        session.request.return_value = response
        result = check_http(session, "https://example.com", 5, 0)
        self.assertEqual(result["status_code"], 200)
        self.assertTrue(result["php_indicated"])

    def test_timeout(self):
        session = MagicMock()
        session.request.side_effect = requests.exceptions.Timeout()
        result = check_http(session, "https://example.com", 1, 0)
        self.assertIn("Timeout", result["error"])
        status, _ = assess_cve(result)
        self.assertEqual(status, "ERROR")

    def test_http_does_not_prove_cve(self):
        result = {"error": None, "php_indicated": True, "status_code": 200}
        status, notes = assess_cve(result)
        self.assertEqual(status, "NOT_ASSESSED")
        self.assertTrue(notes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
