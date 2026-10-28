import unittest

from app import app
from url_checker import URLValidationError, check_url


class URLCheckerTests(unittest.TestCase):
    def test_rejects_missing_or_unsupported_scheme(self):
        with self.assertRaises(URLValidationError):
            check_url("example.com")
        with self.assertRaises(URLValidationError):
            check_url("javascript://example.com")

    def test_rejects_invalid_host_and_oversized_input(self):
        with self.assertRaises(URLValidationError):
            check_url("https:///missing-host")
        with self.assertRaises(URLValidationError):
            check_url("https://example.com/" + ("a" * 2050))

    def test_detects_at_symbol_and_ip_host(self):
        result = check_url("http://trusted.example@192.0.2.10/login/otp")
        titles = {finding["title"] for finding in result["findings"]}
        self.assertIn("An @ symbol appears before the host", titles)
        self.assertIn("The host is an IP address", titles)
        self.assertEqual(result["status"], "elevated")

    def test_detects_misleading_domain_and_suspicious_words(self):
        result = check_url(
            "https://paypal.com.security-check.example.net/verify-account"
        )
        titles = {finding["title"] for finding in result["findings"]}
        self.assertIn("The domain structure may be misleading", titles)
        self.assertIn("The URL contains commonly used lure words", titles)
        self.assertEqual(result["status"], "elevated")
        self.assertIn("not proof that a site is harmful", result["next_steps"][2])

    def test_plain_http_is_flagged(self):
        result = check_url("http://example.com/ordinary-page")
        self.assertEqual(len(result["findings"]), 1)
        self.assertIn("HTTPS", result["findings"][0]["title"])

    def test_clean_sample_is_not_called_safe(self):
        result = check_url("https://www.example.com/articles/safe-browsing")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["status"], "no-signals")
        self.assertIn("does not prove the URL is trustworthy", result["next_steps"][2])


class FlaskEndpointTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_home_page_renders(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CyberShield", response.data)
        self.assertIn(b"OTP SCAMS", response.data)

    def test_check_endpoint_returns_findings(self):
        response = self.client.post(
            "/check",
            json={"url": "http://192.0.2.10/login"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "elevated")
        self.assertTrue(response.json["findings"])

    def test_check_endpoint_validates_payload(self):
        response = self.client.post("/check", json={"url": "not-a-url"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("http://", response.json["error"])

    def test_health_endpoint(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
