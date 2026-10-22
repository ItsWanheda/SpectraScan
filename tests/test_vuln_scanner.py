import unittest
from unittest.mock import Mock

from modules.vuln_scanner import VulnScanner, _severity


class TestVulnScanner(unittest.TestCase):
    def test_handles_missing_cvss_metrics(self):
        self.assertEqual(_severity({"metrics": {}}), "UNKNOWN")

    def test_keyword_result_is_not_confirmed_without_cpe_evidence(self):
        scanner = VulnScanner("nginx", "1.2.3", session=Mock())
        self.assertIsNone(scanner._matches_cpe({"configurations": []}))

    def test_malformed_api_response_is_structured_error(self):
        session = Mock()
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"vulnerabilities": "not-a-list"}
        session.get.return_value = response
        scanner = VulnScanner("nginx", "1.2.3", session=session)
        self.assertEqual(scanner.check_nvd_api(), [])
        self.assertEqual(scanner.errors[0]["category"], "nvd_api_error")


if __name__ == "__main__":
    unittest.main()
