"""Mocked CVE parsing/correlation tests; no live NVD requests."""
import unittest
from unittest.mock import Mock

from modules.vuln_scanner import VulnScanner


class TestVulnScanner(unittest.TestCase):
    def test_missing_cvss_metrics_do_not_crash(self):
        session = Mock()
        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2025-0001",
                    "descriptions": [{"lang": "en", "value": "Example CVE"}],
                    "metrics": {},
                    "configurations": [],
                }
            }],
        }
        session.get.return_value = response
        scanner = VulnScanner("openssh", "9.1", session=session, max_records=10)
        found = scanner.check_nvd_api()
        self.assertEqual(found[0]["severity"], "UNKNOWN")
        self.assertIn(found[0]["classification"], {"potential", "informational", "confirmed"})

    def test_exact_cpe_version_range_classified_confirmed(self):
        scanner = VulnScanner("openssh", "9.1", vendor="openbsd", product="openssh")
        cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:openbsd:openssh:9.1:*:*:*:*:*:*:*",
                    }]
                }]
            }]
        }
        classification, evidence = scanner._match_evidence(cve)
        self.assertEqual(classification, "confirmed")
        self.assertTrue(evidence)

    def test_keyword_only_match_is_not_confirmed(self):
        scanner = VulnScanner("ssh")
        classification, evidence = scanner._match_evidence({"configurations": []})
        self.assertEqual(classification, "informational")
        self.assertTrue(evidence)

    def test_rate_limit_returns_structured_error(self):
        session = Mock()
        response = Mock()
        response.status_code = 403
        response.headers = {}
        session.get.return_value = response
        scanner = VulnScanner("ssh", session=session)
        self.assertEqual(scanner.check_nvd_api(), [])
        self.assertEqual(scanner.errors[0]["category"], "rate_limited")


if __name__ == "__main__":
    unittest.main()
