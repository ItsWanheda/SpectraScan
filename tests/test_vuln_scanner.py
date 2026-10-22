"""Mocked CVE parsing/correlation tests; no live NVD requests."""
import unittest
from unittest import mock
from unittest.mock import Mock

from modules.vuln_scanner import VulnScanner
import SpectraScan


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

    def test_exact_cpe_version_range_is_potential_without_live_confirmation(self):
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
        self.assertEqual(classification, "potential")
        self.assertTrue(evidence)

    def test_keyword_only_match_is_not_confirmed(self):
        scanner = VulnScanner("ssh")
        classification, evidence = scanner._match_evidence({"configurations": []})
        self.assertEqual(classification, "informational")
        self.assertTrue(evidence)

    def test_cli_cve_correlation_uses_vendor_product_version_and_bound(self):
        fake = mock.MagicMock()
        fake.check_nvd_api.return_value = [{"id": "CVE-2099-1234", "classification": "potential"}]
        with mock.patch.object(SpectraScan, "VulnScanner", return_value=fake) as factory:
            report = SpectraScan.correlate_open_port_cves([
                {"port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_9.1",
                 "version_info": {"type": "SSH", "version": "9.1"}},
                {"port": 2222, "service": "SSH", "banner": "SSH-2.0-OpenSSH_9.1",
                 "version_info": {"type": "SSH", "version": "9.1"}},
                {"port": 80, "service": "HTTP", "banner": "HTTP/1.1 nginx/1.24.0",
                 "version_info": {"type": "HTTP", "version": "1.24.0"}},
            ], max_lookups=1, api_key="test-key")
        factory.assert_called_once()
        self.assertEqual(report["queries_attempted"], 1)
        self.assertEqual(report["queries_skipped_by_limit"], 1)
        self.assertEqual(report["findings"][0]["ports"], [22, 2222])
        self.assertEqual(factory.call_args.kwargs["vendor"], "openbsd")
        self.assertEqual(factory.call_args.kwargs["product"], "openssh")

    def test_cve_lookup_limit_cli_argument_requires_flag(self):
        parser = SpectraScan._cli_parser()
        args = parser.parse_args(["-t", "127.0.0.1", "--max-cve-lookups", "5"])
        self.assertEqual(args.max_cve_lookups, 5)
        self.assertFalse(args.cve_correlate)

    def test_cli_cve_correlation_limit_is_validated(self):
        with self.assertRaises(ValueError):
            SpectraScan.correlate_open_port_cves([], max_lookups=21)

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
