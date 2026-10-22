"""Resource-limit and exclusion tests for CIDR scan orchestration."""
import unittest
from unittest.mock import patch

import SpectraScan


class TestNetworkSweep(unittest.TestCase):
    def test_large_ranges_require_confirmation_before_iteration(self):
        with self.assertRaisesRegex(ValueError, "explicit confirmation"):
            SpectraScan.run_network_port_scan("192.168.1.0/24", {"ports": [80]}, max_targets=1024)

    def test_address_count_hard_cap_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "configured maximum"):
            SpectraScan.run_network_port_scan("192.168.0.0/16", {"ports": [80]}, max_targets=1024, large_scan_confirmed=True)

    def test_excluded_network_is_not_scanned(self):
        seen = []

        class FakeScanner:
            def __init__(self, target, **kwargs):
                self.target = target
                self.results = []

            def scan(self):
                seen.append(self.target)
                self.results = [{"port": 80, "state": "open"}]

        with patch.object(SpectraScan, "PortScanner", FakeScanner):
            rows = SpectraScan.run_network_port_scan(
                "192.0.2.0/30", {"ports": [80], "threads": 1},
                exclusions=["192.0.2.1/32"], max_targets=8,
                large_scan_confirmed=True, host_workers=2,
            )
        self.assertEqual({row["ip"] for row in rows}, {"192.0.2.2"})
        self.assertNotIn("192.0.2.1", seen)


if __name__ == "__main__":
    unittest.main()
