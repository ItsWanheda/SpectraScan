"""Regression tests that verify scanner mode dispatch."""
import unittest
from unittest.mock import patch

import SpectraScan


class FakeUdp:
    def scan(self, target, port, timeout=3.0):
        return {"state": "open", "service": ("DNS", "DNS Query"), "response": "abcd"}


class TestScanModes(unittest.TestCase):
    def test_udp_option_uses_udp_probe(self):
        scanner = SpectraScan.PortScanner(
            "127.0.0.1", scan_type="udp", ports=[53], timing="custom", threads=1
        )
        scanner.resolved_ip = "127.0.0.1"
        with patch.object(SpectraScan, "UDPScan", return_value=FakeUdp()):
            result = scanner.scan_port(53)
        self.assertEqual(result["protocol"], "udp")
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["service"], "DNS")

    def test_syn_option_uses_syn_scanner(self):
        scanner = SpectraScan.PortScanner(
            "127.0.0.1", scan_type="syn", ports=[22], timing="custom", threads=1
        )
        scanner.resolved_ip = "127.0.0.1"
        with patch.object(SpectraScan.SYNScan, "scan", return_value="closed") as probe:
            result = scanner.scan_port(22)
        probe.assert_called_once_with("127.0.0.1", 22, timeout=scanner.timeout)
        self.assertEqual(result["protocol"], "tcp")
        self.assertEqual(result["state"], "closed")

    def test_legacy_scanner_processes_ports_with_bounded_worker_pool(self):
        scanner = SpectraScan.PortScanner(
            "127.0.0.1", ports=list(range(1, 501)), timing="custom", threads=4
        )
        calls = []
        def fake_probe(port):
            calls.append(port)
            return {"port": port, "protocol": "tcp", "state": "closed", "service": "unknown", "banner": "", "vulnerabilities": []}
        with patch.object(scanner, "scan_port", side_effect=fake_probe):
            results = scanner.scan()
        self.assertEqual(len(calls), 500)
        self.assertEqual(results, [])

    def test_syn_scan_does_not_silently_fall_back_to_tcp_connect(self):
        scanner = SpectraScan.SYNScan()
        scanner.is_admin = False
        with patch("socket.socket") as socket_factory:
            state = scanner.scan("127.0.0.1", 80)
        self.assertEqual(state, "error")
        socket_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
