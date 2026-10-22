import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "SpectraScan.py"


class TestCliIntegration(unittest.TestCase):
    def run_cli(self, *args):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=ROOT,
                              env=env, capture_output=True, text=True, timeout=30)

    def test_unknown_arguments_are_rejected(self):
        result = self.run_cli("--target", "127.0.0.1", "--not-a-real-option")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrecognized arguments", result.stderr)

    def test_invalid_ports_are_rejected(self):
        result = self.run_cli("--target", "127.0.0.1", "--ports", "80,nope")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid --ports", result.stderr)

    def test_tcp_scan_honors_port_selection_and_writes_json(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "scan.json"
            result = self.run_cli("--target", "127.0.0.1", "--ports", "1",
                                  "--timeout", "0.1", "--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertTrue(output.exists())
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["target"], "127.0.0.1")
            self.assertEqual(report["scan_type"], "tcp")
            self.assertTrue(all(item["port"] == 1 for item in report["open_ports"]))

    def test_udp_scan_type_is_recorded_and_exported(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "udp.json"
            result = self.run_cli("--target", "127.0.0.1", "--ports", "1",
                                  "--scan-type", "udp", "--timeout", "0.1",
                                  "--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["scan_type"], "udp")


if __name__ == "__main__":
    unittest.main()
