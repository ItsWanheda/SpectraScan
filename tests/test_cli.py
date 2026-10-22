"""CLI integration tests for selected ports, output files, and strict parsing."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "SpectraScan.py"


class TestCliIntegration(unittest.TestCase):
    def _listener(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(0.2)
        port = server.getsockname()[1]
        stop = threading.Event()

        def serve():
            while not stop.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with conn:
                    try:
                        conn.sendall(b"test-service\r\n")
                        conn.settimeout(0.1)
                        try:
                            conn.recv(1024)
                        except OSError:
                            pass
                    except OSError:
                        pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.addCleanup(stop.set)
        self.addCleanup(server.close)
        self.addCleanup(thread.join, 1)
        return port

    def _run(self, *args, cwd):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, args)],
            cwd=cwd, env=env, text=True, capture_output=True, timeout=30,
        )

    def test_selected_port_is_scanned_and_report_written(self):
        port = self._listener()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "scan.json"
            result = self._run(
                "-t", "127.0.0.1", "-p", str(port), "--scan-type", "tcp",
                "--threads", "2", "--timeout", "0.3", "-o", output, cwd=temp,
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
            self.assertTrue(output.exists())
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual([item["port"] for item in report["open_ports"]], [port])
            self.assertEqual(report["scan_type"], "tcp")

    def test_unknown_argument_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self._run("-t", "127.0.0.1", "--not-a-real-option", cwd=temp)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unrecognized arguments", result.stderr)

    def test_invalid_port_range_is_rejected_before_network_access(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self._run("-t", "127.0.0.1", "-p", "0,70000", cwd=temp)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid --ports", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
