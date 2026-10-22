import csv
import tempfile
import unittest
from pathlib import Path

from SpectraScan import PortScanner, ReportManager


class TestReportExports(unittest.TestCase):
    def test_csv_formula_payload_is_neutralized(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "report.csv"
            scanner = PortScanner("127.0.0.1", ports=[80])
            scanner.results = [{"port": 80, "state": "open", "service": "http",
                                "banner": "=HYPERLINK(\"https://example.invalid\")",
                                "vulnerabilities": []}]
            scanner.export_csv(str(path))
            with path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle))
            self.assertTrue(rows[1][4].startswith("'="))

    def test_report_directory_respects_environment(self):
        import os
        with tempfile.TemporaryDirectory() as temp:
            old = os.environ.get("SPECTRASCAN_HOME")
            os.environ["SPECTRASCAN_HOME"] = temp
            try:
                manager = ReportManager()
                self.assertEqual(Path(manager.report_dir), Path(temp))
                self.assertEqual(manager.save_output("atomic.txt", "safe"), str(Path(temp) / "atomic.txt"))
                self.assertEqual((Path(temp) / "atomic.txt").read_text(encoding="utf-8"), "safe")
            finally:
                if old is None:
                    os.environ.pop("SPECTRASCAN_HOME", None)
                else:
                    os.environ["SPECTRASCAN_HOME"] = old


if __name__ == "__main__":
    unittest.main()
