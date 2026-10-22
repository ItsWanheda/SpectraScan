"""Atomic report store and spreadsheet-safe export tests."""
import json
import tempfile
import unittest
from pathlib import Path

from modules.report_store import ReportStore, safe_csv_cell


class TestReportStore(unittest.TestCase):
    def test_atomic_json_write_and_history(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ReportStore(temp)
            path = store.save_json("SS-report.json", {"ok": True})
            self.assertTrue(Path(path).exists())
            self.assertEqual(json.loads(Path(path).read_text(encoding="utf-8")), {"ok": True})
            self.assertIn("SS-report.json", store.list_reports())
            self.assertEqual(store.read_text("SS-report.json").strip()[0], "{")
            store.delete("SS-report.json")
            self.assertNotIn("SS-report.json", store.list_reports())

    def test_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ReportStore(temp)
            with self.assertRaises(ValueError):
                store.read_text("../secret.txt")

    def test_formula_leading_csv_cells_are_neutralized(self):
        for value in ("=1+1", "+cmd", "-2+3", "@SUM(A1:A2)", "  =1+1"):
            with self.subTest(value=value):
                self.assertTrue(safe_csv_cell(value).lstrip().startswith("'"))


if __name__ == "__main__":
    unittest.main()
