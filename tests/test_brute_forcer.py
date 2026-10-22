"""Regression tests for deterministic workers and secret-safe results."""
import tempfile
import unittest
from pathlib import Path

from modules.brute_forcer import BruteForcer


class FakeBruteForcer(BruteForcer):
    def check_ssh(self, username, password):
        if password == "match":
            return {"status": "success", "category": "authenticated", "username": username, "password": password}
        return {"status": "failed", "category": "invalid_credentials", "username": username}


class TestBruteForcer(unittest.TestCase):
    def test_queue_is_filled_before_workers_and_passwords_are_not_retained(self):
        with tempfile.TemporaryDirectory() as temp:
            wordlist = Path(temp) / "words.txt"
            wordlist.write_text("wrong\nmatch\n", encoding="utf-8")
            scanner = FakeBruteForcer("127.0.0.1", 22, "ssh", str(wordlist), max_threads=4)
            results = scanner.run()
            self.assertEqual(len(results), 2)
            self.assertTrue(all("password" not in item and "pass" not in item for item in results))
            self.assertEqual({item["username"] for item in results}, {"admin", "root"})

    def test_unknown_service_and_invalid_port_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            wordlist = Path(temp) / "words.txt"
            wordlist.write_text("x", encoding="utf-8")
            with self.assertRaises(ValueError):
                BruteForcer("localhost", 0, "ssh", str(wordlist))
            with self.assertRaises(ValueError):
                BruteForcer("localhost", 22, "telnet", str(wordlist))


if __name__ == "__main__":
    unittest.main()
