import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.brute_forcer import BruteForcer


class TestBruteForcerQueue(unittest.TestCase):
    def test_all_queued_credentials_are_processed_and_results_are_redacted(self):
        with tempfile.TemporaryDirectory() as temp:
            wordlist = Path(temp) / "passwords.txt"
            wordlist.write_text("one\ntwo\n", encoding="utf-8")
            scanner = BruteForcer("127.0.0.1", 22, "ssh", str(wordlist), max_threads=3)
            attempted = []
            lock = threading.Lock()

            def fake_check(username, password):
                with lock:
                    attempted.append((username, password))
                    scanner.results.append({"status": "SUCCESS", "service": "ssh",
                                            "user": username, "host": scanner.target,
                                            "port": scanner.port})
                return True

            with patch.object(scanner, "check_ssh", side_effect=fake_check):
                results = scanner.run()

            self.assertCountEqual(attempted, [
                ("admin", "one"), ("root", "one"),
                ("admin", "two"), ("root", "two")
            ])
            self.assertEqual(len(results), 4)
            self.assertTrue(all("pass" not in result and "password" not in result for result in results))


if __name__ == "__main__":
    unittest.main()
