import logging
import queue
import threading

import requests


logger = logging.getLogger(__name__)


class WebEnumerator:
    def __init__(self, base_url, wordlist_path, max_threads=20):
        self.base_url = base_url.rstrip("/")
        self.wordlist_path = wordlist_path
        self.max_threads = max(1, int(max_threads))
        self.found_paths = []
        self.lock = threading.Lock()

    def load_wordlist(self):
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as file:
                return [line.strip() for line in file if line.strip()]
        except OSError as exc:
            logger.error("Unable to read wordlist %s: %s", self.wordlist_path, exc)
            return []

    def check_path(self, path):
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            response = requests.head(
                url,
                timeout=2,
                allow_redirects=False,
            )
            if response.status_code in {200, 301, 302, 403}:
                result = {
                    "path": path,
                    "status": response.status_code,
                    "url": url,
                }
                with self.lock:
                    self.found_paths.append(result)
                logger.info("[+] Found: %s (%s)", url, response.status_code)
        except requests.RequestException:
            pass

    def run(self):
        wordlist = self.load_wordlist()
        if not wordlist:
            return []

        tasks = queue.Queue()
        for word in wordlist:
            tasks.put(word)

        def worker():
            while True:
                try:
                    path = tasks.get_nowait()
                except queue.Empty:
                    return

                try:
                    self.check_path(path)
                finally:
                    tasks.task_done()

        threads = [
            threading.Thread(target=worker, daemon=True)
            for _ in range(min(self.max_threads, tasks.qsize()))
        ]

        for thread in threads:
            thread.start()

        tasks.join()

        for thread in threads:
            thread.join(timeout=1)

        return list(self.found_paths)
