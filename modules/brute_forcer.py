"""Credential audit helpers with verified SSH host identity and redacted results."""
import logging
import queue
import threading

logger = logging.getLogger(__name__)


class BruteForcer:
    """Test explicitly authorized credentials; successful records never contain passwords.

    SSH attempts require host keys already present in the user's known_hosts file.
    """
    def __init__(self, target, port, service, wordlist_path, max_threads=10):
        if not isinstance(max_threads, int) or not 1 <= max_threads <= 64:
            raise ValueError("max_threads must be between 1 and 64")
        self.target, self.port, self.service = target, int(port), str(service).lower()
        if self.service not in {"ssh", "ftp"}:
            raise ValueError("service must be 'ssh' or 'ftp'")
        self.wordlist_path, self.max_threads = wordlist_path, max_threads
        self.results = []
        self.errors = []
        self.lock = threading.Lock()

    def load_wordlist(self):
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as handle:
                return [line.strip() for line in handle if line.strip()]
        except OSError as exc:
            logger.warning("Cannot read credential wordlist (%s)", type(exc).__name__)
            with self.lock:
                self.errors.append({"category": "wordlist_error", "reason": type(exc).__name__})
            return []

    def check_ssh(self, username, password):
        client = None
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(self.target, port=self.port, username=username, password=password,
                           timeout=3, banner_timeout=3, auth_timeout=3, allow_agent=False,
                           look_for_keys=False)
            with self.lock:
                record = {"status": "SUCCESS", "service": "ssh", "user": username,
                          "host": self.target, "port": self.port}
                if record not in self.results:
                    self.results.append(record)
            return True
        except Exception as exc:
            category = "host_key_error" if exc.__class__.__name__ in {
                "BadHostKeyException", "SSHException"} else (
                "authentication_failed" if exc.__class__.__name__ == "AuthenticationException"
                else "connection_error")
            with self.lock:
                self.errors.append({"category": category, "service": "ssh",
                                    "error_type": type(exc).__name__})
            return False
        finally:
            if client is not None:
                client.close()

    def check_ftp(self, username, password):
        ftp = None
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(self.target, self.port, timeout=3)
            ftp.login(username, password)
            with self.lock:
                record = {"status": "SUCCESS", "service": "ftp", "user": username,
                          "host": self.target, "port": self.port}
                if record not in self.results:
                    self.results.append(record)
            return True
        except Exception as exc:
            category = "authentication_failed" if isinstance(exc, ftplib.error_perm) else "connection_error"
            with self.lock:
                self.errors.append({"category": category, "service": "ftp",
                                    "error_type": type(exc).__name__})
            return False
        finally:
            if ftp is not None:
                try:
                    ftp.close()
                except Exception:
                    pass

    def run(self):
        wordlist = self.load_wordlist()
        if not wordlist:
            return self.results
        tasks = queue.Queue()
        # Fill queue before workers start; sentinel shutdown is deterministic.
        for password in wordlist:
            tasks.put(("admin", password))
            tasks.put(("root", password))
        for _ in range(self.max_threads):
            tasks.put(None)

        def worker():
            while True:
                task = tasks.get()
                try:
                    if task is None:
                        return
                    username, password = task
                    if self.service == "ssh":
                        self.check_ssh(username, password)
                    else:
                        self.check_ftp(username, password)
                finally:
                    tasks.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(self.max_threads)]
        for thread in threads:
            thread.start()
        tasks.join()
        for thread in threads:
            thread.join()
        return self.results
