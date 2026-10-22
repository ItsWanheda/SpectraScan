"""Credential validation for explicitly authorized SSH/FTP audits.

Never logs or retains plaintext passwords. SSH trusts known-host entries or
an explicitly configured SHA256 host-key fingerprint.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import queue
import socket
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _fingerprint(key: Any) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class BruteForcer:
    """Bounded worker queue with explicit result/error categories."""

    def __init__(
        self, target: str, port: int, service: str, wordlist_path: str,
        max_threads: int = 10, known_hosts_path: Optional[str] = None,
        expected_host_fingerprint: Optional[str] = None,
        max_passwords: int = 100,
        allow_insecure_ftp: bool = False,
    ) -> None:
        self.target = str(target)
        self.port = int(port)
        self.service = str(service).lower()
        self.wordlist_path = str(wordlist_path)
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be in the range 1..65535")
        if self.service not in {"ssh", "ftp"}:
            raise ValueError("service must be 'ssh' or 'ftp'")
        if isinstance(max_threads, bool) or not 1 <= int(max_threads) <= 32:
            raise ValueError("max_threads must be between 1 and 32")
        self.max_threads = int(max_threads)
        self.known_hosts_path = known_hosts_path
        self.expected_host_fingerprint = expected_host_fingerprint
        if isinstance(max_passwords, bool) or not 1 <= int(max_passwords) <= 1000:
            raise ValueError("max_passwords must be between 1 and 1000")
        self.max_passwords = int(max_passwords)
        self.allow_insecure_ftp = bool(allow_insecure_ftp)
        if self.expected_host_fingerprint and not self.expected_host_fingerprint.startswith("SHA256:"):
            raise ValueError("expected_host_fingerprint must use the OpenSSH SHA256: format")
        self.results: list[Dict[str, Any]] = []
        self.error_counts: Counter[str] = Counter()
        self.lock = threading.Lock()

    def load_wordlist(self) -> list[str]:
        try:
            words = []
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as stream:
                for line in stream:
                    candidate = line.strip()
                    if not candidate:
                        continue
                    words.append(candidate)
                    if len(words) >= self.max_passwords:
                        break
            return words
        except OSError as exc:
            logger.error("Unable to read credential wordlist (%s)", type(exc).__name__)
            return []

    def _record(self, outcome: Dict[str, Any]) -> None:
        category = str(outcome.get("category", "unknown_error"))
        with self.lock:
            if outcome.get("status") == "success":
                # Whitelist output fields; never persist a password or exception text.
                self.results.append({
                    "status": "SUCCESS", "service": self.service,
                    "target": self.target, "port": self.port,
                    "username": str(outcome.get("username", "")),
                    "category": "authenticated",
                })
            elif outcome.get("status") in {"error", "failed"}:
                self.error_counts[category] += 1

    def check_ssh(self, username: str, password: str) -> Dict[str, Any]:
        try:
            import paramiko
        except ImportError:
            return {"status": "error", "category": "dependency_missing"}
        client = paramiko.SSHClient()
        try:
            expected = (self.expected_host_fingerprint or "").strip()
            # In fingerprint-pinning mode do not load existing known-host keys:
            # Paramiko would accept a known key before invoking MissingHostKeyPolicy.
            if not expected:
                client.load_system_host_keys()
                if self.known_hosts_path:
                    client.load_host_keys(str(Path(self.known_hosts_path).expanduser()))
            if expected:
                class PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
                    def missing_host_key(policy_self, ssh_client, hostname, key):
                        actual = _fingerprint(key)
                        if not hmac.compare_digest(actual, expected):
                            raise paramiko.SSHException("Configured host-key fingerprint mismatch")
                        ssh_client.get_host_keys().add(hostname, key.get_name(), key)
                client.set_missing_host_key_policy(PinnedHostKeyPolicy())
            else:
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(
                self.target, port=self.port, username=username, password=password,
                timeout=5, banner_timeout=5, auth_timeout=5,
                allow_agent=False, look_for_keys=False,
            )
            remote_key = client.get_transport().get_remote_server_key()
            if expected and not hmac.compare_digest(_fingerprint(remote_key), expected):
                return {"status": "error", "category": "host_key_mismatch"}
            return {"status": "success", "category": "authenticated", "username": username}
        except paramiko.BadHostKeyException:
            return {"status": "error", "category": "host_key_mismatch"}
        except paramiko.AuthenticationException:
            return {"status": "failed", "category": "invalid_credentials"}
        except paramiko.SSHException as exc:
            message = str(exc).lower()
            category = "host_key_unverified" if "known_hosts" in message or "host key" in message else "ssh_error"
            return {"status": "error", "category": category}
        except (socket.timeout, TimeoutError):
            return {"status": "error", "category": "timeout"}
        except OSError:
            return {"status": "error", "category": "connection_error"}
        except Exception:
            return {"status": "error", "category": "ssh_error"}
        finally:
            try:
                client.close()
            except Exception:
                pass

    def check_ftp(self, username: str, password: str) -> Dict[str, Any]:
        # FTP is plaintext unless explicit FTPS is used. The insecure path must be
        # deliberately opted into by the caller for isolated legacy test systems.
        import ftplib  # nosec B402 - FTPS is the default; plain FTP requires explicit opt-in.

        ftp = (ftplib.FTP() if self.allow_insecure_ftp else ftplib.FTP_TLS())  # nosec B321 - plain FTP is explicit opt-in only
        try:
            ftp.connect(self.target, self.port, timeout=5)
            ftp.login(username, password)
            if not self.allow_insecure_ftp:
                ftp.prot_p()
            return {"status": "success", "category": "authenticated", "username": username}
        except ftplib.error_perm:
            return {"status": "failed", "category": "invalid_credentials"}
        except (socket.timeout, TimeoutError):
            return {"status": "error", "category": "timeout"}
        except OSError:
            return {"status": "error", "category": "connection_error"}
        except Exception:
            return {"status": "error", "category": "ftp_error"}
        finally:
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass
    def run(self) -> list[Dict[str, Any]]:
        self.results = []
        self.error_counts.clear()
        wordlist = self.load_wordlist()
        if not wordlist:
            return []
        tasks: queue.Queue[Optional[tuple[str, str]]] = queue.Queue()
        for password in wordlist:
            tasks.put(("admin", password))
            tasks.put(("root", password))
        worker_count = min(self.max_threads, tasks.qsize())
        for _ in range(worker_count):
            tasks.put(None)

        def worker() -> None:
            while True:
                item = tasks.get()
                try:
                    if item is None:
                        return
                    username, password = item
                    try:
                        outcome = self.check_ssh(username, password) if self.service == "ssh" else self.check_ftp(username, password)
                    except Exception:
                        outcome = {"status": "error", "category": "worker_error"}
                    self._record(outcome)
                finally:
                    tasks.task_done()

        threads = [threading.Thread(target=worker, name=f"spectrascan-auth-{i}", daemon=True) for i in range(worker_count)]
        for thread in threads:
            thread.start()
        tasks.join()
        for thread in threads:
            thread.join()
        return list(self.results)
