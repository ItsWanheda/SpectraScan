"""
SMTP Enumerator
- Banner grab
- VRFY user enumeration
- EXPN list enumeration
- Open relay test
- STARTTLS support
"""
import socket
import re
from typing import Dict, List


class SMTPEnumerator:
    DEFAULT_PORT = 25

    @staticmethod
    def _recv_line(sock: socket.socket, timeout: float = 5.0) -> str:
        sock.settimeout(timeout)
        data = b""
        while not data.endswith(b"\r\n") and not data.endswith(b"\n"):
            try:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        return data.decode("utf-8", errors="replace").strip()

    @staticmethod
    def _send(sock: socket.socket, cmd: str):
        sock.send(f"{cmd}\r\n".encode())

    @staticmethod
    def check_open(ip: str, port: int = 25, timeout: float = 3.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            return False

    @staticmethod
    def banner(ip: str, port: int = 25, timeout: float = 5.0) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            banner = SMTPEnumerator._recv_line(s, timeout)
            s.close()
            # Strip "220 " prefix
            return re.sub(r"^220\s+", "", banner)
        except Exception:
            return ""

    @staticmethod
    def vrfy_users(ip: str, users: List[str], port: int = 25, timeout: float = 5.0) -> List[str]:
        valid = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            SMTPEnumerator._recv_line(s, timeout)  # banner
            SMTPEnumerator._send(s, "EHLO spectra.local")
            SMTPEnumerator._recv_line(s, timeout)

            for user in users:
                SMTPEnumerator._send(s, f"VRFY {user}")
                resp = SMTPEnumerator._recv_line(s, timeout)
                if resp.startswith("252") or resp.startswith("250"):
                    valid.append(user)
            s.send(b"QUIT\r\n")
            s.close()
        except Exception:
            pass
        return valid

    @staticmethod
    def check_open_relay(ip: str, port: int = 25, timeout: float = 10.0,
                          test_from: str = "test@spectra.local",
                          test_to: str = "test@googlemail.com") -> Dict:
        result = {"open_relay": False, "evidence": []}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            SMTPEnumerator._recv_line(s, timeout)
            SMTPEnumerator._send(s, "EHLO relaytest.local")
            SMTPEnumerator._recv_line(s, timeout)
            SMTPEnumerator._send(s, f"MAIL FROM:<{test_from}>")
            resp = SMTPEnumerator._recv_line(s, timeout)
            if not resp.startswith("250"):
                s.close()
                return result
            SMTPEnumerator._send(s, f"RCPT TO:<{test_to}>")
            resp = SMTPEnumerator._recv_line(s, timeout)
            if resp.startswith("250"):
                result["open_relay"] = True
                result["evidence"].append(f"Server accepted RCPT TO:<{test_to}> from {test_from}")
            s.send(b"QUIT\r\n")
            s.close()
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def check_starttls(ip: str, port: int = 25, timeout: float = 5.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            SMTPEnumerator._recv_line(s, timeout)
            SMTPEnumerator._send(s, "EHLO spectra.local")
            SMTPEnumerator._recv_line(s, timeout)
            SMTPEnumerator._send(s, "STARTTLS")
            resp = SMTPEnumerator._recv_line(s, timeout)
            s.close()
            return resp.startswith("220")
        except Exception:
            return False

    @staticmethod
    def scan(ip: str, port: int = 25, test_relay: bool = True,
             users_to_test: List[str] = None) -> Dict:
        result = {
            "module": "smtp", "target": ip, "port": port,
            "open": False, "banner": "", "starttls": False,
            "open_relay": False, "valid_users": [],
            "vulnerabilities": []
        }
        if not SMTPEnumerator.check_open(ip, port):
            return result
        result["open"] = True

        result["banner"] = SMTPEnumerator.banner(ip, port)
        result["starttls"] = SMTPEnumerator.check_starttls(ip, port)

        if users_to_test is None:
            users_to_test = ["root", "admin", "postmaster", "test", "info", "mail"]
        result["valid_users"] = SMTPEnumerator.vrfy_users(ip, users_to_test, port)

        if result["valid_users"]:
            result["vulnerabilities"].append({
                "name": f"VRFY command enabled - {len(result['valid_users'])} users enumerated",
                "severity": "MEDIUM",
                "cve": "N/A"
            })

        if test_relay:
            relay = SMTPEnumerator.check_open_relay(ip, port)
            result["open_relay"] = relay.get("open_relay", False)
            if result["open_relay"]:
                result["vulnerabilities"].append({
                    "name": "SMTP open relay detected",
                    "severity": "HIGH",
                    "cve": "N/A"
                })

        if not result["starttls"]:
            result["vulnerabilities"].append({
                "name": "STARTTLS not supported - credentials transmitted in plaintext",
                "severity": "MEDIUM",
                "cve": "N/A"
            })

        return result