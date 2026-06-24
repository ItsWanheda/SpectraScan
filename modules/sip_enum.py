"""
SIP Enumerator
- OPTIONS request to detect SIP services
- Parse Allow, Server, Supported headers
- Enumerate extensions (basic)
"""
import socket
import re
from typing import Dict


class SIPEnumerator:
    DEFAULT_PORT = 5060

    @staticmethod
    def check_open(ip: str, port: int = 5060, timeout: float = 3.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            # UDP - just try sending
            s.sendto(b"\r\n", (ip, port))
            s.settimeout(1.0)
            try:
                data, _ = s.recvfrom(4096)
                s.close()
                return True
            except socket.timeout:
                s.close()
                # Try TCP fallback
                try:
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2.settimeout(timeout)
                    s2.connect((ip, port))
                    s2.close()
                    return True
                except Exception:
                    return False
        except Exception:
            return False

    @staticmethod
    def options_request(ip: str, port: int = 5060, use_tcp: bool = False,
                        timeout: float = 5.0) -> Dict:
        result = {"open": False, "server": None, "allow": [], "supported": []}
        request = (
            f"OPTIONS sip:{ip} SIP/2.0\r\n"
            f"Via: SIP/2.0/{'TCP' if use_tcp else 'UDP'} {ip}:{port};branch=z9hG4bK-spectra\r\n"
            f"Max-Forwards: 70\r\n"
            f"To: <sip:{ip}>\r\n"
            f"From: <sip:spectra@{ip}>;tag=spectra\r\n"
            f"Call-ID: spectra-{port}@spectra\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"Contact: <sip:spectra@{ip}:{port}>\r\n"
            f"Content-Length: 0\r\n\r\n"
        ).encode()
        try:
            if use_tcp:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.connect((ip, port)) if use_tcp else None
            s.send(request)
            data, _ = s.recvfrom(4096)
            s.close()
            text = data.decode("latin-1", errors="replace")
            result["open"] = True
            for line in text.split("\r\n"):
                if line.lower().startswith("server:"):
                    result["server"] = line.split(":", 1).strip()
                elif line.lower().startswith("allow:"):
                    result["allow"] = [m.strip() for m in line.split(":", 1).split(",")]
                elif line.lower().startswith("supported:"):
                    result["supported"] = [m.strip() for m in line.split(":", 1).split(",")]
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def scan(ip: str, port: int = 5060) -> Dict:
        result = {
            "module": "sip", "target": ip, "port": port,
            "open": False, "server": None, "methods": [],
            "vulnerabilities": []
        }

        # Try UDP first
        udp = SIPEnumerator.options_request(ip, port, use_tcp=False)
        if udp.get("open"):
            result.update(udp)
        else:
            tcp = SIPEnumerator.options_request(ip, port, use_tcp=True)
            if tcp.get("open"):
                result.update(tcp)
                result["transport"] = "TCP"

        if result["open"]:
            # Check for dangerous methods
            dangerous = [m for m in result["methods"] if m in ["INVITE", "REGISTER", "BYE", "CANCEL"]]
            if dangerous:
                result["vulnerabilities"].append({
                    "name": f"SIP server exposes call control methods: {', '.join(dangerous)}",
                    "severity": "MEDIUM",
                    "cve": "N/A"
                })

        return result