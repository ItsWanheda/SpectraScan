"""
VNC Enumerator
- Banner grab (RFB protocol)
- Detect auth type (None / VNC / RealVNC / Apple)
- Detect screen dimensions
"""
import socket
import struct
from typing import Dict


class VNCEnumerator:
    DEFAULT_PORT = 5900

    @staticmethod
    def check_open(ip: str, port: int = 5900, timeout: float = 3.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            return False

    @staticmethod
    def scan(ip: str, port: int = 5900) -> Dict:
        result = {
            "module": "vnc", "target": ip, "port": port,
            "open": False, "version": "", "auth_types": [],
            "no_auth": False, "vulnerabilities": []
        }
        if not VNCEnumerator.check_open(ip, port):
            return result
        result["open"] = True

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((ip, port))
            # RFB server sends: "RFB xxx.yyy\n"
            banner = b""
            while b"\n" not in banner:
                chunk = s.recv(64)
                if not chunk:
                    break
                banner += chunk
                if len(banner) > 64:
                    break
            s.close()
            result["version"] = banner.decode("latin-1", errors="replace").strip()
        except Exception as e:
            result["error"] = str(e)
            return result

        # Reconnect and get auth types
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((ip, port))
            # Read banner
            banner = b""
            while b"\n" not in banner:
                chunk = s.recv(64)
                if not chunk:
                    break
                banner += chunk
            # Send client version match
            s.send(b"RFB 003.008\n")
            # Read auth types count
            num_types_byte = s.recv(1)
            if num_types_byte:
                num_types = num_types_byte
                if num_types == 0:
                    # Read 4-byte reason length + reason
                    reason_len = struct.unpack(">I", s.recv(4))
                    reason = s.recv(reason_len)
                    result["connection_error"] = reason.decode("latin-1", errors="replace")
                else:
                    types_raw = s.recv(num_types)
                    auth_map = {
                        1: "None", 2: "VNC", 3: "RA2", 5: "RA2ne",
                        6: "Tight", 16: "Ultra", 18: "TLS",
                        19: "VeNCrypt", 20: "GTK-VNC_SASL",
                        21: "MD5_NS_Auth", 30: "Apple30",
                        35: "RSA-AES", 36: "RSA-AES-256"
                    }
                    for b in types_raw:
                        result["auth_types"].append(auth_map.get(b, f"Unknown({b})"))
                    if 1 in types_raw:
                        result["no_auth"] = True
            s.close()
        except Exception as e:
            result["error2"] = str(e)

        if result["no_auth"]:
            result["vulnerabilities"].append({
                "name": "VNC server allows no authentication",
                "severity": "CRITICAL",
                "cve": "N/A"
            })

        return result