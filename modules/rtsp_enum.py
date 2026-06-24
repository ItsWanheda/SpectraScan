"""
RTSP Enumerator
- DESCRIBE request to detect RTSP services
- Parse SDP for stream info
- Detect unauthenticated streams
"""
import socket
import re
from typing import Dict


class RTSPEnumerator:
    DEFAULT_PORT = 554

    @staticmethod
    def check_open(ip: str, port: int = 554, timeout: float = 3.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            return False

    @staticmethod
    def describe(ip: str, port: int = 554, url: str = "/",
                 timeout: float = 5.0) -> Dict:
        result = {"open": False, "auth_required": False, "server": None,
                  "sdp": None, "streams": []}
        request = (
            f"DESCRIBE rtsp://{ip}:{port}{url} RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: SpectraScan\r\n"
            f"Accept: application/sdp\r\n\r\n"
        ).encode()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.send(request)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data and len(data) > 500:
                    break
            s.close()
            text = data.decode("latin-1", errors="replace")
            result["raw_status"] = text.split("\r\n", 1) if "\r\n" in text else ""
            result["open"] = "RTSP/1.0" in text or "RTSP/2.0" in text

            for line in text.split("\r\n"):
                if line.lower().startswith("server:"):
                    result["server"] = line.split(":", 1).strip()
                elif line.lower().startswith("www-authenticate:"):
                    result["auth_required"] = True
                elif line.startswith("m="):
                    # m=video 0 RTP/AVP 96
                    parts = line[2:].split()
                    if parts and len(parts) > 1:
                        result["streams"].append({
                            "type": parts, "port": parts, "protocol": parts
                        })

            # Get SDP body if present
            if "\r\n\r\n" in text:
                sdp = text.split("\r\n\r\n", 1)
                if sdp and sdp.isdigit():
                    result["sdp_length"] = sdp.split("\r\n", 1)
                    sdp_body = sdp.split("\r\n", 1) if "\r\n" in sdp else ""
                    result["sdp"] = sdp_body[:500]
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def scan(ip: str, port: int = 554, urls: list = None) -> Dict:
        result = {
            "module": "rtsp", "target": ip, "port": port,
            "open": False, "server": None, "auth_required": False,
            "streams": [], "vulnerabilities": []
        }
        if not RTSPEnumerator.check_open(ip, port):
            return result

        urls = urls or ["/", "/stream", "/live", "/video", "/cam", "/h264"]
        for url in urls:
            resp = RTSPEnumerator.describe(ip, port, url)
            if resp.get("open"):
                result["open"] = True
                result["server"] = resp.get("server", result["server"])
                result["auth_required"] = resp.get("auth_required", result["auth_required"])
                if resp.get("streams"):
                    result["streams"].extend(resp["streams"])
                    result["url_works"] = url
                    break

        if result["open"] and not result["auth_required"]:
            result["vulnerabilities"].append({
                "name": f"RTSP stream accessible without authentication at {result.get('url_works', '/')}",
                "severity": "HIGH",
                "cve": "N/A"
            })

        return result