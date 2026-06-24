"""
Database Enumerator (MySQL, PostgreSQL, MSSQL)
- Protocol-level handshake probes
- Detect version and capabilities
- Detect auth requirements
"""
import socket
import struct
import re
from typing import Dict


class MySQLEnumerator:
    DEFAULT_PORT = 3306

    @staticmethod
    def scan(ip: str, port: int = 3306) -> Dict:
        result = {
            "module": "mysql", "target": ip, "port": port,
            "open": False, "version": None, "vulnerabilities": []
        }
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((ip, port))
            # MySQL handshake: packet length (3) + seq (1) + protocol version (1) + server version (null-terminated)
            header = s.recv(4)
            if len(header) < 4:
                s.close()
                return result
            pkt_len = header | (header << 8) | (header << 16)
            data = s.recv(pkt_len)
            s.close()
            result["open"] = True
            # Skip protocol version (1 byte)
            version_end = data.find(b"\x00", 1)
            if version_end > 0:
                result["version"] = data[1:version_end].decode("latin-1", errors="replace")
            result["vulnerabilities"].append({
                "name": "MySQL exposed to network",
                "severity": "MEDIUM",
                "cve": "N/A"
            })
        except Exception as e:
            result["error"] = str(e)
        return result


class PostgreSQLEnumerator:
    DEFAULT_PORT = 5432

    @staticmethod
    def scan(ip: str, port: int = 5432) -> Dict:
        result = {
            "module": "postgresql", "target": ip, "port": port,
            "open": False, "version": None, "vulnerabilities": []
        }
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((ip, port))
            # PostgreSQL: send SSL request first to see if SSL is supported
            ssl_req = struct.pack(">IIII", 8, 80877103, 0, 0)
            s.send(ssl_req)
            resp = s.recv(1)
            if resp == b"S":
                result["ssl_supported"] = True
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5.0)
                s.connect((ip, port))
            else:
                result["ssl_supported"] = False
            # Send startup message - fails with error that contains version info
            startup = struct.pack(">II", 8, 196608)  # protocol 3.0
            s.send(startup)
            data = s.recv(1024)
            s.close()
            result["open"] = True
            # Error message format: 'E' + length(4) + fields
            if data and data[0:1] in (b"E", b"R"):
                # Try to find version in error message text
                text = data.decode("latin-1", errors="replace")
                ver_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", text)
                if ver_match:
                    result["version"] = ver_match.group(1)
                result["error_response_sample"] = text[:200]
            result["vulnerabilities"].append({
                "name": "PostgreSQL exposed to network",
                "severity": "MEDIUM",
                "cve": "N/A"
            })
        except Exception as e:
            result["error"] = str(e)
        return result


class MSSQLEnumerator:
    DEFAULT_PORT = 1433

    @staticmethod
    def scan(ip: str, port: int = 1433) -> Dict:
        result = {
            "module": "mssql", "target": ip, "port": port,
            "open": False, "version": None, "instance_name": None,
            "vulnerabilities": []
        }
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((ip, port))
            # TDS PRELOGIN
            prelogin = bytes([
                0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
                0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x01, 0x03,
                0x00, 0x1d, 0x00, 0x00, 0x04, 0x00, 0x00, 0xff
            ])
            s.send(prelogin)
            resp = s.recv(4096)
            s.close()
            result["open"] = True
            # Parse PRELOGIN response
            if len(resp) > 30:
                # Look for version in TDS response
                text = resp.decode("latin-1", errors="replace")
                ver_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", text)
                if ver_match:
                    result["version"] = ver_match.group(1)
                # Instance name often in payload
                idx = resp.find(b"MSSQLSERVER")
                if idx > 0:
                    end = resp.find(b"\x00", idx)
                    result["instance_name"] = resp[idx:end].decode("latin-1", errors="replace")
            result["vulnerabilities"].append({
                "name": "MSSQL exposed to network",
                "severity": "MEDIUM",
                "cve": "N/A"
            })
        except Exception as e:
            result["error"] = str(e)
        return result


def scan_all_databases(ip: str) -> Dict:
    """Scan all common database ports."""
    return {
        "mysql": MySQLEnumerator.scan(ip),
        "postgresql": PostgreSQLEnumerator.scan(ip),
        "mssql": MSSQLEnumerator.scan(ip),
    }