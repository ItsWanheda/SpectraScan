"""
Redis Enumerator
- Detect Redis (6379)
- Try unauthenticated access
- Get INFO, CONFIG, KEYS * (carefully)
- Detect ACL
"""
import socket
from typing import Dict


class RedisEnumerator:
    DEFAULT_PORT = 6379

    @staticmethod
    def check_open(ip: str, port: int = 6379, timeout: float = 3.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            return False

    @staticmethod
    def send_command(ip: str, port: int, command: str, timeout: float = 5.0) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            # RESP protocol: *1\r\n$4\r\nPING\r\n
            parts = command.split()
            req = f"*{len(parts)}\r\n"
            for p in parts:
                req += f"${len(p)}\r\n{p}\r\n"
            s.send(req.encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536 or b"\r\n" in chunk:
                    # For most simple commands, the response should be received
                    import time
                    time.sleep(0.3)
                    try:
                        s.settimeout(0.3)
                        more = s.recv(4096)
                        if more:
                            data += more
                    except socket.timeout:
                        pass
                    break
            s.close()
            return data.decode("latin-1", errors="replace")
        except Exception as e:
            return f"ERROR: {e}"

    @staticmethod
    def scan(ip: str, port: int = 6379) -> Dict:
        result = {
            "module": "redis", "target": ip, "port": port,
            "open": False, "auth_required": True, "version": None,
            "info": {}, "vulnerabilities": []
        }
        if not RedisEnumerator.check_open(ip, port):
            return result
        result["open"] = True

        # Try PING
        ping_resp = RedisEnumerator.send_command(ip, port, "PING")
        result["auth_required"] = not ping_resp.startswith("+PONG")
        result["ping_response"] = ping_resp.strip()

        if result["auth_required"]:
            return result

        # Get version
        info_resp = RedisEnumerator.send_command(ip, port, "INFO server")
        for line in info_resp.split("\n"):
            line = line.strip()
            if line.startswith("redis_version:"):
                result["version"] = line.split(":", 1).strip()
            elif ":" in line and not line.startswith("#"):
                k, _, v = line.partition(":")
                if k.strip() and len(result["info"]) < 30:
                    result["info"][k.strip()] = v.strip()

        # Get keyspace (database sizes)
        keys_resp = RedisEnumerator.send_command(ip, port, "DBSIZE")
        result["db_size"] = keys_resp.strip()

        # Sample keys (limit to 10)
        keys_resp = RedisEnumerator.send_command(ip, port, "RANDOMKEY")
        sample_key = keys_resp.strip().lstrip("$").split("\r\n")[-1] if "$" in keys_resp else ""
        result["sample_key"] = sample_key[:100] if sample_key else None

        # Vulnerabilities
        result["vulnerabilities"].append({
            "name": "Redis accessible without authentication",
            "severity": "CRITICAL",
            "cve": "N/A"
        })

        if result["version"]:
            try:
                v_parts = [int(x) for x in result["version"].split(".")]
                # Detect versions < 6.0 (no ACL)
                if v_parts < 6:
                    result["vulnerabilities"].append({
                        "name": f"Redis {result['version']} - no ACL support, weak auth model",
                        "severity": "HIGH",
                        "cve": "N/A"
                    })
            except Exception:
                pass

        return result