"""
SNMP Enumerator
- Detect SNMP (UDP 161)
- Query system info, processes, users, network interfaces
- Tries common community strings
- Uses pysnmp if available, otherwise raw BER parser fallback, otherwise snmpwalk
"""
import socket
import subprocess
import random
import struct
from typing import Dict, List


class SNMPEnumerator:
    DEFAULT_COMMUNITIES = ["public", "private", "manager", "monitor", "admin", "cisco", "snmp"]
    SYSTEM_OIDS = {
        "1.3.6.1.2.1.1.1.0": "sysDescr",
        "1.3.6.1.2.1.1.2.0": "sysObjectID",
        "1.3.6.1.2.1.1.3.0": "sysUpTime",
        "1.3.6.1.2.1.1.4.0": "sysContact",
        "1.3.6.1.2.1.1.5.0": "sysName",
        "1.3.6.1.2.1.1.6.0": "sysLocation",
        "1.3.6.1.2.1.1.7.0": "sysServices",
    }

    @staticmethod
    def _ber_encode_length(length: int) -> bytes:
        if length < 128:
            return bytes([length])
        data = []
        while length > 0:
            data.insert(0, length & 0xff)
            length >>= 8
        return bytes([0x80 | len(data)] + data)

    @staticmethod
    def _ber_encode_integer(value: int) -> bytes:
        if value == 0:
            data = b"\x00"
        else:
            data = []
            v = value
            while v > 0:
                data.insert(0, v & 0xff)
                v >>= 8
            if data & 0x80:
                data.insert(0, 0)
            data = bytes(data)
        return b"\x02" + SNMPEnumerator._ber_encode_length(len(data)) + data

    @staticmethod
    def _ber_encode_string(s: bytes) -> bytes:
        return b"\x04" + SNMPEnumerator._ber_encode_length(len(s)) + s

    @staticmethod
    def _ber_encode_oid(oid: str) -> bytes:
        parts = [int(x) for x in oid.split(".")]
        if len(parts) < 2:
            return b""
        encoded = [40 * parts + parts]
        for p in parts[2:]:
            if p < 128:
                encoded.append(p)
            else:
                stack = []
                v = p
                while v > 0:
                    stack.append(v & 0x7f)
                    v >>= 7
                stack.reverse()
                for i in range(len(stack) - 1):
                    stack[i] |= 0x80
                encoded.extend(stack)
        data = bytes(encoded)
        return b"\x06" + SNMPEnumerator._ber_encode_length(len(data)) + data

    @staticmethod
    def _build_get_request(community: str, oid: str, request_id: int = None) -> bytes:
        if request_id is None:
            request_id = random.randint(1, 2**31 - 1)

        # VarBind: OID + NULL
        varbind = (
            b"\x30" + SNMPEnumerator._ber_encode_length(0)
            + SNMPEnumerator._ber_encode_oid(oid)
            + b"\x05\x00"
        )
        varbind = b"\x30" + SNMPEnumerator._ber_encode_length(len(varbind)) + varbind

        # PDU: GetRequest (0xa0)
        req_id = SNMPEnumerator._ber_encode_integer(request_id)
        error = SNMPEnumerator._ber_encode_integer(0)
        err_idx = SNMPEnumerator._ber_encode_integer(0)
        pdu_body = req_id + error + err_idx + varbind
        pdu = b"\xa0" + SNMPEnumerator._ber_encode_length(len(pdu_body)) + pdu_body

        # Version: 1 (SNMPv2c)
        version = b"\x02\x01\x01"
        community_enc = SNMPEnumerator._ber_encode_string(community.encode())
        msg_body = version + community_enc + pdu
        msg = b"\x30" + SNMPEnumerator._ber_encode_length(len(msg_body)) + msg_body
        return msg

    @staticmethod
    def query(ip: str, community: str, oid: str, timeout: float = 3.0) -> str:
        """Send SNMP GET request, return value as string or None."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            pkt = SNMPEnumerator._build_get_request(community, oid)
            s.sendto(pkt, (ip, 161))
            data, _ = s.recvfrom(4096)
            s.close()
            # Crude parser: find OCTET STRING or INTEGER value after the OID
            # Skip to varbind value
            if b"\x04" in data or b"\x02" in data or b"\x06" in data:
                # Find last value-type byte and read length
                for marker in [b"\x04", b"\x02", b"\x06", b"\x41"]:
                    idx = data.rfind(marker)
                    if idx >= 0 and idx + 1 < len(data):
                        length = data[idx + 1]
                        if length & 0x80 == 0 and idx + 2 + length <= len(data):
                            value = data[idx + 2: idx + 2 + length]
                            try:
                                return value.decode("utf-8", errors="replace")
                            except Exception:
                                return value.hex()
                # Fallback: dump everything after OID match
                return data.hex()
        except socket.timeout:
            return None
        except Exception:
            return None
        return None

    @staticmethod
    def scan(ip: str, communities: List[str] = None) -> Dict:
        result = {
            "module": "snmp", "target": ip, "open": False,
            "community": None, "system": {}, "vulnerabilities": []
        }
        communities = communities or SNMPEnumerator.DEFAULT_COMMUNITIES

        # First detect if SNMP is responding at all
        for community in communities:
            val = SNMPEnumerator.query(ip, community, "1.3.6.1.2.1.1.1.0", timeout=2.0)
            if val and len(val) > 0 and "noSuch" not in val.lower():
                result["open"] = True
                result["community"] = community
                # Query system info
                for oid, name in SNMPEnumerator.SYSTEM_OIDS.items():
                    v = SNMPEnumerator.query(ip, community, oid, timeout=2.0)
                    if v:
                        result["system"][name] = v
                break

        if not result["open"]:
            # Last resort: try snmpwalk
            for community in communities:
                if subprocess.run(["which", "snmpwalk"], capture_output=True).returncode == 0:
                    try:
                        out = subprocess.run(
                            ["snmpwalk", "-v2c", "-c", community, "-t", "2", ip, "1.3.6.1.2.1.1"],
                            capture_output=True, text=True, timeout=30
                        )
                        if out.returncode == 0 and out.stdout:
                            result["open"] = True
                            result["community"] = community
                            for line in out.stdout.splitlines():
                                if "=" in line:
                                    k, _, v = line.partition("=")
                                    result["system"][k.strip()] = v.strip()
                            break
                    except Exception:
                        pass
            return result

        # Detect vulnerabilities based on community string
        weak = ["public", "private", "manager", "admin", "cisco", "monitor", "snmp", "test"]
        if result["community"] in weak:
            result["vulnerabilities"].append({
                "name": f"Weak/default SNMP community string: '{result['community']}'",
                "severity": "HIGH",
                "cve": "N/A"
            })

        # Heuristic checks on sysDescr
        desc = result["system"].get("sysDescr", "").lower()
        if "linux" in desc or "ubuntu" in desc or "debian" in desc:
            result["os_guess"] = "Linux"
        elif "windows" in desc:
            result["os_guess"] = "Windows"
        elif "cisco" in desc or "ios" in desc:
            result["os_guess"] = "Cisco IOS"
            result["vulnerabilities"].append({
                "name": "Cisco device exposed via SNMP",
                "severity": "MEDIUM",
                "cve": "N/A"
            })

        return result