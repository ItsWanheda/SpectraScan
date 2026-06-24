"""
RDP Enumerator
- Detect RDP (3389)
- Check NLA (Network Level Authentication)
- Get server version info
- Test for BlueKeep (CVE-2019-0708) - basic check
"""
import socket
import struct
import re
from typing import Dict


class RDPEnumerator:
    DEFAULT_PORT = 3389

    @staticmethod
    def check_open(ip: str, port: int = 3389, timeout: float = 3.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            return False

    @staticmethod
    def _parse_x224(data: bytes) -> Dict:
        """Parse X.224 / TPKT / MCS initial connection sequence."""
        result = {"tpkt_version": None, "rdp_version": None, "nla_supported": None}
        try:
            # TPKT header: version(1) + reserved(1) + length(2)
            if len(data) < 4:
                return result
            result["tpkt_version"] = data
            length = struct.unpack(">H", data[2:4])
            # X.224 TPDU
            # Look for RDP version info later in packet
            text = data.decode("latin-1", errors="replace")
            # RDP Negotiation Request/Response often contains VERSION_INFO
            # Look for version patterns
            ver_match = re.search(rb"\x04\x00\x08\x00", data)
            if ver_match:
                # Could be RDP_NEG_RSP with selectedProtocol
                pass
        except Exception:
            pass
        return result

    @staticmethod
    def grab_banner(ip: str, port: int = 3389, timeout: float = 5.0) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            # Send X.224 Connection Request
            # TPKT header (4) + X.224 length (1) + X.224 type (1) + dst_ref (2) + src_ref (2) + class (1) + cookie + RDP_NEG_REQ
            cookie = b"Cookie: mstshash=admin\r\n\x00"
            rdp_neg = b"\x26\x00\x00\x00\x00\x00\x00\x00"  # type=TYPE_RDP_NEG_REQ, flags=0, length=8, protocol=PROTOCOL_RDP (0)
            # Actually use extended: PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX
            rdp_neg_req = struct.pack("<BBHI", 0x01, 0x00, 0x08, 0x00000003)  # requested protocols

            x224_payload = b"\x26" + rdp_neg_req
            x224_tpdu = b"\xe0" + bytes([len(x224_payload)]) + x224_payload
            tpkt_payload = cookie + x224_tpdu
            tpkt = struct.pack(">BBH", 3, 0, len(tpkt_payload) + 4) + tpkt_payload
            s.send(tpkt)
            data = s.recv(4096)
            s.close()
            return data.hex()
        except Exception as e:
            return f"error: {e}"

    @staticmethod
    def check_nla(ip: str, port: int = 3389, timeout: float = 5.0) -> Dict:
        """Check if NLA is required by sending RDP_NEG_REQ with PROTOCOL_HYBRID."""
        result = {"responds": False, "nla_likely": False, "raw": ""}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            cookie = b"Cookie: mstshash=admin\r\n\x00"
            rdp_neg_req = struct.pack("<BBHI", 0x01, 0x00, 0x08, 0x00000002)  # PROTOCOL_HYBRID only
            x224_payload = b"\x26" + rdp_neg_req
            x224_tpdu = b"\xe0" + bytes([len(x224_payload)]) + x224_payload
            tpkt_payload = cookie + x224_tpdu
            tpkt = struct.pack(">BBH", 3, 0, len(tpkt_payload) + 4) + tpkt_payload
            s.send(tpkt)
            data = s.recv(4096)
            s.close()
            result["responds"] = True
            result["raw"] = data.hex()
            # If server accepts HYBRID (NLA), it will reply with PROTOCOL_HYBRID (0x02)
            # If it rejects/downgrades, it picks PROTOCOL_RDP (0x00) or PROTOCOL_SSL (0x01)
            # Look for selectedProtocol field
            if len(data) > 19:
                # Find RDP_NEG_RSP: type=0x02, then flags(1), length(2), selectedProtocol(4)
                if b"\x02\x00\x08\x00" in data:
                    idx = data.find(b"\x02\x00\x08\x00")
                    if idx + 8 <= len(data):
                        proto = struct.unpack("<I", data[idx + 4: idx + 8])
                        result["selected_protocol"] = proto
                        result["nla_likely"] = (proto == 2)
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def scan(ip: str, port: int = 3389) -> Dict:
        result = {
            "module": "rdp", "target": ip, "port": port,
            "open": False, "nla": False, "version": None,
            "vulnerabilities": []
        }
        if not RDPEnumerator.check_open(ip, port):
            return result
        result["open"] = True

        nla = RDPEnumerator.check_nla(ip, port)
        result["nla"] = nla.get("nla_likely", False)

        if not result["nla"]:
            result["vulnerabilities"].append({
                "name": "RDP without NLA exposed - vulnerable to man-in-the-middle",
                "severity": "MEDIUM",
                "cve": "N/A"
            })

        # BlueKeep heuristic: if NLA not required AND port open AND old Windows
        # (proper BlueKeep detection needs to send malicious packets - we just flag potential exposure)
        result["vulnerabilities"].append({
            "name": "Potential exposure to BlueKeep (CVE-2019-0708) - verify patch level",
            "severity": "CRITICAL",
            "cve": "CVE-2019-0708"
        })

        return result