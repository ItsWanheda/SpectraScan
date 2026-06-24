"""
DNS Zone Transfer
- Attempt AXFR against all NS records
- Parse and return zone entries
"""
import socket
import struct
import random
from typing import Dict, List


class DNSZone:
    @staticmethod
    def _build_axfr_request(domain: str, request_id: int = None) -> bytes:
        if request_id is None:
            request_id = random.randint(1, 65535)
        # Header
        header = struct.pack(">HHHHHH", request_id, 0x0100, 1, 0, 0, 0)
        # Question
        question = b""
        for label in domain.split("."):
            question += bytes([len(label)]) + label.encode()
        question += b"\x00"
        question += struct.pack(">HH", 252, 1)  # QTYPE=AXFR, QCLASS=IN
        return header + question

    @staticmethod
    def _parse_response_name(data: bytes, offset: int) -> tuple:
        """Parse a DNS name, return (name, new_offset)."""
        labels = []
        jumped = False
        original_offset = offset
        while True:
            if offset >= len(data):
                break
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0 == 0xC0:  # Pointer
                if not jumped:
                    original_offset = offset + 2
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                offset = pointer
                jumped = True
            else:
                offset += 1
                labels.append(data[offset:offset + length].decode("latin-1", errors="replace"))
                offset += length
        return ".".join(labels), (original_offset if jumped else offset)

    @staticmethod
    def _parse_axfr_response(data: bytes) -> List[Dict]:
        records = []
        try:
            # Skip header (12 bytes)
            offset = 12
            # Skip question section
            qdcount = struct.unpack(">H", data[4:6])
            for _ in range(qdcount):
                _, offset = DNSZone._parse_response_name(data, offset)
                offset += 4  # QTYPE + QCLASS
            # Parse answer records
            ancount = struct.unpack(">H", data[6:8])
            for _ in range(ancount):
                name, offset = DNSZone._parse_response_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
                offset += 10
                rdata = data[offset:offset + rdlength]
                rdata_str = ""
                if rtype == 1 and rdlength == 4:  # A
                    rdata_str = ".".join(str(b) for b in rdata)
                elif rtype == 2:  # NS
                    rdata_str, _ = DNSZone._parse_response_name(data, offset)
                elif rtype == 5:  # CNAME
                    rdata_str, _ = DNSZone._parse_response_name(data, offset)
                elif rtype == 15:  # MX
                    pref = struct.unpack(">H", rdata[:2])
                    exchange, _ = DNSZone._parse_response_name(data, offset + 2)
                    rdata_str = f"{pref} {exchange}"
                elif rtype == 16:  # TXT
                    rdata_str = rdata[1:].decode("latin-1", errors="replace")
                records.append({
                    "name": name, "type": rtype, "ttl": ttl,
                    "value": rdata_str, "raw": rdata.hex()
                })
                offset += rdlength
        except Exception:
            pass
        return records

    @staticmethod
    def try_transfer(nameserver: str, domain: str, port: int = 53,
                     timeout: float = 10.0) -> Dict:
        result = {"nameserver": nameserver, "domain": domain, "success": False, "records": []}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((nameserver, port))
            pkt = DNSZone._build_axfr_request(domain)
            s.send(struct.pack(">H", len(pkt)) + pkt)
            full = b""
            while True:
                chunk = s.recv(8192)
                if not chunk:
                    break
                full += chunk
                if len(full) > 65536:
                    break
            s.close()
            if full:
                records = DNSZone._parse_axfr_response(full)
                if records:
                    result["success"] = True
                    result["records"] = records
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def scan(domain: str) -> Dict:
        result = {
            "module": "dns_zone", "domain": domain,
            "nameservers": [], "transfers": [], "vulnerabilities": []
        }
        # Get NS records
        try:
            answers = socket.getaddrinfo(domain, None)
            result["resolves"] = True
        except Exception:
            result["resolves"] = False
            return result

        # Try dig subprocess first (more reliable)
        import subprocess
        try:
            ns_out = subprocess.run(
                ["dig", "+short", "NS", domain],
                capture_output=True, text=True, timeout=10
            ).stdout.strip().splitlines()
            nameservers = [n.rstrip(".") for n in ns_out if n]
        except Exception:
            nameservers = []

        # Fallback: try common NS patterns
        if not nameservers:
            nameservers = [f"ns1.{domain}", f"ns2.{domain}"]

        result["nameservers"] = nameservers
        for ns in nameservers:
            try:
                ns_ip = socket.gethostbyname(ns)
            except Exception:
                continue
            transfer = DNSZone.try_transfer(ns_ip, domain)
            transfer["hostname"] = ns
            result["transfers"].append(transfer)
            if transfer["success"]:
                result["vulnerabilities"].append({
                    "name": f"DNS zone transfer allowed on {ns}",
                    "severity": "HIGH",
                    "cve": "N/A"
                })

        return result