"""
MongoDB Enumerator
- Detect MongoDB (27017)
- Try unauthenticated connection
- Get server info, databases, sample documents
- Detect wire version
"""
import socket
import struct
from typing import Dict, List


class MongoDBEnumerator:
    DEFAULT_PORT = 27017

    @staticmethod
    def check_open(ip: str, port: int = 27017, timeout: float = 3.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            return False

    @staticmethod
    def _send_op_msg(sock: socket.socket, doc: bytes) -> bytes:
        """Send OP_MSG (opcode 2013) with given BSON document."""
        # Flags (4) + section kind (1=doc, 0) + bson
        section = b"\x00" + doc
        # Body excludes opcode and requestID
        body = struct.pack("<I", 0) + section  # flags + section
        request_id = 1
        msg_len = 16 + len(body)
        header = struct.pack("<IIII", msg_len, request_id, 0, 2013)  # opcode 2013
        sock.send(header + body)

        # Read response
        data = b""
        try:
            while len(data) < 4:
                data += sock.recv(4 - len(data))
            msg_len = struct.unpack("<I", data[:4])
            data = b""
            while len(data) < msg_len:
                chunk = sock.recv(msg_len - len(data))
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data

    @staticmethod
    def _bson_encode(doc: dict) -> bytes:
        """Minimal BSON encoder for simple documents."""
        parts = b""
        for k, v in doc.items():
            key_bytes = k.encode("utf-8")
            if isinstance(v, int):
                parts += b"\x10" + key_bytes + b"\x00" + struct.pack("<i", v)
            elif isinstance(v, str):
                v_bytes = v.encode("utf-8")
                parts += b"\x02" + key_bytes + b"\x00" + struct.pack("<i", len(v_bytes) + 1) + v_bytes + b"\x00"
            elif isinstance(v, bool):
                parts += b"\x08" + key_bytes + b"\x00" + (b"\x01" if v else b"\x00")
            elif isinstance(v, dict):
                nested = MongoDBEnumerator._bson_encode(v)
                parts += b"\x03" + key_bytes + b"\x00" + struct.pack("<i", len(nested)) + nested
        doc_bytes = parts + b"\x00"
        return struct.pack("<i", len(doc_bytes) + 4) + doc_bytes

    @staticmethod
    def _parse_bson(data: bytes, offset: int = 0) -> Dict:
        """Very minimal BSON parser for top-level documents."""
        result = {}
        try:
            if offset + 5 > len(data):
                return result
            doc_len = struct.unpack("<i", data[offset:offset + 4])
            end = offset + doc_len
            pos = offset + 4
            while pos < end - 1:
                type_byte = data[pos]
                pos += 1
                # Read cstring key (null-terminated)
                key_end = data.find(b"\x00", pos)
                if key_end == -1:
                    break
                key = data[pos:key_end].decode("utf-8", errors="replace")
                pos = key_end + 1
                # Read value based on type
                if type_byte == 0x10:  # int32
                    if pos + 4 > end:
                        break
                    result[key] = struct.unpack("<i", data[pos:pos + 4])
                    pos += 4
                elif type_byte == 0x02:  # string
                    if pos + 4 > end:
                        break
                    str_len = struct.unpack("<i", data[pos:pos + 4])
                    pos += 4
                    result[key] = data[pos:pos + str_len - 1].decode("utf-8", errors="replace")
                    pos += str_len
                elif type_byte == 0x08:  # bool
                    result[key] = bool(data[pos])
                    pos += 1
                elif type_byte == 0x03:  # document
                    nested_len = struct.unpack("<i", data[pos:pos + 4])
                    result[key] = MongoDBEnumerator._parse_bson(data, pos)
                    pos += nested_len
                elif type_byte == 0x04:  # array
                    arr_len = struct.unpack("<i", data[pos:pos + 4])
                    pos += arr_len
                elif type_byte == 0x01:  # double
                    pos += 8
                elif type_byte == 0x12:  # int64
                    pos += 8
                else:
                    break
        except Exception:
            pass
        return result

    @staticmethod
    def scan(ip: str, port: int = 27017) -> Dict:
        result = {
            "module": "mongodb", "target": ip, "port": port,
            "open": False, "auth_required": True, "version": None,
            "databases": [], "vulnerabilities": []
        }
        if not MongoDBEnumerator.check_open(ip, port):
            return result
        result["open"] = True

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((ip, port))

            # Build hello/isMaster command
            doc = MongoDBEnumerator._bson_encode({
                "hello": 1,
                "$db": "admin"
            })
            resp = MongoDBEnumerator._send_op_msg(s, doc)
            s.close()

            if resp:
                parsed = MongoDBEnumerator._parse_bson(resp, 16)  # skip header
                # OP_MSG response has section
                if "ok" in parsed:
                    result["auth_required"] = False
                    result["version"] = parsed.get("maxWireVersion")
                    # Try to list databases
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2.settimeout(5.0)
                    s2.connect((ip, port))
                    doc2 = MongoDBEnumerator._bson_encode({
                        "listDatabases": 1,
                        "nameOnly": True,
                        "$db": "admin"
                    })
                    resp2 = MongoDBEnumerator._send_op_msg(s2, doc2)
                    s2.close()
                    if resp2:
                        parsed2 = MongoDBEnumerator._parse_bson(resp2, 16)
                        if "databases" in parsed2:
                            result["databases"] = [d.get("name") for d in parsed2["databases"] if isinstance(d, dict) and "name" in d]
                        elif "documents" in parsed2:
                            result["databases"] = [d.get("name") for d in parsed2["documents"] if isinstance(d, dict) and "name" in d]
        except Exception as e:
            result["error"] = str(e)

        if not result["auth_required"]:
            result["vulnerabilities"].append({
                "name": "MongoDB accessible without authentication",
                "severity": "CRITICAL",
                "cve": "N/A"
            })

        return result