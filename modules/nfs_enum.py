"""
NFS Enumerator
- Detect NFS (2049)
- Enumerate exported shares via mountd (portmap + MOUNT)
- Try to mount anonymously
"""
import socket
import struct
import subprocess
from typing import Dict, List


class NFSEnumerator:
    DEFAULT_PORT = 2049

    @staticmethod
    def check_open(ip: str, port: int = 2049, timeout: float = 3.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            return False

    @staticmethod
    def rpc_portmap_dump(ip: str, timeout: float = 5.0) -> Dict:
        """Query portmapper (TCP/UDP 111) for service ports."""
        result = {"open": False, "services": {}}
        # Try TCP first
        for proto in ["tcp", "udp"]:
            try:
                if proto == "tcp":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                port = 111
                if proto == "tcp":
                    s.connect((ip, port))
                # RPC PORTMAP DUMP (program=100000, version=4, procedure=4=DUMP)
                # Record Marking for TCP: 4 bytes big-endian length
                xid = b"\x12\x34\x56\x78"
                msg_type = b"\x00\x00\x00\x00"  # CALL
                rpc_version = b"\x00\x00\x00\x02"
                program = b"\x00\x18\x6c\x40"  # 100000
                version = b"\x00\x00\x00\x04"
                procedure = b"\x00\x00\x00\x04"  # DUMP
                # Credentials (AUTH_UNIX)
                flavor = b"\x00\x00\x00\x01"
                length = b"\x00\x00\x00\x1c"
                stamp = b"\x00\x00\x00\x00"
                machinename = b"\x00\x00\x00\x00\x00\x00\x00\x00"
                uid = b"\x00\x00\x00\x00"
                gid = b"\x00\x00\x00\x00"
                gids = b"\x00\x00\x00\x00"
                # Verifier (AUTH_NULL)
                v_flavor = b"\x00\x00\x00\x00"
                v_length = b"\x00\x00\x00\x00"
                rpc_call = (xid + msg_type + rpc_version + program + version + procedure
                            + flavor + length + stamp + machinename + uid + gid + gids
                            + v_flavor + v_length)
                if proto == "tcp":
                    s.send(struct.pack(">I", len(rpc_call)) + rpc_call)
                    size = struct.unpack(">I", s.recv(4))
                    data = s.recv(size)
                else:
                    s.send(rpc_call)
                    data, _ = s.recvfrom(8192)
                s.close()
                # Crude parsing: find program numbers and ports
                # Each mapping: prog(4) + ver(4) + proto(4) + port(4)
                text = data.hex()
                for prog_name, prog_id in [("nfs", 100003), ("mountd", 100005),
                                            ("portmap", 100000), ("nlockmgr", 100021)]:
                    pattern = struct.pack(">I", prog_id).hex()
                    if pattern in text:
                        idx = text.find(pattern)
                        # After prog+ver+proto (12 bytes), read port
                        port_hex = text[idx + 24: idx + 32]
                        try:
                            port_num = int(port_hex, 16)
                            if port_num > 0 and port_num < 65536:
                                result["services"][prog_name] = port_num
                        except ValueError:
                            pass
                result["open"] = True
                break
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
        return result

    @staticmethod
    def mount_export(ip: str, port: int, timeout: float = 5.0) -> List[str]:
        """Query MOUNTD (program 100005) for exports list."""
        exports = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            xid = b"\x12\x34\x56\x78"
            msg_type = b"\x00\x00\x00\x00"
            rpc_version = b"\x00\x00\x00\x02"
            program = struct.pack(">I", 100005)
            version = struct.pack(">I", 1)
            procedure = struct.pack(">I", 5)  # EXPORT
            flavor = b"\x00\x00\x00\x01"
            length = b"\x00\x00\x00\x1c"
            stamp = b"\x00\x00\x00\x00"
            machinename = b"\x00\x00\x00\x00\x00\x00\x00\x00"
            uid = b"\x00\x00\x00\x00"
            gid = b"\x00\x00\x00\x00"
            gids = b"\x00\x00\x00\x00"
            v_flavor = b"\x00\x00\x00\x00"
            v_length = b"\x00\x00\x00\x00"
            rpc_call = (xid + msg_type + rpc_version + program + version + procedure
                        + flavor + length + stamp + machinename + uid + gid + gids
                        + v_flavor + v_length)
            s.send(struct.pack(">I", len(rpc_call)) + rpc_call)
            size = struct.unpack(">I", s.recv(4))
            data = b""
            while len(data) < size:
                data += s.recv(size - len(data))
            s.close()
            # Parse: list of (dirname, list_of_groups)
            offset = 0
            try:
                # First: accepted reply verifier (8 bytes - AUTH_NULL)
                # Then: export list
                # Skip reply verifier
                if data[0:4] == b"\x00\x00\x00\x01":  # accepted
                    offset = 8
                    # Skip accept_stat (4) and opaque_auth verifier (8) = 12 bytes after header
                    offset = 24
                # Each export: dirname (hyper string) + groups (hyper list)
                while offset < len(data):
                    # dirname length
                    if offset + 4 > len(data):
                        break
                    dir_len = struct.unpack(">I", data[offset:offset + 4])
                    offset += 4
                    if offset + dir_len > len(data):
                        break
                    dirname = data[offset:offset + dir_len].decode("latin-1", errors="replace").strip("\x00")
                    offset += dir_len
                    if dirname:
                        exports.append(dirname)
                    # Skip groups (complex parsing - skip for now)
                    if offset + 4 > len(data):
                        break
                    groups_len = struct.unpack(">I", data[offset:offset + 4])
                    if groups_len == 0:
                        offset += 4
                        # Possible end of list (follows)
                        offset += 4  # follow (boolean/flag)
            except Exception:
                pass
        except Exception:
            pass
        return exports

    @staticmethod
    def scan_with_showmount(ip: str) -> List[str]:
        """Use showmount subprocess as fallback."""
        exports = []
        if subprocess.run(["which", "showmount"], capture_output=True).returncode == 0:
            try:
                out = subprocess.run(
                    ["showmount", "-e", ip],
                    capture_output=True, text=True, timeout=15
                ).stdout
                for line in out.splitlines():
                    line = line.strip()
                    if line and not line.startswith("Export list") and not line.startswith("---"):
                        exports.append(line.split() if line.split() else line)
            except Exception:
                pass
        return exports

    @staticmethod
    def scan(ip: str) -> Dict:
        result = {
            "module": "nfs", "target": ip,
            "open": False, "exports": [], "vulnerabilities": []
        }
        if not NFSEnumerator.check_open(ip):
            return result
        result["open"] = True

        # Try to get mountd port
        portmap = NFSEnumerator.rpc_portmap_dump(ip)
        mountd_port = portmap.get("services", {}).get("mountd", 0)

        if mountd_port:
            result["exports"] = NFSEnumerator.mount_export(ip, mountd_port)

        if not result["exports"]:
            result["exports"] = NFSEnumerator.scan_with_showmount(ip)

        if result["exports"]:
            for export in result["exports"]:
                if "rw" in export.lower() or "*" in export or "everyone" in export.lower():
                    result["vulnerabilities"].append({
                        "name": f"NFS export with permissive access: {export}",
                        "severity": "HIGH",
                        "cve": "N/A"
                    })
                    break

        return result