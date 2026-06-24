"""
SMB Enumerator
- Detect SMB versions (1, 2, 3)
- Enumerate shares
- Detect anonymous auth
- Get OS, hostname, domain
- Uses impacket if available, falls back to smbclient/enum4linux/crackmapexec
"""
import socket
import subprocess
import os
import struct
from typing import Dict, List


class SMBEnumerator:
    DEFAULT_PORTS =

    @staticmethod
    def check_open(ip: str, port: int = 445, timeout: float = 3.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            return False

    @staticmethod
    def negotiate_smb(ip: str, port: int = 445, timeout: float = 5.0) -> Dict:
        """Send SMB1 Negotiate Protocol Request and parse response."""
        result = {
            "port": port, "open": False, "smb1": False, "smb2": False, "smb3": False,
            "os": "Unknown", "hostname": "Unknown", "domain": "Unknown",
            "anonymous": False, "signing_required": False, "raw": b""
        }
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            result["open"] = True

            # NetBIOS Session Service + SMB1 Negotiate
            netbios = b"\x00\x00\x00\x2f"  # length
            smb_header = bytes([
                0xff, 0x53, 0x4d, 0x42,  # SMB magic
                0x72,  # Negotiate Protocol (0x72)
                0x00, 0x00, 0x00, 0x00,  # Status
                0x18,  # Flags
                0x53, 0xc8,  # Flags2
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # PID high, signature
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # reserved
                0xff, 0xfe,  # TID
                0x00, 0x00,  # PID
                0x00, 0x00,  # UID
                0x00, 0x00,  # MID
            ])
            # Word Count=0, Byte Count=2, Dialects=[PC NETWORK PROGRAM 1.0]
            payload = bytes([0x00, 0x00, 0x02, 0x02, 0x50, 0x43])
            packet = netbios + smb_header + payload
            s.send(packet)

            data = s.recv(4096)
            result["raw"] = data
            s.close()

            if b"\xffSMB" in data:
                result["smb1"] = True
                # Parse NT Status (offset 9-12 in SMB header after NetBIOS)
                # Look for OS string at end of response
                if b"Windows" in data:
                    win_idx = data.find(b"Windows")
                    if win_idx > 0:
                        end = data.find(b"\x00", win_idx)
                        result["os"] = data[win_idx:end].decode("utf-8", errors="ignore")

            # Check SMB2/3 by sending SMB2 negotiate
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(timeout)
                s2.connect((ip, port))
                # SMB2 header (64 bytes) + Negotiate Request
                smb2_header = (
                    b"\x00\x00\x00\x00"  # NetBIOS length placeholder
                    b"\xfeSMB"  # SMB2 magic
                    + b"\x00" * 38  # rest of header
                )
                negotiate_req = (
                    b"\x24\x00"  # Structure size
                    b"\x01\x00"  # Dialect count
                    b"\x01\x00"  # Security mode
                    b"\x00\x00\x00\x00"  # Reserved
                    b"\x00\x00\x00\x00"  # Capabilities
                    + b"\x00" * 16  # Client GUID
                    + b"\x00\x00\x00\x00"  # Negotiate context offset
                    + b"\x02\x00"  # Dialect: SMB 2.1 (will try multiple if needed)
                )
                pkt = b"\x00\x00\x00\x3a" + smb2_header[4:] + negotiate_req
                s2.send(pkt)
                resp = s2.recv(4096)
                if b"\xfeSMB" in resp:
                    result["smb2"] = True
                    result["smb3"] = b"SMB 3" in resp.decode("latin-1", errors="ignore") or len(resp) > 100
                s2.close()
            except Exception:
                pass

        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def enumerate_with_impacket(ip: str) -> Dict:
        """Use impacket for full enumeration."""
        result = {"method": "impacket", "shares": [], "users": [], "groups": []}
        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(ip, ip, timeout=5)
            # Try anonymous
            try:
                conn.login("", "")
                result["anonymous"] = True
                result["hostname"] = conn.getRemoteName()
                result["os"] = conn.getServerOS()
                result["domain"] = conn.getServerDomain()
                try:
                    result["shares"] = [s["shi1_netname"][:-1] for s in conn.listShares()]
                except Exception:
                    pass
                try:
                    result["users"] = list(conn.listUsers())
                except Exception:
                    pass
            except Exception as e:
                result["anonymous"] = False
                result["login_error"] = str(e)
            conn.close()
        except ImportError:
            result["error"] = "impacket not installed (pip install impacket)"
        return result

    @staticmethod
    def enumerate_with_tools(ip: str) -> Dict:
        """Fallback: use smbclient/enum4linux/crackmapexec subprocess."""
        result = {"method": "subprocess", "shares": [], "os": "Unknown"}
        # Try enum4linux
        if subprocess.run(["which", "enum4linux"], capture_output=True).returncode == 0:
            try:
                out = subprocess.run(
                    ["enum4linux", "-a", ip], capture_output=True, text=True, timeout=120
                ).stdout
                if "Domain:" in out:
                    for line in out.splitlines():
                        if "Domain:" in line or "OS:" in line:
                            result["os"] += f" | {line.strip()}"
                if "Sharename" in out:
                    in_shares = False
                    for line in out.splitlines():
                        if "Sharename" in line:
                            in_shares = True
                            continue
                        if in_shares:
                            if line.strip() == "" or "----" in line:
                                if "IPC$" in result["shares"] or len(result["shares"]) > 3:
                                    in_shares = False
                            elif line.strip():
                                result["shares"].append(line.split())
                return result
            except Exception as e:
                result["enum4linux_error"] = str(e)

        # Try smbclient
        if subprocess.run(["which", "smbclient"], capture_output=True).returncode == 0:
            try:
                out = subprocess.run(
                    ["smbclient", "-L", ip, "-N"], capture_output=True, text=True, timeout=30
                ).stdout
                for line in out.splitlines():
                    if "Disk" in line and "|" in line:
                        result["shares"].append(line.split("|").strip())
            except Exception as e:
                result["smbclient_error"] = str(e)

        # Try crackmapexec
        if subprocess.run(["which", "crackmapexec"], capture_output=True).returncode == 0:
            try:
                out = subprocess.run(
                    ["crackmapexec", "smb", ip], capture_output=True, text=True, timeout=30
                ).stdout
                for line in out.splitlines():
                    if "Windows" in line or "Linux" in line:
                        result["os"] = line.strip()
            except Exception as e:
                result["cme_error"] = str(e)
        return result

    @staticmethod
    def scan(ip: str, port: int = 445) -> Dict:
        result = {
            "module": "smb", "target": ip, "port": port,
            "open": False, "versions": [], "os": "Unknown",
            "shares": [], "anonymous": False, "vulnerabilities": []
        }
        if not SMBEnumerator.check_open(ip, port):
            result["open"] = False
            return result
        result["open"] = True

        # Try impacket first (cleanest)
        imp = SMBEnumerator.enumerate_with_impacket(ip)
        if "error" not in imp or "anonymous" in imp:
            result.update(imp)
        else:
            # Native negotiation + tool fallback
            neg = SMBEnumerator.negotiate_smb(ip, port)
            for v in ["smb1", "smb2", "smb3"]:
                if neg.get(v):
                    result["versions"].append(v.upper())
            if neg.get("os") and neg["os"] != "Unknown":
                result["os"] = neg["os"]
            result["anonymous"] = False

            tools = SMBEnumerator.enumerate_with_tools(ip)
            result["shares"] = tools.get("shares", [])
            if tools.get("os") != "Unknown":
                result["os"] = tools["os"]

        # Vulnerability heuristics
        if "SMB1" in result["versions"]:
            result["vulnerabilities"].append({
                "name": "SMBv1 enabled (EternalBlue/MS17-010)",
                "severity": "CRITICAL",
                "cve": "CVE-2017-0144"
            })
        if result.get("anonymous"):
            result["vulnerabilities"].append({
                "name": "Anonymous SMB access allowed",
                "severity": "HIGH",
                "cve": "N/A"
            })
        if result.get("shares"):
            for share in result["shares"]:
                if any(sensitive in share.upper() for sensitive in ["BACKUP", "C$", "ADMIN$", "ROOT"]):
                    result["vulnerabilities"].append({
                        "name": f"Sensitive share exposed: {share}",
                        "severity": "HIGH",
                        "cve": "N/A"
                    })
                    break
        return result