"""
LDAP Enumerator
- Detect LDAP (389) and LDAPS (636)
- Try anonymous bind
- Get server info (naming contexts, root DSE)
- Enumerate users/groups (if anonymous bind works or creds provided)
- Falls back to ldapsearch subprocess
"""
import socket
import subprocess
from typing import Dict, List, Optional


class LDAPEnumerator:
    DEFAULT_PORTS =

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
    def _build_bind_request(username: str = "", password: str = "") -> bytes:
        """Build a simple LDAP BindRequest (anonymous or simple)."""
        # LDAPMessage: SEQUENCE { messageID, BindRequest }
        bind_op = b"\x60"  # BindRequest APPLICATION
        # version (INTEGER 3) - LDAPv3
        version = b"\x02\x01\x03"
        # name (OCTET STRING) - empty for anonymous
        name = b"\x04\x00"
        # authentication CHOICE - simple
        if username or password:
            auth_val = f"{username}:{password}".encode()
            auth = b"\x80" + LDAPEnumerator._ber_encode_length(len(auth_val)) + auth_val
        else:
            auth = b"\x80\x00"  # simple, empty creds = anonymous

        bind_body = version + name + auth
        bind_op = b"\x60" + LDAPEnumerator._ber_encode_length(len(bind_body)) + bind_body

        msg_id = b"\x02\x01\x01"  # messageID = 1
        msg_body = msg_id + bind_op
        return b"\x30" + LDAPEnumerator._ber_encode_length(len(msg_body)) + msg_body

    @staticmethod
    def _build_search_root_dse() -> bytes:
        """Build SearchRequest for root DSE (base DN empty)."""
        msg_id = b"\x02\x01\x02"

        # SearchRequest APPLICATION
        base_dn = b"\x04\x00"  # empty
        scope = b"\x0a\x01\x00"  # base
        deref = b"\x0a\x01\x00"
        size_limit = b"\x02\x01\x00"
        time_limit = b"\x02\x01\x00"
        types_only = b"\x01\x01\x00"
        filter_str = b"\xa0\x00"  # present filter

        # Attributes (SEQUENCE OF attributeSelector) - empty = all
        attrs = b"\x30\x00"

        search_body = base_dn + scope + deref + size_limit + time_limit + types_only + filter_str + attrs
        search_req = b"\x63" + LDAPEnumerator._ber_encode_length(len(search_body)) + search_body
        msg_body = msg_id + search_req
        return b"\x30" + LDAPEnumerator._ber_encode_length(len(msg_body)) + msg_body

    @staticmethod
    def check_open(ip: str, port: int = 389, timeout: float = 3.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            return False

    @staticmethod
    def try_anonymous_bind(ip: str, port: int = 389, timeout: float = 5.0) -> Dict:
        result = {"open": False, "anonymous": False, "error": None}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            result["open"] = True
            s.send(LDAPEnumerator._build_bind_request("", ""))
            resp = s.recv(4096)
            s.close()
            # success = resultCode 0 (bind OK)
            # Look for 0x0a 0x01 0x00 (ENUMERATED 0) inside BindResponse
            if b"\x0a\x01\x00" in resp:
                result["anonymous"] = True
            else:
                # Look for "success" indication in raw response
                result["anonymous"] = b"\x61\x07\x0a\x01\x00\x04\x00\x04\x00" in resp
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def get_root_dse(ip: str, port: int = 389, timeout: float = 5.0) -> Dict:
        """Get root DSE info (naming contexts, server info)."""
        result = {"naming_contexts": [], "server_name": None, "raw": ""}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            # Bind anonymous first
            s.send(LDAPEnumerator._build_bind_request("", ""))
            s.recv(4096)
            # Search root DSE
            s.send(LDAPEnumerator._build_search_root_dSE() if hasattr(LDAPEnumerator, '_build_search_root_dSE') else LDAPEnumerator._build_search_root_dse())
            resp = s.recv(8192)
            s.close()
            result["raw"] = resp.hex()
            # Crude parsing: look for "DC=" markers
            text = resp.decode("latin-1", errors="replace")
            import re
            dcs = re.findall(r"(DC=[a-zA-Z0-9-]+(?:,DC=[a-zA-Z0-9-]+)+)", text)
            result["naming_contexts"] = list(set(dcs))
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def scan_with_ldapsearch(ip: str, port: int = 389, base_dn: str = None) -> Dict:
        """Use ldapsearch subprocess for full enumeration."""
        result = {"method": "ldapsearch", "users": [], "groups": []}
        if subprocess.run(["which", "ldapsearch"], capture_output=True).returncode != 0:
            result["error"] = "ldapsearch not installed"
            return result
        try:
            # Get base DN if not provided
            if not base_dn:
                out = subprocess.run(
                    ["ldapsearch", "-x", "-H", f"ldap://{ip}:{port}", "-s", "base", "namingContexts"],
                    capture_output=True, text=True, timeout=15
                )
                for line in out.stdout.splitlines():
                    if line.lower().startswith("namingcontexts:"):
                        base_dn = line.split(":", 1).strip()
                        break

            if not base_dn:
                return result

            # Enumerate users
            user_filter = "(objectClass=user)"
            out = subprocess.run(
                ["ldapsearch", "-x", "-H", f"ldap://{ip}:{port}", "-b", base_dn, user_filter, "sAMAccountName"],
                capture_output=True, text=True, timeout=30
            )
            for line in out.stdout.splitlines():
                if line.lower().startswith("samaccountname:"):
                    result["users"].append(line.split(":", 1).strip())

            # Enumerate groups
            grp_filter = "(objectClass=group)"
            out = subprocess.run(
                ["ldapsearch", "-x", "-H", f"ldap://{ip}:{port}", "-b", base_dn, grp_filter, "cn"],
                capture_output=True, text=True, timeout=30
            )
            for line in out.stdout.splitlines():
                if line.lower().startswith("cn:"):
                    result["groups"].append(line.split(":", 1).strip())
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def scan(ip: str, port: int = 389, username: str = "", password: str = "") -> Dict:
        result = {
            "module": "ldap", "target": ip, "port": port,
            "open": False, "anonymous": False, "base_dn": None,
            "users": [], "groups": [], "vulnerabilities": []
        }

        if not LDAPEnumerator.check_open(ip, port):
            return result
        result["open"] = True

        # Try anonymous bind
        anon = LDAPEnumerator.try_anonymous_bind(ip, port)
        result["anonymous"] = anon.get("anonymous", False)

        # Get root DSE for naming contexts
        dse = LDAPEnumerator.get_root_dse(ip, port)
        if dse.get("naming_contexts"):
            result["base_dn"] = dse["naming_contexts"]

        # If anonymous, try full enumeration via subprocess
        if result["anonymous"]:
            full = LDAPEnumerator.scan_with_ldapsearch(ip, port, result["base_dn"])
            result["users"] = full.get("users", [])
            result["groups"] = full.get("groups", [])
            result["vulnerabilities"].append({
                "name": "LDAP anonymous bind enabled",
                "severity": "HIGH",
                "cve": "N/A"
            })

        return result