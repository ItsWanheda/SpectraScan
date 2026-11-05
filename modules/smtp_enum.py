"""SMTP probing with complete multiline replies and conservative findings."""
from __future__ import annotations
import socket
from typing import Any, Dict, List, Optional

def _recv_line(sock: socket.socket,timeout: float=5.0,max_bytes: int=8192)->str:
    sock.settimeout(timeout); data=bytearray()
    while len(data)<max_bytes:
        part=sock.recv(1)
        if not part: break
        data.extend(part)
        if data.endswith(b"\n"): break
    if len(data)>=max_bytes and not data.endswith(b"\n"): raise ValueError("SMTP line too long")
    return data.decode("utf-8",errors="replace").rstrip("\r\n")

def _recv_response(sock: socket.socket,timeout: float=5.0,max_lines: int=100)->List[str]:
    lines=[]; expected=None
    for _ in range(max_lines):
        line=_recv_line(sock,timeout)
        if not line:
            if lines: break
            raise ConnectionError("SMTP server closed connection")
        lines.append(line)
        if len(line)<3 or not line[:3].isdigit():
            if expected is None: break
            continue
        code=line[:3]
        if expected is None: expected=code
        if code==expected and (len(line)==3 or line[3:4]!="-"): return lines
    if len(lines)>=max_lines: raise ValueError("SMTP multiline response too large")
    return lines

def _code(lines: List[str])->Optional[int]:
    return int(lines[0][:3]) if lines and len(lines[0])>=3 and lines[0][:3].isdigit() else None

class SMTPEnumerator:
    DEFAULT_PORT=25
    _recv_line=staticmethod(_recv_line)
    _recv_response=staticmethod(_recv_response)
    @staticmethod
    def _send(sock: socket.socket,command: str)->None:
        if "\r" in command or "\n" in command: raise ValueError("SMTP command contains line break")
        sock.sendall(command.encode("ascii")+b"\r\n")
    @staticmethod
    def check_open(ip: str,port: int=25,timeout: float=3.0)->bool:
        try:
            with socket.create_connection((ip,port),timeout=timeout): return True
        except OSError: return False
    @staticmethod
    def banner(ip: str,port: int=25,timeout: float=5.0)->str:
        try:
            with socket.create_connection((ip,port),timeout=timeout) as sock:
                lines=_recv_response(sock,timeout)
                return lines[0][4:].strip() if lines and lines[0].startswith("220") else ""
        except (OSError,ValueError,ConnectionError): return ""
    @staticmethod
    def _ehlo(sock: socket.socket,timeout: float)->List[str]:
        SMTPEnumerator._send(sock,"EHLO spectrascan.local")
        lines=_recv_response(sock,timeout)
        if _code(lines)!=250:
            SMTPEnumerator._send(sock,"HELO spectrascan.local"); lines=_recv_response(sock,timeout)
        return lines
    @staticmethod
    def vrfy_users(ip: str,users: List[str],port: int=25,timeout: float=5.0)->List[str]:
        valid=[]
        try:
            with socket.create_connection((ip,port),timeout=timeout) as sock:
                _recv_response(sock,timeout); SMTPEnumerator._ehlo(sock,timeout)
                for user in users:
                    SMTPEnumerator._send(sock,f"VRFY {user}")
                    if _code(_recv_response(sock,timeout)) in (250,252): valid.append(user)
                SMTPEnumerator._send(sock,"QUIT"); _recv_response(sock,timeout)
        except (OSError,ValueError,ConnectionError): pass
        return valid
    @staticmethod
    def check_open_relay(ip: str,port: int=25,timeout: float=10.0,
                         test_from: str="test@spectra.local",test_to: str="test@example.net")->Dict[str,Any]:
        result={"open_relay":False,"evidence":[],"classification":"not_detected"}
        try:
            with socket.create_connection((ip,port),timeout=timeout) as sock:
                _recv_response(sock,timeout); SMTPEnumerator._ehlo(sock,timeout)
                SMTPEnumerator._send(sock,f"MAIL FROM:<{test_from}>")
                if _code(_recv_response(sock,timeout))!=250: return result
                SMTPEnumerator._send(sock,f"RCPT TO:<{test_to}>")
                if _code(_recv_response(sock,timeout))==250:
                    result["open_relay"]=True; result["classification"]="potential"
                    result["evidence"].append("External RCPT TO accepted without authentication; no DATA/message was sent.")
                SMTPEnumerator._send(sock,"RSET"); _recv_response(sock,timeout)
                SMTPEnumerator._send(sock,"QUIT"); _recv_response(sock,timeout)
        except (OSError,ValueError,ConnectionError) as exc: result["error"]=type(exc).__name__
        return result
    @staticmethod
    def check_starttls(ip: str,port: int=25,timeout: float=5.0)->bool:
        try:
            with socket.create_connection((ip,port),timeout=timeout) as sock:
                _recv_response(sock,timeout); capabilities=SMTPEnumerator._ehlo(sock,timeout)
                if not any("STARTTLS" in line.upper() for line in capabilities[1:]): return False
                SMTPEnumerator._send(sock,"STARTTLS")
                return _code(_recv_response(sock,timeout))==220
        except (OSError,ValueError,ConnectionError): return False
    @staticmethod
    def scan(ip: str,port: int=25,test_relay: bool=True,users_to_test: List[str]=None)->Dict[str,Any]:
        result={"module":"smtp","target":ip,"port":port,"open":False,"banner":"","starttls":None,
                "open_relay":False,"valid_users":[],"vulnerabilities":[],"observations":[]}
        if not SMTPEnumerator.check_open(ip,port): return result
        result["open"]=True; result["banner"]=SMTPEnumerator.banner(ip,port)
        result["starttls"]=SMTPEnumerator.check_starttls(ip,port)
        if not result["starttls"]:
            result["observations"].append("STARTTLS was not successfully negotiated; this alone does not prove credentials are sent in plaintext.")
        result["valid_users"]=SMTPEnumerator.vrfy_users(ip,users_to_test or ["root","admin","postmaster","test","info","mail"],port)
        if result["valid_users"]:
            result["vulnerabilities"].append({"name":f"SMTP VRFY disclosed {len(result['valid_users'])} user(s)","severity":"LOW","cve":"N/A"})
        if test_relay:
            relay=SMTPEnumerator.check_open_relay(ip,port); result["open_relay"]=relay.get("open_relay",False)
            if result["open_relay"]:
                result["vulnerabilities"].append({"name":"Potential SMTP open relay; RCPT accepted but no message was sent",
                    "severity":"MEDIUM","cve":"N/A","evidence":relay.get("evidence",[])})
        return result
