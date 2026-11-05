"""Read-only MySQL, PostgreSQL, and MSSQL protocol handshakes."""
from __future__ import annotations
import socket, ssl, struct
from typing import Any, Dict

def _recv_exact(sock: socket.socket,size: int)->bytes:
    data=bytearray()
    while len(data)<size:
        chunk=sock.recv(size-len(data))
        if not chunk: raise ConnectionError("Database peer closed connection")
        data.extend(chunk)
    return bytes(data)

class MySQLEnumerator:
    DEFAULT_PORT=3306
    @staticmethod
    def parse_handshake(packet: bytes):
        if len(packet)<6 or packet[0] not in (9,10): return None
        end=packet.find(b"\x00",1)
        return packet[1:end].decode("ascii",errors="replace") if end>1 else None
    @staticmethod
    def scan(ip: str,port: int=3306)->Dict[str,Any]:
        result={"module":"mysql","target":ip,"port":port,"open":False,"version":None,"vulnerabilities":[]}
        try:
            with socket.create_connection((ip,port),timeout=5) as sock:
                sock.settimeout(5); header=_recv_exact(sock,4)
                size=int.from_bytes(header[:3],"little")
                if not 6<=size<=1024*1024: raise ValueError("Invalid MySQL handshake length")
                packet=_recv_exact(sock,size)
            version=MySQLEnumerator.parse_handshake(packet)
            if version is None: raise ValueError("Unrecognized MySQL handshake")
            result["open"]=True; result["version"]=version
            result["observations"]=["Handshake detected; network exposure alone is not a confirmed vulnerability."]
        except (OSError,ValueError,ConnectionError) as exc: result["error"]=type(exc).__name__
        return result

class PostgreSQLEnumerator:
    DEFAULT_PORT=5432
    @staticmethod
    def startup_message(user: str="spectrascan",database: str="postgres")->bytes:
        body=struct.pack(">I",196608)+f"user\x00{user}\x00database\x00{database}\x00client_encoding\x00UTF8\x00\x00".encode()
        return struct.pack(">I",len(body)+4)+body
    @staticmethod
    def scan(ip: str,port: int=5432)->Dict[str,Any]:
        result={"module":"postgresql","target":ip,"port":port,"open":False,"ssl_supported":None,
                "tls_negotiated":False,"auth_required":None,"version":None,"vulnerabilities":[]}
        try:
            with socket.create_connection((ip,port),timeout=5) as raw:
                raw.settimeout(5); raw.sendall(struct.pack(">II",8,80877103))
                response=_recv_exact(raw,1); result["open"]=True; result["ssl_supported"]=response==b"S"
                channel=raw
                if response==b"S":
                    try:
                        channel=ssl.create_default_context().wrap_socket(raw,server_hostname=ip)
                        result["tls_negotiated"]=True
                    except ssl.SSLError:
                        result["tls_error"]="certificate_or_handshake_error"; return result
                elif response!=b"N":
                    result["error"]="unexpected_ssl_response"; return result
                channel.sendall(PostgreSQLEnumerator.startup_message())
                kind=_recv_exact(channel,1); size=struct.unpack(">I",_recv_exact(channel,4))[0]
                if not 4<=size<=1024*1024: raise ValueError("Invalid PostgreSQL response length")
                payload=_recv_exact(channel,size-4)
                if kind==b"R":
                    result["auth_required"]=True
                    result["auth_method_code"]=struct.unpack(">I",payload[:4])[0] if len(payload)>=4 else None
                elif kind==b"E":
                    sample=payload.decode("utf-8",errors="replace")
                    result["auth_required"]="password" in sample.lower() or "authentication" in sample.lower()
                    result["error_response_sample"]=sample[:200]
                else: result["response_type"]=kind.decode("ascii",errors="replace")
        except (OSError,ValueError,ConnectionError,struct.error) as exc: result["error"]=type(exc).__name__
        return result

class MSSQLEnumerator:
    DEFAULT_PORT=1433
    @staticmethod
    def scan(ip: str,port: int=1433)->Dict[str,Any]:
        result={"module":"mssql","target":ip,"port":port,"open":False,"version":None,"instance_name":None,"vulnerabilities":[]}
        prelogin=bytes([0x12,0x01,0x00,0x2f,0,0,0,1,0,0,0x15,0,6,1,0,0x1b,0,1,2,0,0x1c,0,1,3,0,0x1d,0,0,4,0,0,0xff])
        try:
            with socket.create_connection((ip,port),timeout=5) as sock:
                sock.settimeout(5); sock.sendall(prelogin); response=sock.recv(4096)
            result["open"]=bool(response); result["response_bytes"]=len(response)
        except OSError as exc: result["error"]=type(exc).__name__
        return result

def scan_all_databases(ip: str)->Dict[str,Any]:
    return {"mysql":MySQLEnumerator.scan(ip),"postgresql":PostgreSQLEnumerator.scan(ip),
            "mssql":MSSQLEnumerator.scan(ip)}
