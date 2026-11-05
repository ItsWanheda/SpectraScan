"""Bounded Redis RESP2 reader and read-only exposure checks."""
from __future__ import annotations
import socket
from typing import Any, Dict
MAX_RESPONSE=65536

def _read_line(stream)->bytes:
    line=stream.readline(8193)
    if not line or len(line)>8192 or not line.endswith(b"\r\n"): raise ValueError("Invalid Redis RESP line")
    return line[:-2]

def _read_resp(stream,depth: int=0)->Any:
    if depth>8: raise ValueError("Redis RESP nesting too deep")
    prefix=stream.read(1)
    if prefix==b"+": return _read_line(stream).decode("utf-8",errors="replace")
    if prefix==b"-": return "ERROR: "+_read_line(stream).decode("utf-8",errors="replace")
    if prefix==b":": return int(_read_line(stream))
    if prefix==b"$":
        size=int(_read_line(stream))
        if size==-1: return None
        if size<0 or size>MAX_RESPONSE: raise ValueError("Redis bulk response exceeds limit")
        raw=stream.read(size+2)
        if len(raw)!=size+2 or not raw.endswith(b"\r\n"): raise ValueError("Truncated Redis bulk response")
        return raw[:-2].decode("utf-8",errors="replace")
    if prefix==b"*":
        count=int(_read_line(stream))
        if count==-1: return None
        if count<0 or count>1024: raise ValueError("Redis array exceeds limit")
        return [_read_resp(stream,depth+1) for _ in range(count)]
    if not prefix: raise ConnectionError("Redis peer closed connection")
    raise ValueError("Unsupported RESP type")

class RedisEnumerator:
    DEFAULT_PORT=6379
    @staticmethod
    def check_open(ip: str,port: int=6379,timeout: float=3.0)->bool:
        try:
            with socket.create_connection((ip,port),timeout=timeout): return True
        except OSError: return False
    @staticmethod
    def send_command(ip: str,port: int,command: str,timeout: float=5.0)->str:
        args=command.split()
        if not args or len(args)>16 or any("\r" in x or "\n" in x for x in args): raise ValueError("Invalid Redis command")
        payload=f"*{len(args)}\r\n".encode()
        for arg in args:
            value=arg.encode(); payload+=b"$"+str(len(value)).encode()+b"\r\n"+value+b"\r\n"
        with socket.create_connection((ip,port),timeout=timeout) as sock:
            sock.settimeout(timeout); sock.sendall(payload)
            with sock.makefile("rb") as stream: value=_read_resp(stream)
        if value is None: return ""
        return "\n".join("" if v is None else str(v) for v in value) if isinstance(value,list) else str(value)
    @staticmethod
    def scan(ip: str,port: int=6379)->Dict[str,Any]:
        result={"module":"redis","target":ip,"port":port,"open":False,"auth_required":None,
                "version":None,"info":{},"vulnerabilities":[]}
        if not RedisEnumerator.check_open(ip,port): return result
        result["open"]=True
        try:
            ping=RedisEnumerator.send_command(ip,port,"PING"); result["ping_response"]=ping[:200]
            if ping.startswith("ERROR: NOAUTH") or ping.startswith("ERROR: WRONGPASS"):
                result["auth_required"]=True; return result
            if ping!="PONG": result["error"]="Unexpected Redis PING response"; return result
            info=RedisEnumerator.send_command(ip,port,"INFO server")
            if info.startswith("ERROR:"):
                result["auth_required"]=True; result["access_note"]=info[:200]; return result
            result["auth_required"]=False
            for line in info.splitlines():
                key,sep,value=line.strip().partition(":")
                if sep and len(result["info"])<30: result["info"][key]=value
                if sep and key=="redis_version": result["version"]=value
            result["vulnerabilities"].append({"name":"Redis INFO accessible without authentication","severity":"HIGH","cve":"N/A"})
            dbsize=RedisEnumerator.send_command(ip,port,"DBSIZE")
            if not dbsize.startswith("ERROR:"): result["db_size"]=dbsize
        except (OSError,ValueError,ConnectionError) as exc: result["error"]=type(exc).__name__
        return result
