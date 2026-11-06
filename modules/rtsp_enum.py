"""RTSP DESCRIBE with correct response header and SDP extraction."""
from __future__ import annotations
import re, socket
from typing import Any, Dict, List

def _parse_response(raw: bytes)->Dict[str,Any]:
    if b"\r\n\r\n" not in raw:
        raise ValueError("RTSP response is missing the header terminator")
    header,_,body=raw.partition(b"\r\n\r\n")
    try:
        lines=header.decode("latin-1").split("\r\n")
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid RTSP headers") from exc
    if not lines or not re.fullmatch(r"RTSP/1\.[0-9] [1-5][0-9]{2}(?: .*)?",lines[0]):
        raise ValueError("Malformed RTSP status line")
    code=int(lines[0].split(" ",2)[1])
    headers={}
    content_length=None
    for line in lines[1:]:
        if not line or line[0] in " \t":
            raise ValueError("Malformed RTSP header line")
        name,colon,value=line.partition(":")
        if not colon or not name.strip():
            raise ValueError("Malformed RTSP header")
        key=name.strip().lower()
        if key in headers:
            raise ValueError("Duplicate RTSP header")
        value=value.strip()
        headers[key]=value
        if key=="content-length":
            if not value.isdigit():
                raise ValueError("Invalid RTSP Content-Length")
            content_length=int(value)
            if content_length>65536:
                raise ValueError("RTSP body exceeds parser limit")
    if content_length is not None and len(body)!=content_length:
        raise ValueError("RTSP Content-Length does not match received body")
    body_text=body.decode("latin-1")
    streams=[]
    for line in body_text.splitlines():
        if line.startswith("m="):
            parts=line[2:].split()
            if len(parts)<3:
                raise ValueError("Malformed SDP media line")
            port_text=parts[1].split("/",1)[0]
            if not port_text.isdigit():
                raise ValueError("Invalid SDP media port")
            streams.append({"type":parts[0],"port":int(port_text),
                            "protocol":parts[2],"formats":parts[3:]})
    return {"status_code":code,"status_line":lines[0],
            "headers":headers,"body":body_text,"streams":streams,"server":headers.get("server"),
            "auth_required":code==401 or "www-authenticate" in headers,"open":True}

class RTSPEnumerator:
    DEFAULT_PORT=554
    @staticmethod
    def check_open(ip: str,port: int=554,timeout: float=3.0)->bool:
        try:
            with socket.create_connection((ip,port),timeout=timeout): return True
        except OSError: return False
    @staticmethod
    def describe(ip: str,port: int=554,url: str="/",timeout: float=5.0)->Dict[str,Any]:
        path=url if url.startswith("/") else "/"+url
        request=(f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                 "CSeq: 1\r\nUser-Agent: SpectraScan\r\nAccept: application/sdp\r\n"
                 "Connection: close\r\n\r\n").encode("ascii",errors="replace")
        result={"open":False,"auth_required":None,"server":None,"sdp":None,"streams":[],"status_code":None}
        try:
            with socket.create_connection((ip,port),timeout=timeout) as sock:
                sock.settimeout(timeout); sock.sendall(request); data=bytearray()
                while len(data)<65536:
                    chunk=sock.recv(min(4096,65536-len(data)))
                    if not chunk: break
                    data.extend(chunk)
                    if b"\r\n\r\n" in data:
                        head,_,body=bytes(data).partition(b"\r\n\r\n")
                        length=0
                        for line in head.split(b"\r\n")[1:]:
                            if line.lower().startswith(b"content-length:"):
                                try: length=int(line.split(b":",1)[1].strip())
                                except ValueError: length=0
                        if len(body)>=length: break
            parsed=_parse_response(bytes(data)); result.update(parsed); result["sdp"]=parsed["body"][:500]
        except (OSError,ValueError) as exc: result["error"]=type(exc).__name__
        return result
    @staticmethod
    def scan(ip: str,port: int=554,urls: List[str]=None)->Dict[str,Any]:
        result={"module":"rtsp","target":ip,"port":port,"open":False,"server":None,
                "auth_required":None,"streams":[],"vulnerabilities":[]}
        if not RTSPEnumerator.check_open(ip,port): return result
        for path in urls or ["/","/stream","/live","/video","/cam","/h264"]:
            response=RTSPEnumerator.describe(ip,port,path)
            if not response.get("open"): continue
            result["open"]=True; result["server"]=response.get("server") or result["server"]
            if response.get("auth_required"):
                result["auth_required"]=True; continue
            if response.get("status_code")==200 and response.get("streams"):
                result["auth_required"]=False; result["streams"].extend(response["streams"])
                result["url_works"]=path; result["sdp"]=response.get("sdp"); break
        if result["auth_required"] is False and result["streams"]:
            result["vulnerabilities"].append({
                "name":f"RTSP media description accessible without authentication at {result['url_works']}",
                "severity":"HIGH","cve":"N/A",
                "evidence":"Server returned RTSP 200 with SDP media sections without an authentication challenge.",
            })
        return result
