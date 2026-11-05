"""RTSP DESCRIBE with correct response header and SDP extraction."""
from __future__ import annotations
import socket
from typing import Any, Dict, List

def _parse_response(raw: bytes)->Dict[str,Any]:
    text=raw.decode("latin-1",errors="replace")
    header,sep,body=text.partition("\r\n\r\n")
    lines=header.split("\r\n")
    status=lines[0].split(" ",2) if lines else []
    code=int(status[1]) if len(status)>1 and status[1].isdigit() else None
    headers={}
    for line in lines[1:]:
        name,colon,value=line.partition(":")
        if colon: headers[name.strip().lower()]=value.strip()
    streams=[]
    for line in body.splitlines() if sep else []:
        if line.startswith("m="):
            parts=line[2:].split()
            if len(parts)>=3:
                streams.append({"type":parts[0],"port":int(parts[1]) if parts[1].isdigit() else None,
                                "protocol":parts[2],"formats":parts[3:]})
    return {"status_code":code,"status_line":lines[0] if lines else "",
            "headers":headers,"body":body,"streams":streams,"server":headers.get("server"),
            "auth_required":code==401 or "www-authenticate" in headers,"open":code is not None}

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
