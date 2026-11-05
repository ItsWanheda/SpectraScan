"""RDP negotiation parsing with conservative NLA and BlueKeep assessment."""
from __future__ import annotations
import socket
import struct
from typing import Any, Dict

PROTOCOL_RDP=0x00
PROTOCOL_SSL=0x01
PROTOCOL_HYBRID=0x02
PROTOCOL_HYBRID_EX=0x08

def _connection_request(protocols: int)->bytes:
    cookie=b"Cookie: mstshash:spectrascan\r\n"
    negotiation=struct.pack("<BBHI",1,0,8,protocols)
    # X.224 CR: LI, code, dst-ref, src-ref, class, cookie, negotiation.
    body=b"\xE0\x00\x00\x00\x00\x00"+cookie+negotiation
    tpdu=bytes([len(body)])+body
    return struct.pack(">BBH",3,0,len(tpdu)+4)+tpdu

def _parse_negotiation(data: bytes)->Dict[str,Any]:
    result={"responds":False,"nla":None,"selected_protocol":None}
    if len(data)<11 or data[0]!=3: return result
    result["responds"]=True
    for pos in range(4,len(data)-7):
        if data[pos]==2 and data[pos+2:pos+4]==b"\x08\x00":
            selected=struct.unpack_from("<I",data,pos+4)[0]
            result["selected_protocol"]=selected
            result["nla"]=selected in (PROTOCOL_HYBRID,PROTOCOL_HYBRID_EX)
            return result
        if data[pos]==3 and data[pos+2:pos+4]==b"\x08\x00":
            result["negotiation_failure"]=struct.unpack_from("<I",data,pos+4)[0]
            return result
    return result

class RDPEnumerator:
    DEFAULT_PORT=3389
    @staticmethod
    def check_open(ip: str,port: int=3389,timeout: float=3.0)->bool:
        try:
            with socket.create_connection((ip,port),timeout=timeout): return True
        except OSError: return False
    @staticmethod
    def grab_banner(ip: str,port: int=3389,timeout: float=5.0)->str:
        try:
            with socket.create_connection((ip,port),timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(_connection_request(PROTOCOL_RDP|PROTOCOL_SSL|PROTOCOL_HYBRID|PROTOCOL_HYBRID_EX))
                return sock.recv(4096).hex()
        except OSError: return ""
    @staticmethod
    def check_nla(ip: str,port: int=3389,timeout: float=5.0)->Dict[str,Any]:
        result={"responds":False,"nla_likely":None,"raw":""}
        try:
            with socket.create_connection((ip,port),timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(_connection_request(PROTOCOL_RDP|PROTOCOL_SSL|PROTOCOL_HYBRID|PROTOCOL_HYBRID_EX))
                data=sock.recv(4096)
            parsed=_parse_negotiation(data); result.update(parsed)
            result["nla_likely"]=parsed.get("nla"); result["raw"]=data.hex()[:256]
        except (OSError,ConnectionError) as exc: result["error"]=type(exc).__name__
        return result
    @staticmethod
    def scan(ip: str,port: int=3389)->Dict[str,Any]:
        result={"module":"rdp","target":ip,"port":port,"open":False,"nla":None,
                "version":None,"vulnerabilities":[],"observations":[]}
        if not RDPEnumerator.check_open(ip,port): return result
        result["open"]=True
        negotiation=RDPEnumerator.check_nla(ip,port)
        result["nla"]=negotiation.get("nla_likely")
        if result["nla"] is False:
            result["vulnerabilities"].append({
                "name":"RDP negotiated without Network Level Authentication","severity":"MEDIUM","cve":"N/A",
                "evidence":f"Server selected protocol {negotiation.get('selected_protocol')}.",
            })
        elif result["nla"] is True:
            result["observations"].append("RDP negotiation selected an NLA-capable protocol.")
        else:
            result["observations"].append("NLA status could not be determined from the negotiation response.")
        result["bluekeep_assessment"]={"status":"not_assessed",
            "reason":"An open RDP port or disabled NLA is not evidence of BlueKeep; OS and patch-level evidence are required."}
        return result
