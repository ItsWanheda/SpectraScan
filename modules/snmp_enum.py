"""SNMPv2c query and response handling using bounded BER parsing."""
from __future__ import annotations
import random, shutil, socket, subprocess
from typing import Any, Dict, List, Optional, Tuple

class SNMPError(ValueError): pass

def _length(n: int) -> bytes:
    if n < 0: raise ValueError("negative BER length")
    if n < 128: return bytes([n])
    raw = n.to_bytes((n.bit_length()+7)//8, "big")
    return bytes([0x80|len(raw)]) + raw

def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value

def _integer(value: int, tag: int = 2) -> bytes:
    if value == 0: raw = b"\x00"
    else:
        raw = value.to_bytes(max(1,(value.bit_length()+8)//8),"big",signed=True)
        while len(raw)>1 and ((raw[0]==0 and not raw[1]&128) or (raw[0]==255 and raw[1]&128)): raw=raw[1:]
    return _tlv(tag,raw)

def _base128(value: int) -> bytes:
    if value < 0: raise ValueError("negative OID arc")
    out=[value&127]; value >>= 7
    while value: out.append(128|(value&127)); value >>= 7
    return bytes(reversed(out))

def _oid(oid: str) -> bytes:
    try: arcs=[int(v) for v in oid.strip(".").split(".")]
    except (TypeError,ValueError) as exc: raise ValueError("invalid OID") from exc
    if len(arcs)<2 or arcs[0] not in (0,1,2) or any(v<0 for v in arcs) or (arcs[0]<2 and arcs[1]>39):
        raise ValueError("invalid OID arcs")
    return _tlv(6,_base128(40*arcs[0]+arcs[1])+b"".join(_base128(v) for v in arcs[2:]))

def _read_length(data: bytes, pos: int) -> Tuple[int,int]:
    if pos>=len(data): raise SNMPError("missing BER length")
    first=data[pos]; pos+=1
    if first<128: return first,pos
    count=first&127
    if not count or count>4 or pos+count>len(data) or data[pos]==0: raise SNMPError("invalid BER length")
    size=int.from_bytes(data[pos:pos+count],"big")
    if size<128: raise SNMPError("non-canonical BER length")
    return size,pos+count

def _read_tlv(data: bytes,pos: int=0) -> Tuple[int,bytes,int]:
    if pos>=len(data): raise SNMPError("missing BER tag")
    tag=data[pos]; size,start=_read_length(data,pos+1); end=start+size
    if end>len(data): raise SNMPError("BER value exceeds message")
    return tag,data[start:end],end

def _decode_oid(raw: bytes) -> str:
    arcs=[]; value=0
    for byte in raw:
        value=(value<<7)|(byte&127)
        if not byte&128: arcs.append(value); value=0
    if not raw or raw[-1]&128 or not arcs: raise SNMPError("invalid OID encoding")
    first=min(arcs[0]//40,2)
    return ".".join(map(str,[first,arcs[0]-40*first,*arcs[1:]]))

def _decode_value(tag: int, raw: bytes) -> str:
    if tag==6: return _decode_oid(raw)
    if tag in (2,65,66,67,70):
        n=int.from_bytes(raw,"big",signed=(tag==2))
        return f"{n} ticks" if tag==67 else str(n)
    if tag==4: return raw.decode("utf-8",errors="replace")
    if tag==5: return "NULL"
    if tag in (128,129,130): return {128:"noSuchObject",129:"noSuchInstance",130:"endOfMibView"}[tag]
    return raw.hex()

def _parse_response(data: bytes, expected_oid: Optional[str]=None) -> str:
    tag,msg,end=_read_tlv(data)
    if tag!=48 or end!=len(data): raise SNMPError("invalid SNMP envelope")
    _,_,pos=_read_tlv(msg,0)
    community_tag,_,pos=_read_tlv(msg,pos)
    if community_tag!=4: raise SNMPError("invalid community field")
    pdu_tag,pdu,_=_read_tlv(msg,pos)
    if pdu_tag!=162: raise SNMPError("expected GetResponse PDU")
    _,_,pos=_read_tlv(pdu,0)
    status_tag,status,pos=_read_tlv(pdu,pos)
    _,_,pos=_read_tlv(pdu,pos)
    list_tag,bindings,_=_read_tlv(pdu,pos)
    if status_tag!=2 or list_tag!=48 or int.from_bytes(status,"big",signed=True)!=0:
        raise SNMPError("SNMP agent returned an error")
    bind_tag,binding,bind_end=_read_tlv(bindings)
    if bind_tag!=48 or bind_end!=len(bindings): raise SNMPError("invalid variable binding")
    oid_tag,oid_raw,pos=_read_tlv(binding,0)
    value_tag,value_raw,_=_read_tlv(binding,pos)
    returned=_decode_oid(oid_raw) if oid_tag==6 else ""
    if expected_oid and returned!=expected_oid: raise SNMPError("response OID mismatch")
    return _decode_value(value_tag,value_raw)

class SNMPEnumerator:
    DEFAULT_COMMUNITIES=["public","private","manager","monitor","admin","cisco","snmp"]
    SYSTEM_OIDS={
        "1.3.6.1.2.1.1.1.0":"sysDescr","1.3.6.1.2.1.1.2.0":"sysObjectID",
        "1.3.6.1.2.1.1.3.0":"sysUpTime","1.3.6.1.2.1.1.4.0":"sysContact",
        "1.3.6.1.2.1.1.5.0":"sysName","1.3.6.1.2.1.1.6.0":"sysLocation",
        "1.3.6.1.2.1.1.7.0":"sysServices"}
    _ber_encode_length=staticmethod(_length)
    _ber_encode_integer=staticmethod(_integer)
    _ber_encode_oid=staticmethod(_oid)

    @staticmethod
    def _build_get_request(community: str, oid: str, request_id: Optional[int]=None) -> bytes:
        rid=request_id if request_id is not None else random.randint(1,2**31-1)
        binding=_tlv(48,_oid(oid)+_tlv(5,b""))
        bindings=_tlv(48,binding)
        pdu=_tlv(160,_integer(rid)+_integer(0)+_integer(0)+bindings)
        return _tlv(48,_integer(1)+_tlv(4,community.encode("utf-8"))+pdu)

    @staticmethod
    def query(ip: str, community: str, oid: str, timeout: float=3.0) -> Optional[str]:
        try:
            family=socket.AF_INET6 if ":" in ip else socket.AF_INET
            with socket.socket(family,socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(SNMPEnumerator._build_get_request(community,oid),(ip,161))
                data,_=sock.recvfrom(65535)
            value=_parse_response(data,oid)
            return None if value.startswith("noSuch") or value=="NULL" else value
        except (OSError,SNMPError,ValueError): return None

    @staticmethod
    def _snmpwalk(ip: str, communities: List[str]) -> Optional[Dict[str,str]]:
        exe=shutil.which("snmpwalk")
        if not exe: return None
        for community in communities:
            try:
                proc=subprocess.run([exe,"-v2c","-c",community,"-t","2",ip,"1.3.6.1.2.1.1"],
                                     capture_output=True,text=True,timeout=15,check=False)
            except (OSError,subprocess.TimeoutExpired): continue
            if proc.returncode==0 and proc.stdout:
                values={}
                for line in proc.stdout.splitlines():
                    key,sep,value=line.partition("=")
                    if sep: values[key.strip()]=value.strip()
                if values: return {"community":community,**values}
        return None

    @staticmethod
    def scan(ip: str, communities: Optional[List[str]]=None) -> Dict[str,Any]:
        result={"module":"snmp","target":ip,"open":False,"community":None,"system":{},"vulnerabilities":[]}
        candidates=list(communities or SNMPEnumerator.DEFAULT_COMMUNITIES)
        for community in candidates:
            value=SNMPEnumerator.query(ip,community,"1.3.6.1.2.1.1.1.0",2.0)
            if value is None: continue
            result.update(open=True,community=community)
            result["system"]["sysDescr"]=value
            for oid,name in SNMPEnumerator.SYSTEM_OIDS.items():
                if name=="sysDescr": continue
                other=SNMPEnumerator.query(ip,community,oid,2.0)
                if other is not None: result["system"][name]=other
            break
        if not result["open"]:
            fallback=SNMPEnumerator._snmpwalk(ip,candidates)
            if fallback:
                result["open"]=True; result["community"]=fallback.pop("community"); result["system"]=fallback
        if result["open"] and result["community"] in SNMPEnumerator.DEFAULT_COMMUNITIES:
            result["vulnerabilities"].append({"name":"Default SNMP community string accepted","severity":"MEDIUM","cve":"N/A"})
        desc=str(result["system"].get("sysDescr","")).lower()
        if any(t in desc for t in ("linux","ubuntu","debian")): result["os_guess"]="Linux"
        elif "windows" in desc: result["os_guess"]="Windows"
        elif "cisco" in desc or "ios" in desc: result["os_guess"]="Cisco IOS"
        return result
