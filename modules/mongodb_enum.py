"""MongoDB OP_MSG framing and BSON parsing."""
from __future__ import annotations
import socket, struct
from typing import Any, Dict

MAX_MESSAGE_SIZE=16*1024*1024

def _recv_exact(sock: socket.socket,size: int)->bytes:
    data=bytearray()
    while len(data)<size:
        chunk=sock.recv(size-len(data))
        if not chunk: raise ConnectionError("MongoDB peer closed mid-frame")
        data.extend(chunk)
    return bytes(data)

class MongoDBEnumerator:
    DEFAULT_PORT=27017
    @staticmethod
    def check_open(ip: str,port: int=27017,timeout: float=3.0)->bool:
        try:
            with socket.create_connection((ip,port),timeout=timeout): return True
        except OSError: return False
    @staticmethod
    def _send_op_msg(sock: socket.socket,doc: bytes,request_id: int=1)->bytes:
        body=struct.pack("<I",0)+b"\x00"+doc
        length=16+len(body)
        if length>MAX_MESSAGE_SIZE: raise ValueError("MongoDB request too large")
        sock.sendall(struct.pack("<iiii",length,request_id,0,2013)+body)
        header=_recv_exact(sock,16)
        response_length,_,response_to,opcode=struct.unpack("<iiii",header)
        if response_length<21 or response_length>MAX_MESSAGE_SIZE or opcode!=2013:
            raise ValueError("Invalid MongoDB response header")
        if response_to != request_id: raise ValueError("MongoDB response id mismatch")
        payload=_recv_exact(sock,response_length-16)
        if payload[4]!=0: raise ValueError("Unsupported OP_MSG section")
        document=payload[5:]
        size=struct.unpack_from("<i",document,0)[0]
        if size<5 or size>len(document): raise ValueError("Invalid BSON response length")
        return document[:size]
    @staticmethod
    def _bson_encode(doc: Dict[str,Any])->bytes:
        elements=bytearray()
        for key,value in doc.items():
            if "\x00" in key: raise ValueError("BSON keys cannot contain NUL")
            k=key.encode()+b"\x00"
            if isinstance(value,bool): elements+=b"\x08"+k+(b"\x01" if value else b"\x00")
            elif isinstance(value,int):
                if -(2**31)<=value<2**31: elements+=b"\x10"+k+struct.pack("<i",value)
                elif -(2**63)<=value<2**63: elements+=b"\x12"+k+struct.pack("<q",value)
                else: raise ValueError("BSON integer out of range")
            elif isinstance(value,str):
                raw=value.encode()+b"\x00"; elements+=b"\x02"+k+struct.pack("<i",len(raw))+raw
            elif value is None: elements+=b"\x0A"+k
            elif isinstance(value,float): elements+=b"\x01"+k+struct.pack("<d",value)
            elif isinstance(value,dict): elements+=b"\x03"+k+MongoDBEnumerator._bson_encode(value)
            elif isinstance(value,list):
                nested=MongoDBEnumerator._bson_encode({str(i):v for i,v in enumerate(value)})
                elements+=b"\x04"+k+nested
            else: raise TypeError(f"Unsupported BSON value: {type(value).__name__}")
        payload=bytes(elements)+b"\x00"
        return struct.pack("<i",len(payload)+4)+payload
    @staticmethod
    def _parse_bson(data: bytes,offset: int=0)->Dict[str,Any]:
        if offset<0 or offset+5>len(data): raise ValueError("Truncated BSON document")
        size=struct.unpack_from("<i",data,offset)[0]; end=offset+size
        if size<5 or end>len(data) or data[end-1]!=0: raise ValueError("Invalid BSON document bounds")
        result={}; pos=offset+4
        while pos<end-1:
            kind=data[pos]; pos+=1
            key_end=data.find(b"\x00",pos,end)
            if key_end<0: raise ValueError("Unterminated BSON key")
            key=data[pos:key_end].decode("utf-8",errors="replace"); pos=key_end+1
            if kind==1: value=struct.unpack_from("<d",data,pos)[0]; pos+=8
            elif kind==2:
                n=struct.unpack_from("<i",data,pos)[0]; pos+=4
                if n<1 or pos+n>end: raise ValueError("Invalid BSON string length")
                value=data[pos:pos+n-1].decode("utf-8",errors="replace"); pos+=n
            elif kind in (3,4):
                n=struct.unpack_from("<i",data,pos)[0]
                if n<5 or pos+n>end: raise ValueError("Invalid nested BSON length")
                nested=MongoDBEnumerator._parse_bson(data,pos)
                value=nested if kind==3 else [nested[k] for k in sorted(nested,key=lambda v:int(v)) if k.isdigit()]
                pos+=n
            elif kind==5:
                n=struct.unpack_from("<i",data,pos)[0]; pos+=5
                if n<0 or pos+n>end: raise ValueError("Invalid BSON binary length")
                value=data[pos:pos+n].hex(); pos+=n
            elif kind==8:
                if pos>=end: raise ValueError("Truncated BSON bool")
                value=bool(data[pos]); pos+=1
            elif kind==9: value=struct.unpack_from("<q",data,pos)[0]; pos+=8
            elif kind==10: value=None
            elif kind==16: value=struct.unpack_from("<i",data,pos)[0]; pos+=4
            elif kind==18: value=struct.unpack_from("<q",data,pos)[0]; pos+=8
            else: raise ValueError(f"Unsupported BSON type {kind}")
            if pos>end-1: raise ValueError("BSON value outside document")
            result[key]=value
        return result
    @staticmethod
    def scan(ip: str,port: int=27017)->Dict[str,Any]:
        result={"module":"mongodb","target":ip,"port":port,"open":False,"auth_required":None,
                "version":None,"databases":[],"vulnerabilities":[]}
        try:
            with socket.create_connection((ip,port),timeout=5) as sock:
                sock.settimeout(5)
                hello=MongoDBEnumerator._bson_encode({"hello":1,"$db":"admin"})
                hello_doc=MongoDBEnumerator._parse_bson(MongoDBEnumerator._send_op_msg(sock,hello,1))
                result["open"]=True; result["max_wire_version"]=hello_doc.get("maxWireVersion")
                cmd=MongoDBEnumerator._bson_encode({"listDatabases":1,"nameOnly":True,"$db":"admin"})
                response=MongoDBEnumerator._parse_bson(MongoDBEnumerator._send_op_msg(sock,cmd,2))
                if response.get("ok") in (1,1.0,True):
                    result["auth_required"]=False
                    result["databases"]=[d.get("name") for d in response.get("databases",[]) if isinstance(d,dict) and d.get("name")]
                    result["vulnerabilities"].append({"name":"MongoDB database listing accessible without authentication","severity":"HIGH","cve":"N/A"})
                else:
                    result["auth_required"]=True; result["auth_error"]=str(response.get("errmsg","not authorized"))[:200]
        except (OSError,ValueError,struct.error,ConnectionError) as exc: result["error"]=type(exc).__name__
        return result
