"""NFS export discovery using bounded ONC RPC record and XDR parsing."""
from __future__ import annotations
import shutil
import socket
import struct
import subprocess
from typing import Any, Dict, List, Tuple

def _recv_exact(sock: socket.socket,size: int)->bytes:
    data=bytearray()
    while len(data)<size:
        chunk=sock.recv(size-len(data))
        if not chunk: raise ConnectionError("RPC peer closed the connection")
        data.extend(chunk)
    return bytes(data)

def _rpc_call(xid: int,program: int,version: int,procedure: int,args: bytes=b"")->bytes:
    header=struct.pack(">6I",xid,0,2,program,version,procedure)
    auth_null=struct.pack(">2I",0,0)
    return header+auth_null+auth_null+args

def _rpc_tcp(sock: socket.socket,payload: bytes)->bytes:
    sock.sendall(struct.pack(">I",0x80000000|len(payload))+payload)
    marker=struct.unpack(">I",_recv_exact(sock,4))[0]
    size=marker&0x7fffffff
    if not marker&0x80000000 or size>1024*1024: raise ValueError("Invalid or oversized RPC record")
    return _recv_exact(sock,size)

def _rpc_result_offset(data: bytes)->int:
    if len(data)<24: raise ValueError("Truncated RPC reply")
    _,message_type,reply_status=struct.unpack_from(">3I",data,0)
    if message_type!=1 or reply_status!=0: raise ValueError("RPC call was not accepted")
    verifier_length=struct.unpack_from(">I",data,16)[0]
    padded=(verifier_length+3)&~3
    accept_offset=20+padded
    if accept_offset+4>len(data): raise ValueError("Truncated RPC verifier")
    if struct.unpack_from(">I",data,accept_offset)[0]!=0: raise ValueError("RPC accept status is not SUCCESS")
    return accept_offset+4

def _parse_portmap_dump(data: bytes)->Dict[str,Dict[str,int]]:
    pos=_rpc_result_offset(data); result={}
    names={100000:"portmap",100003:"nfs",100005:"mountd",100021:"nlockmgr"}
    while pos+4<=len(data):
        present=struct.unpack_from(">I",data,pos)[0]; pos+=4
        if present==0: break
        if present!=1 or pos+16>len(data): raise ValueError("Malformed portmapper DUMP")
        program,version,protocol,port=struct.unpack_from(">4I",data,pos); pos+=16
        if program in names and 0<port<65536:
            row=result.setdefault(names[program],{})
            row[str(version)]=port; row["port"]=port; row["protocol"]=protocol
    return result

def _read_xdr_string(data: bytes,pos: int)->Tuple[str,int]:
    if pos+4>len(data): raise ValueError("Truncated XDR string")
    size=struct.unpack_from(">I",data,pos)[0]; pos+=4
    padded=(size+3)&~3
    if size>65536 or pos+padded>len(data): raise ValueError("Invalid XDR string size")
    return data[pos:pos+size].decode("utf-8",errors="replace"),pos+padded

def _parse_exports(data: bytes)->List[Dict[str,Any]]:
    pos=_rpc_result_offset(data); exports=[]
    while pos+4<=len(data):
        present=struct.unpack_from(">I",data,pos)[0]; pos+=4
        if present==0: break
        if present!=1: raise ValueError("Malformed export linked list")
        directory,pos=_read_xdr_string(data,pos)
        groups=[]
        while pos+4<=len(data):
            has_group=struct.unpack_from(">I",data,pos)[0]; pos+=4
            if has_group==0: break
            if has_group!=1: raise ValueError("Malformed export group list")
            group,pos=_read_xdr_string(data,pos); groups.append(group)
        exports.append({"path":directory,"allowed_clients":groups})
    return exports

class NFSEnumerator:
    DEFAULT_PORT=2049
    @staticmethod
    def check_open(ip: str,port: int=2049,timeout: float=3.0)->bool:
        try:
            with socket.create_connection((ip,port),timeout=timeout): return True
        except OSError: return False
    @staticmethod
    def rpc_portmap_dump(ip: str,timeout: float=5.0)->Dict[str,Any]:
        result={"open":False,"services":{}}
        try:
            with socket.create_connection((ip,111),timeout=timeout) as sock:
                sock.settimeout(timeout)
                reply=_rpc_tcp(sock,_rpc_call(0x53535031,100000,2,4))
            result["services"]=_parse_portmap_dump(reply); result["open"]=True
        except (OSError,ValueError,ConnectionError,struct.error): pass
        return result
    @staticmethod
    def mount_export(ip: str,port: int,timeout: float=5.0)->List[Dict[str,Any]]:
        try:
            with socket.create_connection((ip,port),timeout=timeout) as sock:
                sock.settimeout(timeout)
                reply=_rpc_tcp(sock,_rpc_call(0x53535032,100005,1,5))
            return _parse_exports(reply)
        except (OSError,ValueError,ConnectionError,struct.error): return []
    @staticmethod
    def scan_with_showmount(ip: str)->List[Dict[str,Any]]:
        exe=shutil.which("showmount")
        if not exe: return []
        try:
            proc=subprocess.run([exe,"-e",ip],capture_output=True,text=True,timeout=15,check=False)
        except (OSError,subprocess.TimeoutExpired): return []
        exports=[]
        for line in proc.stdout.splitlines():
            line=line.strip()
            if not line or line.lower().startswith("export list") or line.startswith("---"): continue
            parts=line.split()
            if parts: exports.append({"path":parts[0],"allowed_clients":parts[1:]})
        return exports
    @staticmethod
    def scan(ip: str)->Dict[str,Any]:
        result={"module":"nfs","target":ip,"open":False,"exports":[],"vulnerabilities":[]}
        if not NFSEnumerator.check_open(ip): return result
        result["open"]=True
        rpc=NFSEnumerator.rpc_portmap_dump(ip)
        mountd=rpc.get("services",{}).get("mountd",{})
        if isinstance(mountd,dict) and mountd.get("port") and mountd.get("protocol",6)==6:
            result["exports"]=NFSEnumerator.mount_export(ip,mountd["port"])
        if not result["exports"]: result["exports"]=NFSEnumerator.scan_with_showmount(ip)
        for export in result["exports"]:
            if "*" in export.get("allowed_clients",[]):
                result["vulnerabilities"].append({
                    "name":f"Wildcard client access listed for NFS export {export.get('path')}",
                    "severity":"MEDIUM","cve":"N/A",
                    "evidence":"Mountd listed a wildcard client. Read/write permissions were not established.",
                })
        return result
