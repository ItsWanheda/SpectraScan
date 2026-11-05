"""Protocol-service aggregator retaining a distinct result per port."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor,as_completed
from typing import Any,Dict,List
from . import database_enum,dns_zone,ldap_enum,mongodb_enum,nfs_enum,rdp_enum,redis_enum,rtsp_enum,sip_enum,smb_enum,smtp_enum,snmp_enum,vnc_enum

SERVICE_MAP={
 21:("ftp_banner",None),22:("ssh_banner",None),25:("smtp",smtp_enum.SMTPEnumerator.scan),
 53:("dns_zone",None),110:("pop3",None),139:("smb",smb_enum.SMBEnumerator.scan),
 143:("imap",None),161:("snmp",snmp_enum.SNMPEnumerator.scan),389:("ldap",ldap_enum.LDAPEnumerator.scan),
 445:("smb",smb_enum.SMBEnumerator.scan),514:("syslog",None),554:("rtsp",rtsp_enum.RTSPEnumerator.scan),
 636:("ldaps",ldap_enum.LDAPEnumerator.scan),1433:("mssql",database_enum.MSSQLEnumerator.scan),
 2049:("nfs",nfs_enum.NFSEnumerator.scan),3306:("mysql",database_enum.MySQLEnumerator.scan),
 3389:("rdp",rdp_enum.RDPEnumerator.scan),5060:("sip",sip_enum.SIPEnumerator.scan),
 5432:("postgresql",database_enum.PostgreSQLEnumerator.scan),5900:("vnc",vnc_enum.VNCEnumerator.scan),
 6379:("redis",redis_enum.RedisEnumerator.scan),27017:("mongodb",mongodb_enum.MongoDBEnumerator.scan)
}

def scan_port_with_service(ip: str,port: int,**kwargs: Any)->Dict[str,Any]:
    name,func=SERVICE_MAP.get(port,(None,None))
    if func is None: return {"module":name or "unknown","target":ip,"port":port,"skipped":True}
    try:
        if port in (161, 2049):
            return func(ip, **kwargs)
        return func(ip, port=port, **kwargs)
    except Exception as exc:
        return {"module":name,"target":ip,"port":port,"error":type(exc).__name__}

def deep_scan(ip: str,ports: List[int]=None,max_workers: int=5)->Dict[str,Any]:
    if isinstance(max_workers,bool) or not 1<=int(max_workers)<=32: raise ValueError("max_workers must be 1..32")
    selected=list(SERVICE_MAP) if ports is None else list(dict.fromkeys(int(p) for p in ports))
    result={"target":ip,"scans":{},"vulnerabilities":[]}
    targets=[p for p in selected if p in SERVICE_MAP and SERVICE_MAP[p][1] is not None]
    with ThreadPoolExecutor(max_workers=int(max_workers)) as pool:
        futures={pool.submit(scan_port_with_service,ip,p):p for p in targets}
        for future in as_completed(futures):
            port=futures[future]; name=SERVICE_MAP[port][0]; key=f"{name}:{port}"
            try: row=future.result()
            except Exception as exc: row={"module":name,"target":ip,"port":port,"error":type(exc).__name__}
            result["scans"][key]=row
            if isinstance(row,dict) and row.get("vulnerabilities"):
                result["vulnerabilities"].extend(row["vulnerabilities"])
    return result
