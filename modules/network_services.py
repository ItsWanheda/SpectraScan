"""
Network Services Aggregator
Single entrypoint for scanning all protocol modules.
"""
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import smb_enum, snmp_enum, ldap_enum, rdp_enum, smtp_enum
from . import dns_zone, nfs_enum, vnc_enum, redis_enum, mongodb_enum
from . import sip_enum, rtsp_enum, database_enum


# Map port -> module function
SERVICE_MAP = {
    21: ("ftp_banner", None),  # Already covered in main scanner
    22: ("ssh_banner", None),
    25: ("smtp", smtp_enum.SMTPEnumerator.scan),
    53: ("dns_zone", None),  # Needs domain
    110: ("pop3", None),
    139: ("smb", smb_enum.SMBEnumerator.scan),
    143: ("imap", None),
    161: ("snmp", None),  # Special - needs UDP, custom call
    389: ("ldap", ldap_enum.LDAPEnumerator.scan),
    445: ("smb", smb_enum.SMBEnumerator.scan),
    514: ("syslog", None),
    554: ("rtsp", rtsp_enum.RTSPEnumerator.scan),
    636: ("ldaps", ldap_enum.LDAPEnumerator.scan),
    1433: ("mssql", database_enum.MSSQLEnumerator.scan),
    2049: ("nfs", nfs_enum.NFSEnumerator.scan),
    3306: ("mysql", database_enum.MySQLEnumerator.scan),
    3389: ("rdp", rdp_enum.RDPEnumerator.scan),
    5060: ("sip", sip_enum.SIPEnumerator.scan),
    5432: ("postgresql", database_enum.PostgreSQLEnumerator.scan),
    5900: ("vnc", vnc_enum.VNCEnumerator.scan),
    6379: ("redis", redis_enum.RedisEnumerator.scan),
    27017: ("mongodb", mongodb_enum.MongoDBEnumerator.scan),
}


def scan_port_with_service(ip: str, port: int, **kwargs) -> Dict:
    """Dispatch scan to appropriate module based on port."""
    service_name, func = SERVICE_MAP.get(port, (None, None))
    if func:
        try:
            return func(ip, port=port, **kwargs)
        except Exception as e:
            return {"module": service_name, "error": str(e)}
    return {"module": service_name or "unknown", "skipped": True}


def deep_scan(ip: str, ports: List[int] = None, max_workers: int = 5) -> Dict:
    """Run all applicable service scans in parallel."""
    if ports is None:
        ports = list(SERVICE_MAP.keys())
    results = {"target": ip, "scans": {}, "vulnerabilities": []}

    scan_targets = [(ip, p) for p in ports if SERVICE_MAP.get(p, (None, None)) is not None]
    # Special handling for SNMP (UDP)
    snmp_targets = [(ip, p) for p in ports if p == 161]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for ip_t, port in scan_targets:
            service_name = SERVICE_MAP[port]
            futures[executor.submit(scan_port_with_service, ip_t, port)] = service_name

        for ip_t, port in snmp_targets:
            futures[executor.submit(snmp_enum.SNMPEnumerator.scan, ip_t)] = "snmp"

        for future in as_completed(futures):
            service_name = futures[future]
            try:
                r = future.result()
                results["scans"][service_name] = r
                if r.get("vulnerabilities"):
                    results["vulnerabilities"].extend(r["vulnerabilities"])
            except Exception as e:
                results["scans"][service_name] = {"error": str(e)}

    return results