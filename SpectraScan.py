#!/usr/bin/env python3
"""
SpectraScann - Optimized Edition
Features: SYN, UDP, OS Detection, SSL/TLS, HTTP Enum, Firewall Detection,
          Ping Sweep, ARP Scan, Proxy Support, IDS Evasion, Rate Limiting,
          Domain/IP/Phone/Email Scanning, EXIF Extraction, Link Sniffing.
"""
import socket
import concurrent.futures
import argparse
import sys
import time
import json
import random
import struct
import os
import logging
import ssl
import subprocess
import re
import csv
import ipaddress
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich import print as rprint
from rich.markdown import Markdown
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn

sys.path.append(os.path.join(os.path.dirname(__file__), "modules"))

# Initialize Rich Console
console = Console()

# ============== Configuration ==============
COMMON_PORTS = {
    21: ("FTP", "File Transfer Protocol"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Telnet"),
    25: ("SMTP", "Mail Server"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Web Server"),
    110: ("POP3", "Mail Retrieval"),
    143: ("IMAP", "Mail Access"),
    443: ("HTTPS", "Secure Web"),
    445: ("SMB", "SMB/CIFS"),
    993: ("IMAPS", "Secure IMAP"),
    995: ("POP3S", "Secure POP"),
    1433: ("MSSQL", "MS SQL Server"),
    1521: ("Oracle", "Oracle DB"),
    3306: ("MySQL", "MySQL Server"),
    3389: ("RDP", "Remote Desktop"),
    5432: ("PostgreSQL", "PostgreSQL"),
    5900: ("VNC", "VNC"),
    6379: ("Redis", "Redis"),
    8080: ("HTTP-Alt", "Alt HTTP"),
    8443: ("HTTPS-Alt", "Alt HTTPS"),
    27017: ("MongoDB", "MongoDB"),
}

VULNERABILITIES = {
    21: ["Anonymous FTP enabled", "FTP cleartext transmission"],
    22: ["SSH brute-force possible", "Outdated SSH version"],
    23: ["Telnet unencrypted", "No authentication required"],
    25: ["Open SMTP relay", "Mail server misconfiguration"],
    80: ["HTTP methods enabled", "Directory listing possible"],
    443: ["SSL/TLS vulnerabilities", "Outdated certificates"],
    445: ["SMB vulnerabilities", "EternalBlue (MS17-010)"],
    3306: ["MySQL exposed", "Default credentials possible"],
    3389: ["RDP vulnerabilities", "BlueKeep (CVE-2019-0708)"],
    8080: ["Proxy misconfiguration", "Debug endpoints exposed"],
}

TIMING_PROFILES = {
    "T0": {"threads": 1, "timeout": 5.0, "delay": 300, "name": "Paranoid"},
    "T1": {"threads": 5, "timeout": 3.0, "delay": 100, "name": "Sneaky"},
    "T2": {"threads": 10, "timeout": 2.0, "delay": 50, "name": "Polite"},
    "T3": {"threads": 50, "timeout": 1.0, "delay": 10, "name": "Normal"},
    "T4": {"threads": 100, "timeout": 0.5, "delay": 0, "name": "Aggressive"},
    "T5": {"threads": 200, "timeout": 0.2, "delay": 0, "name": "Insane"},
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "blog", "dev", "test", "api", "cdn",
    "smtp", "pop", "imap", "ssh", "vpn", "cloud", "backup", "staging",
    "demo", "old", "new",
]

HTTP_PATHS = [
    "/", "/admin", "/login", "/wp-admin", "/phpmyadmin", "/api", "/api-docs",
    "/swagger", "/console", "/manager", "/backup", "/wp-login.php",
    "/admin/login", "/administrator", "/.env", "/config", "/config.php",
    "/settings", "/dashboard", "/robots.txt", "/sitemap.xml", "/.git/config",
    "/.htaccess",
]

# Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ============== Report Manager ==============
class ReportManager:
    def __init__(self):
        self.report_dir = os.path.expanduser("~/.local/share/SpectraScan")
        os.makedirs(self.report_dir, exist_ok=True)
        self.current_file = None
        self.append_file = False

    def save_output(self):
        # In CLI mode, we might skip auto-prompting if not explicitly asked, 
        # but we keep the logic for consistency.
        pass 

    def write(self, text):
        # In CLI mode, we can just print to console directly
        print(text)

    def read_report(self):
        report_files = [f for f in os.listdir(self.report_dir) if f.startswith('SS-report')]
        if not report_files:
            print(f"{RED}No reports found.{RESET}")
            return
        print(f"\n{CYAN}[-] Files in {self.report_dir}:{RESET}")
        for i, f in enumerate(report_files):
            print(f"{GREEN}[{i+1}]{RESET} {f}")

        try:
            target_num = int(input(f"{CYAN}Enter number to read: {RESET}"))
            if 1 <= target_num <= len(report_files):
                file_path = os.path.join(self.report_dir, report_files[target_num-1])
                print(f"\n{BOLD}{RED}{file_path}{RESET}\n")
                with open(file_path, 'r') as f:
                    print(f.read())
            else:
                print(f"{RED}Invalid input.{RESET}")
        except ValueError:
            print(f"{RED}Invalid input.{RESET}")

    def delete_report(self):
        report_files = [f for f in os.listdir(self.report_dir) if f.startswith('SS-report')]
        if not report_files:
            print(f"{RED}No reports found.{RESET}")
            return
        print(f"\n{CYAN}[-] Files in {self.report_dir}:{RESET}")
        for i, f in enumerate(report_files):
            print(f"{GREEN}[{i+1}]{RESET} {f}")

        try:
            target_num = int(input(f"{CYAN}Enter number to delete: {RESET}"))
            if 1 <= target_num <= len(report_files):
                file_path = os.path.join(self.report_dir, report_files[target_num-1])
                confirm = input(f"{RED}Delete {file_path}? (y/N): {RESET}").lower()
                if confirm == 'y':
                    os.remove(file_path)
                    print(f"{GREEN}[+] Deleted.{RESET}")
                else:
                    print(f"{YELLOW}Cancelled.{RESET}")
            else:
                print(f"{RED}Invalid input.{RESET}")
        except ValueError:
            print(f"{RED}Invalid input.{RESET}")

# ============== Utility Functions ==============
def resolve_host(hostname: str) -> str:
    """Resolve hostname to IP"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f"{RED}[-] Error: Cannot resolve {hostname}")
        sys.exit(1)

def reverse_dns(ip: str) -> str:
    """Reverse DNS lookup"""
    try:
        return socket.gethostbyaddr(ip)
    except:
        return "Unknown"

def get_local_ip() -> str:
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def generate_decoys(count: int) -> list:
    """Generate random decoy IP addresses"""
    decoys = []
    for _ in range(count):
        ip_type = random.randint(1, 3)
        if ip_type == 1:
            decoy = f"10.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        elif ip_type == 2:
            decoy = f"172.{random.randint(16,31)}.{random.randint(1,255)}.{random.randint(1,255)}"
        else:
            decoy = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        decoys.append(decoy)
    return decoys

def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """Grab banner from service"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        probes = {
            22: b"SSH-2.0-OpenSSH_8.0\r\n",
            80: b"HEAD / HTTP/1.0\r\n\r\n",
            443: b"HEAD / HTTP/1.0\r\n\r\n",
        }
        if port in probes:
            sock.send(probes[port])
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner if banner else ""
    except:
        return ""

def identify_service(banner: str) -> Dict:
    """Identify service from banner"""
    if not banner:
        return {"type": "unknown", "version": "unknown"}
    signatures = {
        "SSH": ["SSH", "OpenSSH", "Dropbear"],
        "FTP": ["220", "FTP", "vsftpd", "ProFTPD"],
        "HTTP": ["HTTP", "Apache", "nginx", "IIS"],
        "MySQL": ["mysql", "MariaDB"],
        "Redis": ["REDIS", "-ERR"],
    }
    for service, sigs in signatures.items():
        for sig in sigs:
            if sig.lower() in banner.lower():
                ver = re.search(r"(\d+\.\d+(?:\.\d+)?)", banner)
                return {"type": service, "version": ver.group(1) if ver else "unknown"}
    return {"type": "unknown", "version": "unknown"}

def check_vulnerabilities(port: int, service: str, banner: str = "") -> List[Dict]:
    """Check for known vulnerabilities"""
    vulns = []
    if port in VULNERABILITIES:
        for vuln in VULNERABILITIES[port]:
            severity = (
                "HIGH"
                if any(k in vuln.lower() for k in ["unencrypted", "exposed", "vuln"])
                else "MEDIUM"
            )
            vulns.append(
                {
                    "port": port,
                    "service": service,
                    "vulnerability": vuln,
                    "severity": severity,
                    "cve": "N/A",
                }
            )
    return vulns

# ============== Rate Limiter ==============
class RateLimiter:
    __slots__ = ("pps", "delay", "last_request")
    
    def __init__(self, packets_per_second: int = 100):
        self.pps = packets_per_second
        self.delay = 1.0 / packets_per_second if packets_per_second > 0 else 0
        self.last_request = 0

    def wait(self):
        if self.delay > 0:
            elapsed = time.time() - self.last_request
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self.last_request = time.time()

# ============== SYN Scanner ==============
class SYNScan:
    __slots__ = ("is_admin",)
    
    def __init__(self):
        self.is_admin = os.geteuid() == 0 if hasattr(os, "geteuid") else False

    def create_packet(self, src_ip: str, dst_ip: str, dst_port: int) -> bytes:
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            40,
            random.randint(1, 65535),
            0,
            64,
            6,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            random.randint(1024, 65535),
            dst_port,
            random.randint(0, 4294967295),
            0,
            0x50,
            0x02,
            65535,
            0,
            0,
        )
        return ip_header + tcp_header

    def scan(self, target_ip: str, port: int, timeout: float = 2.0) -> str:
        if not self.is_admin:
            return "admin_required"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(timeout)
            packet = self.create_packet(get_local_ip(), target_ip, port)
            sock.sendto(packet, (target_ip, 0))
            data, _ = sock.recvfrom(1024)
            sock.close()
            tcp_flags = data[20 + 13]
            if tcp_flags & 0x12:
                return "open"
            elif tcp_flags & 0x14 or tcp_flags & 0x04:
                return "closed"
            return "filtered"
        except:
            return "error"

# ============== UDP Scanner ==============
class UDPScan:
    __slots__ = ("common_udp_ports",)
    
    def __init__(self):
        self.common_udp_ports = {
            53: ("DNS", "DNS Query"),
            67: ("DHCP", "DHCP Server"),
            68: ("DHCP", "DHCP Client"),
            69: ("TFTP", "Trivial FTP"),
            123: ("NTP", "Network Time Protocol"),
            161: ("SNMP", "Simple Network Management"),
            162: ("SNMPTRAP", "SNMP Trap"),
            389: ("LDAP", "Lightweight Directory Access"),
            500: ("ISAKMP", "Internet Security"),
            514: ("Syslog", "System Logging"),
            520: ("RIP", "Routing Information"),
            1194: ("OpenVPN", "VPN"),
            1701: ("L2TP", "Layer 2 Tunneling"),
            1812: ("RADIUS", "Authentication"),
            1813: ("RADIUS", "Accounting"),
            4500: ("IPSec", "NAT Traversal"),
        }

    def scan(self, target_ip: str, port: int, timeout: float = 3.0) -> Dict:
        result = {
            "port": port,
            "protocol": "udp",
            "state": "open|filtered",
            "service": self.common_udp_ports.get(port, ("unknown", "")),
            "info": self.common_udp_ports.get(port, ("unknown", "")),
        }
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            probes = {
                53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01",
                161: b"\x30\x00\x00\x00\x02\x01\x00\x04\x06public\xa0\x1f\x02\x01\x00\x02\x01\x00\x30\x14",
            }
            sock.sendto(probes.get(port, b"\x00"), (target_ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                result["state"] = "open"
                result["response"] = data.hex()[:100]
            except socket.timeout:
                result["state"] = "open|filtered"
            sock.close()
        except socket.error as e:
            result["state"] = "error"
            result["error"] = str(e)
        return result

# ============== OS Fingerprinting ==============
class OSFingerprint:
    @staticmethod
    def get_ttl(ip: str) -> Optional[int]:
        try:
            cmd = (
                ["ping", "-n", "1", "-w", "100", ip]
                if sys.platform == "win32"
                else ["ping", "-c", "1", "-W", "2", ip]
            )
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
            return int(match.group(1)) if match else None
        except:
            return None

    @staticmethod
    def detect_os(ip: str) -> Dict:
        result = {"os": "Unknown", "confidence": 0, "ttl": None, "details": []}
        ttl = OSFingerprint.get_ttl(ip)
        if ttl:
            result["ttl"] = ttl
            result["details"].append(f"TTL: {ttl}")
            if ttl <= 64:
                result["os"] = "Linux/Unix/MacOS"
                result["confidence"] = 70
            elif ttl <= 128:
                result["os"] = "Windows"
                result["confidence"] = 70
            else:
                result["os"] = "Network Device/Unix"
                result["confidence"] = 50
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 80))
            sock.close()
            response_time = time.time() - start
            result["details"].append(f"Response: {response_time*1000:.1f}ms")
            result["details"].append(
                "Fast response: Likely Linux/Unix"
                if response_time < 0.1
                else "Slow response: Possibly Windows"
            )
        except:
            pass
        return result

# ============== SSL/TLS Analyzer ==============
class SSLAnalyzer:
    @staticmethod
    def analyze(ip: str, port: int = 443, timeout: float = 5.0) -> Dict:
        result = {
            "supports_ssl": False,
            "versions": [],
            "cipher_suites": [],
            "certificate": {},
            "vulnerabilities": [],
            "grade": "N/A",
        }
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    result["supports_ssl"] = True
                    result["versions"] = ssock.version()
                    if ssock.cipher():
                        result["certificate"] = {"cipher": ssock.cipher()}
                    version = ssock.version()
                    if version in ["SSLv2", "SSLv3"]:
                        result["vulnerabilities"].append(
                            f"Deprecated {version} protocol"
                        )
                    result["grade"] = (
                        "A+"
                        if "TLSv1.3" in str(result["versions"])
                        else (
                            "A"
                            if "TLSv1.2" in str(result["versions"])
                            else "C" if "TLSv1.0" in str(result["versions"]) else "F"
                        )
                    )
        except:
            pass
        return result

# ============== HTTP Enumerator ==============
class HTTPEnumerator:
    @staticmethod
    def get_headers(ip: str, port: int = 80, use_ssl: bool = False) -> Dict:
        result = {
            "server": "Unknown",
            "content_type": None,
            "security_headers": {},
            "methods": [],
            "status_code": None,
        }
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{ip}:{port}/"
        try:
            req = Request(url, method="GET")
            req.add_header("User-Agent", "Mozilla/5.0 (Port Scanner)")
            with urlopen(req, timeout=5) as response:
                result["status_code"] = response.status
                result["server"] = response.headers.get("Server", "Unknown")
                result["content_type"] = response.headers.get("Content-Type")
                result["security_headers"] = {
                    "X-Frame-Options": response.headers.get("X-Frame-Options"),
                    "X-Content-Type": response.headers.get("X-Content-Type-Options"),
                    "CSP": response.headers.get("Content-Security-Policy"),
                    "HSTS": response.headers.get("Strict-Transport-Security"),
                }
        except:
            pass
        return result

    @staticmethod
    def check_methods(ip: str, port: int = 80, use_ssl: bool = False) -> List[str]:
        methods = []
        protocol = "https" if use_ssl else "http"
        url = f"{protocol}://{ip}:{port}/"
        http_methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
        for method in http_methods:
            try:
                req = Request(url, method=method)
                req.add_header("User-Agent", "Port Scanner")
                with urlopen(req, timeout=3) as response:
                    if response.status and response.status < 400:
                        methods.append(method)
            except:
                pass
        return methods

    @staticmethod
    def enumerate_paths(ip: str, port: int = 80, use_ssl: bool = False) -> List[Dict]:
        found = []
        protocol = "https" if use_ssl else "http"
        for path in HTTP_PATHS:
            url = f"{protocol}://{ip}:{port}{path}"
            try:
                req = Request(url, method="GET")
                req.add_header("User-Agent", "Port Scanner")
                with urlopen(req, timeout=3) as response:
                    found.append(
                        {
                            "path": path,
                            "status": response.status,
                            "size": response.headers.get("Content-Length", "Unknown"),
                        }
                    )
            except HTTPError as e:
                found.append({"path": path, "status": e.code, "size": 0})
            except:
                pass
        return found

# ============== DNS Enumerator ==============
class DNSEnumerator:
    @staticmethod
    def get_records(domain: str) -> Dict:
        result = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
        try:
            import dns.resolver
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    for rdata in answers:
                        if rtype == "MX":
                            result["MX"].append(
                                f"{rdata.exchange} (pref: {rdata.preference})"
                            )
                        else:
                            result[rtype].append(str(rdata))
                except:
                    pass
        except ImportError:
            try:
                ip = socket.gethostbyname(domain)
                result["A"].append(ip)
            except:
                pass
        except:
            pass
        return result

    @staticmethod
    def enumerate_subdomains(domain: str, wordlist: List[str] = None) -> List[str]:
        found = []
        subdomains = wordlist or COMMON_SUBDOMAINS
        for sub in subdomains:
            hostname = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(hostname)
                found.append({"subdomain": hostname, "ip": ip})
            except:
                pass
        return found

# ============== Service Enumerator ==============
class ServiceEnumerator:
    @staticmethod
    def enumerate_ftp(ip: str, port: int = 21) -> Dict:
        result = {"anonymous": False, "features": [], "version": None}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            result["version"] = banner
            sock.send(b"USER anonymous\r\n")
            resp = sock.recv(1024).decode("utf-8", errors="ignore")
            if "331" in resp:
                sock.send(b"PASS anonymous@example.com\r\n")
                resp = sock.recv(1024).decode("utf-8", errors="ignore")
                if "230" in resp:
                    result["anonymous"] = True
            sock.send(b"FEAT\r\n")
            resp = sock.recv(4096).decode("utf-8", errors="ignore")
            if "211" in resp:
                result["features"] = resp.split("\n")[1:-1]
            sock.close()
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def enumerate_ssh(ip: str, port: int = 22) -> Dict:
        result = {"version": None, "algorithms": {}}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
            result["version"] = banner
            if "OpenSSH" in banner:
                match = re.search(r"OpenSSH_([\d.]+)", banner)
                if match:
                    result["version"] = f"OpenSSH {match.group(1)}"
            sock.close()
        except Exception as e:
            result["error"] = str(e)
        return result

    @staticmethod
    def enumerate_smb(ip: str, port: int = 445) -> Dict:
        result = {"version": None, "signing": None, "shares": []}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.close()
        except:
            pass
        return result

# ============== Firewall Detector ==============
class FirewallDetector:
    @staticmethod
    def detect(ip: str, port: int = 80) -> Dict:
        result = {"has_firewall": "Unknown", "evidence": [], "stealth_score": 0}
        try:
            if sys.platform == "win32":
                cmd = ["ping", "-n", "1", "-w", "100", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            if "TTL=" in output or "ttl=" in output:
                result["evidence"].append("Host responds to ICMP")
            else:
                result["evidence"].append("No ICMP response - possible firewall")
                result["stealth_score"] += 30
        except:
            result["evidence"].append("ICMP blocked - likely firewall")
            result["stealth_score"] += 40
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.close()
            result["evidence"].append("TCP connection successful")
        except:
            result["evidence"].append("TCP connection blocked")
            result["stealth_score"] += 20
        if result["stealth_score"] >= 50:
            result["has_firewall"] = "Likely"
        elif result["stealth_score"] >= 30:
            result["has_firewall"] = "Possible"
        else:
            result["has_firewall"] = "Unlikely"
        return result

# ============== Ping Sweep ==============
class PingSweep:
    @staticmethod
    def sweep(network: str, timeout: float = 1.0) -> List[Dict]:
        hosts = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            print(f"{CYAN}[*] Scanning {network} for live hosts...")
            def ping_host(ip):
                try:
                    cmd = (
                        ["ping", "-n", "1", "-w", str(int(timeout * 1000)), str(ip)]
                        if sys.platform == "win32"
                        else ["ping", "-c", "1", "-W", str(int(timeout)), str(ip)]
                    )
                    result = subprocess.run(
                        cmd, capture_output=True, timeout=timeout + 1
                    )
                    if result.returncode == 0:
                        return {"ip": str(ip), "alive": True}
                except:
                    pass
                return {"ip": str(ip), "alive": False}
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(ping_host, ip) for ip in net.hosts()]
                for future in concurrent.futures.as_completed(futures):
                    res = future.result()
                    if res["alive"]:
                        hosts.append(res)
                        print(f"{GREEN}[+] Host found: {res['ip']}{RESET}")
        except Exception as e:
            print(f"{RED}[-] Error: {e}{RESET}")
        return hosts

# ============== ARP Scanner ==============
class ARPScanner:
    @staticmethod
    def scan(network: str) -> List[Dict]:
        hosts = []
        try:
            cmd = ["arp", "-a"] if sys.platform == "win32" else ["arp", "-a", "-n"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            for line in output.split("\n"):
                match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+(\w+)", line, re.IGNORECASE
                )
                if match:
                    ip, mac, iface = match.groups()
                    if ip.startswith(network.split(".")):
                        hosts.append({"ip": ip, "mac": mac, "interface": iface})
        except Exception as e:
            print(f"{RED}[-] ARP scan error: {e}{RESET}")
        return hosts

# ============== Traceroute ==============
def traceroute(target: str, max_hops: int = 30) -> List[Dict]:
    hops = []
    print(f"{CYAN}[*] Traceroute to {target}...")
    for ttl in range(1, max_hops + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(b"traceroute", (target, 33434 + ttl))
            data, addr = sock.recvfrom(512)
            hops.append({"ttl": ttl, "ip": addr, "hostname": reverse_dns(addr)})
            sock.close()
            if addr == target:
                break
        except socket.timeout:
            hops.append({"ttl": ttl, "ip": "*", "hostname": "Timeout"})
        except:
            break
    return hops

# ============== Main Port Scanner ==============
class PortScanner:
    __slots__ = (
        "target",
        "timeout",
        "threads",
        "scan_type",
        "timing",
        "ports",
        "decoys",
        "check_vulns",
        "rate_limit",
        "resolved_ip",
        "results",
        "vulnerabilities",
        "start_time",
        "rate_limiter",
    )
    
    def __init__(self, target: str, **kwargs):
        self.target = target
        self.timeout = kwargs.get("timeout", 1.0)
        self.threads = kwargs.get("threads", 100)
        self.scan_type = kwargs.get("scan_type", "tcp")
        self.timing = kwargs.get("timing", "T3")
        self.ports = kwargs.get("ports", list(COMMON_PORTS.keys()))
        self.decoys = kwargs.get("decoys", [])
        self.check_vulns = kwargs.get("check_vulns", False)
        self.rate_limit = kwargs.get("rate_limit", 0)
        self.resolved_ip = None
        self.results = []
        self.vulnerabilities = []
        self.start_time = None
        self.rate_limiter = RateLimiter(self.rate_limit) if self.rate_limit else None
        if self.timing in TIMING_PROFILES:
            profile = TIMING_PROFILES[self.timing]
            self.threads = profile["threads"]
            self.timeout = profile["timeout"]

    def initialize(self):
        print(f"\n{BOLD}{CYAN}{'='*60}")
        print(f"{BOLD}{CYAN}[*] SpectraScan - Enhanced Edition")
        print(f"{CYAN}{'='*60}{RESET}")
        self.resolved_ip = resolve_host(self.target)
        hostname = reverse_dns(self.resolved_ip)
        print(f"{CYAN}[*] Target: {self.target} ({self.resolved_ip})")
        print(f"[*] Hostname: {hostname}")
        print(f"[*] Scan Type: {self.scan_type.upper()}")
        print(f"[*] Ports: {len(self.ports)}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Timing: {self.timing} ({TIMING_PROFILES[self.timing]['name']})")
        if self.decoys:
            print(f"{YELLOW}[*] Decoys: {len(self.decoys)} IPs active")
        if self.rate_limit:
            print(f"{YELLOW}[*] Rate Limit: {self.rate_limit} pps")
        print(f"{CYAN}{'='*60}{RESET}\n")

    def scan_port(self, port: int) -> Dict:
        if self.rate_limiter:
            self.rate_limiter.wait()
        result = {
            "port": port,
            "protocol": "tcp",
            "state": "closed",
            "service": COMMON_PORTS.get(port, ("unknown", "")),
            "description": COMMON_PORTS.get(port, ("unknown", "")),
            "banner": "",
            "version_info": {"type": "unknown", "version": "unknown"},
            "vulnerabilities": [],
        }
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if self.decoys:
                decoy = random.choice(self.decoys)
                try:
                    sock.bind((decoy, 0))
                except:
                    pass
            if sock.connect_ex((self.resolved_ip, port)) == 0:
                result["state"] = "open"
                banner = grab_banner(self.resolved_ip, port, self.timeout)
                result["banner"] = banner
                result["version_info"] = identify_service(banner)
                if self.check_vulns:
                    vulns = check_vulnerabilities(port, result["service"], banner)
                    if vulns:
                        result["vulnerabilities"] = vulns
                        self.vulnerabilities.extend(vulns)
            sock.close()
        except socket.timeout:
            result["state"] = "filtered"
        except socket.error:
            result["state"] = "error"
        return result

    def scan(self) -> List[Dict]:
        self.start_time = time.time()
        print(f"{CYAN}[*] Spectra is scanning...\n")
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.threads
        ) as executor:
            futures = {
                executor.submit(self.scan_port, port): port for port in self.ports
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result["state"] == "open":
                    self.results.append(result)
                    self._print_result(result)
        return self.results

    def _print_result(self, result: Dict):
        vuln_count = len(result.get("vulnerabilities", []))
        vuln_str = f" {RED}[!]{vuln_count} vulns{RESET}" if vuln_count else ""
        banner = result.get("banner", "") or ""
        banner_display = banner[:50] if len(banner) > 50 else banner
        print(
            f"{GREEN}[+] Port {result['port']:>5}/tcp  "
            f"{result['state']:<10} {result['service']:<12} "
            f"{CYAN}| {banner_display}{vuln_str}{RESET}"
        )

    def print_summary(self):
        duration = time.time() - self.start_time
        print(f"\n{CYAN}{'='*60}")
        print(f"{GREEN}[✓] Scan completed in {duration:.2f} seconds")
        print(f"[+] Found {len(self.results)} open ports")
        if self.results:
            print(f"\n{YELLOW}Open Ports Summary:{RESET}")
            print(f"{'Port':<10}{'Service':<15}{'State':<10}{'Version'}")
            print(f"{'-'*45}")
            for r in sorted(self.results, key=lambda x: x["port"]):
                version = r.get("version_info", {}).get("version", "N/A")
                print(f"{r['port']:<10}{r['service']:<15}{r['state']:<10}{version}")
        if self.vulnerabilities:
            print(
                f"\n{RED}[!] Found {len(self.vulnerabilities)} vulnerabilities:{RESET}"
            )
            for v in self.vulnerabilities:
                if v['severity'] == "HIGH":
                    sev = f"[{RED}{v['severity']}{RESET}]"
                else:
                    sev = f"[{YELLOW}{v['severity']}{RESET}]"
                
                print(
                    f"  {RED}•{RESET} Port {v['port']} ({v['service']}): {v['vulnerability']} {sev}"
                )
        print(f"{CYAN}{'='*60}{RESET}")

    def get_results(self) -> Dict:
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "scan_type": self.scan_type,
            "timestamp": datetime.now().isoformat(),
            "duration": time.time() - self.start_time,
            "open_ports": self.results,
            "vulnerabilities": self.vulnerabilities,
        }

    def export_json(self, filename: str):
        with open(filename, "w") as f:
            json.dump(self.get_results(), f, indent=2, default=str)
        print(f"{GREEN}[+] JSON report saved: {filename}")

    def export_html(self, filename: str):
        results = self.get_results()
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>SpectraScan Report - {results['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .summary {{ background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        table {{ width:            <tr><th>Port</th><th>Service</th><th>State</th><th>Banner</th></tr>"""
        for port in results["open_ports"]:
            banner = port.get("banner", "") or "N/A"
            html += f"<tr><td>{port['port']}</td><td>{port['service']}</td><td class='open'>{port['state']}</td><td>{banner[:50]}</td></tr>"
        html += """</table>
    </div>
</body>
</html>"""
        with open(filename, "w") as f:
            f.write(html)
        print(f"{GREEN}[+] HTML report saved: {filename}")

    def export_csv(self, filename: str):
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["Port", "Protocol", "State", "Service", "Banner", "Vulnerabilities"]
            )
            for port in self.results:
                banner = port.get("banner", "") or "None"
                vulns = (
                    "; ".join(
                        [v["vulnerability"] for v in port.get("vulnerabilities", [])]
                    )
                    or "None"
                )
                writer.writerow(
                    [
                        port["port"],
                        "tcp",
                        port["state"],
                        port["service"],
                        banner[:50],
                        vulns,
                    ]
                )
        print(f"{GREEN}[+] CSV report saved: {filename}")

# ============== Network Scanner ==============
class NetworkScanner:
    @staticmethod
    def scan_network(network: str, ports: List[int] = None, **kwargs) -> List[Dict]:
        try:
            net = ipaddress.ip_network(network, strict=False)
            print(f"{CYAN}[*] Spectra is Scanning network: {network}")
            print(f"[*] Hosts: {net.num_addresses - 2}")
            results = []
            for ip in net.hosts():
                ip_str = str(ip)
                scanner = PortScanner(
                    ip_str, ports=ports or list(COMMON_PORTS.keys()), **kwargs
                )
                scanner.resolved_ip = ip_str
                scanner.scan()
                if scanner.results:
                    results.append(
                        {
                            "ip": ip_str,
                            "hostname": reverse_dns(ip_str),
                            "ports": scanner.results,
                        }
                    )
                    print(f"{GREEN}[+] {ip_str}: {len(scanner.results)} open ports")
            return results
        except ValueError as e:
            print(f"{RED}[-] Invalid network: {e}")
            return []

# ============== Integrated Modules ==============
class DomainScanner:
    """Integrates SpectraScan Domain Scanner features"""
    @staticmethod
    def scan(domain: str, report_manager: ReportManager):
        report_manager.write(f"\n-----DOMAIN SCAN OF {domain}-----\n\n[*] ADMIN INFO \n-------------------------------------------------------------------------------")

        # Spectra
        report_manager.write("\n[*] ADMIN INFO ")
        try:
            # Try 'Spectra' first, then fall back if needed
            result = subprocess.run(["Spectra", domain], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                report_manager.write(result.stdout)
            else:
                report_manager.write(f"[-] Spectra command failed: {result.stderr}")
        except FileNotFoundError:
            report_manager.write("[-] 'Spectra' command not found. Install Git Bash and run 'pacman -S whois' in Git Bash.")
        except Exception as e:
            report_manager.write(f"Error running Spectra: {e}")

        report_manager.write("\n[*] DNS LOOKUP\n-------------------------------------------------------------------------------")

        # DNS Lookup via API (Fallback if curl fails)
        try:
            result = subprocess.run(["curl", "-s", f"https://api.hackertarget.com/dnslookup/?q={domain}"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                report_manager.write(result.stdout)
            else:
                # Fallback to nslookup (Windows built-in)
                report_manager.write("[*] Falling back to nslookup (Windows built-in tool)\n")
                result = subprocess.run(["nslookup", domain], capture_output=True, text=True, timeout=10)
                report_manager.write(result.stdout)
        except FileNotFoundError:
            report_manager.write("[-] 'curl' not found. Using nslookup fallback.\n")
            try:
                result = subprocess.run(["nslookup", domain], capture_output=True, text=True, timeout=10)
                report_manager.write(result.stdout)
            except Exception as e:
                report_manager.write(f"Error with nslookup: {e}")
        except Exception as e:
            report_manager.write(f"Error with DNS lookup API: {e}")

        # Host command (Replaced with nslookup for Windows compatibility)
        report_manager.write("\n[*] NSLOOKUP (Windows Equivalent of 'host')\n-------------------------------------------------------------------------------")
        try:
            result = subprocess.run(["nslookup", domain], capture_output=True, text=True, timeout=10)
            report_manager.write(result.stdout)
        except Exception as e:
            report_manager.write(f"Error running nslookup: {e}")

        report_manager.write("-------------------------------------------------------------------------------\n[*] DONE")

class IPScanner:
    """Integrates SpectraScan IP Scanner features"""
    @staticmethod
    def scan(ip: str, report_manager: ReportManager):
        report_manager.write(f"\n-----IP SCAN OF {ip}-----\n")

        # GeoIP
        report_manager.write("[*] LOCALISATION")
        try:
            result = subprocess.run(["curl", "-s", f"https://api.hackertarget.com/geoip/?q={ip}"], capture_output=True, text=True)
            report_manager.write(result.stdout)
        except Exception as e:
            report_manager.write(f"Error with GeoIP: {e}")
        # WHOIS
        report_manager.write("\n[*] ADMIN INFO")
        try:
            result = subprocess.run(["Spectra", ip], capture_output=True, text=True)
            report_manager.write(result.stdout)
        except Exception as e:
            report_manager.write(f"Error running Spectra: {e}")
        # Shodan    
        report_manager.write("\n[*] SHODAN RESULTS")
        try:
            import shodan
            api = shodan.Shodan("mWFf82jgCVnFpkl9s1Y9Q4dQTNAam7w5")  # Replace with your actual API key
            result = api.host(ip)
            report_manager.write(f"Open Ports: {len(result.get('ports', []))}")
            for port in result.get('ports', []):
                report_manager.write(f"  Port {port}: {result.get('data', [{}]).get('product', 'Unknown')}")
        except ImportError:
            report_manager.write("Shodan Python library not found. Install with: pip install shodan")
        except Exception as e:
            report_manager.write(f"Error with Shodan: {e}")

        report_manager.write("\n[*] DONE")

class PhoneScanner:
    """Integrates SpectraScan Phone Scanner features"""
    @staticmethod
    def scan(phone: str, report_manager: ReportManager):
        report_manager.write(f"\nScan of {phone}\n")
        report_manager.write("Gathering Information...")
        report_manager.write(f"\n[*] PHONE {phone}")
        report_manager.write("-------------------------------------------------------------------------------")

        # Uses the external python script from the original codebase
        script_path = os.path.join(os.path.dirname(__file__), "modules", "phone_scanner.py")
        if os.path.exists(script_path):
            try:
                result = subprocess.run(["python3", script_path, phone], capture_output=True, text=True)
                report_manager.write(result.stdout)
                if result.stderr:
                    report_manager.write(f"Stderr: {result.stderr}")
            except Exception as e:
                report_manager.write(f"Error running phone scanner: {e}")
        else:
            report_manager.write("Phone scanner module not found.")

        report_manager.write("\n[*] DONE")

class EmailScanner:
    """Integrates SpectraScan Email Scanner features"""
    @staticmethod
    def scan(email: str, report_manager: ReportManager):
        report_manager.write(f"\n[*] Gathering informations for {email}...")
        try:
            result = subprocess.run(["curl", "-s", f"https://emailrep.io/{email}"], capture_output=True, text=True)
            json_data = json.loads(result.stdout)

            report_manager.write(f"\n_____FULL REPORT_____")
            report_manager.write(f"-Email: {email}")
            report_manager.write(f"-Suspicious: {json_data.get('suspicious')}")
            report_manager.write(f"-Reputation: {json_data.get('reputation')}")
            report_manager.write(f"-Blacklisted: {json_data.get('details', {}).get('blacklisted')}")
            report_manager.write(f"-Malicious Activity: {json_data.get('details', {}).get('malicious_activity')}")
            report_manager.write(f"-Data Breach: {json_data.get('details', {}).get('data_breach')}")
            report_manager.write(f"-First Seen: {json_data.get('details', {}).get('first_seen')}")
            report_manager.write(f"-Last Seen: {json_data.get('details', {}).get('last_seen')}")
            report_manager.write(f"-Domain Exists: {json_data.get('details', {}).get('domain_exists')}")
            report_manager.write(f"-Free Provider: {json_data.get('details', {}).get('free_provider')}")
            report_manager.write(f"-Disposable: {json_data.get('details', {}).get('disposable')}")
            report_manager.write(f"-Deliverable: {json_data.get('details', {}).get('deliverable')}")
            report_manager.write(f"-Spoofable: {json_data.get('details', {}).get('spoofable')}")

        except Exception as e:
            report_manager.write(f"Error scraping emailrep: {e}")
        report_manager.write("\n[*] DONE")

class ImageScanner:
    """Integrates SpectraScan Image EXIF Scanner features"""
    @staticmethod
    def scan(image_path: str, report_manager: ReportManager):
        report_manager.write(f"\nEXIF data from: {image_path}")
        try:
            # Try exiv2 first, then exiftool
            if os.path.exists("/usr/bin/exiv2"):
                result = subprocess.run(["exiv2", image_path], capture_output=True, text=True)
                report_manager.write(result.stdout)
            elif os.path.exists("/usr/bin/exiftool"):
                result = subprocess.run(["exiftool", image_path], capture_output=True, text=True)
                report_manager.write(result.stdout)
            else:
                report_manager.write("No EXIF tool found (exiv2 or exiftool required).")
        except Exception as e:
            report_manager.write(f"Error reading EXIF: {e}")
        report_manager.write("\n[*] DONE")

class LinkScanner:
    """Integrates SpectraScann Link Sniffing features"""
    @staticmethod
    def scan(domain: str, report_manager: ReportManager):
        report_manager.write(f"\n__________Link Sniffing__________\n")
        report_manager.write(f"[*] SNIFFING LINKS for {domain}")
        report_manager.write("-------------------------------------------------------------------------------")
        try:
            result = subprocess.run(["curl", "-s", f"https://api.hackertarget.com/pagelinks/?q={domain}"], capture_output=True, text=True)
            report_manager.write(result.stdout)
        except Exception as e:
            report_manager.write(f"Error with link sniffing: {e}")
        report_manager.write("\n[*] DONE")

class CriminalScanner:
    """Integrates SpectraScan Criminal Scanner features"""
    @staticmethod
    def scan(first_name: str, last_name: str, state: str, city: str, report_manager: ReportManager):
        if state:
            state = f"{state}."
        link = f"https://{state}staterecords.org/search.php?firstname={first_name}&lastname={last_name}&city={city}"
        report_manager.write(f"\n[*] Generating Link...")
        report_manager.write(f"\n\nCTRL + click on this link to get your report: [{link}]")
        report_manager.write("\n[*] DONE")

# ============== CLI ==============
def print_banner():
    """Prints the SpectraScan Title Banner"""
    banner_text = """
    ================================================
             SPECTRASCAN - ENHANCED EDITION
    ================================================
    """
    console.print(Panel(banner_text, border_style="cyan", style="bold cyan"))
    console.print("[*] Initializing SpectraScan Core...", style="green")
    time.sleep(0.5)
    console.print("[+] Core Loaded. Awaiting Input.\n", style="green")

def hacker_input(prompt_text: str, default: str = "") -> str:
    """Simulates a terminal input with nice formatting"""
    if default:
        prompt = f"{CYAN}root@spectra:~#{RESET} {prompt_text} [{default}]: "
    else:
        prompt = f"{CYAN}root@spectra:~#{RESET} {prompt_text}: "
    
    user_input = input(prompt).strip()
    return user_input if user_input else default

def run_port_scan_cli():
    """Interactive Port Scan Menu"""
    console.print("\n[bold cyan]--- PORT SCANNER MODULE ---[/bold cyan]")
    target = hacker_input("Enter Target IP or Hostname")
    if not target:
        console.print("[!] Target required. Returning to menu.", style="red")
        return

    scan_type = Prompt.ask("Scan Type", choices=["tcp", "syn", "udp"], default="tcp")
    timing = Prompt.ask("Timing Profile", choices=["T0", "T1", "T2", "T3", "T4", "T5"], default="T3")
    
    ports_input = hacker_input("Enter Ports (comma-separated, e.g., 80,443,8080) or 'all' for full scan", "common")
    if ports_input.lower() == "all":
        ports = list(range(1, 65536))
    elif ports_input.lower() == "common":
        ports = list(COMMON_PORTS.keys())
    else:
        try:
            ports = [int(p.strip()) for p in ports_input.split(",")]
        except ValueError:
            console.print("[!] Invalid port format. Returning to menu.", style="red")
            return

    check_vulns = Confirm.ask("Check for Vulnerabilities?", default=False)
    
    console.print(f"\n[+]Spectra Starting Scan on {target}...", style="bold yellow")
    
    kwargs = {
        "timeout": 1.0,
        "threads": 50,
        "scan_type": scan_type,
        "timing": timing,
        "ports": ports,
        "decoys": [],
        "check_vulns": check_vulns,
        "rate_limit": 0,
    }
    
    scanner = PortScanner(target, **kwargs)
    scanner.initialize()
    scanner.scan()
    scanner.print_summary()
    
    # Export options
    if scanner.results:
        export = Confirm.ask("Export Results?", default=True)
        if export:
            fmt = Prompt.ask("Format", choices=["json", "html", "csv"], default="json")
            filename = hacker_input("Filename (without extension)", "scan_report")
            full_path = f"{filename}.{fmt}"
            if fmt == "json":
                scanner.export_json(full_path)
            elif fmt == "html":
                scanner.export_html(full_path)
            elif fmt == "csv":
                scanner.export_csv(full_path)

def run_other_scanners():
    """Interactive menu for Domain, IP, Email, etc."""
    console.print("\n[bold cyan]--- ADVANCED MODULES ---[/bold cyan]")
    mode = Prompt.ask("Select Module", choices=[
        "domain", "ip", "phone", "email", "image", "link", "criminal", "reports"
    ])
    
    if mode == "domain":
        domain = hacker_input("Enter Domain")
        if domain:
            DomainScanner.scan(domain, ReportManager())
            
    elif mode == "ip":
        ip = hacker_input("Enter IP Address")
        if ip:
            IPScanner.scan(ip, ReportManager())
            
    elif mode == "phone":
        phone = hacker_input("Enter Phone Number")
        if phone:
            PhoneScanner.scan(phone, ReportManager())
            
    elif mode == "email":
        email = hacker_input("Enter Email Address")
        if email:
            EmailScanner.scan(email, ReportManager())
            
    elif mode == "image":
        path = hacker_input("Enter Image Path")
        if path:
            ImageScanner.scan(path, ReportManager())
            
    elif mode == "link":
        domain = hacker_input("Enter Domain for Link Sniffing")
        if domain:
            LinkScanner.scan(domain, ReportManager())
            
    elif mode == "criminal":
        first = hacker_input("First Name")
        last = hacker_input("Last Name")
        state = hacker_input("State (Optional)")
        city = hacker_input("City")
        CriminalScanner.scan(first, last, state, city, ReportManager())
        
    elif mode == "reports":
        action = Prompt.ask("Action", choices=["read", "delete"])
        rm = ReportManager()
        if action == "read":
            rm.read_report()
        elif action == "delete":
            rm.delete_report()

def main():
    # Check for legacy CLI args first for backward compatibility
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="SpectraScan Legacy CLI")
        parser.add_argument("-t", "--target", help="Target")
        parser.add_argument("-d", "--domain", help="Domain")
        parser.add_argument("-i", "--ip", help="IP")
        args, _ = parser.parse_known_args()
        
        if args.target:
            # Fallback to old style if args are provided
            scanner = PortScanner(args.target)
            scanner.initialize()
            scanner.scan()
            scanner.print_summary()
            return

    # CLI
    print_banner()
    
    while True:
        console.print("\n[bold green]1.[/bold green] Port Scanner")
        console.print("[bold green]2.[/bold green] Advanced Modules (Domain/IP/Email/etc)")
        console.print("[bold red]3.[/bold red] Exit")
        
        choice = input(f"{CYAN}root@spectra:~#{RESET} Select Option: ").strip()
        
        if choice == "1":
            run_port_scan_cli()
        elif choice == "2":
            run_other_scanners()
        elif choice == "3":
            console.print("[*] Exiting SpectraScan. Stay Anonymous.", style="yellow")
            break
        else:
            console.print("[!] Invalid Option. Please try again.", style="red")

if __name__ == "__main__":
    main()