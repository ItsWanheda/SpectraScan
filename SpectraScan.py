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
import html
import urllib.parse
from functools import wraps
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
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

PORT_DESCRIPTIONS = {
    21: "File Transfer Protocol",
    22: "Secure Shell",
    23: "Telnet",
    25: "Mail Server",
    53: "Domain Name System",
    80: "Web Server",
    110: "Mail Retrieval",
    143: "Mail Access",
    443: "Secure Web",
    445: "SMB/CIFS",
    993: "Secure IMAP",
    995: "Secure POP",
    1433: "MS SQL Server",
    1521: "Oracle DB",
    3306: "MySQL Server",
    3389: "Remote Desktop",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "Alt HTTP",
    8443: "Alt HTTPS",
    27017: "MongoDB",
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
def normalize_target(target: str) -> str:
    """Normalize an IP, CIDR, hostname, host:port, or HTTP(S) URL."""
    if not target:
        return ""

    target = target.strip()
    target = target.strip("\"'")

    if not target:
        return ""

    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass

    if "://" in target:
        try:
            parsed = urllib.parse.urlparse(target)
            if parsed.hostname:
                return parsed.hostname
        except Exception:
            pass

    try:
        if target.startswith("["):
            closing = target.find("]")
            if closing != -1:
                return target[1:closing]

        parsed = urllib.parse.urlparse("//" + target)
        if parsed.hostname:
            return parsed.hostname
    except Exception:
        pass

    return target.rstrip("/")


def resolve_host(hostname: str) -> str:
    """Resolve a single host/IP. CIDR networks are handled separately."""
    target = normalize_target(hostname)

    if not target:
        raise ValueError("Target cannot be empty")

    try:
        network = ipaddress.ip_network(target, strict=False)
        raise ValueError(f"CIDR network detected: {network}")
    except ValueError as exc:
        if "CIDR network detected" in str(exc):
            raise

    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve target: {target}") from exc

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
        # Fall back to TCP connect scan if we don't have raw socket privileges
        if not self.is_admin:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                rc = sock.connect_ex((target_ip, port))
                sock.close()
                if rc == 0:
                    return "open"
                elif rc in (111, 10061):  # ECONNREFUSED
                    return "closed"
                else:
                    return "filtered"
            except socket.timeout:
                return "filtered"
            except:
                return "error"
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
        svc_tuple = self.common_udp_ports.get(port, ("unknown", ""))
        result = {
            "port": port,
            "protocol": "udp",
            "state": "open|filtered",
            "service": svc_tuple,
            "info": svc_tuple,
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
            # Determine the network prefix (e.g., "192.168.1.") for membership testing
            try:
                net = ipaddress.ip_network(network, strict=False)
                net_hosts = {str(ip) for ip in net.hosts()}
            except ValueError:
                net_hosts = None

            cmd = ["arp", "-a"] if sys.platform == "win32" else ["arp", "-a", "-n"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            for line in output.split("\n"):
                match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:-]+)\s+(\w+)",
                    line,
                    re.IGNORECASE,
                )
                if match:
                    ip, mac, iface = match.groups()
                    if net_hosts is None:
                        if ip.startswith(".".join(network.split(".")[:3]) + "."):
                            hosts.append({"ip": ip, "mac": mac, "interface": iface})
                    else:
                        if ip in net_hosts:
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
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            sock.sendto(b"traceroute", (target, 33434 + ttl))
            data, addr = sock.recvfrom(512)
            hop_ip = addr if isinstance(addr, tuple) else addr
            hops.append({"ttl": ttl, "ip": hop_ip, "hostname": reverse_dns(hop_ip)})
            sock.close()
            if hop_ip == target:
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
            "service": COMMON_PORTS.get(port, "unknown"),
            "description": PORT_DESCRIPTIONS.get(port, ""),
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

        # Handle service being either a tuple or string
        service = result.get("service", "unknown")
        if isinstance(service, tuple):
            service = service if service else "unknown"
        service_display = service or "unknown"

        # Description fallback chain: description field -> PORT_DESCRIPTIONS -> service
        description = result.get("description", "") or PORT_DESCRIPTIONS.get(
            result.get("port"), service_display
        )
        if isinstance(description, tuple):
            description_display = description if description else ""
        else:
            description_display = description

        print(
            f"{GREEN}[+] Port {result['port']:>5}/tcp  "
            f"{result['state']:<10} {service_display:<12} "
            f"{CYAN}| {banner_display}{vuln_str}{RESET}"
        )

    def print_summary(self):
        duration = time.time() - self.start_time if self.start_time else 0.0
        print(f"\n{CYAN}{'='*60}")
        print(f"{GREEN}[✓] Scan completed in {duration:.2f} seconds")
        print(f"[+] Found {len(self.results)} open ports")
        if self.results:
            print(f"\n{YELLOW}Open Ports Summary:{RESET}")
            print(f"{'Port':<10}{'Service':<15}{'State':<10}{'Version'}")
            print(f"{'-'*45}")
            for r in sorted(self.results, key=lambda x: x["port"]):
                service = r.get("service", "unknown")
                if isinstance(service, tuple):
                    service = service if service else "unknown"
                version = r.get("version_info", {}).get("version", "N/A")
                print(f"{r['port']:<10}{service:<15}{r['state']:<10}{version}")
        if self.vulnerabilities:
            print(f"\n{RED}[!] Found {len(self.vulnerabilities)} vulnerabilities:{RESET}")
            for v in self.vulnerabilities:
                svc = v.get("service", "unknown")
                if isinstance(svc, tuple):
                    svc = svc if svc else "unknown"
                sev_color = RED if v.get("severity") == "HIGH" else YELLOW
                print(
                    f"  {RED}•{RESET} Port {v['port']} ({svc}): "
                    f"{v['vulnerability']} [{sev_color}{v.get('severity', 'INFO')}{RESET}]"
                )
        print(f"{CYAN}{'='*60}{RESET}")

    def get_results(self) -> Dict:
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "scan_type": self.scan_type,
            "timestamp": datetime.now().isoformat(),
            "duration": (time.time() - self.start_time) if self.start_time else 0.0,
            "open_ports": self.results,
            "vulnerabilities": self.vulnerabilities,
        }

    def export_json(self, filename: str):
        with open(filename, "w") as f:
            json.dump(self.get_results(), f, indent=2, default=str)
        print(f"{GREEN}[+] JSON report saved: {filename}")

    def export_html(self, filename: str):
        results = self.get_results()
        target = html.escape(str(results.get("target", "")))
        scan_type = html.escape(str(results.get("scan_type", "")))
        resolved_ip = html.escape(str(results.get("resolved_ip", "") or ""))
        timestamp = html.escape(str(results.get("timestamp", "")))
        duration = f"{results.get('duration', 0):.2f}"

        parts = [f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SpectraScan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .summary {{ background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #007bff; color: white; }}
        tr:hover {{ background: #f1f1f1; }}
        .open {{ color: #28a745; font-weight: bold; }}
        .closed {{ color: #dc3545; }}
        .filtered {{ color: #ffc107; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>SpectraScan Report</h1>
        <div class="summary">
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Resolved IP:</strong> {resolved_ip}</p>
            <p><strong>Scan Type:</strong> {scan_type}</p>
            <p><strong>Timestamp:</strong> {timestamp}</p>
            <p><strong>Duration:</strong> {duration}s</p>
            <p><strong>Open Ports:</strong> {len(results.get('open_ports', []))}</p>
            <p><strong>Vulnerabilities:</strong> {len(results.get('vulnerabilities', []))}</p>
        </div>
        <h2>Open Ports</h2>
        <table>
            <tr><th>Port</th><th>Service</th><th>State</th><th>Banner</th></tr>"""]

        for port in results.get("open_ports", []):
            port_num = html.escape(str(port.get("port", "")))
            service = port.get("service", "")
            if isinstance(service, tuple):
                service = service if service else ""
            service = html.escape(str(service))
            state = html.escape(str(port.get("state", "")))
            banner = html.escape((port.get("banner", "") or "N/A")[:50])
            parts.append(
                f"<tr><td>{port_num}</td><td>{service}</td>"
                f"<td class='open'>{state}</td><td>{banner}</td></tr>"
            )

        parts.append("""        </table>
    </div>
</body>
</html>""")

        with open(filename, "w") as f:
            f.write("".join(parts))
        print(f"{GREEN}[+] HTML report saved: {filename}")

    def export_csv(self, filename: str):
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["Port", "Protocol", "State", "Service", "Banner", "Vulnerabilities"]
            )
            for port in self.results:
                service = port.get("service", "")
                if isinstance(service, tuple):
                    service = service if service else ""
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
                        service,
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

# ============== Protocol Module Scanner ==============
class ProtocolModuleScanner:
    """Stub implementation of protocol scanners.
    Replace these methods with calls into the real modules in ./modules if present.
    """

    @staticmethod
    def _print_result(name: str, result: Dict):
        console.print(f"\n[bold cyan]--- {name} ---[/bold cyan]")
        if isinstance(result, dict):
            for key, value in result.items():
                console.print(f"  [green]{key}:[/green] {value}")
        else:
            console.print(f"  {result}")

    @staticmethod
    def _tcp_probe(ip: str, port: int, timeout: float = 5.0) -> Dict:
        result = {"ip": ip, "port": port, "state": "closed", "banner": None}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                result["state"] = "open"
                try:
                    sock.settimeout(2.0)
                    data = sock.recv(256)
                    if data:
                        result["banner"] = data.decode("utf-8", errors="ignore").strip()
                except:
                    pass
            sock.close()
        except socket.timeout:
            result["state"] = "filtered"
        except Exception as e:
            result["state"] = "error"
            result["error"] = str(e)
        return result

    @staticmethod
    def run_smb(target: str):
        ip = target if target.replace(".", "").isdigit() else resolve_host(target)
        result = ProtocolModuleScanner._tcp_probe(ip, 445)
        ProtocolModuleScanner._print_result("SMB Enumerator", result)
        return result

    @staticmethod
    def run_snmp(target: str):
        ip = target if target.replace(".", "").isdigit() else resolve_host(target)
        result = ProtocolModuleScanner._tcp_probe(ip, 161, timeout=3.0)
        # SNMP is UDP, so do a quick UDP probe too
        try:
            usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            usock.settimeout(3.0)
            probe = b"\x30\x00\x00\x00\x02\x01\x00\x04\x06public\xa0\x1f\x02\x01\x00\x02\x01\x00\x30\x14"
            usock.sendto(probe, (ip, 161))
            data, _ = usock.recvfrom(1024)
            result["snmp_response"] = data.hex()[:100]
            result["state"] = "open"
            usock.close()
        except socket.timeout:
            result["snmp_response"] = None
        except Exception as e:
            result["snmp_error"] = str(e)
        ProtocolModuleScanner._print_result("SNMP Enumerator", result)
        return result

    @staticmethod
    def run_ldap(target: str, port: int = 389):
        ip = target if target.replace(".", "").isdigit() else resolve_host(target)
        result = ProtocolModuleScanner._tcp_probe(ip, port)
        ProtocolModuleScanner._print_result("LDAP Enumerator", result)
        return result

    @staticmethod
    def run_rdp(target: str):
        ip = target if target.replace(".", "").isdigit() else resolve_host(target)
        result = ProtocolModuleScanner._tcp_probe(ip, 3389)
        ProtocolModuleScanner._print_result("RDP Enumerator", result)
        return result

    @staticmethod
    def run_smtp(target: str, port: int = 25, test_relay: bool = True):
        ip = target if target.replace(".", "").isdigit() else resolve_host(target)
        result = {"banner": None, "open_relay": None, "error": None}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            result["banner"] = banner
            if test_relay:
                sock.send(b"EHLO test.local\r\n")
                sock.recv(1024)
                sock.send(b"MAIL FROM:<test@test.local>\r\n")
                resp = sock.recv(1024).decode("utf-8", errors="ignore")
                sock.send(b"RCPT TO:<probe@example.com>\r\n")
                resp2 = sock.recv(1024).decode("utf-8", errors="ignore")
                result["open_relay"] = "250" in resp2
            sock.send(b"QUIT\r\n")
            sock.close()
        except Exception as e:
            result["error"] = str(e)
        ProtocolModuleScanner._print_result("SMTP Enumerator", result)
        return result

    @staticmethod
    def run_dns_zone(domain: str):
        result = {"domain": domain, "records": {}}
        try:
            import dns.resolver
            import dns.zone
            import dns.query
            ns_answers = dns.resolver.resolve(domain, "NS")
            for ns in ns_answers:
                ns_str = str(ns).rstrip(".")
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(ns_str, domain, timeout=5))
                    result["records"][ns_str] = [str(n) for n in z.nodes.keys()]
                except Exception as e:
                    result["records"][ns_str] = f"Transfer failed: {e}"
        except ImportError:
            result["records"]["error"] = "dnspython not installed"
        except Exception as e:
            result["records"]["error"] = str(e)
        ProtocolModuleScanner._print_result("DNS Zone Transfer", result)
        return result

    @staticmethod
    def run_nfs(target: str):
        ip = target if target.replace(".", "").isdigit() else resolve_host(target)
        result = ProtocolModuleScanner._tcp_probe(ip, 2049)
        ProtocolModuleScanner._print_result("NFS Enumerator", result)
        return result

    @staticmethod
    def run_vnc(target: str, port: int = 5900):
        ip = target if target.replace(".", "").isdigit() else resolve_host(target)
        result = ProtocolModuleScanner._tcp_probe(ip, port)
        ProtocolModuleScanner._print_result("VNC Enumerator", result)
        return result

    @staticmethod
    def run_redis(target: str, port: int = 6379):
        ip = target if target.replace(".", "").isdigit() else resolve_host(target)
        result = {"ip": ip, "port": port}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.send(b"PING\r\n")
            data = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            result["response"] = data
            result["unauth"] = "PONG" in data
            sock.close()
        except Exception as e:
            result["error"] = str(e)
        ProtocolModuleScanner._print_result("Redis Enumerator", result)
        return result

    @staticmethod
    def run_mongodb(target: str, port: int = 27017):
        ip = target if target.replace(".", "").isdigit() else resolve_host(target)
        result = {"ip": ip, "port": port}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            # Send a minimal ismaster command
            sock.close()
            result["state"] = "open"
        except Exception as e:
            result["error"] = str(e)
        ProtocolModuleScanner._print_result("MongoDB Enumerator", result)
        return result

    @staticmethod
    def run_sip(target: str, port: int = 5060):
        ip = target if target.replace(".", "").isdigit() else resolve_host(target)
        result = {"ip": ip, "port": port, "state": "unknown"}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(b"OPTIONS sip:test@" + ip.encode() + b" SIP/2.0\r\n\r\n", (ip, port))
            data, _ = sock.recvfrom(1024)
            result["state"] = "open"
            result["response"] = data.decode("utf-8", errors="ignore").strip()[:200]
            sock.close()
        except socket.timeout:
            result["state"] = "open|filtered"
        except Exception as e:
            result["error"] = str(e)
        ProtocolModuleScanner._print_result("SIP Enumerator", result)
        return result

    @staticmethod
    def run_rtsp(target: str, port: int = 554):
        ip = target if target.replace(".", "").isdigit() else resolve_host(target)
        result = {"ip": ip, "port": port}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.send(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            data = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            result["response"] = data[:200]
            result["state"] = "open"
            sock.close()
        except Exception as e:
            result["error"] = str(e)
        ProtocolModuleScanner._print_result("RTSP Enumerator", result)
        return result

    @staticmethod
    def run_databases(target: str):
        ip = target if target.replace(".", "").isdigit() else resolve_host(target)
        db_ports = {
            "mysql": 3306,
            "postgres": 5432,
            "mssql": 1433,
            "oracle": 1521,
        }
        results = {}
        for db, port in db_ports.items():
            results[db] = ProtocolModuleScanner._tcp_probe(ip, port, timeout=3.0)
        for db_name, db_result in results.items():
            ProtocolModuleScanner._print_result(db_name.upper(), db_result)
        return results


def run_protocol_modules():
    """Interactive menu for protocol modules."""
    console.print("\n[bold cyan]--- PROTOCOL ENUMERATION MODULES ---[/bold cyan]")
    console.print("[bold green]1.[/bold green] SMB Enumerator")
    console.print("[bold green]2.[/bold green] SNMP Enumerator")
    console.print("[bold green]3.[/bold green] LDAP Enumerator")
    console.print("[bold green]4.[/bold green] RDP Enumerator")
    console.print("[bold green]5.[/bold green] SMTP Enumerator")
    console.print("[bold green]6.[/bold green] DNS Zone Transfer")
    console.print("[bold green]7.[/bold green] NFS Enumerator")
    console.print("[bold green]8.[/bold green] VNC Enumerator")
    console.print("[bold green]9.[/bold green] Redis Enumerator")
    console.print("[bold green]10.[/bold green] MongoDB Enumerator")
    console.print("[bold green]11.[/bold green] SIP Enumerator")
    console.print("[bold green]12.[/bold green] RTSP Enumerator")
    console.print("[bold green]13.[/bold green] Database Scan (MySQL/Postgres/MSSQL)")
    console.print("[bold blue]14.[/bold blue] Dark Web Recon")
    console.print("[bold red]15.[/bold red] Back to main menu")

    choice = hacker_input("Select module")

    def _safe_int(prompt: str, default: int) -> int:
        raw = hacker_input(prompt, str(default))
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default

    try:
        if choice == "1":
            target = hacker_input("Enter target IP/hostname")
            if target:
                ProtocolModuleScanner.run_smb(target)
        elif choice == "2":
            target = hacker_input("Enter target IP/hostname")
            if target:
                ProtocolModuleScanner.run_snmp(target)
        elif choice == "3":
            target = hacker_input("Enter target IP/hostname")
            port = _safe_int("Port (default 389)", 389)
            if target:
                ProtocolModuleScanner.run_ldap(target, port)
        elif choice == "4":
            target = hacker_input("Enter target IP/hostname")
            if target:
                ProtocolModuleScanner.run_rdp(target)
        elif choice == "5":
            target = hacker_input("Enter target IP/hostname")
            relay = Confirm.ask("Test open relay?", default=True)
            if target:
                ProtocolModuleScanner.run_smtp(target, test_relay=relay)
        elif choice == "6":
            domain = hacker_input("Enter domain (e.g., example.com)")
            if domain:
                ProtocolModuleScanner.run_dns_zone(domain)
        elif choice == "7":
            target = hacker_input("Enter target IP/hostname")
            if target:
                ProtocolModuleScanner.run_nfs(target)
        elif choice == "8":
            target = hacker_input("Enter target IP/hostname")
            port = _safe_int("Port (default 5900)", 5900)
            if target:
                ProtocolModuleScanner.run_vnc(target, port)
        elif choice == "9":
            target = hacker_input("Enter target IP/hostname")
            if target:
                ProtocolModuleScanner.run_redis(target)
        elif choice == "10":
            target = hacker_input("Enter target IP/hostname")
            if target:
                ProtocolModuleScanner.run_mongodb(target)
        elif choice == "11":
            target = hacker_input("Enter target IP/hostname")
            if target:
                ProtocolModuleScanner.run_sip(target)
        elif choice == "12":
            target = hacker_input("Enter target IP/hostname")
            if target:
                ProtocolModuleScanner.run_rtsp(target)
        elif choice == "13":
            target = hacker_input("Enter target IP/hostname")
            if target:
                ProtocolModuleScanner.run_databases(target)
        elif choice == "14":
            # ---- Dark Web Recon ----
            try:
                from modules.darkweb import run_darkweb_menu, SOCKS_AVAILABLE
            except ImportError as e:
                console.print(f"[!] Cannot load darkweb module: {e}",
                              style="red")
                return
            if not SOCKS_AVAILABLE:
                console.print(
                    "[!] 'pysocks' not installed. .onion ops will be disabled.",
                    style="yellow")
                console.print(
                    "    Install with: pip install pysocks", style="yellow")
            console.print(
                "[*] Tor required for .onion ops (127.0.0.1:9050). "
                "Clearnet APIs work without Tor.",
                style="cyan")
            run_darkweb_menu()
        elif choice == "15":
            return
        else:
            console.print("[!] Invalid option.", style="red")
    except Exception as e:
        console.print(f"{RED}[!] Error: {e}{RESET}", style="red")


# ============== Domain Intelligence Scanner ==============
class DomainScanner:
    """Passive-first domain intelligence for SpectraScan.

    Keeps the existing DomainScanner.scan(domain, report_manager) API while
    adding WHOIS, DNS, SPF, DMARC, DKIM selector checks, CAA, DNSSEC evidence,
    Certificate Transparency, passive subdomain discovery, HTTP/TLS metadata,
    security headers, technology/CDN hints, robots.txt, sitemap and scoring.
    """

    VERSION = "2.0.0"
    HTTP_TIMEOUT = 12
    DNS_TIMEOUT = 4
    CT_TIMEOUT = 20
    USER_AGENT = f"SpectraScan-DomainIntelligence/{VERSION}"

    DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV")
    SECURITY_HEADERS = (
        "strict-transport-security", "content-security-policy",
        "x-content-type-options", "x-frame-options", "referrer-policy",
        "permissions-policy", "cross-origin-opener-policy",
        "cross-origin-resource-policy",
    )
    DKIM_SELECTORS = (
        "default", "selector1", "selector2", "google", "k1", "k2",
        "mail", "dkim", "s1", "s2", "smtp", "mandrill", "zoho",
        "sendgrid", "mailjet", "amazonses", "protonmail",
    )
    TECH_PATTERNS = {
        "WordPress": (r"/wp-content/", r"/wp-includes/", r"wp-json"),
        "Drupal": (r"drupalSettings", r"/sites/default/"),
        "Joomla": (r"/media/system/", r"joomla"),
        "Next.js": (r"__NEXT_DATA__", r"/_next/"),
        "Nuxt": (r"__NUXT__", r"/_nuxt/"),
        "React": (r"react(?:dom)?",),
        "Vue.js": (r"vue(?:\.router)?",),
        "Angular": (r"ng-version", r"angular"),
        "jQuery": (r"jquery",),
        "Bootstrap": (r"bootstrap",),
        "Tailwind CSS": (r"tailwind",),
        "Google Analytics": (r"google-analytics", r"gtag", r"googletagmanager"),
        "Google Tag Manager": (r"googletagmanager", r"gtm\.js"),
        "Cloudflare": (r"cf-ray", r"cloudflare"),
    }
    CDN_PATTERNS = {
        "Cloudflare": ("cf-ray", "cf-cache-status", "cloudflare"),
        "Akamai": ("akamai", "x-akamai"),
        "Fastly": ("fastly", "x-served-by"),
        "Amazon CloudFront": ("cloudfront", "x-amz-cf-id", "x-amz-cf-pop"),
        "Imperva": ("imperva", "incap_ses", "visid_incap"),
        "Azure Front Door": ("x-azure-ref", "azure"),
    }

    @staticmethod
    def normalize_domain(value: str) -> str:
        value = (value or "").strip()
        if not value:
            return ""
        if "://" not in value:
            value = "https://" + value
        try:
            host = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(value).hostname or ""
        except Exception:
            host = ""
        return host.lower().rstrip(".")

    @staticmethod
    def _unique(values):
        seen, out = set(), []
        for value in values or []:
            if value is None:
                continue
            value = str(value).strip().rstrip(".")
            if value and value.lower() not in seen:
                seen.add(value.lower())
                out.append(value)
        return out

    @staticmethod
    def _write(report_manager, text):
        try:
            report_manager.write(str(text))
        except Exception:
            pass

    @classmethod
    def _http(cls, url, timeout=None):
        try:
            import requests
            return requests.get(
                url,
                headers={"User-Agent": cls.USER_AGENT, "Accept": "*/*"},
                timeout=timeout or cls.HTTP_TIMEOUT,
                allow_redirects=True,
                verify=True,
            )
        except Exception:
            return None

    @classmethod
    def _whois(cls, domain):
        result = {"available": False, "source": None, "registrar": None,
                  "organization": None, "creation_date": None,
                  "expiration_date": None, "updated_date": None,
                  "name_servers": [], "status": [], "emails": [], "raw": None}
        try:
            import whois
            data = whois.whois(domain)
            result["available"] = True
            result["source"] = "python-whois"
            result["registrar"] = str(data.registrar) if data.registrar else None
            result["organization"] = str(getattr(data, "org", None)) if getattr(data, "org", None) else None
            for key, attr in (("creation_date", "creation_date"), ("expiration_date", "expiration_date"), ("updated_date", "updated_date")):
                value = getattr(data, attr, None)
                if value:
                    result[key] = str(value)
            result["name_servers"] = cls._unique(getattr(data, "name_servers", None) or [])
            result["status"] = cls._unique(getattr(data, "status", None) or [])
            result["emails"] = cls._unique(getattr(data, "emails", None) or [])
            return result
        except Exception as exc:
            result["error"] = str(exc)
        try:
            proc = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=20)
            raw = (proc.stdout or proc.stderr or "").strip()
            if raw:
                result["available"] = True
                result["source"] = "system-whois"
                result["raw"] = raw
                patterns = {
                    "registrar": r"(?im)^Registrar(?: Name)?:\s*(.+)$",
                    "organization": r"(?im)^(?:Registrant Organization|Organization):\s*(.+)$",
                    "creation_date": r"(?im)^(?:Creation Date|Created|Registered On):\s*(.+)$",
                    "expiration_date": r"(?im)^(?:Registry Expiry Date|Expiration Date|Expiry Date):\s*(.+)$",
                    "updated_date": r"(?im)^(?:Updated Date|Last Updated):\s*(.+)$",
                }
                for key, pattern in patterns.items():
                    match = re.search(pattern, raw)
                    if match:
                        result[key] = match.group(1).strip()
                result["name_servers"] = cls._unique(re.findall(r"(?im)^(?:Name Server|Nameserver|nserver):\s*([^\s]+)", raw))
        except Exception as exc:
            result["error"] = str(exc)
        return result

    @classmethod
    def _dns(cls, domain):
        result = {"records": {}, "errors": {}, "resolved_ips": []}
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = cls.DNS_TIMEOUT
            resolver.lifetime = cls.DNS_TIMEOUT + 1
            for rtype in cls.DNS_TYPES:
                values = []
                try:
                    answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
                    for answer in answers:
                        if rtype == "MX":
                            values.append(f"{answer.exchange} (pref: {answer.preference})")
                        elif rtype == "SOA":
                            values.append(str(answer))
                        else:
                            values.append(str(answer).strip('"').rstrip('.'))
                except Exception as exc:
                    result["errors"][rtype] = str(exc)
                result["records"][rtype] = cls._unique(values)
        except ImportError:
            result["errors"]["dns"] = "dnspython is not installed"
        except Exception as exc:
            result["errors"]["dns"] = str(exc)
        try:
            result["resolved_ips"] = cls._unique(
                result["records"].get("A", []) + result["records"].get("AAAA", [])
            )
            if not result["resolved_ips"]:
                result["resolved_ips"] = cls._unique(
                    item[4][0] for item in socket.getaddrinfo(domain, None)
                )
        except Exception:
            pass
        return result

    @classmethod
    def _spf(cls, dns_data):
        records = [x for x in dns_data.get("records", {}).get("TXT", []) if x.lower().startswith("v=spf1")]
        return {"present": bool(records), "records": records, "mechanisms": cls._unique(" ".join(records).split()[1:])}

    @classmethod
    def _dmarc(cls, domain):
        result = {"present": False, "record": None, "policy": None}
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = cls.DNS_TIMEOUT
            resolver.lifetime = cls.DNS_TIMEOUT + 1
            values = [str(x).strip('"') for x in resolver.resolve(f"_dmarc.{domain}", "TXT")]
            record = next((x for x in values if x.lower().startswith("v=dmarc1")), None)
            if record:
                result["present"] = True
                result["record"] = record
                match = re.search(r"(?:^|;)\s*p=([^;]+)", record, re.I)
                result["policy"] = match.group(1).strip().lower() if match else None
        except Exception as exc:
            result["error"] = str(exc)
        return result

    @classmethod
    def _dkim(cls, domain):
        result = {"tested": list(cls.DKIM_SELECTORS), "found": []}
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 3
            for selector in cls.DKIM_SELECTORS:
                try:
                    values = [str(x).strip('"') for x in resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")]
                    if values:
                        result["found"].append({"selector": selector, "records": values})
                except Exception:
                    continue
        except ImportError:
            result["error"] = "dnspython is not installed"
        return result

    @staticmethod
    def _security_headers(headers):
        normalized = {str(k).lower(): str(v) for k, v in headers.items()}
        return {key: normalized.get(key) for key in DomainScanner.SECURITY_HEADERS}

    @classmethod
    def _technologies(cls, response):
        body = (response.text or "")[:1500000]
        blob = body + "\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        found = set()
        for name, patterns in cls.TECH_PATTERNS.items():
            if any(re.search(p, blob, re.I) for p in patterns):
                found.add(name)
        if response.headers.get("Server"):
            found.add("Server: " + response.headers["Server"].strip())
        if response.headers.get("X-Powered-By"):
            found.add("Powered-By: " + response.headers["X-Powered-By"].strip())
        return sorted(found)

    @classmethod
    def _cdn(cls, headers):
        blob = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
        return sorted(name for name, patterns in cls.CDN_PATTERNS.items() if any(p.lower() in blob for p in patterns))

    @staticmethod
    def _title(body):
        match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
        return re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()[:300] if match else None

    @classmethod
    def _web(cls, domain):
        result = {"preferred_url": None, "http": {}, "https": {}, "redirect_chain": [],
                  "headers": {}, "security_headers": {}, "server": None,
                  "content_type": None, "title": None, "technologies": [], "cdn": []}
        responses = {}
        for scheme in ("https", "http"):
            response = cls._http(f"{scheme}://{domain}/")
            if response is not None:
                responses[scheme] = response
                result[scheme] = {
                    "available": True, "status": response.status_code,
                    "final_url": response.url,
                    "history": [{"status": x.status_code, "url": x.url, "location": x.headers.get("Location")} for x in response.history],
                    "headers": dict(response.headers),
                }
            else:
                result[scheme] = {"available": False}
        response = responses.get("https") or responses.get("http")
        if response is not None:
            result["preferred_url"] = response.url
            result["redirect_chain"] = [x.url for x in response.history] + [response.url]
            result["headers"] = dict(response.headers)
            result["security_headers"] = cls._security_headers(response.headers)
            result["server"] = response.headers.get("Server")
            result["content_type"] = response.headers.get("Content-Type")
            result["title"] = cls._title(response.text)
            result["technologies"] = cls._technologies(response)
            result["cdn"] = cls._cdn(response.headers)
        return result

    @classmethod
    def _tls(cls, domain):
        result = {"available": False, "version": None, "cipher": None, "subject": {}, "issuer": {}, "san": [], "not_before": None, "not_after": None}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as tls:
                    cert = tls.getpeercert()
                    result["available"] = True
                    result["version"] = tls.version()
                    result["cipher"] = tls.cipher()
                    result["subject"] = dict(x[0] for x in cert.get("subject", ()))
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                    result["not_before"] = cert.get("notBefore")
                    result["not_after"] = cert.get("notAfter")
                    result["san"] = cls._unique(v for k, v in cert.get("subjectAltName", ()) if k.lower() == "dns")
        except Exception as exc:
            result["error"] = str(exc)
        return result

    @classmethod
    def _ct(cls, domain):
        result = {"available": False, "source": "crt.sh", "certificates": 0, "names": []}
        try:
            import requests
            response = requests.get(
                "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                headers={"User-Agent": cls.USER_AGENT}, timeout=cls.CT_TIMEOUT, verify=True,
            )
            if response.status_code != 200:
                result["error"] = f"HTTP {response.status_code}"
                return result
            records = response.json()
            names = set()
            for record in records:
                for name in str(record.get("name_value", "")).splitlines():
                    name = name.strip().lower().replace("*.", "")
                    if name == domain or name.endswith("." + domain):
                        names.add(name)
            result.update({"available": True, "certificates": len(records), "names": sorted(names)})
        except Exception as exc:
            result["error"] = str(exc)
        return result

    @classmethod
    def _subdomains(cls, domain, ct):
        candidates = set(x for x in ct.get("names", []) if x != domain and x.endswith("." + domain))
        for prefix in COMMON_SUBDOMAINS:
            candidates.add(f"{prefix}.{domain}")
        resolved = []
        for host in sorted(candidates):
            try:
                ips = cls._unique(item[4][0] for item in socket.getaddrinfo(host, None))
                if ips:
                    resolved.append({"hostname": host, "ips": ips})
            except Exception:
                pass
        return {"candidates": sorted(candidates), "resolved": resolved, "count": len(resolved)}

    @classmethod
    def _robots(cls, domain):
        result = {"found": False, "status": None, "url": None, "sitemaps": [], "disallow": [], "allow": []}
        for scheme in ("https", "http"):
            response = cls._http(f"{scheme}://{domain}/robots.txt")
            if response is not None and response.status_code == 200:
                result.update({"found": True, "status": response.status_code, "url": response.url})
                for line in response.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or ":" not in line:
                        continue
                    key, value = line.split(":", 1)
                    value = value.strip()
                    if key.lower() == "sitemap": result["sitemaps"].append(value)
                    elif key.lower() == "disallow" and value: result["disallow"].append(value)
                    elif key.lower() == "allow" and value: result["allow"].append(value)
                result["sitemaps"] = cls._unique(result["sitemaps"])
                result["disallow"] = cls._unique(result["disallow"])
                result["allow"] = cls._unique(result["allow"])
                return result
        return result

    @classmethod
    def _sitemap(cls, domain, robots):
        candidates = cls._unique(robots.get("sitemaps", []) + [f"https://{domain}/sitemap.xml", f"https://{domain}/sitemap_index.xml"])
        for url in candidates:
            response = cls._http(url)
            if response is None or response.status_code != 200:
                continue
            body = response.text
            if "<urlset" not in body.lower() and "<sitemapindex" not in body.lower() and "xml" not in response.headers.get("Content-Type", "").lower():
                continue
            urls = cls._unique(html.unescape(x.strip()) for x in re.findall(r"<loc>\s*(.*?)\s*</loc>", body, re.I | re.S))
            return {"found": True, "url": response.url, "status": response.status_code, "urls": urls[:5000]}
        return {"found": False, "url": None, "status": None, "urls": []}

    @classmethod
    def _reverse_dns(cls, ips):
        result = {}
        for ip in ips:
            try:
                result[ip] = socket.gethostbyaddr(ip)[0]
            except Exception:
                result[ip] = None
        return result

    @classmethod
    def _infrastructure(cls, dns_data):
        ips = dns_data.get("resolved_ips", [])
        result = {"ips": ips, "reverse_dns": cls._reverse_dns(ips)}
        api_key = os.environ.get("SHODAN_API_KEY")
        if api_key and ips:
            try:
                import requests
                response = requests.get(
                    f"https://api.shodan.io/shodan/host/{ips[0]}",
                    params={"key": api_key}, headers={"User-Agent": cls.USER_AGENT}, timeout=10,
                )
                if response.status_code == 200:
                    data = response.json()
                    result["shodan"] = {
                        "ip": data.get("ip_str"), "organization": data.get("org"),
                        "isp": data.get("isp"), "asn": data.get("asn"),
                        "os": data.get("os"), "ports": data.get("ports", []),
                    }
            except Exception as exc:
                result["shodan_error"] = str(exc)
        return result

    @classmethod
    def _score(cls, dns_data, spf, dmarc, dkim, web, tls):
        score = 0
        if dns_data.get("records", {}).get("A") or dns_data.get("records", {}).get("AAAA"): score += 10
        if dns_data.get("records", {}).get("NS"): score += 5
        if dns_data.get("records", {}).get("SOA"): score += 5
        if dns_data.get("records", {}).get("CAA"): score += 5
        if spf.get("present"): score += 8
        if dmarc.get("present"): score += 8
        if dmarc.get("policy") in ("quarantine", "reject"): score += 4
        if dkim.get("found"): score += 5
        if tls.get("available"): score += 15
        if tls.get("version") in ("TLSv1.2", "TLSv1.3"): score += 5
        if web.get("https", {}).get("available"): score += 8
        headers = web.get("security_headers", {})
        score += min(17, sum(2 for value in headers.values() if value))
        score = min(100, score)
        rating = "EXCELLENT" if score >= 90 else "STRONG" if score >= 75 else "MODERATE" if score >= 60 else "WEAK" if score >= 40 else "HIGH EXPOSURE"
        return {"score": score, "rating": rating}

    @classmethod
    def _findings(cls, spf, dmarc, caa, dnssec, web, tls, robots, ct):
        findings = []
        if not spf.get("present"): findings.append({"severity": "MEDIUM", "category": "Email", "message": "No SPF record observed."})
        if not dmarc.get("present"): findings.append({"severity": "MEDIUM", "category": "Email", "message": "No DMARC record observed."})
        elif dmarc.get("policy") == "none": findings.append({"severity": "LOW", "category": "Email", "message": "DMARC policy is set to none."})
        if not caa.get("records"): findings.append({"severity": "LOW", "category": "DNS", "message": "No CAA record observed."})
        if not dnssec.get("present"): findings.append({"severity": "LOW", "category": "DNS", "message": "DNSSEC evidence was not observed."})
        missing = [k for k, v in web.get("security_headers", {}).items() if not v]
        if missing: findings.append({"severity": "LOW", "category": "Web", "message": f"{len(missing)} recommended security headers were not observed.", "details": missing})
        if web.get("https", {}).get("available") and not web.get("security_headers", {}).get("strict-transport-security"):
            findings.append({"severity": "LOW", "category": "TLS", "message": "HTTPS is available but HSTS was not observed."})
        if not tls.get("available"): findings.append({"severity": "MEDIUM", "category": "TLS", "message": "TLS certificate inspection failed."})
        if robots.get("disallow"): findings.append({"severity": "INFO", "category": "Web", "message": "robots.txt exposes disallowed paths.", "details": robots["disallow"][:50]})
        if ct.get("names"): findings.append({"severity": "INFO", "category": "CT", "message": f"{len(ct['names'])} certificate names discovered."})
        return findings

    @classmethod
    def scan(cls, domain: str, report_manager: ReportManager):
        started = time.time()
        domain = cls.normalize_domain(domain)
        if not domain or len(domain) > 253 or " " in domain:
            cls._write(report_manager, "[-] Invalid domain.")
            return None

        cls._write(report_manager, f"\n-----DOMAIN INTELLIGENCE SCAN: {domain}-----\n")
        data = {"module": "Domain Intelligence", "version": cls.VERSION, "domain": domain,
                "timestamp": datetime.now().isoformat(), "whois": {}, "dns": {}, "spf": {},
                "dmarc": {}, "dkim": {}, "caa": {}, "dnssec": {}, "certificate_transparency": {},
                "subdomains": {}, "infrastructure": {}, "web": {}, "tls": {}, "robots": {},
                "sitemap": {}, "findings": [], "score": {}}

        steps = [
            ("WHOIS", lambda: cls._whois(domain), "whois"),
            ("DNS", lambda: cls._dns(domain), "dns"),
        ]
        for label, func, key in steps:
            cls._write(report_manager, f"[*] Collecting {label}...")
            try: data[key] = func()
            except Exception as exc: data[key] = {"error": str(exc)}

        try: data["spf"] = cls._spf(data["dns"])
        except Exception as exc: data["spf"] = {"error": str(exc), "present": False}
        try: data["dmarc"] = cls._dmarc(domain)
        except Exception as exc: data["dmarc"] = {"error": str(exc), "present": False}
        try: data["dkim"] = cls._dkim(domain)
        except Exception as exc: data["dkim"] = {"error": str(exc), "found": []}

        records = data["dns"].get("records", {})
        data["caa"] = {"present": bool(records.get("CAA")), "records": records.get("CAA", [])}
        data["dnssec"] = {"present": bool(records.get("DS") or records.get("DNSKEY")), "records": {"DS": records.get("DS", []), "DNSKEY": records.get("DNSKEY", [])}}

        cls._write(report_manager, "[*] Querying Certificate Transparency...")
        data["certificate_transparency"] = cls._ct(domain)
        data["subdomains"] = cls._subdomains(domain, data["certificate_transparency"])
        cls._write(report_manager, "[*] Inspecting HTTP/HTTPS and TLS...")
        data["web"] = cls._web(domain)
        data["tls"] = cls._tls(domain)
        data["robots"] = cls._robots(domain)
        data["sitemap"] = cls._sitemap(domain, data["robots"])
        data["infrastructure"] = cls._infrastructure(data["dns"])
        data["related_hosts"] = cls._unique(
            records.get("NS", []) + records.get("CNAME", []) + records.get("MX", [])
        )
        data["findings"] = cls._findings(data["spf"], data["dmarc"], data["caa"], data["dnssec"], data["web"], data["tls"], data["robots"], data["certificate_transparency"])
        data["score"] = cls._score(data["dns"], data["spf"], data["dmarc"], data["dkim"], data["web"], data["tls"])
        data["runtime_seconds"] = round(time.time() - started, 2)

        cls._write(report_manager, "\n[ WHOIS ]")
        whois_data = data["whois"]
        for key in ("registrar", "organization", "creation_date", "updated_date", "expiration_date"):
            cls._write(report_manager, f"{key.replace('_', ' ').title()}: {whois_data.get(key) or 'Unknown'}")
        cls._write(report_manager, "Name Servers: " + (", ".join(whois_data.get("name_servers", [])) or "Unknown"))

        cls._write(report_manager, "\n[ DNS ]")
        for rtype in cls.DNS_TYPES:
            values = records.get(rtype, [])
            if values: cls._write(report_manager, f"{rtype}: {', '.join(values[:25])}")

        cls._write(report_manager, "\n[ EMAIL SECURITY ]")
        cls._write(report_manager, f"SPF: {'FOUND' if data['spf'].get('present') else 'NOT FOUND'}")
        cls._write(report_manager, f"DMARC: {data['dmarc'].get('policy') or 'NOT FOUND'}")
        cls._write(report_manager, f"DKIM selectors found: {len(data['dkim'].get('found', []))}")

        cls._write(report_manager, "\n[ WEB / TLS ]")
        cls._write(report_manager, f"URL: {data['web'].get('preferred_url') or 'Unavailable'}")
        cls._write(report_manager, f"Title: {data['web'].get('title') or 'Unknown'}")
        cls._write(report_manager, f"Server: {data['web'].get('server') or 'Unknown'}")
        cls._write(report_manager, "Technologies: " + (", ".join(data['web'].get('technologies', [])) or "None detected"))
        cls._write(report_manager, "CDN/WAF: " + (", ".join(data['web'].get('cdn', [])) or "None detected"))
        cls._write(report_manager, f"TLS: {data['tls'].get('version') or 'Unavailable'}")
        cls._write(report_manager, f"TLS SANs: {len(data['tls'].get('san', []))}")

        cls._write(report_manager, "\n[ CERTIFICATE TRANSPARENCY / SUBDOMAINS ]")
        cls._write(report_manager, f"Certificates: {data['certificate_transparency'].get('certificates', 0)}")
        cls._write(report_manager, f"Resolved subdomains: {data['subdomains'].get('count', 0)}")
        for item in data["subdomains"].get("resolved", [])[:100]:
            cls._write(report_manager, f"  {item['hostname']} -> {', '.join(item['ips'])}")

        cls._write(report_manager, "\n[ PUBLIC RESOURCES ]")
        cls._write(report_manager, f"robots.txt: {'FOUND' if data['robots'].get('found') else 'NOT FOUND'}")
        cls._write(report_manager, f"sitemap: {'FOUND' if data['sitemap'].get('found') else 'NOT FOUND'}")

        cls._write(report_manager, "\n[ FINDINGS ]")
        for finding in data["findings"] or [{"severity": "INFO", "category": "General", "message": "No notable findings."}]:
            cls._write(report_manager, f"[{finding['severity']}] {finding['category']}: {finding['message']}")

        cls._write(report_manager, f"\n[ INTELLIGENCE SCORE ] {data['score']['score']}/100 — {data['score']['rating']}")
        cls._write(report_manager, f"[*] DOMAIN INTELLIGENCE COMPLETE in {data['runtime_seconds']:.2f}s")
        return data

# ============== IP Scanner ==============
class IPScanner:
    """Integrates SpectraScan IP Scanner features"""
    @staticmethod
    def scan(ip: str, report_manager: ReportManager):
        report_manager.write(f"\n-----IP SCAN OF {ip}-----\n")

        # GeoIP
        report_manager.write("[*] LOCALISATION")
        try:
            result = subprocess.run(
                ["curl", "-s", f"https://api.hackertarget.com/geoip/?q={ip}"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            report_manager.write(result.stdout)
        except FileNotFoundError:
            report_manager.write("[-] 'curl' not found.")
        except Exception as e:
            report_manager.write(f"Error with GeoIP: {e}")

        # WHOIS
        report_manager.write("\n[*] ADMIN INFO (WHOIS)")
        report_manager.write(DomainScanner._run_whois(ip))

        # Shodan
        report_manager.write("\n[*] SHODAN RESULTS")
        api_key = os.environ.get("SHODAN_API_KEY")
        if not api_key:
            report_manager.write("[-] SHODAN_API_KEY environment variable not set. Skipping Shodan lookup.")
        else:
            try:
                import shodan
                api = shodan.Shodan(api_key)
                result = api.host(ip)
                ports = result.get("ports", [])
                report_manager.write(f"Open Ports: {len(ports)}")
                for port in ports:
                    banner = ""
                    for entry in result.get("data", []):
                        if entry.get("port") == port:
                            banner = entry.get("product", "Unknown")
                            break
                    report_manager.write(f"  Port {port}: {banner}")
            except ImportError:
                report_manager.write("[-] Shodan Python library not found. Install with: pip install shodan")
            except Exception as e:
                report_manager.write(f"Error with Shodan: {e}")

        report_manager.write("\n[*] DONE")

# ============== Phone Scanner ==============
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
                result = subprocess.run(
                    ["python3", script_path, phone],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                report_manager.write(result.stdout)
                if result.stderr:
                    report_manager.write(f"Stderr: {result.stderr}")
            except Exception as e:
                report_manager.write(f"Error running phone scanner: {e}")
        else:
            report_manager.write("Phone scanner module not found (modules/phone_scanner.py).")

        report_manager.write("\n[*] DONE")

# ============== Email Scanner ==============
class EmailScanner:
    """Integrates SpectraScan Email Scanner features"""
    @staticmethod
    def scan(email: str, report_manager: ReportManager):
        report_manager.write(f"\n[*] Gathering informations for {email}...")
        try:
            headers = {"User-Agent": "SpectraScan/1.0"}
            try:
                result = subprocess.run(
                    ["curl", "-s", "-H", f"User-Agent: {headers['User-Agent']}",
                     f"https://emailrep.io/{email}"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                payload = result.stdout
            except FileNotFoundError:
                req = Request(f"https://emailrep.io/{email}", headers=headers)
                with urlopen(req, timeout=10) as resp:
                    payload = resp.read().decode("utf-8", errors="ignore")

            json_data = json.loads(payload) if payload else {}

            details = json_data.get("details", {}) or {}
            report_manager.write("\n_____FULL REPORT_____")
            report_manager.write(f"-Email: {email}")
            report_manager.write(f"-Suspicious: {json_data.get('suspicious')}")
            report_manager.write(f"-Reputation: {json_data.get('reputation')}")
            report_manager.write(f"-Blacklisted: {details.get('blacklisted')}")
            report_manager.write(f"-Malicious Activity: {details.get('malicious_activity')}")
            report_manager.write(f"-Data Breach: {details.get('data_breach')}")
            report_manager.write(f"-First Seen: {details.get('first_seen')}")
            report_manager.write(f"-Last Seen: {details.get('last_seen')}")
            report_manager.write(f"-Domain Exists: {details.get('domain_exists')}")
            report_manager.write(f"-Free Provider: {details.get('free_provider')}")
            report_manager.write(f"-Disposable: {details.get('disposable')}")
            report_manager.write(f"-Deliverable: {details.get('deliverable')}")
            report_manager.write(f"-Spoofable: {details.get('spoofable')}")
        except Exception as e:
            report_manager.write(f"Error scraping emailrep: {e}")
        report_manager.write("\n[*] DONE")

# ============== Image Scanner ==============
class ImageScanner:
    """Integrates SpectraScan Image EXIF Scanner features"""
    @staticmethod
    def scan(image_path: str, report_manager: ReportManager):
        report_manager.write(f"\nEXIF data from: {image_path}")
        if not os.path.exists(image_path):
            report_manager.write(f"[-] File not found: {image_path}")
            report_manager.write("\n[*] DONE")
            return
        try:
            # Try exiv2 first, then exiftool
            exiv2_path = "/usr/bin/exiv2" if sys.platform != "win32" else r"C:\Program Files\exiv2\exiv2.exe"
            exiftool_path = "/usr/bin/exiftool" if sys.platform != "win32" else r"C:\Windows\exiftool.exe"
            if os.path.exists(exiv2_path):
                result = subprocess.run(
                    ["exiv2", image_path], capture_output=True, text=True, timeout=30
                )
                report_manager.write(result.stdout)
            elif os.path.exists(exiftool_path):
                result = subprocess.run(
                    ["exiftool", image_path], capture_output=True, text=True, timeout=30
                )
                report_manager.write(result.stdout)
            else:
                report_manager.write("No EXIF tool found (exiv2 or exiftool required).")
        except FileNotFoundError:
            report_manager.write("No EXIF tool found (exiv2 or exiftool required).")
        except Exception as e:
            report_manager.write(f"Error reading EXIF: {e}")
        report_manager.write("\n[*] DONE")

# ============== Link Scanner ==============
class LinkScanner:
    """Integrates SpectraScann Link Sniffing features"""
    @staticmethod
    def scan(domain: str, report_manager: ReportManager):
        report_manager.write(f"\n__________Link Sniffing__________\n")
        report_manager.write(f"[*] SNIFFING LINKS for {domain}")
        report_manager.write("-------------------------------------------------------------------------------")
        try:
            result = subprocess.run(
                ["curl", "-s", f"https://api.hackertarget.com/pagelinks/?q={domain}"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            report_manager.write(result.stdout or "[-] No response from API.")
        except FileNotFoundError:
            report_manager.write("[-] 'curl' not found.")
        except Exception as e:
            report_manager.write(f"Error with link sniffing: {e}")
        report_manager.write("\n[*] DONE")

# ============== Criminal Scanner ==============
class CriminalScanner:
    """Integrates SpectraScan Criminal Scanner features"""
    @staticmethod
    def scan(first_name: str, last_name: str, state: str, city: str, report_manager: ReportManager):
        state_prefix = f"{state}." if state else ""
        link = f"https://{state_prefix}staterecords.org/search.php?firstname={first_name}&lastname={last_name}&city={city}"
        report_manager.write("\n[*] Generating Link...")
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
 
 
def guard_interrupt(fn):
    """Decorator: catch Ctrl+C / Ctrl+D inside a submenu and bounce
    back to the caller instead of killing the whole program."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (KeyboardInterrupt, EOFError):
            console.print("\n[!] Cancelled. Returning to previous menu.", style="yellow")
            return None
    return wrapper
 
 
def hacker_input(prompt_text: str, default: str = "") -> str:
    """Simulates a terminal input with nice formatting"""
    if default:
        prompt = f"{CYAN}root@spectra:~#{RESET} {prompt_text} [{default}]: "
    else:
        prompt = f"{CYAN}root@spectra:~#{RESET} {prompt_text}: "
 
    user_input = input(prompt).strip()
    return user_input if user_input else default
 
 
def parse_ports(ports_input: str):
    """Turn a ports string into a list[int], or None if invalid.
    Supports comma lists, ranges (80-100), 'all', and 'common'."""
    ports_input = ports_input.lower().strip()
 
    if ports_input == "all":
        return list(range(1, 65536))
    if ports_input == "common":
        return list(COMMON_PORTS.keys())
 
    ports = set()
    try:
        for chunk in ports_input.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start, end = chunk.split("-", 1)
                start, end = int(start), int(end)
                if not (1 <= start <= end <= 65535):
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                p = int(chunk)
                if not (1 <= p <= 65535):
                    raise ValueError
                ports.add(p)
    except ValueError:
        return None
 
    return sorted(ports) if ports else None
 
 
def run_network_port_scan(
    network_target: str,
    scan_kwargs: dict,
):
    """Scan each usable host in a CIDR network."""

    try:
        network = ipaddress.ip_network(
            network_target,
            strict=False,
        )
    except ValueError as exc:
        console.print(
            f"[!] Invalid network: {exc}",
            style="bold red",
        )
        return []

    hosts = list(network.hosts())

    if not hosts:
        console.print(
            "[!] No usable hosts found.",
            style="bold red",
        )
        return []

    if len(hosts) > 256:
        proceed = Confirm.ask(
            f"[!] Network contains {len(hosts)} hosts. Continue?",
            default=False,
        )
        if not proceed:
            console.print(
                "[*] Network scan cancelled.",
                style="yellow",
            )
            return []

    console.print(
        "\n[bold cyan]"
        "============================================================"
        "[/bold cyan]"
    )
    console.print(
        f"[bold green][+] Network Scan: {network}[/bold green]"
    )
    console.print(
        f"[cyan][*] Hosts: {len(hosts)}[/cyan]"
    )
    console.print(
        "[bold cyan]"
        "============================================================"
        "[/bold cyan]\n"
    )

    all_results = []

    for index, host in enumerate(hosts, start=1):
        host_ip = str(host)

        console.print(
            f"\n[bold yellow]"
            f"[{index}/{len(hosts)}] Scanning {host_ip}"
            f"[/bold yellow]"
        )

        try:
            resolved_ip = resolve_host(host_ip)

            scanner = PortScanner(
                host_ip,
                **scan_kwargs,
            )

            scanner.resolved_ip = resolved_ip
            scanner.scan()

            result = scanner.get_results()

            if isinstance(result, dict):
                all_results.append(result)

            scanner.print_summary()

        except KeyboardInterrupt:
            console.print(
                "\n[!] Network scan interrupted.",
                style="yellow",
            )
            break

        except Exception as exc:
            console.print(
                f"[!] {host_ip}: {exc}",
                style="red",
            )

    total_open = sum(
        len(result.get("open_ports", []))
        for result in all_results
        if isinstance(result, dict)
    )

    console.print(
        "\n[bold cyan]"
        "============================================================"
        "[/bold cyan]"
    )
    console.print(
        "[bold green][✓] Network scan complete[/bold green]"
    )
    console.print(
        f"[cyan][*] Hosts processed: "
        f"{len(all_results)}/{len(hosts)}[/cyan]"
    )
    console.print(
        f"[cyan][*] Total open ports: {total_open}[/cyan]"
    )
    console.print(
        "[bold cyan]"
        "============================================================"
        "[/bold cyan]"
    )

    return all_results


@guard_interrupt
def run_port_scan_cli():
    """Interactive Port Scan Menu."""

    console.print(
        "\n[bold cyan]--- PORT SCANNER MODULE ---[/bold cyan]"
    )

    target = hacker_input(
        "Enter Target IP, CIDR, Hostname, or URL"
    )

    if not target:
        console.print(
            "[!] Target required. Returning to menu.",
            style="red",
        )
        return

    target = normalize_target(target)

    if not target:
        console.print(
            "[!] Invalid target.",
            style="red",
        )
        return

    scan_type = Prompt.ask(
        "Scan Type",
        choices=["tcp", "syn", "udp"],
        default="tcp",
    )

    timing = Prompt.ask(
        "Timing Profile",
        choices=["T0", "T1", "T2", "T3", "T4", "T5"],
        default="T3",
    )

    ports_input = hacker_input(
        "Enter Ports (e.g. 80,443,8080 or 1-1024), "
        "'common', or 'all'",
        "common",
    )

    ports = parse_ports(ports_input)

    if ports is None:
        console.print(
            "[!] Invalid port format. Returning to menu.",
            style="red",
        )
        return

    if len(ports) > 5000:
        proceed = Confirm.ask(
            f"[!] {len(ports)} ports selected — this may take a while. Continue?",
            default=True,
        )
        if not proceed:
            console.print(
                "[*] Scan cancelled.",
                style="yellow",
            )
            return

    check_vulns = Confirm.ask(
        "Check for Vulnerabilities?",
        default=False,
    )

    console.print(
        f"\n[+] Spectra Starting Scan on {target}...",
        style="bold yellow",
    )

    scan_kwargs = {
        "timeout": 1.0,
        "threads": 50,
        "scan_type": scan_type,
        "timing": timing,
        "ports": ports,
        "decoys": [],
        "check_vulns": check_vulns,
        "rate_limit": 0,
    }

    try:
        network = ipaddress.ip_network(
            target,
            strict=False,
        )

        console.print(
            f"[cyan][*] CIDR network detected: {network}[/cyan]"
        )

        run_network_port_scan(
            str(network),
            scan_kwargs,
        )
        return

    except ValueError:
        pass

    try:
        resolved_ip = resolve_host(target)

        console.print(
            f"[cyan][*] Resolved: "
            f"{target} -> {resolved_ip}[/cyan]"
        )
    except Exception as exc:
        console.print(
            f"[!] Cannot resolve target: {exc}",
            style="bold red",
        )
        return

    try:
        scanner = PortScanner(
            target,
            **scan_kwargs,
        )

        scanner.resolved_ip = resolved_ip
        scanner.scan()

    except KeyboardInterrupt:
        console.print(
            "[!] Scan interrupted by user.",
            style="yellow",
        )
        return

    except Exception as exc:
        console.print(
            f"[!] Scan failed: {exc}",
            style="bold red",
        )
        return

    scanner.print_summary()

    if not scanner.results:
        console.print(
            "[*] No results to export.",
            style="yellow",
        )
        return

    if not Confirm.ask(
        "Export Results?",
        default=True,
    ):
        return

    fmt = Prompt.ask(
        "Format",
        choices=["json", "html", "csv"],
        default="json",
    )

    filename = hacker_input(
        "Filename (without extension)",
        "scan_report",
    )

    filename = "".join(
        char
        for char in filename
        if char.isalnum() or char in ("_", "-")
    ) or "scan_report"

    full_path = f"{filename}.{fmt}"

    try:
        if fmt == "json":
            scanner.export_json(full_path)
        elif fmt == "html":
            scanner.export_html(full_path)
        else:
            scanner.export_csv(full_path)

        console.print(
            f"[+] Results exported to {full_path}",
            style="green",
        )

    except Exception as exc:
        console.print(
            f"[!] Export failed: {exc}",
            style="bold red",
        )

@guard_interrupt
def run_other_scanners():
    """Interactive menu for Domain, IP, Email, etc."""
    console.print("\n[bold cyan]--- ADVANCED MODULES ---[/bold cyan]")
    mode = Prompt.ask("Select Module", choices=[
        "domain", "ip", "phone", "email", "image", "link", "criminal", "reports"
    ])
 
    rm = ReportManager()
 
    module_map = {
        "domain": ("Enter Domain", DomainScanner),
        "ip": ("Enter IP Address", IPScanner),
        "phone": ("Enter Phone Number", PhoneScanner),
        "email": ("Enter Email Address", EmailScanner),
        "image": ("Enter Image Path", ImageScanner),
        "link": ("Enter Domain for Link Sniffing", LinkScanner),
    }
 
    if mode in module_map:
        prompt_text, scanner_cls = module_map[mode]
        value = hacker_input(prompt_text)
        if not value:
            console.print("[!] Input required. Returning to menu.", style="red")
            return
        try:
            scanner_cls.scan(value, rm)
        except Exception as e:
            console.print(f"[!] {mode.capitalize()} scan failed: {e}", style="bold red")
 
    elif mode == "criminal":
        first = hacker_input("First Name")
        last = hacker_input("Last Name")
        if not first or not last:
            console.print("[!] First and last name are required.", style="red")
            return
        state = hacker_input("State (Optional)")
        city = hacker_input("City")
        try:
            CriminalScanner.scan(first, last, state, city, rm)
        except Exception as e:
            console.print(f"[!] Criminal lookup failed: {e}", style="bold red")
 
    elif mode == "reports":
        action = Prompt.ask("Action", choices=["read", "delete"])
        try:
            if action == "read":
                rm.read_report()
            elif action == "delete":
                if Confirm.ask("Are you sure you want to delete a report?", default=False):
                    rm.delete_report()
                else:
                    console.print("[*] Delete cancelled.", style="yellow")
        except Exception as e:
            console.print(f"[!] Report action failed: {e}", style="bold red")
 
 
MENU_ACTIONS = {
    "1": ("Port Scanner", run_port_scan_cli),
    "2": ("Advanced Modules (Domain/IP/Email/etc)", run_other_scanners),
    "3": ("Protocol Modules (SMB/SNMP/LDAP/RDP/etc)", lambda: run_protocol_modules()),
}
 
 
def print_main_menu():
    console.print("\n[bold]MAIN MENU[/bold]")
    for key, (label, _) in MENU_ACTIONS.items():
        style = "bold green" if key in ("1", "2") else "bold magenta"
        console.print(f"[{style}]{key}.[/{style}] {label}")
    console.print("[bold red]4.[/bold red] Exit")
 
 
def main():
    # Legacy CLI args for backward compatibility / scripting
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="SpectraScan Legacy CLI")
        parser.add_argument("-t", "--target", help="Target")
        parser.add_argument("-d", "--domain", help="Domain")
        parser.add_argument("-i", "--ip", help="IP")
        args, _ = parser.parse_known_args()
 
        if args.target:
            try:
                target = normalize_target(args.target)
                resolved_ip = resolve_host(target)

                scanner = PortScanner(target)
                scanner.resolved_ip = resolved_ip
                scanner.scan()
                scanner.print_summary()

            except Exception as exc:
                console.print(
                    f"[!] Scan failed: {exc}",
                    style="bold red",
                )
                sys.exit(1)

            return
 
    print_banner()
 
    while True:
        print_main_menu()
        try:
            choice = input(f"{CYAN}root@spectra:~#{RESET} Select Option: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[*] Exiting SpectraScan. Stay Anonymous.", style="yellow")
            break
 
        if choice == "4":
            console.print("[*] Exiting SpectraScan. Stay Anonymous.", style="yellow")
            break
        elif choice in MENU_ACTIONS:
            MENU_ACTIONS[choice][1]()
        else:
            console.print("[!] Invalid Option. Please try again.", style="red")
 
 
if __name__ == "__main__":
    main()