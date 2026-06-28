"""
SpectraScan Dark Web Recon Module
=================================
Features:
  - Auto-target type detection (.onion, BTC, ETH, XMR, email, hash, ...)
  - HTTPS/HTTP .onion banner grab (TLS cert, server, page title)
  - BTC first-seen timestamp + balance + tx count (multi-API fallback)
  - Onion link extraction from text
  - Ahmia.fi dark web search (clearnet)
  - Tor SOCKS connectivity check
  - Heuristic risk scoring for BTC addresses

Soft dependencies (auto-detected):
  - pysocks       -> required for .onion
  - requests      -> required for clearnet APIs
  - cryptography  -> richer TLS cert parsing
"""

from __future__ import annotations

import os
import re
import sys
import json
import socket
import ssl
import time
import html as html_mod
import hashlib
import urllib.parse
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Any

try:
    import socks  # PySocks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

console = Console()

# ============================================================
# Constants
# ============================================================

# Onion regex (v3 = 56 chars, v2 = 16 chars -)
ONION_V3_REGEX = re.compile(r'\b[a-z2-7]{56}\.onion\b', re.IGNORECASE)
ONION_V2_REGEX = re.compile(r'\b[a-z2-7]{16}\.onion\b', re.IGNORECASE)

# Crypto regex
BTC_BECH32_REGEX = re.compile(r'^bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{11,87}$', re.IGNORECASE)
BTC_BASE58_REGEX = re.compile(r'^[a-km-zA-HJ-NP-Z1-9]{25,34}$')
ETH_REGEX = re.compile(r'^0x[a-fA-F0-9]{40}$')
XMR_REGEX = re.compile(r'^4[0-9AB][0-9a-zA-Z]{93}$')
LTC_REGEX = re.compile(r'^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$')

# Generic regex
EMAIL_REGEX = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
IPV4_REGEX = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
MD5_REGEX = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_REGEX = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')
PGP_KEY_REGEX = re.compile(r'-----BEGIN PGP PUBLIC KEY BLOCK-----')
PHONE_REGEX = re.compile(r'^\+?\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}$')
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

# Public APIs (no key required)
BLOCKSTREAM_API = "https://blockstream.info/api"
BLOCKCHAIR_API = "https://api.blockchair.com/bitcoin"
BLOCKCHAIN_INFO = "https://blockchain.info"
AHMIA_SEARCH = "https://ahmia.fi/search/?q="

# Tor SOCKS config
TOR_SOCKS_HOST = os.environ.get("TOR_HOST", "127.0.0.1")
TOR_SOCKS_PORT = int(os.environ.get("TOR_PORT", "9050"))
TOR_HTTP_PROXY = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"

# Disposable email domain blocklist (subset)
DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "guerrillamail.com",
    "10minutemail.com", "throwaway.email", "trashmail.com",
    "yopmail.com", "fakeinbox.com", "maildrop.cc",
    "getnada.com", "dispostable.com", "sharklasers.com",
}

# Suspicious TLDs (frequently abused for phishing)
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click"}

# ============================================================
# BTC Address Validation (Base58Check + Bech32/Bech32m)
# ============================================================

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _base58_decode(s: str) -> bytes:
    """Decode a Base58 string to raw bytes."""
    n = 0
    for c in s:
        n = n * 58 + BASE58_ALPHABET.index(c)
    result = []
    while n > 0:
        result.append(n % 256)
        n //= 256
    for c in s:
        if c == "1":
            result.append(0)
        else:
            break
    return bytes(reversed(result))


def _bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + + [ord(x) & 31 for x in hrp]


def _bech32_decode(bech):
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return None, None, None
    if bech.lower() != bech and bech.upper() != bech:
        return None, None, None
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None, None, None
    if not all(x in BECH32_CHARSET for x in bech[pos + 1:]):
        return None, None, None
    hrp = bech[:pos]
    data = [BECH32_CHARSET.find(x) for x in bech[pos + 1:]]
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if const == 1:
        return hrp, data[:-6], "bech32"
    if const == 0x2bc830a3:
        return hrp, data[:-6], "bech32m"
    return None, None, None


def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def validate_btc_address(addr: str) -> bool:
    """Validate a BTC mainnet address (Base58Check or Bech32/Bech32m)."""
    try:
        if addr.lower().startswith("bc1"):
            hrpgot, data, spec = _bech32_decode(addr)
            if hrpgot is None or data is None:
                return False
            if hrpgot != "bc":
                return False
            decoded = _convertbits(data[1:], 5, 8, False)
            if decoded is None or len(decoded) < 2:
                return False
            # witness version 0..16
            if decoded > 16:
                return False
            # v0 -> 20 or 32 bytes (P2WPKH / P2WSH)
            if decoded == 0 and len(decoded) not in (20, 32):
                return False
            # general witness program 2..40 bytes
            if not (2 <= len(decoded) <= 40):
                return False
            # spec <-> witness version coupling (BIP-350)
            if spec == "bech32m" and decoded == 0:
                return False
            if spec == "bech32" and decoded != 0:
                return False
            return True

        # Base58Check path
        if not (26 <= len(addr) <= 35):
            return False
        if not all(c in BASE58_ALPHABET for c in addr):
            return False
        decoded = _base58_decode(addr)
        if len(decoded) != 25:
            return False
        # 0x00 = P2PKH (1...), 0x05 = P2SH (3...)
        if decoded not in (0, 5):
            return False
        payload, checksum = decoded[:-4], decoded[-4:]
        hashed = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
        return hashed[:4] == checksum
    except Exception:
        return False


# ============================================================
# Auto Target Type Detection
# ============================================================

def detect_target_type(target: str) -> Dict:
    """Auto-detect the type of target (onion, crypto, email, hash, ...)."""
    if not target:
        return {"input": target, "type": "empty", "valid": False, "confidence": 0}

    result: Dict[str, Any] = {
        "input": target,
        "type": "unknown",
        "subtype": None,
        "valid": False,
        "confidence": 0,
        "metadata": {},
        "warnings": [],
    }

    # Strip scheme & trailing slash for matching
    norm = target.strip()
    if "://" in norm:
        norm = norm.split("://", 1)
    norm = norm.rstrip("/").split("?", 1).split("#", 1)

    # 1) .onion v3 (most specific)
    m = ONION_V3_REGEX.search(norm)
    if m:
        result.update({
            "type": "onion", "subtype": "v3", "valid": True, "confidence": 100,
            "metadata": {"onion": m.group(0).lower(),
                         "length": len(m.group(0).split("."))},
        })
        return result

    # 2) .onion v2
    m = ONION_V2_REGEX.search(norm)
    if m:
        result.update({
            "type": "onion", "subtype": "v2", "valid": True, "confidence": 100,
            "metadata": {"onion": m.group(0).lower(),
                         "length": len(m.group(0).split("."))},
            "warnings": ["Onion v2 is DEPRECATED - Tor >= 0.4.6 no longer resolves it."],
        })
        return result

    # 3) Email
    if EMAIL_REGEX.match(norm):
        email = norm.lower()
        domain = email.split("@", 1)
        result.update({
            "type": "email", "valid": True, "confidence": 95,
            "metadata": {"email": email, "domain": domain},
        })
        if domain in DISPOSABLE_DOMAINS:
            result["metadata"]["disposable"] = True
            result["warnings"].append("Disposable email domain")
        return result

    # 4) IPv4
    if IPV4_REGEX.match(norm):
        try:
            ip = ipaddress.ip_address(norm)
            result.update({
                "type": "ipv4", "valid": True, "confidence": 95,
                "metadata": {"ip": str(ip), "private": ip.is_private,
                             "loopback": ip.is_loopback},
            })
            return result
        except ValueError:
            pass

    # 5) BTC (full checksum validation)
    if BTC_BECH32_REGEX.match(norm) or BTC_BASE58_REGEX.match(norm):
        if validate_btc_address(norm):
            result.update({
                "type": "crypto", "subtype": "btc", "valid": True, "confidence": 100,
            })
            if norm.lower().startswith("bc1"):
                result["metadata"]["format"] = "Bech32/Bech32m (Native SegWit)"
            elif norm.startswith("1"):
                result["metadata"]["format"] = "Legacy P2PKH"
            else:
                result["metadata"]["format"] = "P2SH (SegWit compatible)"
            return result

    # 6) ETH
    if ETH_REGEX.match(norm):
        result.update({
            "type": "crypto", "subtype": "eth", "valid": True, "confidence": 95,
            "metadata": {"format": "Ethereum"},
        })
        return result

    # 7) XMR
    if XMR_REGEX.match(norm):
        result.update({
            "type": "crypto", "subtype": "xmr", "valid": True, "confidence": 75,
            "metadata": {"format": "Monero"},
            "warnings": ["XMR validation is regex-based only."],
        })
        return result

    # 8) LTC
    if LTC_REGEX.match(norm):
        result.update({
            "type": "crypto", "subtype": "ltc", "valid": True, "confidence": 75,
            "metadata": {"format": "Litecoin"},
            "warnings": ["LTC validation is regex-based only."],
        })
        return result

    # 9) Hashes (longest first to avoid false positives)
    if SHA256_REGEX.match(norm):
        result.update({"type": "hash", "subtype": "sha256",
                       "valid": True, "confidence": 95})
        return result
    if SHA1_REGEX.match(norm):
        result.update({"type": "hash", "subtype": "sha1",
                       "valid": True, "confidence": 95})
        return result
    if MD5_REGEX.match(norm):
        result.update({"type": "hash", "subtype": "md5",
                       "valid": True, "confidence": 90})
        return result

    # 10) PGP key block
    if PGP_KEY_REGEX.search(target):
        result.update({"type": "pgp_key", "valid": True, "confidence": 100})
        return result

    # 11) Phone
    if PHONE_REGEX.match(norm):
        digits = re.sub(r"\D", "", norm)
        if 7 <= len(digits) <= 15:
            result.update({
                "type": "phone", "valid": True, "confidence": 70,
                "metadata": {"digits": digits, "length": len(digits)},
            })
            return result

    # 12) Domain (most generic - checked last)
    if DOMAIN_REGEX.match(norm):
        domain = norm.lower()
        tld = domain.rsplit(".", 1)[-1]
        result.update({
            "type": "domain", "valid": True, "confidence": 80,
            "metadata": {"domain": domain, "tld": tld},
        })
        if tld in SUSPICIOUS_TLDS:
            result["warnings"].append(f"Free/abuse-prone TLD: .{tld}")
        return result

    # 13) Possible username
    if re.match(r"^[a-zA-Z][a-zA-Z0-9_.-]{2,30}$", norm):
        result.update({
            "type": "username", "valid": True, "confidence": 40,
            "warnings": ["Likely a username - confirm via OSINT."],
        })
        return result

    return result


# ============================================================
# Tor Connectivity Check
# ============================================================

def check_tor_connection(timeout: float = 15.0) -> Dict:
    """Verify the Tor SOCKS proxy is reachable and functional."""
    result = {
        "socks_reachable": False,
        "tor_working": False,
        "exit_ip": None,
        "error": None,
    }
    if not SOCKS_AVAILABLE:
        result["error"] = "pysocks not installed (pip install pysocks)"
        return result

    s: Optional[socks.socksocket] = None
    try:
        s = socks.socksocket()
        s.set_proxy(socks.PROXY_TYPE_SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT, rdns=True)
        s.settimeout(timeout)
        s.connect(("check.torproject.org", 443))
        result["socks_reachable"] = True

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(s, server_hostname="check.torproject.org") as ss:
            req = (
                "GET /api/ip HTTP/1.1\r\n"
                "Host: check.torproject.org\r\n"
                "User-Agent: SpectraScan/1.0\r\n"
                "Connection: close\r\n\r\n"
            )
            ss.send(req.encode())
            chunks = []
            while True:
                chunk = ss.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            data = b"".join(chunks)
            if b"\r\n\r\n" in data:
                body = data.split(b"\r\n\r\n", 1)
                try:
                    j = json.loads(body.decode("utf-8", errors="ignore"))
                    result["exit_ip"] = j.get("IP") or j.get("ip")
                except Exception:
                    pass
                result["tor_working"] = True
    except socks.ProxyError as e:
        result["error"] = f"Proxy error: {e}"
    except socket.timeout:
        result["error"] = "Tor connection timed out (is Tor running?)"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return result


# ============================================================
# HTTPS / HTTP .onion Banner Grab
# ============================================================

def _extract_title(body: bytes) -> Optional[str]:
    """Extract <title> from an HTML body and decode entities."""
    try:
        text = body.decode("utf-8", errors="ignore")
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if m:
            return html_mod.unescape(m.group(1)).strip()[:500]
    except Exception:
        pass
    return None


def grab_onion_banner(
    onion: str,
    port: int = 443,
    use_ssl: bool = True,
    timeout: float = 30.0,
    max_body: int = 200_000,
) -> Dict:
    """
    Connect to a .onion service over Tor and grab its HTTP(S) banner.
    Extracts: TLS cert (subject/issuer/SAN/SHA-256), HTTP status,
    headers, page title.
    """
    if not SOCKS_AVAILABLE:
        return {"error": "pysocks not installed (pip install pysocks)"}

    # Parse the target
    target = onion.strip()
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
    else:
        # host[:port][/path]
        host_part = target.split("/", 1)
        path = "/" + target.split("/", 1) if "/" in target else "/"
        if ":" in host_part:
            host, port_str = host_part.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                port = port
        else:
            host = host_part

    if not host:
        return {"error": "No hostname parsed"}

    if not (ONION_V3_REGEX.search(host) or ONION_V2_REGEX.search(host)):
        return {"error": f"Invalid .onion hostname: {host}"}

    result: Dict[str, Any] = {
        "target": onion,
        "host": host,
        "port": port,
        "scheme": "https" if use_ssl else "http",
        "reachable": False,
        "tls": None,
        "http": None,
        "title": None,
        "error": None,
    }

    sock: Optional[socket.socket] = None
    try:
        sock = socks.socksocket()
        sock.set_proxy(socks.PROXY_TYPE_SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT, rdns=True)
        sock.settimeout(timeout)
        sock.connect((host, port))
        result["reachable"] = True

        stream = sock
        if use_ssl:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                stream = ctx.wrap_socket(sock, server_hostname=host)

                tls_info: Dict[str, Any] = {"version": stream.version()}
                if stream.cipher():
                    tls_info["cipher"] = stream.cipher()

                try:
                    der = stream.getpeercert(binary_form=True)
                    if der:
                        tls_info["sha256_fp"] = hashlib.sha256(der).hexdigest()
                        tls_info["sha1_fp"] = hashlib.sha1(der).hexdigest()
                        tls_info["cert_size"] = len(der)

                        if CRYPTOGRAPHY_AVAILABLE:
                            cert = x509.load_der_x509_certificate(der, default_backend())
                            tls_info["subject"] = cert.subject.rfc4514_string()
                            tls_info["issuer"] = cert.issuer.rfc4514_string()
                            try:
                                ext = cert.extensions.get_extension_for_class(
                                    x509.SubjectAlternativeName
                                )
                                tls_info["san"] = [str(d) for d in ext.value]
                            except Exception:
                                pass
                            tls_info["not_before"] = cert.not_valid_before.isoformat()
                            tls_info["not_after"] = cert.not_valid_after.isoformat()
                            delta = (cert.not_valid_after - datetime.utcnow()).days
                            tls_info["days_to_expiry"] = delta
                            tls_info["expired"] = delta < 0
                except Exception as e:
                    tls_info["cert_error"] = str(e)

                result["tls"] = tls_info
            except (ssl.SSLError, OSError) as e:
                result["tls"] = {"error": str(e)}

        # Send HTTP request
        req_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}",
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) SpectraScan/1.0",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Connection: close",
            "",
            "",
        ]
        stream.send("\r\n".join(req_lines).encode())

        chunks, total = [], 0
        while True:
            try:
                chunk = stream.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_body:
                break
        data = b"".join(chunks)

        # Parse HTTP response
        if b"\r\n\r\n" in data:
            header_part, body = data.split(b"\r\n\r\n", 1)
            try:
                lines = header_part.decode("iso-8859-1", errors="ignore").split("\r\n")
                status_line = lines if lines else ""

                headers: Dict[str, str] = {}
                for line in lines[1:]:
                    if ":" in line:
                        k, _, v = line.partition(":")
                        headers[k.strip().lower()] = v.strip()

                http_info: Dict[str, Any] = {
                    "status": status_line,
                    "status_code": int(status_line.split())
                        if len(status_line.split()) >= 2 else None,
                    "headers": headers,
                    "body_size": len(body),
                }
                for k in ("server", "content-type", "content-length",
                          "x-powered-by", "set-cookie", "location",
                          "strict-transport-security"):
                    if k in headers:
                        http_info[k] = headers[k]

                if b"<html" in body.lower() or b"<title" in body.lower():
                    result["title"] = _extract_title(body)

                result["http"] = http_info
            except Exception as e:
                result["http"] = {"parse_error": str(e), "raw_size": len(data)}
        else:
            result["http"] = {"raw_size": len(data), "note": "No HTTP header delimiter"}

    except socks.ProxyError as e:
        result["error"] = f"Tor proxy error: {e}"
    except socket.timeout:
        result["error"] = f"Timeout after {timeout}s (Tor is slow or service down)"
    except ConnectionRefusedError:
        result["error"] = "Connection refused (service down?)"
    except OSError as e:
        result["error"] = f"Network error: {e}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return result


# ============================================================
# BTC First-Seen Timestamp + Balance
# ============================================================

def btc_first_seen(address: str, timeout: float = 20.0) -> Dict:
    """
    Look up when a BTC address first appeared on the blockchain.
    Tries Blockchair -> Blockstream (paginated) -> Blockchain.info.
    """
    result: Dict[str, Any] = {
        "address": address,
        "valid": False,
        "first_seen": None,
        "first_seen_timestamp": None,
        "first_seen_block": None,
        "last_seen": None,
        "tx_count": None,
        "total_received_btc": None,
        "total_sent_btc": None,
        "balance_btc": None,
        "age_days": None,
        "age_years": None,
        "source": None,
        "error": None,
    }

    if not validate_btc_address(address):
        result["error"] = "Invalid BTC address (checksum failed)"
        return result
    result["valid"] = True

    if not REQUESTS_AVAILABLE:
        result["error"] = "requests not installed (pip install requests)"
        return result

    proxies = {"http": TOR_HTTP_PROXY, "https": TOR_HTTP_PROXY} if SOCKS_AVAILABLE else None
    headers = {"User-Agent": "SpectraScan/1.0"}

    def _age(ts: int) -> None:
        result["age_days"] = int((time.time() - ts) / 86400)
        result["age_years"] = round(result["age_days"] / 365.25, 2)

    # 1) Blockchair - returns first_seen_receiving directly
    try:
        r = requests.get(
            f"{BLOCKCHAIR_API}/dashboards/address/{address}",
            timeout=timeout, proxies=proxies, headers=headers,
        )
        if r.status_code == 200:
            payload = r.json()
            addr = payload.get("data", {}).get(address, {})
            addr_meta = addr.get("address", {})
            chain = addr.get("chain_stats", {})

            fs = addr_meta.get("first_seen_receiving")
            if fs:
                result["first_seen"] = fs
                try:
                    dt = datetime.strptime(fs, "%Y-%m-%d %H:%M:%S")
                    result["first_seen_timestamp"] = int(dt.timestamp())
                except Exception:
                    pass
            ls = addr_meta.get("last_seen_receiving")
            if ls:
                result["last_seen"] = ls

            funded = chain.get("funded_txo_sum") or 0
            spent = chain.get("spent_txo_sum") or 0
            result["tx_count"] = chain.get("tx_count")
            result["total_received_btc"] = funded / 1e8
            result["total_sent_btc"] = spent / 1e8
            result["balance_btc"] = (funded - spent) / 1e8
            result["source"] = "blockchair.com"

            if result["first_seen_timestamp"]:
                _age(result["first_seen_timestamp"])
            return result
    except Exception:
        pass

    # 2) Blockstream - paginate to find the oldest tx
    try:
        first_tx = None
        last_txid = None
        for _ in range(20):  # safety cap
            url = f"{BLOCKSTREAM_API}/address/{address}/txs"
            if last_txid:
                url += f"/chain/{last_txid}"
            r = requests.get(url, timeout=timeout, proxies=proxies, headers=headers)
            if r.status_code != 200:
                break
            txs = r.json()
            if not txs:
                break
            if first_tx is None:
                first_tx = txs[-1]  # last in newest-first page = oldest
            if len(txs) < 25:
                break
            last_txid = txs[-1]["txid"]

        if first_tx:
            status = first_tx.get("status", {})
            ts = status.get("block_time")
            if ts:
                result["first_seen_timestamp"] = ts
                result["first_seen"] = datetime.utcfromtimestamp(ts).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
                _age(ts)
            result["first_seen_block"] = status.get("block_height")

        # Chain stats (single call)
        r = requests.get(
            f"{BLOCKSTREAM_API}/address/{address}",
            timeout=timeout, proxies=proxies, headers=headers,
        )
        if r.status_code == 200:
            stats = r.json()
            chain = stats.get("chain_stats", {})
            funded = chain.get("funded_txo_sum") or 0
            spent = chain.get("spent_txo_sum") or 0
            result["tx_count"] = chain.get("tx_count")
            result["total_received_btc"] = funded / 1e8
            result["total_sent_btc"] = spent / 1e8
            result["balance_btc"] = (funded - spent) / 1e8
            result["source"] = "blockstream.info"
        return result
    except Exception:
        pass

    # 3) Blockchain.info fallback
    try:
        r = requests.get(
            f"{BLOCKCHAIN_INFO}/rawaddr/{address}?limit=50",
            timeout=timeout, proxies=proxies, headers=headers,
        )
        if r.status_code == 200:
            data = r.json()
            txs = data.get("txs", [])
            if txs:
                first_tx = txs[-1]
                ts = first_tx.get("time")
                if ts:
                    result["first_seen_timestamp"] = ts
                    result["first_seen"] = datetime.utcfromtimestamp(ts).strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    )
                    _age(ts)
                result["first_seen_block"] = (
                    first_tx.get("block_index") or first_tx.get("block_height")
                )
            result["total_received_btc"] = data.get("total_received", 0)
            result["total_sent_btc"] = data.get("total_sent", 0)
            result["balance_btc"] = data.get("final_balance", 0)
            result["tx_count"] = data.get("n_tx", 0)
            result["source"] = "blockchain.info"
            return result
    except Exception:
        pass

    result["error"] = "All BTC lookup APIs failed (check connectivity)"
    return result


def score_btc_risk(btc_data: Dict) -> Dict:
    """Heuristic risk scoring for a BTC address (0-100, higher = riskier)."""
    risk = {"score": 0, "factors": [], "level": "UNKNOWN"}
    if not btc_data.get("valid"):
        return risk

    age = btc_data.get("age_days")
    if age is not None:
        if age < 1:
            risk["score"] += 30
            risk["factors"].append(f"Brand new address ({age}d old)")
        elif age < 7:
            risk["score"] += 15
            risk["factors"].append(f"Very new address ({age}d old)")
        elif age < 30:
            risk["score"] += 5
            risk["factors"].append(f"Recent address ({age}d old)")

    tx_count = btc_data.get("tx_count") or 0
    if tx_count > 1000:
        risk["score"] -= 10
        risk["factors"].append(f"High tx count ({tx_count}) — likely service/exchange")
    elif tx_count == 0:
        risk["score"] += 5
        risk["factors"].append("No transactions yet (watch-only / unused)")

    balance = btc_data.get("balance_btc") or 0
    if balance > 10 and tx_count < 5:
        risk["score"] += 10
        risk["factors"].append(
            f"Dormant high-balance wallet ({balance} BTC, {tx_count} txs)"
        )

    risk["score"] = max(0, min(100, risk["score"]))

    if risk["score"] >= 60:
        risk["level"] = "HIGH"
    elif risk["score"] >= 30:
        risk["level"] = "MEDIUM"
    else:
        risk["level"] = "LOW"

    return risk


# ============================================================
# Onion Link Extractor
# ============================================================

def extract_onion_links(text: str) -> Dict:
    """Extract .onion v2 and v3 links from arbitrary text."""
    v3 = list({m.group(0).lower() for m in ONION_V3_REGEX.finditer(text)})
    v2 = list({m.group(0).lower() for m in ONION_V2_REGEX.finditer(text)})
    return {"v3": sorted(v3), "v2": sorted(v2), "total": len(v3) + len(v2)}


# ============================================================
# Ahmia Dark Web Search
# ============================================================

def ahmia_search(query: str, timeout: float = 15.0) -> Dict:
    """Search Ahmia.fi (clearnet) for .onion results."""
    if not REQUESTS_AVAILABLE:
        return {"error": "requests not installed"}
    try:
        r = requests.get(
            AHMIA_SEARCH + urllib.parse.quote(query),
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 SpectraScan/1.0"},
        )
        if r.status_code != 200:
            return {"error": f"Ahmia returned HTTP {r.status_code}"}
        links = extract_onion_links(r.text)
        return {
            "query": query,
            "v3_links": links["v3"][:30],
            "v2_links": links["v2"][:30],
            "total": links["total"],
            "source": "ahmia.fi",
        }
    except Exception as e:
        return {"error": f"Ahmia request failed: {e}"}


# ============================================================
# Display Helpers
# ============================================================

def display_detection(detection: Dict) -> None:
    """Pretty-print target detection."""
    if detection.get("type") == "empty":
        console.print("[red]No target provided.[/red]")
        return

    t = detection["type"]
    if t == "unknown":
        console.print(Panel(
            f"[red]Could not identify target type[/red]\n[dim]{detection['input']}[/dim]",
            title="Detection", border_style="red"))
        return

    color_map = {
        "onion": "magenta", "crypto": "yellow", "email": "cyan",
        "ipv4": "blue", "hash": "green", "domain": "cyan",
        "phone": "white", "username": "white", "pgp_key": "green",
    }
    color = color_map.get(t, "white")

    table = Table(title="Target Detection", border_style=color, show_header=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")

    type_label = t.upper()
    if detection.get("subtype"):
        type_label += f" ({detection['subtype'].upper()})"
    table.add_row("Type", f"[{color}]{type_label}[/{color}]")
    table.add_row("Confidence", f"{detection['confidence']}%")
    table.add_row("Valid", "[green]Yes[/green]" if detection["valid"] else "[red]No[/red]")

    for k, v in detection.get("metadata", {}).items():
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v[:5])
        table.add_row(k, str(v)[:80])

    for w in detection.get("warnings", []):
        table.add_row("[yellow]![/yellow]", f"[yellow]{w}[/yellow]")

    console.print(table)


def display_onion_banner(banner: Dict) -> None:
    """Pretty-print onion banner grab result."""
    if banner.get("error"):
        console.print(Panel(
            f"[red]{banner['error']}[/red]",
            title=f"X  {banner.get('host', '?')}",
            border_style="red"))
        return

    t = Table(
        title=f"Onion  {banner['host']}:{banner['port']} ({banner['scheme'].upper()})",
        border_style="magenta", show_header=False,
    )
    t.add_column("Field", style="bold magenta")
    t.add_column("Value")
    t.add_row("Reachable",
              "[green]OK[/green]" if banner["reachable"] else "[red]NO[/red]")

    if banner.get("title"):
        t.add_row("Title", f"[cyan]{banner['title']}[/cyan]")

    if banner.get("tls"):
        tls = banner["tls"]
        if "version" in tls:
            t.add_row("TLS Version", tls["version"])
        if "cipher" in tls and tls["cipher"]:
            t.add_row("Cipher", str(tls["cipher"]))
        if "sha256_fp" in tls:
            t.add_row("Cert SHA-256", f"[dim]{tls['sha256_fp'][:32]}...[/dim]")
        if "subject" in tls:
            t.add_row("Subject", tls["subject"][:70])
        if "issuer" in tls:
            t.add_row("Issuer", tls["issuer"][:70])
        if "san" in tls and tls["san"]:
            t.add_row("SAN", ", ".join(tls["san"][:3]))
        if "days_to_expiry" in tls:
            days = tls["days_to_expiry"]
            color = "red" if days < 0 else ("yellow" if days < 30 else "green")
            label = f"[{color}]{days} days[/{color}]"
            if tls.get("expired"):
                label += " [red](EXPIRED)[/red]"
            t.add_row("Cert Expiry", label)
        if "cert_error" in tls:
            t.add_row("Cert Error", f"[red]{tls['cert_error']}[/red]")

    if banner.get("http"):
        http = banner["http"]
        if "status_code" in http and http["status_code"]:
            code = http["status_code"]
            color = "green" if 200 <= code < 300 else (
                "yellow" if 300 <= code < 400 else "red"
            )
            t.add_row("HTTP Status",
                      f"[{color}]{code}[/{color}]  [dim]{http.get('status', '')}[/dim]")
        for k in ("server", "content-type", "x-powered-by", "location"):
            if k in http:
                t.add_row(k.title(), str(http[k])[:80])
        if "body_size" in http:
            t.add_row("Body Size", f"{http['body_size']:,} bytes")

    console.print(t)


def display_btc(data: Dict, risk: Optional[Dict] = None) -> None:
    """Pretty-print BTC first-seen result."""
    if not data.get("valid"):
        console.print(Panel(
            f"[red]{data.get('error', 'Invalid BTC address')}[/red]",
            title="BTC Lookup", border_style="red"))
        return

    t = Table(title=f"BTC  {data['address']}", border_style="yellow", show_header=False)
    t.add_column("Field", style="bold yellow")
    t.add_column("Value")

    if data.get("first_seen"):
        t.add_row("First Seen", f"[green]{data['first_seen']}[/green]")
    if data.get("first_seen_timestamp"):
        t.add_row("Timestamp", str(data["first_seen_timestamp"]))
    if data.get("first_seen_block"):
        t.add_row("First Block", f"#{data['first_seen_block']:,}")
    if data.get("age_days") is not None:
        t.add_row("Age",
                  f"{data['age_days']:,} days  (~{data.get('age_years', 0)} years)")
    if data.get("last_seen"):
        t.add_row("Last Seen", data["last_seen"])

    t.add_row("", "")
    t.add_row("Tx Count", f"{data.get('tx_count', 0):,}")
    t.add_row("Total Received", f"{data.get('total_received_btc', 0):.8f} BTC")
    t.add_row("Total Sent", f"{data.get('total_sent_btc', 0):.8f} BTC")
    bal = data.get("balance_btc", 0) or 0
    bal_color = "green" if bal > 0 else "white"
    t.add_row("Current Balance", f"[{bal_color}]{bal:.8f} BTC[/{bal_color}]")

    t.add_row("", "")
    t.add_row("[dim]Source[/dim]", f"[dim]{data.get('source', '?')}[/dim]")

    console.print(t)

    if risk and risk.get("factors"):
        rt = Table(title="Risk Heuristics", border_style="red", show_header=False)
        rt.add_column("Score", style="bold")
        rt.add_column("Level")
        rt.add_column("Factors")
        level_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(
            risk["level"], "white")
        rt.add_row(
            str(risk["score"]),
            f"[{level_color}]{risk['level']}[/{level_color}]",
            "\n".join("- " + f for f in risk["factors"]),
        )
        console.print(rt)


# ============================================================
# Menu
# ============================================================

def _prompt(text: str, default: str = "") -> str:
    s = Prompt.ask(f"[cyan]{text}[/cyan]", default=default)
    return s.strip() if s else default


def run_darkweb_menu() -> None:
    """Main Dark Web Recon interactive menu."""
    if not SOCKS_AVAILABLE:
        console.print(
            "[yellow]![/yellow] pysocks not installed. .onion operations disabled.\n"
            "    Install with: [cyan]pip install pysocks[/cyan]")
    if not REQUESTS_AVAILABLE:
        console.print(
            "[yellow]![/yellow] requests not installed. Clearnet API lookups disabled.\n"
            "    Install with: [cyan]pip install requests[/cyan]")

    while True:
        console.print(Panel("""
[bold magenta]DARK WEB RECON MODULE[/bold magenta]

[green]1.[/green]  Auto-Detect & Analyze Target
[green]2.[/green]  HTTPS .onion Banner Grab
[green]3.[/green]  BTC First-Seen Timestamp
[green]4.[/green]  Extract .onion Links from Text
[green]5.[/green]  Ahmia Dark Web Search
[green]6.[/green]  Tor Connectivity Check
[green]7.[/green]  Full Recon (auto-detect + analyze)
[red]8.[/red]  Back
        """, border_style="magenta"))

        choice = Prompt.ask(
            "[bold magenta]Select option[/bold magenta]",
            choices=["1", "2", "3", "4", "5", "6", "7", "8"], default="1")

        try:
            if choice == "1":
                target = _prompt("Enter target")
                if target:
                    display_detection(detect_target_type(target))

            elif choice == "2":
                if not SOCKS_AVAILABLE:
                    console.print("[red]pysocks required for .onion ops.[/red]")
                    continue
                onion = _prompt("Enter .onion URL or hostname")
                if not onion:
                    continue
                port_s = _prompt("Port (443/80/8080)", "443")
                try:
                    port = int(port_s)
                except ValueError:
                    port = 443
                use_ssl = Confirm.ask("Use HTTPS?", default=(port == 443))
                with console.status(f"[magenta]Grabbing banner from {onion}...[/magenta]"):
                    banner = grab_onion_banner(onion, port=port, use_ssl=use_ssl)
                display_onion_banner(banner)

            elif choice == "3":
                addr = _prompt("Enter BTC address")
                if not addr:
                    continue
                with console.status("[yellow]Querying blockchain APIs...[/yellow]"):
                    data = btc_first_seen(addr)
                    risk = score_btc_risk(data) if data.get("valid") else None
                display_btc(data, risk)

            elif choice == "4":
                console.print("[dim]Paste text containing .onion links "
                              "(press Enter twice to finish):[/dim]")
                lines, empty = [], 0
                try:
                    while True:
                        line = input()
                        if not line:
                            empty += 1
                            if empty >= 2:
                                break
                            continue
                        empty = 0
                        lines.append(line)
                except EOFError:
                    pass
                links = extract_onion_links("\n".join(lines))
                console.print(
                    f"[magenta]Found:[/magenta] "
                    f"[green]{len(links['v3'])}[/green] v3, "
                    f"[red]{len(links['v2'])}[/red] v2 (deprecated)")
                if links["v3"]:
                    console.print(Panel(
                        "\n".join(links["v3"]),
                        title="v3 Onion Links", border_style="magenta"))
                if links["v2"]:
                    console.print(Panel(
                        "\n".join(links["v2"]),
                        title="v2 Onion Links (DEPRECATED)",
                        border_style="red"))

            elif choice == "5":
                query = _prompt("Search query")
                if not query:
                    continue
                with console.status("[cyan]Querying Ahmia.fi...[/cyan]"):
                    res = ahmia_search(query)
                if res.get("error"):
                    console.print(f"[red]{res['error']}[/red]")
                else:
                    console.print(f"[green]Found {res['total']} .onion links[/green]")
                    if res["v3_links"]:
                        console.print(Panel(
                            "\n".join(res["v3_links"][:20]),
                            title="v3 Results", border_style="magenta"))
                    if res["v2_links"]:
                        console.print(Panel(
                            "\n".join(res["v2_links"][:20]),
                            title="v2 Results (deprecated)",
                            border_style="red"))

            elif choice == "6":
                with console.status("[magenta]Testing Tor connection...[/magenta]"):
                    tor = check_tor_connection()
                if tor.get("tor_working"):
                    console.print(Panel(
                        f"[green]Tor is working[/green]\n"
                        f"Exit IP: [cyan]{tor['exit_ip']}[/cyan]",
                        border_style="green"))
                else:
                    console.print(Panel(
                        f"[red]Tor not working[/red]\n"
                        f"{tor.get('error', '')}",
                        border_style="red"))

            elif choice == "7":
                target = _prompt("Enter target (auto-detect + analyze)")
                if not target:
                    continue
                det = detect_target_type(target)
                display_detection(det)

                if not det.get("valid"):
                    continue

                t = det["type"]
                st = det.get("subtype")

                if t == "onion":
                    port_s = _prompt("Port (443/80)", "443")
                    try:
                        port = int(port_s)
                    except ValueError:
                        port = 443
                    use_ssl = Confirm.ask("Use HTTPS?", default=(port == 443))
                    with console.status(
                        f"[magenta]Grabbing banner from {target}...[/magenta]"
                    ):
                        banner = grab_onion_banner(
                            target, port=port, use_ssl=use_ssl)
                    display_onion_banner(banner)

                elif t == "crypto" and st == "btc":
                    with console.status("[yellow]Querying BTC...[/yellow]"):
                        data = btc_first_seen(det["input"])
                        risk = score_btc_risk(data)
                    display_btc(data, risk)

                elif t == "email":
                    domain = det["metadata"].get("domain")
                    console.print(f"[cyan]Email domain:[/cyan] {domain}")
                    if domain and not det["metadata"].get("disposable"):
                        with console.status("[cyan]Ahmia lookup...[/cyan]"):
                            res = ahmia_search(domain)
                        if res.get("v3_links"):
                            console.print(
                                f"[green]Found {len(res['v3_links'])} "
                                f"related .onion links[/green]")
                            for link in res["v3_links"][:10]:
                                console.print(f"  [magenta]{link}[/magenta]")
                        elif not res.get("error"):
                            console.print("[yellow]No .onion hits on Ahmia.[/yellow]")

                elif t == "domain":
                    with console.status("[cyan]Ahmia lookup...[/cyan]"):
                        res = ahmia_search(det["input"])
                    if res.get("v3_links"):
                        console.print(
                            f"[green]Found {len(res['v3_links'])} .onion links[/green]")
                        for link in res["v3_links"][:10]:
                            console.print(f"  [magenta]{link}[/magenta]")
                    elif not res.get("error"):
                        console.print("[yellow]No .onion hits on Ahmia.[/yellow]")

                elif t in ("crypto", "hash", "username", "phone", "ipv4", "pgp_key"):
                    console.print(
                        f"[cyan]Hint:[/cyan] For '{t}' targets, consider "
                        "OSINT lookups (namechk, maigret, h8mail, etc.).")

            elif choice == "8":
                break

        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {type(e).__name__}: {e}[/red]")


# Backwards-compat alias
def darkweb_menu() -> None:
    return run_darkweb_menu()


if __name__ == "__main__":
    run_darkweb_menu()