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



import hashlib
import html as html_mod
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------

try:
    import socks  # type: ignore

    SOCKS_AVAILABLE = True
except ImportError:
    socks = None
    SOCKS_AVAILABLE = False

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    REQUESTS_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    x509 = None
    default_backend = None
    CRYPTOGRAPHY_AVAILABLE = False

try:
    import dns.resolver  # type: ignore

    DNS_AVAILABLE = True
except ImportError:
    dns = None
    DNS_AVAILABLE = False

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

MODULE_NAME = "SpectraScan Dark Web Intelligence"
MODULE_VERSION = "2.0.0"

TOR_SOCKS_HOST = os.getenv("TOR_HOST", "127.0.0.1")

try:
    TOR_SOCKS_PORT = int(os.getenv("TOR_PORT", "9050"))
except ValueError:
    TOR_SOCKS_PORT = 9050

TOR_HTTP_PROXY = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"

DEFAULT_TIMEOUT = float(os.getenv("SPECTRASCAN_TIMEOUT", "20"))
MAX_HTTP_BODY = int(os.getenv("SPECTRASCAN_MAX_BODY", "500000"))
MAX_REDIRECTS = int(os.getenv("SPECTRASCAN_MAX_REDIRECTS", "5"))

USER_AGENT = (
    f"SpectraScan/{MODULE_VERSION} "
    "(authorized-security-research)"
)

# ---------------------------------------------------------------------
# Regex
# ---------------------------------------------------------------------

ONION_V3_REGEX = re.compile(
    r"(?<![a-z0-9])"
    r"[a-z2-7]{56}\.onion"
    r"(?![a-z0-9])",
    re.IGNORECASE,
)

ONION_V2_REGEX = re.compile(
    r"(?<![a-z0-9])"
    r"[a-z2-7]{16}\.onion"
    r"(?![a-z0-9])",
    re.IGNORECASE,
)

EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"
)

IPV4_REGEX = re.compile(
    r"(?<![\d.])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![\d.])"
)

IPV6_REGEX = re.compile(
    r"(?<![0-9a-fA-F:])"
    r"(?:[0-9a-fA-F]{1,4}:){2,7}"
    r"[0-9a-fA-F]{0,4}"
    r"(?![0-9a-fA-F:])"
)

DOMAIN_REGEX = re.compile(
    r"\b"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}"
    r"\b"
)

URL_REGEX = re.compile(
    r"\bhttps?://"
    r"[^\s<>'\"\\]+",
    re.IGNORECASE,
)

BTC_BASE58_REGEX = re.compile(
    r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"
)

BTC_BECH32_REGEX = re.compile(
    r"^bc1[ac-hj-np-z02-9]{11,87}$",
    re.IGNORECASE,
)

BTC_TX_REGEX = re.compile(
    r"^[a-fA-F0-9]{64}$"
)

ETH_REGEX = re.compile(
    r"^0x[a-fA-F0-9]{40}$"
)

ETH_TX_REGEX = re.compile(
    r"^0x[a-fA-F0-9]{64}$"
)

XMR_REGEX = re.compile(
    r"^4[0-9AB][0-9a-zA-Z]{93}$"
)

LTC_REGEX = re.compile(
    r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$"
)

MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
SHA512_REGEX = re.compile(r"^[a-fA-F0-9]{128}$")

PGP_BEGIN_REGEX = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----",
    re.IGNORECASE,
)

PHONE_REGEX = re.compile(
    r"^\+?\d{1,3}"
    r"[\s.-]?"
    r"\(?\d{1,4}\)?"
    r"[\s.-]?"
    r"\d{3,4}"
    r"[\s.-]?"
    r"\d{3,4}$"
)

USERNAME_REGEX = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_.-]{2,31}$"
)

DISPOSABLE_DOMAINS = {
    "10minutemail.com",
    "dispostable.com",
    "fakeinbox.com",
    "getnada.com",
    "guerrillamail.com",
    "maildrop.cc",
    "mailinator.com",
    "sharklasers.com",
    "tempmail.com",
    "throwaway.email",
    "trashmail.com",
    "yopmail.com",
}

SUSPICIOUS_TLDS = {
    "cf",
    "click",
    "ga",
    "gq",
    "icu",
    "ml",
    "online",
    "rest",
    "site",
    "top",
    "tk",
    "xyz",
}

SENSITIVE_HEADERS = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "COOP",
    "cross-origin-resource-policy": "CORP",
    "cross-origin-embedder-policy": "COEP",
}

COMMON_TECH_SIGNATURES = {
    "WordPress": [
        r"/wp-content/",
        r"/wp-includes/",
        r"wp-json",
    ],
    "Drupal": [
        r"drupalSettings",
        r"/sites/default/",
        r"Drupal.settings",
    ],
    "Joomla": [
        r"/media/system/",
        r"Joomla!",
    ],
    "PHP": [
        r"\.php(?:[?#]|$)",
        r"PHPSESSID",
    ],
    "Laravel": [
        r"laravel_session",
        r"Laravel",
    ],
    "Django": [
        r"csrftoken",
        r"__django",
    ],
    "nginx": [
        r"nginx",
    ],
    "Apache": [
        r"Apache",
    ],
    "Cloudflare": [
        r"cloudflare",
        r"cf-ray",
    ],
    "React": [
        r"react",
        r"__NEXT_DATA__",
    ],
    "Next.js": [
        r"__NEXT_DATA__",
        r"_next/static/",
    ],
    "Vue.js": [
        r"vue",
        r"__vue__",
    ],
}

# ---------------------------------------------------------------------
# Public APIs
# ---------------------------------------------------------------------

BLOCKSTREAM_API = "https://blockstream.info/api"
BLOCKCHAIR_API = "https://api.blockchair.com/bitcoin"
BLOCKCHAIN_INFO = "https://blockchain.info"
AHMIA_SEARCH = "https://ahmia.fi/search/?q="

# ---------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(
    value: Any,
    default: Optional[float] = None,
) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_target(target: str) -> str:
    """
    Normalize a target without destroying URL path/query information.
    """
    target = (target or "").strip()

    if not target:
        return ""

    if "://" in target:
        parsed = urllib.parse.urlsplit(target)

        host = parsed.hostname or ""

        if parsed.port:
            host = f"{host}:{parsed.port}"

        path = parsed.path or ""

        normalized = f"{parsed.scheme.lower()}://{host}{path}"

        if parsed.query:
            normalized += f"?{parsed.query}"

        return normalized.rstrip("/")

    return target.rstrip("/")


def normalize_domain(value: str) -> str:
    value = value.strip().lower()

    if "://" in value:
        value = urllib.parse.urlsplit(value).hostname or ""

    value = value.split("/", 1)[0]
    value = value.split(":", 1)[0]

    return value.rstrip(".")


def is_valid_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_valid_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def dedupe(items: Iterable[str]) -> List[str]:
    return sorted(
        set(
            x.strip()
            for x in items
            if x and x.strip()
        )
    )


# ---------------------------------------------------------------------
# Base58Check
# ---------------------------------------------------------------------

BASE58_ALPHABET = (
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    "abcdefghijkmnopqrstuvwxyz"
)


def _base58_decode(value: str) -> bytes:
    number = 0

    for char in value:
        number *= 58
        number += BASE58_ALPHABET.index(char)

    decoded = bytearray()

    while number:
        decoded.append(number % 256)
        number //= 256

    leading_zeroes = 0

    for char in value:
        if char == "1":
            leading_zeroes += 1
        else:
            break

    return bytes(
        b"\x00" * leading_zeroes
        + bytes(reversed(decoded))
    )


def validate_btc_base58(address: str) -> bool:
    try:
        if not BTC_BASE58_REGEX.fullmatch(address):
            return False

        decoded = _base58_decode(address)

        if len(decoded) != 25:
            return False

        version = decoded[0]

        if version not in (0x00, 0x05):
            return False

        payload = decoded[:-4]
        checksum = decoded[-4:]

        expected = hashlib.sha256(
            hashlib.sha256(payload).digest()
        ).digest()[:4]

        return checksum == expected

    except (ValueError, IndexError):
        return False


# ---------------------------------------------------------------------
# Bech32 / Bech32m
# ---------------------------------------------------------------------

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: Iterable[int]) -> int:
    generators = [
        0x3B6A57B2,
        0x26508E6D,
        0x1EA119FA,
        0x3D4233DD,
        0x2A1462B3,
    ]

    checksum = 1

    for value in values:
        top = checksum >> 25

        checksum = (
            (checksum & 0x1FFFFFF) << 5
        ) ^ value

        for index in range(5):
            if (top >> index) & 1:
                checksum ^= generators[index]

    return checksum


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return (
        [ord(char) >> 5 for char in hrp]
        + [0]
        + [ord(char) & 31 for char in hrp]
    )


def _bech32_decode(
    value: str,
) -> Tuple[Optional[str], Optional[List[int]], Optional[str]]:
    if not value:
        return None, None, None

    if len(value) > 90:
        return None, None, None

    if value.lower() != value and value.upper() != value:
        return None, None, None

    value = value.lower()

    position = value.rfind("1")

    if position < 1:
        return None, None, None

    if position + 7 > len(value):
        return None, None, None

    data_part = value[position + 1:]

    if not all(
        char in BECH32_CHARSET
        for char in data_part
    ):
        return None, None, None

    hrp = value[:position]

    data = [
        BECH32_CHARSET.find(char)
        for char in data_part
    ]

    polymod = _bech32_polymod(
        _bech32_hrp_expand(hrp) + data
    )

    if polymod == 1:
        spec = "bech32"
    elif polymod == 0x2BC830A3:
        spec = "bech32m"
    else:
        return None, None, None

    return hrp, data[:-6], spec


def _convertbits(
    data: Iterable[int],
    frombits: int,
    tobits: int,
    pad: bool = True,
) -> Optional[List[int]]:
    accumulator = 0
    bits = 0
    result: List[int] = []

    max_value = (1 << tobits) - 1
    max_accumulator = (
        1 << (frombits + tobits - 1)
    ) - 1

    for value in data:
        if value < 0 or value >> frombits:
            return None

        accumulator = (
            (accumulator << frombits) | value
        ) & max_accumulator

        bits += frombits

        while bits >= tobits:
            bits -= tobits

            result.append(
                (accumulator >> bits) & max_value
            )

    if pad:
        if bits:
            result.append(
                (accumulator << (tobits - bits))
                & max_value
            )

    elif bits >= frombits:
        return None

    elif (
        (accumulator << (tobits - bits))
        & max_value
    ):
        return None

    return result


def validate_btc_bech32(address: str) -> bool:
    try:
        hrp, data, spec = _bech32_decode(address)

        if hrp != "bc" or data is None or spec is None:
            return False

        if not data:
            return False

        witness_version = data[0]

        if witness_version > 16:
            return False

        program = _convertbits(
            data[1:],
            5,
            8,
            False,
        )

        if program is None:
            return False

        if not 2 <= len(program) <= 40:
            return False

        if witness_version == 0:
            if spec != "bech32":
                return False

            if len(program) not in (20, 32):
                return False

        else:
            if spec != "bech32m":
                return False

        return True

    except Exception:
        return False


def validate_btc_address(address: str) -> bool:
    address = address.strip()

    if validate_btc_base58(address):
        return True

    return validate_btc_bech32(address)


def btc_address_format(address: str) -> Optional[str]:
    if not validate_btc_address(address):
        return None

    if address.lower().startswith("bc1"):
        return "Bech32 / SegWit"

    if address.startswith("1"):
        return "Legacy P2PKH"

    if address.startswith("3"):
        return "P2SH"

    return "Bitcoin"


# ---------------------------------------------------------------------
# Target detection
# ---------------------------------------------------------------------


def detect_target_type(target: str) -> Dict[str, Any]:
    """
    Detect and normalize a target.

    This function remains compatible with the original SpectraScan API.
    """

    original = target or ""

    result: Dict[str, Any] = {
        "input": original,
        "normalized": normalize_target(original),
        "type": "unknown",
        "subtype": None,
        "valid": False,
        "confidence": 0,
        "metadata": {},
        "warnings": [],
    }

    if not original.strip():
        result["type"] = "empty"
        return result

    normalized = result["normalized"]
    plain = normalized

    # URL
    if re.match(r"^https?://", plain, re.IGNORECASE):
        parsed = urllib.parse.urlsplit(plain)

        hostname = parsed.hostname or ""

        if hostname.endswith(".onion"):
            onion_type = (
                "v3"
                if ONION_V3_REGEX.fullmatch(hostname)
                else "v2"
                if ONION_V2_REGEX.fullmatch(hostname)
                else None
            )

            if onion_type:
                result.update(
                    {
                        "type": "onion",
                        "subtype": onion_type,
                        "valid": True,
                        "confidence": 100,
                        "metadata": {
                            "onion": hostname.lower(),
                            "scheme": parsed.scheme.lower(),
                            "port": parsed.port,
                            "path": parsed.path or "/",
                        },
                    }
                )

                if onion_type == "v2":
                    result["warnings"].append(
                        "Onion v2 is deprecated."
                    )

                return result

        result.update(
            {
                "type": "url",
                "valid": True,
                "confidence": 98,
                "metadata": {
                    "scheme": parsed.scheme.lower(),
                    "host": hostname.lower(),
                    "port": parsed.port,
                    "path": parsed.path or "/",
                },
            }
        )

        return result

    # Onion hostname
    onion_v3 = ONION_V3_REGEX.fullmatch(plain)
    if onion_v3:
        result.update(
            {
                "type": "onion",
                "subtype": "v3",
                "valid": True,
                "confidence": 100,
                "metadata": {
                    "onion": plain.lower(),
                    "length": 56,
                },
            }
        )
        return result

    onion_v2 = ONION_V2_REGEX.fullmatch(plain)
    if onion_v2:
        result.update(
            {
                "type": "onion",
                "subtype": "v2",
                "valid": True,
                "confidence": 100,
                "metadata": {
                    "onion": plain.lower(),
                    "length": 16,
                },
                "warnings": [
                    "Onion v2 is deprecated."
                ],
            }
        )
        return result

    # Email
    email_match = EMAIL_REGEX.fullmatch(plain)

    if email_match:
        email = plain.lower()
        domain = email.rsplit("@", 1)[1]

        result.update(
            {
                "type": "email",
                "valid": True,
                "confidence": 98,
                "metadata": {
                    "email": email,
                    "domain": domain,
                    "disposable": (
                        domain in DISPOSABLE_DOMAINS
                    ),
                },
            }
        )

        if domain in DISPOSABLE_DOMAINS:
            result["warnings"].append(
                "Disposable email domain."
            )

        return result

    # IPv4
    if IPV4_REGEX.fullmatch(plain) and is_valid_ipv4(plain):
        ip = ipaddress.ip_address(plain)

        result.update(
            {
                "type": "ipv4",
                "valid": True,
                "confidence": 99,
                "metadata": {
                    "ip": str(ip),
                    "private": ip.is_private,
                    "loopback": ip.is_loopback,
                    "reserved": ip.is_reserved,
                    "global": ip.is_global,
                },
            }
        )

        return result

    # IPv6
    if ":" in plain and is_valid_ipv6(plain):
        ip = ipaddress.ip_address(plain)

        result.update(
            {
                "type": "ipv6",
                "valid": True,
                "confidence": 99,
                "metadata": {
                    "ip": str(ip),
                    "private": ip.is_private,
                    "loopback": ip.is_loopback,
                    "reserved": ip.is_reserved,
                    "global": ip.is_global,
                },
            }
        )

        return result

    # BTC
    if validate_btc_address(plain):
        result.update(
            {
                "type": "crypto",
                "subtype": "btc",
                "valid": True,
                "confidence": 100,
                "metadata": {
                    "format": btc_address_format(plain),
                },
            }
        )
        return result

    # ETH transaction hash / address
    if ETH_TX_REGEX.fullmatch(plain):
        result.update(
            {
                "type": "crypto",
                "subtype": "eth_tx",
                "valid": True,
                "confidence": 99,
            }
        )
        return result

    if ETH_REGEX.fullmatch(plain):
        result.update(
            {
                "type": "crypto",
                "subtype": "eth",
                "valid": True,
                "confidence": 99,
                "metadata": {
                    "format": "Ethereum address"
                },
            }
        )
        return result

    # XMR
    if XMR_REGEX.fullmatch(plain):
        result.update(
            {
                "type": "crypto",
                "subtype": "xmr",
                "valid": True,
                "confidence": 75,
                "metadata": {
                    "format": "Monero"
                },
                "warnings": [
                    "Monero validation is format-based."
                ],
            }
        )
        return result

    # LTC
    if LTC_REGEX.fullmatch(plain):
        result.update(
            {
                "type": "crypto",
                "subtype": "ltc",
                "valid": True,
                "confidence": 75,
                "metadata": {
                    "format": "Litecoin"
                },
                "warnings": [
                    "Litecoin validation is format-based."
                ],
            }
        )
        return result

    # Hashes
    hash_types = (
        ("sha512", SHA512_REGEX),
        ("sha256", SHA256_REGEX),
        ("sha1", SHA1_REGEX),
        ("md5", MD5_REGEX),
    )

    for name, pattern in hash_types:
        if pattern.fullmatch(plain):
            result.update(
                {
                    "type": "hash",
                    "subtype": name,
                    "valid": True,
                    "confidence": 96,
                }
            )
            return result

    # PGP
    if PGP_BEGIN_REGEX.search(original):
        result.update(
            {
                "type": "pgp_key",
                "valid": True,
                "confidence": 100,
            }
        )
        return result

    # Phone
    if PHONE_REGEX.fullmatch(plain):
        digits = re.sub(r"\D", "", plain)

        if 7 <= len(digits) <= 15:
            result.update(
                {
                    "type": "phone",
                    "valid": True,
                    "confidence": 70,
                    "metadata": {
                        "digits": digits,
                        "length": len(digits),
                    },
                }
            )
            return result

    # Domain
    domain = normalize_domain(plain)

    if DOMAIN_REGEX.fullmatch(domain):
        tld = domain.rsplit(".", 1)[-1]

        result.update(
            {
                "type": "domain",
                "valid": True,
                "confidence": 90,
                "metadata": {
                    "domain": domain,
                    "tld": tld,
                },
            }
        )

        if tld in SUSPICIOUS_TLDS:
            result["warnings"].append(
                f"Abuse-prone/suspicious TLD: .{tld}"
            )

        return result

    # Username
    if USERNAME_REGEX.fullmatch(plain):
        result.update(
            {
                "type": "username",
                "valid": True,
                "confidence": 45,
            }
        )

        result["warnings"].append(
            "Likely username; confirm through OSINT sources."
        )

        return result

    return result


# ---------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------


def extract_iocs(text: str) -> Dict[str, Any]:
    """
    Extract and normalize common public indicators from text.
    """

    text = text or ""

    urls = dedupe(
        URL_REGEX.findall(text)
    )

    onions_v3 = dedupe(
        m.group(0).lower()
        for m in ONION_V3_REGEX.finditer(text)
    )

    onions_v2 = dedupe(
        m.group(0).lower()
        for m in ONION_V2_REGEX.finditer(text)
    )

    emails = dedupe(
        m.group(0).lower()
        for m in EMAIL_REGEX.finditer(text)
    )

    ipv4 = []

    for match in IPV4_REGEX.finditer(text):
        value = match.group(0)

        if is_valid_ipv4(value):
            ipv4.append(value)

    ipv4 = dedupe(ipv4)

    ipv6 = []

    for match in IPV6_REGEX.finditer(text):
        value = match.group(0)

        if is_valid_ipv6(value):
            ipv6.append(value)

    ipv6 = dedupe(ipv6)

    domains = []

    for match in DOMAIN_REGEX.finditer(text):
        value = match.group(0).lower()

        if not value.endswith(".onion"):
            domains.append(value)

    domains = dedupe(domains)

    btc = []
    eth = []
    xmr = []
    ltc = []

    tokens = re.findall(
        r"[A-Za-z0-9]{20,100}",
        text,
    )

    for token in tokens:
        clean = token.strip(".,;:!?()[]{}<>\"'")

        if validate_btc_address(clean):
            btc.append(clean)

        elif ETH_REGEX.fullmatch(clean):
            eth.append(clean)

        elif XMR_REGEX.fullmatch(clean):
            xmr.append(clean)

        elif LTC_REGEX.fullmatch(clean):
            ltc.append(clean)

    hashes = {
        "md5": [],
        "sha1": [],
        "sha256": [],
        "sha512": [],
    }

    for token in re.findall(
        r"\b[a-fA-F0-9]{32,128}\b",
        text,
    ):
        length = len(token)

        if length == 32:
            hashes["md5"].append(token.lower())

        elif length == 40:
            hashes["sha1"].append(token.lower())

        elif length == 64:
            hashes["sha256"].append(token.lower())

        elif length == 128:
            hashes["sha512"].append(token.lower())

    pgp_blocks = re.findall(
        r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?"
        r"-----END PGP PUBLIC KEY BLOCK-----",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    return {
        "urls": dedupe(urls),
        "onions": {
            "v3": dedupe(onions_v3),
            "v2": dedupe(onions_v2),
        },
        "domains": dedupe(domains),
        "ipv4": dedupe(ipv4),
        "ipv6": dedupe(ipv6),
        "emails": dedupe(emails),
        "crypto": {
            "btc": dedupe(btc),
            "eth": dedupe(eth),
            "xmr": dedupe(xmr),
            "ltc": dedupe(ltc),
        },
        "hashes": {
            key: dedupe(value)
            for key, value in hashes.items()
        },
        "pgp_blocks": pgp_blocks,
        "counts": {
            "urls": len(urls),
            "onions": len(onions_v3) + len(onions_v2),
            "domains": len(domains),
            "ipv4": len(ipv4),
            "ipv6": len(ipv6),
            "emails": len(emails),
            "btc": len(btc),
            "eth": len(eth),
            "xmr": len(xmr),
            "ltc": len(ltc),
            "hashes": sum(
                len(value)
                for value in hashes.values()
            ),
            "pgp_blocks": len(pgp_blocks),
        },
    }


def extract_onion_links(text: str) -> Dict[str, Any]:
    iocs = extract_iocs(text)

    return {
        "v3": iocs["onions"]["v3"],
        "v2": iocs["onions"]["v2"],
        "total": (
            len(iocs["onions"]["v3"])
            + len(iocs["onions"]["v2"])
        ),
    }


# ---------------------------------------------------------------------
# Tor
# ---------------------------------------------------------------------


def _tor_socket(
    timeout: float = DEFAULT_TIMEOUT,
):
    if not SOCKS_AVAILABLE:
        raise RuntimeError(
            "PySocks is not installed."
        )

    sock = socks.socksocket()

    sock.set_proxy(
        socks.PROXY_TYPE_SOCKS5,
        TOR_SOCKS_HOST,
        TOR_SOCKS_PORT,
        rdns=True,
    )

    sock.settimeout(timeout)

    return sock


def check_tor_connection(
    timeout: float = 15.0,
) -> Dict[str, Any]:

    result = {
        "socks_reachable": False,
        "tor_working": False,
        "exit_ip": None,
        "error": None,
        "timestamp": utc_now(),
    }

    if not SOCKS_AVAILABLE:
        result["error"] = (
            "pysocks not installed."
        )
        return result

    sock = None

    try:
        sock = _tor_socket(timeout)

        sock.connect(
            ("check.torproject.org", 443)
        )

        result["socks_reachable"] = True

        context = ssl.create_default_context()

        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(
            sock,
            server_hostname="check.torproject.org",
        ) as secure:

            request = (
                "GET /api/ip HTTP/1.1\r\n"
                "Host: check.torproject.org\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            secure.sendall(
                request.encode()
            )

            chunks = []

            while True:
                chunk = secure.recv(8192)

                if not chunk:
                    break

                chunks.append(chunk)

            raw = b"".join(chunks)

            if b"\r\n\r\n" in raw:
                body = raw.split(
                    b"\r\n\r\n",
                    1,
                )[1]

                try:
                    payload = json.loads(
                        body.decode(
                            "utf-8",
                            errors="ignore",
                        )
                    )

                    result["exit_ip"] = (
                        payload.get("IP")
                        or payload.get("ip")
                    )

                except Exception:
                    pass

            result["tor_working"] = True

    except Exception as exc:
        result["error"] = (
            f"{type(exc).__name__}: {exc}"
        )

    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    return result


# ---------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------


def _parse_http_headers(
    header_bytes: bytes,
) -> Tuple[str, Optional[int], Dict[str, str]]:

    text = header_bytes.decode(
        "iso-8859-1",
        errors="replace",
    )

    lines = text.split("\r\n")

    status_line = lines[0] if lines else ""

    status_code = None

    parts = status_line.split()

    if len(parts) >= 2:
        status_code = safe_int(parts[1])

    headers: Dict[str, str] = {}

    for line in lines[1:]:
        if ":" not in line:
            continue

        key, value = line.split(
            ":",
            1,
        )

        headers[key.strip().lower()] = (
            value.strip()
        )

    return (
        status_line,
        status_code,
        headers,
    )


def _extract_title(
    body: bytes,
) -> Optional[str]:

    try:
        text = body.decode(
            "utf-8",
            errors="ignore",
        )

        match = re.search(
            r"<title[^>]*>(.*?)</title>",
            text,
            flags=re.IGNORECASE | re.DOTALL,
        )

        if not match:
            return None

        title = html_mod.unescape(
            match.group(1)
        )

        title = re.sub(
            r"\s+",
            " ",
            title,
        ).strip()

        return title[:500] or None

    except Exception:
        return None


def _security_header_analysis(
    headers: Dict[str, str],
    scheme: str,
) -> Dict[str, Any]:

    present = {}
    missing = []

    for header, label in SECURITY_HEADERS.items():
        if header in headers:
            present[label] = headers[header]
        else:
            missing.append(label)

    score = 100

    for header in missing:
        if header == "HSTS" and scheme == "https":
            score -= 20
        elif header in (
            "CSP",
            "X-Frame-Options",
            "X-Content-Type-Options",
        ):
            score -= 15
        else:
            score -= 5

    if scheme != "https":
        score -= 20

    return {
        "score": max(0, min(100, score)),
        "present": present,
        "missing": missing,
    }


def _technology_fingerprint(
    body: bytes,
    headers: Dict[str, str],
) -> List[Dict[str, Any]]:

    text = body.decode(
        "utf-8",
        errors="ignore",
    )

    combined = (
        text[:200000]
        + "\n"
        + "\n".join(
            f"{k}: {v}"
            for k, v in headers.items()
        )
    )

    findings = []

    for technology, signatures in (
        COMMON_TECH_SIGNATURES.items()
    ):
        matches = []

        for signature in signatures:
            try:
                if re.search(
                    signature,
                    combined,
                    flags=re.IGNORECASE,
                ):
                    matches.append(signature)
            except re.error:
                continue

        if matches:
            findings.append(
                {
                    "technology": technology,
                    "confidence": min(
                        95,
                        50 + len(matches) * 15,
                    ),
                    "evidence": matches,
                }
            )

    return findings


# ---------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------


def _parse_tls_certificate(
    der: bytes,
) -> Dict[str, Any]:

    info: Dict[str, Any] = {
        "sha256_fp": hashlib.sha256(
            der
        ).hexdigest(),

        "sha1_fp": hashlib.sha1(
            der
        ).hexdigest(),

        "cert_size": len(der),
    }

    if not CRYPTOGRAPHY_AVAILABLE:
        info["parser"] = "openssl/native"
        return info

    try:
        certificate = (
            x509.load_der_x509_certificate(
                der,
                default_backend(),
            )
        )

        info["subject"] = (
            certificate.subject.rfc4514_string()
        )

        info["issuer"] = (
            certificate.issuer.rfc4514_string()
        )

        info["serial"] = str(
            certificate.serial_number
        )

        info["version"] = (
            str(certificate.version)
        )

        try:
            san = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )

            info["san"] = [
                str(value)
                for value in san.value
            ]

        except Exception:
            info["san"] = []

        not_before = (
            certificate.not_valid_before_utc
            if hasattr(
                certificate,
                "not_valid_before_utc",
            )
            else certificate.not_valid_before.replace(
                tzinfo=timezone.utc
            )
        )

        not_after = (
            certificate.not_valid_after_utc
            if hasattr(
                certificate,
                "not_valid_after_utc",
            )
            else certificate.not_valid_after.replace(
                tzinfo=timezone.utc
            )
        )

        info["not_before"] = (
            not_before.isoformat()
        )

        info["not_after"] = (
            not_after.isoformat()
        )

        now = datetime.now(timezone.utc)

        days = (
            not_after - now
        ).days

        info["days_to_expiry"] = days
        info["expired"] = days < 0

        info["self_signed"] = (
            certificate.subject
            == certificate.issuer
        )

    except Exception as exc:
        info["cert_error"] = str(exc)

    return info


# ---------------------------------------------------------------------
# Onion reconnaissance
# ---------------------------------------------------------------------


def _parse_onion_target(
    target: str,
    port: int = 443,
    use_ssl: bool = True,
) -> Dict[str, Any]:

    target = target.strip()

    if "://" in target:
        parsed = urllib.parse.urlsplit(
            target
        )

        host = parsed.hostname

        if not host:
            raise ValueError(
                "Unable to parse hostname."
            )

        scheme = parsed.scheme.lower()

        use_ssl = scheme == "https"

        actual_port = (
            parsed.port
            or (443 if use_ssl else 80)
        )

        path = parsed.path or "/"

        if parsed.query:
            path += f"?{parsed.query}"

        return {
            "host": host.lower(),
            "port": actual_port,
            "scheme": scheme,
            "path": path,
        }

    parsed = urllib.parse.urlsplit(
        f"//{target}",
    )

    host = parsed.hostname

    if not host:
        raise ValueError(
            "Unable to parse hostname."
        )

    actual_port = (
        parsed.port
        or port
    )

    path = parsed.path or "/"

    if parsed.query:
        path += f"?{parsed.query}"

    return {
        "host": host.lower(),
        "port": actual_port,
        "scheme": (
            "https"
            if use_ssl
            else "http"
        ),
        "path": path,
    }


def grab_onion_banner(
    onion: str,
    port: int = 443,
    use_ssl: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
    max_body: int = MAX_HTTP_BODY,
) -> Dict[str, Any]:

    result: Dict[str, Any] = {
        "target": onion,
        "host": None,
        "port": port,
        "scheme": (
            "https"
            if use_ssl
            else "http"
        ),
        "reachable": False,
        "tls": None,
        "http": None,
        "title": None,
        "security": None,
        "technologies": [],
        "iocs": None,
        "error": None,
        "timestamp": utc_now(),
    }

    if not SOCKS_AVAILABLE:
        result["error"] = (
            "pysocks not installed."
        )
        return result

    try:
        parsed = _parse_onion_target(
            onion,
            port=port,
            use_ssl=use_ssl,
        )

        host = parsed["host"]
        actual_port = parsed["port"]
        scheme = parsed["scheme"]
        path = parsed["path"]

        result["host"] = host
        result["port"] = actual_port
        result["scheme"] = scheme

        if not (
            ONION_V3_REGEX.fullmatch(host)
            or ONION_V2_REGEX.fullmatch(host)
        ):
            result["error"] = (
                f"Invalid onion hostname: {host}"
            )
            return result

        sock = _tor_socket(timeout)

        try:
            sock.connect(
                (host, actual_port)
            )

            result["reachable"] = True

            stream = sock

            if scheme == "https":
                context = (
                    ssl.create_default_context()
                )

                context.check_hostname = False
                context.verify_mode = (
                    ssl.CERT_NONE
                )

                stream = context.wrap_socket(
                    sock,
                    server_hostname=host,
                )

                tls = {
                    "version": stream.version(),
                    "cipher": stream.cipher(),
                }

                try:
                    der = (
                        stream.getpeercert(
                            binary_form=True
                        )
                    )

                    if der:
                        tls.update(
                            _parse_tls_certificate(
                                der
                            )
                        )

                except Exception as exc:
                    tls["cert_error"] = str(
                        exc
                    )

                result["tls"] = tls

            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                "Accept: text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            stream.sendall(
                request.encode()
            )

            chunks = []
            total = 0

            while total < max_body:
                try:
                    chunk = stream.recv(
                        min(8192, max_body - total)
                    )
                except socket.timeout:
                    break

                if not chunk:
                    break

                chunks.append(chunk)
                total += len(chunk)

            raw = b"".join(chunks)

            if b"\r\n\r\n" not in raw:
                result["http"] = {
                    "raw_size": len(raw),
                    "error": (
                        "No HTTP header delimiter."
                    ),
                }
                return result

            header_bytes, body = raw.split(
                b"\r\n\r\n",
                1,
            )

            (
                status_line,
                status_code,
                headers,
            ) = _parse_http_headers(
                header_bytes
            )

            # Don't expose complete cookies.
            safe_headers = dict(headers)

            if "set-cookie" in safe_headers:
                safe_headers["set-cookie"] = (
                    "[redacted]"
                )

            http_info = {
                "status": status_line,
                "status_code": status_code,
                "headers": safe_headers,
                "body_size": len(body),
                "content_type": headers.get(
                    "content-type"
                ),
                "server": headers.get(
                    "server"
                ),
                "location": headers.get(
                    "location"
                ),
            }

            result["http"] = http_info

            result["title"] = _extract_title(
                body
            )

            result["security"] = (
                _security_header_analysis(
                    headers,
                    scheme,
                )
            )

            result["technologies"] = (
                _technology_fingerprint(
                    body,
                    headers,
                )
            )

            result["iocs"] = extract_iocs(
                body.decode(
                    "utf-8",
                    errors="ignore",
                )
            )

        finally:
            try:
                sock.close()
            except Exception:
                pass

    except Exception as exc:
        result["error"] = (
            f"{type(exc).__name__}: {exc}"
        )

    return result


# ---------------------------------------------------------------------
# Redirect analysis
# ---------------------------------------------------------------------


def analyze_redirects(
    target: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_redirects: int = MAX_REDIRECTS,
    through_tor: bool = False,
) -> Dict[str, Any]:

    result = {
        "target": target,
        "chain": [],
        "final_url": None,
        "redirect_count": 0,
        "error": None,
    }

    if not REQUESTS_AVAILABLE:
        result["error"] = (
            "requests not installed."
        )
        return result

    proxies = (
        {
            "http": TOR_HTTP_PROXY,
            "https": TOR_HTTP_PROXY,
        }
        if through_tor and SOCKS_AVAILABLE
        else None
    )

    current = target

    for _ in range(max_redirects + 1):
        try:
            response = requests.get(
                current,
                timeout=timeout,
                allow_redirects=False,
                proxies=proxies,
                headers={
                    "User-Agent": USER_AGENT
                },
            )

            location = response.headers.get(
                "location"
            )

            entry = {
                "url": current,
                "status_code": response.status_code,
                "location": location,
            }

            result["chain"].append(entry)

            if not location:
                result["final_url"] = current
                break

            current = urllib.parse.urljoin(
                current,
                location,
            )

            result["redirect_count"] += 1

        except Exception as exc:
            result["error"] = str(exc)
            break

    return result


# ---------------------------------------------------------------------
# Domain / DNS intelligence
# ---------------------------------------------------------------------


def domain_intelligence(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:

    domain = normalize_domain(domain)

    result: Dict[str, Any] = {
        "domain": domain,
        "valid": bool(
            DOMAIN_REGEX.fullmatch(domain)
        ),
        "records": {},
        "error": None,
        "timestamp": utc_now(),
    }

    if not result["valid"]:
        result["error"] = (
            "Invalid domain."
        )
        return result

    if not DNS_AVAILABLE:
        result["error"] = (
            "dnspython not installed."
        )
        return result

    record_types = (
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
        "SOA",
    )

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for record_type in record_types:
        try:
            answers = resolver.resolve(
                domain,
                record_type,
            )

            values = []

            for answer in answers:
                values.append(
                    str(answer)
                )

            result["records"][
                record_type
            ] = values

        except Exception:
            result["records"][
                record_type
            ] = []

    txt_records = result[
        "records"
    ].get("TXT", [])

    txt_joined = " ".join(
        txt_records
    ).lower()

    result["email_security"] = {
        "spf": "v=spf1" in txt_joined,
        "dmarc_hint": False,
    }

    try:
        dmarc = resolver.resolve(
            f"_dmarc.{domain}",
            "TXT",
        )

        result["email_security"][
            "dmarc_hint"
        ] = any(
            "v=dmarc1"
            in str(record).lower()
            for record in dmarc
        )

    except Exception:
        pass

    return result


# ---------------------------------------------------------------------
# Email intelligence
# ---------------------------------------------------------------------


def email_intelligence(
    email: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:

    email = email.strip().lower()

    detection = detect_target_type(
        email
    )

    if detection["type"] != "email":
        return {
            "email": email,
            "valid": False,
            "error": "Invalid email address.",
        }

    domain = detection[
        "metadata"
    ]["domain"]

    result = {
        "email": email,
        "valid": True,
        "domain": domain,
        "disposable": (
            domain in DISPOSABLE_DOMAINS
        ),
        "domain_intelligence": None,
        "timestamp": utc_now(),
    }

    result["domain_intelligence"] = (
        domain_intelligence(
            domain,
            timeout=timeout,
        )
    )

    return result


# ---------------------------------------------------------------------
# Ahmia
# ---------------------------------------------------------------------


def ahmia_search(
    query: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:

    if not REQUESTS_AVAILABLE:
        return {
            "error": (
                "requests not installed."
            )
        }

    query = query.strip()

    if not query:
        return {
            "error": "Empty search query."
        }

    try:
        response = requests.get(
            AHMIA_SEARCH
            + urllib.parse.quote_plus(query),
            timeout=timeout,
            headers={
                "User-Agent": USER_AGENT
            },
        )

        if response.status_code != 200:
            return {
                "error": (
                    f"Ahmia returned HTTP "
                    f"{response.status_code}"
                )
            }

        links = extract_onion_links(
            response.text
        )

        return {
            "query": query,
            "v3_links": links["v3"][:50],
            "v2_links": links["v2"][:50],
            "total": links["total"],
            "source": "ahmia.fi",
            "timestamp": utc_now(),
        }

    except Exception as exc:
        return {
            "error": (
                f"Ahmia request failed: {exc}"
            )
        }


# ---------------------------------------------------------------------
# BTC intelligence
# ---------------------------------------------------------------------


def btc_first_seen(
    address: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:

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
        "timestamp": utc_now(),
    }

    address = address.strip()

    if not validate_btc_address(address):
        result["error"] = (
            "Invalid BTC address."
        )
        return result

    result["valid"] = True

    if not REQUESTS_AVAILABLE:
        result["error"] = (
            "requests not installed."
        )
        return result

    proxies = (
        {
            "http": TOR_HTTP_PROXY,
            "https": TOR_HTTP_PROXY,
        }
        if SOCKS_AVAILABLE
        else None
    )

    headers = {
        "User-Agent": USER_AGENT
    }

    def set_age(timestamp: int) -> None:
        age_days = max(
            0,
            int(
                (
                    time.time()
                    - timestamp
                )
                / 86400
            ),
        )

        result["age_days"] = age_days
        result["age_years"] = round(
            age_days / 365.25,
            2,
        )

    # Blockchair
    try:
        response = requests.get(
            f"{BLOCKCHAIR_API}/dashboards/address/"
            f"{address}",
            timeout=timeout,
            proxies=proxies,
            headers=headers,
        )

        if response.status_code == 200:
            payload = response.json()

            data = payload.get(
                "data",
                {},
            ).get(
                address,
                {},
            )

            address_meta = data.get(
                "address",
                {},
            )

            chain = data.get(
                "chain_stats",
                {},
            )

            first_seen = address_meta.get(
                "first_seen_receiving"
            )

            if first_seen:
                result["first_seen"] = (
                    first_seen
                )

                try:
                    parsed = datetime.strptime(
                        first_seen,
                        "%Y-%m-%d %H:%M:%S",
                    ).replace(
                        tzinfo=timezone.utc
                    )

                    timestamp = int(
                        parsed.timestamp()
                    )

                    result[
                        "first_seen_timestamp"
                    ] = timestamp

                    set_age(timestamp)

                except Exception:
                    pass

            result["last_seen"] = (
                address_meta.get(
                    "last_seen_receiving"
                )
            )

            funded = (
                chain.get(
                    "funded_txo_sum"
                )
                or 0
            )

            spent = (
                chain.get(
                    "spent_txo_sum"
                )
                or 0
            )

            result["tx_count"] = (
                chain.get("tx_count")
            )

            result[
                "total_received_btc"
            ] = funded / 1e8

            result[
                "total_sent_btc"
            ] = spent / 1e8

            result[
                "balance_btc"
            ] = (funded - spent) / 1e8

            result["source"] = (
                "blockchair"
            )

            return result

    except Exception:
        pass

    # Blockstream
    try:
        first_tx = None
        cursor = None

        for _ in range(20):
            url = (
                f"{BLOCKSTREAM_API}/address/"
                f"{address}/txs"
            )

            if cursor:
                url += (
                    f"/chain/{cursor}"
                )

            response = requests.get(
                url,
                timeout=timeout,
                proxies=proxies,
                headers=headers,
            )

            if response.status_code != 200:
                break

            transactions = response.json()

            if not transactions:
                break

            first_tx = transactions[-1]

            if len(transactions) < 25:
                break

            cursor = transactions[
                -1
            ].get("txid")

            if not cursor:
                break

        if first_tx:
            status = first_tx.get(
                "status",
                {},
            )

            block_time = status.get(
                "block_time"
            )

            if block_time:
                result[
                    "first_seen_timestamp"
                ] = block_time

                result["first_seen"] = (
                    datetime.fromtimestamp(
                        block_time,
                        timezone.utc,
                    ).isoformat()
                )

                set_age(block_time)

            result[
                "first_seen_block"
            ] = status.get(
                "block_height"
            )

        response = requests.get(
            f"{BLOCKSTREAM_API}/address/"
            f"{address}",
            timeout=timeout,
            proxies=proxies,
            headers=headers,
        )

        if response.status_code == 200:
            stats = response.json()

            chain = stats.get(
                "chain_stats",
                {},
            )

            funded = (
                chain.get(
                    "funded_txo_sum"
                )
                or 0
            )

            spent = (
                chain.get(
                    "spent_txo_sum"
                )
                or 0
            )

            result["tx_count"] = (
                chain.get("tx_count")
            )

            result[
                "total_received_btc"
            ] = funded / 1e8

            result[
                "total_sent_btc"
            ] = spent / 1e8

            result[
                "balance_btc"
            ] = (funded - spent) / 1e8

            result["source"] = (
                "blockstream"
            )

            return result

    except Exception:
        pass

    # Blockchain.info
    try:
        response = requests.get(
            f"{BLOCKCHAIN_INFO}/rawaddr/"
            f"{address}?limit=50",
            timeout=timeout,
            proxies=proxies,
            headers=headers,
        )

        if response.status_code == 200:
            data = response.json()

            transactions = data.get(
                "txs",
                [],
            )

            if transactions:
                first_tx = transactions[-1]

                timestamp = first_tx.get(
                    "time"
                )

                if timestamp:
                    result[
                        "first_seen_timestamp"
                    ] = timestamp

                    result["first_seen"] = (
                        datetime.fromtimestamp(
                            timestamp,
                            timezone.utc,
                        ).isoformat()
                    )

                    set_age(timestamp)

                result[
                    "first_seen_block"
                ] = (
                    first_tx.get(
                        "block_index"
                    )
                    or first_tx.get(
                        "block_height"
                    )
                )

            result[
                "total_received_btc"
            ] = (
                data.get(
                    "total_received",
                    0,
                )
                / 1e8
            )

            result[
                "total_sent_btc"
            ] = (
                data.get(
                    "total_sent",
                    0,
                )
                / 1e8
            )

            result[
                "balance_btc"
            ] = (
                data.get(
                    "final_balance",
                    0,
                )
                / 1e8
            )

            result["tx_count"] = data.get(
                "n_tx",
                0,
            )

            result["source"] = (
                "blockchain.info"
            )

            return result

    except Exception:
        pass

    result["error"] = (
        "All BTC APIs failed."
    )

    return result


# ---------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------


def score_btc_risk(
    btc_data: Dict[str, Any],
) -> Dict[str, Any]:

    risk = {
        "score": 0,
        "level": "LOW",
        "confidence": 50,
        "factors": [],
    }

    if not btc_data.get("valid"):
        risk["level"] = "UNKNOWN"
        risk["confidence"] = 0
        return risk

    age = btc_data.get(
        "age_days"
    )

    tx_count = (
        btc_data.get("tx_count")
        or 0
    )

    balance = (
        btc_data.get("balance_btc")
        or 0
    )

    if age is not None:
        if age < 1:
            risk["score"] += 30
            risk["factors"].append(
                "Address first observed less than 1 day ago."
            )

        elif age < 7:
            risk["score"] += 15
            risk["factors"].append(
                "Very recently observed address."
            )

        elif age < 30:
            risk["score"] += 5
            risk["factors"].append(
                "Recently observed address."
            )

    if tx_count == 0:
        risk["score"] += 5
        risk["factors"].append(
            "No observed transactions."
        )

    elif tx_count > 1000:
        risk["score"] -= 10
        risk["factors"].append(
            "High transaction volume; "
            "could represent a service or exchange."
        )

    if balance > 10 and tx_count < 5:
        risk["score"] += 10
        risk["factors"].append(
            "High balance with low transaction count."
        )

    risk["score"] = max(
        0,
        min(
            100,
            risk["score"],
        ),
    )

    if risk["score"] >= 60:
        risk["level"] = "HIGH"

    elif risk["score"] >= 30:
        risk["level"] = "MEDIUM"

    else:
        risk["level"] = "LOW"

    risk["confidence"] = min(
        95,
        50 + len(
            risk["factors"]
        ) * 10,
    )

    return risk


def calculate_target_risk(
    detection: Dict[str, Any],
    recon: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    score = 0
    factors: List[str] = []

    if not detection.get("valid"):
        return {
            "score": 0,
            "level": "UNKNOWN",
            "confidence": 0,
            "factors": [],
        }

    target_type = detection.get(
        "type"
    )

    warnings = detection.get(
        "warnings",
        [],
    )

    score += min(
        len(warnings) * 5,
        20,
    )

    factors.extend(
        warnings
    )

    if target_type == "onion":
        score += 10
        factors.append(
            "Target is a Tor onion service."
        )

        if detection.get(
            "subtype"
        ) == "v2":
            score += 20
            factors.append(
                "Deprecated onion v2 service."
            )

    elif target_type == "email":
        if detection.get(
            "metadata",
            {},
        ).get("disposable"):
            score += 25
            factors.append(
                "Disposable email domain."
            )

    elif target_type == "domain":
        tld = detection.get(
            "metadata",
            {},
        ).get("tld")

        if tld in SUSPICIOUS_TLDS:
            score += 15
            factors.append(
                f"Abuse-prone TLD: .{tld}"
            )

    if recon:
        security = recon.get(
            "security"
        )

        if security:
            security_score = (
                security.get(
                    "score",
                    100,
                )
            )

            if security_score < 50:
                score += 15
                factors.append(
                    "Weak HTTP security-header posture."
                )

        tls = recon.get("tls")

        if tls and tls.get("expired"):
            score += 20
            factors.append(
                "Expired TLS certificate."
            )

    score = max(
        0,
        min(
            100,
            score,
        ),
    )

    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "confidence": min(
            95,
            50 + len(factors) * 8,
        ),
        "factors": factors,
    }


# ---------------------------------------------------------------------
# Full target reconnaissance
# ---------------------------------------------------------------------


def full_recon(
    target: str,
    timeout: float = DEFAULT_TIMEOUT,
    perform_network: bool = True,
) -> Dict[str, Any]:

    started = time.time()

    detection = detect_target_type(
        target
    )

    report: Dict[str, Any] = {
        "tool": "SpectraScan",
        "module": MODULE_NAME,
        "module_version": MODULE_VERSION,
        "timestamp": utc_now(),
        "target": target,
        "detection": detection,
        "recon": {},
        "iocs": None,
        "risk": None,
        "errors": [],
    }

    if not detection.get("valid"):
        report["risk"] = {
            "score": 0,
            "level": "UNKNOWN",
            "confidence": 0,
            "factors": [
                "Target could not be validated."
            ],
        }

        return report

    target_type = detection["type"]
    subtype = detection.get("subtype")

    if not perform_network:
        report["risk"] = (
            calculate_target_risk(
                detection
            )
        )
        return report

    try:
        if target_type == "onion":
            report["recon"] = (
                grab_onion_banner(
                    target,
                    timeout=timeout,
                )
            )

        elif target_type == "domain":
            report["recon"] = (
                domain_intelligence(
                    target,
                    timeout=timeout,
                )
            )

        elif target_type == "url":
            report["recon"] = (
                analyze_redirects(
                    target,
                    timeout=timeout,
                )
            )

        elif target_type == "email":
            report["recon"] = (
                email_intelligence(
                    target,
                    timeout=timeout,
                )
            )

        elif (
            target_type == "crypto"
            and subtype == "btc"
        ):
            btc = btc_first_seen(
                target,
                timeout=timeout,
            )

            report["recon"] = btc

            report["risk"] = (
                score_btc_risk(btc)
            )

        elif target_type in (
            "hash",
            "username",
            "phone",
            "ipv4",
            "ipv6",
            "pgp_key",
        ):
            report["recon"] = {
                "note": (
                    "Target recognized. "
                    "No intrusive lookup performed."
                )
            }

    except Exception as exc:
        report["errors"].append(
            f"{type(exc).__name__}: {exc}"
        )

    if report["risk"] is None:
        report["risk"] = (
            calculate_target_risk(
                detection,
                report.get("recon"),
            )
        )

    report["duration_seconds"] = round(
        time.time() - started,
        3,
    )

    return report


# ---------------------------------------------------------------------
# JSON reporting
# ---------------------------------------------------------------------


def save_json_report(
    report: Dict[str, Any],
    output_path: str,
) -> str:

    output_path = os.path.abspath(
        os.path.expanduser(
            output_path
        )
    )

    directory = os.path.dirname(
        output_path
    )

    if directory:
        os.makedirs(
            directory,
            exist_ok=True,
        )

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    return output_path


# ---------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------


def display_detection(
    detection: Dict[str, Any],
) -> None:

    if detection.get("type") == "empty":
        console.print(
            "[red]No target provided.[/red]"
        )
        return

    target_type = detection.get(
        "type",
        "unknown",
    )

    if target_type == "unknown":
        console.print(
            Panel(
                f"[red]Unknown target[/red]\n"
                f"{detection.get('input', '')}",
                title="Detection",
                border_style="red",
            )
        )
        return

    colors = {
        "onion": "magenta",
        "crypto": "yellow",
        "email": "cyan",
        "ipv4": "blue",
        "ipv6": "blue",
        "hash": "green",
        "domain": "cyan",
        "url": "cyan",
        "phone": "white",
        "username": "white",
        "pgp_key": "green",
    }

    color = colors.get(
        target_type,
        "white",
    )

    table = Table(
        title="Target Detection",
        border_style=color,
        show_header=False,
    )

    table.add_column(
        "Field",
        style="bold",
    )

    table.add_column("Value")

    label = target_type.upper()

    if detection.get("subtype"):
        label += (
            f" ({detection['subtype'].upper()})"
        )

    table.add_row(
        "Type",
        f"[{color}]{label}[/{color}]",
    )

    table.add_row(
        "Confidence",
        f"{detection.get('confidence', 0)}%",
    )

    table.add_row(
        "Valid",
        (
            "[green]YES[/green]"
            if detection.get("valid")
            else "[red]NO[/red]"
        ),
    )

    if detection.get("normalized"):
        table.add_row(
            "Normalized",
            detection["normalized"][:120],
        )

    for key, value in detection.get(
        "metadata",
        {},
    ).items():

        if isinstance(value, list):
            value = ", ".join(
                str(x)
                for x in value[:5]
            )

        table.add_row(
            key,
            str(value)[:120],
        )

    for warning in detection.get(
        "warnings",
        [],
    ):
        table.add_row(
            "[yellow]![/yellow]",
            f"[yellow]{warning}[/yellow]",
        )

    console.print(table)


def display_onion_banner(
    banner: Dict[str, Any],
) -> None:

    if banner.get("error"):
        console.print(
            Panel(
                f"[red]{banner['error']}[/red]",
                title=(
                    f"Onion {banner.get('host', '?')}"
                ),
                border_style="red",
            )
        )
        return

    table = Table(
        title=(
            f"Onion Recon — "
            f"{banner.get('host', '?')}:"
            f"{banner.get('port', '?')}"
        ),
        border_style="magenta",
        show_header=False,
    )

    table.add_column(
        "Field",
        style="bold magenta",
    )

    table.add_column("Value")

    table.add_row(
        "Reachable",
        (
            "[green]YES[/green]"
            if banner.get("reachable")
            else "[red]NO[/red]"
        ),
    )

    table.add_row(
        "Scheme",
        str(
            banner.get(
                "scheme",
                "?",
            )
        ).upper(),
    )

    if banner.get("title"):
        table.add_row(
            "Title",
            banner["title"],
        )

    tls = banner.get("tls")

    if tls:
        if tls.get("version"):
            table.add_row(
                "TLS",
                str(tls["version"]),
            )

        if tls.get("cipher"):
            table.add_row(
                "Cipher",
                str(tls["cipher"]),
            )

        if tls.get("sha256_fp"):
            table.add_row(
                "Certificate SHA-256",
                tls["sha256_fp"],
            )

        if tls.get("subject"):
            table.add_row(
                "Subject",
                tls["subject"][:100],
            )

        if tls.get("issuer"):
            table.add_row(
                "Issuer",
                tls["issuer"][:100],
            )

        if tls.get("days_to_expiry") is not None:
            days = tls[
                "days_to_expiry"
            ]

            color = (
                "red"
                if days < 0
                else "yellow"
                if days < 30
                else "green"
            )

            table.add_row(
                "Certificate Expiry",
                f"[{color}]{days} days[/{color}]",
            )

    http = banner.get("http")

    if http:
        status = http.get(
            "status_code"
        )

        if status:
            color = (
                "green"
                if 200 <= status < 300
                else "yellow"
                if 300 <= status < 400
                else "red"
            )

            table.add_row(
                "HTTP",
                f"[{color}]{status}[/{color}]",
            )

        if http.get("server"):
            table.add_row(
                "Server",
                str(
                    http["server"]
                )[:100],
            )

        if http.get("content_type"):
            table.add_row(
                "Content-Type",
                str(
                    http["content_type"]
                )[:100],
            )

        table.add_row(
            "Body Size",
            f"{http.get('body_size', 0):,} bytes",
        )

    security = banner.get(
        "security"
    )

    if security:
        table.add_row(
            "Security Score",
            f"{security.get('score', 0)}/100",
        )

    console.print(table)

    technologies = banner.get(
        "technologies",
        [],
    )

    if technologies:
        tech_table = Table(
            title="Technology Fingerprint",
            border_style="cyan",
        )

        tech_table.add_column(
            "Technology"
        )

        tech_table.add_column(
            "Confidence"
        )

        for item in technologies:
            tech_table.add_row(
                item["technology"],
                f"{item['confidence']}%",
            )

        console.print(
            tech_table
        )

    iocs = banner.get("iocs")

    if iocs:
        display_ioc_summary(iocs)


def display_ioc_summary(
    iocs: Dict[str, Any],
) -> None:

    counts = iocs.get(
        "counts",
        {},
    )

    table = Table(
        title="IOC Summary",
        border_style="green",
    )

    table.add_column("IOC")
    table.add_column("Count")

    labels = (
        ("URLs", "urls"),
        ("Onion", "onions"),
        ("Domains", "domains"),
        ("IPv4", "ipv4"),
        ("IPv6", "ipv6"),
        ("Emails", "emails"),
        ("BTC", "btc"),
        ("ETH", "eth"),
        ("XMR", "xmr"),
        ("LTC", "ltc"),
        ("Hashes", "hashes"),
        ("PGP", "pgp_blocks"),
    )

    for label, key in labels:
        count = counts.get(
            key,
            0,
        )

        if count:
            table.add_row(
                label,
                str(count),
            )

    console.print(table)


def display_btc(
    data: Dict[str, Any],
    risk: Optional[Dict[str, Any]] = None,
) -> None:

    if not data.get("valid"):
        console.print(
            Panel(
                f"[red]{data.get('error', 'Invalid BTC address')}[/red]",
                title="BTC Intelligence",
                border_style="red",
            )
        )
        return

    table = Table(
        title=(
            f"BTC Intelligence — "
            f"{data['address']}"
        ),
        border_style="yellow",
        show_header=False,
    )

    table.add_column(
        "Field",
        style="bold yellow",
    )

    table.add_column("Value")

    if data.get("first_seen"):
        table.add_row(
            "First Seen",
            str(data["first_seen"]),
        )

    if data.get("first_seen_block"):
        table.add_row(
            "First Block",
            f"#{data['first_seen_block']:,}",
        )

    if data.get("age_days") is not None:
        table.add_row(
            "Age",
            f"{data['age_days']:,} days "
            f"(~{data.get('age_years', 0)} years)",
        )

    table.add_row(
        "Transactions",
        f"{data.get('tx_count') or 0:,}",
    )

    table.add_row(
        "Received",
        f"{data.get('total_received_btc') or 0:.8f} BTC",
    )

    table.add_row(
        "Sent",
        f"{data.get('total_sent_btc') or 0:.8f} BTC",
    )

    table.add_row(
        "Balance",
        f"{data.get('balance_btc') or 0:.8f} BTC",
    )

    table.add_row(
        "Source",
        str(
            data.get(
                "source",
                "unknown",
            )
        ),
    )

    console.print(table)

    if risk:
        color = {
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get(
            risk.get("level"),
            "white",
        )

        console.print(
            Panel(
                f"Score: [bold]{risk.get('score', 0)}/100[/bold]\n"
                f"Level: [{color}]"
                f"{risk.get('level', 'UNKNOWN')}"
                f"[/{color}]\n"
                f"Confidence: "
                f"{risk.get('confidence', 0)}%",
                title="BTC Risk Heuristics",
                border_style=color,
            )
        )

        for factor in risk.get(
            "factors",
            [],
        ):
            console.print(
                f"  [yellow]•[/yellow] {factor}"
            )


# ---------------------------------------------------------------------
# Menu helpers
# ---------------------------------------------------------------------


def _prompt(
    text: str,
    default: str = "",
) -> str:

    value = Prompt.ask(
        f"[cyan]{text}[/cyan]",
        default=default,
    )

    return value.strip()


def _save_report_interactive(
    report: Dict[str, Any],
) -> None:

    path = _prompt(
        "Output JSON path",
        "spectrascan_darkweb_report.json",
    )

    try:
        saved = save_json_report(
            report,
            path,
        )

        console.print(
            f"[green]Report saved:[/green] "
            f"{saved}"
        )

    except Exception as exc:
        console.print(
            f"[red]Unable to save report: "
            f"{exc}[/red]"
        )


# ---------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------


def run_darkweb_menu() -> None:
    """
    Main Dark Web Intelligence interactive menu.
    """

    console.print(
        Panel(
            f"[bold magenta]"
            f"SPECTRASCAN DARK WEB INTELLIGENCE"
            f"[/bold magenta]\n"
            f"[dim]Module {MODULE_VERSION}[/dim]",
            border_style="magenta",
        )
    )

    if not SOCKS_AVAILABLE:
        console.print(
            "[yellow]![/yellow] "
            "PySocks unavailable — "
            "Tor operations disabled."
        )

    if not REQUESTS_AVAILABLE:
        console.print(
            "[yellow]![/yellow] "
            "Requests unavailable — "
            "HTTP/API operations disabled."
        )

    if not DNS_AVAILABLE:
        console.print(
            "[yellow]![/yellow] "
            "dnspython unavailable — "
            "DNS intelligence disabled."
        )

    while True:
        console.print(
            Panel(
                """
[bold magenta]DARK WEB INTELLIGENCE[/bold magenta]

[green]1.[/green]  Auto Detect Target
[green]2.[/green]  Full Recon
[green]3.[/green]  Onion Banner / Web Recon
[green]4.[/green]  Extract IOCs
[green]5.[/green]  BTC Intelligence
[green]6.[/green]  Domain / DNS Intelligence
[green]7.[/green]  Email Intelligence
[green]8.[/green]  Ahmia Search
[green]9.[/green]  Redirect Analysis
[green]10.[/green] Tor Connectivity
[green]11.[/green] Save JSON Report
[red]12.[/red] Exit
                """,
                border_style="magenta",
            )
        )

        choice = Prompt.ask(
            "[bold magenta]Select option[/bold magenta]",
            choices=[
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "7",
                "8",
                "9",
                "10",
                "11",
                "12",
            ],
            default="1",
        )

        try:
            # ---------------------------------------------------------
            # Detection
            # ---------------------------------------------------------

            if choice == "1":
                target = _prompt(
                    "Target"
                )

                if target:
                    display_detection(
                        detect_target_type(
                            target
                        )
                    )

            # ---------------------------------------------------------
            # Full recon
            # ---------------------------------------------------------

            elif choice == "2":
                target = _prompt(
                    "Target"
                )

                if not target:
                    continue

                with console.status(
                    "[magenta]Running full reconnaissance...[/magenta]"
                ):
                    report = full_recon(
                        target
                    )

                display_detection(
                    report["detection"]
                )

                if report[
                    "detection"
                ]["type"] == "onion":
                    display_onion_banner(
                        report["recon"]
                    )

                elif (
                    report[
                        "detection"
                    ]["subtype"]
                    == "btc"
                ):
                    display_btc(
                        report["recon"],
                        report["risk"],
                    )

                else:
                    console.print(
                        Panel(
                            json.dumps(
                                report[
                                    "recon"
                                ],
                                indent=2,
                                default=str,
                            )[:10000],
                            title="Recon Result",
                            border_style="cyan",
                        )
                    )

                risk = report.get(
                    "risk"
                )

                if risk:
                    console.print(
                        Panel(
                            f"Risk: "
                            f"[bold]{risk.get('level')}[/bold]\n"
                            f"Score: "
                            f"{risk.get('score')}/100\n"
                            f"Confidence: "
                            f"{risk.get('confidence')}%",
                            title="Risk",
                            border_style=(
                                "red"
                                if risk.get(
                                    "level"
                                ) == "HIGH"
                                else "yellow"
                            ),
                        )
                    )

                if Confirm.ask(
                    "Save JSON report?",
                    default=False,
                ):
                    _save_report_interactive(
                        report
                    )

            # ---------------------------------------------------------
            # Onion
            # ---------------------------------------------------------

            elif choice == "3":
                if not SOCKS_AVAILABLE:
                    console.print(
                        "[red]PySocks required.[/red]"
                    )
                    continue

                target = _prompt(
                    "Onion URL / hostname"
                )

                if not target:
                    continue

                with console.status(
                    "[magenta]Performing onion reconnaissance...[/magenta]"
                ):
                    result = (
                        grab_onion_banner(
                            target
                        )
                    )

                display_onion_banner(
                    result
                )

            # ---------------------------------------------------------
            # IOC
            # ---------------------------------------------------------

            elif choice == "4":
                console.print(
                    "[dim]Paste text. "
                    "Press Enter twice to finish.[/dim]"
                )

                lines = []
                empty_lines = 0

                while True:
                    try:
                        line = input()
                    except EOFError:
                        break

                    if not line:
                        empty_lines += 1

                        if empty_lines >= 2:
                            break

                        continue

                    empty_lines = 0
                    lines.append(line)

                iocs = extract_iocs(
                    "\n".join(lines)
                )

                display_ioc_summary(
                    iocs
                )

                if Confirm.ask(
                    "Show extracted values?",
                    default=True,
                ):
                    console.print(
                        Panel(
                            json.dumps(
                                iocs,
                                indent=2,
                                ensure_ascii=False,
                            ),
                            title="Extracted IOCs",
                            border_style="green",
                        )
                    )

            # ---------------------------------------------------------
            # BTC
            # ---------------------------------------------------------

            elif choice == "5":
                address = _prompt(
                    "BTC address"
                )

                if not address:
                    continue

                with console.status(
                    "[yellow]Querying public blockchain data...[/yellow]"
                ):
                    data = btc_first_seen(
                        address
                    )

                risk = (
                    score_btc_risk(data)
                    if data.get("valid")
                    else None
                )

                display_btc(
                    data,
                    risk,
                )

            # ---------------------------------------------------------
            # Domain
            # ---------------------------------------------------------

            elif choice == "6":
                domain = _prompt(
                    "Domain"
                )

                if not domain:
                    continue

                with console.status(
                    "[cyan]Resolving DNS records...[/cyan]"
                ):
                    result = (
                        domain_intelligence(
                            domain
                        )
                    )

                console.print(
                    Panel(
                        json.dumps(
                            result,
                            indent=2,
                            default=str,
                        ),
                        title="Domain Intelligence",
                        border_style="cyan",
                    )
                )

            # ---------------------------------------------------------
            # Email
            # ---------------------------------------------------------

            elif choice == "7":
                email = _prompt(
                    "Email"
                )

                if not email:
                    continue

                with console.status(
                    "[cyan]Analyzing email domain...[/cyan]"
                ):
                    result = (
                        email_intelligence(
                            email
                        )
                    )

                console.print(
                    Panel(
                        json.dumps(
                            result,
                            indent=2,
                            default=str,
                        ),
                        title="Email Intelligence",
                        border_style="cyan",
                    )
                )

            # ---------------------------------------------------------
            # Ahmia
            # ---------------------------------------------------------

            elif choice == "8":
                query = _prompt(
                    "Ahmia search"
                )

                if not query:
                    continue

                with console.status(
                    "[cyan]Searching Ahmia...[/cyan]"
                ):
                    result = (
                        ahmia_search(
                            query
                        )
                    )

                if result.get("error"):
                    console.print(
                        f"[red]{result['error']}[/red]"
                    )
                    continue

                console.print(
                    f"[green]Found "
                    f"{result['total']} "
                    f".onion indicators.[/green]"
                )

                if result["v3_links"]:
                    console.print(
                        Panel(
                            "\n".join(
                                result[
                                    "v3_links"
                                ]
                            ),
                            title="Onion v3",
                            border_style="magenta",
                        )
                    )

                if result["v2_links"]:
                    console.print(
                        Panel(
                            "\n".join(
                                result[
                                    "v2_links"
                                ]
                            ),
                            title="Onion v2",
                            border_style="red",
                        )
                    )

            # ---------------------------------------------------------
            # Redirects
            # ---------------------------------------------------------

            elif choice == "9":
                target = _prompt(
                    "HTTP/HTTPS URL"
                )

                if not target:
                    continue

                with console.status(
                    "[cyan]Analyzing redirects...[/cyan]"
                ):
                    result = (
                        analyze_redirects(
                            target
                        )
                    )

                table = Table(
                    title="Redirect Chain",
                    border_style="cyan",
                )

                table.add_column(
                    "#"
                )

                table.add_column(
                    "Status"
                )

                table.add_column(
                    "URL"
                )

                for index, item in enumerate(
                    result["chain"],
                    start=1,
                ):
                    table.add_row(
                        str(index),
                        str(
                            item[
                                "status_code"
                            ]
                        ),
                        item["url"][:150],
                    )

                console.print(
                    table
                )

                if result.get(
                    "final_url"
                ):
                    console.print(
                        f"[green]Final URL:[/green] "
                        f"{result['final_url']}"
                    )

                if result.get("error"):
                    console.print(
                        f"[red]{result['error']}[/red]"
                    )

            # ---------------------------------------------------------
            # Tor
            # ---------------------------------------------------------

            elif choice == "10":
                with console.status(
                    "[magenta]Testing Tor SOCKS connectivity...[/magenta]"
                ):
                    result = (
                        check_tor_connection()
                    )

                if result.get(
                    "tor_working"
                ):
                    console.print(
                        Panel(
                            f"[green]Tor connection operational[/green]\n"
                            f"SOCKS: "
                            f"{TOR_SOCKS_HOST}:"
                            f"{TOR_SOCKS_PORT}\n"
                            f"Exit IP: "
                            f"[cyan]"
                            f"{result.get('exit_ip')}"
                            f"[/cyan]",
                            title="Tor",
                            border_style="green",
                        )
                    )
                else:
                    console.print(
                        Panel(
                            f"[red]Tor unavailable[/red]\n"
                            f"{result.get('error')}",
                            title="Tor",
                            border_style="red",
                        )
                    )

            # ---------------------------------------------------------
            # JSON report
            # ---------------------------------------------------------

            elif choice == "11":
                target = _prompt(
                    "Target"
                )

                if not target:
                    continue

                with console.status(
                    "[cyan]Building report...[/cyan]"
                ):
                    report = full_recon(
                        target
                    )

                _save_report_interactive(
                    report
                )

            # ---------------------------------------------------------
            # Exit
            # ---------------------------------------------------------

            elif choice == "12":
                console.print(
                    "[dim]Leaving Dark Web Intelligence module.[/dim]"
                )
                break

        except KeyboardInterrupt:
            console.print(
                "\n[yellow]Operation cancelled.[/yellow]"
            )

        except Exception as exc:
            console.print(
                f"[red]Error: "
                f"{type(exc).__name__}: "
                f"{exc}[/red]"
            )


# ---------------------------------------------------------------------
# Backwards compatibility
# ---------------------------------------------------------------------


def darkweb_menu() -> None:
    return run_darkweb_menu()


# ---------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------



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
                run_darkweb_menu()
            except KeyboardInterrupt:
                console.print(
                    "[*] Dark Web module interrupted.",
                    style="yellow")
            except Exception as e:
                console.print(
                    f"[!] Dark Web module error: {e}",
                    style="bold red")
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