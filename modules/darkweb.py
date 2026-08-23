"""
SpectraScan Dark Web Intelligence Module
========================================

Defensive / authorized OSINT reconnaissance module.

Core features
-------------
- Automatic target detection
- Onion v2/v3 detection
- Tor SOCKS5 connectivity testing
- HTTP/HTTPS onion reconnaissance
- TLS certificate intelligence
- HTTP security-header analysis
- Redirect-chain analysis
- Technology fingerprinting
- IOC extraction
- BTC address validation + public blockchain intelligence
- ETH/LTC/XMR recognition
- Email/domain intelligence
- Ahmia clearnet search
- Domain/DNS intelligence
- Generic risk scoring
- JSON report generation
- Rich terminal interface

Optional dependencies
---------------------
pysocks
requests
cryptography
dnspython

Environment
-----------
TOR_HOST=127.0.0.1
TOR_PORT=9050

Usage
-----
python -m Modules.darkweb
"""

from __future__ import annotations

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


if __name__ == "__main__":
    run_darkweb_menu()