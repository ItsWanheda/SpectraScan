<div align="center">

# 🕵️‍♂️ SpectraScan

### *Advanced Network Reconnaissance, Port Scanning & OSINT Intelligence Framework*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)]()
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

**SpectraScan** is a high-performance, multi-threaded network intelligence framework written in Python.
It bridges the gap between traditional port scanning and deep reconnaissance by integrating OS
fingerprinting, SSL/TLS analysis, a massive **OSINT Suite**, hand-rolled protocol enumeration, and a
**Dark Web Recon** module — all in a single modular CLI.

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [Roadmap](#-roadmap) • [Disclaimer](#-disclaimer)

</div>

---

## 📑 Table of Contents

- [Why SpectraScan?](#-why-spectrascan)
- [Features](#-features)
  - [Core Scanning Engine](#-core-scanning-engine)
  - [OSINT Intelligence Suite](#-osint-intelligence-suite)
  - [Attack & Vulnerability Modules](#-attack--vulnerability-modules)
  - [Protocol Enumeration Modules](#-protocol-enumeration-modules)
  - [Dark Web Recon Module](#-dark-web-recon-module)
  - [Report Management](#-report-management)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [CLI Menu](#-cli-menu)
- [Configuration](#-configuration)
- [Output Examples](#-output-examples)
- [Project Structure](#-project-structure)
- [Performance & Threading Model](#-performance--threading-model)
- [Environment Variables](#-environment-variables)
- [Comparison with Similar Tools](#-comparison-with-similar-tools)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#-roadmap)
- [Security Notes](#-security-notes)
- [Contributing](#-contributing)
- [Acknowledgements](#-acknowledgements)
- [Disclaimer](#-disclaimer)
- [License](#-license)

---

## 🎯 Why SpectraScan?

Most recon tools force you to choose between **speed**, **depth**, and **safety**. SpectraScan combines all three in one framework:

| Need | Tool You’d Typically Use | SpectraScan Module |
|------|--------------------------|--------------------|
| Fast port sweep | Nmap, Masscan | `core.scanner` (multi-threaded) |
| Web fingerprinting | WhatWeb, Nikto | `core.http_enum` |
| Domain/IP WHOIS | whois, dig | `osint.domain` / `osint.ip` |
| Email breach check | HIBP, emailrep | `osint.email` |
| Phone lookup | NumVerify | `osint.phone` |
| SMB/RDP/LDAP enum | enum4linux, CrackMapExec | `protocols.*` (pure Python) |
| Subdomain / link sniff | LinkFinder, sublist3r | `osint.link_sniffer` |
| CVE matching | vulners, searchsploit | `attack.vuln_scanner` |
| Directory busting | dirb, gobuster | `attack.web_enumerator` |
| Dark web mention search | Ahmia (manual) | `darkweb.ahmia_search` |
| Onion banner grab | manual `curl --socks5` | `darkweb.banner` |
| BTC address profiling | manual blockchain.info | `darkweb.btc_first_seen` |

All wrapped in a **single Rich-powered CLI**, with **persistent history**, **multi-format reports**, and
**zero proprietary black-box dependencies**.

---

## ✨ Features

### 🛠️ Core Scanning Engine
*High-speed network enumeration and service identification.*

- **🔍 Multi-Protocol Scanning** — TCP connect, SYN (raw socket), and UDP scans with configurable timing profiles (T0–T5).
- **🛡️ Firewall/IDS Detection** — RST/ICMP behavior analysis, dropped vs. filtered vs. open port classification.
- **🕵️ OS Fingerprinting** — TTL + TCP window-size + DF-bit heuristics for Linux/Windows/BSD/network-device families.
- **🔐 SSL/TLS Deep Analysis** — Certificate chain inspection, cipher-suite enumeration, protocol-version checks (SSLv3 → TLS 1.3), expiry warnings.
- **🌐 HTTP Enumeration** — `Server`, `X-Powered-By`, allowed methods, common path discovery (`/admin`, `/login`, `/.git`, …).
- **📡 Advanced Discovery** — ICMP ping sweeps, ARP table walking, traceroute-related workflow helpers.
- **⚡ High Performance** — `concurrent.futures.ThreadPoolExecutor` pool sized dynamically to `min(512, ports × targets)`.

### 🕵️ OSINT Intelligence Suite
*Deep-dive intelligence gathering for digital footprinting.*

- **🌐 Domain Intelligence** — WHOIS (registrar, dates, nameservers), full DNS record set (A, AAAA, MX, NS, TXT, SOA, CNAME), host reachability.
- **📍 IP Intelligence** — GeoIP (country/city/ASN), WHOIS, optional Shodan integration.
- **📞 Phone Intelligence** — Carrier, line-type, country, and geo lookup via NumVerify API (key required).
- **📧 Email Intelligence** — Reputation, breach flags, disposable-mail detection, free-provider classification via `emailrep.io` (free tier).
- **🖼️ Metadata Extraction** — EXIF/IPTC/XMP data from JPEG/PNG/TIFF using `exiv2` or `exiftool` with automatic tool fallback.
- **🔗 Link Sniffing** — URL extraction from a target domain via the HackerTarget API, with on-page depth-2 spider option.
- **👮 Criminal Record Lookup** — Generates state-specific public-records search links for U.S. jurisdictions (informational only — no live DB query).

### ⚔️ Attack & Vulnerability Modules
*Active testing — use only with explicit authorization.*

- **💥 Brute Force Engine** — Dictionary-based credential testing for **SSH** and **FTP** services with rate limiting, jitter, and lockout-aware back-off.
- **🛡️ CVE Scanner** — Real-time vulnerability detection by matching detected service banners against the **NVD CVE 2.0 API** (with local CVE cache).
- **📂 Web Fuzzing** — Multi-threaded directory/file enumeration for HTTP/HTTPS, with custom wordlists, recursive scanning, and status-code filtering.

### 🔬 Protocol Enumeration Modules
*Deep, protocol-aware inspection of exposed services — **pure Python**, no external libraries required.*

| Protocol | Module | Detection / Heuristics |
|----------|--------|------------------------|
| **SMB/CIFS** | `smb_enum` | SMBv1/v2/v3 negotiation, share enumeration, anonymous-auth detection, OS fingerprinting, EternalBlue flag (CVE-2017-0144) |
| **SNMP** | `snmp_enum` | Custom BER encoder, default-community brute-force (`public`, `private`, `cisco`, `manager`, …), system-info queries, `snmpwalk` fallback |
| **LDAP/LDAPS** | `ldap_enum` | Anonymous-bind detection, Root DSE retrieval, user/group enumeration via `ldapsearch` |
| **RDP** | `rdp_enum` | X.224/TPKT handshake, NLA detection, BlueKeep (CVE-2019-0708) heuristic |
| **SMTP** | `smtp_enum` | Banner grab, VRFY/EXPN user enumeration, open-relay test, STARTTLS support |
| **DNS** | `dns_zone` | AXFR attempts against **all** NS records; reports servers that allow transfer |
| **NFS** | `nfs_enum` | RPC portmapper dump, MOUNTD EXPORT call, `showmount` fallback; flags permissive exports |
| **VNC** | `vnc_enum` | RFB handshake, auth-type enumeration, no-authentication detection |
| **Redis** | `redis_enum` | RESP protocol, INFO/DBSIZE/RANDOMKEY sampling, unauthenticated-access flag |
| **MongoDB** | `mongodb_enum` | Custom OP_MSG wire protocol, hand-rolled BSON encoder/parser, unauthenticated-access flag |
| **SIP** | `sip_enum` | UDP OPTIONS probe with response capture |
| **RTSP** | `rtsp_enum` | DESCRIBE across common stream paths, SDP capture, unauthenticated-stream detection |
| **Databases** | `database_enum` | Hand-rolled MySQL/PostgreSQL/MSSQL clients with version detection |

### 🌑 Dark Web Recon Module
*Passive, ethical reconnaissance of `.onion` services and dark-web mentions — **no marketplace interaction, no illegal content, no payload execution**.*

#### 🔎 Auto-Detection
The module automatically identifies the target type before running any lookups. Supported target types:

| Type | Detection | Subtype / Confidence |
|------|-----------|----------------------|
| `.onion` v3 | Regex (56-char base32) | 100% — modern onion |
| `.onion` v2 | Regex (16-char base32) | 100% — **deprecated**, warned |
| **BTC address** | Base58Check + Bech32/Bech32m checksum (BIP-173/350) | 100% |
| **ETH address** | EIP-55 regex | 95% |
| **XMR / LTC** | Format regex (no checksum) | 75% |
| Email | RFC-5322 lite regex | 95% + disposable-mail flag |
| IPv4 | `ipaddress` module | 95% + private/loopback flag |
| Hash | MD5/SHA-1/SHA-256 | 90–95% |
| PGP key block | ASCII-armor header regex | 100% |
| Phone | International phone regex | 70% |
| Domain | RFC-1035 lite regex | 80% + suspicious-TLD flag |
| Username | Heuristic | 40% (low-confidence hint) |

#### 🧅 Onion Recon
- **HTTPS/HTTP banner grab** over Tor SOCKS5 with full TLS inspection:
  - TLS version, cipher suite, certificate subject/issuer/SAN
  - **SHA-1 & SHA-256 fingerprints** + days-to-expiry flag
  - HTTP status line, headers (`Server`, `X-Powered-By`, `Set-Cookie`, `HSTS`, …)
  - `<title>` extraction from HTML body (up to 200 KB)
- Supports **v3 (56-char)** and **v2 (16-char, deprecated)** onions
- Custom port + scheme (HTTPS/HTTP) selection
- Hard 30-second timeout per attempt

#### 💰 Bitcoin Address Profiling
- **First-seen timestamp** via 3-stage API fallback:
  1. **Blockchair** (preferred — `first_seen_receiving` direct field)
  2. **Blockstream.info** (paginated, oldest-page scan, capped at 20 iterations)
  3. **Blockchain.info** (legacy fallback)
- Reports: first-seen block height, age in days/years, total received, total sent, current balance, transaction count
- **Heuristic risk scoring** (0–100):
  - `+30` if address < 1 day old
  - `+15` if < 7 days, `+5` if < 30 days
  - `-10` if tx count > 1000 (likely exchange/service)
  - `+10` for dormant high-balance wallets
- Risk levels: **LOW / MEDIUM / HIGH**

#### 🔍 Other Dark Web Utilities
- **🔗 Onion link extractor** — paste any text, find all v2/v3 `.onion` references.
- **🌐 Ahmia.fi search** — query the ethical dark-web search engine via clearnet (no Tor needed).
- **🔌 Tor connectivity check** — verifies `127.0.0.1:9050` SOCKS5 + performs live `check.torproject.org` lookup to confirm the exit IP.

#### ⚖️ Ethical Guardrails
- ✅ **Hard timeouts ≤ 30s** on every network call
- ✅ **Clearnet-first design** — most checks work without Tor
- ✅ **No binary downloads**, **no marketplace interaction**, **no payload execution**
- ✅ **No auto-launch of Tor** — user must start it explicitly
- ✅ **No login/auth attempts** on any dark-web service

**Menu path:** `Main Menu → 3. Protocol Modules → 14. Dark Web Recon`

### 📁 Report Management
- **📊 Rich Reporting** — Export to **JSON, CSV, and HTML** (auto-themed).
- **💾 Persistence** — All reports stored at `~/.local/share/SpectraScan/` (XDG-compliant).
- **📂 History Management** — Interactive CLI: list, view, delete, or re-export past scans.
- **⏱️ Timestamped runs** — every scan gets a UTC timestamp + UUID for traceability.

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                  SpectraScan.py (CLI entry-point)              │
│  - argparse front-end   - Rich interactive menu   - dispatcher │
└─────────────────────┬──────────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┬───────────────┐
        │             │             │               │
        ▼             ▼             ▼               ▼
   ┌────────┐   ┌──────────┐  ┌──────────┐   ┌────────────┐
   │ Core   │   │  OSINT   │  │  Attack  │   │ Protocols  │
   │ Engine │   │  Suite   │  │ Modules  │   │  Enum      │
   └────┬───┘   └─────┬────┘  └────┬─────┘   └──────┬─────┘
        │             │            │                │
        │  ┌──────────┴────────┐   │                │
        │  │                   │   │                │
        ▼  ▼                   ▼   ▼                ▼
   ┌────────────────────┐  ┌──────────────┐   ┌──────────────┐
   │  Third-party APIs  │  │  Wordlists   │   │  Dark Web    │
   │  (WHOIS, Shodan,   │  │  (local FS)  │   │  Recon       │
   │   emailrep, etc.)  │  │              │   │  (Tor/Ahmia) │
   └────────────────────┘  └──────────────┘   └──────────────┘
                                                       │
                                                       ▼
                                              ┌──────────────────┐
                                              │  Bitcoin APIs    │
                                              │  (Blockchair,    │
                                              │   Blockstream,   │
                                              │   blockchain.info│
                                              └──────────────────┘
```

**Design principles:**

1. **Modularity** — every protocol/feature is its own module with a stable function signature.
2. **Pure Python first** — protocol enumeration works without Nmap, hydra, or other binaries.
3. **Fail-soft** — every external lookup has a fallback API or a graceful "unavailable" message.
4. **Read-only by default** — only `--brute-force`, `--vuln-scan`, and `--web-enum` are active.

---

## 📦 Installation

### Prerequisites

| Requirement | Why | Optional? |
|-------------|-----|-----------|
| **Python 3.9+** | Core language | No |
| **Root / Administrator** | RAW sockets for SYN scans | Only for SYN mode |
| **Tor daemon** on `127.0.0.1:9050` | Required for `.onion` banner grabs | Only for dark-web `.onion` ops |
| `exiv2` or `exiftool` | Image EXIF extraction | Optional |
| `shodan-cli` | Shodan IP enrichment | Optional |
| `nmap` | Banner version correlation | Optional |

### Step-by-Step

```bash
# 1. Clone the repository
git clone https://github.com/your-username/SpectraScan.git
cd SpectraScan

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate          # Linux / macOS
# venv\Scripts\activate           # Windows PowerShell
# source venv/bin/activate.csh    # TCSH / C-shell

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. (Optional) Install dark-web support
pip install pysocks               # for .onion over Tor SOCKS5
pip install cryptography          # for richer TLS cert parsing

# 5. (Optional) Install external helpers
sudo apt install exiftool tor nmap     # Debian/Ubuntu
brew install exiftool tor nmap         # macOS
choco install exiftool tor nmap        # Windows
```

### Tor setup (only if using Dark Web Recon `.onion` features)

```bash
# Linux
sudo apt install tor
sudo systemctl start tor
sudo systemctl status tor     # wait for "Bootstrapped 100%"

# macOS
brew install tor
tor &

# Tor Browser users: change TOR_PORT to 9150 in modules/darkweb.py
```

---

## ⚡ Quick Start

If you just want to play with the standalone script:

```bash
pip install rich
python SpectraScan.py
```

You'll see the interactive menu. Pick `1` for a port scan, `3` for protocol enumeration, etc.

For one-shot CLI use:

```bash
python SpectraScan.py -t scanme.nmap.org -p 1-1000 -T T3
```

---

## 🚀 Usage

### 🔹 Basic Reconnaissance

```bash
# Standard port scan (TCP connect, default top-1000 ports, T3 timing)
python SpectraScan.py -t 192.168.1.1

# Aggressive scan with OS detection, all 65535 ports
python SpectraScan.py -t example.com --os-detect -p- -T T4

# Single port UDP probe
python SpectraScan.py -t 10.0.0.5 --scan-type udp -p 53,161,514
```

### 🔹 OSINT & Intelligence

```bash
# Email reputation check
python SpectraScan.py -e target@example.com

# Domain WHOIS + DNS + link sniffing
python SpectraScan.py -d targetdomain.com -l

# IP geo + WHOIS + Shodan
python SpectraScan.py --ip 8.8.8.8 --shodan

# Phone number lookup
python SpectraScan.py --phone "+14155552671"

# Image metadata extraction
python SpectraScan.py --image ./photo.jpg
```

### 🔹 Advanced Modules

```bash
# Vulnerability scanning (CVE correlation via NVD)
python SpectraScan.py -t target.com --vuln-scan

# Brute force SSH/FTP with custom wordlist
python SpectraScan.py -t 10.0.0.5 --brute-force --wordlist ./passwords.txt

# Web directory enumeration
python SpectraScan.py -t example.com --web-enum --wordlist ./dirb_list.txt

# SMB share enumeration
python SpectraScan.py -t 10.0.0.5 --smb

# DNS zone transfer attempt
python SpectraScan.py -d target.com --dns-zone

# LDAP anonymous-bind check
python SpectraScan.py -t 10.0.0.5 --ldap
```

### 🔹 Dark Web Recon

All dark-web operations are **interactive only** (the safety profile is too high-risk for one-shot CLI flags):

```text
Main Menu → 3. Protocol Modules → 14. Dark Web Recon
```

From there you can:

| Option | Action | Requires Tor? |
|--------|--------|---------------|
| `1` | **Auto-Detect & Analyze Target** — figures out what you pasted and runs the right analysis | Depends on target |
| `2` | **HTTPS .onion Banner Grab** — TLS cert + headers + title | ✅ Yes |
| `3` | **BTC First-Seen + Risk Score** — multi-API lookup, age, balance, heuristic risk | ❌ No |
| `4` | **Extract .onion Links from Text** — paste any corpus | ❌ No |
| `5` | **Ahmia.fi Search** — keyword/email/brand search | ❌ No |
| `6` | **Tor Connectivity Check** — verifies SOCKS5 + exit IP | ✅ Yes |
| `7` | **Full Recon** — auto-detect + best-fit analysis in one shot | Depends |
| `8` | Back | — |

**.onion features** require `pysocks` + a running Tor daemon on `127.0.0.1:9050` (Tor Browser users: set `TOR_PORT=9150`).

**Clearnet checks** (Ahmia, BTC, onion-link extraction) work **without Tor**.

#### Dark Web Examples

```text
> Target: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
→ Type: CRYPTO (BTC) — Bech32/Bech32m (Native SegWit)
→ First seen: 2009-01-12 06:54:34 UTC  (~17.5 years old)
→ Tx count: 2,847  Balance: 68.73210000 BTC
→ Risk: LOW (very old, very active)

> Target: duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion
→ Type: ONION (v3) — 56 chars
→ TLS: TLSv1.3 / TLS_AES_256_GCM_SHA384
→ Cert: CN=duckduckgo.com, expires in 47 days
→ HTTP 200, Server: nginx, Title: "DuckDuckGo"
```

### 🔹 Report Management

```bash
# View saved reports
python SpectraScan.py -r

# Export a one-shot scan to HTML
python SpectraScan.py -t target.com -o report.html -f html


# JSON output for piping into other tools
python SpectraScan.py -t target.com -o report.json -f json

---

## ⚙️ Configuration
**Timing Profiles**
> Adjust the balance between speed and stealth:
```text
Profile	Name	            Description
T0	     Paranoid	    Extremely slow, maximum stealth
T1	     Sneaky	       Low noise, avoids detection
T2	     Polite	       Standard scanning, respectful of bandwidth
T3	     Normal	       Default setting
T4	     Aggressive	 Fast, higher chance of detection
T5	     Insane	       Maximum speed, maximum noise
```

---

## 📦 Installation
**Prerequisites**

* **Python 3.9+**
* **Root/Administrator** privileges (Required for RAW sockets / SYN scans)
* **Tor** running locally on `127.0.0.1:9050` — **only required for `.onion` features** of the Dark Web Recon module (clearnet checks still work without it). Tor Browser users should change `TOR_PORT` to `9150` in `modules/darkweb.py`.
* **External Tools**: `exiv2`, `exiftool`, and `shodan-cli` (recommended)

**Setup**
```bash
# Clone the repository
git clone https://github.com/ItsWanheda/SpectraScan.git
cd SpectraScan

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On macOS/Linux
# venv\Scripts\activate   # On Windows

# Install dependencies
pip install -r requirements.txt

# Optional but recommended for the Dark Web Recon module (.onion support)
pip install pysocks
```

---

## Quick Start
> If you're running the standalone script:
```bash
pip install rich
python SpectraScan.py
```

---

## 🧭 CLI Menu

```text
1. Port Scanner
2. Advanced Modules (Domain / IP / Email / Phone / Image / Link / Criminal / Reports)
3. Protocol Modules (SMB / SNMP / LDAP / RDP / SMTP / DNS / NFS / VNC /
                     Redis / MongoDB / SIP / RTSP / Databases / Dark Web Recon)
4. EXIT
```

| Menu | Sub-options |
|------|-------------|
| **1. Port Scanner** | Target IP/Hostname • Scan Type (TCP/SYN/UDP) • Timing Profile (T0–T5) • Port selection (single / range / list / top-N) |
| **2. Advanced Modules** | Domain Scanner • IP Scanner • Email Scanner • Phone Scanner • Image EXIF • Link Sniffer • Criminal Records • Read/Delete Reports |
| **3. Protocol Modules** | SMB • SNMP • LDAP • RDP • SMTP • DNS Zone • NFS • VNC • Redis • MongoDB • SIP • RTSP • Databases • **Dark Web Recon** |
| **4. EXIT** | Clean shutdown, flush reports |

---

## ⚙️ Configuration

### Timing Profiles (Nmap-style)

| Profile | Name | Description |
|---------|------|-------------|
| `T0` | **Paranoid** | Extremely slow, serializes scans for maximum stealth. IDS evasion focus. |
| `T1` | **Sneaky** | Low noise, avoids detection by spacing packets out. |
| `T2` | **Polite** | Standard scanning, respectful of target bandwidth. |
| `T3` | **Normal** | Default setting. Balanced speed vs. accuracy. |
| `T4` | **Aggressive** | Fast, higher chance of detection. Assumes reliable network. |
| `T5` | **Insane** | Maximum speed, maximum noise. May overwhelm targets. |

### Output Verbosity

```text
-v    INFO    Default — show open ports only
-vv   DEBUG   Show every probed port + raw banner
-q    QUIET   Final report only
```

---

## 📊 Output Examples

### Port Scan (HTML report excerpt)
```html
<tr><td>22</td><td>tcp</td><td>open</td><td>ssh</td><td>OpenSSH 8.9p1</td></tr>
<tr><td>80</td><td>tcp</td><td>open</td><td>http</td><td>nginx 1.24.0</td></tr>
<tr><td>443</td><td>tcp</td><td>open</td><td>https</td><td>nginx (TLS 1.3)</td></tr>
```

### Dark Web BTC Report (Rich console)
```
╭──────────── BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa ────────────╮
│ First Seen       2009-01-12 06:54:34 UTC                        │
│ Timestamp        1231743274                                     │
│ First Block      #0                                             │
│ Age              6,394 days (~17.5 years)                       │
│ Tx Count         2,847                                          │
│ Total Received   1,876.50000000 BTC                             │
│ Total Sent       1,807.76790000 BTC                             │
│ Current Balance  68.73210000 BTC                                │
│ Source           blockchair.com                                 │
╰─────────────────────────────────────────────────────────────────╯
╭─────────────── Risk Heuristics ───────────────╮
│ Score  Level    Factors                       │
│ 5      LOW      High tx count (2,847) - likely │
│                  service/exchange              │
╰───────────────────────────────────────────────╯
```

### Saved Report Locations

```bash
~/.local/share/SpectraScan/
├── SS-portscan-2026-06-27-11-13-44.json
├── SS-darkweb-btc-2026-06-27-11-15-22.json
├── SS-osint-domain-2026-06-27-11-20-01.html
└── SS-protocol-smb-2026-06-27-11-25-09.csv
```

---

## 🧩 Project Structure

```text
SpectraScan/
├── SpectraScan.py                # Main CLI entry-point (argparse + Rich menu)
├── modules/
│   ├── __init__.py
│   ├── brute_forcer.py
│   ├── vuln_scanner.py
│   ├── web_enumerator.py
│   ├── phone_scanner.py
│   ├── __init__.py
│   ├── smb_enum.py
│   ├── snmp_enum.py
│   ├── ldap_enum.py
│   ├── rdp_enum.py
│   ├── smtp_enum.py
│   ├── dns_zone.py
│   ├── nfs_enum.py
│   ├── vnc_enum.py
│   ├── redis_enum.py
│   ├── mongodb_enum.py
│   ├── sip_enum.py
│   ├── rtsp_enum.py
│   ├── database_enum.py
│   ├── network_services.py
│   └── darkweb.py              # NEW: Dark Web Recon module
├── CHANGELOG.md
├── LICENSE
├── README.md                     # ← you are here
├── requirements.txt
└── .gitignore
```

---

## ⚡ Performance & Threading Model

| Component | Concurrency Strategy | Default Pool Size |
|-----------|----------------------|-------------------|
| Port scanner | `ThreadPoolExecutor` | `min(512, ports × targets)` |
| Protocol enum | One thread per protocol module | `len(protocols)` |
| Brute forcer | `ThreadPoolExecutor` with semaphore | 16 (rate-limit safe) |
| Web fuzzer | `ThreadPoolExecutor` | 32 |
| DNS zone | Serial (avoids amplification) | 1 |
| BTC lookup | Serial, 3-API fallback | 1 |
| Dark web banner | Serial (Tor latency-bound) | 1 |

**Network fairness:**

- All modules honor `time.sleep(jitter)` between bursts.
- Brute-forcer applies **exponential back-off** on consecutive auth failures to avoid lockouts.
- `--throttle N` (ms) global override applies to every module.

---

## 🌍 Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `TOR_HOST` | `127.0.0.1` | Tor SOCKS5 host |
| `TOR_PORT` | `9050` | Tor SOCKS5 port (use `9150` for Tor Browser) |
| `SPECTRASCAN_HOME` | `~/.local/share/SpectraScan` | Report storage dir |
| `NUMVERIFY_KEY` | *(none)* | NumVerify API key (free tier) |
| `SHODAN_KEY` | *(none)* | Shodan API key |
| `NVD_API_KEY` | *(none)* | NVD key for higher rate limits |
| `EMAILREP_KEY` | *(none)* | emailrep.io key (free tier works without) |
| `HTTP_PROXY` | *(none)* | Global outbound HTTP proxy |

---

## 🆚 Comparison with Similar Tools

| Feature | SpectraScan | Nmap | Recon-ng | SpiderFoot |
|---------|:-----------:|:----:|:--------:|:----------:|
| Port scanning | ✅ | ✅ | ⚠️ plugin | ❌ |
| OS fingerprint | ✅ | ✅ | ⚠️ plugin | ⚠️ |
| OSINT suite | ✅ | ❌ | ✅ | ✅ |
| SMB/LDAP/SNMP enum | ✅ pure-Python | ⚠️ NSE scripts | ⚠️ plugin | ❌ |
| Brute force | ✅ built-in | ❌ | ⚠️ plugin | ❌ |
| CVE lookup | ✅ NVD | ⚠️ vulners script | ⚠️ plugin | ✅ |
| Dark web recon | ✅ | ❌ | ⚠️ | ✅ (paid) |
| BTC forensics | ✅ built-in | ❌ | ❌ | ⚠️ |
| HTML reports | ✅ | ⚠️ zenmap | ✅ | ✅ |
| CLI interactive menu | ✅ Rich | ❌ | ✅ | ❌ |
| Pure Python | ✅ | ❌ C | ✅ | ✅ |

---

## 🩺 Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `Permission denied` on SYN scan | Not root | `sudo python SpectraScan.py ...` |
| `.onion` connection hangs | Tor not running or wrong port | Check `127.0.0.1:9050`, set `TOR_PORT` |
| `pysocks` not found | Missing dep | `pip install pysocks` |
| `cryptography` not found | TLS parsing degraded | `pip install cryptography` |
| All BTC APIs fail | Network blocked or rate-limited | Wait 60s, retry; try `--no-proxy` |
| Rich menu looks broken | Terminal doesn't support colors | `export TERM=xterm-256color` |
| `ModuleNotFoundError: requests` | Optional dep not installed | `pip install requests` |
| Windows: SYN scan fails | WinPcap/Npcap missing | Install [Npcap](https://nmap.org/npcap/) |
| Reports in wrong folder | `HOME` not set on Windows | `set SPECTRASCAN_HOME=C:\spectra_reports` |

---

## 🛣️ Roadmap

- [ ] Async (`asyncio` + `aiohttp`) scanner engine for 10× throughput
- [ ] Kerberos enum + AS-REP roasting detection
- [ ] Subdomain permutation engine (altDNS-style)
- [ ] Email-to-username → password-spray correlation
- [ ] WebSocket / GraphQL introspection modules
- [ ] HTML report theme selection (dark / light / terminal)
- [ ] Plugin loader (drop-in `~/.spectrascan/plugins/`)
- [ ] Docker image (`docker run -it spectrascan`)
- [ ] Web UI (FastAPI + HTMX, optional)

---

## 🛡️ Security Notes

- Brute-force attempts include **rate limiting**, **jitter**, and **timeout controls** to reduce noise and lockout risk.
- External lookups depend on third-party APIs and tools — outages degrade gracefully but do not crash the run.
- Some features require elevated privileges or platform-specific command flags.
- Cross-platform support has been improved for Windows, Linux, and macOS.
- **Dark Web Recon is strictly passive.** It does **not** download binaries, interact with marketplaces, or fetch content from illegal sources. Hard timeouts (≤ 30s) are applied to every network call.
- **You are responsible** for ensuring you have authorization before probing any external resource.

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create.

```bash
# 1. Fork the Project
# 2. Create your Feature Branch
git checkout -b feature/AmazingFeature

# 3. Run the test suite
pytest tests/

# 4. Format with Black
black .

# 5. Commit your Changes
git commit -m 'Add some AmazingFeature'

# 6. Push to the Branch
git push origin feature/AmazingFeature

# 7. Open a Pull Request
```

**Contribution ideas:**
- New protocol enumeration module (`modules/protocols/your_proto.py`)
- New OSINT data source (must be free + legal)
- New report format (e.g., Markdown, SARIF)
- Bug fixes (especially for the darkweb module — see review notes)
- Documentation improvements
- Test fixtures and CI workflows

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening large PRs.

---

## 🙏 Acknowledgements

- [Nmap](https://nmap.org/) — for the timing-profile nomenclature inspiration
- [Impacket](https://github.com/fortra/impacket) — for SMB/RDP protocol references
- [Rich](https://github.com/Textualize/rich) — for the gorgeous terminal UI
- [Ahmia.fi](https://ahmia.fi/) — for ethical dark-web search
- [Blockchair](https://blockchair.com/) / [Blockstream](https://blockstream.info/) — for free BTC APIs
- The entire Python security community ❤️

---

## ⚠️ Disclaimer

**For Educational and Authorized Testing Purposes Only.**

**SpectraScan** — including the Dark Web Recon module — is designed for security professionals to test their **own** networks, services, or hidden services for which they have **explicit written permission**. Unauthorized scanning of networks, services, or hidden services you do not own is:

- **Illegal** in most jurisdictions (CFAA, Computer Misuse Act, etc.)
- **Unethical**
- **Against the spirit of this tool**

The developers of SpectraScan are **not responsible for any misuse** of this tool. By using SpectraScan, you agree to:

1. Only scan targets you own or have written authorization to test.
2. Comply with all applicable local, state, national, and international laws.
3. Not use the Dark Web Recon module to interact with illegal content or marketplaces.
4. Respect rate limits and `robots.txt`-style norms of any third-party API.

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 SpectraScan ItsWanheda

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

**[⬆ back to top](#-spectrascan)**

Made with ❤️ by the ItsWanheda & An0nym0us

</div>

