<div align="center">

# 🕵️‍♂️ SpectraScan

### Advanced Network Reconnaissance, Port Scanning & OSINT Intelligence Framework

<p>
  <a href="https://github.com/ItsWanheda/SpectraScan/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  </a>
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Status-Stable-brightgreen.svg" alt="Status">
  <img src="https://img.shields.io/badge/Code%20Style-Black-000000.svg" alt="Black">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg" alt="PRs Welcome">
</p>

<p>
  <strong>One modular CLI for network scanning, service enumeration, OSINT,
  vulnerability correlation, protocol intelligence, and passive dark-web reconnaissance.</strong>
</p>

<p>
  <a href="#-why-spectrascan">Why SpectraScan</a> ·
  <a href="#-features">Features</a> ·
  <a href="#-installation">Installation</a> ·
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-architecture">Architecture</a> ·
  <a href="#-roadmap">Roadmap</a>
</p>

</div>

---

## 📑 Table of Contents

- [🎯 Why SpectraScan?](#-why-spectrascan)
- [✨ Features](#-features)
  - [Core Scanning Engine](#-core-scanning-engine)
  - [OSINT Intelligence Suite](#-osint-intelligence-suite)
  - [Attack & Vulnerability Modules](#-attack--vulnerability-modules)
  - [Protocol Enumeration](#-protocol-enumeration)
  - [Dark Web Recon](#-dark-web-recon)
  - [Report Management](#-report-management)
- [🏗️ Architecture](#-architecture)
- [📦 Installation](#-installation)
- [⚡ Quick Start](#-quick-start)
- [🚀 Usage](#-usage)
- [🧭 CLI Menu](#-cli-menu)
- [⚙️ Configuration](#-configuration)
- [📊 Output Examples](#-output-examples)
- [🧩 Project Structure](#-project-structure)
- [⚡ Performance & Threading](#-performance--threading)
- [🌍 Environment Variables](#-environment-variables)
- [🆚 Comparison](#-comparison)
- [🩺 Troubleshooting](#-troubleshooting)
- [🛣️ Roadmap](#-roadmap)
- [🛡️ Security Notes](#-security-notes)
- [🤝 Contributing](#-contributing)
- [🙏 Acknowledgements](#-acknowledgements)
- [⚠️ Disclaimer](#-disclaimer)
- [📜 License](#-license)

---

## 🎯 Why SpectraScan?

Reconnaissance usually means switching between several tools, formats, terminals,
and output styles. **SpectraScan** brings a broad collection of reconnaissance
and enumeration workflows into one modular Python CLI.

| Need | Typical Tooling | SpectraScan |
|---|---|---|
| Fast port scanning | Nmap, Masscan | `core.scanner` |
| Web fingerprinting | WhatWeb, Nikto | `core.http_enum` |
| Domain / IP intelligence | WHOIS, dig | `osint.domain`, `osint.ip` |
| Email intelligence | HIBP, emailrep | `osint.email` |
| Phone intelligence | NumVerify | `osint.phone` |
| SMB / RDP / LDAP enumeration | enum4linux, CrackMapExec | `protocols.*` |
| Link / subdomain discovery | LinkFinder, Sublist3r | `osint.link_sniffer` |
| CVE correlation | Vulners, SearchSploit | `attack.vuln_scanner` |
| Web directory enumeration | Dirb, Gobuster | `attack.web_enumerator` |
| Onion reconnaissance | Manual Tor tooling | `darkweb.*` |
| Bitcoin address profiling | Blockchain APIs | `darkweb.btc_first_seen` |

Everything is presented through a **Rich-powered CLI**, with persistent scan
history and JSON / CSV / HTML reporting. The project aims to keep protocol
logic transparent and modular rather than hiding everything behind a single
black-box dependency.

---

## ✨ Features

### 🛠️ Core Scanning Engine

High-speed network enumeration and service identification.

- 🔍 **Multi-protocol scanning**
  - TCP connect
  - SYN / raw-socket scanning
  - UDP probing
  - Configurable timing profiles from `T0` to `T5`
- 🛡️ **Firewall / IDS heuristics**
  - RST and ICMP behavior analysis
  - Open / filtered / dropped classification
- 🕵️ **OS fingerprinting**
  - TTL
  - TCP window size
  - DF-bit heuristics
  - Linux / Windows / BSD / network-device families
- 🔐 **SSL/TLS analysis**
  - Certificate chain inspection
  - Cipher-suite enumeration
  - Protocol-version checks
  - Expiration warnings
- 🌐 **HTTP enumeration**
  - `Server`
  - `X-Powered-By`
  - Allowed methods
  - Common-path discovery such as `/admin`, `/login`, and `/.git`
- 📡 **Network discovery**
  - ICMP sweeps
  - ARP table walking
  - Traceroute-related helpers
- ⚡ **Threaded execution**
  - Dynamic `ThreadPoolExecutor` sizing
  - Default upper bound of `min(512, ports × targets)`

---

### 🕵️ OSINT Intelligence Suite

Designed for gathering publicly available intelligence around domains,
IP addresses, emails, phones, images, and links.

- 🌐 **Domain intelligence**
  - WHOIS
  - A / AAAA / MX / NS / TXT / SOA / CNAME
  - Host reachability
- 📍 **IP intelligence**
  - GeoIP
  - ASN
  - WHOIS
  - Optional Shodan enrichment
- 📞 **Phone intelligence**
  - Carrier
  - Line type
  - Country
  - Geo lookup via NumVerify
- 📧 **Email intelligence**
  - Reputation
  - Breach flags
  - Disposable-mail detection
  - Free-provider classification
- 🖼️ **Metadata extraction**
  - EXIF / IPTC / XMP
  - JPEG / PNG / TIFF
  - `exiv2` / `exiftool` fallback
- 🔗 **Link sniffing**
  - HackerTarget API
  - Optional depth-2 on-page spider
- 👮 **Public-record search helper**
  - Generates U.S. state-specific public-record search links
  - Does not query private or restricted databases

---

### ⚔️ Attack & Vulnerability Modules

> **Active testing requires explicit authorization. Only use these modules against
> systems you own or are explicitly permitted to test.**

- 💥 **Credential testing**
  - Dictionary-based SSH / FTP testing
  - Rate limiting
  - Jitter
  - Lockout-aware back-off
- 🛡️ **CVE scanner**
  - Matches detected service banners against the NVD CVE 2.0 API
  - Supports local CVE caching
- 📂 **Web enumeration**
  - HTTP / HTTPS directory and file discovery
  - Custom wordlists
  - Recursive scanning
  - Status-code filtering

---

### 🔬 Protocol Enumeration

Protocol-aware service inspection implemented primarily in Python.

| Protocol | Module | Detection / Heuristics |
|---|---|---|
| SMB/CIFS | `smb_enum` | SMBv1/v2/v3 negotiation, shares, anonymous auth, OS fingerprinting, EternalBlue heuristic |
| SNMP | `snmp_enum` | BER encoding, community checks, system information, `snmpwalk` fallback |
| LDAP/LDAPS | `ldap_enum` | Anonymous bind, Root DSE, user/group enumeration |
| RDP | `rdp_enum` | X.224 / TPKT handshake, NLA, BlueKeep heuristic |
| SMTP | `smtp_enum` | Banner, VRFY/EXPN, relay test, STARTTLS |
| DNS | `dns_zone` | AXFR attempts against discovered NS records |
| NFS | `nfs_enum` | RPC / MOUNTD inspection, export checks |
| VNC | `vnc_enum` | RFB handshake, authentication types, no-auth detection |
| Redis | `redis_enum` | RESP inspection, INFO / DBSIZE / RANDOMKEY sampling |
| MongoDB | `mongodb_enum` | OP_MSG, BSON parsing, unauthenticated-access detection |
| SIP | `sip_enum` | UDP OPTIONS probing |
| RTSP | `rtsp_enum` | DESCRIBE requests, SDP capture, auth checks |
| Databases | `database_enum` | MySQL / PostgreSQL / MSSQL version detection |

---

## 🌑 Dark Web Recon

SpectraScan includes a dedicated **passive reconnaissance** module for `.onion`
services and publicly observable dark-web references.

**No marketplace interaction. No payload execution. No automatic Tor launch.**

### 🔎 Automatic Target Detection

The module identifies likely target types before analysis:

| Type | Detection | Confidence |
|---|---|---:|
| `.onion` v3 | 56-character Base32 pattern | 100% |
| `.onion` v2 | 16-character Base32 pattern | 100% |
| BTC address | Base58Check / Bech32 / Bech32m | 100% |
| ETH address | EIP-55 pattern | 95% |
| XMR / LTC | Format heuristic | 75% |
| Email | RFC-5322-lite pattern | 95% |
| IPv4 | Python `ipaddress` | 95% |
| Hash | MD5 / SHA-1 / SHA-256 | 90–95% |
| PGP block | ASCII-armored header | 100% |
| Phone | International format heuristic | 70% |
| Domain | RFC-1035-lite pattern | 80% |
| Username | Heuristic | 40% |

### 🧅 Onion Recon

For supported `.onion` targets:

- HTTPS / HTTP banner collection through Tor SOCKS5
- TLS version and cipher suite
- Certificate subject / issuer / SAN
- SHA-1 and SHA-256 certificate fingerprints
- Certificate expiration
- HTTP status and selected headers
- HTML `<title>` extraction
- Custom port and scheme
- Hard 30-second network timeout

### 💰 Bitcoin Address Profiling

The module can query public blockchain APIs using a fallback chain:

1. Blockchair
2. Blockstream
3. Blockchain.info

Reported information can include:

- First-seen timestamp
- First-seen block
- Address age
- Total received
- Total sent
- Current balance
- Transaction count
- Heuristic risk indicators

### 🔍 Other Utilities

- 🔗 Extract `.onion` links from arbitrary text
- 🌐 Search Ahmia through clearnet
- 🔌 Check local Tor SOCKS5 connectivity
- 🧭 Verify the Tor exit connection through Tor Project's check endpoint

### ⚖️ Guardrails

- ✅ Network timeouts capped at 30 seconds
- ✅ Clearnet-first workflows where possible
- ✅ No binary downloads
- ✅ No marketplace interaction
- ✅ No payload execution
- ✅ No automatic Tor startup
- ✅ No login / authentication attempts against dark-web services

---

## 📁 Report Management

SpectraScan keeps scan output organized and reusable.

- 📊 Export reports as **JSON, CSV, or HTML**
- 💾 Store reports under:
  `~/.local/share/SpectraScan/`
- 📂 List, inspect, delete, and re-export historical scans
- ⏱️ Attach UTC timestamps and UUIDs to scan runs

---

## 🏗️ Architecture

```text
                         ┌───────────────────────────────┐
                         │      SpectraScan.py           │
                         │   CLI + Rich + Dispatcher     │
                         └───────────────┬───────────────┘
                                         │
              ┌──────────────────────────┼──────────────────────────┐
              │                          │                          │
              ▼                          ▼                          ▼
      ┌──────────────┐          ┌────────────────┐         ┌────────────────┐
      │ Core Engine  │          │  OSINT Suite   │         │ Attack Modules │
      └──────┬───────┘          └───────┬────────┘         └───────┬────────┘
             │                          │                          │
             └──────────────────────────┼──────────────────────────┘
                                        │
                                        ▼
                              ┌────────────────────┐
                              │ Protocol Modules   │
                              │ SMB / SNMP / LDAP   │
                              │ RDP / SMTP / DNS    │
                              │ NFS / VNC / DB ... │
                              └─────────┬──────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
                ┌─────────────────┐          ┌──────────────────┐
                │ Third-party APIs│          │ Dark Web Recon   │
                │ WHOIS / Shodan  │          │ Tor / Ahmia      │
                │ NVD / emailrep  │          └────────┬─────────┘
                └─────────────────┘                   │
                                                     ▼
                                             ┌────────────────┐
                                             │ Bitcoin APIs   │
                                             └────────────────┘
```

### Design Principles

1. **Modular** — each capability lives in a focused module.
2. **Pure Python first** — protocol functionality avoids unnecessary external
   binaries where practical.
3. **Fail-soft** — external failures should degrade gracefully.
4. **Read-only by default** — active capabilities are explicit opt-in features.
5. **Traceable output** — scans produce timestamped, reusable reports.

---

## 📦 Installation

### Prerequisites

| Requirement | Purpose | Required? |
|---|---|---|
| Python 3.9+ | Core runtime | ✅ |
| Root / Administrator | Raw sockets for SYN scans | Only for SYN mode |
| Tor on `127.0.0.1:9050` | `.onion` operations | Only for onion features |
| `exiv2` or `exiftool` | Image metadata | Optional |
| `shodan-cli` | Shodan enrichment | Optional |
| `nmap` | Banner/version correlation | Optional |

### 1. Clone

```bash
git clone https://github.com/ItsWanheda/SpectraScan.git
cd SpectraScan
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

**Linux / macOS**

```bash
source venv/bin/activate
```

**Windows PowerShell**

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Optional dependencies

```bash
pip install pysocks cryptography
```

### 5. Optional system tools

**Debian / Ubuntu**

```bash
sudo apt install exiftool tor nmap
```

**macOS**

```bash
brew install exiftool tor nmap
```

**Windows**

```powershell
choco install exiftool tor nmap
```

### 🧅 Tor Setup

```bash
sudo apt install tor
sudo systemctl start tor
sudo systemctl status tor
```

For Tor Browser, use port `9150` instead of `9050`:

```bash
export TOR_PORT=9150
```

---

## ⚡ Quick Start

### Interactive CLI

```bash
pip install rich
python SpectraScan.py
```

### One-shot scan

```bash
python SpectraScan.py -t scanme.nmap.org -p 1-1000 -T T3
```

> Only scan hosts you own or have explicit permission to test.

---

## 🚀 Usage

### 🔍 Basic Reconnaissance

```bash
# Standard TCP scan
python SpectraScan.py -t 192.168.1.1

# OS detection + all ports
python SpectraScan.py -t example.com --os-detect -p- -T T4

# UDP probes
python SpectraScan.py -t 10.0.0.5 --scan-type udp -p 53,161,514
```

### 🕵️ OSINT

```bash
# Email reputation
python SpectraScan.py -e target@example.com

# Domain intelligence + link sniffing
python SpectraScan.py -d targetdomain.com -l

# IP intelligence + Shodan
python SpectraScan.py --ip 8.8.8.8 --shodan

# Phone lookup
python SpectraScan.py --phone "+14155552671"

# Image metadata
python SpectraScan.py --image ./photo.jpg
```

### ⚔️ Advanced Modules

```bash
# CVE correlation
python SpectraScan.py -t target.com --vuln-scan

# SSH / FTP credential testing
python SpectraScan.py -t 10.0.0.5 --brute-force --wordlist ./passwords.txt

# Web directory enumeration
python SpectraScan.py -t example.com --web-enum --wordlist ./dirb_list.txt

# SMB enumeration
python SpectraScan.py -t 10.0.0.5 --smb

# DNS zone-transfer check
python SpectraScan.py -d target.com --dns-zone

# LDAP anonymous-bind check
python SpectraScan.py -t 10.0.0.5 --ldap
```

### 🌑 Dark Web Recon

Dark-web functionality is exposed through the interactive menu:

```text
Main Menu
└── 3. Protocol Modules
    └── 14. Dark Web Recon
```

Available operations:

| Option | Action | Tor |
|---:|---|:---:|
| `1` | Auto-detect & analyze target | Depends |
| `2` | HTTPS `.onion` banner grab | ✅ |
| `3` | BTC first-seen + heuristic analysis | ❌ |
| `4` | Extract `.onion` links from text | ❌ |
| `5` | Ahmia search | ❌ |
| `6` | Tor connectivity check | ✅ |
| `7` | Full recon | Depends |
| `8` | Back | — |

### 📊 Reports

```bash
# View saved reports
python SpectraScan.py -r

# HTML report
python SpectraScan.py -t target.com -o report.html -f html

# JSON report
python SpectraScan.py -t target.com -o report.json -f json
```

---

## 🧭 CLI Menu

```text
╭──────────────────────────────────────────────╮
│                 SpectraScan                  │
├──────────────────────────────────────────────┤
│  1. Port Scanner                             │
│  2. Advanced Modules                         │
│  3. Protocol Modules                         │
│  4. Exit                                     │
╰──────────────────────────────────────────────╯
```

### Menu Overview

| Menu | Includes |
|---|---|
| **1. Port Scanner** | TCP / SYN / UDP · timing profiles · port ranges / lists / top-N |
| **2. Advanced Modules** | Domain · IP · Email · Phone · Image EXIF · Links · Reports |
| **3. Protocol Modules** | SMB · SNMP · LDAP · RDP · SMTP · DNS · NFS · VNC · Redis · MongoDB · SIP · RTSP · Databases · Dark Web |
| **4. Exit** | Clean shutdown and report flushing |

---

## ⚙️ Configuration

### Timing Profiles

The profiles follow an Nmap-style naming convention:

| Profile | Name | Description |
|---|---|---|
| `T0` | Paranoid | Extremely slow |
| `T1` | Sneaky | Low-noise scanning |
| `T2` | Polite | Conservative bandwidth usage |
| `T3` | Normal | Default balanced profile |
| `T4` | Aggressive | Faster, noisier |
| `T5` | Insane | Maximum speed and noise |

### Output Verbosity

```text
-v     INFO     Open ports and normal status
-vv    DEBUG    Detailed probes and raw banners
-q     QUIET    Final report only
```

---

## 📊 Output Examples

### Port Scan

```text
PORT    STATE    SERVICE    VERSION
22/tcp  open     ssh        OpenSSH 8.9p1
80/tcp  open     http       nginx 1.24.0
443/tcp open     https      nginx / TLS 1.3
```

### Saved Reports

```text
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
├── SpectraScan.py
├── modules/
│   ├── __init__.py
│   ├── brute_forcer.py
│   ├── vuln_scanner.py
│   ├── web_enumerator.py
│   ├── phone_scanner.py
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
│   └── darkweb.py
├── CHANGELOG.md
├── LICENSE
├── README.md
├── requirements.txt
└── .gitignore
```

---

## ⚡ Performance & Threading

| Component | Strategy | Default |
|---|---|---:|
| Port scanner | `ThreadPoolExecutor` | `min(512, ports × targets)` |
| Protocol enumeration | One thread per protocol | `len(protocols)` |
| Brute forcer | Thread pool + semaphore | 16 |
| Web fuzzer | `ThreadPoolExecutor` | 32 |
| DNS zone | Serial | 1 |
| BTC lookup | Serial fallback chain | 1 |
| Dark-web banner | Serial / Tor-bound | 1 |

### Network Fairness

- Modules can apply jitter between bursts.
- Credential testing uses exponential back-off after repeated failures.
- `--throttle N` provides a global millisecond delay override.

---

## 🌍 Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `TOR_HOST` | `127.0.0.1` | Tor SOCKS5 host |
| `TOR_PORT` | `9050` | Tor SOCKS5 port |
| `SPECTRASCAN_HOME` | `~/.local/share/SpectraScan` | Report directory |
| `NUMVERIFY_KEY` | — | NumVerify API key |
| `SHODAN_KEY` | — | Shodan API key |
| `NVD_API_KEY` | — | NVD API key |
| `EMAILREP_KEY` | — | emailrep.io key |
| `HTTP_PROXY` | — | Global outbound HTTP proxy |

---

## 🆚 Comparison

SpectraScan is intended to complement established security tooling rather than
replace every specialized tool.

| Capability | SpectraScan | Nmap | Recon-ng | SpiderFoot |
|---|:---:|:---:|:---:|:---:|
| Port scanning | ✅ | ✅ | ⚠️ | ❌ |
| OS fingerprinting | ✅ | ✅ | ⚠️ | ⚠️ |
| OSINT suite | ✅ | ❌ | ✅ | ✅ |
| SMB / LDAP / SNMP | ✅ | ⚠️ | ⚠️ | ❌ |
| Credential testing | ✅ | ❌ | ⚠️ | ❌ |
| CVE correlation | ✅ | ⚠️ | ⚠️ | ✅ |
| Dark-web recon | ✅ | ❌ | ⚠️ | ✅ |
| BTC profiling | ✅ | ❌ | ❌ | ⚠️ |
| HTML reports | ✅ | ⚠️ | ✅ | ✅ |
| Interactive CLI | ✅ | ❌ | ✅ | ❌ |

---

## 🩺 Troubleshooting

| Problem | Likely Cause | Fix |
|---|---|---|
| `Permission denied` on SYN scan | Missing privileges | Run with appropriate administrator/root privileges |
| `.onion` connection hangs | Tor unavailable / wrong port | Check `TOR_HOST` and `TOR_PORT` |
| `pysocks` missing | Optional dependency absent | `pip install pysocks` |
| TLS parsing is limited | `cryptography` missing | `pip install cryptography` |
| BTC APIs fail | Network / rate limit | Retry later or review proxy settings |
| Rich UI looks broken | Terminal capability issue | Use a 256-color capable terminal |
| `ModuleNotFoundError: requests` | Dependency missing | Install project requirements |
| Windows SYN scan fails | Raw-packet support unavailable | Install a compatible Npcap setup |
| Reports use the wrong folder | Custom path not configured | Set `SPECTRASCAN_HOME` |

---



### Async Scanner Engine

SpectraScan now includes an additive `AsyncPortScanner` engine in `modules/async_scanner.py`. It uses `asyncio` for concurrent TCP probing and `aiohttp` for optional HTTP enrichment without replacing the legacy `PortScanner` API.

CLI usage:

```bash
python SpectraScan.py -t scanme.nmap.org --async-scan
python SpectraScan.py -t scanme.nmap.org --async-scan --async-concurrency 200 --async-timeout 0.75
```

## 🛣️ Roadmap

- [x] Async scanner engine with `asyncio` + `aiohttp`
- [ ] Kerberos enumeration + AS-REP roasting detection
- [ ] Subdomain permutation engine
- [ ] Email-to-username correlation workflows
- [ ] WebSocket / GraphQL introspection
- [ ] Multi-user collaboration and scan sharing
- [ ] Machine-learning anomaly detection
- [ ] Official Docker image
- [ ] GitHub Actions CI/CD
- [ ] Plugin system for custom modules

---

## 🛡️ Security Notes

- Credential-testing modules include rate limiting, jitter, and timeout controls.
- External APIs are treated as optional dependencies and can fail gracefully.
- Some features require elevated privileges or platform-specific support.
- Cross-platform support targets Linux, Windows, and macOS.
- Dark Web Recon is designed for passive reconnaissance and does not
  intentionally download binaries, interact with marketplaces, or execute payloads.
- **Authorization is your responsibility.** Always obtain permission before
  probing external infrastructure.

---

## 🤝 Contributing

Contributions, bug reports, documentation improvements, protocol modules, tests,
and new legal OSINT data sources are welcome.

```bash
# Fork the repository

# Create a feature branch
git checkout -b feature/AmazingFeature

# Run tests
pytest tests/

# Format
black .

# Commit
git commit -m "feat: add AmazingFeature"

# Push
git push origin feature/AmazingFeature
```

### 💡 Contribution Ideas

- New protocol enumeration modules
- New free and legal OSINT sources
- Markdown / SARIF report exporters
- Bug fixes
- Test fixtures
- CI improvements
- Documentation improvements

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a large PR.

---

## 🙏 Acknowledgements

- [Nmap](https://nmap.org/) — timing-profile inspiration
- [Impacket](https://github.com/fortra/impacket) — protocol references
- [Rich](https://github.com/Textualize/rich) — terminal UI
- [Ahmia](https://ahmia.fi/) — clearnet dark-web search
- [Blockchair](https://blockchair.com/) / [Blockstream](https://blockstream.info/) — public Bitcoin APIs
- The Python security community ❤️

---

## ⚠️ Disclaimer

**For educational and authorized security testing only.**

SpectraScan is intended for security professionals, researchers, and learners
testing systems they own or have explicit permission to assess.

Unauthorized scanning or enumeration may violate laws, contracts, network
policies, or terms of service. The developers are not responsible for misuse.

By using SpectraScan, you agree to:

1. Scan only systems you own or are explicitly authorized to test.
2. Follow applicable local, national, and international laws.
3. Avoid illegal content and unauthorized marketplace interaction.
4. Respect service limits and applicable API policies.

---

## 📜 License

This project is licensed under the **MIT License**.

See [`LICENSE`](LICENSE) for the complete license text.

---

<div align="center">

### 🕵️‍♂️ SpectraScan

**Recon. Enumerate. Understand.**

Made with ❤️ by **ItsWanheda & An0nym0us**

[⬆ Back to top](#-spectrascan)

</div>
