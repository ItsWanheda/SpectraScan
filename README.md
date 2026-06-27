# 🕵️‍♂️ SpectraScan

> **Advanced Network Reconnaissance, Port Scanning & OSINT Intelligence Tool**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)]()
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**SpectraScan** is a high-performance, multi-threaded network intelligence framework written in Python. It bridges the gap between traditional port scanning and deep reconnaissance by integrating OS fingerprinting, SSL/TLS analysis, a massive **OSINT Suite**, and a **Dark Web Recon** module.

Designed for security professionals, pentesters, and network administrators who need a single, modular tool for end-to-end target profiling.

---

## ✨ Features

### 🛠️ Core Scanning Engine
*High-speed network enumeration and service identification.*

- **🔍 Multi-Protocol Scanning** — TCP, SYN, and UDP scanning with configurable timing profiles.
- **🛡️ Firewall Detection** — Basic firewall and filtering behavior analysis.
- **🕵️ OS Fingerprinting** — TTL and response-time-based OS detection.
- **🔐 SSL/TLS Analysis** — Certificate inspection, cipher suite analysis, and protocol version checks.
- **🌐 HTTP Enumeration** — Server header analysis, allowed methods, and path discovery.
- **📡 Advanced Recon** — Ping sweep, ARP scan, and traceroute-related discovery workflows.
- **⚡ High Performance** — Built with optimized structures and concurrency-friendly design.

### 🕵️ OSINT Intelligence Suite
*Deep-dive intelligence gathering for digital footprinting.*

- **🌐 Domain Intelligence** — WHOIS, DNS lookup, and host information.
- **📍 IP Intelligence** — GeoIP, WHOIS, and Shodan integration.
- **📞 Phone Intelligence** — Carrier and location lookup via NumVerify API.
- **📧 Email Intelligence** — Reputation analysis via `emailrep.io`.
- **🖼️ Metadata Extraction** — Image EXIF data harvesting using `exiv2` or `exiftool`.
- **🔗 Link Sniffing** — Automated URL extraction from target domains via HackerTarget API.
- **👮 Criminal Record Lookup** — Generates state-specific record search links.

### ⚔️ Attack & Vulnerability Modules
- **💥 Brute Force** — Dictionary-based attacks for SSH and FTP services.
- **🛡️ CVE Scanner** — Real-time vulnerability detection via NVD API integration.
- **📂 Web Fuzzing** — Advanced directory and file enumeration for web servers.

### 📁 Report Management
- **📊 Rich Reporting** — Export results to **JSON, CSV, and HTML**.
- **💾 Persistence** — Save and append scan results to local storage at `~/.local/share/SpectraScan/`.
- **📂 History Management** — Read or delete stored reports from the CLI.

### 🔬 Protocol Enumeration Modules
*Deep, protocol-aware inspection of exposed services — pure Python, no external libraries required.*

- **🔐 SMB/CIFS** — SMBv1/v2/v3 negotiation, share enumeration, anonymous auth detection, OS fingerprinting, EternalBlue flag.
- **📡 SNMP** — Custom BER encoder, default-community brute-force (`public`, `private`, `cisco`, …), system-info queries, `snmpwalk` fallback.
- **📂 LDAP / LDAPS** — Anonymous-bind detection, root DSE retrieval, user/group enumeration via `ldapsearch`.
- **🖥️ RDP** — X.224/TPKT handshake, NLA detection, BlueKeep (CVE-2019-0708) heuristic.
- **✉️ SMTP** — Banner grab, VRFY user enumeration, open-relay test, STARTTLS support.
- **🌐 DNS Zone Transfer** — AXFR attempts against all NS records; reports servers that allow transfer.
- **📁 NFS** — RPC portmapper dump, MOUNTD EXPORT call, `showmount` fallback; flags permissive exports.
- **🖼️ VNC** — RFB handshake, auth-type enumeration, no-authentication detection.
- **🗄️ Redis** — RESP protocol, INFO/DBSIZE/RANDOMKEY sampling, unauthenticated-access flag.
- **🍃 MongoDB** — Custom OP_MSG wire protocol, hand-rolled BSON encoder/parser, unauthenticated-access flag.
- **📞 SIP** — UDP OPTIONS probe with response capture.
- **🎥 RTSP** — DESCRIBE across common stream paths, SDP capture, unauthenticated-stream detection.
- **🗃️ Databases** — Hand-rolled MySQL/PostgreSQL/MSSQL clients with version detection.

### 🌑 Dark Web Recon Module
*Passive, ethical reconnaissance of `.onion` services and dark-web mentions — **no marketplace interaction, no illegal content**.*

- **🧅 `.onion` Resolve + Banner** — Verify reachability and capture HTTP headers from any v2 (16-char) or v3 (56-char) hidden service via Tor SOCKS5.
- **🔎 Ahmia Search** — Search Ahmia.fi (the ethical dark-web search engine) for keywords, emails, domains, or brand names.
- **🔑 PGP Key Lookup** — Find public PGP keys by email or name on `keys.openpgp.org`.
- **📧 Email / Domain Reputation** — Free `emailrep.io` lookups for breach / suspicious / disposable / blacklisted flags.
- **💰 BTC Address Report** — Balance, transaction count, total sent/received via `blockchain.info` (no API key).
- **🌐 Clearnet-First Design** — Most checks run over HTTPS without Tor; only `.onion` ops require Tor.
- **📄 JSON Reporting** — Auto-saves structured results to `~/.local/share/SpectraScan/SS-darkweb-*.json`.
- **⚖️ Ethical by Default** — No payload execution, hard timeouts on every network call, no auto-Tor-launch.

**Accessed from:** Main Menu → `3. Protocol Modules` → `14. Dark Web Recon`

---

## 🚀 Usage

### 🔹 Basic Reconnaissance

**Standard Port Scan**
```bash
python SpectraScan.py -t 192.168.1.1
```

**Aggressive Scan with OS Detection**
```bash
python SpectraScan.py -t example.com --os-detect -T T4
```

### 🔹 OSINT & Intelligence

**Email Reputation Check**
```bash
python SpectraScan.py -e target@example.com
```

**Domain & Link Sniffing**
```bash
python SpectraScan.py -d targetdomain.com -l
```

### 🔹 Advanced Modules

**Vulnerability Scanning (CVE)**
```bash
python SpectraScan.py -t target.com --vuln-scan
```

**Brute Force Attack**
```bash
python SpectraScan.py -t 10.0.0.5 --brute-force --wordlist ./passwords.txt
```

**Web Directory Enumeration**
```bash
python SpectraScan.py -t example.com --web-enum --wordlist ./dirb_list.txt
```

### 🔹 Dark Web Recon

> All dark-web checks are **passive** and run from the interactive menu:

```text
Main Menu → 3. Protocol Modules → 14. Dark Web Recon
```

From there you can:
1. Verify Tor reachability (`127.0.0.1:9050`)
2. Search Ahmia.fi for a keyword, email, or brand
3. Look up PGP public keys by email or name
4. Run leak / reputation checks (`emailrep.io`)
5. Report on a BTC address (balance, tx count, totals)
6. Resolve a `.onion` and capture a banner via Tor
7. Run **all passive checks** in one shot
8. Save a structured JSON report

`.onion` features require `pysocks` and a locally running Tor daemon. Clearnet checks (Ahmia, PGP, BTC, emailrep) work without Tor.

### 🔹 Report Management

**View Saved Reports**
```bash
python SpectraScan.py -r
```

**Generate HTML Report**
```bash
python SpectraScan.py -t target.com -o report.html -f html
```

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
git clone https://github.com/your-username/SpectraScan.git
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
**The interactive CLI provides:**
```text
1. Port Scanner
2. Advanced Modules (Domain / IP / Email / Phone / Image / Link / Criminal / Reports)
3. Protocol Modules (SMB / SNMP / LDAP / RDP / SMTP / DNS / NFS / VNC /
                     Redis / MongoDB / SIP / RTSP / Databases / Dark Web Recon)
4. EXIT
```

1. **Port Scanner**
   * Target IP / Hostname
   * Scan Type
   * Timing Profile
   * Ports selection
2. **Advanced Modules**
   * Domain Scanner
   * IP Scanner
   * Email Scanner
   * Phone Scanner
   * Image EXIF Scanner
   * Link Sniffer
   * Criminal Record Lookup
   * Read / Delete reports
3. **Protocol Modules**
   * SMB / SNMP / LDAP / RDP / SMTP / DNS Zone / NFS / VNC /
     Redis / MongoDB / SIP / RTSP / Databases
   * **Dark Web Recon** *(Ahmia, PGP, BTC, emailrep, `.onion` resolve)*
4. **EXIT**

---

## 🧩 Project Structure
```text
SpectraScan/
├── SpectraScan.py
├── modules/
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
├── README.md
└── requirements.txt
```

---

## 🛡️ Security Notes
* Brute-force attempts include rate limiting and timeout controls to reduce noise and lockout risk.
* External lookups may depend on third-party APIs and tools.
* Some features may require elevated privileges or platform-specific command flags.
* Cross-platform support has been improved for Windows, Linux, and macOS.
* **Dark Web Recon is strictly passive.** It does **not** download binaries, interact with marketplaces, or fetch content from illegal sources. Hard timeouts (≤ 15s) are applied to every network call. Users are responsible for ensuring they have authorization before probing any external resource.

## 🤝 Contributing
> Contributions are what make the open-source community such an amazing place to learn, inspire, and create.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⚠️ Disclaimer
**For Educational and Authorized Testing Purposes Only.**

**SpectraScan — including the Dark Web Recon module — is designed for security professionals to test their own networks or networks they have explicit permission to scan. Unauthorized scanning of networks, services, or hidden services you do not own is illegal and unethical. The developers of SpectraScan are not responsible for any misuse of this tool.**

## 📜 License
This project is licensed under the MIT License - see the (LICENSE) file for details.