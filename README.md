# 🕵️‍♂️ SpectraScan

> **Advanced Network Reconnaissance, Port Scanning & OSINT Intelligence Tool**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)]()
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**SpectraScan** is a high-performance, multi-threaded network intelligence framework written in Python. It bridges the gap between traditional port scanning and deep reconnaissance by integrating OS fingerprinting, SSL/TLS analysis, and a massive **OSINT Suite**. 

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
- **📧 Email Intelligence** — Reputation analysis via `emailrep.io.
- **🖼️ Metadata Extraction** — Image EXIF data harvesting using `exiv2` or `exiftool`
- **🔗 Link Sniffing** — Automated URL extraction from target domains via HackerTarget API.
- **👮 Criminal Record Lookup** — Generates state-specific record search links.

### ⚔️ Attack & Vulnerability Modules
- **💥 Brute Force** — Dictionary-based attacks for SSH and FTP services.
- **🛡️ CVE Scanner** — Real-time vulnerability detection via NVD API integration.
- **📂 Web Fuzzing** — Advanced directory and file enumeration for web servers.

### 📁 Report Managemen
- **📊 Rich Reporting** — Export results to **JSON, CSV, and HTML**
- **💾 Persistence** — Save and append scan results to local storage at `~/.local/share/SpectraScan/`
- **📂 History Management** — Read or delete stored reports from the CLI.

---

## 🚀 Usage

### 🔹 Basic Recnaissance

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
* **Root/Administrator** privileges (Required for RAW sockets/SYN scans)
* **External Tools**: exiv2, exiftool, and shodan-cli (recommended)

**Setup**
```bash
# Clone the repository
git clone https://github.com/your-username/SpectraScan.git
cd SpectraScan

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On macOS/Linux
# venv\Scripts\activate  # On Windows

# Install dependencies
pip install -r requirements.txt
```

---

## Quick Start
> If you’re running the standalone script:
```bash
pip install rich
python SpectraScan.py
```

---

## 🧭 CLI Menu
**The interactive CLI provides:**

1. **Port Scanner**
* Target IP/Hostname
* Scan Type
* Timing Profile
* Ports selection
2. **Advanced Modules**
* Domain Scanner
* IP Scanner
* Email Scanner
* Phone Scanner
3. **EXIT**

---

## 🧩 Project Structure
```text
SpectraScan/
├── SpectraScan.py
├── modules/
│   ├── brute_forcer.py
│   ├── vuln_scanner.py
│   ├── web_enumerator.py
│   └── phone_Locator.py
├── CHANGELOG.md
├── README.md
└── requirements.txt
```

---

## 🛡️ Security Notes
* Brute-force attempts include rate limiting and timeout controls to reduce noise and lockout risk
* External lookups may depend on third-party APIs and tools
* Some features may require elevated privileges or platform-specific command flags
* Cross-platform support has been improved for Windows, Linux, and macOS

## 🤝 Contributing
> Contributions are what make the open-source community such an amazing place to learn, inspire, and create.

1. Fork the Project
2. Create your Feature Branch (git checkout -b feature/AmazingFeature)
3. Commit your Changes (git commit -m 'Add some AmazingFeature')
4. Push to the Branch (git push origin feature/AmazingFeature)
5. Open a Pull Request

## ⚠️ Disclaimer
**For Educational and Authorized Testing Purposes Only.**

**SpectraScan is designed for security professionals to test their own networks or networks they have explicit permission to scan. Unauthorized scanning of networks you do not own is illegal and unethical. The developers of SpectraScan are not responsible for any misuse of this tool.**

## 📜 License
This project is licensed under the MIT License - see the (LICENSE) file for details.
