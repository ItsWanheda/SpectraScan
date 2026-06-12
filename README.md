# 🚀 SpectraScan

> **Advanced Network Reconnaissance & Port Scanning Tool**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)]()
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**SpectraScan** is a high-performance, multi-threaded network scanner written in Python. It goes beyond simple port scanning by integrating OS fingerprinting, SSL/TLS analysis, HTTP enumeration, and vulnerability heuristics. Designed for security professionals, pentesters, and network administrators.

## ✨ Features

- **🔍 Multi-Protocol Scanning**: TCP, SYN, and UDP scanning with configurable timing profiles.
- **🛡️ Stealth & Evasion**: Decoy generation, rate limiting, and firewall detection.
- **🖥️ OS Fingerprinting**: TTL-based and response-time-based OS detection.
- **🔐 SSL/TLS Analysis**: Certificate inspection, cipher suite analysis, and protocol version checking.
- **🌐 HTTP Enumeration**: Server header analysis, allowed methods, and path discovery.
- **📊 Rich Reporting**: Export results to JSON, CSV, and beautiful HTML reports.
- **⚡ High Performance**: Optimized with `concurrent.futures` and async-friendly structures.
- **🕵️‍♂️ Advanced Recon**: Ping sweep, ARP scan, and traceroute capabilities.

### Advanced Features
- **Brute Force**: `python SpectraScan.py -t <target> --brute-force --wordlist <path>`
- **Web Enumeration**: `python SpectraScnn.py -t <target> --web-enum --wordlist <path>`
- **CVE Scanning**: `python SpectraScann.py -t <target> --vuln-scan`

## 📦 Installation

### Prerequisites
- Python 3.9 or higher
- Root/Administrator privileges (required for raw socket/SYN scans)

### Clone and Setup

```bash
# Clone the repository
git clone https://github.com/your-username/SpectraScan.git
cd SpectraScan

# Create a virtual environment (recommended)
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

## 🚀 Usage
 Basic Scan
    python SpectraScan.py -t 192.168.1.1

 Advanced Scan with Vulnerability Check
    python SpectraScan.py -t example.com --vuln-check --os-detect


 Fast Scan with Rate Limiting
    python SpectraScan.py -t 10.0.0.1 -T T4 --rate-limit 50

 Network Ping Sweep
    python SpectraScan.py --ping-sweep 192.168.1.0/24

 Generate HTML Report
    python SpectraScan.py -t target.com -o report.html -f html   

## ⚙️ Configuration

Timing Profiles
Adjust the speed and stealth of the scan:

T0: Paranoid (Very slow, high stealth)
T1: Sneaky
T2: Polite
T3: Normal (Default)
T4: Aggressive
T5: Insane (Fastest, least stealth)

Common Ports
The scanner includes a predefined list of common ports (FTP, SSH, HTTP, MySQL, etc.). You can specify custom ports using -p.
```
## 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the Project
2. Create your Feature Branch (git checkout -b feature/AmazingFeature)
3. Commit your Changes (git commit -m 'Add some AmazingFeature')
4. Push to the Branch (git push origin feature/AmazingFeature)
5. Open a Pull Request

## ⚠️ Disclaimer
For Educational and Authorized Testing Purposes Only.

SpectraScan is designed for security professionals to test their own networks or networks they have explicit permission to scan. Unauthorized scanning of networks you do not own is illegal and unethical. The developers of SpectraScan are not responsible for any misuse of this tool.

## 📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements
Python Standard Library (socket, concurrent.futures, ssl)
