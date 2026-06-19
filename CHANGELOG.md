# Changelog

All notable changes to this project will be documented in this file.

## [released]

---

## [2.0.0] - 2026-06-19

### 🚀 Added

#### SpectraScan Integration
Integrated a full **OSINT** suite:

- **Domain Scanner** — WHOIS, DNS lookup, host information
- **IP Scanner** — GeoIP, WHOIS, Shodan integration
- **Phone Scanner** — NumVerify API integration for carrier/location data
- **Email Scanner** — Reputation checks via `emailrep.io`  
  - suspicious status
  - blacklisted status
  - breach data 
- **Image EXIF Scanner** — Metadata extraction using `exiv2` or `exiftool`
- **Link Sniffer** — URL extraction from domains via HackerTarget API
- **Criminal Scanner** — State record search link generator

#### Report Management System
**Introduced a new `ReportManager` class for handling scan results:**

- **Save / Append** — Stores outputs in `~/.local/share/SpectraScan/` and appends to existing reports
- **Read / Delete** — CLI commands (`-r`, `-del`) for managing stored reports

#### New CLI Flags

- `-d`, `--domain` — Domain scanning
- `-i`, `--ip` — IP scanning
- `--phone` — Phone number scanning
- `-e`, `--email` — Email reputation scanning
- `--img` — Image EXIF extraction
- `-l`, `--link` — Link sniffing
- `--crim` — Criminal record lookup
- `-r`, `--read-report` — View saved reports
- `-del`, `--delete-report` — Remove saved reports

### 🐛 Fixed

- **Syntax Error** — Fixed incomplete statement: `if response.status in:` in `HTTPEnumerator.check_methods`
- **Path Portability* — Replaced hardcoded paths with relative module imports (`sys.path.append`) for cross-platform compatibility
- **OS Compatibility** — Updated `ping` and `arp` command flags for:
  - Windows: `-n`, `-w`
  - Linux/macOS: `-c`, `-W`

### 🧹 Changed

- **Architecture** — Refactored the codebase into modular components. SpectraScan features now live in separate classes such as `DomainScanner`, `IPScanner`, and others
- **Cleanup** — Remove bash-style comments and consolidated color definitions
- **Dependencies** — Added graceful fallbacks for external tools like `exiv2`, `exiftool`, and `shodan-cli`

### 📝 Documentation

- Expanded `argparse` help text with comprehensive examples for all new features
- Added usage instructions for the ne report management system

### 📂 New File

- modules/phone_Locator.py`

---

## [v1.5.0] - 2026-06-12

### Added

#### Modular Architecture
Refactored the codebase to support external plugins for better maintainability and scalability.

#### Brute Forcing Module
`modules/brute_forcer.py`

- Dictionary-based brute forcing for SSH and FTP services
- Support for custom wordlists via `--wordlist`
- Multi-threaded credential testing for speed

#### Vulnerability Scanner Module
`modules/vuln_scanner.py`

- Integrated NVD API queries for real-time CVE detection
- Checks service versions against known vulnerability databases
- Activated via `--vuln-scan`

#### Web Enumerator Module
`modules/web_enumerator.py`

- Advanced directory and file fuzzing for HTTP/HTTPS services
- Detects hidden paths, backups, and misconfigurations
- Activated via `--web-enum`

#### New CLI Arguments

- `--brute-force` — Enables credential testing
- `--vuln-scan` — Enables detailed CVE scanning
- `--web-enum` — Enables web directory enumeration
- `--wordlist` — Specifies path to dictionary files

### Changed

- Refactored `SpectraScan.py`:
  - Removed inline logic for brute forcing and web enumeration to reduce file size and complexity
  - Improved import handling to support optional dependencies such as `paramiko` and `requests`

### Fixed

- Resolved potential `ImportError` issues by adding graceful fallbacks for optional modules

### Security

- Added rate limiting and timeout controls to brute-force attempts to reduce account lockouts and excessive noise
