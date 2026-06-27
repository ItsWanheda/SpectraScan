# Changelog

All notable changes to this project will be documented in this file.

---
## [Unreleased]

### 🚀 Added — Dark Web Recon Module

A brand-new **Dark Web Recon** layer has been integrated as a strictly passive, ethical reconnaissance module.

> **Ethical policy:** no marketplace interaction, no payload execution, no illegal content, hard timeouts on every network call, no auto-Tor-launch. Clearnet checks work without Tor; only `.onion` operations require it.

**New file:** `modules/darkweb.py`

| Feature | Source / API | Auth required |
|---|---|---|
| `.onion` v2 / v3 resolve + HTTP banner | Tor SOCKS5 (`127.0.0.1:9050`) via `pysocks` | local Tor |
| Ahmia search (`.onion` results for a keyword) | `https://ahmia.fi/api/v1/search` | none |
| PGP public-key lookup by email or name | `https://keys.openpgp.org/vks/v1/...` | none |
| Email / domain leak & reputation | `https://emailrep.io/` | none |
| BTC address report (balance, tx count, totals) | `https://blockchain.info/rawaddr/` | none |
| Structured JSON report | local file | — |

**Module design highlights:**
- Single class `DarkWebScanner` — easy to import as a library.
- Hard-coded timeouts (HTTP: 15s, `.onion`: 12s, BTC: 10s) prevent runaway connections.
- Auto-saves results to `~/.local/share/SpectraScan/SS-darkweb-<target>-<timestamp>.json`.
- Auto-detects whether the target is a BTC address, `.onion`, or generic keyword and pre-selects the appropriate menu item.
- "Run ALL passive checks" option batches every check that applies to the current target.

**CLI integration:**
- New entry `14. Dark Web Recon` inside `run_protocol_modules()` (option 3 of the main menu).
- Old `Back to main menu` entry shifted from `14` → `15`.
- Graceful degradation: if `pysocks` is missing, the module warns and disables only the `.onion` checks; everything else keeps working.
- Import errors are caught by the existing `try/except` in the dispatch block, so a missing module cannot abort the rest of the CLI.

### 📦 Dependencies

- **Added (optional):** `pysocks` — required only for `.onion` resolve + hidden-service banner. The module continues to function without it.
- `requirements.txt` updated with a documented `pysocks` entry and an explanatory comment block.

### 🧹 Changed

- `run_protocol_modules()` menu header updated to show options `1–15` (added `14. Dark Web Recon`, renumbered back-button to `15`).
- `run_protocol_modules()` dispatch block updated with the new `elif choice == "14"` branch and shifted back-button check to `"15"`.

### 📝 Documentation

- New "🌑 Dark Web Recon Module" section in `README.md` (features, ethical notes, requirements).
- New "🔹 Dark Web Recon" usage section in `README.md` explaining the in-menu workflow.
- Updated `🧭 CLI Menu` table to list `Dark Web Recon` under Protocol Modules.
- Updated `🧩 Project Structure` to include `modules/darkweb.py`.
- Updated `📦 Installation` with `pysocks` install line and Tor notes.
- Updated `🛡️ Security Notes` and `⚠️ Disclaimer` to cover the dark-web functionality.

### 📂 Files

**New:**
- `modules/darkweb.py`

**Modified:**
- `SpectraScan.py` (menu header + dispatch block only)
- `README.md`
- `CHANGELOG.md`
- `requirements.txt`

---

## [released]

---

## [2.1.0] - 2026-06-24

### 🚀 Added

#### Protocol Modules Suite

  A brand-new layer of protocol-level enumerators built from scratch with **pure-Python** implementations. No third-party libraries are required for core functionality — optional libraries are used opportunistically when available.

  **13 new modules under `modules/`:**

| Module | Protocol | Capabilities |
|---|---|---|
| `smb_enum.py` | SMB/CIFS (445) | SMBv1/v2/v3 negotiation, share enumeration, anonymous auth detection, OS/hostname/domain via impacket |
| `snmp_enum.py` | SNMP (161) | Custom BER encoder/parser, default-community brute-force, system-info queries |
| `ldap_enum.py` | LDAP (389) / LDAPS (636) | Anonymous bind detection, root DSE, user/group enumeration via ldapsearch |
| `rdp_enum.py` | RDP (3389) | X.224/TPKT parsing, NLA detection, BlueKeep (CVE-2019-0708) heuristic |
| `smtp_enum.py` | SMTP (25) | Banner, VRFY, open-relay test, STARTTLS support |
| `dns_zone.py` | DNS (53) | AXFR zone-transfer attempts against all NS records |
| `nfs_enum.py` | NFS (2049) | RPC portmapper dump, MOUNTD EXPORT call, showmount fallback |
| `vnc_enum.py` | VNC (5900) | RFB handshake, auth-type enumeration, no-auth detection |
| `redis_enum.py` | Redis (6379) | RESP protocol client, INFO/DBSIZE/RANDOMKEY sampling |
| `mongodb_enum.py` | MongoDB (27017) | OP_MSG wire protocol, custom BSON encoder/parser, isMaster/listDatabases |
| `sip_enum.py` | SIP (5060) | UDP OPTIONS probe |
| `rtsp_enum.py` | RTSP (554) | DESCRIBE across common stream paths, SDP capture |
| `database_enum.py` | MySQL/PostgreSQL/MSSQL | Hand-rolled protocol clients with version detection |

---

#### Aggregator & Registry

- **`modules/network_services.py`** — Port-to-module dispatcher with parallel `deep_scan(ip, ports)` using `ThreadPoolExecutor`
- **`modules/__init__.py`** — Centralised registry exposing every module as a library

---

#### New CLI Integration

- **Option 3 — Protocol Modules (SMB / SNMP / LDAP / RDP / SMTP / DNS / NFS / VNC / Redis / MongoDB / SIP / RTSP / DBs)** in the main menu
- Each enumerator can be invoked interactively with prompts for target, port, and credentials
- Backward-compatible with Options 1 (Port Scanner) and 2 (Advanced Modules)
- Added a legacy-CLI short-circuit: `python SpectraScan.py -t <target>` runs a default scan

---

### 🐛 Fixed

- **MySQL handshake length parsing** — `pkt_len` was computed by OR-ing the same byte three times; now correctly reads `header | (header << 8) | (header << 16)`.
- **LDAP method-name typo** — `hasattr(LDAPEnumerator, '_build_search_root_dSE')` no longer matches; replaced with a defensive fallback to the correct method name.
- **Duplicate file content** — `dns_zone.py`, `sip_enum.py`, and `rtsp_enum.py` had been overwritten with copies of unrelated modules during a prior paste operation; all three files now contain their intended implementations.
- **`ProtocolModuleScanner._print_result`** — Now uses Rich console for consistent output across the CLI.

---

## 🧹 Changed

- **`main()`** now detects legacy CLI arguments (`-t`) and exits cleanly after the scan, enabling non-interactive usage.
- All protocol-module calls in the menu are wrapped in `try/except` so a single failure cannot abort the whole run.
- `hacker_input()` helper supports default values for faster interaction.

---

## 📝 Documentation

- New "Protocol Enumeration Modules" section in `README.md`
- Updated CLI menu table and project structure
- Updated `requirements.txt` with the optional `shodan` entry for the IP scanner

---

## 📂 New Files

**New:**

- modules/smb_enum.py
- modules/snmp_enum.py
- modules/ldap_enum.py
- modules/rdp_enum.py
- modules/smtp_enum.py
- modules/dns_zone.py
- modules/nfs_enum.py
- modules/vnc_enum.py
- modules/redis_enum.py
- modules/mongodb_enum.py
- modules/sip_enum.py
- modules/rtsp_enum.py
- modules/database_enum.py
- modules/network_services.py

**Modified:**

- modules/ init.py
- SpectraScan.py
- README.md
- CHANGELOG.md
- requirements.txt

---

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