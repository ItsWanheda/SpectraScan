# Changelog

## [v1.5.0] - 2026-06-12
### Added
- **Modular Architecture**: Refactored codebase to support external plugins for better maintainability and scalability.
- **Brute Forcing Module** (`modules/brute_forcer.py`):
  - Added dictionary-based brute-forcing for SSH and FTP services.
  - Supports custom wordlists via `--wordlist` argument.
  - Multi-threaded for faster credential testing.
- **Vulnerability Scanner Module** (`modules/vuln_scanner.py`):
  - Integrated NVD API queries for real-time CVE detection.
  - Checks service versions against known vulnerability databases.
  - Activated via `--vuln-scan` flag.
- **Web Enumerator Module** (`modules/web_enumerator.py`):
  - Advanced directory and file fuzzing for HTTP/HTTPS services.
  - Detects hidden paths, backups, and misconfigurations.
  - Activated via `--web-enum` flag.
- **New CLI Arguments**:
  - `--brute-force`: Enables credential testing.
  - `--vuln-scan`: Enables detailed CVE scanning.
  - `--web-enum`: Enables web directory enumeration.
  - `--wordlist`: Specifies path to dictionary files.

### Changed
- **Refactored `SpectraScan.py`**:
  - Removed inline logic for brute-forcing and web enumeration to reduce file size and complexity.
  - Improved import handling to support optional dependencies (`paramiko`, `requests`).

### Fixed
- Resolved potential `ImportError` issues by adding graceful fallbacks for optional modules.

### Security
- Added rate-limiting and timeout controls to brute-force attempts to prevent account lockouts and excessive noise.