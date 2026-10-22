"""NVD CVE lookup with cautious CPE/version correlation.

Keyword-only matches are never presented as confirmed vulnerabilities.
The legacy VulnScanner(service_name, version) constructor remains supported.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, Iterable, Optional

import requests

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _version_key(value: str) -> Optional[tuple]:
    """Compare plain numeric dotted versions; decline ambiguous formats."""
    if not value or not re.fullmatch(r"\d+(?:\.\d+){0,7}", value):
        return None
    try:
        parts = [int(part) for part in value.split(".")]
        # Treat release notation such as 9.1 and 9.1.0 as equivalent.
        while len(parts) < 8:
            parts.append(0)
        return tuple(parts)
    except ValueError:
        return None


def _cpe_parts(criteria: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    parts = (criteria or "").split(":")
    if len(parts) < 6 or not parts[0].startswith("cpe"):
        return None, None, None
    return parts[3].lower(), parts[4].lower(), parts[5].lower()


def _all_cpe_matches(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        if "criteria" in value or "cpe23Uri" in value:
            yield value
        for child in value.values():
            yield from _all_cpe_matches(child)
    elif isinstance(value, list):
        for child in value:
            yield from _all_cpe_matches(child)


def _version_in_range(version: str, match: Dict[str, Any]) -> Optional[bool]:
    key = _version_key(version)
    if key is None:
        return None
    criteria = match.get("criteria") or match.get("cpe23Uri") or ""
    _, _, cpe_version = _cpe_parts(criteria)
    if cpe_version not in {None, "", "*", "-"}:
        cpe_key = _version_key(cpe_version)
        if cpe_key is None:
            return version.lower() == cpe_version.lower()
        return key == cpe_key
    bounds = (
        ("versionStartIncluding", ">="), ("versionStartExcluding", ">"),
        ("versionEndIncluding", "<="), ("versionEndExcluding", "<"),
    )
    for field, operation in bounds:
        bound = match.get(field)
        if not bound:
            continue
        bound_key = _version_key(str(bound))
        if bound_key is None:
            return None
        if operation == ">=" and key < bound_key:
            return False
        if operation == ">" and key <= bound_key:
            return False
        if operation == "<=" and key > bound_key:
            return False
        if operation == "<" and key >= bound_key:
            return False
    has_range = any(match.get(field) for field, _ in bounds)
    return True if has_range or cpe_version in {"*", "-"} else None


class VulnScanner:
    def __init__(
        self, service_name: str, version: Optional[str] = None,
        vendor: Optional[str] = None, product: Optional[str] = None,
        cpe: Optional[str] = None, api_key: Optional[str] = None,
        timeout: float = 8.0, max_records: int = 300,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.service = (service_name or "").strip().lower()
        self.version = (version or "").strip()
        self.vendor = (vendor or "").strip().lower()
        self.product = (product or service_name or "").strip().lower()
        self.cpe = (cpe or self._build_cpe()).strip() or None
        self.api_key = api_key
        self.timeout = max(1.0, min(float(timeout), 60.0))
        self.max_records = max(1, min(int(max_records), 2000))
        self.session = session or requests.Session()
        self.cves: list[Dict[str, Any]] = []
        self.errors: list[Dict[str, Any]] = []

    def _build_cpe(self) -> str:
        safe = re.compile(r"^[a-z0-9_.-]+$")
        if self.vendor and self.product and self.version and all(
            safe.fullmatch(value) for value in (self.vendor, self.product, self.version)
        ):
            return f"cpe:2.3:a:{self.vendor}:{self.product}:{self.version}:*:*:*:*:*:*:*"
        return ""

    def _params(self, start_index: int) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "startIndex": start_index,
            "resultsPerPage": min(200, self.max_records - start_index),
        }
        if self.cpe:
            params["cpeName"] = self.cpe
        else:
            params["keywordSearch"] = " ".join(
                value for value in (self.vendor, self.product, self.version) if value
            )
        return params

    @staticmethod
    def _metrics(cve: Dict[str, Any]) -> tuple[Optional[str], Optional[float], Optional[str]]:
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key)
            if not isinstance(values, list) or not values:
                continue
            entry = values[0] if isinstance(values[0], dict) else {}
            cvss = entry.get("cvssData") or {}
            severity = cvss.get("baseSeverity") or entry.get("baseSeverity")
            score = cvss.get("baseScore")
            vector = cvss.get("vectorString")
            return (
                str(severity).upper() if severity else None,
                float(score) if isinstance(score, (int, float)) else None,
                vector,
            )
        return None, None, None

    def _match_evidence(self, cve: Dict[str, Any]) -> tuple[str, list[str]]:
        evidence: list[str] = []
        candidates = []
        for match in _all_cpe_matches(cve.get("configurations") or []):
            if match.get("vulnerable") is False:
                continue
            criteria = match.get("criteria") or match.get("cpe23Uri") or ""
            vendor, product, _ = _cpe_parts(criteria)
            if self.vendor and vendor not in {self.vendor, "*", "-"}:
                continue
            if self.product and product not in {self.product, "*", "-"}:
                continue
            in_range = _version_in_range(self.version, match) if self.version else None
            if in_range is True:
                candidates.append(match)
            elif in_range is None:
                evidence.append(f"Software CPE matched ({criteria}) but version applicability could not be proven.")
        if candidates:
            matched = candidates[0]
            criteria = matched.get("criteria") or matched.get("cpe23Uri")
            evidence.append(f"Detected product/version matches an NVD vulnerable CPE range: {criteria}.")
            for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
                if matched.get(key):
                    evidence.append(f"{key}={matched[key]}")
            # Static version/CPE correlation is evidence of potential exposure, not live confirmation.
            evidence.append("This is a version-based correlation only; verify exploit preconditions before treating it as confirmed.")
            return "potential", evidence
        if self.cpe:
            evidence.append("NVD returned the exact CPE query, but no corroborating affected-version range was exposed.")
            return "potential", evidence
        if self.version and self.vendor and self.product:
            evidence.append("Keyword result only; no exact vulnerable CPE/version range was confirmed.")
            return "potential", evidence
        evidence.append("Broad keyword correlation only; product/version identity is insufficient for a vulnerability claim.")
        return "informational", evidence

    def check_nvd_api(self) -> list[Dict[str, Any]]:
        """Fetch paginated NVD results and classify correlation strength."""
        self.cves = []
        self.errors = []
        start_index = 0
        total_results: Optional[int] = None
        headers = {"Accept": "application/json", "User-Agent": "SpectraScan-CVE-Scanner/2.1"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        while start_index < self.max_records and (total_results is None or start_index < total_results):
            params = self._params(start_index)
            params["resultsPerPage"] = min(200, self.max_records - start_index)
            try:
                response = self.session.get(NVD_ENDPOINT, params=params, headers=headers, timeout=self.timeout)
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", "1")
                    try:
                        delay = max(0.0, min(float(retry_after), 5.0))
                    except (ValueError, TypeError):
                        delay = 1.0
                    time.sleep(delay)
                    response = self.session.get(NVD_ENDPOINT, params=params, headers=headers, timeout=self.timeout)
                if response.status_code in (403, 429):
                    self.errors.append({"category": "rate_limited", "status_code": response.status_code, "message": "NVD rate limit or access policy prevented further results."})
                    break
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("NVD returned a non-object JSON response")
                total_results = int(payload.get("totalResults", 0))
                vulnerabilities = payload.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    raise ValueError("NVD vulnerabilities field was not a list")
                if not vulnerabilities:
                    break
                for item in vulnerabilities:
                    cve = item.get("cve") if isinstance(item, dict) else None
                    if not isinstance(cve, dict) or not cve.get("id"):
                        continue
                    descriptions = cve.get("descriptions") or []
                    description = next((
                        row.get("value", "") for row in descriptions
                        if isinstance(row, dict) and row.get("lang") == "en"
                    ), "")
                    severity, score, vector = self._metrics(cve)
                    classification, evidence = self._match_evidence(cve)
                    self.cves.append({
                        "id": cve["id"], "severity": severity or "UNKNOWN",
                        "cvss_score": score, "cvss_vector": vector,
                        "description": str(description)[:500],
                        "classification": classification, "evidence": evidence,
                        "reason": evidence[0] if evidence else "No usable version evidence was returned.",
                        "source": "NVD",
                    })
                    if len(self.cves) >= self.max_records:
                        break
                start_index += len(vulnerabilities)
                if start_index >= total_results:
                    break
            except (requests.Timeout, requests.ConnectionError) as exc:
                self.errors.append({"category": "network_error", "message": type(exc).__name__})
                break
            except requests.HTTPError as exc:
                status = getattr(exc.response, "status_code", None)
                self.errors.append({"category": "http_error", "status_code": status, "message": "NVD returned an HTTP error."})
                break
            except (ValueError, TypeError, KeyError):
                self.errors.append({"category": "invalid_response", "message": "NVD response was malformed."})
                break
            except requests.RequestException as exc:
                self.errors.append({"category": "request_error", "message": type(exc).__name__})
                break
        return list(self.cves)

    def get_results(self) -> list[Dict[str, Any]]:
        return list(self.cves)
