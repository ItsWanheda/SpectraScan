"""Evidence-oriented NVD CVE lookup with conservative classification."""
import logging
import time
from urllib.parse import urlencode

import requests

logger = logging.getLogger(__name__)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _severity(cve):
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if isinstance(entries, list) and entries:
            data = entries[0].get("cvssData") or {}
            value = data.get("baseSeverity") or data.get("baseScore")
            if value is not None:
                return value
    return "UNKNOWN"


def _description(cve):
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en" and isinstance(item.get("value"), str):
            return item["value"][:1000]
    return ""


class VulnScanner:
    def __init__(self, service_name, version, vendor=None, product=None, cpe_name=None,
                 session=None, max_pages=10, sleep=time.sleep):
        self.service = str(service_name or "").strip().lower()
        self.version = str(version or "").strip()
        self.vendor = str(vendor or "").strip().lower() or None
        self.product = str(product or service_name or "").strip().lower() or None
        self.cpe_name = cpe_name
        self.cves = []
        self.errors = []
        self.session = session or requests.Session()
        self.max_pages = max(1, min(int(max_pages), 100))
        self.sleep = sleep

    def _matches_cpe(self, cve):
        configurations = cve.get("configurations") or []
        if not configurations:
            return None
        terms = []
        def walk(node):
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable") and match.get("criteria"):
                    terms.append(match)
            for child in node.get("children") or []:
                walk(child)
        for config in configurations:
            for node in config.get("nodes") or []:
                walk(node)
        if not terms:
            return None
        if self.cpe_name:
            terms = [term for term in terms if term.get("criteria") == self.cpe_name]
        elif self.product:
            needle = self.product.replace(" ", "_")
            terms = [term for term in terms if needle in term.get("criteria", "").lower()]
            if self.vendor:
                terms = [term for term in terms if self.vendor.replace(" ", "_") in term.get("criteria", "").lower()]
        else:
            return None
        if not terms:
            return False
        if not self.version:
            return None
        for term in terms:
            criteria = term.get("criteria", "")
            parts = criteria.split(":")
            cpe_version = parts[5] if len(parts) > 5 else "*"
            if cpe_version == self.version:
                return True
            # NVD version bounds are inclusive/exclusive and must be respected.
            start_inc, start_exc = term.get("versionStartIncluding"), term.get("versionStartExcluding")
            end_inc, end_exc = term.get("versionEndIncluding"), term.get("versionEndExcluding")
            if any((start_inc, start_exc, end_inc, end_exc)):
                # Avoid unsafe lexicographic version comparisons; ambiguous ranges remain potential.
                return None
        return False

    def check_nvd_api(self):
        self.cves = []
        params = {"cpeName": self.cpe_name} if self.cpe_name else {"keywordSearch": " ".join(x for x in (self.vendor, self.product, self.service, self.version) if x)}
        start_index = 0
        seen = set()
        for _ in range(self.max_pages):
            try:
                response = self.session.get(NVD_URL, params={**params, "startIndex": start_index, "resultsPerPage": 100},
                                            headers={"Accept": "application/json"}, timeout=(3.05, 15))
                if response.status_code == 429:
                    retry = response.headers.get("Retry-After", "2")
                    try:
                        self.sleep(min(max(float(retry), 1), 30))
                    except (TypeError, ValueError):
                        self.sleep(2)
                    response = self.session.get(NVD_URL, params={**params, "startIndex": start_index, "resultsPerPage": 100},
                                                headers={"Accept": "application/json"}, timeout=(3.05, 15))
                response.raise_for_status()
                data = response.json()
                entries = data.get("vulnerabilities")
                if not isinstance(entries, list):
                    raise ValueError("NVD response has no valid vulnerabilities list")
            except (requests.RequestException, ValueError, TypeError) as exc:
                self.errors.append({"category": "nvd_api_error", "error_type": type(exc).__name__})
                logger.warning("NVD query failed (%s)", type(exc).__name__)
                break

            for item in entries:
                cve = item.get("cve") if isinstance(item, dict) else None
                if not isinstance(cve, dict):
                    continue
                cve_id = cve.get("id")
                if not cve_id or cve_id in seen:
                    continue
                seen.add(cve_id)
                match = self._matches_cpe(cve)
                classification = "confirmed" if match is True else "potential" if match is None else "informational"
                self.cves.append({"id": cve_id, "severity": _severity(cve),
                    "description": _description(cve), "classification": classification,
                    "evidence": {"vendor": self.vendor, "product": self.product,
                                 "detected_version": self.version, "cpe_name": self.cpe_name},
                    "reason": ("CPE and detected version match available evidence" if match is True else
                               "Search result; affected version could not be confirmed" if match is None else
                               "No matching vulnerable CPE found for the supplied product")})
            total = data.get("totalResults", len(entries))
            start_index += len(entries)
            if not entries or start_index >= total:
                break
        return self.cves

    def get_results(self):
        return list(self.cves)
