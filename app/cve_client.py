import asyncio
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

import httpx

from app.config import settings

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def _nvd_headers() -> dict:
    if settings.NVD_API_KEY:
        return {"apiKey": settings.NVD_API_KEY}
    return {}


def _nvd_sleep() -> float:
    # With API key: 50 req/30s → 0.65s safe interval
    # Without: 5 req/30s → 7s safe interval
    return 0.65 if settings.NVD_API_KEY else 7.0


def _to_iso8601(dt: datetime) -> str:
    return dt.replace(microsecond=0).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_name(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()
    return normalized or None


def _parse_cpe_uri(cpe_uri: str) -> Set[str]:
    parts = cpe_uri.split(":")
    result: Set[str] = set()
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        vendor = _normalize_name(parts[3])
        product = _normalize_name(parts[4])
        if vendor:
            result.add(vendor)
        if product:
            result.add(product)
        result.add(" ".join(filter(None, [vendor, product])))
    else:
        normalized = _normalize_name(cpe_uri)
        if normalized:
            result.update(normalized.split())
    return result


def _extract_nvd_affected_names(cve: dict) -> Dict[str, List[str]]:
    affected_vendors: Set[str] = set()
    affected_products: Set[str] = set()
    affected_keywords: Set[str] = set()

    # NVD API v2: configurations is a list of objects, each with a nodes list
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe_uri = cpe_match.get("criteria") or cpe_match.get("cpe23Uri")
                if not cpe_uri:
                    continue
                values = _parse_cpe_uri(cpe_uri)
                for value in values:
                    affected_keywords.add(value)
                if cpe_uri.startswith("cpe:2.3:"):
                    parts = cpe_uri.split(":")
                    if len(parts) >= 5:
                        vendor = _normalize_name(parts[3])
                        product = _normalize_name(parts[4])
                        if vendor:
                            affected_vendors.add(vendor)
                        if product:
                            affected_products.add(product)

    return {
        "affected_vendors": sorted(affected_vendors),
        "affected_products": sorted(affected_products),
        "affected_keywords": sorted(affected_keywords),
    }


def _extract_osv_package_names(payload: dict) -> Dict[str, List[str]]:
    affected_packages: Set[str] = set()
    affected_ecosystems: Set[str] = set()
    affected_keywords: Set[str] = set()

    for vuln in payload.get("vulns", []):
        for affected in vuln.get("affected", []):
            package = affected.get("package", {})
            ecosystem = package.get("ecosystem")
            name = package.get("name")
            normalized_name = _normalize_name(name)
            normalized_ecosystem = _normalize_name(ecosystem)
            if normalized_name:
                affected_packages.add(normalized_name)
                affected_keywords.update(normalized_name.split())
            if normalized_ecosystem:
                affected_ecosystems.add(normalized_ecosystem)
                affected_keywords.update(normalized_ecosystem.split())
            if normalized_name and normalized_ecosystem:
                affected_keywords.add(f"{normalized_ecosystem} {normalized_name}")

    return {
        "affected_packages": sorted(affected_packages),
        "affected_ecosystems": sorted(affected_ecosystems),
        "affected_keywords": sorted(affected_keywords),
    }


async def _nvd_get(client: httpx.AsyncClient, params: dict) -> httpx.Response:
    """GET NVD CVEs with backoff on 429. Sends API key header when configured."""
    for attempt in range(5):
        resp = await client.get(NVD_BASE_URL, params=params, headers=_nvd_headers())
        if resp.status_code != 429:
            resp.raise_for_status()
            return resp
        await asyncio.sleep(30 * (attempt + 1))
    resp.raise_for_status()
    return resp


def _parse_nvd_vuln(item: dict) -> dict:
    cve = item.get("cve", {})
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    metrics = cve.get("metrics", {})
    severity, cvss_score = "unknown", None
    for metric_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        ml = metrics.get(metric_name, [])
        if ml:
            cvss_score = str(ml[0].get("cvssData", {}).get("baseScore") or "")
            severity = (ml[0].get("cvssData", {}).get("baseSeverity") or "unknown").lower()
            break
    return {
        "cve_id": cve.get("id", ""),
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score or None,
        "fixed_version": None,
        "patched": False,
    }


async def fetch_cves_for_app(app_name: str, results: int = 100) -> List[dict]:
    """Live NVD keyword search for a given app — used by the UI endpoint."""
    params = {"keywordSearch": app_name, "resultsPerPage": min(results, 2000)}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await _nvd_get(client, params)
    return [_parse_nvd_vuln(item) for item in resp.json().get("vulnerabilities", [])]


async def search_cpe(keyword: str) -> List[dict]:
    """Search NVD CPE dictionary — lets users discover any software NVD tracks."""
    params = {"keywordSearch": keyword, "resultsPerPage": 15}
    async with httpx.AsyncClient(timeout=15.0) as client:
        for attempt in range(3):
            resp = await client.get(NVD_CPE_URL, params=params, headers=_nvd_headers())
            if resp.status_code != 429:
                break
            await asyncio.sleep(30 * (attempt + 1))
        resp.raise_for_status()

    seen: Set[str] = set()
    results: List[dict] = []
    for entry in resp.json().get("products", []):
        cpe = entry.get("cpe", {})
        cpe_name = cpe.get("cpeName", "")
        parts = cpe_name.split(":")
        if len(parts) < 5:
            continue
        product = parts[4]
        if not product or product in ("*", "-") or product in seen:
            continue
        seen.add(product)
        title = next(
            (t["title"] for t in cpe.get("titles", []) if t.get("lang") == "en"),
            product,
        )
        vendor = parts[3].replace("_", " ").replace("-", " ").title()
        results.append({"cpe": cpe_name, "app_name": product, "title": title, "vendor": vendor})
    return results


async def fetch_recent_cve_ids(start_date: datetime, end_date: datetime) -> List[str]:
    params = {
        "pubStartDate": _to_iso8601(start_date),
        "pubEndDate": _to_iso8601(end_date),
        "resultsPerPage": 200,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await _nvd_get(client, params)
        payload = response.json()

    cve_ids: List[str] = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if cve_id:
            cve_ids.append(cve_id)

    return cve_ids


async def fetch_nvd_cve_detail(cve_id: str) -> Dict[str, Optional[str]]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await _nvd_get(client, {"cveId": cve_id})
        vulns = response.json().get("vulnerabilities", [])

    if not vulns:
        return {
            "cve_id": cve_id,
            "description": "",
            "severity": "unknown",
            "cvss_score": None,
            "affected_vendors": [],
            "affected_products": [],
            "affected_keywords": [],
        }

    cve = vulns[0].get("cve", {})

    description = ""
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            description = item.get("value", "")
            break

    metrics = cve.get("metrics", {})
    cvss_score = None
    severity = None

    for metric_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics_list = metrics.get(metric_name, [])
        if metrics_list:
            metric = metrics_list[0]
            score = metric.get("cvssData", {}).get("baseScore")
            state = metric.get("cvssData", {}).get("baseSeverity")
            if score is not None:
                cvss_score = str(score)
            if state:
                severity = state.lower()
            break

    affected_meta = _extract_nvd_affected_names(cve)

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": severity or "unknown",
        "cvss_score": cvss_score,
        "affected_vendors": affected_meta["affected_vendors"],
        "affected_products": affected_meta["affected_products"],
        "affected_keywords": affected_meta["affected_keywords"],
    }


async def fetch_osv_fix(cve_id: str) -> Dict[str, Optional[str]]:
    empty: Dict[str, Optional[str]] = {
        "fixed_version": None,
        "patched": False,
        "affected_packages": [],
        "affected_ecosystems": [],
        "affected_keywords": [],
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(f"https://api.osv.dev/v1/vulns/{cve_id}")
        if response.status_code in (400, 404):
            return empty
        response.raise_for_status()
        vuln = response.json()

    affected_meta = _extract_osv_package_names({"vulns": [vuln]})

    fixed_version = None
    for affected_item in vuln.get("affected", []):
        for range_item in affected_item.get("ranges", []):
            for event in range_item.get("events", []):
                if event.get("fixed"):
                    fixed_version = event.get("fixed")
                    break
            if fixed_version:
                break
        if fixed_version:
            break

    return {
        "fixed_version": fixed_version,
        "patched": fixed_version is not None,
        "affected_packages": affected_meta["affected_packages"],
        "affected_ecosystems": affected_meta["affected_ecosystems"],
        "affected_keywords": affected_meta["affected_keywords"],
    }


async def build_cve_record(cve_id: str) -> Dict[str, Optional[str]]:
    nvd_record = await fetch_nvd_cve_detail(cve_id)
    osv_record = await fetch_osv_fix(cve_id)
    return {
        "cve_id": nvd_record["cve_id"],
        "description": nvd_record["description"],
        "severity": nvd_record["severity"],
        "cvss_score": nvd_record["cvss_score"],
        "fixed_version": osv_record["fixed_version"],
        "patched": osv_record["patched"],
        "affected_vendors": nvd_record["affected_vendors"],
        "affected_products": nvd_record["affected_products"],
        "affected_packages": osv_record["affected_packages"],
        "affected_ecosystems": osv_record["affected_ecosystems"],
        "affected_keywords": sorted(set(nvd_record["affected_keywords"] + osv_record["affected_keywords"])),
    }
