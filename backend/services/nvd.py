import asyncio
import logging
import os
import random

import httpx
from fastapi import HTTPException

from services.versions import compare_versions, version_lt

# Base URL for the NVD API
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json"

# Initialize a logger for this module
logger = logging.getLogger(__name__)

# NVD rate limits by API key presence: 5 requests / 30 s anonymous, 50 / 30 s
# with a key (https://nvd.nist.gov/developers/start-here). A nightly refresh
# over a few dozen products blows straight through the anonymous budget, and
# NVD answers with 403/429 rather than an error the caller would notice — the
# component simply comes back with no vulnerabilities. Request a free key at
# https://nvd.nist.gov/developers/request-an-api-key and set NVD_API_KEY.
_API_KEY = os.getenv("NVD_API_KEY")

# Minimum spacing between requests, derived from the applicable budget with
# headroom (the limit is a rolling window, not a token bucket). Override with
# NVD_MIN_INTERVAL — raise it if NVD still throttles you, or set it to 0 when
# the API is mocked.
_DEFAULT_MIN_INTERVAL = 0.7 if _API_KEY else 6.5
try:
    _MIN_INTERVAL = float(os.getenv("NVD_MIN_INTERVAL", _DEFAULT_MIN_INTERVAL))
except ValueError:
    logger.warning("NVD_MIN_INTERVAL is not a number, using the default")
    _MIN_INTERVAL = _DEFAULT_MIN_INTERVAL

_MAX_RETRIES = 4
_BACKOFF_BASE = 2.0
_TIMEOUT = 30.0

# NVD counts requests per source IP, so the pacing has to be process-wide
# rather than per-call: without the lock a refresh_all fan-out would issue
# every request at once and trip the limit on the first component.
_throttle_lock = asyncio.Lock()
_last_request_at = 0.0


def has_api_key() -> bool:
    return bool(_API_KEY)


async def _throttle() -> None:
    """Space requests out so we stay inside the applicable NVD budget."""
    if _MIN_INTERVAL <= 0:
        return
    global _last_request_at
    async with _throttle_lock:
        loop = asyncio.get_running_loop()
        wait = _last_request_at + _MIN_INTERVAL - loop.time()
        if wait > 0:
            await asyncio.sleep(wait)
        _last_request_at = loop.time()


async def _get_with_retry(client: httpx.AsyncClient, url: str, params: dict) -> httpx.Response:
    """
    GET with throttling and exponential backoff on rate limits.

    NVD signals throttling with 403 as well as 429, and returns 503 under load;
    all three are worth retrying. Anything else is returned to the caller as-is.
    """
    headers = {"apiKey": _API_KEY} if _API_KEY else {}
    last_response = None

    for attempt in range(_MAX_RETRIES):
        await _throttle()
        try:
            response = await client.get(url, params=params, headers=headers, timeout=_TIMEOUT)
        except httpx.TimeoutException:
            if attempt == _MAX_RETRIES - 1:
                raise
            delay = _BACKOFF_BASE ** attempt + random.uniform(0, 0.5)
            logger.warning(f"NVD timed out, retrying in {delay:.1f}s "
                           f"(attempt {attempt + 1}/{_MAX_RETRIES})")
            await asyncio.sleep(delay)
            continue

        if response.status_code not in (403, 429, 503):
            return response

        last_response = response
        if attempt == _MAX_RETRIES - 1:
            break

        # Honour Retry-After when NVD sends one, else exponential backoff with
        # jitter so parallel refreshes do not resynchronise on the same slot.
        retry_after = response.headers.get("Retry-After")
        try:
            delay = float(retry_after) if retry_after else _BACKOFF_BASE ** attempt
        except ValueError:
            delay = _BACKOFF_BASE ** attempt
        delay += random.uniform(0, 0.5)

        logger.warning(
            f"NVD rate-limited (HTTP {response.status_code}), retrying in {delay:.1f}s "
            f"(attempt {attempt + 1}/{_MAX_RETRIES})"
            + ("" if _API_KEY else " — set NVD_API_KEY to raise the limit 10x")
        )
        await asyncio.sleep(delay)

    return last_response


def _fixed_version_from_configurations(cve: dict, version: str) -> str | None:
    """
    The version that fixes this CVE, if NVD says so unambiguously.

    Only `versionEndExcluding` states a fix: "everything below X is affected"
    means X carries the patch. `versionEndIncluding` says the opposite — X is
    still vulnerable and the fix is some later, unnamed release — and an exact
    CPE match carries no range at all. Both yield None rather than a guess,
    which is why products often have no fix version while libraries do.
    """
    candidates = []
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                end_excluding = match.get("versionEndExcluding")
                if not end_excluding:
                    continue
                start = match.get("versionStartIncluding")
                if start and version_lt(version, start):
                    continue  # range starts after our version
                if not version_lt(version, end_excluding):
                    continue  # we are already at or past this fix
                candidates.append(end_excluding)

    if not candidates:
        return None
    lowest = candidates[0]
    for candidate in candidates[1:]:
        if compare_versions(candidate, lowest) < 0:
            lowest = candidate
    return lowest


async def analyze_nvd(identifier: str, name: str, version: str) -> list[dict]:
    """
    Queries the NVD API using a CPE identifier to retrieve a list of vulnerabilities.

    Parameters:
        identifier (str): The CPE name identifier (e.g., "cpe:2.3:a:f5:nginx:1.24.0").
        name (str): The name of the product/component (used for context/logging).
        version (str): The version of the product/component (used for context/logging).

    Returns:
        list[dict]: A list of vulnerabilities in structured dictionary format.
    """
    url = f"{NVD_API_BASE}/cves/2.0"
    params = {"cpeName": identifier}
    logger.info(f"Querying NVD for identifier: {identifier}"
                + ("" if _API_KEY else " (no API key — throttled to 5 req/30s)"))

    async with httpx.AsyncClient() as client:
        response = await _get_with_retry(client, url, params)

        if response is None or response.status_code != 200:
            status = response.status_code if response is not None else "no response"
            body = response.text if response is not None else ""
            logger.error(f"NVD request failed with status {status}: {body}")
            raise HTTPException(status_code=404, detail=f"NVD error: {body}")

        data = response.json()
        vulns = data.get("vulnerabilities", [])
        result = []

        for vuln in vulns:
            cve = vuln.get("cve", {})
            descriptions = cve.get("descriptions", [])
            # Get English summary if available
            summary = next((d["value"] for d in descriptions if d["lang"] == "en"), None)
            # Append a structured vulnerability dictionary to the result list
            metrics = cve.get("metrics", {})
            cvss_score = None
            if metrics.get("cvssMetricV31"):
                metric = metrics["cvssMetricV31"][0]["cvssData"]
                severity   = metric.get("baseSeverity", "unknown").lower()
                cvss_score = metric.get("baseScore")
            elif metrics.get("cvssMetricV30"):
                metric = metrics["cvssMetricV30"][0]["cvssData"]
                severity   = metric.get("baseSeverity", "unknown").lower()
                cvss_score = metric.get("baseScore")
            elif metrics.get("cvssMetricV2"):
                metric = metrics["cvssMetricV2"][0]
                severity   = metric.get("baseSeverity", "unknown").lower()
                cvss_score = metric.get("cvssData", {}).get("baseScore")
            else:
                severity = "unknown"

            try:
                fixed_version = _fixed_version_from_configurations(cve, version)
            except Exception as e:
                logger.warning(f"Could not resolve fix version for {cve.get('id')}: {e}")
                fixed_version = None

            result.append({
                "id": cve.get("id"),
                "summary": summary,
                "details": None,
                "aliases": [],
                "severity": severity,
                "cvss_score": cvss_score,
                "fixed_version": fixed_version,
                "source": "nvd",
            })

        logger.info(f"Found {len(result)} NVD vulnerabilities for {name} {version}")
        return result
