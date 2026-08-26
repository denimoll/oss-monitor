"""
CVE-PaaS integration.

Enriches stored vulnerabilities with exploitation-aware prioritisation from
a self-hosted CVE-PaaS instance (https://github.com/denimoll/CVE-PaaS).

CVE-PaaS combines CVSS, EPSS, CISA/VulnCheck KEV, public PoCs and Nuclei
templates into a single `Priority` verdict, which is a far better ordering
signal than CVSS severity alone: a "high" CVSS CVE with no exploit is much
less urgent than a "medium" one that is actively exploited in the wild.

Security note: the base URL comes from stored settings or an environment
variable — never from a request body. This mirrors the webhook design and
keeps the endpoint free of SSRF.
"""

import logging
import os
import re
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# CVE-PaaS caps a bulk request at 50 IDs.
BULK_LIMIT = 50

# Only real CVE IDs can be prioritised — OSV also returns GHSA-/PYSEC-/GO- IDs,
# which vulnx cannot resolve.
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# CVE-PaaS priority ladder, most urgent first.
PRIORITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "Undefined"]
PRIORITY_RANK = {p.lower(): i for i, p in enumerate(PRIORITY_ORDER)}

_ENV_URL = os.getenv("CVEPAAS_URL")
_ENV_API_KEY = os.getenv("CVEPAAS_API_KEY")


def resolve_base_url(settings: dict) -> str | None:
    """
    Resolve the CVE-PaaS base URL: stored setting wins, env var is the default.
    Returns None when the integration is disabled or unconfigured.
    """
    if not settings.get("cvepaas_enabled"):
        return None
    url = settings.get("cvepaas_url") or _ENV_URL
    if not url:
        return None
    url = url.rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        logger.error(f"Invalid cvepaas_url, ignoring: {url!r}")
        return None
    return url


def is_cve_id(vuln_id: str | None) -> bool:
    return bool(vuln_id and CVE_ID_RE.match(vuln_id))


def pick_cve(vuln_id: str | None, aliases: str | None = None) -> str | None:
    """
    Find the CVE ID for a vulnerability.

    NVD hands us CVE IDs directly, but OSV keys advisories by GHSA/PYSEC/GO ID
    and carries the CVE in `aliases`. Without this lookup no library component
    would ever be prioritised, since OSV is the only source for them.
    """
    if is_cve_id(vuln_id):
        return vuln_id.upper()
    for alias in (aliases or "").split(","):
        alias = alias.strip()
        if is_cve_id(alias):
            return alias.upper()
    return None


def _headers() -> dict:
    return {"X-API-Key": _ENV_API_KEY} if _ENV_API_KEY else {}


def _normalize(entry: dict) -> dict | None:
    """
    Flatten one CVE-PaaS result into the fields we persist.
    Returns None for error records (`{"error": ...}`) so they are skipped
    and retried on the next run instead of overwriting good data.
    """
    if not isinstance(entry, dict) or "Priority" not in entry:
        return None

    details = entry.get("Details") or {}
    return {
        "priority": entry["Priority"],
        "epss_score": details.get("EPSS"),
        "cvss_score": details.get("CVSS"),
        "is_kev": bool(details.get("is_kev") or details.get("is_vkev")),
        "is_poc": bool(details.get("is_poc")),
        "is_template": bool(details.get("is_template")),
        "links": details.get("Links") or {},
        "raw": entry,
    }


async def enrich_cves(
    cve_ids: list[str],
    base_url: str,
    timeout: float = 120.0,
) -> dict[str, dict]:
    """
    Look up priorities for a list of CVE IDs. Batches into chunks of
    BULK_LIMIT and merges the responses.

    Never raises — a failing CVE-PaaS instance must not break a refresh.
    CVEs that fail are simply absent from the returned mapping.
    """
    wanted = sorted({c.upper() for c in cve_ids if is_cve_id(c)})
    if not wanted:
        return {}

    logger.info(f"CVE-PaaS: enriching {len(wanted)} CVE(s) via {base_url}")
    results: dict[str, dict] = {}

    async with httpx.AsyncClient(timeout=timeout, headers=_headers()) as client:
        for start in range(0, len(wanted), BULK_LIMIT):
            chunk = wanted[start:start + BULK_LIMIT]
            try:
                response = await client.post(
                    f"{base_url}/v1/cve", json={"cve_ids": chunk}
                )
                response.raise_for_status()
                data = response.json()
            except Exception as e:
                logger.error(f"CVE-PaaS batch failed ({len(chunk)} CVEs): {e}")
                continue

            if not isinstance(data, dict):
                logger.error(f"CVE-PaaS returned unexpected payload type: {type(data)}")
                continue

            for cve_id, entry in data.items():
                normalized = _normalize(entry)
                if normalized:
                    results[cve_id.upper()] = normalized
                else:
                    logger.warning(f"CVE-PaaS could not resolve {cve_id}: {entry}")

    logger.info(f"CVE-PaaS: {len(results)}/{len(wanted)} CVE(s) enriched")
    return results


async def check_health(base_url: str, timeout: float = 10.0) -> dict:
    """
    Probe the CVE-PaaS readiness endpoint. Returns {"ok": bool, "detail": str}.
    Used by the Settings page to validate configuration before relying on it.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=_headers()) as client:
            response = await client.get(f"{base_url}/healthz")
        if response.status_code == 200:
            return {"ok": True, "detail": "CVE-PaaS is reachable and ready"}
        return {
            "ok": False,
            "detail": f"CVE-PaaS returned HTTP {response.status_code}: {response.text[:200]}",
        }
    except Exception as e:
        return {"ok": False, "detail": f"Could not reach CVE-PaaS: {e}"}


def worst_priority(priorities: list[str | None]) -> str | None:
    """Return the most urgent priority in the list, or None if all are empty."""
    known = [p for p in priorities if p and p.lower() in PRIORITY_RANK]
    if not known:
        return None
    return min(known, key=lambda p: PRIORITY_RANK[p.lower()])


# Kept for symmetry with the sync callers in tests.
__all__ = [
    "BULK_LIMIT",
    "PRIORITY_ORDER",
    "check_health",
    "enrich_cves",
    "is_cve_id",
    "pick_cve",
    "resolve_base_url",
    "worst_priority",
]
