import logging

import httpx
from fastapi import HTTPException

# Base URL for the NVD API
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json"

# Initialize a logger for this module
logger = logging.getLogger(__name__)


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
    logger.info(f"Querying NVD for identifier: {identifier}")

    async with httpx.AsyncClient() as client:
        response = await client.get(url, params=params)

        if response.status_code != 200:
            logger.error(f"NVD request failed with status {response.status_code}: {response.text}")
            raise HTTPException(status_code=404, detail=f"NVD error: {response.text}")

        data = response.json()
        vulns = data.get("vulnerabilities", [])
        result = []

        for vuln in vulns:
            cve = vuln.get("cve", {})
            descriptions = cve.get("descriptions", [])
            # Get English summary if available
            summary = next((d["value"] for d in descriptions if d["lang"] == "en"), None)
            # Append a structured vulnerability dictionary to the result list
            if cve.get("metrics").get("cvssMetricV31"):
                severity = cve.get("metrics").get("cvssMetricV31")[0].get("cvssData").get("baseSeverity").lower()
            elif cve.get("metrics").get("cvssMetricV30"):
                severity = cve.get("metrics").get("cvssMetricV30")[0].get("cvssData").get("baseSeverity").lower()
            elif cve.get("metrics").get("cvssMetricV2"):
                severity = cve.get("metrics").get("cvssMetricV2")[0].get("baseSeverity").lower()
            else:
                severity = "unknown"
            result.append({
                "id": cve.get("id"),
                "summary": summary,
                "details": None,
                "aliases": [],
                "severity": severity,
                "source": "nvd"
            })

        logger.info(f"Found {len(result)} NVD vulnerabilities for {name} {version}")
        return result
