import httpx
from models import ComponentRequest
import logging

# Configure logger for this module
logger = logging.getLogger(__name__)

# Base URL for the OSV API
BASE_URL = "https://api.osv.dev/v1/query"
# Mapping local ecosystem names to OSV-compatible ones
OSV_ECOSYSTEM_MAP = {
    "maven": "Maven",
    "pypi": "PyPI",
    "npm": "npm",
    "nuget": "NuGet",
    "go": "Go",
    "crates.io": "crates.io"
}


async def analyze_osv(identifier: str, request: ComponentRequest) -> list[dict]:
    """
    Analyze a library component using the OSV API and return a list of vulnerabilities.

    Args:
        identifier (str): The Package URL (purl) identifier.
        request (ComponentRequest): Component request data.

    Returns:
        list[dict]: List of vulnerability dictionaries.
    """
    payload = {
        "package": {
            "name": request.name,
            "ecosystem": OSV_ECOSYSTEM_MAP.get(request.ecosystem)
        },
        "version": request.version
    }

    logger.info(f"Sending request to OSV for {request.name}@{request.version} ({payload['package']['ecosystem']})")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(BASE_URL, json=payload)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"OSV API error {e.response.status_code}: {e.response.text}")
        raise
    except Exception:
        logger.exception("Unexpected error occurred while querying OSV")
        raise

    vulns = data.get("vulns", [])
    logger.info(f"Found {len(vulns)} vulnerabilities for {request.name}@{request.version}")
    
    result = []
    for vuln in vulns:
        result.append({
            "id": vuln.get("id"),
            "summary": vuln.get("summary"),
            "details": vuln.get("details"),
            "aliases": vuln.get("aliases", []),
            "severity": vuln.get("severity", []),
            "source": "osv"
        })

    return result
