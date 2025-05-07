import httpx
from models import ComponentRequest

BASE_URL = "https://api.osv.dev/v1/query"
OSV_ECOSYSTEM_MAP = {
    "maven": "Maven",
    "pypi": "PyPI",
    "npm": "npm",
    "nuget": "NuGet",
    "go": "Go",
    "crates.io": "crates.io"
}


async def analyze_osv(identifier: str, request: ComponentRequest) -> list[dict]:
    payload = {
        "package": {
            "name": request.name,
            "ecosystem": OSV_ECOSYSTEM_MAP.get(request.ecosystem)
        },
        "version": request.version
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(BASE_URL, json=payload)
        response.raise_for_status()
        data = response.json()

    vulns = data.get("vulns", [])
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
