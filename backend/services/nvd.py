import httpx
from fastapi import HTTPException

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json"


async def fetch_cpe_name(name: str, version: str) -> str | None:
    params = {"keywordSearch": name}
    url = f"{NVD_API_BASE}/cpes/2.0"
    async with httpx.AsyncClient() as client:
        response = await client.get(url, params=params)
        if response.status_code != 200:
            return None

        data = response.json()
        for item in data.get("products", []):
            cpe = item.get("cpe", {}).get("cpeName")
            if cpe and version in cpe:
                return cpe

        return None


async def analyze_nvd(identifier: str, name: str, version: str) -> tuple[str, list[dict]]:
    cpe_name = identifier or await fetch_cpe_name(name, version)

    if not cpe_name:
        raise HTTPException(status_code=400, detail="CPE not found automatically. Please provide identifier_override.")

    url = f"{NVD_API_BASE}/cves/2.0"
    params = {"cpeName": cpe_name}

    async with httpx.AsyncClient() as client:
        response = await client.get(url, params=params)
        if response.status_code != 200:
            raise HTTPException(status_code=404, detail=f"NVD error: {response.text}")

        data = response.json()
        vulns = data.get("vulnerabilities", [])
        result = []

        for vuln in vulns:
            cve = vuln["cve"]
            descriptions = cve.get("descriptions", [])
            summary = next((d["value"] for d in descriptions if d["lang"] == "en"), None)
            result.append({
                "id": cve.get("id"),
                "summary": summary,
                "details": None,
                "aliases": [],
                "severity": cve.get("metrics"),
                "source": "nvd"
            })

        return cpe_name, result
