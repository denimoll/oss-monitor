import httpx
from fastapi import HTTPException

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json"


async def analyze_nvd(identifier: str, name: str, version: str) -> list[dict]:
    url = f"{NVD_API_BASE}/cves/2.0"
    params = {"cpeName": identifier}

    async with httpx.AsyncClient() as client:
        response = await client.get(url, params=params)
        if response.status_code != 200:
            raise HTTPException(status_code=404, detail=f"NVD error: {response.text}")

        data = response.json()
        vulns = data.get("vulnerabilities", [])
        result = []

        for vuln in vulns:
            cve = vuln.get("cve")
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

        return result
