import httpx
from models import ComponentRequest, ComponentType

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
    

async def generate_identifier(data: ComponentRequest) -> str:
    if data.identifier_override:
        return data.identifier_override.strip()

    if data.type == ComponentType.library:
        if not data.ecosystem:
            raise ValueError("Ecosystem is required for libraries.")
        return f"pkg:{data.ecosystem}/{data.name}@{data.version}"

    elif data.type == ComponentType.product:
        cpe_name = await fetch_cpe_name(data.name, data.version)
        if not cpe_name:
            return ""
        return cpe_name

    raise ValueError("Unknown component type.")
