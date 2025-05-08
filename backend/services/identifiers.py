import logging

import httpx
from models import ComponentRequest, ComponentType

# Base URL for the NVD API
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json"

# Configure module-level logger
logger = logging.getLogger(__name__)


async def fetch_cpe_name(name: str, version: str) -> str | None:
    """
    Attempts to fetch the appropriate CPE 2.3 name for a given product name and version
    by querying the NVD CPE API.

    Args:
        name (str): Product name.
        version (str): Product version.

    Returns:
        str | None: CPE name if found, otherwise None.
    """
    params = {"keywordSearch": name}
    url = f"{NVD_API_BASE}/cpes/2.0"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, params=params)
            if response.status_code != 200:
                logger.warning(f"NVD API returned status {response.status_code} for CPE fetch.")
                return None

            data = response.json()
            for item in data.get("products", []):
                cpe = item.get("cpe", {}).get("cpeName")
                if cpe and version in cpe:
                    logger.info(f"Matched CPE: {cpe}")
                    return cpe

    except Exception as e:
        logger.error(f"Failed to fetch CPE name: {e}")

    logger.info("No matching CPE found.")
    return None
    

async def generate_identifier(data: ComponentRequest) -> str:
    """
    Generates a unique identifier for a component:
    - For libraries: returns a PURL.
    - For products: attempts to find a CPE name via NVD.

    Args:
        data (ComponentRequest): The component data.

    Returns:
        str: The identifier string (PURL or CPE).
    """
    if data.identifier_override:
        logger.info("Using provided identifier override.")
        return data.identifier_override.strip()

    if data.type == ComponentType.library:
        if not data.ecosystem:
            logger.error("Ecosystem is required for libraries.")
            raise ValueError("Ecosystem is required for libraries.")
        identifier = f"pkg:{data.ecosystem}/{data.name}@{data.version}"
        logger.info(f"Generated PURL: {identifier}")
        return identifier

    elif data.type == ComponentType.product:
        logger.info(f"Attempting to fetch CPE for product: {data.name} {data.version}")
        cpe_name = await fetch_cpe_name(data.name, data.version)
        if not cpe_name:
            logger.warning("CPE not found, returning empty string.")
            return ""
        return cpe_name

    raise ValueError("Unknown component type.")
