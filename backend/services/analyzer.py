import logging

from fastapi import HTTPException
from models import ComponentRequest, ComponentType

from services.identifiers import generate_identifier
from services.nvd import analyze_nvd
from services.osv import analyze_osv

# Configure a logger for this module
logger = logging.getLogger(__name__)


async def analyze_component(request: ComponentRequest) -> tuple[str, list[dict]]:
    """
    Analyze a software component for known vulnerabilities using either
    NVD (for standalone products) or OSV (for libraries).

    Args:
        request (ComponentRequest): The component data provided by the user.

    Returns:
        tuple[str, list[dict]]: A tuple containing the unique identifier (CPE or PURL)
                                and a list of vulnerabilities found.
    """
    # Generate a unique identifier for the component (CPE or PURL)
    try:
        identifier = await generate_identifier(request)
        logger.info(f"Generated identifier: {identifier}")
    except Exception as e:
        logger.error(f"Failed to generate identifier: {e}")
        raise HTTPException(status_code=500, detail=f"Identifier generation error: {e}")
    
    vulnerabilities = []

    # Use the appropriate service based on component type
    try:
        if request.type == ComponentType.product:
            logger.info(f"Analyzing product via NVD: {request.name} {request.version}")
            vulnerabilities = await analyze_nvd(identifier, request.name, request.version)
        elif request.type == ComponentType.library:
            logger.info(f"Analyzing library via OSV: {request.name} {request.version}")
            vulnerabilities = await analyze_osv(identifier, request)
    except Exception as e:
        logger.error(f"Vulnerability analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"NVD or OSV error: {e}")

    logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
    return identifier, vulnerabilities
