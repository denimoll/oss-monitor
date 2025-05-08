from models import ComponentRequest, ComponentType
from services.identifiers import generate_identifier
from services.nvd import analyze_nvd
from services.osv import analyze_osv
from fastapi import HTTPException

async def analyze_component(request: ComponentRequest) -> tuple[str, list[dict]]:
    identifier = await generate_identifier(request)
    vulnerabilities = []

    try:
        if request.type == ComponentType.product:
            vulnerabilities = await analyze_nvd(identifier, request.name, request.version)
        elif request.type == ComponentType.library:
            vulnerabilities = await analyze_osv(identifier, request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"NVD or OSV error: {e}")

    return identifier, vulnerabilities
