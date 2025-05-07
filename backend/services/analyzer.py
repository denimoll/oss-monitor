from models import ComponentRequest, ComponentType
from services.identifiers import generate_identifier
from services.nvd import analyze_nvd
from services.osv import analyze_osv
from fastapi import HTTPException

async def analyze_component(request: ComponentRequest) -> tuple[str, list[dict]]:
    identifier = generate_identifier(request)
    vulnerabilities = []

    if request.type == ComponentType.product:
        try:
            cpe_name, vulnerabilities = await analyze_nvd(identifier, request.name, request.version)
            identifier = cpe_name or identifier
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"OSV error: {e}")
    elif request.type == ComponentType.library:
        try:
            vulnerabilities = await analyze_osv(identifier, request)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"NVD error: {e}")

    return identifier, vulnerabilities
