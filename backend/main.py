from fastapi import FastAPI, HTTPException
from models import ComponentRequest, ComponentType
from services.identifiers import generate_identifier
from services.osv import analyze_osv
from services.nvd import analyze_nvd

app = FastAPI()

@app.post("/analyze")
async def analyze_component(request: ComponentRequest):
    try:
        identifier = generate_identifier(request)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    result = {
        "name": request.name,
        "version": request.version,
        "type": request.type,
        "identifier": identifier,
        "vulnerabilities": [],
        "source": None
    }

    if request.type == ComponentType.library:
        try:
            vulns = await analyze_osv(request)
            result["vulnerabilities"] = vulns
            result["source"] = "osv.dev"
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"OSV error: {e}")
    elif request.type == ComponentType.product:
        try:
            identifier, vulns = await analyze_nvd(
                identifier=request.identifier_override,
                name=request.name,
                version=request.version)
            result["identifier"] = identifier
            result["vulnerabilities"] = vulns
            result["source"] = "nvd.nist.gov"
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"NVD error: {e}")

    return result
