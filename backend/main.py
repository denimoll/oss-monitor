import logging
from contextlib import asynccontextmanager

from crud.components import (
    create_component_with_vulns,
    delete_component,
    get_all_components,
    get_component_by_id,
)
from db.database import Base, async_session, engine
from fastapi import Depends, FastAPI, HTTPException
from models import ComponentRequest
from services.analyzer import analyze_component
from services.identifiers import generate_identifier
from sqlalchemy.ext.asyncio import AsyncSession

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] [%(name)s] %(message)s"
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context to initialize the database schema.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
app = FastAPI(lifespan=lifespan)


async def get_db():
    """
    Dependency to provide an async database session.
    """
    async with async_session() as session:
        yield session


@app.post(
    "/analyze",
    summary="Analyze a component for vulnerabilities",
    description=(
        "Analyze a software component for known vulnerabilities using OSV and NVD sources. "
        "The result is returned but not stored in the database. "
        "Useful for previewing the security status before saving the component."
    )
)
async def analyze(request: ComponentRequest):
    logger.info(f"Analyzing component: {request.name}@{request.version}")
    identifier, vulnerabilities = await analyze_component(request)

    return {
        "name": request.name,
        "version": request.version,
        "type": request.type,
        "identifier": identifier,
        "vulnerabilities": [v["id"] for v in vulnerabilities],
        "source": "nvd.nist.gov + osv.dev"
    }


@app.post(
    "/generate_identifier",
    summary="Generate a unique identifier (PURL or CPE)",
    description=(
        "Generate a unique identifier (Package URL or CPE) for a given software component."
        "The identifier can be used to check for known vulnerabilities."
        "The component must specify whether it is a library or a product."
    )
)
async def generate_id(request: ComponentRequest):
    logger.info(f"Generating identifier for: {request}")
    try:
        identifier = await generate_identifier(request)
        return {"identifier": identifier}
    except Exception as e:
        logger.error(f"Error generating identifier: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    

@app.post(
    "/components",
    summary="Add and analyze a component",
    description=(
        "Analyze a software component and store it in the database along with any discovered vulnerabilities. "
        "Supports open source libraries and standalone software products."
    )
)
async def add_component(request: ComponentRequest, db: AsyncSession = Depends(get_db)):
    logger.info(f"Adding component: {request.name}@{request.version}")
    identifier, vulnerabilities = await analyze_component(request)

    component_data = {
        "name": request.name,
        "version": request.version,
        "type": request.type,
        "ecosystem": request.ecosystem,
        "identifier": identifier
    }

    saved_component = await create_component_with_vulns(db, component_data, vulnerabilities)

    return {
        "id": saved_component.id,
        "name": saved_component.name,
        "version": saved_component.version,
        "type": saved_component.type.value,
        "identifier": saved_component.identifier,
        "vulnerabilities": vulnerabilities
    }


@app.get(
    "/components",
    summary="List all components",
    description=(
        "Retrieve a list of all stored components along with their associated vulnerability information."
    )
)
async def list_components(db: AsyncSession = Depends(get_db)):
    logger.info("Fetching all components")
    components = await get_all_components(db)

    return [
        {
            "id": c.id,
            "name": c.name,
            "version": c.version,
            "type": c.type.value,
            "ecosystem": c.ecosystem,
            "identifier": c.identifier,
            "vulnerabilities": [
                {"id": v.cve_id, "source": v.source} for v in c.vulnerabilities
            ]
        }
        for c in components
    ]


@app.get(
    "/components/{component_id}",
    summary="Get a component by ID",
    description=(
        "Retrieve details of a specific component by its database ID, including any linked vulnerabilities."
    )
)
async def get_component(component_id: int, db: AsyncSession = Depends(get_db)):
    logger.info(f"Fetching component with ID {component_id}")
    component = await get_component_by_id(db, component_id)

    if not component:
        logger.warning(f"Component ID {component_id} not found")
        raise HTTPException(status_code=404, detail="Component not found")

    return {
        "id": component.id,
        "name": component.name,
        "version": component.version,
        "type": component.type.value,
        "ecosystem": component.ecosystem,
        "identifier": component.identifier,
        "vulnerabilities": [
            {"id": v.cve_id, "source": v.source} for v in component.vulnerabilities
        ]
    }

@app.delete(
    "/components/{component_id}",
    summary="Delete a component",
    description=(
        "Remove a component and all of its associated vulnerability data from the database."
    )
)
async def delete_component_route(component_id: int, db: AsyncSession = Depends(get_db)):
    logger.info(f"Attempting to delete component ID {component_id}")
    deleted = await delete_component(db, component_id)
    if not deleted:
        logger.warning(f"Component ID {component_id} not found for deletion")
        raise HTTPException(status_code=404, detail="Component not found")
    logger.info(f"Component ID {component_id} deleted")
    return {"detail": f"Component {component_id} deleted successfully"}
