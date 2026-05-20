import logging
from contextlib import asynccontextmanager
from datetime import datetime

from sqlalchemy import text

from crud.components import (
    create_component_with_vulns,
    delete_component,
    get_all_components,
    get_component_by_id,
    update_component,
)
from crud.vulnerabilities import update_false_positive
from db.database import Base, async_session, engine
from db.models import SeverityLevel, Vulnerability
from fastapi import Body, Depends, FastAPI, HTTPException
from models import ComponentRequest, ComponentUpdateRequest
from services.analyzer import analyze_component
from services.identifiers import generate_identifier
from services.scheduler import start_scheduler
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
    FastAPI lifespan context to initialize the database schema and run migrations.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Safe migration: add 'tags' column if it doesn't exist yet
        try:
            await conn.execute(
                text("ALTER TABLE components ADD COLUMN tags TEXT")
            )
            logger.info("Migration: added 'tags' column to components")
        except Exception:
            pass  # Column already exists — normal on fresh installs too
    start_scheduler()
    yield

app = FastAPI(lifespan=lifespan)


async def get_db():
    """
    Dependency to provide an async database session.
    """
    async with async_session() as session:
        yield session


def _serialize_component(c) -> dict:
    """Serialize a Component ORM object to a dict."""
    return {
        "id": c.id,
        "name": c.name,
        "version": c.version,
        "type": c.type.value,
        "ecosystem": c.ecosystem,
        "identifier": c.identifier,
        "last_updated": c.last_updated,
        "notes": c.notes,
        "tags": c.tags,
        "vulnerabilities": [
            {
                "id": v.id,
                "cve_id": v.cve_id,
                "source": v.source,
                "severity": v.severity,
                "is_false_positive": v.is_false_positive,
                "false_positive_reason": v.false_positive_reason
            } for v in c.vulnerabilities
        ]
    }


@app.get(
    "/dashboard",
    summary="Get dashboard summary",
    description="Returns aggregated vulnerability statistics across all components."
)
async def get_dashboard(db: AsyncSession = Depends(get_db)):
    logger.info("Fetching dashboard stats")
    components = await get_all_components(db)

    total = len(components)
    severity_counts = {s.value: 0 for s in SeverityLevel}
    components_with_vulns = 0
    top_vulnerable = []

    for c in components:
        active_vulns = [v for v in c.vulnerabilities if not v.is_false_positive]
        if active_vulns:
            components_with_vulns += 1
        for v in active_vulns:
            severity_counts[v.severity.value] += 1
        top_vulnerable.append({
            "id": c.id,
            "name": c.name,
            "version": c.version,
            "tags": c.tags,
            "vuln_count": len(active_vulns),
            "critical": sum(1 for v in active_vulns if v.severity == SeverityLevel.critical),
            "high": sum(1 for v in active_vulns if v.severity == SeverityLevel.high),
        })

    top_vulnerable.sort(key=lambda x: (x["critical"], x["high"], x["vuln_count"]), reverse=True)

    return {
        "total_components": total,
        "components_with_vulns": components_with_vulns,
        "severity_counts": severity_counts,
        "top_vulnerable": top_vulnerable[:5],
    }


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
        "identifier": identifier,
        "notes": request.notes,
        "tags": request.tags,
    }

    saved_component = await create_component_with_vulns(db, component_data, vulnerabilities)

    return {
        "id": saved_component.id,
        "name": saved_component.name,
        "version": saved_component.version,
        "type": saved_component.type.value,
        "identifier": saved_component.identifier,
        "last_updated": saved_component.last_updated.strftime("%d.%m.%Y %H:%M"),
        "notes": saved_component.notes,
        "tags": saved_component.tags,
        "vulnerabilities": vulnerabilities
    }


@app.get(
    "/components",
    summary="List all components",
    description=(
        "Retrieve a list of all stored components along with their associated vulnerability information. "
        "Optionally filter by tag."
    )
)
async def list_components(tag: str | None = None, db: AsyncSession = Depends(get_db)):
    logger.info("Fetching all components")
    components = await get_all_components(db)

    if tag:
        components = [
            c for c in components
            if c.tags and tag in [t.strip() for t in c.tags.split(",")]
        ]

    return [_serialize_component(c) for c in components]


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

    return _serialize_component(component)


@app.patch(
    "/components/{component_id}",
    summary="Update component metadata",
    description="Update notes and tags for a specific component."
)
async def update_component_route(
    component_id: int,
    data: ComponentUpdateRequest,
    db: AsyncSession = Depends(get_db)
):
    logger.info(f"Updating component ID {component_id}")
    component = await update_component(db, component_id, data.notes, data.tags)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    return _serialize_component(component)


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


@app.post(
    "/components/refresh_all",
    summary="Refresh all components",
    description="Re-analyze and update vulnerabilities for all components in the database."
)
async def refresh_all_components(db: AsyncSession = Depends(get_db)):
    logger.info("Attempting to refresh all components")
    components = await get_all_components(db)
    updated = []

    for component in components:
        request_data = ComponentRequest(
            type=component.type,
            name=component.name,
            version=component.version,
            ecosystem=component.ecosystem,
            identifier_override=component.identifier
        )

        identifier, vulnerabilities = await analyze_component(request_data)

        existing_vulns = {(v.cve_id, v.source) for v in component.vulnerabilities}

        for vuln in vulnerabilities:
            if (vuln["id"], vuln["source"]) in existing_vulns:
                continue
            db.add(Vulnerability(
                cve_id=vuln["id"],
                source=vuln["source"],
                severity=vuln.get("severity", "unknown"),
                is_false_positive=False,
                false_positive_reason=None,
                component=component
            ))

        component.last_updated = datetime.now()
        updated.append({"id": component.id, "name": component.name})
        logger.info(f"Component ID {component.id} refreshed")

    await db.commit()

    return {"updated": updated, "count": len(updated)}


@app.post(
    "/components/{component_id}/refresh",
    summary="Refresh vulnerabilities for a specific component",
    description="Re-analyze the component and update its vulnerability information in the database."
)
async def refresh_component(component_id: int, db: AsyncSession = Depends(get_db)):
    logger.info(f"Attempting to refresh component ID {component_id}")
    component = await get_component_by_id(db, component_id)
    if not component:
        logger.warning(f"Component ID {component_id} not found for refreshing")
        raise HTTPException(status_code=404, detail="Component not found")

    request_data = ComponentRequest(
        type=component.type,
        name=component.name,
        version=component.version,
        ecosystem=component.ecosystem,
        identifier_override=component.identifier
    )

    identifier, vulnerabilities = await analyze_component(request_data)
    existing_vulns = {(v.cve_id, v.source) for v in component.vulnerabilities}

    for vuln in vulnerabilities:
        if (vuln["id"], vuln["source"]) in existing_vulns:
            continue
        db.add(Vulnerability(
            cve_id=vuln["id"],
            source=vuln["source"],
            severity=vuln.get("severity", "unknown"),
            is_false_positive=False,
            false_positive_reason=None,
            component=component
        ))

    component.last_updated = datetime.now()
    await db.commit()
    # Re-query with eager load — db.refresh() does not reload relationships
    refreshed = await get_component_by_id(db, component_id)
    logger.info(f"Component ID {component_id} refreshed")
    return _serialize_component(refreshed)


@app.patch(
    "/vulnerabilities/{vuln_id}/false_positive",
    summary="Update false positive status",
    description="Update the false positive status for a specific vulnerability by ID."
)
async def update_vulnerability_false_positive(
    vuln_id: int,
    data: dict = Body(...),
    db: AsyncSession = Depends(get_db)
):
    is_false_positive = data.get("is_false_positive")
    reason = data.get("reason", None)
    logger.info(f"Request to update false_positive for vulnerability {vuln_id} to {is_false_positive}")

    updated = await update_false_positive(db, vuln_id, is_false_positive, reason)

    if not updated:
        logger.warning(f"Vulnerability {vuln_id} not found for false_positive update")
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    logger.info(f"Vulnerability {vuln_id} false_positive updated to {is_false_positive}, reason: {reason}")
    return {"detail": f"False positive updated to {is_false_positive}"}
