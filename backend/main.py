import json
import logging
import os
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
from crud.evidence import create_evidence, delete_evidence, get_evidence_for_component
from crud.settings import get_all_settings, set_settings
from crud.vulnerabilities import update_false_positive
from db.database import Base, async_session, engine
from db.models import SeverityLevel, Vulnerability
from fastapi import Body, Depends, FastAPI, Header, HTTPException
from models import ComponentRequest, ComponentUpdateRequest, EvidenceRequest, SettingsUpdate
from services.analyzer import analyze_component
from services.identifiers import generate_identifier
from services.qg import evaluate_new_vulns
from services.scheduler import start_scheduler
from services.scorecard import fetch_scorecard
from sqlalchemy.ext.asyncio import AsyncSession

# ── Logging ───────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] [%(name)s] %(message)s",
)

# ── API key auth (optional) ───────────────────────────────────────────────────
# Set OSS_MONITOR_API_KEY env var to enable. If not set, auth is disabled.

_API_KEY = os.getenv("OSS_MONITOR_API_KEY")


async def verify_api_key(x_api_key: str | None = Header(default=None)):
    if _API_KEY and x_api_key != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ── DB Migrations ─────────────────────────────────────────────────────────────

_MIGRATIONS = [
    "ALTER TABLE components ADD COLUMN tags TEXT",
    "ALTER TABLE components ADD COLUMN repo_url TEXT",
    "ALTER TABLE components ADD COLUMN distrib_url TEXT",
    "ALTER TABLE components ADD COLUMN scorecard_score REAL",
    "ALTER TABLE components ADD COLUMN scorecard_data TEXT",
    "ALTER TABLE components ADD COLUMN scorecard_updated DATETIME",
    "ALTER TABLE vulnerabilities ADD COLUMN cvss_score REAL",
    "ALTER TABLE vulnerabilities ADD COLUMN first_seen DATETIME",
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB schema and run safe column migrations on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for migration in _MIGRATIONS:
            try:
                await conn.execute(text(migration))
            except Exception:
                pass  # Column already exists — safe to ignore
    start_scheduler()
    yield


app = FastAPI(
    lifespan=lifespan,
    dependencies=[Depends(verify_api_key)],
)


@app.get("/health", include_in_schema=False, dependencies=[])  # no auth on health
async def health():
    return {"status": "ok"}


async def get_db():
    async with async_session() as session:
        yield session


# ── Serializers ───────────────────────────────────────────────────────────────

def _serialize_vuln(v) -> dict:
    return {
        "id": v.id,
        "cve_id": v.cve_id,
        "source": v.source,
        "severity": v.severity,
        "cvss_score": v.cvss_score,
        "is_false_positive": v.is_false_positive,
        "false_positive_reason": v.false_positive_reason,
        "first_seen": v.first_seen,
    }


def _serialize_evidence(e) -> dict:
    return {
        "id": e.id,
        "type": e.type.value if hasattr(e.type, "value") else e.type,
        "title": e.title,
        "url": e.url,
        "notes": e.notes,
        "created_at": e.created_at,
    }


def _serialize_component(c) -> dict:
    sc_data = None
    if c.scorecard_data:
        try:
            sc_data = json.loads(c.scorecard_data)
        except Exception:
            pass
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
        "repo_url": c.repo_url,
        "distrib_url": c.distrib_url,
        "scorecard_score": c.scorecard_score,
        "scorecard_data": sc_data,
        "scorecard_updated": c.scorecard_updated,
        "vulnerabilities": [_serialize_vuln(v) for v in c.vulnerabilities],
        "evidence": [_serialize_evidence(e) for e in c.evidence],
    }


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/dashboard", summary="Get dashboard summary")
async def get_dashboard(db: AsyncSession = Depends(get_db)):
    components = await get_all_components(db)
    settings = await get_all_settings(db)
    sc_threshold = settings.get("scorecard_min_score", 5.0)

    severity_counts = {s.value: 0 for s in SeverityLevel}
    components_with_vulns = 0
    scorecard_warnings = 0
    top_vulnerable = []

    for c in components:
        active_vulns = [v for v in c.vulnerabilities if not v.is_false_positive]
        if active_vulns:
            components_with_vulns += 1
        for v in active_vulns:
            severity_counts[v.severity.value] += 1
        if c.scorecard_score is not None and c.scorecard_score < sc_threshold:
            scorecard_warnings += 1
        top_vulnerable.append({
            "id": c.id,
            "name": c.name,
            "version": c.version,
            "tags": c.tags,
            "scorecard_score": c.scorecard_score,
            "vuln_count": len(active_vulns),
            "critical": sum(1 for v in active_vulns if v.severity == SeverityLevel.critical),
            "high": sum(1 for v in active_vulns if v.severity == SeverityLevel.high),
        })

    top_vulnerable.sort(key=lambda x: (x["critical"], x["high"], x["vuln_count"]), reverse=True)

    return {
        "total_components": len(components),
        "components_with_vulns": components_with_vulns,
        "scorecard_warnings": scorecard_warnings,
        "severity_counts": severity_counts,
        "top_vulnerable": top_vulnerable[:5],
    }


# ── Analyze (no storage) ──────────────────────────────────────────────────────

@app.post("/analyze", summary="Analyze a component for vulnerabilities")
async def analyze(request: ComponentRequest):
    logger.info(f"Analyzing component: {request.name}@{request.version}")
    identifier, vulnerabilities = await analyze_component(request)
    return {
        "name": request.name,
        "version": request.version,
        "type": request.type,
        "identifier": identifier,
        "vulnerabilities": [v["id"] for v in vulnerabilities],
        "source": "nvd.nist.gov + osv.dev",
    }


@app.post("/generate_identifier", summary="Generate a unique identifier (PURL or CPE)")
async def generate_id(request: ComponentRequest):
    try:
        identifier = await generate_identifier(request)
        return {"identifier": identifier}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Components ────────────────────────────────────────────────────────────────

@app.post("/components", summary="Add and analyze a component")
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
        "repo_url": request.repo_url,
        "distrib_url": request.distrib_url,
    }
    saved = await create_component_with_vulns(db, component_data, vulnerabilities)

    if request.repo_url:
        sc = await fetch_scorecard(request.repo_url)
        if sc:
            await update_component(db, saved.id, {
                "scorecard_score": sc["score"],
                "scorecard_data": json.dumps(sc),
                "scorecard_updated": datetime.now(),
            })
            saved = await get_component_by_id(db, saved.id)

    return _serialize_component(saved)


@app.post(
    "/components/import",
    summary="Bulk import components from a JSON list",
    description=(
        "Import multiple components at once from a JSON array. "
        "Each item is analyzed for vulnerabilities. "
        "Already-existing components (same name+version+type+ecosystem) are skipped."
    ),
)
async def import_components(
    items: list[ComponentRequest],
    db: AsyncSession = Depends(get_db),
):
    if not items:
        raise HTTPException(status_code=400, detail="Empty import list")
    if len(items) > 200:
        raise HTTPException(status_code=400, detail="Maximum 200 components per import")

    results = {"imported": [], "skipped": [], "errors": []}

    for req in items:
        try:
            identifier, vulnerabilities = await analyze_component(req)
            component_data = {
                "name": req.name,
                "version": req.version,
                "type": req.type,
                "ecosystem": req.ecosystem,
                "identifier": identifier,
                "notes": req.notes,
                "tags": req.tags,
                "repo_url": req.repo_url,
                "distrib_url": req.distrib_url,
            }
            saved = await create_component_with_vulns(db, component_data, vulnerabilities)
            # create_component_with_vulns returns existing if duplicate
            key = f"{req.name}@{req.version}"
            if any(v.component_id == saved.id for v in saved.vulnerabilities) or not saved.vulnerabilities:
                results["imported"].append({"name": req.name, "version": req.version, "id": saved.id})
            else:
                results["skipped"].append(key)
        except Exception as e:
            logger.error(f"Import error for {req.name}@{req.version}: {e}")
            results["errors"].append({"name": req.name, "version": req.version, "error": str(e)})

    logger.info(f"Import complete: {len(results['imported'])} imported, {len(results['skipped'])} skipped, {len(results['errors'])} errors")
    return results


@app.get("/components", summary="List all components")
async def list_components(tag: str | None = None, db: AsyncSession = Depends(get_db)):
    components = await get_all_components(db)
    if tag:
        components = [
            c for c in components
            if c.tags and tag in [t.strip() for t in c.tags.split(",")]
        ]
    return [_serialize_component(c) for c in components]


@app.get("/components/{component_id}", summary="Get a component by ID")
async def get_component(component_id: int, db: AsyncSession = Depends(get_db)):
    component = await get_component_by_id(db, component_id)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    return _serialize_component(component)


@app.patch("/components/{component_id}", summary="Update component metadata")
async def update_component_route(
    component_id: int,
    data: ComponentUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    updates = {k: v for k, v in data.model_dump().items() if v is not None or k in ("notes",)}
    component = await update_component(db, component_id, updates)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    return _serialize_component(component)


@app.delete("/components/{component_id}", summary="Delete a component")
async def delete_component_route(component_id: int, db: AsyncSession = Depends(get_db)):
    deleted = await delete_component(db, component_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Component not found")
    return {"detail": f"Component {component_id} deleted successfully"}


# ── Scorecard ─────────────────────────────────────────────────────────────────

@app.post("/components/{component_id}/scorecard", summary="Refresh Scorecard for a component")
async def refresh_scorecard(component_id: int, db: AsyncSession = Depends(get_db)):
    component = await get_component_by_id(db, component_id)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    if not component.repo_url:
        raise HTTPException(status_code=400, detail="Component has no repo_url set")

    sc = await fetch_scorecard(component.repo_url)
    if not sc:
        raise HTTPException(status_code=404, detail="Scorecard not found for this repository")

    updated = await update_component(db, component_id, {
        "scorecard_score": sc["score"],
        "scorecard_data": json.dumps(sc),
        "scorecard_updated": datetime.now(),
    })
    return {
        "score": sc["score"],
        "date": sc["date"],
        "checks": sc["checks"],
        "component": _serialize_component(updated),
    }


# ── Refresh ───────────────────────────────────────────────────────────────────

@app.post("/components/refresh_all", summary="Refresh all components")
async def refresh_all_components(db: AsyncSession = Depends(get_db)):
    components = await get_all_components(db)
    updated = []
    now = datetime.now()
    for component in components:
        request_data = ComponentRequest(
            type=component.type,
            name=component.name,
            version=component.version,
            ecosystem=component.ecosystem,
            identifier_override=component.identifier,
        )
        _, vulnerabilities = await analyze_component(request_data)
        existing_vulns = {(v.cve_id, v.source) for v in component.vulnerabilities}
        for vuln in vulnerabilities:
            if (vuln["id"], vuln["source"]) not in existing_vulns:
                db.add(Vulnerability(
                    cve_id=vuln["id"], source=vuln["source"],
                    severity=vuln.get("severity", "unknown"),
                    cvss_score=vuln.get("cvss_score"),
                    is_false_positive=False,
                    first_seen=now,
                    component=component,
                ))
        component.last_updated = now
        updated.append({"id": component.id, "name": component.name})
    await db.commit()
    return {"updated": updated, "count": len(updated)}


@app.post("/components/{component_id}/refresh", summary="Refresh a specific component")
async def refresh_component(component_id: int, db: AsyncSession = Depends(get_db)):
    component = await get_component_by_id(db, component_id)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")

    request_data = ComponentRequest(
        type=component.type,
        name=component.name,
        version=component.version,
        ecosystem=component.ecosystem,
        identifier_override=component.identifier,
    )
    _, vulnerabilities = await analyze_component(request_data)
    existing_vulns = {(v.cve_id, v.source) for v in component.vulnerabilities}
    now = datetime.now()

    new_vulns = []
    for vuln in vulnerabilities:
        if (vuln["id"], vuln["source"]) not in existing_vulns:
            db.add(Vulnerability(
                cve_id=vuln["id"], source=vuln["source"],
                severity=vuln.get("severity", "unknown"),
                cvss_score=vuln.get("cvss_score"),
                is_false_positive=False,
                first_seen=now,
                component=component,
            ))
            new_vulns.append(vuln)

    component.last_updated = now
    await db.commit()

    if new_vulns:
        settings = await get_all_settings(db)
        webhook_url = settings.get("webhook_url")
        if webhook_url:
            await evaluate_new_vulns(component, new_vulns, settings, webhook_url)

    refreshed = await get_component_by_id(db, component_id)
    return _serialize_component(refreshed)


# ── Evidence ──────────────────────────────────────────────────────────────────

@app.get("/components/{component_id}/evidence", summary="List evidence for a component")
async def list_evidence(component_id: int, db: AsyncSession = Depends(get_db)):
    component = await get_component_by_id(db, component_id)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    items = await get_evidence_for_component(db, component_id)
    return [_serialize_evidence(e) for e in items]


@app.post("/components/{component_id}/evidence", summary="Add evidence to a component")
async def add_evidence(
    component_id: int,
    data: EvidenceRequest,
    db: AsyncSession = Depends(get_db),
):
    component = await get_component_by_id(db, component_id)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    evidence = await create_evidence(db, component_id, data.model_dump())
    return _serialize_evidence(evidence)


@app.delete("/evidence/{evidence_id}", summary="Delete an evidence entry")
async def remove_evidence(evidence_id: int, db: AsyncSession = Depends(get_db)):
    deleted = await delete_evidence(db, evidence_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return {"detail": f"Evidence {evidence_id} deleted"}


# ── Settings ──────────────────────────────────────────────────────────────────

@app.get("/settings", summary="Get current settings")
async def get_settings(db: AsyncSession = Depends(get_db)):
    return await get_all_settings(db)


@app.put("/settings", summary="Update settings")
async def update_settings(data: SettingsUpdate, db: AsyncSession = Depends(get_db)):
    return await set_settings(db, data.model_dump())


# ── Vulnerabilities ───────────────────────────────────────────────────────────

@app.patch("/vulnerabilities/{vuln_id}/false_positive", summary="Update false positive status")
async def update_vulnerability_false_positive(
    vuln_id: int,
    data: dict = Body(...),
    db: AsyncSession = Depends(get_db),
):
    is_false_positive = data.get("is_false_positive")
    reason = data.get("reason", None)
    updated = await update_false_positive(db, vuln_id, is_false_positive, reason)
    if not updated:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return {"detail": f"False positive updated to {is_false_positive}"}
