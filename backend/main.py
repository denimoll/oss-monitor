import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime

from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from crud.components import (
    create_component_with_vulns,
    delete_component,
    get_all_components,
    get_component_by_id,
    update_component,
)
from crud.enrichment import enrich_all, enrich_vulnerabilities
from crud.evidence import create_evidence, delete_evidence, get_evidence_for_component
from crud.settings import get_all_settings, set_settings
from crud.vulnerabilities import update_false_positive
from db.database import Base, async_session, engine
from db.models import SeverityLevel, Vulnerability
from fastapi import Body, Depends, FastAPI, Header, HTTPException
from models import ComponentRequest, ComponentUpdateRequest, EvidenceRequest, SettingsUpdate
from services.analyzer import analyze_component
from services.cvepaas import PRIORITY_ORDER, check_health, resolve_base_url
from services.identifiers import generate_identifier
from services.qg import evaluate_escalations, evaluate_new_vulns
from services.scheduler import start_scheduler
from services.scorecard import fetch_scorecard
from services.versions import build_remediation
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
#
# Schema changes are Alembic migrations (backend/migrations/versions). The list
# below is a one-time bridge for databases created before Alembic existed here:
# it is idempotent, brings such a database to exactly the baseline revision's
# shape, after which it is stamped and never runs again.

_LEGACY_MIGRATIONS = [
    "ALTER TABLE components ADD COLUMN tags TEXT",
    "ALTER TABLE components ADD COLUMN repo_url TEXT",
    "ALTER TABLE components ADD COLUMN distrib_url TEXT",
    "ALTER TABLE components ADD COLUMN scorecard_score REAL",
    "ALTER TABLE components ADD COLUMN scorecard_data TEXT",
    "ALTER TABLE components ADD COLUMN scorecard_updated DATETIME",
    "ALTER TABLE vulnerabilities ADD COLUMN cvss_score REAL",
    "ALTER TABLE vulnerabilities ADD COLUMN first_seen DATETIME",
    "ALTER TABLE vulnerabilities ADD COLUMN aliases TEXT",
    "ALTER TABLE vulnerabilities ADD COLUMN fixed_version TEXT",
    "ALTER TABLE components ADD COLUMN owner TEXT",
    # CVE-PaaS enrichment
    "ALTER TABLE vulnerabilities ADD COLUMN priority TEXT",
    "ALTER TABLE vulnerabilities ADD COLUMN epss_score REAL",
    "ALTER TABLE vulnerabilities ADD COLUMN is_kev BOOLEAN",
    "ALTER TABLE vulnerabilities ADD COLUMN is_poc BOOLEAN",
    "ALTER TABLE vulnerabilities ADD COLUMN is_template BOOLEAN",
    "ALTER TABLE vulnerabilities ADD COLUMN cvepaas_data TEXT",
    "ALTER TABLE vulnerabilities ADD COLUMN priority_updated DATETIME",
]


_ALEMBIC_DIR = Path(__file__).resolve().parent


def _alembic_config(connection) -> Config:
    config = Config(str(_ALEMBIC_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(_ALEMBIC_DIR / "migrations"))
    # Reuse the app's connection rather than opening a second one against the
    # same SQLite file, which would deadlock on the write lock.
    config.attributes["connection"] = connection
    return config


def _migrate(connection) -> None:
    """
    Bring the database to the latest revision.

    Three cases, because this app predates its own migration tooling:

    * already under Alembic  -> upgrade normally;
    * predates Alembic       -> apply the idempotent legacy ALTERs, which land
                                it on the baseline shape, then stamp it so it
                                joins the normal path from here on;
    * empty                  -> create everything from the baseline revision.
    """
    tables = set(sa.inspect(connection).get_table_names())
    config = _alembic_config(connection)

    if "alembic_version" in tables:
        command.upgrade(config, "head")
        return

    if "components" in tables:
        logger.info("Pre-Alembic database detected — applying legacy column migrations")
        for migration in _LEGACY_MIGRATIONS:
            try:
                connection.execute(text(migration))
            except Exception:
                pass  # Column already exists — safe to ignore
        command.stamp(config, "head")
        logger.info("Database stamped at head; future changes run as migrations")
        return

    command.upgrade(config, "head")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Bring the schema up to date, then start the scheduler."""
    async with engine.begin() as conn:
        await conn.run_sync(_migrate)
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


async def _enrich_if_enabled(db: AsyncSession, vulns: list, settings: dict,
                             force: bool = False) -> tuple[list[dict], dict[str, dict]]:
    """
    Run CVE-PaaS enrichment when the integration is enabled.

    Returns (change records, {CVE-ID: verdict}). Both are empty when the
    integration is off or unreachable — enrichment is best-effort and must
    never fail the request that triggered it.
    """
    base_url = resolve_base_url(settings)
    if not base_url or not vulns:
        return [], {}
    changes = await enrich_vulnerabilities(db, vulns, base_url, force=force)
    verdicts = {
        c["vuln_id"].upper(): {
            "priority": c["after"]["priority"],
            "epss_score": c["after"]["epss_score"],
            "is_kev": c["after"]["is_kev"],
            "is_poc": c["vuln"].is_poc,
            "is_template": c["vuln"].is_template,
        }
        for c in changes
    }
    return changes, verdicts


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
        "aliases": [a.strip() for a in (v.aliases or "").split(",") if a.strip()],
        "fixed_version": v.fixed_version,
        # CVE-PaaS enrichment (all None when the integration is off)
        "priority": v.priority,
        "epss_score": v.epss_score,
        "is_kev": v.is_kev,
        "is_poc": v.is_poc,
        "is_template": v.is_template,
        "priority_updated": v.priority_updated,
        "cvepaas_links": _cvepaas_links(v),
    }


def _cvepaas_links(v) -> dict | None:
    """Extract the PoC / Nuclei / KEV links from the stored CVE-PaaS blob."""
    if not v.cvepaas_data:
        return None
    try:
        return (json.loads(v.cvepaas_data).get("Details") or {}).get("Links")
    except Exception:
        return None


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
        "owner": c.owner,
        "repo_url": c.repo_url,
        "distrib_url": c.distrib_url,
        "scorecard_score": c.scorecard_score,
        "scorecard_data": sc_data,
        "scorecard_updated": c.scorecard_updated,
        "vulnerabilities": [_serialize_vuln(v) for v in c.vulnerabilities],
        "evidence": [_serialize_evidence(e) for e in c.evidence],
        # Upgrade advice over the active findings only — a suppressed false
        # positive must not drag the recommended version up.
        "remediation": build_remediation(
            c.version, [v for v in c.vulnerabilities if not v.is_false_positive]
        ),
    }


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/dashboard", summary="Get dashboard summary")
async def get_dashboard(db: AsyncSession = Depends(get_db)):
    components = await get_all_components(db)
    settings = await get_all_settings(db)
    sc_threshold = settings.get("scorecard_min_score", 5.0)

    severity_counts = {s.value: 0 for s in SeverityLevel}
    priority_counts = {p: 0 for p in PRIORITY_ORDER}
    components_with_vulns = 0
    scorecard_warnings = 0
    kev_count = 0
    exploitable_count = 0
    fixable_count = 0
    unfixable_count = 0
    top_vulnerable = []
    upgrades = []

    for c in components:
        active_vulns = [v for v in c.vulnerabilities if not v.is_false_positive]
        if active_vulns:
            components_with_vulns += 1
        for v in active_vulns:
            severity_counts[v.severity.value] += 1
            if v.priority in priority_counts:
                priority_counts[v.priority] += 1
            if v.is_kev:
                kev_count += 1
            # Same definition appsec-compose uses for `fail_on_exploitable`:
            # something concrete exists to exploit this right now. The priority
            # check is part of the CVE-PaaS contract (Critical is returned
            # exactly on KEV/PoC/template), so the gate stays correct even if
            # the detail flags are renamed upstream.
            if v.is_kev or v.is_poc or v.is_template or v.priority == "Critical":
                exploitable_count += 1
            if v.fixed_version:
                fixable_count += 1
            else:
                unfixable_count += 1
        if c.scorecard_score is not None and c.scorecard_score < sc_threshold:
            scorecard_warnings += 1
        remediation = build_remediation(c.version, active_vulns)
        if remediation:
            upgrades.append({
                "id": c.id,
                "name": c.name,
                "version": c.version,
                "owner": c.owner,
                "recommended_version": remediation["recommended_version"],
                "clears": remediation["clears"],
            })

        c_kev = sum(1 for v in active_vulns if v.is_kev)
        top_vulnerable.append({
            "id": c.id,
            "name": c.name,
            "version": c.version,
            "tags": c.tags,
            "scorecard_score": c.scorecard_score,
            "vuln_count": len(active_vulns),
            "critical": sum(1 for v in active_vulns if v.severity == SeverityLevel.critical),
            "high": sum(1 for v in active_vulns if v.severity == SeverityLevel.high),
            "kev": c_kev,
        })

    # KEV first: a component carrying an actively exploited CVE outranks one
    # with more, but purely theoretical, criticals.
    top_vulnerable.sort(
        key=lambda x: (x["kev"], x["critical"], x["high"], x["vuln_count"]),
        reverse=True,
    )

    upgrades.sort(key=lambda u: u["clears"], reverse=True)

    return {
        "total_components": len(components),
        "components_with_vulns": components_with_vulns,
        "scorecard_warnings": scorecard_warnings,
        "severity_counts": severity_counts,
        "priority_counts": priority_counts,
        "kev_count": kev_count,
        "exploitable_count": exploitable_count,
        "fixable_count": fixable_count,
        "unfixable_count": unfixable_count,
        "upgrades": upgrades[:5],
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
        "owner": request.owner,
        "repo_url": request.repo_url,
        "distrib_url": request.distrib_url,
    }
    saved = await create_component_with_vulns(db, component_data, vulnerabilities)

    settings = await get_all_settings(db)
    changes, _ = await _enrich_if_enabled(db, list(saved.vulnerabilities), settings)
    if changes:
        saved = await get_component_by_id(db, saved.id)

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
                "owner": req.owner,
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
                    aliases=",".join(vuln.get("aliases") or []) or None,
                    fixed_version=vuln.get("fixed_version"),
                    is_false_positive=False,
                    first_seen=now,
                    component=component,
                ))
        component.last_updated = now
        updated.append({"id": component.id, "name": component.name})
    await db.commit()

    settings = await get_all_settings(db)
    enriched = 0
    if resolve_base_url(settings):
        # One CVE-PaaS pass over everything still missing a verdict, rather
        # than one call per component.
        enriched = len(await enrich_all(db, resolve_base_url(settings)))

    return {"updated": updated, "count": len(updated), "enriched": enriched}


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
                aliases=",".join(vuln.get("aliases") or []) or None,
                fixed_version=vuln.get("fixed_version"),
                is_false_positive=False,
                first_seen=now,
                component=component,
            ))
            new_vulns.append(vuln)

    component.last_updated = now
    await db.commit()

    settings = await get_all_settings(db)
    refreshed = await get_component_by_id(db, component_id)

    # Enrich every vulnerability that still lacks a verdict, so escalations on
    # long-standing CVEs are picked up alongside the brand-new ones.
    changes, verdicts = await _enrich_if_enabled(db, list(refreshed.vulnerabilities), settings)
    if changes:
        refreshed = await get_component_by_id(db, component_id)

    webhook_url = settings.get("webhook_url")
    if webhook_url:
        if new_vulns:
            await evaluate_new_vulns(component, new_vulns, settings, webhook_url, verdicts)
        new_ids = {v["id"] for v in new_vulns}
        escalations = [c for c in changes if c["vuln_id"] not in new_ids]
        if escalations:
            await evaluate_escalations(component, escalations, settings, webhook_url)

    return _serialize_component(refreshed)


# ── CVE-PaaS enrichment ───────────────────────────────────────────────────────

@app.post(
    "/components/{component_id}/enrich",
    summary="Enrich a component's CVEs with CVE-PaaS priorities",
    description=(
        "Looks up every CVE on this component in the configured CVE-PaaS "
        "instance and stores the priority, EPSS score and KEV/PoC flags. "
        "By default only CVEs without a verdict are fetched; pass force=true "
        "to re-fetch all of them."
    ),
)
async def enrich_component(
    component_id: int,
    force: bool = False,
    db: AsyncSession = Depends(get_db),
):
    component = await get_component_by_id(db, component_id)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")

    settings = await get_all_settings(db)
    base_url = resolve_base_url(settings)
    if not base_url:
        raise HTTPException(
            status_code=400,
            detail="CVE-PaaS integration is disabled or has no URL configured",
        )

    changes = await enrich_vulnerabilities(
        db, list(component.vulnerabilities), base_url, force=force
    )

    webhook_url = settings.get("webhook_url")
    if webhook_url and changes:
        await evaluate_escalations(component, changes, settings, webhook_url)

    refreshed = await get_component_by_id(db, component_id)
    return {"enriched": len(changes), "component": _serialize_component(refreshed)}


@app.post(
    "/vulnerabilities/enrich",
    summary="Enrich all stored CVEs with CVE-PaaS priorities",
    description=(
        "Backfills priorities for every vulnerability in the database. "
        "Use force=true after a long gap to refresh verdicts that may have "
        "changed (a PoC published, a KEV listing added)."
    ),
)
async def enrich_all_vulnerabilities(force: bool = False, db: AsyncSession = Depends(get_db)):
    settings = await get_all_settings(db)
    base_url = resolve_base_url(settings)
    if not base_url:
        raise HTTPException(
            status_code=400,
            detail="CVE-PaaS integration is disabled or has no URL configured",
        )
    changes = await enrich_all(db, base_url, force=force)
    return {"enriched": len(changes)}


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


@app.post("/settings/test-webhook", summary="Send a test notification to the configured webhook")
async def test_webhook(db: AsyncSession = Depends(get_db)):
    """
    Reads the webhook_url from stored settings and sends a test payload.
    The URL never comes from the request body — this prevents SSRF from
    the frontend passing arbitrary URLs.
    """
    settings = await get_all_settings(db)
    webhook_url = settings.get("webhook_url")
    if not webhook_url:
        raise HTTPException(status_code=400, detail="No webhook URL configured in settings")

    from services.webhook import send_webhook
    payload = {"text": "✅ OSS Monitor — test notification", "event": "test"}
    ok = await send_webhook(webhook_url, payload)
    if not ok:
        raise HTTPException(status_code=502, detail="Webhook delivery failed — check the URL and try again")
    return {"detail": "Test notification delivered successfully"}


@app.post("/settings/test-cvepaas", summary="Check connectivity to the configured CVE-PaaS instance")
async def test_cvepaas(db: AsyncSession = Depends(get_db)):
    """
    Probes CVE-PaaS /healthz using the stored URL. As with the webhook test,
    the URL never comes from the request body — that keeps this endpoint from
    being usable as an SSRF primitive.
    """
    settings = await get_all_settings(db)
    base_url = resolve_base_url(settings)
    if not base_url:
        raise HTTPException(
            status_code=400,
            detail="CVE-PaaS integration is disabled or has no URL configured",
        )
    result = await check_health(base_url)
    if not result["ok"]:
        raise HTTPException(status_code=502, detail=result["detail"])
    return {"detail": result["detail"], "url": base_url}


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
