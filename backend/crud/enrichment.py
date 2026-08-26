"""
Persistence layer for CVE-PaaS enrichment.

Keeps the CVE-PaaS client (services/cvepaas.py) free of DB concerns:
this module selects which vulnerabilities need a priority, calls the client
once for the whole set, and writes the verdicts back.
"""

import json
import logging
from datetime import datetime

from db.models import Vulnerability
from services.cvepaas import enrich_cves, pick_cve
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

logger = logging.getLogger(__name__)


def apply_verdict(vuln: Vulnerability, verdict: dict, now: datetime) -> None:
    """Write one CVE-PaaS verdict onto a Vulnerability row."""
    vuln.priority = verdict.get("priority")
    vuln.epss_score = verdict.get("epss_score")
    vuln.is_kev = verdict.get("is_kev")
    vuln.is_poc = verdict.get("is_poc")
    vuln.is_template = verdict.get("is_template")
    vuln.cvepaas_data = json.dumps(verdict.get("raw") or {})
    vuln.priority_updated = now
    # CVE-PaaS reports a CVSS base score even where NVD/OSV gave us none.
    if vuln.cvss_score is None and verdict.get("cvss_score") is not None:
        vuln.cvss_score = verdict["cvss_score"]


async def enrich_vulnerabilities(
    db: AsyncSession,
    vulns: list[Vulnerability],
    base_url: str,
    force: bool = False,
) -> list[dict]:
    """
    Enrich the given Vulnerability rows in place and commit.

    Only rows with a real CVE ID are eligible. Rows that already carry a
    priority are skipped unless `force` is set, so a nightly run costs one
    CVE-PaaS call for the newly discovered CVEs and nothing more.

    Returns one change record per updated row, carrying the previous
    priority/KEV state so callers can detect escalations (a PoC published
    for a CVE we have been carrying for months is worth an alert, and it is
    only visible as a transition).
    """
    # Map each eligible row to the CVE it should be looked up by — for OSV rows
    # that is an alias, not the primary ID.
    candidates = [
        (v, cve) for v in vulns
        if (force or v.priority is None)
        and (cve := pick_cve(v.cve_id, v.aliases))
    ]
    if not candidates:
        return []

    verdicts = await enrich_cves([cve for _, cve in candidates], base_url)
    if not verdicts:
        return []

    now = datetime.now()
    changes = []
    for vuln, cve in candidates:
        verdict = verdicts.get(cve)
        if not verdict:
            continue
        before = {"priority": vuln.priority, "is_kev": vuln.is_kev, "epss_score": vuln.epss_score}
        apply_verdict(vuln, verdict, now)
        changes.append({
            "vuln": vuln,
            "cve_id": cve,
            "vuln_id": vuln.cve_id,
            "before": before,
            "after": {"priority": vuln.priority, "is_kev": vuln.is_kev, "epss_score": vuln.epss_score},
        })

    if changes:
        await db.commit()
    logger.info(f"CVE-PaaS: {len(changes)} vulnerability row(s) updated")
    return changes


async def enrich_all(db: AsyncSession, base_url: str, force: bool = False) -> list[dict]:
    """Enrich every stored vulnerability that still lacks a priority."""
    stmt = select(Vulnerability)
    if not force:
        stmt = stmt.where(Vulnerability.priority.is_(None))
    result = await db.execute(stmt)
    return await enrich_vulnerabilities(db, list(result.scalars().all()), base_url, force)
