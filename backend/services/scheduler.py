import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)


def start_scheduler():
    scheduler = AsyncIOScheduler()

    @scheduler.scheduled_job(CronTrigger(hour=3, minute=0, timezone="UTC"))
    async def refresh_all_job():
        """
        Daily job: refresh all component vulnerabilities, update Scorecards,
        then run Quality Gate evaluation and send webhook notifications.
        """
        logger.info("Scheduler: starting daily refresh + QG run")
        try:
            from crud.components import get_all_components
            from crud.settings import get_all_settings
            from db.database import async_session
            from db.models import Vulnerability
            from models import ComponentRequest
            from services.analyzer import analyze_component
            from services.qg import evaluate_new_vulns, run_daily_digest
            from services.scorecard import fetch_scorecard
            import json

            async with async_session() as db:
                settings = await get_all_settings(db)
                webhook_url = settings.get("webhook_url")
                components = await get_all_components(db)

                for component in components:
                    # ── Vulnerability refresh ─────────────────────────────
                    try:
                        request_data = ComponentRequest(
                            type=component.type,
                            name=component.name,
                            version=component.version,
                            ecosystem=component.ecosystem,
                            identifier_override=component.identifier,
                        )
                        _, vulnerabilities = await analyze_component(request_data)
                        existing_vulns = {(v.cve_id, v.source) for v in component.vulnerabilities}

                        new_vulns = []
                        for vuln in vulnerabilities:
                            if (vuln["id"], vuln["source"]) not in existing_vulns:
                                db.add(Vulnerability(
                                    cve_id=vuln["id"],
                                    source=vuln["source"],
                                    severity=vuln.get("severity", "unknown"),
                                    is_false_positive=False,
                                    component=component,
                                ))
                                new_vulns.append(vuln)

                        component.last_updated = datetime.now()

                        # ── Immediate QG alerts for new CVEs ──────────────
                        if new_vulns:
                            await evaluate_new_vulns(component, new_vulns, settings, webhook_url)

                    except Exception as e:
                        logger.error(f"Refresh failed for '{component.name}': {e}")

                    # ── Scorecard refresh ─────────────────────────────────
                    if component.repo_url:
                        try:
                            sc = await fetch_scorecard(component.repo_url)
                            if sc:
                                component.scorecard_score = sc["score"]
                                component.scorecard_data = json.dumps(sc)
                                component.scorecard_updated = datetime.now()
                        except Exception as e:
                            logger.error(f"Scorecard refresh failed for '{component.name}': {e}")

                await db.commit()

                # ── Daily digest (scorecard + stale) ─────────────────────
                await run_daily_digest(components, settings)
                logger.info("Scheduler: daily refresh + QG complete")

        except Exception as e:
            logger.error(f"Scheduled job failed: {e}")

    scheduler.start()
    logger.info("Scheduler started — daily refresh + QG at 03:00 UTC")
