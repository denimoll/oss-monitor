import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

# Configure logging
logger = logging.getLogger(__name__)


def start_scheduler():
    scheduler = AsyncIOScheduler()

    @scheduler.scheduled_job(CronTrigger(hour=3, minute=0, timezone="UTC"))
    async def refresh_all_job():
        """
        Daily job to refresh vulnerabilities for all components.
        Calls the DB directly instead of making an HTTP request to avoid
        localhost resolution issues in containerized environments.
        """
        try:
            from crud.components import get_all_components
            from db.database import async_session
            from db.models import Vulnerability
            from models import ComponentRequest
            from services.analyzer import analyze_component
            from datetime import datetime

            async with async_session() as db:
                components = await get_all_components(db)
                updated = []

                for component in components:
                    try:
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
                        updated.append(component.name)
                    except Exception as e:
                        logger.error(f"Failed to refresh component '{component.name}': {e}")

                await db.commit()
                logger.info(f"Scheduled refresh complete: {len(updated)} components updated")

        except Exception as e:
            logger.error(f"Scheduled refresh job failed: {e}")

    scheduler.start()
    logger.info("Scheduler started — daily refresh at 03:00 UTC")
