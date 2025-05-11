import logging

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

# Configure logging
logger = logging.getLogger(__name__)

def start_scheduler():
    scheduler = AsyncIOScheduler()

    # Cron job
    @scheduler.scheduled_job( CronTrigger(hour=3, minute=0, timezone="UTC"))
    async def refresh_all_components():
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post("http://localhost:8000/components/refresh_all")
                response.raise_for_status()
                logger.info("All components refreshed successfully.")
        except Exception as e:
            logger.error(f"Scheduled refresh failed: {e}")

    scheduler.start()
