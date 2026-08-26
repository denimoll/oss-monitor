import json
import logging

from db.models import Settings
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

logger = logging.getLogger(__name__)

DEFAULTS = {
    "webhook_url": None,
    "notify_on_critical": "true",
    "notify_on_high": "false",
    "scorecard_min_score": "5.0",
    "stale_days_threshold": "730",
    "notify_on_scorecard_fail": "true",
    "notify_on_stale": "true",
    # ── CVE-PaaS integration ──────────────────────────────────────────────
    "cvepaas_enabled": "false",
    "cvepaas_url": None,
    "notify_on_kev": "true",
    "notify_on_priority_critical": "false",
    "epss_alert_threshold": "0.0",
    # JSON list — see services/routing.py
    "notification_routes": None,
}


async def get_all_settings(db: AsyncSession) -> dict:
    result = await db.execute(select(Settings))
    rows = {row.key: row.value for row in result.scalars().all()}
    # Merge with defaults so all keys are always present
    merged = {**DEFAULTS, **rows}
    return _cast_settings(merged)


async def set_settings(db: AsyncSession, updates: dict) -> dict:
    for key, value in updates.items():
        result = await db.execute(select(Settings).where(Settings.key == key))
        row = result.scalar_one_or_none()
        # Structured settings (routes) round-trip as JSON; scalars as str().
        if value is None:
            str_value = None
        elif isinstance(value, (list, dict)):
            str_value = json.dumps(value)
        else:
            str_value = str(value)
        if row:
            row.value = str_value
        else:
            db.add(Settings(key=key, value=str_value))
    await db.commit()
    logger.info(f"Settings updated: {list(updates.keys())}")
    return await get_all_settings(db)


def _cast_settings(raw: dict) -> dict:
    """Cast string values to proper Python types."""
    casted = {}
    bool_keys = {
        "notify_on_critical", "notify_on_high", "notify_on_scorecard_fail",
        "notify_on_stale", "cvepaas_enabled", "notify_on_kev",
        "notify_on_priority_critical",
    }
    float_keys = {"scorecard_min_score", "epss_alert_threshold"}
    int_keys = {"stale_days_threshold"}
    json_keys = {"notification_routes"}

    for k, v in raw.items():
        if v is None:
            casted[k] = None
        elif k in bool_keys:
            casted[k] = str(v).lower() in ("true", "1", "yes")
        elif k in float_keys:
            casted[k] = float(v)
        elif k in int_keys:
            casted[k] = int(v)
        elif k in json_keys:
            try:
                casted[k] = json.loads(v) if isinstance(v, str) else v
            except (ValueError, TypeError):
                logger.error(f"Setting {k!r} holds invalid JSON — returning empty")
                casted[k] = []
        else:
            casted[k] = v
    return casted
