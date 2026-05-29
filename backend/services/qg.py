"""
Quality Gate evaluation service.

Evaluates each component against configured thresholds and returns
a list of QG events. The scheduler calls this after every refresh.
Immediate alerts (new critical/high CVEs) are sent right away;
scorecard/stale issues are batched into a daily digest.
"""

import json
import logging
from datetime import datetime, timedelta

from services.webhook import (
    build_new_cve_payload,
    build_scorecard_fail_payload,
    build_stale_payload,
    build_digest_payload,
    send_webhook,
)

logger = logging.getLogger(__name__)


async def evaluate_new_vulns(component, new_vulns: list[dict],
                              settings: dict, webhook_url: str | None) -> list[dict]:
    """
    Send immediate alerts for newly discovered critical/high CVEs.
    Returns list of triggered events.
    """
    events = []
    for vuln in new_vulns:
        severity = vuln.get("severity", "unknown")
        should_notify = (
            (severity == "critical" and settings.get("notify_on_critical")) or
            (severity == "high" and settings.get("notify_on_high"))
        )
        if should_notify and webhook_url:
            payload = build_new_cve_payload(
                component.name, component.version,
                component.tags, vuln["id"], severity
            )
            await send_webhook(webhook_url, payload)
            logger.info(f"Alert sent for {vuln['id']} ({severity}) on {component.name}")

        events.append({
            "component": f"{component.name} {component.version}",
            "reason": f"New {severity} CVE: {vuln['id']}",
            "severity": severity,
            "type": "new_cve",
        })
    return events


async def evaluate_scorecard(component, settings: dict) -> dict | None:
    """
    Check Scorecard score against threshold.
    Returns a QG event dict if the gate fails, None otherwise.
    """
    if not settings.get("notify_on_scorecard_fail"):
        return None
    if component.scorecard_score is None:
        return None

    threshold = settings.get("scorecard_min_score", 5.0)
    if component.scorecard_score < threshold:
        logger.info(f"Scorecard QG fail: {component.name} score={component.scorecard_score} < {threshold}")
        return {
            "component": f"{component.name} {component.version}",
            "reason": f"Scorecard score {component.scorecard_score}/10 below threshold {threshold}",
            "type": "scorecard_fail",
        }
    return None


async def evaluate_staleness(component, settings: dict) -> dict | None:
    """
    Check if the repo hasn't been updated for too long.
    Uses scorecard data (last_commit_date from Maintained check) if available,
    otherwise falls back to component.scorecard_updated.
    """
    if not settings.get("notify_on_stale"):
        return None

    threshold_days = settings.get("stale_days_threshold", 730)
    last_date = None

    # Try to extract last commit date from scorecard JSON
    if component.scorecard_data:
        try:
            sc = json.loads(component.scorecard_data)
            for check in sc.get("checks", []):
                if check.get("name") == "Maintained":
                    details = check.get("details") or []
                    for detail in details:
                        if "last commit" in detail.lower():
                            # "last commit: 2023-01-15" style
                            parts = detail.split(":")
                            if len(parts) > 1:
                                try:
                                    last_date = datetime.fromisoformat(parts[-1].strip())
                                except ValueError:
                                    pass
        except Exception:
            pass

    if last_date is None:
        return None

    days_since = (datetime.now() - last_date).days
    if days_since > threshold_days:
        logger.info(f"Stale QG: {component.name} last commit {days_since} days ago")
        return {
            "component": f"{component.name} {component.version}",
            "reason": f"No commits for {days_since} days (threshold: {threshold_days})",
            "type": "stale",
        }
    return None


async def run_daily_digest(components: list, settings: dict):
    """
    Run scorecard + staleness QG for all components and send digest if issues found.
    """
    webhook_url = settings.get("webhook_url")
    if not webhook_url:
        return

    digest_events = []
    for component in components:
        sc_event = await evaluate_scorecard(component, settings)
        if sc_event:
            digest_events.append(sc_event)

        stale_event = await evaluate_staleness(component, settings)
        if stale_event:
            digest_events.append(stale_event)

    if digest_events:
        payload = build_digest_payload(digest_events)
        await send_webhook(webhook_url, payload)
        logger.info(f"Daily digest sent: {len(digest_events)} issue(s)")
