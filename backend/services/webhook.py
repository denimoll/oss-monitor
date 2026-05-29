"""
Webhook notification service.

Sends JSON payloads to a configured URL (Slack, Telegram via bot,
or any custom HTTP endpoint).

Slack-compatible format is used by default — works with Slack incoming webhooks
and most other tools that accept a `text` field.
"""

import json
import logging

import httpx

logger = logging.getLogger(__name__)


async def send_webhook(webhook_url: str, payload: dict) -> bool:
    """
    Send a JSON payload to the webhook URL.
    Returns True on success, False on failure (never raises).
    """
    if not webhook_url:
        return False
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(webhook_url, json=payload)
            response.raise_for_status()
            logger.info(f"Webhook sent successfully to {webhook_url[:40]}...")
            return True
    except Exception as e:
        logger.error(f"Webhook delivery failed: {e}")
        return False


def build_new_cve_payload(component_name: str, component_version: str,
                           tags: str | None, cve_id: str, severity: str) -> dict:
    tag_str = f" [{tags}]" if tags else ""
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
    return {
        "text": f"{icon} *New {severity.upper()} vulnerability detected*",
        "event": "new_vulnerability",
        "component": f"{component_name} {component_version}{tag_str}",
        "cve_id": cve_id,
        "severity": severity,
    }


def build_scorecard_fail_payload(component_name: str, component_version: str,
                                  score: float, threshold: float,
                                  repo_url: str | None) -> dict:
    return {
        "text": f"🟠 *Scorecard score below threshold*",
        "event": "scorecard_fail",
        "component": f"{component_name} {component_version}",
        "score": score,
        "threshold": threshold,
        "repo_url": repo_url,
    }


def build_stale_payload(component_name: str, component_version: str,
                         days: int, repo_url: str | None) -> dict:
    return {
        "text": f"🟡 *Component may be abandoned*",
        "event": "stale_component",
        "component": f"{component_name} {component_version}",
        "days_since_update": days,
        "repo_url": repo_url,
    }


def build_digest_payload(results: list[dict]) -> dict:
    """Build a daily digest payload summarising all QG events."""
    lines = [f"📋 *Daily QG digest — {len(results)} issue(s) found*"]
    for r in results:
        lines.append(f"• {r['component']}: {r['reason']}")
    return {
        "text": "\n".join(lines),
        "event": "daily_digest",
        "issues": results,
    }
