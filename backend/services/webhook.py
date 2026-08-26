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
                           tags: str | None, cve_id: str, severity: str,
                           enrichment: dict | None = None,
                           owner: str | None = None,
                           fixed_version: str | None = None) -> dict:
    """
    Build a new-CVE alert. When CVE-PaaS enrichment is available the payload
    additionally carries the exploitation-aware verdict (priority, EPSS, KEV,
    PoC), which is what an on-call responder actually triages on.
    """
    tag_str = f" [{tags}]" if tags else ""
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
    payload = {
        "text": f"{icon} *New {severity.upper()} vulnerability detected*",
        "event": "new_vulnerability",
        "component": f"{component_name} {component_version}{tag_str}",
        "cve_id": cve_id,
        "severity": severity,
    }
    if owner:
        payload["owner"] = owner
    if enrichment:
        payload.update(_enrichment_fields(enrichment))
        payload["text"] += f"\n{_enrichment_line(enrichment)}"
    if fixed_version:
        # The single most actionable field in the whole alert.
        payload["fixed_version"] = fixed_version
        payload["text"] += f"\nFix: upgrade to *{fixed_version}*"
    return payload


def _enrichment_fields(enrichment: dict) -> dict:
    """The CVE-PaaS verdict fields carried on any enriched payload."""
    return {
        "priority": enrichment.get("priority"),
        "epss_score": enrichment.get("epss_score"),
        "is_kev": enrichment.get("is_kev"),
        "is_poc": enrichment.get("is_poc"),
        "is_template": enrichment.get("is_template"),
    }


def _enrichment_line(enrichment: dict) -> str:
    """Human-readable one-liner summarising the CVE-PaaS verdict."""
    parts = []
    if enrichment.get("priority"):
        parts.append(f"priority *{enrichment['priority']}*")
    epss = enrichment.get("epss_score")
    if epss is not None:
        parts.append(f"EPSS {epss:.2%}")
    if enrichment.get("is_kev"):
        parts.append("🚨 in KEV")
    if enrichment.get("is_poc"):
        parts.append("PoC available")
    if enrichment.get("is_template"):
        parts.append("Nuclei template")
    return "CVE-PaaS: " + ", ".join(parts) if parts else "CVE-PaaS: no verdict"


def build_escalation_payload(component_name: str, component_version: str,
                              tags: str | None, cve_id: str,
                              before: dict, after: dict,
                              owner: str | None = None) -> dict:
    """
    Alert for a CVE we already track whose exploitation status got worse —
    e.g. a PoC was published or CISA added it to KEV. This is the signal
    that a stale "medium" finding just became today's problem.
    """
    tag_str = f" [{tags}]" if tags else ""
    old = before.get("priority") or "unknown"
    new = after.get("priority") or "unknown"
    reason = "added to KEV" if after.get("is_kev") and not before.get("is_kev") else \
             f"priority raised {old} → {new}"
    payload = {
        "text": f"⬆️ *Exploitation status escalated* — {cve_id} {reason}",
        "event": "priority_escalation",
        "component": f"{component_name} {component_version}{tag_str}",
        "cve_id": cve_id,
        "previous_priority": before.get("priority"),
        "priority": after.get("priority"),
        "epss_score": after.get("epss_score"),
        "is_kev": after.get("is_kev"),
    }
    if owner:
        payload["owner"] = owner
    return payload


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
