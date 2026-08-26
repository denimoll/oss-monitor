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

from services.cvepaas import PRIORITY_RANK
from services.routing import resolve_webhooks
from services.webhook import (
    build_escalation_payload,
    build_new_cve_payload,
    build_scorecard_fail_payload,
    build_stale_payload,
    build_digest_payload,
    send_webhook,
)

logger = logging.getLogger(__name__)


def should_alert_on_exploitability(enrichment: dict | None, settings: dict) -> str | None:
    """
    Decide whether the CVE-PaaS verdict alone justifies an alert, regardless
    of CVSS severity. Returns the triggering reason, or None.

    This is the point of the integration: CVSS ranks theoretical impact,
    CVE-PaaS ranks what is actually being exploited. A medium-CVSS CVE that
    is in KEV outranks an unexploited critical one.
    """
    if not enrichment:
        return None

    if settings.get("notify_on_kev") and enrichment.get("is_kev"):
        return "listed in CISA/VulnCheck KEV"

    if settings.get("notify_on_priority_critical"):
        priority = (enrichment.get("priority") or "").lower()
        if priority and PRIORITY_RANK.get(priority, 99) <= PRIORITY_RANK["critical"]:
            return "CVE-PaaS priority Critical"

    threshold = settings.get("epss_alert_threshold") or 0.0
    epss = enrichment.get("epss_score")
    if threshold > 0 and epss is not None and epss >= threshold:
        return f"EPSS {epss:.2%} at or above threshold {threshold:.2%}"

    return None


async def evaluate_new_vulns(component, new_vulns: list[dict],
                              settings: dict, webhook_url: str | None,
                              enrichment: dict[str, dict] | None = None) -> list[dict]:
    """
    Send immediate alerts for newly discovered CVEs.

    A CVE fires an alert when either the CVSS severity rules match
    (notify_on_critical / notify_on_high) or the CVE-PaaS exploitation rules
    do (notify_on_kev / notify_on_priority_critical / epss_alert_threshold).
    Exactly one alert is sent per CVE, carrying both signals.

    `enrichment` maps upper-case CVE ID → CVE-PaaS verdict; when omitted the
    behaviour is identical to the pre-integration severity-only logic.
    Returns list of triggered events.
    """
    enrichment = enrichment or {}
    events = []
    for vuln in new_vulns:
        severity = vuln.get("severity", "unknown")
        verdict = enrichment.get((vuln["id"] or "").upper())

        severity_match = (
            (severity == "critical" and settings.get("notify_on_critical")) or
            (severity == "high" and settings.get("notify_on_high"))
        )
        exploit_reason = should_alert_on_exploitability(verdict, settings)

        if severity_match or exploit_reason:
            payload = build_new_cve_payload(
                component.name, component.version,
                component.tags, vuln["id"], severity, verdict,
                owner=getattr(component, "owner", None),
                fixed_version=vuln.get("fixed_version"),
            )
            for target in resolve_webhooks(component, settings, webhook_url):
                await send_webhook(target, payload)
            logger.info(
                f"Alert sent for {vuln['id']} ({severity}"
                f"{', ' + exploit_reason if exploit_reason else ''}) on {component.name}"
            )

        reason = f"New {severity} CVE: {vuln['id']}"
        if exploit_reason:
            reason += f" — {exploit_reason}"

        events.append({
            "component": f"{component.name} {component.version}",
            "reason": reason,
            "severity": severity,
            "priority": (verdict or {}).get("priority"),
            "type": "new_cve",
        })
    return events


async def evaluate_escalations(component, changes: list[dict],
                                settings: dict, webhook_url: str | None) -> list[dict]:
    """
    Alert on CVEs already in the database whose exploitation status got worse
    since the last CVE-PaaS refresh — newly added to KEV, or promoted to a
    higher priority (typically because a PoC or Nuclei template appeared).

    Rows that had no previous verdict are skipped: a first-time enrichment is
    not an escalation, and `evaluate_new_vulns` already covers new findings.
    """
    events = []
    for change in changes:
        before, after = change["before"], change["after"]
        if before.get("priority") is None:
            continue  # first enrichment, not a change in the world
        if change["vuln"].is_false_positive:
            continue

        newly_kev = bool(after.get("is_kev")) and not bool(before.get("is_kev"))
        old_rank = PRIORITY_RANK.get((before.get("priority") or "").lower(), 99)
        new_rank = PRIORITY_RANK.get((after.get("priority") or "").lower(), 99)
        promoted = new_rank < old_rank

        if not (newly_kev or promoted):
            continue

        payload = build_escalation_payload(
            component.name, component.version, component.tags,
            change["cve_id"], before, after,
            owner=getattr(component, "owner", None),
        )
        for target in resolve_webhooks(component, settings, webhook_url):
            await send_webhook(target, payload)

        logger.info(
            f"Escalation on {component.name}: {change['cve_id']} "
            f"{before.get('priority')} → {after.get('priority')}"
            f"{' (now in KEV)' if newly_kev else ''}"
        )
        events.append({
            "component": f"{component.name} {component.version}",
            "reason": (
                f"{change['cve_id']} added to KEV" if newly_kev
                else f"{change['cve_id']} priority raised "
                     f"{before.get('priority')} → {after.get('priority')}"
            ),
            "type": "priority_escalation",
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
    Run scorecard + staleness QG for all components and send digests.

    Events are grouped by destination channel, so each team receives a digest
    covering its own components rather than the whole inventory. With no routes
    configured every event lands on the global webhook, exactly as before.
    """
    default_url = settings.get("webhook_url")

    # Preserve component order within each channel's digest.
    per_channel: dict[str, list[dict]] = {}
    for component in components:
        events = []
        sc_event = await evaluate_scorecard(component, settings)
        if sc_event:
            events.append(sc_event)

        stale_event = await evaluate_staleness(component, settings)
        if stale_event:
            events.append(stale_event)

        if not events:
            continue

        for target in resolve_webhooks(component, settings, default_url):
            per_channel.setdefault(target, []).extend(events)

    for target, events in per_channel.items():
        payload = build_digest_payload(events)
        await send_webhook(target, payload)
        logger.info(f"Daily digest sent to {target[:40]}: {len(events)} issue(s)")
