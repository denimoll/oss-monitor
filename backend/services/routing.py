"""
Notification routing.

One webhook for the whole inventory means every team gets every alert, which
is how alert channels turn into noise nobody reads. A route sends a component's
alerts to the channel of whoever actually owns it.

Routes live in the `notification_routes` setting as a JSON list:

    [
      {"match": {"owner": "platform"},          "webhook_url": "https://…/platform"},
      {"match": {"tag": "prod"},                "webhook_url": "https://…/oncall"},
      {"match": {"owner": "data", "tag": "db"}, "webhook_url": "https://…/data-db"}
    ]

Every route whose criteria match receives the alert — a prod component owned by
the platform team reaches both channels above, which is usually what you want
for an on-call channel. When nothing matches, the global `webhook_url` is used,
so adding routes never silently drops alerts for unrouted components.
"""

import json
import logging

logger = logging.getLogger(__name__)

_MATCH_KEYS = {"owner", "tag"}


def parse_routes(settings: dict) -> list[dict]:
    """
    Read and validate the configured routes.

    Malformed entries are dropped with a warning rather than raising: a typo in
    one route must not take down notifications for everything else.
    """
    raw = settings.get("notification_routes")
    if not raw:
        return []

    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            logger.error("notification_routes is not valid JSON — ignoring all routes")
            return []

    if not isinstance(raw, list):
        logger.error("notification_routes must be a list — ignoring")
        return []

    routes = []
    for entry in raw:
        if not isinstance(entry, dict):
            logger.warning(f"Ignoring non-object notification route: {entry!r}")
            continue
        url = entry.get("webhook_url")
        match = entry.get("match")
        if not url or not isinstance(match, dict) or not match:
            logger.warning(f"Ignoring notification route with no webhook_url or match: {entry!r}")
            continue
        unknown = set(match) - _MATCH_KEYS
        if unknown:
            logger.warning(
                f"Ignoring notification route with unknown match key(s) "
                f"{sorted(unknown)} — supported: {sorted(_MATCH_KEYS)}"
            )
            continue
        routes.append({"match": match, "webhook_url": url})
    return routes


def _component_tags(component) -> set[str]:
    return {t.strip().lower() for t in (getattr(component, "tags", None) or "").split(",") if t.strip()}


def route_matches(component, match: dict) -> bool:
    """Whether a component satisfies every criterion in one route."""
    owner = match.get("owner")
    if owner is not None:
        component_owner = (getattr(component, "owner", None) or "").strip().lower()
        if component_owner != str(owner).strip().lower():
            return False

    tag = match.get("tag")
    if tag is not None and str(tag).strip().lower() not in _component_tags(component):
        return False

    return True


def resolve_webhooks(component, settings: dict, default: str | None = None) -> list[str]:
    """
    Every webhook a component's alerts should reach.

    Falls back to `default` (the global webhook) when no route matches, so an
    unrouted component is never left without notifications. The result is
    de-duplicated while preserving order — two routes pointing at the same
    channel must not send the alert twice.
    """
    targets = [r["webhook_url"] for r in parse_routes(settings) if route_matches(component, r["match"])]

    if not targets and default:
        targets = [default]

    seen = set()
    unique = []
    for url in targets:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique
