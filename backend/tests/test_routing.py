"""
Tests for owner/tag notification routing and the NVD rate-limit handling.
"""

import json

import pytest
import respx
from httpx import Response

from crud.settings import set_settings
from services import nvd
from services.qg import evaluate_new_vulns, run_daily_digest
from services.routing import parse_routes, resolve_webhooks, route_matches

PLATFORM = "https://hooks.test/platform"
ONCALL = "https://hooks.test/oncall"
GLOBAL = "https://hooks.test/global"


class _Component:
    def __init__(self, owner=None, tags=None, name="nginx", version="1.24.0"):
        self.owner = owner
        self.tags = tags
        self.name = name
        self.version = version
        self.scorecard_score = None
        self.scorecard_data = None


def routes(*entries):
    return {"notification_routes": list(entries)}


# ── Parsing ───────────────────────────────────────────────────────────────────

def test_parse_routes_accepts_a_list():
    parsed = parse_routes(routes({"match": {"owner": "platform"}, "webhook_url": PLATFORM}))
    assert parsed == [{"match": {"owner": "platform"}, "webhook_url": PLATFORM}]


def test_parse_routes_accepts_a_json_string():
    """Settings round-trip through SQLite as text."""
    raw = json.dumps([{"match": {"tag": "prod"}, "webhook_url": ONCALL}])
    assert len(parse_routes({"notification_routes": raw})) == 1


def test_parse_routes_on_empty_config():
    assert parse_routes({}) == []
    assert parse_routes({"notification_routes": None}) == []
    assert parse_routes({"notification_routes": []}) == []


def test_invalid_json_disables_routes_without_raising():
    assert parse_routes({"notification_routes": "{not json"}) == []


def test_one_bad_entry_does_not_discard_the_good_ones():
    """A typo in one route must not take down notifications for everything."""
    parsed = parse_routes(routes(
        {"match": {"owner": "platform"}, "webhook_url": PLATFORM},
        {"match": {"owner": "data"}},                       # no webhook_url
        {"webhook_url": ONCALL},                            # no match
        {"match": {"team": "x"}, "webhook_url": ONCALL},    # unknown match key
        "nonsense",
    ))
    assert parsed == [{"match": {"owner": "platform"}, "webhook_url": PLATFORM}]


# ── Matching ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("owner,tags,match,expected", [
    ("platform", None, {"owner": "platform"}, True),
    ("Platform", None, {"owner": "platform"}, True),          # case-insensitive
    (" platform ", None, {"owner": "platform"}, True),        # whitespace-tolerant
    ("data", None, {"owner": "platform"}, False),
    (None, None, {"owner": "platform"}, False),
    (None, "prod,web", {"tag": "prod"}, True),
    (None, "prod,web", {"tag": "PROD"}, True),
    (None, "production", {"tag": "prod"}, False),             # no substring match
    (None, None, {"tag": "prod"}, False),
    # Both keys present must both hold.
    ("data", "db,prod", {"owner": "data", "tag": "db"}, True),
    ("data", "prod", {"owner": "data", "tag": "db"}, False),
    ("other", "db", {"owner": "data", "tag": "db"}, False),
])
def test_route_matches(owner, tags, match, expected):
    assert route_matches(_Component(owner, tags), match) is expected


# ── Resolution ────────────────────────────────────────────────────────────────

def test_unrouted_component_falls_back_to_the_global_webhook():
    """Adding routes must never silently drop alerts for anyone else."""
    settings = routes({"match": {"owner": "platform"}, "webhook_url": PLATFORM})
    assert resolve_webhooks(_Component(owner="data"), settings, GLOBAL) == [GLOBAL]


def test_matched_component_does_not_also_hit_the_global_webhook():
    settings = routes({"match": {"owner": "platform"}, "webhook_url": PLATFORM})
    assert resolve_webhooks(_Component(owner="platform"), settings, GLOBAL) == [PLATFORM]


def test_every_matching_route_receives_the_alert():
    settings = routes(
        {"match": {"owner": "platform"}, "webhook_url": PLATFORM},
        {"match": {"tag": "prod"}, "webhook_url": ONCALL},
    )
    targets = resolve_webhooks(_Component(owner="platform", tags="prod,web"), settings, GLOBAL)
    assert targets == [PLATFORM, ONCALL]


def test_duplicate_targets_are_collapsed():
    settings = routes(
        {"match": {"owner": "platform"}, "webhook_url": PLATFORM},
        {"match": {"tag": "prod"}, "webhook_url": PLATFORM},
    )
    assert resolve_webhooks(_Component(owner="platform", tags="prod"), settings, GLOBAL) == [PLATFORM]


def test_no_targets_at_all_when_nothing_is_configured():
    assert resolve_webhooks(_Component(), {}, None) == []


# ── Routing applied to alerts ─────────────────────────────────────────────────

@respx.mock
async def test_new_cve_alert_goes_to_the_owner_channel():
    platform = respx.post(PLATFORM).mock(return_value=Response(200))
    glob = respx.post(GLOBAL).mock(return_value=Response(200))

    settings = {"notify_on_critical": True,
                **routes({"match": {"owner": "platform"}, "webhook_url": PLATFORM})}
    await evaluate_new_vulns(
        _Component(owner="platform"),
        [{"id": "CVE-2024-9999", "severity": "critical"}],
        settings, GLOBAL,
    )

    assert platform.call_count == 1
    assert glob.call_count == 0


@respx.mock
async def test_alert_payload_carries_owner_and_fix_version():
    hook = respx.post(GLOBAL).mock(return_value=Response(200))

    await evaluate_new_vulns(
        _Component(owner="platform"),
        [{"id": "CVE-2024-9999", "severity": "critical", "fixed_version": "1.25.3"}],
        {"notify_on_critical": True}, GLOBAL,
    )

    payload = json.loads(hook.calls[0].request.content)
    assert payload["owner"] == "platform"
    assert payload["fixed_version"] == "1.25.3"
    assert "1.25.3" in payload["text"]


@respx.mock
async def test_digest_is_split_per_channel():
    """
    Each team gets a digest covering its own components, not the whole
    inventory — the reason routing exists at all.
    """
    platform = respx.post(PLATFORM).mock(return_value=Response(200))
    data_hook = respx.post(ONCALL).mock(return_value=Response(200))

    settings = {
        "notify_on_scorecard_fail": True,
        "notify_on_stale": False,
        "scorecard_min_score": 5.0,
        "webhook_url": GLOBAL,
        **routes(
            {"match": {"owner": "platform"}, "webhook_url": PLATFORM},
            {"match": {"owner": "data"}, "webhook_url": ONCALL},
        ),
    }

    nginx = _Component(owner="platform", name="nginx")
    nginx.scorecard_score = 2.0
    redis = _Component(owner="data", name="redis")
    redis.scorecard_score = 1.0

    await run_daily_digest([nginx, redis], settings)

    assert platform.call_count == 1
    assert data_hook.call_count == 1
    platform_issues = json.loads(platform.calls[0].request.content)["issues"]
    assert len(platform_issues) == 1
    assert "nginx" in platform_issues[0]["component"]


@respx.mock
async def test_digest_without_routes_behaves_as_before():
    glob = respx.post(GLOBAL).mock(return_value=Response(200))

    component = _Component(name="nginx")
    component.scorecard_score = 2.0
    await run_daily_digest([component], {
        "notify_on_scorecard_fail": True, "notify_on_stale": False,
        "scorecard_min_score": 5.0, "webhook_url": GLOBAL,
    })

    assert glob.call_count == 1


# ── Settings round-trip ───────────────────────────────────────────────────────

async def test_routes_round_trip_through_settings(client):
    payload = [{"match": {"owner": "platform"}, "webhook_url": PLATFORM}]
    response = await client.put("/settings", json={"notification_routes": payload})
    assert response.status_code == 200

    stored = (await client.get("/settings")).json()["notification_routes"]
    assert stored == payload


async def test_routes_default_to_none(client):
    assert (await client.get("/settings")).json()["notification_routes"] is None


async def test_owner_round_trips_on_a_component(client, db_session, seeded_component):
    response = await client.patch(f"/components/{seeded_component.id}",
                                  json={"owner": "platform-team"})
    assert response.status_code == 200
    assert response.json()["owner"] == "platform-team"


# ── NVD rate limiting ─────────────────────────────────────────────────────────

@respx.mock
async def test_nvd_retries_on_rate_limit_and_succeeds():
    route = respx.get(url__startswith=f"{nvd.NVD_API_BASE}/cves/2.0").mock(
        side_effect=[
            Response(429, headers={"Retry-After": "0"}),
            Response(403),
            Response(200, json={"vulnerabilities": []}),
        ]
    )
    result = await nvd.analyze_nvd("cpe:2.3:a:f5:nginx:1.24.0", "nginx", "1.24.0")

    assert route.call_count == 3
    assert result == []


@respx.mock
async def test_nvd_gives_up_after_the_retry_budget():
    route = respx.get(url__startswith=f"{nvd.NVD_API_BASE}/cves/2.0").mock(
        return_value=Response(429, headers={"Retry-After": "0"})
    )
    with pytest.raises(Exception):
        await nvd.analyze_nvd("cpe:2.3:a:f5:nginx:1.24.0", "nginx", "1.24.0")
    assert route.call_count == nvd._MAX_RETRIES


@respx.mock
async def test_nvd_does_not_retry_a_genuine_error():
    """A 404 is an answer, not throttling — burning retries on it is waste."""
    route = respx.get(url__startswith=f"{nvd.NVD_API_BASE}/cves/2.0").mock(
        return_value=Response(404, text="not found")
    )
    with pytest.raises(Exception):
        await nvd.analyze_nvd("cpe:bogus", "x", "1.0")
    assert route.call_count == 1


@respx.mock
async def test_nvd_sends_the_api_key_when_configured(monkeypatch):
    monkeypatch.setattr(nvd, "_API_KEY", "secret-key")
    route = respx.get(url__startswith=f"{nvd.NVD_API_BASE}/cves/2.0").mock(
        return_value=Response(200, json={"vulnerabilities": []})
    )
    await nvd.analyze_nvd("cpe:2.3:a:f5:nginx:1.24.0", "nginx", "1.24.0")
    assert route.calls[0].request.headers["apiKey"] == "secret-key"


@respx.mock
async def test_nvd_extracts_fix_version_from_version_end_excluding():
    respx.get(url__startswith=f"{nvd.NVD_API_BASE}/cves/2.0").mock(
        return_value=Response(200, json={"vulnerabilities": [{"cve": {
            "id": "CVE-2024-0001",
            "descriptions": [{"lang": "en", "value": "test"}],
            "metrics": {},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*",
                 "versionStartIncluding": "1.20.0", "versionEndExcluding": "1.25.3"},
            ]}]}],
        }}]})
    )
    result = await nvd.analyze_nvd("cpe:2.3:a:f5:nginx:1.24.0", "nginx", "1.24.0")
    assert result[0]["fixed_version"] == "1.25.3"


@respx.mock
async def test_nvd_reports_no_fix_for_version_end_including():
    """
    `versionEndIncluding` says the named version is still vulnerable, so the
    fix is some later, unnamed release — reporting it would be wrong.
    """
    respx.get(url__startswith=f"{nvd.NVD_API_BASE}/cves/2.0").mock(
        return_value=Response(200, json={"vulnerabilities": [{"cve": {
            "id": "CVE-2024-0002",
            "descriptions": [{"lang": "en", "value": "test"}],
            "metrics": {},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*",
                 "versionEndIncluding": "1.24.0"},
            ]}]}],
        }}]})
    )
    result = await nvd.analyze_nvd("cpe:2.3:a:f5:nginx:1.24.0", "nginx", "1.24.0")
    assert result[0]["fixed_version"] is None
