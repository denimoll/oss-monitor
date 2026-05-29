"""Tests for Quality Gate evaluation logic."""
import json
import pytest
import respx
from httpx import Response
from unittest.mock import AsyncMock, patch


# ── evaluate_new_vulns ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_evaluate_new_vulns_sends_critical_alert(seeded_component):
    from services.qg import evaluate_new_vulns

    settings = {"notify_on_critical": True, "notify_on_high": False}
    new_vulns = [{"id": "CVE-2024-9999", "severity": "critical", "source": "nvd"}]

    with patch("services.qg.send_webhook", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        events = await evaluate_new_vulns(
            seeded_component, new_vulns, settings, "https://hooks.example.com"
        )

    assert len(events) == 1
    assert events[0]["type"] == "new_cve"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][1]
    assert payload["event"] == "new_vulnerability"
    assert payload["severity"] == "critical"


@pytest.mark.asyncio
async def test_evaluate_new_vulns_no_alert_for_medium(seeded_component):
    from services.qg import evaluate_new_vulns

    settings = {"notify_on_critical": True, "notify_on_high": False}
    new_vulns = [{"id": "CVE-2024-1111", "severity": "medium", "source": "nvd"}]

    with patch("services.qg.send_webhook", new_callable=AsyncMock) as mock_send:
        events = await evaluate_new_vulns(
            seeded_component, new_vulns, settings, "https://hooks.example.com"
        )

    mock_send.assert_not_called()
    assert events[0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_evaluate_new_vulns_high_alert_when_enabled(seeded_component):
    from services.qg import evaluate_new_vulns

    settings = {"notify_on_critical": True, "notify_on_high": True}
    new_vulns = [{"id": "CVE-2024-2222", "severity": "high", "source": "nvd"}]

    with patch("services.qg.send_webhook", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        await evaluate_new_vulns(
            seeded_component, new_vulns, settings, "https://hooks.example.com"
        )

    mock_send.assert_called_once()


@pytest.mark.asyncio
async def test_evaluate_new_vulns_no_webhook_url(seeded_component):
    from services.qg import evaluate_new_vulns

    settings = {"notify_on_critical": True, "notify_on_high": True}
    new_vulns = [{"id": "CVE-2024-3333", "severity": "critical", "source": "nvd"}]

    with patch("services.qg.send_webhook", new_callable=AsyncMock) as mock_send:
        await evaluate_new_vulns(seeded_component, new_vulns, settings, None)

    mock_send.assert_not_called()


# ── evaluate_scorecard ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scorecard_gate_fail(seeded_component):
    from services.qg import evaluate_scorecard

    seeded_component.scorecard_score = 3.5
    settings = {"notify_on_scorecard_fail": True, "scorecard_min_score": 5.0}

    event = await evaluate_scorecard(seeded_component, settings)
    assert event is not None
    assert event["type"] == "scorecard_fail"
    assert "3.5" in event["reason"]


@pytest.mark.asyncio
async def test_scorecard_gate_pass(seeded_component):
    from services.qg import evaluate_scorecard

    seeded_component.scorecard_score = 7.0
    settings = {"notify_on_scorecard_fail": True, "scorecard_min_score": 5.0}

    event = await evaluate_scorecard(seeded_component, settings)
    assert event is None


@pytest.mark.asyncio
async def test_scorecard_gate_no_score(seeded_component):
    from services.qg import evaluate_scorecard

    seeded_component.scorecard_score = None
    settings = {"notify_on_scorecard_fail": True, "scorecard_min_score": 5.0}

    event = await evaluate_scorecard(seeded_component, settings)
    assert event is None


@pytest.mark.asyncio
async def test_scorecard_gate_disabled(seeded_component):
    from services.qg import evaluate_scorecard

    seeded_component.scorecard_score = 2.0
    settings = {"notify_on_scorecard_fail": False, "scorecard_min_score": 5.0}

    event = await evaluate_scorecard(seeded_component, settings)
    assert event is None


# ── evaluate_staleness ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_staleness_gate_fail(seeded_component):
    from services.qg import evaluate_staleness

    seeded_component.scorecard_data = json.dumps({
        "checks": [
            {"name": "Maintained", "details": ["last commit: 2020-01-01"]}
        ]
    })
    settings = {"notify_on_stale": True, "stale_days_threshold": 365}

    event = await evaluate_staleness(seeded_component, settings)
    assert event is not None
    assert event["type"] == "stale"


@pytest.mark.asyncio
async def test_staleness_gate_pass(seeded_component):
    from services.qg import evaluate_staleness
    from datetime import datetime, timedelta

    recent = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    seeded_component.scorecard_data = json.dumps({
        "checks": [
            {"name": "Maintained", "details": [f"last commit: {recent}"]}
        ]
    })
    settings = {"notify_on_stale": True, "stale_days_threshold": 365}

    event = await evaluate_staleness(seeded_component, settings)
    assert event is None


@pytest.mark.asyncio
async def test_staleness_no_scorecard_data(seeded_component):
    from services.qg import evaluate_staleness

    seeded_component.scorecard_data = None
    settings = {"notify_on_stale": True, "stale_days_threshold": 365}

    event = await evaluate_staleness(seeded_component, settings)
    assert event is None


# ── webhook integration ───────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_refresh_triggers_webhook_on_new_critical(client, seeded_component):
    """Integration: refresh endpoint sends webhook for new critical CVE."""
    # Configure webhook
    await client.put("/settings", json={
        "webhook_url": "https://hooks.example.com/test",
        "notify_on_critical": True,
        "notify_on_high": False,
        "scorecard_min_score": 5.0,
        "stale_days_threshold": 730,
        "notify_on_scorecard_fail": True,
        "notify_on_stale": True,
    })

    # Mock NVD: returns a NEW critical CVE not yet in DB
    respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
        return_value=Response(200, json={
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-BRAND-NEW",
                    "descriptions": [{"lang": "en", "value": "New critical"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]},
                }
            }]
        })
    )
    # Mock webhook endpoint
    webhook_mock = respx.post("https://hooks.example.com/test").mock(
        return_value=Response(200)
    )

    resp = await client.post(f"/components/{seeded_component.id}/refresh")
    assert resp.status_code == 200
    assert webhook_mock.called
