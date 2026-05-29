"""Tests for Settings API and QG configuration."""
import pytest


@pytest.mark.asyncio
async def test_get_settings_returns_defaults(client):
    resp = await client.get("/settings")
    assert resp.status_code == 200
    data = resp.json()
    assert data["notify_on_critical"] is True
    assert data["notify_on_high"] is False
    assert data["scorecard_min_score"] == 5.0
    assert data["stale_days_threshold"] == 730
    assert data["webhook_url"] is None


@pytest.mark.asyncio
async def test_update_settings(client):
    resp = await client.put("/settings", json={
        "webhook_url": "https://hooks.slack.com/test/webhook",
        "notify_on_critical": True,
        "notify_on_high": True,
        "scorecard_min_score": 6.0,
        "stale_days_threshold": 365,
        "notify_on_scorecard_fail": True,
        "notify_on_stale": False,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["webhook_url"] == "https://hooks.slack.com/test/webhook"
    assert data["notify_on_high"] is True
    assert data["scorecard_min_score"] == 6.0
    assert data["stale_days_threshold"] == 365
    assert data["notify_on_stale"] is False


@pytest.mark.asyncio
async def test_settings_persist_across_requests(client):
    await client.put("/settings", json={
        "webhook_url": "https://example.com/hook",
        "notify_on_critical": True,
        "notify_on_high": False,
        "scorecard_min_score": 5.0,
        "stale_days_threshold": 730,
        "notify_on_scorecard_fail": True,
        "notify_on_stale": True,
    })
    resp = await client.get("/settings")
    assert resp.json()["webhook_url"] == "https://example.com/hook"


@pytest.mark.asyncio
async def test_update_settings_partial(client):
    # Set initial state
    await client.put("/settings", json={
        "webhook_url": "https://initial.com",
        "notify_on_critical": True,
        "notify_on_high": False,
        "scorecard_min_score": 5.0,
        "stale_days_threshold": 730,
        "notify_on_scorecard_fail": True,
        "notify_on_stale": True,
    })
    # Update only one field
    await client.put("/settings", json={
        "webhook_url": "https://updated.com",
        "notify_on_critical": True,
        "notify_on_high": False,
        "scorecard_min_score": 5.0,
        "stale_days_threshold": 730,
        "notify_on_scorecard_fail": True,
        "notify_on_stale": True,
    })
    resp = await client.get("/settings")
    assert resp.json()["webhook_url"] == "https://updated.com"
    assert resp.json()["notify_on_critical"] is True
