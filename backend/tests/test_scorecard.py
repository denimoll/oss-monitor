"""Tests for Scorecard service and API endpoint."""
import pytest
import respx
from httpx import Response

from services.scorecard import _parse_github_repo, fetch_scorecard

SCORECARD_API = "https://api.securityscorecards.dev/projects/github.com"

SCORECARD_RESPONSE = {
    "score": 7.3,
    "date": "2024-05-01",
    "checks": [
        {"name": "Maintained", "score": 10, "details": ["last commit: 2024-04-15"]},
        {"name": "Branch-Protection", "score": 8, "details": []},
        {"name": "Signed-Releases", "score": -1, "details": ["no releases found"]},
    ],
    "repo": {"name": "github.com/nginx/nginx"},
}


# ── URL parsing ───────────────────────────────────────────────────────────────

def test_parse_github_url():
    assert _parse_github_repo("https://github.com/nginx/nginx") == "nginx/nginx"


def test_parse_github_url_with_git_suffix():
    assert _parse_github_repo("https://github.com/owner/repo.git") == "owner/repo"


def test_parse_github_url_with_path():
    assert _parse_github_repo("https://github.com/owner/repo/tree/main") == "owner/repo"


def test_parse_non_github_url():
    assert _parse_github_repo("https://gitlab.com/owner/repo") is None


def test_parse_invalid_url():
    assert _parse_github_repo("not-a-url") is None


# ── Scorecard API ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_fetch_scorecard_success():
    respx.get(f"{SCORECARD_API}/nginx/nginx").mock(
        return_value=Response(200, json=SCORECARD_RESPONSE)
    )
    result = await fetch_scorecard("https://github.com/nginx/nginx")
    assert result is not None
    assert result["score"] == 7.3
    assert result["repo"] == "nginx/nginx"
    assert len(result["checks"]) == 3


@pytest.mark.asyncio
@respx.mock
async def test_fetch_scorecard_not_found():
    respx.get(f"{SCORECARD_API}/unknown/repo").mock(return_value=Response(404))
    result = await fetch_scorecard("https://github.com/unknown/repo")
    assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_fetch_scorecard_server_error():
    respx.get(f"{SCORECARD_API}/nginx/nginx").mock(return_value=Response(500))
    result = await fetch_scorecard("https://github.com/nginx/nginx")
    assert result is None


@pytest.mark.asyncio
async def test_fetch_scorecard_non_github():
    result = await fetch_scorecard("https://gitlab.com/owner/repo")
    assert result is None


# ── API endpoint ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_scorecard_endpoint(client, seeded_component):
    # First set repo_url
    await client.patch(f"/components/{seeded_component.id}", json={
        "repo_url": "https://github.com/nginx/nginx",
    })

    respx.get(f"{SCORECARD_API}/nginx/nginx").mock(
        return_value=Response(200, json=SCORECARD_RESPONSE)
    )

    resp = await client.post(f"/components/{seeded_component.id}/scorecard")
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 7.3
    assert "checks" in data
    assert data["component"]["scorecard_score"] == 7.3


@pytest.mark.asyncio
async def test_scorecard_endpoint_no_repo_url(client, seeded_component):
    resp = await client.post(f"/components/{seeded_component.id}/scorecard")
    assert resp.status_code == 400
    assert "repo_url" in resp.json()["detail"]


@pytest.mark.asyncio
@respx.mock
async def test_scorecard_auto_fetch_on_add(client):
    respx.post("https://api.osv.dev/v1/query").mock(
        return_value=Response(200, json={"vulns": []})
    )
    respx.get(f"{SCORECARD_API}/nginx/nginx").mock(
        return_value=Response(200, json=SCORECARD_RESPONSE)
    )

    resp = await client.post("/components", json={
        "type": "library",
        "name": "test-lib",
        "version": "1.0.0",
        "ecosystem": "npm",
        "identifier_override": "pkg:npm/test-lib@1.0.0",
        "repo_url": "https://github.com/nginx/nginx",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["scorecard_score"] == 7.3


@pytest.mark.asyncio
@respx.mock
async def test_scorecard_not_found_endpoint(client, seeded_component):
    await client.patch(f"/components/{seeded_component.id}", json={
        "repo_url": "https://github.com/unknown/repo",
    })
    respx.get(f"{SCORECARD_API}/unknown/repo").mock(return_value=Response(404))

    resp = await client.post(f"/components/{seeded_component.id}/scorecard")
    assert resp.status_code == 404
