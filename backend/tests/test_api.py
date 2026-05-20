"""
Integration tests for all FastAPI endpoints.

Uses an in-memory SQLite DB (via conftest fixtures) and mocks all
external HTTP calls to NVD / OSV via respx.
"""

import pytest
import respx
from httpx import Response

OSV_URL = "https://api.osv.dev/v1/query"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

OSV_VULN_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-abcd-1234-efgh",
            "summary": "Critical RCE",
            "details": "",
            "aliases": ["CVE-2023-99999"],
            "database_specific": {"severity": "CRITICAL"},
        }
    ]
}

NVD_VULN_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-44487",
                "descriptions": [{"lang": "en", "value": "HTTP/2 Rapid Reset"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
            }
        }
    ]
}

NVD_CPE_RESPONSE = {
    "products": [
        {"cpe": {"cpeName": "cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*"}}
    ]
}


# ── /analyze ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_analyze_library(client):
    respx.post(OSV_URL).mock(return_value=Response(200, json=OSV_VULN_RESPONSE))

    resp = await client.post("/analyze", json={
        "type": "library",
        "name": "spring-core",
        "version": "5.3.0",
        "ecosystem": "maven",
        "identifier_override": "pkg:maven/spring-core@5.3.0",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "spring-core"
    assert "GHSA-abcd-1234-efgh" in data["vulnerabilities"]


@pytest.mark.asyncio
@respx.mock
async def test_analyze_product(client):
    respx.get(NVD_CVE_URL).mock(return_value=Response(200, json=NVD_VULN_RESPONSE))

    resp = await client.post("/analyze", json={
        "type": "product",
        "name": "nginx",
        "version": "1.23.0",
        "identifier_override": "cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*",
    })
    assert resp.status_code == 200
    assert "CVE-2023-44487" in resp.json()["vulnerabilities"]


# ── /generate_identifier ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_generate_identifier_library(client):
    resp = await client.post("/generate_identifier", json={
        "type": "library",
        "name": "lodash",
        "version": "4.17.21",
        "ecosystem": "npm",
    })
    assert resp.status_code == 200
    assert resp.json()["identifier"] == "pkg:npm/lodash@4.17.21"


# ── POST /components ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_add_component_with_tags(client):
    respx.post(OSV_URL).mock(return_value=Response(200, json=OSV_VULN_RESPONSE))

    resp = await client.post("/components", json={
        "type": "library",
        "name": "spring-core",
        "version": "5.3.0",
        "ecosystem": "maven",
        "identifier_override": "pkg:maven/spring-core@5.3.0",
        "tags": "prod,backend",
        "notes": "Managed by team-a",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["tags"] == "prod,backend"
    assert data["notes"] == "Managed by team-a"
    assert data["id"] is not None


@pytest.mark.asyncio
@respx.mock
async def test_add_duplicate_component_returns_existing(client):
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))

    payload = {
        "type": "library",
        "name": "lodash",
        "version": "4.17.21",
        "ecosystem": "npm",
        "identifier_override": "pkg:npm/lodash@4.17.21",
    }
    resp1 = await client.post("/components", json=payload)
    resp2 = await client.post("/components", json=payload)

    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert resp1.json()["id"] == resp2.json()["id"]


# ── GET /components ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_components_empty(client):
    resp = await client.get("/components")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_components_returns_seeded(client, seeded_component):
    resp = await client.get("/components")
    assert resp.status_code == 200
    names = [c["name"] for c in resp.json()]
    assert "nginx" in names


@pytest.mark.asyncio
async def test_list_components_filter_by_tag(client, seeded_component):
    resp = await client.get("/components?tag=prod")
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    resp_no_match = await client.get("/components?tag=staging")
    assert resp_no_match.json() == []


# ── GET /components/{id} ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_component_by_id(client, seeded_component):
    resp = await client.get(f"/components/{seeded_component.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "nginx"
    assert len(data["vulnerabilities"]) == 1
    assert data["vulnerabilities"][0]["cve_id"] == "CVE-2023-44487"


@pytest.mark.asyncio
async def test_get_component_not_found(client):
    resp = await client.get("/components/99999")
    assert resp.status_code == 404


# ── PATCH /components/{id} ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_component_notes_and_tags(client, seeded_component):
    resp = await client.patch(f"/components/{seeded_component.id}", json={
        "notes": "Updated note",
        "tags": "prod,db-server",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["notes"] == "Updated note"
    assert data["tags"] == "prod,db-server"


@pytest.mark.asyncio
async def test_update_component_not_found(client):
    resp = await client.patch("/components/99999", json={"notes": "x"})
    assert resp.status_code == 404


# ── DELETE /components/{id} ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_component(client, seeded_component):
    resp = await client.delete(f"/components/{seeded_component.id}")
    assert resp.status_code == 200

    # Confirm gone
    resp2 = await client.get(f"/components/{seeded_component.id}")
    assert resp2.status_code == 404


@pytest.mark.asyncio
async def test_delete_component_not_found(client):
    resp = await client.delete("/components/99999")
    assert resp.status_code == 404


# ── POST /components/{id}/refresh ────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_refresh_component_adds_new_vulns(client, seeded_component):
    # Simulate NVD returning a NEW CVE not yet in DB
    respx.get(NVD_CVE_URL).mock(return_value=Response(200, json={
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-00001",
                    "descriptions": [{"lang": "en", "value": "New vuln"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]},
                }
            }
        ]
    }))

    resp = await client.post(f"/components/{seeded_component.id}/refresh")
    assert resp.status_code == 200
    vuln_ids = [v["cve_id"] for v in resp.json()["vulnerabilities"]]
    # Original vuln still there + new one added
    assert "CVE-2023-44487" in vuln_ids
    assert "CVE-2024-00001" in vuln_ids


@pytest.mark.asyncio
async def test_refresh_component_not_found(client):
    resp = await client.post("/components/99999/refresh")
    assert resp.status_code == 404


# ── POST /components/refresh_all ─────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_refresh_all(client, seeded_component):
    respx.get(NVD_CVE_URL).mock(return_value=Response(200, json={"vulnerabilities": []}))

    resp = await client.post("/components/refresh_all")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    assert data["updated"][0]["name"] == "nginx"


# ── GET /dashboard ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dashboard_empty(client):
    resp = await client.get("/dashboard")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_components"] == 0
    assert data["components_with_vulns"] == 0
    assert data["severity_counts"]["critical"] == 0


@pytest.mark.asyncio
async def test_dashboard_with_seeded(client, seeded_component):
    resp = await client.get("/dashboard")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_components"] == 1
    assert data["components_with_vulns"] == 1
    assert data["severity_counts"]["high"] == 1
    assert data["top_vulnerable"][0]["name"] == "nginx"


# ── PATCH /vulnerabilities/{id}/false_positive ───────────────────────────────

@pytest.mark.asyncio
async def test_mark_false_positive(client, seeded_component):
    vuln_id = seeded_component.vulnerabilities[0].id

    resp = await client.patch(f"/vulnerabilities/{vuln_id}/false_positive", json={
        "is_false_positive": True,
        "reason": "Internal service, not exposed",
    })
    assert resp.status_code == 200

    # Dashboard should no longer count it
    dash = await client.get("/dashboard")
    assert dash.json()["components_with_vulns"] == 0


@pytest.mark.asyncio
async def test_mark_false_positive_not_found(client):
    resp = await client.patch("/vulnerabilities/99999/false_positive", json={
        "is_false_positive": True,
    })
    assert resp.status_code == 404
