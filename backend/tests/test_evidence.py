"""Tests for Evidence CRUD and API endpoints."""
import pytest


@pytest.mark.asyncio
async def test_add_and_list_evidence(client, seeded_component):
    cid = seeded_component.id

    resp = await client.post(f"/components/{cid}/evidence", json={
        "type": "virustotal",
        "title": "VT scan 2024-01",
        "url": "https://virustotal.com/gui/file/abc123",
        "notes": "0/72 detections",
    })
    assert resp.status_code == 200
    e = resp.json()
    assert e["title"] == "VT scan 2024-01"
    assert e["type"] == "virustotal"
    assert e["url"] == "https://virustotal.com/gui/file/abc123"
    assert e["id"] is not None

    # List
    resp2 = await client.get(f"/components/{cid}/evidence")
    assert resp2.status_code == 200
    assert len(resp2.json()) == 1


@pytest.mark.asyncio
async def test_add_evidence_all_types(client, seeded_component):
    cid = seeded_component.id
    types = ["analyst_report", "incident_link", "virustotal",
             "cve_discussion", "audit_report", "other"]
    for t in types:
        resp = await client.post(f"/components/{cid}/evidence", json={
            "type": t, "title": f"Test {t}",
        })
        assert resp.status_code == 200, f"Failed for type {t}"


@pytest.mark.asyncio
async def test_delete_evidence(client, seeded_component):
    cid = seeded_component.id
    resp = await client.post(f"/components/{cid}/evidence", json={
        "type": "other", "title": "To be deleted",
    })
    eid = resp.json()["id"]

    del_resp = await client.delete(f"/evidence/{eid}")
    assert del_resp.status_code == 200

    list_resp = await client.get(f"/components/{cid}/evidence")
    assert all(e["id"] != eid for e in list_resp.json())


@pytest.mark.asyncio
async def test_delete_evidence_not_found(client):
    resp = await client.delete("/evidence/99999")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_evidence_for_nonexistent_component(client):
    resp = await client.get("/components/99999/evidence")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_add_evidence_nonexistent_component(client):
    resp = await client.post("/components/99999/evidence", json={
        "type": "other", "title": "Orphan",
    })
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_evidence_appears_in_component_serialization(client, seeded_component):
    cid = seeded_component.id
    await client.post(f"/components/{cid}/evidence", json={
        "type": "incident_link",
        "title": "GitHub incident #1234",
        "url": "https://github.com/org/repo/issues/1234",
    })

    resp = await client.get(f"/components/{cid}")
    data = resp.json()
    assert "evidence" in data
    assert len(data["evidence"]) == 1
    assert data["evidence"][0]["type"] == "incident_link"
