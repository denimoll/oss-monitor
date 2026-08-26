"""
Tests for the background job runner and the per-client rate limiter.
"""

import asyncio

import pytest
import respx
from httpx import Response

from db.models import Job, JobStatus
from services import ratelimit
from services.jobs import (
    JobAlreadyRunning,
    fail_interrupted_jobs,
    get_active_job,
    list_jobs,
    start_job,
    wait_for_job,
)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ── Runner ────────────────────────────────────────────────────────────────────

async def test_job_runs_and_records_its_result(db_session):
    async def body(db, progress):
        progress.set_total(3)
        for i in range(3):
            await progress.advance(detail=f"item {i}")
        return {"done": 3}

    job = await start_job(db_session, "test", body)
    assert job.status == JobStatus.pending

    await wait_for_job(job.id)
    # refresh() rather than expire_all(): an expired attribute reloads lazily on
    # access, which under async SQLAlchemy means IO outside a greenlet context.
    await db_session.refresh(job)

    assert job.status == JobStatus.completed
    assert job.processed == 3
    assert job.total == 3
    assert job.result == '{"done": 3}'
    assert job.started_at is not None
    assert job.finished_at is not None
    # The "working on…" note is cleared once there is nothing left to work on.
    assert job.detail is None


async def test_a_failing_body_is_recorded_not_swallowed(db_session):
    async def body(db, progress):
        raise ValueError("upstream exploded")

    job = await start_job(db_session, "test", body)
    await wait_for_job(job.id)
    await db_session.refresh(job)

    assert job.status == JobStatus.failed
    assert "ValueError" in job.error
    assert "upstream exploded" in job.error
    assert job.finished_at is not None


async def test_job_returning_nothing_completes(db_session):
    async def body(db, progress):
        return None

    job = await start_job(db_session, "test", body)
    await wait_for_job(job.id)
    await db_session.refresh(job)

    assert job.status == JobStatus.completed
    assert job.result is None


async def test_only_one_job_of_a_kind_runs_at_a_time(db_session):
    """Two concurrent full refreshes would double the load on NVD for nothing."""
    release = asyncio.Event()

    async def body(db, progress):
        await release.wait()
        return {}

    first = await start_job(db_session, "refresh_all", body)

    with pytest.raises(JobAlreadyRunning) as excinfo:
        await start_job(db_session, "refresh_all", body)
    assert excinfo.value.job.id == first.id

    release.set()
    await wait_for_job(first.id)


async def test_a_different_kind_is_not_blocked(db_session):
    release = asyncio.Event()

    async def body(db, progress):
        await release.wait()
        return {}

    first = await start_job(db_session, "refresh_all", body)
    second = await start_job(db_session, "enrich_all", body)
    assert second.id != first.id

    release.set()
    await wait_for_job(first.id)
    await wait_for_job(second.id)


async def test_a_finished_job_no_longer_blocks_the_next_one(db_session):
    async def body(db, progress):
        return {}

    first = await start_job(db_session, "refresh_all", body)
    await wait_for_job(first.id)
    await db_session.refresh(first)

    second = await start_job(db_session, "refresh_all", body)
    assert second.id != first.id
    await wait_for_job(second.id)


async def test_list_jobs_is_newest_first_and_filterable(db_session):
    async def body(db, progress):
        return {}

    for kind in ("refresh_all", "enrich_all", "refresh_all"):
        job = await start_job(db_session, kind, body)
        await wait_for_job(job.id)
        await db_session.refresh(job)

    everything = await list_jobs(db_session)
    assert [j.kind for j in everything] == ["refresh_all", "enrich_all", "refresh_all"]

    only_refresh = await list_jobs(db_session, kind="refresh_all")
    assert len(only_refresh) == 2


# ── Restart recovery ──────────────────────────────────────────────────────────

async def test_interrupted_jobs_are_failed_on_startup(db_session):
    """
    Jobs live in the process. Anything still active after a restart died with
    it, and leaving the row alone would both mislead the UI and block every
    future job of that kind.
    """
    for status in (JobStatus.pending, JobStatus.running):
        db_session.add(Job(kind="refresh_all", status=status, processed=0))
    db_session.add(Job(kind="refresh_all", status=JobStatus.completed, processed=1))
    await db_session.commit()

    assert await fail_interrupted_jobs(db_session) == 2

    jobs = await list_jobs(db_session)
    assert sorted(j.status for j in jobs) == sorted(
        [JobStatus.failed, JobStatus.failed, JobStatus.completed])
    for job in jobs:
        if job.status == JobStatus.failed:
            assert job.error == "Interrupted by a restart"


async def test_recovery_unblocks_the_kind(db_session):
    db_session.add(Job(kind="refresh_all", status=JobStatus.running, processed=0))
    await db_session.commit()
    assert await get_active_job(db_session, "refresh_all") is not None

    await fail_interrupted_jobs(db_session)
    assert await get_active_job(db_session, "refresh_all") is None


async def test_recovery_is_a_no_op_when_nothing_was_interrupted(db_session):
    assert await fail_interrupted_jobs(db_session) == 0


# ── HTTP surface ──────────────────────────────────────────────────────────────

@respx.mock
async def test_refresh_all_is_rejected_while_one_is_running(client, seeded_component):
    respx.get(url__startswith=NVD_CVE_URL).mock(
        return_value=Response(200, json={"vulnerabilities": []}))

    first = (await client.post("/components/refresh_all")).json()
    second = await client.post("/components/refresh_all")

    assert second.status_code == 409
    assert str(first["id"]) in second.json()["detail"]

    await wait_for_job(first["id"])


async def test_job_not_found(client):
    assert (await client.get("/jobs/9999")).status_code == 404


@respx.mock
async def test_jobs_listing_endpoint(client, seeded_component):
    respx.get(url__startswith=NVD_CVE_URL).mock(
        return_value=Response(200, json={"vulnerabilities": []}))

    job = (await client.post("/components/refresh_all")).json()
    await wait_for_job(job["id"])

    listing = (await client.get("/jobs")).json()
    assert len(listing) == 1
    assert listing[0]["kind"] == "refresh_all"

    assert (await client.get("/jobs?kind=enrich_all")).json() == []


@respx.mock
async def test_one_broken_component_does_not_abandon_the_run(client, db_session,
                                                             seeded_component):
    """
    A refresh spanning an inventory must survive a single unreachable source —
    otherwise one bad component silently costs you every later one.
    """
    from db.models import Component, ComponentTypeEnum

    db_session.add(Component(name="broken", version="9.9.9",
                             type=ComponentTypeEnum.product, identifier="cpe:broken"))
    await db_session.commit()

    def responder(request):
        if "broken" in str(request.url):
            raise ConnectionError("upstream down")
        return Response(200, json={"vulnerabilities": []})

    respx.get(url__startswith=NVD_CVE_URL).mock(side_effect=responder)

    job = (await client.post("/components/refresh_all")).json()
    await wait_for_job(job["id"])

    finished = (await client.get(f"/jobs/{job['id']}")).json()
    assert finished["status"] == "completed"
    assert finished["result"]["count"] == 1          # nginx still refreshed
    assert len(finished["result"]["failed"]) == 1
    assert finished["result"]["failed"][0]["name"] == "broken"
    assert finished["processed"] == 2                # both were attempted


# ── Rate limiting ─────────────────────────────────────────────────────────────

async def test_requests_under_the_limit_pass(client, monkeypatch):
    monkeypatch.setattr(ratelimit, "RATE_LIMIT", 5)

    with respx.mock:
        respx.post("https://api.osv.dev/v1/query").mock(
            return_value=Response(200, json={"vulns": []}))
        for _ in range(5):
            resp = await client.post("/analyze", json={
                "type": "library", "name": "lodash",
                "version": "4.17.21", "ecosystem": "npm",
            })
            assert resp.status_code == 200


async def test_exceeding_the_limit_returns_429_with_retry_after(client, monkeypatch):
    monkeypatch.setattr(ratelimit, "RATE_LIMIT", 2)

    with respx.mock:
        respx.post("https://api.osv.dev/v1/query").mock(
            return_value=Response(200, json={"vulns": []}))
        payload = {"type": "library", "name": "lodash",
                   "version": "4.17.21", "ecosystem": "npm"}

        for _ in range(2):
            assert (await client.post("/analyze", json=payload)).status_code == 200

        blocked = await client.post("/analyze", json=payload)

    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    assert blocked.headers["X-RateLimit-Remaining"] == "0"
    assert "2 requests per minute" in blocked.json()["detail"]


async def test_successful_responses_carry_the_budget_headers(client, monkeypatch):
    monkeypatch.setattr(ratelimit, "RATE_LIMIT", 10)

    with respx.mock:
        respx.post("https://api.osv.dev/v1/query").mock(
            return_value=Response(200, json={"vulns": []}))
        resp = await client.post("/analyze", json={
            "type": "library", "name": "lodash",
            "version": "4.17.21", "ecosystem": "npm",
        })

    assert resp.headers["X-RateLimit-Limit"] == "10"
    assert resp.headers["X-RateLimit-Remaining"] == "9"
    assert int(resp.headers["X-RateLimit-Reset"]) > 0


async def test_a_zero_limit_disables_the_check(client, monkeypatch):
    monkeypatch.setattr(ratelimit, "RATE_LIMIT", 0)

    with respx.mock:
        respx.post("https://api.osv.dev/v1/query").mock(
            return_value=Response(200, json={"vulns": []}))
        for _ in range(20):
            resp = await client.post("/analyze", json={
                "type": "library", "name": "lodash",
                "version": "4.17.21", "ecosystem": "npm",
            })
            assert resp.status_code == 200


async def test_analyze_and_generate_identifier_share_a_budget(client, monkeypatch):
    """
    Both cost an external lookup, so alternating between them must not double
    the effective allowance.
    """
    monkeypatch.setattr(ratelimit, "RATE_LIMIT", 2)
    payload = {"type": "library", "name": "lodash",
               "version": "4.17.21", "ecosystem": "npm"}

    with respx.mock:
        respx.post("https://api.osv.dev/v1/query").mock(
            return_value=Response(200, json={"vulns": []}))
        assert (await client.post("/analyze", json=payload)).status_code == 200
        assert (await client.post("/generate_identifier", json=payload)).status_code == 200
        assert (await client.post("/analyze", json=payload)).status_code == 429


async def test_reads_are_never_limited(client, monkeypatch):
    """The limiter protects the external quota, not the database."""
    monkeypatch.setattr(ratelimit, "RATE_LIMIT", 1)
    for _ in range(10):
        assert (await client.get("/components")).status_code == 200


# ── Client identification ─────────────────────────────────────────────────────

class _FakeRequest:
    def __init__(self, host, headers=None):
        self.headers = headers or {}
        self.client = type("C", (), {"host": host})() if host else None


def test_client_key_uses_the_socket_address_by_default(monkeypatch):
    monkeypatch.setattr(ratelimit, "TRUSTED_PROXY_COUNT", 0)
    request = _FakeRequest("10.0.0.1", {"X-Forwarded-For": "1.1.1.1"})
    # X-Forwarded-For is client-controlled; trusting it unconfigured would let
    # anyone reset their own counter on every request.
    assert ratelimit.client_key(request) == "10.0.0.1"


def test_client_key_reads_forwarded_for_when_a_proxy_is_trusted(monkeypatch):
    monkeypatch.setattr(ratelimit, "TRUSTED_PROXY_COUNT", 1)
    request = _FakeRequest("10.0.0.1", {"X-Forwarded-For": "203.0.113.7"})
    assert ratelimit.client_key(request) == "203.0.113.7"


def test_client_key_counts_hops_from_the_right(monkeypatch):
    """
    Counting from the right is what makes the value unspoofable: a client can
    prepend entries but cannot remove the ones the proxies append.
    """
    monkeypatch.setattr(ratelimit, "TRUSTED_PROXY_COUNT", 1)
    request = _FakeRequest("10.0.0.1", {"X-Forwarded-For": "9.9.9.9, 203.0.113.7"})
    assert ratelimit.client_key(request) == "203.0.113.7"


def test_client_key_falls_back_when_there_is_no_client(monkeypatch):
    monkeypatch.setattr(ratelimit, "TRUSTED_PROXY_COUNT", 0)
    assert ratelimit.client_key(_FakeRequest(None)) == "unknown"


def test_separate_clients_have_separate_budgets():
    ratelimit.reset()
    for _ in range(3):
        ratelimit._check("bucket", "client-a", 3)
    # client-a is exhausted; client-b must be unaffected.
    remaining, _ = ratelimit._check("bucket", "client-b", 3)
    assert remaining == 2

    with pytest.raises(Exception):
        ratelimit._check("bucket", "client-a", 3)
