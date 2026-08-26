"""
Tests for the CVE-PaaS integration: the HTTP client, the persistence layer,
the priority-aware Quality Gate rules and the API endpoints.

All CVE-PaaS traffic is mocked with respx — no live instance is required.
"""

import json

import pytest
import respx
from httpx import Response

from crud.enrichment import enrich_all, enrich_vulnerabilities
from crud.settings import set_settings
from db.models import Component, ComponentTypeEnum, SeverityLevel, Vulnerability
from services import cvepaas
from services.qg import evaluate_escalations, should_alert_on_exploitability

CVEPAAS_URL = "http://cve-paas:8000"


def verdict(priority="Critical", epss=0.97, cvss=9.8, kev=True, poc=True, template=True):
    """Build a CVE-PaaS-shaped response entry."""
    return {
        "Priority": priority,
        "Details": {
            "CVSS": cvss,
            "EPSS": epss,
            "is_kev": kev,
            "is_vkev": False,
            "is_poc": poc,
            "is_template": template,
            "Links": {
                "POC": "https://example.test/poc" if poc else None,
                "Nuclei templates": None,
                "KEV": "https://example.test/kev" if kev else None,
            },
        },
    }


# ── URL resolution ────────────────────────────────────────────────────────────

def test_resolve_base_url_requires_enabled_flag():
    assert cvepaas.resolve_base_url({"cvepaas_enabled": False, "cvepaas_url": CVEPAAS_URL}) is None


def test_resolve_base_url_strips_trailing_slash():
    resolved = cvepaas.resolve_base_url(
        {"cvepaas_enabled": True, "cvepaas_url": CVEPAAS_URL + "/"}
    )
    assert resolved == CVEPAAS_URL


@pytest.mark.parametrize("bad", ["file:///etc/passwd", "not-a-url", "ftp://host/x", ""])
def test_resolve_base_url_rejects_non_http_schemes(bad):
    assert cvepaas.resolve_base_url({"cvepaas_enabled": True, "cvepaas_url": bad}) is None


# ── CVE ID filtering ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("vuln_id,expected", [
    ("CVE-2021-44228", True),
    ("cve-2021-44228", True),
    ("GHSA-jfh8-c2jp-5v3q", False),
    ("PYSEC-2021-19", False),
    ("GO-2021-0113", False),
    (None, False),
])
def test_is_cve_id(vuln_id, expected):
    assert cvepaas.is_cve_id(vuln_id) is expected


# ── Client ────────────────────────────────────────────────────────────────────

@respx.mock
async def test_enrich_cves_filters_and_normalizes():
    route = respx.post(f"{CVEPAAS_URL}/v1/cve").mock(
        return_value=Response(200, json={"CVE-2021-44228": verdict()})
    )
    result = await cvepaas.enrich_cves(
        ["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"], CVEPAAS_URL
    )

    # Non-CVE identifiers never reach CVE-PaaS — vulnx cannot resolve them.
    assert json.loads(route.calls[0].request.content) == {"cve_ids": ["CVE-2021-44228"]}
    assert result["CVE-2021-44228"]["priority"] == "Critical"
    assert result["CVE-2021-44228"]["epss_score"] == 0.97
    assert result["CVE-2021-44228"]["is_kev"] is True


async def test_enrich_cves_skips_call_when_no_cve_ids():
    # No respx mock registered: any HTTP call would raise.
    assert await cvepaas.enrich_cves(["GHSA-xxxx-yyyy-zzzz"], CVEPAAS_URL) == {}


@respx.mock
async def test_enrich_cves_batches_at_the_bulk_limit():
    ids = [f"CVE-2024-{1000 + i}" for i in range(cvepaas.BULK_LIMIT + 5)]
    route = respx.post(f"{CVEPAAS_URL}/v1/cve").mock(return_value=Response(200, json={}))
    await cvepaas.enrich_cves(ids, CVEPAAS_URL)

    assert route.call_count == 2
    first = json.loads(route.calls[0].request.content)["cve_ids"]
    second = json.loads(route.calls[1].request.content)["cve_ids"]
    assert len(first) == cvepaas.BULK_LIMIT
    assert len(second) == 5


@respx.mock
async def test_enrich_cves_skips_error_records():
    respx.post(f"{CVEPAAS_URL}/v1/cve").mock(return_value=Response(200, json={
        "CVE-2021-44228": verdict(),
        "CVE-2024-1111": {"error": "vulnx error: Rate limit exceeded"},
    }))
    result = await cvepaas.enrich_cves(["CVE-2021-44228", "CVE-2024-1111"], CVEPAAS_URL)

    # Error records must not overwrite good data — they are simply absent.
    assert set(result) == {"CVE-2021-44228"}


@respx.mock
async def test_enrich_cves_survives_upstream_failure():
    respx.post(f"{CVEPAAS_URL}/v1/cve").mock(return_value=Response(503, text="unavailable"))
    assert await cvepaas.enrich_cves(["CVE-2021-44228"], CVEPAAS_URL) == {}


@respx.mock
async def test_check_health():
    respx.get(f"{CVEPAAS_URL}/healthz").mock(return_value=Response(200, json={"status": "ok"}))
    assert (await cvepaas.check_health(CVEPAAS_URL))["ok"] is True

    respx.get(f"{CVEPAAS_URL}/healthz").mock(return_value=Response(503, text="vulnx missing"))
    result = await cvepaas.check_health(CVEPAAS_URL)
    assert result["ok"] is False and "503" in result["detail"]


def test_worst_priority():
    assert cvepaas.worst_priority(["Low", "Critical", "Medium"]) == "Critical"
    assert cvepaas.worst_priority([None, "Info"]) == "Info"
    assert cvepaas.worst_priority([None, None]) is None


# ── Persistence ───────────────────────────────────────────────────────────────

@respx.mock
async def test_enrich_vulnerabilities_persists_verdict(db_session, seeded_component):
    respx.post(f"{CVEPAAS_URL}/v1/cve").mock(
        return_value=Response(200, json={"CVE-2023-44487": verdict(priority="High", cvss=7.5)})
    )
    changes = await enrich_vulnerabilities(
        db_session, list(seeded_component.vulnerabilities), CVEPAAS_URL
    )

    assert len(changes) == 1
    vuln = seeded_component.vulnerabilities[0]
    assert vuln.priority == "High"
    assert vuln.is_kev is True
    assert vuln.epss_score == 0.97
    assert vuln.priority_updated is not None
    # CVSS is backfilled from CVE-PaaS when NVD/OSV gave us none.
    assert vuln.cvss_score == 7.5
    assert json.loads(vuln.cvepaas_data)["Priority"] == "High"


@respx.mock
async def test_enrich_skips_already_enriched_unless_forced(db_session, seeded_component):
    route = respx.post(f"{CVEPAAS_URL}/v1/cve").mock(
        return_value=Response(200, json={"CVE-2023-44487": verdict()})
    )
    vulns = list(seeded_component.vulnerabilities)

    await enrich_vulnerabilities(db_session, vulns, CVEPAAS_URL)
    assert route.call_count == 1

    # Second run: nothing left without a verdict, so no call is made.
    await enrich_vulnerabilities(db_session, vulns, CVEPAAS_URL)
    assert route.call_count == 1

    await enrich_vulnerabilities(db_session, vulns, CVEPAAS_URL, force=True)
    assert route.call_count == 2


@respx.mock
async def test_enrich_records_transition(db_session, seeded_component):
    vuln = seeded_component.vulnerabilities[0]
    respx.post(f"{CVEPAAS_URL}/v1/cve").mock(
        return_value=Response(200, json={"CVE-2023-44487": verdict(priority="Medium", kev=False, poc=False, template=False)})
    )
    await enrich_vulnerabilities(db_session, [vuln], CVEPAAS_URL)

    respx.post(f"{CVEPAAS_URL}/v1/cve").mock(
        return_value=Response(200, json={"CVE-2023-44487": verdict(priority="Critical", kev=True)})
    )
    changes = await enrich_vulnerabilities(db_session, [vuln], CVEPAAS_URL, force=True)

    assert changes[0]["before"] == {"priority": "Medium", "is_kev": False, "epss_score": 0.97}
    assert changes[0]["after"]["priority"] == "Critical"
    assert changes[0]["after"]["is_kev"] is True


@respx.mock
async def test_enrich_all_backfills_every_row(db_session):
    component = Component(name="redis", version="6.0.0", type=ComponentTypeEnum.product)
    db_session.add(component)
    await db_session.flush()
    for cve in ("CVE-2022-0543", "CVE-2021-32625"):
        db_session.add(Vulnerability(cve_id=cve, source="nvd",
                                     severity=SeverityLevel.high, component=component))
    await db_session.commit()

    respx.post(f"{CVEPAAS_URL}/v1/cve").mock(return_value=Response(200, json={
        "CVE-2022-0543": verdict(priority="Critical"),
        "CVE-2021-32625": verdict(priority="Low", kev=False, poc=False, template=False),
    }))
    changes = await enrich_all(db_session, CVEPAAS_URL)
    assert len(changes) == 2


# ── Quality Gate rules ────────────────────────────────────────────────────────

def test_kev_alerts_regardless_of_cvss_severity():
    settings = {"notify_on_kev": True}
    # A merely "medium" CVE that is actively exploited must still alert —
    # this is the whole reason the integration exists.
    reason = should_alert_on_exploitability(
        {"priority": "Medium", "is_kev": True}, settings
    )
    assert reason and "KEV" in reason


def test_no_alert_when_kev_notifications_disabled():
    assert should_alert_on_exploitability({"is_kev": True}, {"notify_on_kev": False}) is None


def test_priority_critical_rule():
    verdict_ = {"priority": "Critical", "is_kev": False}
    assert should_alert_on_exploitability(verdict_, {"notify_on_priority_critical": True})
    assert should_alert_on_exploitability(verdict_, {"notify_on_priority_critical": False}) is None


def test_epss_threshold_rule():
    settings = {"epss_alert_threshold": 0.5}
    assert should_alert_on_exploitability({"epss_score": 0.6}, settings)
    assert should_alert_on_exploitability({"epss_score": 0.4}, settings) is None
    # A zero threshold disables the rule rather than matching everything.
    assert should_alert_on_exploitability({"epss_score": 0.0}, {"epss_alert_threshold": 0.0}) is None


def test_no_enrichment_means_no_exploitability_alert():
    assert should_alert_on_exploitability(None, {"notify_on_kev": True}) is None


# ── Escalations ───────────────────────────────────────────────────────────────

class _FakeVuln:
    def __init__(self, is_false_positive=False):
        self.is_false_positive = is_false_positive


async def test_escalation_fires_on_new_kev_listing(seeded_component):
    changes = [{
        "vuln": _FakeVuln(), "cve_id": "CVE-2023-44487",
        "before": {"priority": "Medium", "is_kev": False},
        "after": {"priority": "Critical", "is_kev": True},
    }]
    events = await evaluate_escalations(seeded_component, changes, {}, None)
    assert len(events) == 1
    assert "added to KEV" in events[0]["reason"]


async def test_first_enrichment_is_not_an_escalation(seeded_component):
    changes = [{
        "vuln": _FakeVuln(), "cve_id": "CVE-2023-44487",
        "before": {"priority": None, "is_kev": None},
        "after": {"priority": "Critical", "is_kev": True},
    }]
    assert await evaluate_escalations(seeded_component, changes, {}, None) == []


async def test_downgrade_is_not_an_escalation(seeded_component):
    changes = [{
        "vuln": _FakeVuln(), "cve_id": "CVE-2023-44487",
        "before": {"priority": "Critical", "is_kev": True},
        "after": {"priority": "High", "is_kev": True},
    }]
    assert await evaluate_escalations(seeded_component, changes, {}, None) == []


async def test_false_positives_are_not_escalated(seeded_component):
    changes = [{
        "vuln": _FakeVuln(is_false_positive=True), "cve_id": "CVE-2023-44487",
        "before": {"priority": "Low", "is_kev": False},
        "after": {"priority": "Critical", "is_kev": True},
    }]
    assert await evaluate_escalations(seeded_component, changes, {}, None) == []


# ── API endpoints ─────────────────────────────────────────────────────────────

async def test_enrich_endpoint_rejected_when_integration_disabled(client, seeded_component):
    response = await client.post(f"/components/{seeded_component.id}/enrich")
    assert response.status_code == 400
    assert "disabled" in response.json()["detail"]


async def test_enrich_endpoint_404_for_unknown_component(client):
    assert (await client.post("/components/9999/enrich")).status_code == 404


@respx.mock
async def test_enrich_endpoint_returns_enriched_component(client, db_session, seeded_component):
    await set_settings(db_session, {"cvepaas_enabled": True, "cvepaas_url": CVEPAAS_URL})
    respx.post(f"{CVEPAAS_URL}/v1/cve").mock(
        return_value=Response(200, json={"CVE-2023-44487": verdict(priority="High")})
    )

    response = await client.post(f"/components/{seeded_component.id}/enrich")
    assert response.status_code == 200

    body = response.json()
    assert body["enriched"] == 1
    vuln = body["component"]["vulnerabilities"][0]
    assert vuln["priority"] == "High"
    assert vuln["is_kev"] is True
    assert vuln["cvepaas_links"]["KEV"] == "https://example.test/kev"


@respx.mock
async def test_backfill_endpoint(client, db_session, seeded_component):
    await set_settings(db_session, {"cvepaas_enabled": True, "cvepaas_url": CVEPAAS_URL})
    respx.post(f"{CVEPAAS_URL}/v1/cve").mock(
        return_value=Response(200, json={"CVE-2023-44487": verdict()})
    )
    response = await client.post("/vulnerabilities/enrich")
    assert response.status_code == 202

    job = response.json()
    from services.jobs import wait_for_job
    await wait_for_job(job["id"])

    finished = (await client.get(f"/jobs/{job['id']}")).json()
    assert finished["status"] == "completed"
    assert finished["result"]["enriched"] == 1


async def test_test_cvepaas_requires_configuration(client):
    response = await client.post("/settings/test-cvepaas")
    assert response.status_code == 400


@respx.mock
async def test_test_cvepaas_reports_unreachable_instance(client, db_session):
    await set_settings(db_session, {"cvepaas_enabled": True, "cvepaas_url": CVEPAAS_URL})
    respx.get(f"{CVEPAAS_URL}/healthz").mock(return_value=Response(503, text="down"))
    response = await client.post("/settings/test-cvepaas")
    assert response.status_code == 502


# ── Dashboard ─────────────────────────────────────────────────────────────────

@respx.mock
async def test_dashboard_reports_kev_and_priority_counts(client, db_session, seeded_component):
    await set_settings(db_session, {"cvepaas_enabled": True, "cvepaas_url": CVEPAAS_URL})
    respx.post(f"{CVEPAAS_URL}/v1/cve").mock(
        return_value=Response(200, json={"CVE-2023-44487": verdict(priority="Critical")})
    )
    from services.jobs import wait_for_job
    job = (await client.post("/vulnerabilities/enrich")).json()
    await wait_for_job(job["id"])

    # The job committed through its own session. In production the next request
    # gets a fresh session and sees the change; here the fixture shares one
    # session with the request, so its identity map has to be dropped by hand.
    db_session.expire_all()

    data = (await client.get("/dashboard")).json()
    assert data["kev_count"] == 1
    assert data["exploitable_count"] == 1
    assert data["priority_counts"]["Critical"] == 1
    assert data["top_vulnerable"][0]["kev"] == 1


async def test_dashboard_priority_counts_empty_without_enrichment(client, seeded_component):
    data = (await client.get("/dashboard")).json()
    assert data["kev_count"] == 0
    assert set(data["priority_counts"].values()) == {0}


# ── Settings ──────────────────────────────────────────────────────────────────

async def test_cvepaas_settings_round_trip(client):
    response = await client.put("/settings", json={
        "cvepaas_enabled": True,
        "cvepaas_url": CVEPAAS_URL,
        "notify_on_kev": False,
        "notify_on_priority_critical": True,
        "epss_alert_threshold": 0.25,
    })
    assert response.status_code == 200

    settings = (await client.get("/settings")).json()
    assert settings["cvepaas_enabled"] is True
    assert settings["cvepaas_url"] == CVEPAAS_URL
    assert settings["notify_on_kev"] is False
    assert settings["notify_on_priority_critical"] is True
    assert settings["epss_alert_threshold"] == 0.25


async def test_cvepaas_defaults_are_off(client):
    settings = (await client.get("/settings")).json()
    assert settings["cvepaas_enabled"] is False
    assert settings["cvepaas_url"] is None
    assert settings["epss_alert_threshold"] == 0.0


# ── evaluate_new_vulns with enrichment ────────────────────────────────────────

@respx.mock
async def test_new_cve_alert_carries_the_cvepaas_verdict(seeded_component):
    hook = respx.post("https://hooks.test/webhook").mock(return_value=Response(200))
    from services.qg import evaluate_new_vulns

    await evaluate_new_vulns(
        seeded_component,
        [{"id": "CVE-2024-9999", "severity": "critical"}],
        {"notify_on_critical": True},
        "https://hooks.test/webhook",
        {"CVE-2024-9999": {"priority": "Critical", "epss_score": 0.97,
                           "is_kev": True, "is_poc": True, "is_template": False}},
    )

    payload = json.loads(hook.calls[0].request.content)
    assert payload["priority"] == "Critical"
    assert payload["is_kev"] is True
    assert payload["epss_score"] == 0.97
    assert "in KEV" in payload["text"]


@respx.mock
async def test_medium_cve_in_kev_alerts_even_when_severity_rules_would_not(seeded_component):
    hook = respx.post("https://hooks.test/webhook").mock(return_value=Response(200))
    from services.qg import evaluate_new_vulns

    events = await evaluate_new_vulns(
        seeded_component,
        [{"id": "CVE-2024-9999", "severity": "medium"}],
        {"notify_on_critical": True, "notify_on_high": False, "notify_on_kev": True},
        "https://hooks.test/webhook",
        {"CVE-2024-9999": {"priority": "Critical", "is_kev": True}},
    )

    assert hook.call_count == 1
    assert "KEV" in events[0]["reason"]


@respx.mock
async def test_only_one_alert_when_both_rules_match(seeded_component):
    hook = respx.post("https://hooks.test/webhook").mock(return_value=Response(200))
    from services.qg import evaluate_new_vulns

    await evaluate_new_vulns(
        seeded_component,
        [{"id": "CVE-2024-9999", "severity": "critical"}],
        {"notify_on_critical": True, "notify_on_kev": True},
        "https://hooks.test/webhook",
        {"CVE-2024-9999": {"priority": "Critical", "is_kev": True}},
    )
    assert hook.call_count == 1


async def test_evaluate_new_vulns_without_enrichment_is_unchanged(seeded_component):
    """The integration must be invisible when CVE-PaaS is not configured."""
    from services.qg import evaluate_new_vulns

    events = await evaluate_new_vulns(
        seeded_component,
        [{"id": "CVE-2024-9999", "severity": "medium"}],
        {"notify_on_critical": True, "notify_on_kev": True},
        None,
    )
    assert events[0]["reason"] == "New medium CVE: CVE-2024-9999"
    assert events[0]["priority"] is None


# ── OSV advisories are keyed by GHSA, not CVE ─────────────────────────────────

@pytest.mark.parametrize("vuln_id,aliases,expected", [
    ("CVE-2021-44228", None, "CVE-2021-44228"),
    ("GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228", "CVE-2021-44228"),
    ("GHSA-jfh8-c2jp-5v3q", "GHSA-other,CVE-2021-44228", "CVE-2021-44228"),
    ("GHSA-jfh8-c2jp-5v3q", None, None),
    ("GHSA-jfh8-c2jp-5v3q", "PYSEC-2021-19", None),
])
def test_pick_cve(vuln_id, aliases, expected):
    assert cvepaas.pick_cve(vuln_id, aliases) == expected


@respx.mock
async def test_osv_advisory_is_enriched_via_its_cve_alias(db_session):
    """
    OSV keys library advisories by GHSA ID and carries the CVE in `aliases`.
    Without the alias lookup no library component could ever be prioritized.
    """
    component = Component(name="log4j-core", version="2.14.1",
                          type=ComponentTypeEnum.library, ecosystem="maven")
    db_session.add(component)
    await db_session.flush()
    vuln = Vulnerability(
        cve_id="GHSA-jfh8-c2jp-5v3q", source="osv",
        severity=SeverityLevel.critical,
        aliases="CVE-2021-44228", component=component,
    )
    db_session.add(vuln)
    await db_session.commit()

    route = respx.post(f"{CVEPAAS_URL}/v1/cve").mock(
        return_value=Response(200, json={"CVE-2021-44228": verdict()})
    )
    changes = await enrich_vulnerabilities(db_session, [vuln], CVEPAAS_URL)

    # The GHSA ID is never sent — CVE-PaaS is queried with the CVE alias.
    assert json.loads(route.calls[0].request.content) == {"cve_ids": ["CVE-2021-44228"]}
    assert vuln.priority == "Critical"
    assert vuln.is_kev is True
    # The change record keeps both: the CVE it was looked up by, and the row's
    # own ID, which is what the Quality Gate matches new findings on.
    assert changes[0]["cve_id"] == "CVE-2021-44228"
    assert changes[0]["vuln_id"] == "GHSA-jfh8-c2jp-5v3q"


async def test_advisory_without_a_cve_alias_is_skipped(db_session):
    component = Component(name="x", version="1", type=ComponentTypeEnum.library)
    db_session.add(component)
    await db_session.flush()
    vuln = Vulnerability(cve_id="GHSA-aaaa-bbbb-cccc", source="osv",
                         severity=SeverityLevel.high, aliases=None, component=component)
    db_session.add(vuln)
    await db_session.commit()

    # No respx mock: a call would raise, proving none is made.
    assert await enrich_vulnerabilities(db_session, [vuln], CVEPAAS_URL) == []
