"""
Unit tests for services/analyzer.py, services/osv.py, services/nvd.py

All external HTTP calls are mocked — no real network access.
"""

import pytest
import respx
from httpx import Response

from models import ComponentRequest, ComponentType, Ecosystem
from services.analyzer import analyze_component
from services.nvd import analyze_nvd
from services.osv import analyze_osv

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
OSV_URL = "https://api.osv.dev/v1/query"


# ── OSV ───────────────────────────────────────────────────────────────────────

OSV_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-1234-abcd-efgh",
            "summary": "Remote code execution",
            "details": "Details here",
            "aliases": ["CVE-2023-12345"],
            "database_specific": {"severity": "HIGH"},
        },
        {
            "id": "GHSA-9999-zzzz-0000",
            "summary": "XSS vulnerability",
            "details": "",
            "aliases": [],
            "database_specific": {"severity": "MEDIUM"},
        },
    ]
}


@pytest.mark.asyncio
@respx.mock
async def test_osv_returns_vulnerabilities():
    respx.post(OSV_URL).mock(return_value=Response(200, json=OSV_RESPONSE))

    req = ComponentRequest(
        type=ComponentType.library,
        name="spring-core",
        version="5.3.0",
        ecosystem=Ecosystem.maven,
    )
    result = await analyze_osv("pkg:maven/spring-core@5.3.0", req)

    assert len(result) == 2
    assert result[0]["id"] == "GHSA-1234-abcd-efgh"
    assert result[0]["severity"] == "high"
    assert result[0]["source"] == "osv"
    assert result[1]["severity"] == "medium"


@pytest.mark.asyncio
@respx.mock
async def test_osv_empty_response():
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))

    req = ComponentRequest(
        type=ComponentType.library, name="safelib", version="1.0.0", ecosystem=Ecosystem.npm
    )
    result = await analyze_osv("pkg:npm/safelib@1.0.0", req)
    assert result == []


@pytest.mark.asyncio
@respx.mock
async def test_osv_unknown_severity_normalized():
    respx.post(OSV_URL).mock(
        return_value=Response(
            200,
            json={
                "vulns": [
                    {"id": "GHSA-xxxx", "database_specific": {"severity": "WEIRD"}}
                ]
            },
        )
    )
    req = ComponentRequest(
        type=ComponentType.library, name="lib", version="1.0", ecosystem=Ecosystem.pypi
    )
    result = await analyze_osv("pkg:pypi/lib@1.0", req)
    assert result[0]["severity"] == "unknown"


@pytest.mark.asyncio
@respx.mock
async def test_osv_missing_database_specific_normalized():
    respx.post(OSV_URL).mock(
        return_value=Response(
            200,
            json={"vulns": [{"id": "GHSA-yyyy"}]},
        )
    )
    req = ComponentRequest(
        type=ComponentType.library, name="lib", version="1.0", ecosystem=Ecosystem.pypi
    )
    result = await analyze_osv("pkg:pypi/lib@1.0", req)
    assert result[0]["severity"] == "unknown"


# ── NVD ───────────────────────────────────────────────────────────────────────

NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-44487",
                "descriptions": [{"lang": "en", "value": "HTTP/2 Rapid Reset Attack"}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseSeverity": "HIGH"}}
                    ]
                },
            }
        },
        {
            "cve": {
                "id": "CVE-2021-12345",
                "descriptions": [{"lang": "en", "value": "Some other CVE"}],
                "metrics": {
                    "cvssMetricV2": [{"baseSeverity": "MEDIUM"}]
                },
            }
        },
    ]
}


@pytest.mark.asyncio
@respx.mock
async def test_nvd_returns_vulnerabilities():
    respx.get(NVD_CVE_URL).mock(return_value=Response(200, json=NVD_RESPONSE))

    result = await analyze_nvd("cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*", "nginx", "1.23.0")

    assert len(result) == 2
    assert result[0]["id"] == "CVE-2023-44487"
    assert result[0]["severity"] == "high"
    assert result[0]["source"] == "nvd"
    assert result[1]["severity"] == "medium"


@pytest.mark.asyncio
@respx.mock
async def test_nvd_empty_response():
    respx.get(NVD_CVE_URL).mock(return_value=Response(200, json={"vulnerabilities": []}))

    result = await analyze_nvd("cpe:2.3:a:f5:nginx:1.99.0:*", "nginx", "1.99.0")
    assert result == []


@pytest.mark.asyncio
@respx.mock
async def test_nvd_no_metrics_severity_is_unknown():
    respx.get(NVD_CVE_URL).mock(
        return_value=Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2020-99999",
                            "descriptions": [],
                            "metrics": {},
                        }
                    }
                ]
            },
        )
    )
    result = await analyze_nvd("cpe:...", "tool", "1.0")
    assert result[0]["severity"] == "unknown"


# ── analyze_component orchestration ──────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_analyze_component_library():
    respx.post(OSV_URL).mock(return_value=Response(200, json=OSV_RESPONSE))

    req = ComponentRequest(
        type=ComponentType.library,
        name="spring-core",
        version="5.3.0",
        ecosystem=Ecosystem.maven,
        identifier_override="pkg:maven/spring-core@5.3.0",
    )
    identifier, vulns = await analyze_component(req)

    assert identifier == "pkg:maven/spring-core@5.3.0"
    assert len(vulns) == 2


@pytest.mark.asyncio
@respx.mock
async def test_analyze_component_product():
    respx.get(NVD_CVE_URL).mock(return_value=Response(200, json=NVD_RESPONSE))

    req = ComponentRequest(
        type=ComponentType.product,
        name="nginx",
        version="1.23.0",
        identifier_override="cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*",
    )
    identifier, vulns = await analyze_component(req)

    assert identifier == "cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*"
    assert len(vulns) == 2
    assert all(v["source"] == "nvd" for v in vulns)
