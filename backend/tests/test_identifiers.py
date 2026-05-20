"""
Unit tests for services/identifiers.py

All NVD HTTP calls are mocked via respx — no real network access.
"""

import pytest
import respx
from httpx import Response

from models import ComponentRequest, ComponentType, Ecosystem
from services.identifiers import generate_identifier


# ── PURL generation ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_purl_npm():
    req = ComponentRequest(type=ComponentType.library, name="lodash", version="4.17.21", ecosystem=Ecosystem.npm)
    assert await generate_identifier(req) == "pkg:npm/lodash@4.17.21"


@pytest.mark.asyncio
async def test_purl_pypi():
    req = ComponentRequest(type=ComponentType.library, name="requests", version="2.31.0", ecosystem=Ecosystem.pypi)
    assert await generate_identifier(req) == "pkg:pypi/requests@2.31.0"


@pytest.mark.asyncio
async def test_purl_maven():
    req = ComponentRequest(
        type=ComponentType.library,
        name="org.springframework:spring-core",
        version="6.0.15",
        ecosystem=Ecosystem.maven,
    )
    assert await generate_identifier(req) == "pkg:maven/org.springframework:spring-core@6.0.15"


@pytest.mark.asyncio
async def test_library_without_ecosystem_raises():
    req = ComponentRequest(type=ComponentType.library, name="somelib", version="1.0.0")
    with pytest.raises(ValueError, match="Ecosystem is required"):
        await generate_identifier(req)


# ── identifier_override ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_identifier_override_is_returned_as_is():
    req = ComponentRequest(
        type=ComponentType.product,
        name="nginx",
        version="1.23.0",
        identifier_override="  cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*  ",
    )
    result = await generate_identifier(req)
    # Should be stripped
    assert result == "cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*"


# ── CPE lookup via NVD ────────────────────────────────────────────────────────

NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

NVD_CPE_RESPONSE = {
    "products": [
        {
            "cpe": {
                "cpeName": "cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*"
            }
        }
    ]
}


@pytest.mark.asyncio
@respx.mock
async def test_cpe_fetched_from_nvd():
    respx.get(NVD_CPE_URL).mock(return_value=Response(200, json=NVD_CPE_RESPONSE))

    req = ComponentRequest(type=ComponentType.product, name="nginx", version="1.23.0")
    result = await generate_identifier(req)
    assert result == "cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*"


@pytest.mark.asyncio
@respx.mock
async def test_cpe_not_found_returns_empty_string():
    respx.get(NVD_CPE_URL).mock(return_value=Response(200, json={"products": []}))

    req = ComponentRequest(type=ComponentType.product, name="unknowntool", version="9.9.9")
    result = await generate_identifier(req)
    assert result == ""


@pytest.mark.asyncio
@respx.mock
async def test_cpe_nvd_error_returns_none():
    respx.get(NVD_CPE_URL).mock(return_value=Response(500))

    req = ComponentRequest(type=ComponentType.product, name="nginx", version="1.23.0")
    result = await generate_identifier(req)
    assert result == ""
