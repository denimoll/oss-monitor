"""
Shared fixtures for the OSS-Monitor test suite.

Database strategy:
  - Each test gets a fresh in-memory SQLite database (file::memory:?cache=shared).
  - The FastAPI lifespan is bypassed so the scheduler never starts during tests.
  - All external HTTP calls (NVD / OSV) are mocked via respx.
"""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from db.database import Base
from db.models import Component, ComponentTypeEnum, SeverityLevel, Vulnerability
from main import app
from main import get_db


# ── In-memory database ────────────────────────────────────────────────────────

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def db_engine():
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    Session = sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        yield session


# ── FastAPI test client wired to the test DB ──────────────────────────────────

@pytest_asyncio.fixture
async def client(db_session):
    """AsyncClient that uses the in-memory DB and skips the lifespan scheduler."""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


# ── Pre-seeded component helper ───────────────────────────────────────────────

@pytest_asyncio.fixture
async def seeded_component(db_session) -> Component:
    """A Component row with one HIGH vulnerability already in the DB."""
    component = Component(
        name="nginx",
        version="1.23.0",
        type=ComponentTypeEnum.product,
        identifier="cpe:2.3:a:f5:nginx:1.23.0:*:*:*:*:*:*:*",
        notes=None,
        tags="prod,web",
    )
    db_session.add(component)
    await db_session.flush()

    vuln = Vulnerability(
        cve_id="CVE-2023-44487",
        source="nvd",
        severity=SeverityLevel.high,
        is_false_positive=False,
        component=component,
    )
    db_session.add(vuln)
    await db_session.commit()
    # Re-query with selectinload so .vulnerabilities is always accessible
    from sqlalchemy.future import select
    from sqlalchemy.orm import selectinload
    result = await db_session.execute(
        select(Component).options(selectinload(Component.vulnerabilities)).where(Component.id == component.id)
    )
    return result.scalar_one()
