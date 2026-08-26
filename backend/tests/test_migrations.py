"""
Tests for the Alembic schema management, including the bridge that adopts
databases created before this project had migrations.

These build real SQLite files on disk rather than using the in-memory fixture:
the whole point is what happens to a database that already exists.
"""

import sqlite3
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

import main


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "app.db"


def head_revision() -> str:
    """
    The latest revision, read from the migration scripts.

    Deliberately not a literal: hard-coding it would mean every new migration
    breaks these tests for no reason, and the assertions are about the
    *mechanism* landing a database on head, not about which revision head is.
    """
    root = Path(main.__file__).resolve().parent
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    return ScriptDirectory.from_config(config).get_current_head()


async def _migrate(db_path):
    """Run the app's startup migration against a real SQLite file."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(main._migrate)
    finally:
        await engine.dispose()


def _columns(db_path, table) -> set[str]:
    connection = sqlite3.connect(db_path)
    try:
        return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    finally:
        connection.close()


def _tables(db_path) -> set[str]:
    connection = sqlite3.connect(db_path)
    try:
        return {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        connection.close()


def _revision(db_path) -> str | None:
    connection = sqlite3.connect(db_path)
    try:
        row = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        return row[0] if row else None
    finally:
        connection.close()


# The schema a database created before Alembic would have had.
_LEGACY_SCHEMA = """
CREATE TABLE components (
  id INTEGER PRIMARY KEY, name VARCHAR NOT NULL, version VARCHAR NOT NULL,
  type VARCHAR NOT NULL, ecosystem VARCHAR, identifier VARCHAR,
  last_updated DATETIME NOT NULL, notes TEXT);
CREATE TABLE vulnerabilities (
  id INTEGER PRIMARY KEY, cve_id VARCHAR NOT NULL, source VARCHAR NOT NULL,
  severity VARCHAR NOT NULL, is_false_positive BOOLEAN NOT NULL,
  false_positive_reason TEXT, component_id INTEGER REFERENCES components(id));
CREATE TABLE settings (key VARCHAR PRIMARY KEY, value TEXT);
INSERT INTO components VALUES
  (1,'nginx','1.23.0','product',NULL,'cpe:2.3:a:f5:nginx','2025-01-01 00:00:00','keep me');
INSERT INTO vulnerabilities VALUES (1,'CVE-2023-44487','nvd','high',0,NULL,1);
"""


def _write_legacy_db(db_path):
    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(_LEGACY_SCHEMA)
        connection.commit()
    finally:
        connection.close()


# ── Fresh database ────────────────────────────────────────────────────────────

async def test_empty_database_gets_the_full_schema(db_path):
    await _migrate(db_path)

    assert _tables(db_path) >= {"components", "vulnerabilities", "evidence",
                                "settings", "jobs", "alembic_version"}
    assert _revision(db_path) == head_revision()


async def test_fresh_schema_has_every_current_column(db_path):
    await _migrate(db_path)

    vuln_columns = _columns(db_path, "vulnerabilities")
    assert {"aliases", "fixed_version", "priority", "epss_score", "is_kev",
            "is_poc", "is_template", "cvepaas_data", "priority_updated",
            "cvss_score", "first_seen"} <= vuln_columns
    assert "owner" in _columns(db_path, "components")


# ── Pre-Alembic database ──────────────────────────────────────────────────────

async def test_legacy_database_is_upgraded_in_place(db_path):
    _write_legacy_db(db_path)
    assert "alembic_version" not in _tables(db_path)

    await _migrate(db_path)

    vuln_columns = _columns(db_path, "vulnerabilities")
    assert {"aliases", "fixed_version", "priority", "is_kev", "cvepaas_data",
            "cvss_score", "first_seen"} <= vuln_columns
    assert "owner" in _columns(db_path, "components")


async def test_legacy_upgrade_preserves_data(db_path):
    """The bridge adds columns; it must never rebuild a table and lose rows."""
    _write_legacy_db(db_path)
    await _migrate(db_path)

    connection = sqlite3.connect(db_path)
    try:
        assert connection.execute(
            "SELECT name, version, notes FROM components").fetchall() == [
            ("nginx", "1.23.0", "keep me")]
        assert connection.execute(
            "SELECT cve_id, severity FROM vulnerabilities").fetchall() == [
            ("CVE-2023-44487", "high")]
    finally:
        connection.close()


async def test_legacy_database_is_stamped_not_replayed(db_path):
    """
    Stamping is what stops the baseline's CREATE TABLE from running against a
    database that already has those tables.
    """
    _write_legacy_db(db_path)
    await _migrate(db_path)
    assert _revision(db_path) == head_revision()


# ── Idempotence ───────────────────────────────────────────────────────────────

async def test_migrating_twice_is_a_no_op(db_path):
    await _migrate(db_path)
    await _migrate(db_path)
    assert _revision(db_path) == head_revision()


async def test_migrating_a_legacy_database_twice_is_a_no_op(db_path):
    _write_legacy_db(db_path)
    await _migrate(db_path)
    await _migrate(db_path)

    assert _revision(db_path) == head_revision()
    connection = sqlite3.connect(db_path)
    try:
        assert connection.execute("SELECT COUNT(*) FROM components").fetchone()[0] == 1
    finally:
        connection.close()


# ── The migration matches the models ──────────────────────────────────────────

async def test_migrated_schema_matches_the_orm_models(db_path):
    """
    Guards the failure mode this whole change exists to prevent: a column added
    to db/models.py with no matching migration. The app would then work in
    tests (which call create_all) and break in production.
    """
    from db.models import Component, Evidence, Job, Settings, Vulnerability

    await _migrate(db_path)

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        async with engine.connect() as conn:
            reflected = await conn.run_sync(
                lambda sync_conn: {
                    table: {c["name"] for c in inspect(sync_conn).get_columns(table)}
                    for table in ("components", "vulnerabilities", "evidence",
                                  "settings", "jobs")
                }
            )
    finally:
        await engine.dispose()

    for model, table in ((Component, "components"), (Vulnerability, "vulnerabilities"),
                         (Evidence, "evidence"), (Settings, "settings"), (Job, "jobs")):
        expected = {c.name for c in model.__table__.columns}
        missing = expected - reflected[table]
        assert not missing, f"{table} is missing migrated column(s): {sorted(missing)}"
