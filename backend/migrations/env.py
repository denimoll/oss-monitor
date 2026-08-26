"""
Alembic environment.

Runs in two modes:

* **offline** (`alembic upgrade --sql`) — emits SQL without a connection.
* **online** — normally driven from the app's startup with an existing
  connection passed in `config.attributes["connection"]`, so migrations share
  the async engine instead of opening a second one against the same SQLite file.

The URL is never stored in alembic.ini: it comes from db.database, which honours
DATABASE_URL.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from db.database import DATABASE_URL, Base
import db.models  # noqa: F401 — registers the tables on Base.metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _sync_url() -> str:
    """Alembic drives a synchronous connection; drop the async driver."""
    return DATABASE_URL.replace("+aiosqlite", "")


def run_migrations_offline() -> None:
    context.configure(
        url=_sync_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # SQLite cannot ALTER most things in place; batch mode rewrites the
        # table instead, which is what makes future column drops/type changes
        # possible at all.
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        # Driven from the application startup — reuse its connection.
        _do_run_migrations(connection)
        return

    # Standalone `alembic upgrade head` from the CLI.
    connectable = engine_from_config(
        {"sqlalchemy.url": _sync_url()},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as conn:
        _do_run_migrations(conn)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
