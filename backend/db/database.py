import os

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Support DATABASE_URL env var; fall back to local SQLite for development.
# Note: the env var must use the aiosqlite driver scheme.
_raw_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///db_data/app.db")

# Normalise legacy plain-sqlite URLs that may come from docker-compose
if _raw_url.startswith("sqlite:///") and not _raw_url.startswith("sqlite+aiosqlite:///"):
    _raw_url = _raw_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)

DATABASE_URL = _raw_url

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()
