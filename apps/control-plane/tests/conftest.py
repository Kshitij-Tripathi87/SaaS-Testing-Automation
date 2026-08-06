"""Shared test fixtures for the Control Plane backend.

Uses synchronous TestClient for HTTP calls, with async DB setup via asyncio.run().
Patches the module-level engine + session_factory between tests for isolation.
"""

import asyncio
import os

# Configure test DB BEFORE importing app modules
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "")

import pytest
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.main import create_app
from app.db import database
from app.db.base import Base
from app.db import models  # noqa: F401 - register ORM models


@pytest.fixture(autouse=True, scope="function")
def setup_db():
    """Create fresh in-memory SQLite DB for each test."""
    new_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,  # Share one in-memory DB across connections
        echo=False,
    )
    new_factory = async_sessionmaker(
        new_engine, class_=AsyncSession, expire_on_commit=False
    )

    # Patch module-level globals (functions read these at call time via globals())
    database.engine = new_engine
    database.async_session_factory = new_factory

    # Create all tables on the new engine
    def _create_sync(sync_conn):
        Base.metadata.create_all(sync_conn)

    async def _create_async():
        async with new_engine.begin() as conn:
            await conn.run_sync(_create_sync)

    asyncio.set_event_loop(asyncio.new_event_loop())  # Fresh loop
    asyncio.run(_create_async())

    yield

    # Cleanup: drop all tables + dispose engine
    def _drop_sync(sync_conn):
        Base.metadata.drop_all(sync_conn)

    async def _drop_async():
        async with new_engine.begin() as conn:
            await conn.run_sync(_drop_sync)
        await new_engine.dispose()

    asyncio.run(_drop_async())


@pytest.fixture
def client():
    """Synchronous HTTP client for testing FastAPI endpoints."""
    app = create_app()
    # Disable lifespan so we control DB setup ourselves (avoid starlette warnings/errors)
    # Note: lifespan is normally only triggered when using TestClient as context manager
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
