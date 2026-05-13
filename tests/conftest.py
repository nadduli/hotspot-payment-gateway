"""Pytest fixtures: in-memory SQLite engine and an httpx async client."""

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

# Side-effect import so Base.metadata.create_all sees every table.
from src.auth import models as _auth_models  # noqa: F401
from src.database import get_db
from src.main import app
from src.models import Base

# SQLite covers the current auth surface; revisit once we use json_agg / JSONB.
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session", autouse=True)
def _override_settings_for_tests():
    """Disable secure cookies and clear the auth-settings cache before any test runs."""
    import os

    os.environ["REFRESH_COOKIE_SECURE"] = "false"

    from src.auth.config import get_auth_settings

    get_auth_settings.cache_clear()


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    """Session-scoped async engine bound to a fresh in-memory SQLite DB."""
    # StaticPool keeps a single connection so the in-memory DB persists across the pool.
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _fk_pragma_on_connect(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def client(test_engine) -> AsyncIterator[AsyncClient]:
    """Async httpx client wired to the FastAPI app with a freshly truncated DB."""
    session_factory = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # Truncate FK children first; sorted_tables is parent-first.
    async with session_factory() as setup_session:
        for table in reversed(Base.metadata.sorted_tables):
            await setup_session.execute(text(f"DELETE FROM {table.name}"))
        await setup_session.commit()

    async def _get_db_override() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db_override
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac
    app.dependency_overrides.clear()
