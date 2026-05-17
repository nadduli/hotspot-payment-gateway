import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from dotenv import load_dotenv
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from src.auth import models as _auth_models  # noqa: F401
from src.database import get_db
from src.main import app
from src.models import Base

load_dotenv()


def _normalize_db_url(url: str) -> str:
    """Coerce a Neon connection string into something the test suite can use.

    - drops libpq-only query params (sslmode, channel_binding); asyncpg rejects
      them, and SSL is passed via connect_args instead
    - rewrites the pooled `-pooler` endpoint to its direct equivalent; the
      suite runs DDL (drop_all/create_all) which PgBouncer doesn't pass through
    - coerces the scheme to `postgresql+asyncpg://`
    """
    url = url.split("?", 1)[0]
    url = url.replace("-pooler.", ".", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


# Two modes:
#   PYTEST_SQLITE=1                -> in-memory SQLite (fast, for dev iteration)
#   DATABASE_TEST_URL=postgres://… -> Neon branch (slow, full confidence)
USE_SQLITE = os.environ.get("PYTEST_SQLITE") == "1"
_raw_test_url = os.environ.get("DATABASE_TEST_URL")
if USE_SQLITE:
    TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"
elif _raw_test_url:
    TEST_DATABASE_URL = _normalize_db_url(_raw_test_url)
else:
    raise RuntimeError(
        "Set DATABASE_TEST_URL (Neon branch) or PYTEST_SQLITE=1 (fast in-memory) "
        "before running the suite."
    )


@pytest.fixture(scope="session", autouse=True)
def _override_settings_for_tests():
    """Disable secure cookies and rate limiting; clear the auth-settings cache."""
    os.environ["REFRESH_COOKIE_SECURE"] = "false"

    from src.auth.config import get_auth_settings

    get_auth_settings.cache_clear()

    from src.core.rate_limit import limiter

    limiter.enabled = False


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    """Async engine for the test database.

    SQLite uses StaticPool + the foreign_keys pragma so the in-memory DB
    behaves like a real one. Postgres drops + recreates the schema once per
    run so it always matches the current models.
    """
    if USE_SQLITE:
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
    else:
        engine = create_async_engine(
            TEST_DATABASE_URL,
            connect_args={"ssl": "require"},
            pool_pre_ping=True,
            echo=False,
        )

    async with engine.begin() as conn:
        if not USE_SQLITE:
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    if not USE_SQLITE:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def client(test_engine) -> AsyncIterator[AsyncClient]:
    """Async httpx client wired to the app, with every table cleared first."""
    session_factory = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with session_factory() as setup:
        if USE_SQLITE:
            # SQLite has no TRUNCATE; delete children before parents.
            for table in reversed(Base.metadata.sorted_tables):
                await setup.execute(text(f"DELETE FROM {table.name}"))
        else:
            tables = ", ".join(t.name for t in Base.metadata.sorted_tables)
            await setup.execute(text(f"TRUNCATE {tables} CASCADE"))
        await setup.commit()

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


@pytest.fixture(autouse=True)
def captured_emails(monkeypatch):
    """Capture outbound emails instead of sending them.

    Autouse so no test hits real SMTP. Tests that need the verification or
    reset token declare this fixture to read the captured list.
    """
    sent: list[dict] = []

    async def _capture(to: str, subject: str, body: str) -> None:
        sent.append({"to": to, "subject": subject, "body": body})

    monkeypatch.setattr("src.auth.service.send_email", _capture)
    return sent
