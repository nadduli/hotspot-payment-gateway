import os
import tempfile
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from dotenv import load_dotenv
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from src.audit import models as _audit_models  # noqa: F401  register on Base.metadata
from src.auth import models as _auth_models  # noqa: F401
from src.database import get_db
from src.hotspot import models as _hotspot_models  # noqa: F401
from src.main import app
from src.models import Base
from src.payment import models as _payment_models  # noqa: F401
from src.tenant import models as _tenant_models  # noqa: F401
from src.tenant.constants import DEFAULT_TENANT_ID
from src.tenant.models.tenant import Tenant, TenantStatus

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
# Disposable file path used only when USE_SQLITE; cleaned in test_engine teardown.
# `:memory:` was tempting but combining it with async_sessionmaker + StaticPool
# turned out flaky — different sessions occasionally saw different snapshots
# even on the same loop. A real file resolves it deterministically and is
# still wall-clock-fast for the suite.
_SQLITE_FD, _SQLITE_PATH = (
    tempfile.mkstemp(prefix="hotspot_tests_", suffix=".db") if USE_SQLITE else (None, None)
)
if USE_SQLITE:
    os.close(_SQLITE_FD)
    TEST_DATABASE_URL = f"sqlite+aiosqlite:///{_SQLITE_PATH}"
elif _raw_test_url:
    TEST_DATABASE_URL = _normalize_db_url(_raw_test_url)
else:
    raise RuntimeError(
        "Set DATABASE_TEST_URL (Neon branch) or PYTEST_SQLITE=1 (fast on-disk) "
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

    # Seed the default tenant via the ORM — single-tenant Phase A. Using ORM
    # rather than raw SQL keeps the UUID stored in whichever format
    # SQLAlchemy's `Uuid` type uses on each backend (hex on SQLite,
    # native UUID on Postgres); raw SQL with `str(uuid)` mismatches SQLite
    # and breaks FK enforcement.
    async with async_sessionmaker(engine, expire_on_commit=False)() as setup:
        setup.add(
            Tenant(
                id=DEFAULT_TENANT_ID,
                business_name="Default",
                slug="default",
                owner_email="admin@example.local",
                status=TenantStatus.PENDING_SETUP,
                accent_color="#2E75B6",
            )
        )
        await setup.commit()

    yield engine

    if not USE_SQLITE:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()
    if USE_SQLITE and _SQLITE_PATH:
        os.unlink(_SQLITE_PATH)


@pytest_asyncio.fixture
async def client(test_engine) -> AsyncIterator[AsyncClient]:
    """Async httpx client wired to the app, with every table cleared first."""
    session_factory = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    # The seeded default tenant survives across tests; clear everything else.
    truncatable = [t for t in Base.metadata.sorted_tables if t.name != "tenants"]
    async with session_factory() as setup:
        if USE_SQLITE:
            for table in reversed(truncatable):
                await setup.execute(text(f"DELETE FROM {table.name}"))
        elif truncatable:
            names = ", ".join(t.name for t in truncatable)
            await setup.execute(text(f"TRUNCATE {names} CASCADE"))
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
