"""Rate-limiting behavior.

The limiter is disabled suite-wide (see conftest) so it doesn't trip on the
other tests' repeated calls. This module re-enables it locally and restores
the disabled state afterwards.
"""

from src.core.rate_limit import limiter


async def test_login_is_rate_limited(client):
    limiter.enabled = True
    try:
        statuses = []
        for _ in range(8):
            r = await client.post(
                "/api/v1/auth/login",
                json={"email": "nobody@example.com", "password": "WrongPassword1!"},
            )
            statuses.append(r.status_code)
    finally:
        limiter.enabled = False

    # Limit is 5/minute; 8 attempts from one IP must trip at least one 429.
    assert 429 in statuses
