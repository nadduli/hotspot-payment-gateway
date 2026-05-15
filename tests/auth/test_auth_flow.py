SIGNUP_BODY = {
    "first_name": "Jane",
    "email": "jane@example.com",
    "password": "StrongPassword1!",
}


def _verification_token(captured_emails) -> str:
    """Pull the token out of the most recent captured email."""
    return captured_emails[-1]["body"].split("token=")[-1].strip()


async def _signup_and_verify(client, captured_emails, body=None):
    """Sign up and confirm the email. Returns the signup body used."""
    body = body or SIGNUP_BODY
    r = await client.post("/api/v1/auth/signup", json=body)
    assert r.status_code == 201
    r = await client.post(
        "/api/v1/auth/verify-email",
        json={"token": _verification_token(captured_emails)},
    )
    assert r.status_code == 200
    return body


async def _signup_verify_login(client, captured_emails, body=None):
    """Sign up, verify, and log in. Returns the login response JSON."""
    body = await _signup_and_verify(client, captured_emails, body)
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": body["email"], "password": body["password"]},
    )
    assert r.status_code == 200
    return r.json()


async def test_health_returns_ok(client):
    r = await client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


async def test_signup_returns_unverified_user(client, captured_emails):
    r = await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == SIGNUP_BODY["email"]
    assert body["first_name"] == "Jane"
    assert body["is_email_verified"] is False
    # Signup does not auto-login — no token, no cookie.
    assert "access_token" not in body
    assert "refresh_token" not in client.cookies
    # A verification email was queued.
    assert len(captured_emails) == 1
    assert captured_emails[0]["to"] == SIGNUP_BODY["email"]


async def test_signup_normalizes_email_case(client):
    r = await client.post(
        "/api/v1/auth/signup",
        json={**SIGNUP_BODY, "email": "Jane@Example.COM"},
    )
    assert r.status_code == 201
    assert r.json()["email"] == "jane@example.com"


async def test_signup_with_existing_email_returns_409(client):
    await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    r = await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    assert r.status_code == 409


async def test_signup_with_weak_password_returns_422(client):
    r = await client.post(
        "/api/v1/auth/signup",
        json={**SIGNUP_BODY, "password": "weakpass"},
    )
    assert r.status_code == 422


async def test_login_before_verification_returns_403(client):
    await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": SIGNUP_BODY["email"], "password": SIGNUP_BODY["password"]},
    )
    assert r.status_code == 403


async def test_login_after_verification_returns_token(client, captured_emails):
    body = await _signup_verify_login(client, captured_emails)
    assert "access_token" in body
    assert body["user"]["email"] == SIGNUP_BODY["email"]


async def test_login_is_case_insensitive_on_email(client, captured_emails):
    await _signup_and_verify(client, captured_emails)
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "JANE@example.com", "password": SIGNUP_BODY["password"]},
    )
    assert r.status_code == 200


async def test_login_with_wrong_password_returns_401(client):
    # Wrong password is rejected before the verification check, so an
    # unverified account still surfaces 401 here, not 403.
    await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": SIGNUP_BODY["email"], "password": "WrongPassword1!"},
    )
    assert r.status_code == 401


async def test_login_with_unknown_email_returns_401(client):
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "ghost@example.com", "password": "StrongPassword1!"},
    )
    assert r.status_code == 401


async def test_me_with_valid_token_returns_user(client, captured_emails):
    body = await _signup_verify_login(client, captured_emails)
    r = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert r.status_code == 200
    assert r.json()["email"] == SIGNUP_BODY["email"]


async def test_me_without_token_returns_401(client):
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401


async def test_me_with_invalid_token_returns_401(client):
    r = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not.a.real.jwt"},
    )
    assert r.status_code == 401


async def test_refresh_rotates_the_refresh_cookie(client, captured_emails):
    await _signup_verify_login(client, captured_emails)
    first_cookie = client.cookies.get("refresh_token")
    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 200
    assert "access_token" in r.json()
    assert client.cookies.get("refresh_token") != first_cookie


async def test_refresh_without_cookie_returns_401(client):
    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 401


async def test_logout_clears_cookie_and_blocks_refresh(client, captured_emails):
    await _signup_verify_login(client, captured_emails)
    r = await client.post("/api/v1/auth/logout")
    assert r.status_code == 204
    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 401
