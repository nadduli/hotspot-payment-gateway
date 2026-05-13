SIGNUP_BODY = {
    "first_name": "Jane",
    "email": "jane@example.com",
    "password": "StrongPassword1!",
}


async def test_health_returns_ok(client):
    r = await client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


async def test_signup_returns_token_and_user(client):
    r = await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    assert r.status_code == 201
    body = r.json()
    assert "access_token" in body and body["access_token"]
    assert body["user"]["email"] == SIGNUP_BODY["email"]
    assert body["user"]["first_name"] == "Jane"
    assert body["user"]["last_name"] is None
    assert body["user"]["is_email_verified"] is False
    assert "refresh_token" in client.cookies


async def test_signup_normalizes_email_case(client):
    r = await client.post(
        "/api/v1/auth/signup",
        json={**SIGNUP_BODY, "email": "Jane@Example.COM"},
    )
    assert r.status_code == 201
    assert r.json()["user"]["email"] == "jane@example.com"


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


async def test_login_with_valid_credentials_returns_token(client):
    await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": SIGNUP_BODY["email"], "password": SIGNUP_BODY["password"]},
    )
    assert r.status_code == 200
    assert "access_token" in r.json()


async def test_login_is_case_insensitive_on_email(client):
    await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": "JANE@example.com", "password": SIGNUP_BODY["password"]},
    )
    assert r.status_code == 200


async def test_login_with_wrong_password_returns_401(client):
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


async def test_me_with_valid_token_returns_user(client):
    r = await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    token = r.json()["access_token"]
    r = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
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


async def test_refresh_rotates_the_refresh_cookie(client):
    await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    first_cookie = client.cookies.get("refresh_token")
    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 200
    assert "access_token" in r.json()
    assert client.cookies.get("refresh_token") != first_cookie


async def test_refresh_without_cookie_returns_401(client):
    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 401


async def test_logout_clears_cookie_and_blocks_refresh(client):
    await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    r = await client.post("/api/v1/auth/logout")
    assert r.status_code == 204
    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 401
