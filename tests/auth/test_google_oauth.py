import pytest


@pytest.fixture
def mock_google_userinfo(monkeypatch):
    # Patch authlib's token exchange so tests don't hit the network.
    captured: dict = {}

    async def _authorize(request):
        return {"userinfo": captured["userinfo"]}

    from src.auth import oauth as oauth_module

    monkeypatch.setattr(
        oauth_module.oauth.google,
        "authorize_access_token",
        _authorize,
    )

    def _set(
        sub: str = "google-sub-1",
        email: str = "alice@example.com",
        given_name: str | None = "Alice",
        family_name: str | None = "Doe",
        picture: str | None = "https://example.com/alice.jpg",
    ) -> None:
        captured["userinfo"] = {
            "sub": sub,
            "email": email,
            "given_name": given_name,
            "family_name": family_name,
            "picture": picture,
        }

    return _set


async def test_google_callback_creates_new_user(client, mock_google_userinfo):
    mock_google_userinfo(sub="g-new", email="newcomer@example.com", given_name="New")

    r = await client.get("/api/v1/auth/google/callback", follow_redirects=False)
    assert r.status_code == 302
    assert "refresh_token" in client.cookies

    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 200
    access = r.json()["access_token"]

    r = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "newcomer@example.com"
    assert body["first_name"] == "New"
    assert body["is_email_verified"] is True


async def test_google_callback_links_to_existing_password_account(client, mock_google_userinfo):
    r = await client.post(
        "/api/v1/auth/signup",
        json={
            "first_name": "Bob",
            "email": "bob@example.com",
            "password": "StrongPassword1!",
        },
    )
    assert r.status_code == 201
    user_id_before = r.json()["user"]["id"]
    assert r.json()["user"]["is_email_verified"] is False
    client.cookies.clear()

    mock_google_userinfo(sub="g-bob", email="bob@example.com", given_name="Bob")
    r = await client.get("/api/v1/auth/google/callback", follow_redirects=False)
    assert r.status_code == 302

    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 200
    access = r.json()["access_token"]

    r = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == user_id_before
    assert body["is_email_verified"] is True


async def test_google_callback_relogins_existing_google_user(client, mock_google_userinfo):
    mock_google_userinfo(sub="g-carol", email="carol@example.com", given_name="Carol")

    r = await client.get("/api/v1/auth/google/callback", follow_redirects=False)
    assert r.status_code == 302
    r = await client.post("/api/v1/auth/refresh")
    first_access = r.json()["access_token"]
    r = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {first_access}"},
    )
    first_user_id = r.json()["id"]

    client.cookies.clear()

    r = await client.get("/api/v1/auth/google/callback", follow_redirects=False)
    assert r.status_code == 302
    r = await client.post("/api/v1/auth/refresh")
    second_access = r.json()["access_token"]
    r = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {second_access}"},
    )
    assert r.json()["id"] == first_user_id
