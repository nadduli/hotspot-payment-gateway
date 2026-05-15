SIGNUP_BODY = {
    "first_name": "Frank",
    "email": "frank@example.com",
    "password": "StrongPassword1!",
}
NEW_PASSWORD = "BrandNewPassword9!"


def _token(captured_emails) -> str:
    return captured_emails[-1]["body"].split("token=")[-1].strip()


async def _signup_verified(client, captured_emails) -> None:
    await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    await client.post(
        "/api/v1/auth/verify-email",
        json={"token": _token(captured_emails)},
    )


async def test_forgot_password_sends_reset_email(client, captured_emails):
    await _signup_verified(client, captured_emails)
    emails_before = len(captured_emails)

    r = await client.post(
        "/api/v1/auth/forgot-password",
        json={"email": SIGNUP_BODY["email"]},
    )
    assert r.status_code == 202
    assert len(captured_emails) == emails_before + 1


async def test_forgot_password_is_silent_for_unknown_email(client, captured_emails):
    r = await client.post(
        "/api/v1/auth/forgot-password",
        json={"email": "nobody@example.com"},
    )
    assert r.status_code == 202
    assert captured_emails == []


async def test_reset_password_changes_the_password(client, captured_emails):
    await _signup_verified(client, captured_emails)
    await client.post("/api/v1/auth/forgot-password", json={"email": SIGNUP_BODY["email"]})

    r = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": _token(captured_emails),
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
        },
    )
    assert r.status_code == 204

    # Old password no longer works.
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": SIGNUP_BODY["email"], "password": SIGNUP_BODY["password"]},
    )
    assert r.status_code == 401

    # New password does.
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": SIGNUP_BODY["email"], "password": NEW_PASSWORD},
    )
    assert r.status_code == 200


async def test_reset_password_with_bad_token_returns_400(client):
    r = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": "not-a-real-token",
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
        },
    )
    assert r.status_code == 400


async def test_reset_password_token_is_single_use(client, captured_emails):
    await _signup_verified(client, captured_emails)
    await client.post("/api/v1/auth/forgot-password", json={"email": SIGNUP_BODY["email"]})
    payload = {
        "token": _token(captured_emails),
        "new_password": NEW_PASSWORD,
        "confirm_password": NEW_PASSWORD,
    }

    r = await client.post("/api/v1/auth/reset-password", json=payload)
    assert r.status_code == 204

    # Replaying the token must fail.
    r = await client.post("/api/v1/auth/reset-password", json=payload)
    assert r.status_code == 400


async def test_reset_password_revokes_existing_sessions(client, captured_emails):
    await _signup_verified(client, captured_emails)

    # Establish a refresh-cookie session.
    r = await client.post(
        "/api/v1/auth/login",
        json={"email": SIGNUP_BODY["email"], "password": SIGNUP_BODY["password"]},
    )
    assert r.status_code == 200

    await client.post("/api/v1/auth/forgot-password", json={"email": SIGNUP_BODY["email"]})
    r = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": _token(captured_emails),
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD,
        },
    )
    assert r.status_code == 204

    # The pre-reset refresh cookie is now revoked.
    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 401
