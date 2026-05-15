SIGNUP_BODY = {
    "first_name": "Eve",
    "email": "eve@example.com",
    "password": "StrongPassword1!",
}


def _token(captured_emails) -> str:
    return captured_emails[-1]["body"].split("token=")[-1].strip()


async def test_verify_email_marks_user_verified(client, captured_emails):
    r = await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    assert r.status_code == 201
    assert r.json()["is_email_verified"] is False

    r = await client.post(
        "/api/v1/auth/verify-email",
        json={"token": _token(captured_emails)},
    )
    assert r.status_code == 200
    assert r.json()["is_email_verified"] is True


async def test_verify_email_with_bad_token_returns_400(client):
    r = await client.post("/api/v1/auth/verify-email", json={"token": "not-a-real-token"})
    assert r.status_code == 400


async def test_verify_email_token_is_single_use(client, captured_emails):
    await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    token = _token(captured_emails)

    r = await client.post("/api/v1/auth/verify-email", json={"token": token})
    assert r.status_code == 200

    # Replaying the same token must fail.
    r = await client.post("/api/v1/auth/verify-email", json={"token": token})
    assert r.status_code == 400


async def test_resend_verification_sends_a_new_email(client, captured_emails):
    await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    assert len(captured_emails) == 1

    r = await client.post(
        "/api/v1/auth/verify-email/request",
        json={"email": SIGNUP_BODY["email"]},
    )
    assert r.status_code == 202
    assert len(captured_emails) == 2


async def test_resend_verification_is_silent_for_unknown_email(client, captured_emails):
    r = await client.post(
        "/api/v1/auth/verify-email/request",
        json={"email": "nobody@example.com"},
    )
    # Identical response whether or not the account exists — no enumeration.
    assert r.status_code == 202
    assert captured_emails == []


async def test_resend_verification_noop_when_already_verified(client, captured_emails):
    await client.post("/api/v1/auth/signup", json=SIGNUP_BODY)
    await client.post(
        "/api/v1/auth/verify-email",
        json={"token": _token(captured_emails)},
    )
    emails_before = len(captured_emails)

    r = await client.post(
        "/api/v1/auth/verify-email/request",
        json={"email": SIGNUP_BODY["email"]},
    )
    assert r.status_code == 202
    assert len(captured_emails) == emails_before  # nothing re-sent
