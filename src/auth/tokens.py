"""JWT access tokens and SHA-256-hashed opaque refresh tokens."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import jwt
from jwt.exceptions import InvalidTokenError

from src.auth.config import get_auth_settings


def encode_access_token(user_id: UUID, ttl_minutes: int | None = None) -> str:
    """Sign a short-lived JWT access token for the given user."""
    settings = get_auth_settings()
    now = datetime.now(UTC)
    exp = now + timedelta(minutes=ttl_minutes or settings.access_token_ttl_minutes)
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "typ": "access",
    }
    return jwt.encode(
        payload,
        settings.secret_key.get_secret_value(),
        algorithm=settings.algorithm,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """Verify and decode a JWT access token.

    Raises:
        jwt.InvalidTokenError: bad signature, expired, or wrong token type.
    """
    settings = get_auth_settings()
    payload = jwt.decode(
        token,
        settings.secret_key.get_secret_value(),
        algorithms=[settings.algorithm],
    )
    if payload.get("typ") != "access":
        raise InvalidTokenError("Token is not an access token")
    return payload


# SHA-256, not bcrypt: the token is 512 random bits so hash speed is irrelevant,
# and we verify on every API call so it needs to be cheap.
def generate_refresh_token() -> tuple[str, str]:
    """Generate a new refresh token. Returns (raw, sha256_hex_hash)."""
    raw = secrets.token_urlsafe(64)
    return raw, hash_refresh_token(raw)


def hash_refresh_token(raw: str) -> str:
    """Return the SHA-256 hex digest of a raw refresh token."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
