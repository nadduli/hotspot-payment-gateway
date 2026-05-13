"""Auth-domain database operations: signup, login, token rotation, OAuth linking."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.config import get_auth_settings
from src.auth.exceptions import (
    EmailConflictError,
    GoogleOAuthError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
)
from src.auth.models import AuthProvider, RefreshToken, User
from src.auth.schemas import SignupRequest
from src.auth.tokens import (
    encode_access_token,
    generate_refresh_token,
    hash_refresh_token,
)
from src.auth.utils import normalize_email
from src.core.security import hash_password, verify_password


def _as_utc(dt: datetime) -> datetime:
    # SQLite returns naive datetimes for TIMESTAMP WITH TIME ZONE; Postgres returns aware.
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def _build_refresh_token(user_id: UUID) -> tuple[str, RefreshToken]:
    settings = get_auth_settings()
    raw, token_hash = generate_refresh_token()
    row = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_ttl_days),
    )
    return raw, row


async def create_user(session: AsyncSession, signup: SignupRequest) -> User:
    """Create a password user linked to a 'password' AuthProvider.

    Raises:
        EmailConflictError: the email is already registered.
    """
    user = User(
        first_name=signup.first_name,
        last_name=signup.last_name,
        email=signup.email,
        password_hash=hash_password(signup.password),
    )
    user.auth_providers.append(
        AuthProvider(
            provider="password",
            label="Password",
            is_active=True,
        )
    )
    session.add(user)
    try:
        await session.commit()
    except IntegrityError as e:
        # ix_users_email is the unique constraint; no pre-check, avoids TOCTOU
        await session.rollback()
        raise EmailConflictError("Email already registered") from e
    await session.refresh(user)
    return user


async def authenticate(
    session: AsyncSession,
    email: str,
    password: str,
) -> User:
    """Return the user matching email + password.

    Raises:
        InvalidCredentialsError: for every failure mode; the message is
            intentionally identical to prevent email enumeration.
    """
    user = await session.scalar(select(User).where(User.email == email))
    if user is None or user.password_hash is None:
        raise InvalidCredentialsError("Invalid email or password")
    if not verify_password(password, user.password_hash):
        raise InvalidCredentialsError("Invalid email or password")
    return user


async def get_user(session: AsyncSession, user_id: UUID) -> User | None:
    """Fetch a user by primary key, or None if not found."""
    return await session.get(User, user_id)


async def issue_refresh_token(
    session: AsyncSession,
    user: User,
) -> tuple[str, RefreshToken]:
    """Persist a fresh refresh token for the user.

    Returns:
        (raw_token, row). The raw value is shown to the caller exactly once.
    """
    raw, row = _build_refresh_token(user.id)
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return raw, row


async def verify_refresh_token(
    session: AsyncSession,
    raw_token: str,
) -> RefreshToken:
    """Look up and validate a refresh token by its hash.

    Raises:
        InvalidRefreshTokenError: token is missing, revoked, or expired.
    """
    token_hash = hash_refresh_token(raw_token)
    row = await session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    if row is None or row.is_revoked:
        raise InvalidRefreshTokenError("Refresh token is invalid or revoked")
    if _as_utc(row.expires_at) < datetime.now(UTC):
        raise InvalidRefreshTokenError("Refresh token has expired")
    return row


async def rotate_refresh_token(
    session: AsyncSession,
    raw_token: str,
) -> tuple[str, str, User]:
    """Revoke the supplied refresh token and issue a fresh pair.

    The revoke and the new insert commit together so a partial rotation
    cannot occur.

    Returns:
        (access_token, new_raw_refresh_token, user).

    Raises:
        InvalidRefreshTokenError: supplied token failed validation or the
            backing user no longer exists.
    """
    old = await verify_refresh_token(session, raw_token)
    user = await session.get(User, old.user_id)
    if user is None:
        raise InvalidRefreshTokenError("User no longer exists")

    new_raw, new_row = _build_refresh_token(user.id)
    old.is_revoked = True
    session.add(new_row)
    await session.commit()

    access_token = encode_access_token(user.id)
    return access_token, new_raw, user


async def revoke_refresh_token(session: AsyncSession, raw_token: str) -> None:
    """Mark a refresh token revoked. Idempotent — silent if unknown."""
    token_hash = hash_refresh_token(raw_token)
    await session.execute(
        update(RefreshToken).where(RefreshToken.token_hash == token_hash).values(is_revoked=True)
    )
    await session.commit()


async def link_or_create_google_user(
    session: AsyncSession,
    google_sub: str,
    email: str,
    first_name: str | None = None,
    last_name: str | None = None,
    profile_photo_url: str | None = None,
) -> User:
    """Resolve a Google OAuth sub to a User row, auto-linking by email.

    Lookup order:
        1. Existing AuthProvider with the given Google sub.
        2. Existing User with the matching email — attach a Google AuthProvider
           and mark the email verified.
        3. None of the above — create a new verified user.

    Raises:
        GoogleOAuthError: the orphan / race conditions in (1) and (3).
    """
    email = normalize_email(email)

    # 1. known Google sub
    google_provider = await session.scalar(
        select(AuthProvider).where(
            AuthProvider.provider == "google",
            AuthProvider.provider_user_id == google_sub,
        )
    )
    if google_provider is not None:
        user = await session.get(User, google_provider.user_id)
        if user is None:
            raise GoogleOAuthError("Account no longer exists")
        return user

    # 2. email already exists; attach Google to that account
    existing = await session.scalar(select(User).where(User.email == email))
    if existing is not None:
        session.add(
            AuthProvider(
                user_id=existing.id,
                provider="google",
                provider_user_id=google_sub,
                label="Google",
                is_active=True,
            )
        )
        existing.is_email_verified = True
        await session.commit()
        await session.refresh(existing)
        return existing

    # 3. fresh user; Google has verified the email so we trust it
    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        is_email_verified=True,
        profile_photo_url=profile_photo_url,
    )
    new_user.auth_providers.append(
        AuthProvider(
            provider="google",
            provider_user_id=google_sub,
            label="Google",
            is_active=True,
        )
    )
    session.add(new_user)
    try:
        await session.commit()
    except IntegrityError as e:
        await session.rollback()
        raise GoogleOAuthError("Account creation failed") from e
    await session.refresh(new_user)
    return new_user
