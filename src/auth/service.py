"""Auth-domain database operations: signup, login, token rotation, OAuth, email flows."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import BackgroundTasks
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.config import get_auth_settings
from src.auth.exceptions import (
    EmailConflictError,
    EmailNotVerifiedError,
    GoogleOAuthError,
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
    InvalidRefreshTokenError,
    InvalidVerificationTokenError,
)
from src.auth.models import AuthProvider, RefreshToken, User, VerificationToken
from src.auth.schemas import SignupRequest
from src.auth.tokens import (
    encode_access_token,
    generate_refresh_token,
    generate_verification_token,
    hash_refresh_token,
    hash_token,
)
from src.auth.utils import normalize_email
from src.core.logging import get_logger
from src.core.security import hash_password, verify_password
from src.integrations.email import EmailDeliveryError, send_email
from src.tenant.constants import DEFAULT_TENANT_ID

log = get_logger(__name__)

PURPOSE_EMAIL_VERIFY = "email_verify"
PURPOSE_PASSWORD_RESET = "password_reset"


def _as_utc(dt: datetime) -> datetime:
    # SQLite returns naive datetimes for TIMESTAMP WITH TIME ZONE; Postgres returns aware.
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def _mask_email(value: str) -> str:
    local, sep, domain = value.partition("@")
    if not sep:
        return value
    masked_local = local[0] + "***" if local else "***"
    return f"{masked_local}@{domain}"


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

    The account starts unverified.

    Raises:
        EmailConflictError: the email is already registered.
    """
    user = User(
        tenant_id=DEFAULT_TENANT_ID,
        first_name=signup.first_name,
        last_name=signup.last_name,
        email=signup.email,
        password_hash=hash_password(signup.password),
    )
    user.auth_providers.append(AuthProvider(provider="password", label="Password", is_active=True))
    session.add(user)
    try:
        await session.commit()
    except IntegrityError as e:
        # ix_users_email is the unique constraint; no pre-check, avoids TOCTOU
        await session.rollback()
        log.info(
            "auth.signup.conflict",
            email=_mask_email(signup.email),
            detail="unique constraint violation",
        )
        raise EmailConflictError("Email already registered") from e
    await session.refresh(user)
    log.info("auth.signup", user_id=str(user.id))
    return user


async def authenticate(session: AsyncSession, email: str, password: str) -> User:
    """Return the user matching email + password.

    Raises:
        InvalidCredentialsError: every credential failure shares one message
            to prevent email enumeration.
        EmailNotVerifiedError: credentials are valid but the email is unverified.
    """
    user = await session.scalar(select(User).where(User.email == email))
    if user is None or user.password_hash is None:
        log.info("auth.login.failed", email=_mask_email(email), reason="unknown_or_oauth_only")
        raise InvalidCredentialsError("Invalid email or password")
    if not verify_password(password, user.password_hash):
        log.info(
            "auth.login.failed",
            user_id=str(user.id),
            reason="wrong_password",
        )
        raise InvalidCredentialsError("Invalid email or password")
    if not user.is_email_verified:
        log.info("auth.login.unverified", user_id=str(user.id))
        raise EmailNotVerifiedError("Email address is not verified")
    log.info("auth.login.success", user_id=str(user.id))
    return user


async def get_user(session: AsyncSession, user_id: UUID) -> User | None:
    """Fetch a user by primary key, or None if not found."""
    return await session.get(User, user_id)


async def get_user_by_email(session: AsyncSession, email: str) -> User | None:
    """Fetch a user by email (case-insensitive), or None if not found."""
    return await session.scalar(select(User).where(User.email == normalize_email(email)))


async def issue_refresh_token(session: AsyncSession, user: User) -> tuple[str, RefreshToken]:
    """Persist a fresh refresh token for the user.

    Returns:
        (raw_token, row). The raw value is shown to the caller exactly once.
    """
    raw, row = _build_refresh_token(user.id)
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return raw, row


async def verify_refresh_token(session: AsyncSession, raw_token: str) -> RefreshToken:
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


async def rotate_refresh_token(session: AsyncSession, raw_token: str) -> tuple[str, str, User]:
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
    log.info("auth.token.rotated", user_id=str(user.id))
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
        log.info("auth.google.relogin", user_id=str(user.id))
        return user

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
        log.info("auth.google.linked", user_id=str(existing.id))
        return existing

    new_user = User(
        tenant_id=DEFAULT_TENANT_ID,
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
    log.info("auth.google.signup", user_id=str(new_user.id))
    return new_user


async def _consume_token(
    session: AsyncSession,
    raw_token: str,
    purpose: str,
    error_cls: type[Exception],
) -> VerificationToken:
    """Validate a single-use token by hash. Does not mark it used — the caller does.

    Raises:
        error_cls: token is missing, already used, or expired.
    """
    token = await session.scalar(
        select(VerificationToken).where(
            VerificationToken.token_hash == hash_token(raw_token),
            VerificationToken.purpose == purpose,
        )
    )
    if token is None or token.used_at is not None:
        raise error_cls("Token is invalid or already used")
    if _as_utc(token.expires_at) < datetime.now(UTC):
        raise error_cls("Token has expired")
    return token


async def _safe_send_email(to: str, subject: str, body: str) -> None:
    """Background-task wrapper that logs delivery failures instead of crashing.

    Exceptions raised inside a BackgroundTask are eaten by the ASGI cycle, so
    we catch + log explicitly to keep failures visible in the audit log.
    """
    try:
        await send_email(to=to, subject=subject, body=body)
    except EmailDeliveryError as e:
        log.warning("email.delivery_failed", to=to, reason=str(e))
    except Exception as e:
        log.exception(
            "email.delivery_failed_unexpected",
            to=to,
            subject=subject,
            reason=str(e),
        )


async def request_email_verification(
    session: AsyncSession,
    user: User,
    background_tasks: BackgroundTasks,
) -> None:
    """Issue an email-verification token and queue the link for delivery.

    SMTP is slow; queueing the send keeps signup snappy. The token is committed
    before the response goes out, so a failed delivery is recoverable via
    /verify-email/request.
    """
    settings = get_auth_settings()
    raw, token_hash = generate_verification_token()
    session.add(
        VerificationToken(
            user_id=user.id,
            purpose=PURPOSE_EMAIL_VERIFY,
            token_hash=token_hash,
            expires_at=datetime.now(UTC) + timedelta(hours=settings.email_verify_token_ttl_hours),
        )
    )
    await session.commit()
    link = f"{settings.frontend_verify_email_url}?token={raw}"
    background_tasks.add_task(
        _safe_send_email,
        to=user.email,
        subject="Verify your email address",
        body=f"Confirm your email to activate your account:\n\n{link}",
    )
    log.info("auth.verification.requested", user_id=str(user.id))


async def verify_email(session: AsyncSession, raw_token: str) -> User:
    """Consume an email-verification token and mark the user verified.

    Raises:
        InvalidVerificationTokenError: token is missing, used, or expired.
    """
    token = await _consume_token(
        session, raw_token, PURPOSE_EMAIL_VERIFY, InvalidVerificationTokenError
    )
    user = await session.get(User, token.user_id)
    if user is None:
        raise InvalidVerificationTokenError("Account no longer exists")
    user.is_email_verified = True
    token.used_at = datetime.now(UTC)
    await session.commit()
    await session.refresh(user)
    log.info("auth.verification.completed", user_id=str(user.id))
    return user


async def request_password_reset(
    session: AsyncSession,
    email: str,
    background_tasks: BackgroundTasks,
) -> None:
    """Issue a password-reset token and queue the link for delivery.

    No-ops silently when the email matches no account, so callers can return
    an identical response either way (no account enumeration).
    """
    user = await get_user_by_email(session, email)
    if user is None:
        return
    settings = get_auth_settings()
    raw, token_hash = generate_verification_token()
    session.add(
        VerificationToken(
            user_id=user.id,
            purpose=PURPOSE_PASSWORD_RESET,
            token_hash=token_hash,
            expires_at=datetime.now(UTC)
            + timedelta(minutes=settings.password_reset_token_ttl_minutes),
        )
    )
    await session.commit()
    link = f"{settings.frontend_reset_password_url}?token={raw}"
    background_tasks.add_task(
        _safe_send_email,
        to=user.email,
        subject="Reset your password",
        body=f"Reset your password using this link:\n\n{link}",
    )
    log.info("auth.password_reset.requested", user_id=str(user.id))


async def reset_password(session: AsyncSession, raw_token: str, new_password: str) -> None:
    """Consume a password-reset token, set the new password, revoke all sessions.

    Raises:
        InvalidPasswordResetTokenError: token is missing, used, or expired.
    """
    token = await _consume_token(
        session, raw_token, PURPOSE_PASSWORD_RESET, InvalidPasswordResetTokenError
    )
    user = await session.get(User, token.user_id)
    if user is None:
        raise InvalidPasswordResetTokenError("Account no longer exists")
    user.password_hash = hash_password(new_password)
    token.used_at = datetime.now(UTC)
    # Changing the password invalidates every existing session.
    await session.execute(
        update(RefreshToken).where(RefreshToken.user_id == user.id).values(is_revoked=True)
    )
    await session.commit()
    log.info("auth.password_reset.completed", user_id=str(user.id))
