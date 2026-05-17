"""Auth API: signup, login, refresh, logout, /me, Google OAuth, email flows."""

from datetime import timedelta

from authlib.integrations.base_client.errors import OAuthError
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from src.auth import service
from src.auth.config import get_auth_settings
from src.auth.dependencies import CurrentUser
from src.auth.exceptions import (
    EmailConflictError,
    EmailNotVerifiedError,
    GoogleOAuthError,
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
    InvalidRefreshTokenError,
    InvalidVerificationTokenError,
)
from src.auth.models import User
from src.auth.oauth import oauth
from src.auth.schemas import (
    ForgotPasswordRequest,
    LoginRequest,
    LoginResponse,
    RefreshResponse,
    ResendVerificationRequest,
    ResetPasswordRequest,
    SignupRequest,
    UserResponse,
    VerifyEmailRequest,
)
from src.auth.tokens import encode_access_token
from src.core.rate_limit import (
    EMAIL_REQUEST_RATE_LIMIT,
    LOGIN_RATE_LIMIT,
    OAUTH_RATE_LIMIT,
    REFRESH_RATE_LIMIT,
    SIGNUP_RATE_LIMIT,
    limiter,
)
from src.database import DbSession

router = APIRouter()


def _set_refresh_cookie(response: Response, raw_token: str) -> None:
    settings = get_auth_settings()
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=raw_token,
        max_age=int(timedelta(days=settings.refresh_token_ttl_days).total_seconds()),
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
        domain=settings.refresh_cookie_domain,
        path="/api/v1/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    settings = get_auth_settings()
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        path="/api/v1/auth",
        domain=settings.refresh_cookie_domain,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
        httponly=True,
    )


def _read_refresh_cookie(request: Request) -> str | None:
    return request.cookies.get(get_auth_settings().refresh_cookie_name)


def _frontend_redirect(error: str | None = None) -> RedirectResponse:
    settings = get_auth_settings()
    url = settings.frontend_oauth_callback_uri
    if error:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}error={error}"
    return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)


async def _complete_login(db: DbSession, response: Response, user: User) -> LoginResponse:
    raw_refresh, _ = await service.issue_refresh_token(db, user)
    _set_refresh_cookie(response, raw_refresh)
    return LoginResponse(
        access_token=encode_access_token(user.id),
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/signup",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit(SIGNUP_RATE_LIMIT)
async def signup(
    request: Request,
    body: SignupRequest,
    db: DbSession,
    background_tasks: BackgroundTasks,
) -> UserResponse:
    """Register a new account and email a verification link.

    The account starts unverified; login is blocked until the email is confirmed.
    The verification email is sent after the response — /verify-email/request
    is the retry path if delivery fails.
    """
    try:
        user = await service.create_user(db, body)
    except EmailConflictError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    await service.request_email_verification(db, user, background_tasks)
    return UserResponse.model_validate(user)


@router.post("/login", response_model=LoginResponse)
@limiter.limit(LOGIN_RATE_LIMIT)
async def login(
    request: Request,
    body: LoginRequest,
    response: Response,
    db: DbSession,
) -> LoginResponse:
    """Authenticate with email and password. Requires a verified email."""
    try:
        user = await service.authenticate(db, body.email, body.password)
    except InvalidCredentialsError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e)) from e
    except EmailNotVerifiedError as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(e)) from e
    return await _complete_login(db, response, user)


@router.post("/refresh", response_model=RefreshResponse)
@limiter.limit(REFRESH_RATE_LIMIT)
async def refresh(request: Request, response: Response, db: DbSession) -> RefreshResponse:
    """Rotate the refresh cookie and return a new access token."""
    raw = _read_refresh_cookie(request)
    if raw is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing refresh token")
    try:
        access, new_raw, _ = await service.rotate_refresh_token(db, raw)
    except InvalidRefreshTokenError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e)) from e
    _set_refresh_cookie(response, new_raw)
    return RefreshResponse(access_token=access)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response, db: DbSession) -> None:
    """Revoke the active refresh token and clear the cookie."""
    raw = _read_refresh_cookie(request)
    if raw is not None:
        await service.revoke_refresh_token(db, raw)
    _clear_refresh_cookie(response)


@router.get("/me", response_model=UserResponse)
async def me(current_user: CurrentUser) -> UserResponse:
    """Return the authenticated user."""
    return UserResponse.model_validate(current_user)


@router.post("/verify-email", response_model=UserResponse)
@limiter.limit(OAUTH_RATE_LIMIT)
async def verify_email(
    request: Request,
    body: VerifyEmailRequest,
    db: DbSession,
) -> UserResponse:
    """Confirm an email address using the token sent at signup."""
    try:
        user = await service.verify_email(db, body.token)
    except InvalidVerificationTokenError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    return UserResponse.model_validate(user)


@router.post("/verify-email/request", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(EMAIL_REQUEST_RATE_LIMIT)
async def resend_verification(
    request: Request,
    body: ResendVerificationRequest,
    db: DbSession,
    background_tasks: BackgroundTasks,
) -> None:
    """Resend the verification link.

    Always 202 — never reveals whether the account exists or is already verified.
    """
    user = await service.get_user_by_email(db, body.email)
    if user is not None and not user.is_email_verified:
        await service.request_email_verification(db, user, background_tasks)


@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(EMAIL_REQUEST_RATE_LIMIT)
async def forgot_password(
    request: Request,
    body: ForgotPasswordRequest,
    db: DbSession,
    background_tasks: BackgroundTasks,
) -> None:
    """Email a password-reset link.

    Always 202 — never reveals whether the account exists.
    """
    await service.request_password_reset(db, body.email, background_tasks)


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(OAUTH_RATE_LIMIT)
async def reset_password(
    request: Request,
    body: ResetPasswordRequest,
    db: DbSession,
) -> None:
    """Set a new password using a reset token; revokes all existing sessions."""
    try:
        await service.reset_password(db, body.token, body.new_password)
    except InvalidPasswordResetTokenError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e


@router.get("/google/login")
@limiter.limit(OAUTH_RATE_LIMIT)
async def google_login(request: Request) -> RedirectResponse:
    """Redirect the browser to Google's OAuth consent screen."""
    settings = get_auth_settings()
    if not settings.google_client_id:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Google OAuth is not configured",
        )
    return await oauth.google.authorize_redirect(request, settings.google_redirect_uri)


@router.get("/google/callback")
@limiter.limit(OAUTH_RATE_LIMIT)
async def google_callback(request: Request, db: DbSession) -> RedirectResponse:
    """Complete Google OAuth: link or create user, set refresh cookie, redirect to frontend."""
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError:
        return _frontend_redirect(error="oauth_failed")

    userinfo = token.get("userinfo")
    if not userinfo or "sub" not in userinfo or "email" not in userinfo:
        return _frontend_redirect(error="oauth_no_userinfo")

    try:
        user = await service.link_or_create_google_user(
            db,
            google_sub=userinfo["sub"],
            email=userinfo["email"],
            first_name=userinfo.get("given_name"),
            last_name=userinfo.get("family_name"),
            profile_photo_url=userinfo.get("picture"),
        )
    except GoogleOAuthError:
        return _frontend_redirect(error="link_failed")

    raw_refresh, _ = await service.issue_refresh_token(db, user)
    response = _frontend_redirect()
    _set_refresh_cookie(response, raw_refresh)
    return response
