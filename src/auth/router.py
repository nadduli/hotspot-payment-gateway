"""Auth API: signup, login, refresh, logout, /me, Google OAuth."""

from datetime import timedelta

from authlib.integrations.base_client.errors import OAuthError
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from src.auth import service
from src.auth.config import get_auth_settings
from src.auth.dependencies import CurrentUser
from src.auth.exceptions import (
    EmailConflictError,
    GoogleOAuthError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
)
from src.auth.models import User
from src.auth.oauth import oauth
from src.auth.schemas import (
    LoginRequest,
    LoginResponse,
    RefreshResponse,
    SignupRequest,
    UserResponse,
)
from src.auth.tokens import encode_access_token
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


async def _complete_login(
    db: DbSession,
    response: Response,
    user: User,
) -> LoginResponse:
    raw_refresh, _ = await service.issue_refresh_token(db, user)
    _set_refresh_cookie(response, raw_refresh)
    return LoginResponse(
        access_token=encode_access_token(user.id),
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/signup",
    response_model=LoginResponse,
    status_code=status.HTTP_201_CREATED,
)
async def signup(
    body: SignupRequest,
    response: Response,
    db: DbSession,
) -> LoginResponse:
    """Register a new password account; return access token + refresh cookie."""
    try:
        user = await service.create_user(db, body)
    except EmailConflictError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    return await _complete_login(db, response, user)


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    response: Response,
    db: DbSession,
) -> LoginResponse:
    """Authenticate with email and password."""
    try:
        user = await service.authenticate(db, body.email, body.password)
    except InvalidCredentialsError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e)) from e
    return await _complete_login(db, response, user)


@router.post("/refresh", response_model=RefreshResponse)
async def refresh(
    request: Request,
    response: Response,
    db: DbSession,
) -> RefreshResponse:
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
async def logout(
    request: Request,
    response: Response,
    db: DbSession,
) -> None:
    """Revoke the active refresh token and clear the cookie."""
    raw = _read_refresh_cookie(request)
    if raw is not None:
        await service.revoke_refresh_token(db, raw)
    _clear_refresh_cookie(response)


@router.get("/me", response_model=UserResponse)
async def me(current_user: CurrentUser) -> UserResponse:
    """Return the authenticated user."""
    return UserResponse.model_validate(current_user)


@router.get("/google/login")
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
