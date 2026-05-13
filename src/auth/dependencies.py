from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError

from src.auth.models import User
from src.auth.service import get_user
from src.auth.tokens import decode_access_token
from src.database import DbSession

_bearer_scheme = HTTPBearer(auto_error=False)
BearerCreds = Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)]


async def get_current_user(creds: BearerCreds, db: DbSession) -> User:
    """Resolve a Bearer access token into a User row.

    Raises HTTP 401 if the token is missing, malformed, expired, or refers
    to a user that no longer exists.
    """
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if creds is None or creds.scheme.lower() != "bearer":
        raise invalid

    try:
        payload = decode_access_token(creds.credentials)
    except InvalidTokenError as e:
        raise invalid from e

    try:
        user_id = UUID(payload["sub"])
    except (KeyError, ValueError) as e:
        raise invalid from e

    user = await get_user(db, user_id)
    if user is None:
        raise invalid
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
