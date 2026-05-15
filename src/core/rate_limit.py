"""Rate limiting via slowapi.

Keyed by client IP, backed by in-memory storage by default. Set
RATE_LIMIT_STORAGE_URI to a redis:// URL in production so counters are
shared across workers and instances — in-memory storage is per-process
and silently ineffective once you run more than one worker.
"""

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from src.core.config import get_settings

# Per-route limits. These guard the auth surface, which is admin-facing —
# if this ever serves end users behind a hotspot's shared NAT, revisit the
# key function (IP keying would bucket a whole location together).
LOGIN_RATE_LIMIT = "5/minute;30/hour"
SIGNUP_RATE_LIMIT = "10/hour"
REFRESH_RATE_LIMIT = "60/minute"
OAUTH_RATE_LIMIT = "15/minute"
# Endpoints that trigger an outbound email — limit to curb inbox flooding.
EMAIL_REQUEST_RATE_LIMIT = "5/hour"


def _client_ip(request: Request) -> str:
    # request.client.host is the *proxy* IP once deployed behind a load balancer.
    # When that happens, switch to the leftmost X-Forwarded-For entry — but only
    # if the proxy chain is trusted, since clients can otherwise spoof the header.
    return get_remote_address(request)


limiter = Limiter(
    key_func=_client_ip,
    storage_uri=get_settings().rate_limit_storage_uri,
)


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """Return a 429 in the API's standard {"detail": ...} shape, with Retry-After."""
    response = JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Too many requests. Please try again later."},
    )
    # slowapi sets request.state.view_rate_limit when a decorated route trips;
    # _inject_headers adds Retry-After / X-RateLimit-* so clients can back off.
    view_limit = getattr(request.state, "view_rate_limit", None)
    if view_limit is not None:
        response = request.app.state.limiter._inject_headers(response, view_limit)
    return response
