import structlog.contextvars
from fastapi import FastAPI
from fastapi.exception_handlers import http_exception_handler
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import Response

from src.auth.config import get_auth_settings
from src.auth.router import router as auth_router
from src.core.config import get_settings
from src.core.logging import configure_logging
from src.core.middleware import REQUEST_ID_HEADER, RequestIdMiddleware
from src.core.rate_limit import limiter, rate_limit_exceeded_handler

configure_logging()

app = FastAPI(title="Hotspot Payment Gateway")


@app.exception_handler(Exception)
async def add_request_id_to_errors(request: Request, exc: Exception) -> Response:
    response = await http_exception_handler(request, exc)
    request_id = structlog.contextvars.get_contextvars().get("request_id")
    if request_id:
        response.headers[REQUEST_ID_HEADER] = request_id
    return response


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=get_auth_settings().secret_key.get_secret_value(),
    same_site="lax",
    https_only=False,  # TODO: True in prod
)

app.add_middleware(RequestIdMiddleware)


@app.get("/api/v1/health")
async def health() -> dict[str, bool]:
    return {"ok": True}


app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])
