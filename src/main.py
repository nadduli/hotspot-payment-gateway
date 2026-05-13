from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from src.auth.config import get_auth_settings
from src.auth.router import router as auth_router
from src.core.config import get_settings

app = FastAPI(title="Hotspot Payment Gateway")

# allow_credentials so the refresh cookie crosses origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Backs authlib's OAuth state param.
app.add_middleware(
    SessionMiddleware,
    secret_key=get_auth_settings().secret_key.get_secret_value(),
    same_site="lax",
    https_only=False,  # TODO: True in prod
)


@app.get("/api/v1/health")
async def health() -> dict[str, bool]:
    return {"ok": True}


app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])
