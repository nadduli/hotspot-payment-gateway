"""Google OAuth client configured for the OIDC authorization-code flow."""

from authlib.integrations.starlette_client import OAuth

from src.auth.config import get_auth_settings

# Always register; the /google/login route returns 503 if google_client_id is unset.
settings = get_auth_settings()
oauth = OAuth()
oauth.register(
    name="google",
    client_id=settings.google_client_id,
    client_secret=settings.google_client_secret.get_secret_value(),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)
