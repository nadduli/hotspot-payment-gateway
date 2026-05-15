from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    secret_key: SecretStr
    algorithm: str = "HS256"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 30

    refresh_cookie_name: str = "refresh_token"
    refresh_cookie_secure: bool = True
    refresh_cookie_samesite: str = "lax"
    refresh_cookie_domain: str | None = None

    bcrypt_rounds: int = 12

    # Leave google_client_id blank to disable /google/*.
    google_client_id: str = ""
    google_client_secret: SecretStr = SecretStr("")
    google_redirect_uri: str = "http://localhost:8000/api/v1/auth/google/callback"

    # Frontend route the OAuth callback bounces to; errors append ?error=...
    frontend_oauth_callback_uri: str = "http://localhost:3000/auth/callback"

    # Token lifetimes and the frontend routes their email links point at.
    email_verify_token_ttl_hours: int = 24
    password_reset_token_ttl_minutes: int = 30
    frontend_verify_email_url: str = "http://localhost:3000/verify-email"
    frontend_reset_password_url: str = "http://localhost:3000/reset-password"


@lru_cache
def get_auth_settings() -> AuthConfig:
    return AuthConfig()
