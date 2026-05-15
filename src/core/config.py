from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_name: str = "Hotspot Gateway"
    database_url: str
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
    ]
    # "memory://" for dev; a redis:// URL in production so limits are shared.
    rate_limit_storage_uri: str = "memory://"

    # SMTP — Mailtrap sandbox in development.
    smtp_host: str = "sandbox.smtp.mailtrap.io"
    smtp_port: int = 2525
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_start_tls: bool = True
    email_from: str = "noreply@hotspot-gateway.local"

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors(cls, v: str | list[str]) -> list[str]:
        # Accept "a,b,c" in env vars; pydantic-settings only does JSON otherwise.
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v


@lru_cache
def get_settings():
    return Settings()
