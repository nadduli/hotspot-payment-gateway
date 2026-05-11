from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """global settings file"""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_name: str = "Hotspot Gateway"
    database_url: str


@lru_cache
def get_settings():
    return Settings()
