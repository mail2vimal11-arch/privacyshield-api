"""
config.py — Loads all environment variables from .env
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Supabase
    supabase_url: str = ""
    supabase_service_key: str = ""

    # AI APIs
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    google_api_key: str = ""

    # Stripe
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""

    # SendGrid
    sendgrid_api_key: str = ""
    sendgrid_from_email: str = "noreply@aletheos.tech"

    # App
    app_env: str = "development"
    api_base_url: str = "https://api.aletheos.tech"
    app_url: str = "https://aletheos.tech"
    api_key_secret: str = "dev-secret-change-in-production"

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()


# Shortcut — use this everywhere
settings = get_settings()
