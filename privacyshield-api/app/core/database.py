"""
database.py — Supabase client setup
All database operations use this client.
"""
from supabase import create_client, Client
from app.core.config import settings


def get_supabase() -> Client:
    """
    Returns a Supabase client using the service_role key.
    The service_role key bypasses Row Level Security — only use server-side.
    """
    if not settings.supabase_url or not settings.supabase_service_key:
        raise ValueError(
            "Missing SUPABASE_URL or SUPABASE_SERVICE_KEY in environment variables. "
            "Copy .env.example to .env and fill in your Supabase credentials."
        )

    client: Client = create_client(
        settings.supabase_url,
        settings.supabase_service_key
    )
    return client


# Initialize immediately so route files that do
# `from app.core.database import supabase` get the real client,
# not None. Previously supabase was set to None here and only
# initialized later in the lifespan, which was too late.
try:
    supabase: Client = get_supabase()
except Exception as e:
    print(f"⚠️  Supabase init failed at import time: {e}")
    supabase: Client = None


def init_db():
    """Call once at startup to confirm DB client is ready."""
    global supabase
    if supabase is None:
        supabase = get_supabase()
    return supabase
