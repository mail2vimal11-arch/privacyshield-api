"""
database.py — Supabase client setup.

Uses a lazy wrapper so that if the client fails to initialise at import time
(e.g. env vars not yet loaded), it retries automatically on first use.
This fixes the 'NoneType has no attribute table' error on Railway cold starts.
"""
from supabase import create_client, Client
from app.core.config import settings


def _clean_url(url: str) -> str:
    """
    Sanitise the Supabase URL from Railway env vars.
    Handles common copy-paste mistakes:
      - missing https:// prefix
      - trailing slashes
      - accidental whitespace
    """
    url = url.strip().rstrip("/")
    if url and not url.startswith("http"):
        url = "https://" + url
    return url


def get_supabase() -> Client:
    """
    Returns a fresh Supabase client using the service_role key.
    The service_role key bypasses Row Level Security — server-side only.
    """
    if not settings.supabase_url or not settings.supabase_service_key:
        raise ValueError(
            "Missing SUPABASE_URL or SUPABASE_SERVICE_KEY. "
            "Add them to Railway → Variables."
        )
    url = _clean_url(settings.supabase_url)
    key = settings.supabase_service_key.strip()
    return create_client(url, key)


class _LazySupabaseClient:
    """
    Lazy proxy for the Supabase client.

    All route files do `from app.core.database import supabase` and then call
    supabase.table(...) / supabase.rpc(...).  This wrapper intercepts those
    calls, initialises the real client on first use, and retries if a previous
    attempt failed — so a Railway cold-start race between env-var loading and
    module imports can never permanently leave supabase as None.
    """

    def __init__(self):
        self._client: Client | None = None

    def _get_client(self) -> Client:
        if self._client is None:
            self._client = get_supabase()
        return self._client

    # ── Proxy the two methods every route file uses ──────────────────────────

    def table(self, table_name: str):
        return self._get_client().table(table_name)

    def rpc(self, fn: str, params: dict = None):
        return self._get_client().rpc(fn, params or {})

    # ── Auth helpers (used by some routes) ───────────────────────────────────

    @property
    def auth(self):
        return self._get_client().auth

    @property
    def storage(self):
        return self._get_client().storage


# Single shared instance — import this everywhere
supabase = _LazySupabaseClient()


def init_db():
    """
    Call once at startup (lifespan) to verify the DB connection.
    Non-fatal — app still starts even if Supabase is temporarily unreachable.
    """
    from app.core.logger import get_logger as _get_logger
    _db_logger = _get_logger("aletheos.db")
    try:
        client = supabase._get_client()
        _masked_url = _clean_url(settings.supabase_url)
        _masked_url = _masked_url[:8] + "****" + _masked_url[-15:] if len(_masked_url) > 23 else "****"
        _db_logger.info("Supabase client initialised → %s", _masked_url)
        return client
    except Exception as e:
        _db_logger.warning("Database connection failed: %s", type(e).__name__)
        return None
