"""
main.py — Aletheos API
Entry point. Run with: uvicorn main:app --reload
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import os
import asyncio
from datetime import datetime, timezone

from app.core.database import init_db
from app.ai_models.routes import router as ai_models_router
from app.customers.routes import router as customers_router
from app.billing.routes import router as billing_router
from app.shadow_it.routes import router as shadow_it_router
from app.data_deletion.routes import router as deletion_router
from app.web_removal.routes import router as web_removal_router
try:
    from app.dark_web_intelligence.routes import router as dark_web_router
    _dark_web_enabled = True
except Exception as _dwi_err:
    print(f"⚠️  Dark Web Intelligence module failed to load: {_dwi_err}")
    _dark_web_enabled = False


# ----------------------------------------------------------------
# Rate Limiter
# ----------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


# ----------------------------------------------------------------
# Startup / Shutdown
# ----------------------------------------------------------------

async def always_on_monitoring_loop():
    """
    Always-On Monitoring — runs every 24 hours.
    For each Professional/Business customer, re-runs their web removal scan
    and emails them if new data broker exposures are detected.
    """
    from app.core.database import supabase
    from app.core.email import email_sender
    from app.web_removal.brokers import run_broker_scan

    INTERVAL_HOURS = 24

    while True:
        await asyncio.sleep(INTERVAL_HOURS * 3600)
        print(f"[monitoring] Running Always-On scan — {datetime.now(timezone.utc).isoformat()}")

        try:
            # Fetch all active paid customers
            result = supabase.table("customers").select(
                "id, email, full_name, plan, monitoring_email"
            ).in_("plan", ["professional", "business"]).eq("plan_status", "active").execute()

            customers = result.data or []
            print(f"[monitoring] {len(customers)} paid customers to scan")

            for cust in customers:
                try:
                    customer_id = cust["id"]
                    email = cust.get("monitoring_email") or cust["email"]
                    name = cust.get("full_name", "")

                    # Skip if no name (can't scan without a name)
                    if not name:
                        continue

                    # Run a broker scan
                    scan_results = await run_broker_scan(name, email)
                    found_count = sum(1 for b in scan_results if b.get("found"))

                    # Load previous scan result for this customer
                    prev = supabase.table("web_removal_scans").select(
                        "id, brokers_found_count"
                    ).eq("customer_id", customer_id).order(
                        "created_at", desc=True
                    ).limit(2).execute()

                    prev_count = 0
                    if len(prev.data) > 1:
                        prev_count = prev.data[1].get("brokers_found_count", 0) or 0

                    # Save new scan
                    supabase.table("web_removal_scans").insert({
                        "customer_id": customer_id,
                        "scan_type": "always_on",
                        "subject_name": name,
                        "subject_email": email,
                        "brokers_found_count": found_count,
                        "status": "complete",
                        "results": scan_results,
                        "created_at": datetime.utcnow().isoformat(),
                    }).execute()

                    # Email only if new exposures appeared
                    if found_count > prev_count:
                        new_found = found_count - prev_count
                        summary = (
                            f"{new_found} new data broker listing(s) detected — "
                            f"{found_count} total across scanned brokers"
                        )
                        await email_sender.send_scan_complete_notification(
                            customer_email=email,
                            scan_type="Always-On Web Monitoring",
                            summary=summary,
                            risk_level="medium" if found_count < 5 else "high"
                        )
                        print(f"[monitoring] Alerted {email}: {new_found} new exposures")
                    else:
                        print(f"[monitoring] {email}: no new exposures ({found_count} total)")

                except Exception as e:
                    print(f"[monitoring] Error scanning customer {cust.get('id')}: {e}")

        except Exception as e:
            print(f"[monitoring] Loop error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Aletheos API starting up...")
    try:
        init_db()
        print("✅ Database connected")
    except Exception as e:
        print(f"⚠️  Database connection failed: {e}")
        print("   Make sure SUPABASE_URL and SUPABASE_SERVICE_KEY are set in .env")

    # Start Always-On Monitoring background task
    monitoring_task = asyncio.create_task(always_on_monitoring_loop())
    print("✅ Always-On Monitoring scheduler started (24h interval)")

    yield

    monitoring_task.cancel()
    try:
        await monitoring_task
    except asyncio.CancelledError:
        pass
    print("👋 Aletheos API shutting down")


# ----------------------------------------------------------------
# App Setup
# ----------------------------------------------------------------

app = FastAPI(
    title="Aletheos API",
    description=(
        "Privacy intelligence platform. Scan AI models for your personal data, "
        "remove records from data brokers, detect shadow SaaS, and execute "
        "GDPR-compliant data deletions — all under one API."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    servers=[
        {"url": "https://api.aletheos.tech", "description": "Production"},
    ],
)

# Rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS — locked to aletheos.tech only
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8000",
        "https://aletheos.tech",
        "https://www.aletheos.tech",
        "https://api.aletheos.tech",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the static folder (shame dashboard + assets)
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# ----------------------------------------------------------------
# Routers
# ----------------------------------------------------------------

app.include_router(ai_models_router,   prefix="/v1")
app.include_router(customers_router,   prefix="/v1")
app.include_router(billing_router,     prefix="/v1")
app.include_router(shadow_it_router,   prefix="/v1")
app.include_router(deletion_router,    prefix="/v1")
app.include_router(web_removal_router, prefix="/v1")
if _dark_web_enabled:
    app.include_router(dark_web_router, prefix="/v1")


# ----------------------------------------------------------------
# Core Endpoints
# ----------------------------------------------------------------

@app.get("/health")
@limiter.limit("60/minute")
async def health_check(request: Request):
    """Health check — used by Railway."""
    return {"status": "ok", "service": "Aletheos API", "version": "1.0.0"}


@app.get("/debug-env")
async def debug_env():
    """Temporary: show env var shape to diagnose key issues. Remove after fix."""
    import base64, json
    import httpx
    from app.core.config import settings
    from app.core.database import _clean_url
    url = _clean_url(settings.supabase_url or "")
    key = (settings.supabase_service_key or "").strip()

    # Decode JWT payload
    jwt_role = "DECODE_FAILED"
    try:
        payload_b64 = key.split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.b64decode(payload_b64))
        jwt_role = payload.get("role", "NOT_FOUND")
    except Exception as e:
        jwt_role = f"ERROR: {e}"

    # Live test call to Supabase REST API
    live_test = {}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{url}/rest/v1/customers?limit=1",
                headers={
                    "apikey": key,
                    "Authorization": f"Bearer {key}",
                }
            )
            live_test = {
                "http_status": resp.status_code,
                "response": resp.text[:300],
            }
    except Exception as e:
        live_test = {"error": str(e)}

    return {
        "supabase_url": url[:50] if url else "EMPTY",
        "service_key_length": len(key),
        "jwt_role": jwt_role,
        "live_supabase_test": live_test,
    }


@app.get("/shame")
async def shame_dashboard():
    """Public Shame Dashboard — AI vendor GDPR response tracker."""
    shame_path = os.path.join(static_dir, "shame-dashboard.html")
    if os.path.exists(shame_path):
        return FileResponse(shame_path, media_type="text/html")
    return {"error": "Shame dashboard not found"}


@app.get("/")
@limiter.limit("60/minute")
async def root(request: Request):
    return {
        "name": "Aletheos API",
        "version": "1.0.0",
        "docs": "/docs",
        "shame_board": "/shame",
        "products": [
            "AI Model Data Removal   — /v1/ai-models/",
            "Shadow IT Detection     — /v1/shadow-it/",
            "Data Deletion           — /v1/deletion/",
            "Web Data Removal        — /v1/web-removal/",
            "Dark Web Intelligence   — /v1/dark-web/",
            "Customers               — /v1/customers/",
            "Billing                 — /v1/billing/",
        ]
    }
