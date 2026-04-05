"""
main.py — PrivacyShield API
Entry point. Run with: uvicorn main:app --reload
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
import os

from app.core.database import init_db
from app.ai_models.routes import router as ai_models_router
from app.customers.routes import router as customers_router
from app.billing.routes import router as billing_router
from app.shadow_it.routes import router as shadow_it_router
from app.data_deletion.routes import router as deletion_router
from app.web_removal.routes import router as web_removal_router


# ----------------------------------------------------------------
# Startup / Shutdown
# ----------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 PrivacyShield API starting up...")
    try:
        init_db()
        print("✅ Database connected")
    except Exception as e:
        print(f"⚠️  Database connection failed: {e}")
        print("   Make sure SUPABASE_URL and SUPABASE_SERVICE_KEY are set in .env")
    yield
    print("👋 PrivacyShield API shutting down")


# ----------------------------------------------------------------
# App Setup
# ----------------------------------------------------------------

app = FastAPI(
    title="PrivacyShield API",
    description=(
        "The only platform that helps you exercise your GDPR rights against AI companies. "
        "Scan AI models for your personal data, submit deletion requests, and track vendor responses."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS — allow requests from your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://app.privacyshield.io",
        "https://privacyshield.io",
        "https://shame.privacyshield.io"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the static folder (shame dashboard HTML + any future assets)
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# ----------------------------------------------------------------
# Routers
# ----------------------------------------------------------------

app.include_router(ai_models_router, prefix="/v1")
app.include_router(customers_router, prefix="/v1")
app.include_router(billing_router, prefix="/v1")
app.include_router(shadow_it_router, prefix="/v1")
app.include_router(deletion_router, prefix="/v1")
app.include_router(web_removal_router, prefix="/v1")


# ----------------------------------------------------------------
# Core Endpoints
# ----------------------------------------------------------------

@app.get("/health")
async def health_check():
    """Health check — used by Railway."""
    return {"status": "ok", "service": "PrivacyShield API", "version": "1.0.0"}


@app.get("/debug/db")
async def debug_db():
    """Temporary debug endpoint — tests Supabase connection and table access."""
    from app.core.database import supabase
    results = {}
    tables = ["customers", "api_keys", "public_shame_board"]
    for table in tables:
        try:
            r = supabase.table(table).select("id").limit(1).execute()
            results[table] = f"OK ({len(r.data)} rows returned)"
        except Exception as e:
            results[table] = f"ERROR: {str(e)}"
    return {"db_status": results}


@app.get("/shame")
async def shame_dashboard():
    """
    Serve the public Shame Dashboard HTML page.
    Accessible at: https://your-api.railway.app/shame
    """
    shame_path = os.path.join(static_dir, "shame-dashboard.html")
    if os.path.exists(shame_path):
        return FileResponse(shame_path, media_type="text/html")
    return {"error": "Shame dashboard not found"}


@app.get("/")
async def root():
    return {
        "name": "PrivacyShield API",
        "version": "1.0.0",
        "docs": "/docs",
        "shame_board": "/shame",
        "products": [
            "AI Model Data Removal — /v1/ai-models/",
            "Shadow IT Detection — /v1/shadow-it/",
            "Billing — /v1/billing/",
            "Customers — /v1/customers/",
            "Data Deletion — /v1/deletion/",
            "Web Data Removal — /v1/web-removal/",
        ]
    }
