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

from app.core.database import init_db
from app.ai_models.routes import router as ai_models_router
from app.customers.routes import router as customers_router
from app.billing.routes import router as billing_router
from app.shadow_it.routes import router as shadow_it_router
from app.data_deletion.routes import router as deletion_router
from app.web_removal.routes import router as web_removal_router


# ----------------------------------------------------------------
# Rate Limiter
# ----------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


# ----------------------------------------------------------------
# Startup / Shutdown
# ----------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Aletheos API starting up...")
    try:
        init_db()
        print("✅ Database connected")
    except Exception as e:
        print(f"⚠️  Database connection failed: {e}")
        print("   Make sure SUPABASE_URL and SUPABASE_SERVICE_KEY are set in .env")
    yield
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
    lifespan=lifespan
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
        "https://aletheos.tech",
        "https://www.aletheos.tech",
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

app.include_router(ai_models_router,  prefix="/v1")
app.include_router(customers_router,  prefix="/v1")
app.include_router(billing_router,    prefix="/v1")
app.include_router(shadow_it_router,  prefix="/v1")
app.include_router(deletion_router,   prefix="/v1")
app.include_router(web_removal_router, prefix="/v1")


# ----------------------------------------------------------------
# Core Endpoints
# ----------------------------------------------------------------

@app.get("/health")
@limiter.limit("60/minute")
async def health_check(request: Request):
    """Health check — used by Railway."""
    return {"status": "ok", "service": "Aletheos API", "version": "1.0.0"}


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
            "AI Model Data Removal  — /v1/ai-models/",
            "Shadow IT Detection    — /v1/shadow-it/",
            "Data Deletion          — /v1/deletion/",
            "Web Data Removal       — /v1/web-removal/",
            "Customers              — /v1/customers/",
            "Billing                — /v1/billing/",
        ]
    }
