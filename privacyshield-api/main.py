"""
main.py — PrivacyShield API
Entry point. Run with: uvicorn main:app --reload
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.database import init_db
from app.ai_models.routes import router as ai_models_router


# ----------------------------------------------------------------
# Startup / Shutdown
# ----------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # On startup: connect to database
    print("🚀 PrivacyShield API starting up...")
    try:
        init_db()
        print("✅ Database connected")
    except Exception as e:
        print(f"⚠️  Database connection failed: {e}")
        print("   Make sure SUPABASE_URL and SUPABASE_SERVICE_KEY are set in .env")

    yield

    # On shutdown
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
    docs_url="/docs",          # Swagger UI at /docs
    redoc_url="/redoc",        # ReDoc at /redoc
    lifespan=lifespan
)

# CORS — allow requests from your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://app.privacyshield.io",
        "https://privacyshield.io"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------------------------------------------
# Routers
# ----------------------------------------------------------------

# AI Model Data Removal (Product 4 — flagship)
app.include_router(ai_models_router, prefix="/v1")

# TODO: Add these in coming days:
# from app.shadow_it.routes import router as shadow_it_router
# from app.data_deletion.routes import router as deletion_router
# from app.web_removal.routes import router as web_removal_router
# app.include_router(shadow_it_router, prefix="/v1")
# app.include_router(deletion_router, prefix="/v1")
# app.include_router(web_removal_router, prefix="/v1")


# ----------------------------------------------------------------
# Core Endpoints
# ----------------------------------------------------------------

@app.get("/health")
async def health_check():
    """Health check endpoint — used by Railway to verify the app is running."""
    return {"status": "ok", "service": "PrivacyShield API", "version": "1.0.0"}


@app.get("/")
async def root():
    return {
        "name": "PrivacyShield API",
        "version": "1.0.0",
        "docs": "/docs",
        "products": [
            "AI Model Data Removal — /v1/ai-models/",
            "Shadow IT Detection — coming soon",
            "Data Deletion — coming soon",
            "Web Data Removal — coming soon"
        ]
    }
