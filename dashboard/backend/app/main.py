"""
Main FastAPI Application Entrypoint for SecurePipeline Backend.
Mounts routers, configures CORS, and manages database lifecycle.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .crud import backfill_risk_scores
from .database import SessionLocal, init_db
from .routers import scans, findings, dashboard, analyzer
from .schemas import HealthResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite tables on startup and score any legacy findings.
    init_db()
    db = SessionLocal()
    try:
        backfill_risk_scores(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Backend API for SecurePipeline Automated CI/CD Vulnerability Detection System.",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS configuration strictly restricted to local React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(scans.router, prefix=settings.API_PREFIX)
app.include_router(findings.router, prefix=settings.API_PREFIX)
app.include_router(dashboard.router, prefix=settings.API_PREFIX)
app.include_router(analyzer.router, prefix=settings.API_PREFIX)


@app.get(f"{settings.API_PREFIX}/health", response_model=HealthResponse, tags=["Health"])
def health_check():
    """Health check endpoint confirming API service and database readiness."""
    return HealthResponse(
        status="ok",
        project="SecurePipeline",
        timestamp=datetime.now(timezone.utc).isoformat(),
        database="connected",
    )


@app.get("/", tags=["Root"])
def root():
    return {
        "message": "SecurePipeline Backend API is running.",
        "documentation": "/docs",
        "health": f"{settings.API_PREFIX}/health",
    }
