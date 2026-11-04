"""
FastAPI Application Entrypoint
Location: app/main.py
"""

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import admin, auth, refunds
from app.core.config import settings
from app.core.redis import close_redis_pool, init_redis_pool
from app.db.database import SessionLocal, init_db
from app.db.seed import seed_users
from app.middleware.correlation import CorrelationIdMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("app.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager: sets up DB and Redis on startup, cleans up on shutdown."""
    logger.info("Starting up Secure E-Commerce Admin Portal...")
    # Initialize SQLite/PostgreSQL tables
    init_db()
    # Seed required users (CSKH, KETOAN, ADMIN)
    db = SessionLocal()
    try:
        seed_users(db)
        logger.info("Database initialized and default users verified.")
    finally:
        db.close()

    # Initialize Redis pool
    try:
        await init_redis_pool()
        logger.info("Connected to Redis successfully.")
    except Exception as e:
        logger.warning(f"Could not connect to Redis at startup: {e}. Ensure Redis is running.")

    yield

    logger.info("Shutting down Application...")
    await close_redis_pool()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="E-Commerce Admin Portal with hardened authentication, anti-replay TOTP, session rotation, RBAC, SoD and PCI-DSS data masking.",
    lifespan=lifespan,
)

# Correlation ID tracing middleware (must be outermost to trace all requests)
app.add_middleware(CorrelationIdMiddleware)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routers
app.include_router(auth.router, prefix=settings.API_V1_PREFIX)
app.include_router(refunds.router, prefix=settings.API_V1_PREFIX)
app.include_router(admin.router, prefix=settings.API_V1_PREFIX)


@app.get("/health", tags=["Health"])
async def health_check():
    """Service health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "environment": settings.APP_ENV,
    }
