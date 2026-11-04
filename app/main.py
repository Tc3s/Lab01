"""
FastAPI Application Entrypoint
Location: app/main.py
"""

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.deps import get_source_ip
from app.api.v1 import admin, auth, refunds
from app.core.audit import log_audit, sanitize_payload
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

ALREADY_LOGGED_ERRORS = {
    "INVALID_CREDENTIALS",
    "INVALID_OTP",
    "REPLAY_DETECTED",
    "ACCESS_DENIED",
    "INVALID_PASSWORD",
    "SOD_VIOLATION",
}


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
    description="Hardened E-Commerce Admin & Refund Portal with RFC 6238 TOTP, Redis Anti-Replay, Session Hardening, RBAC & Segregation of Duties, and PCI-DSS Data Masking.",
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


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    Global handler for Starlette and FastAPI HTTP exceptions.
    Emits standardized 9-field audit records for unhandled 401/403 security errors
    while preserving the {"detail": ...} error envelope and X-Correlation-ID header.
    """
    cid = getattr(request.state, "correlation_id", "unknown")
    detail = exc.detail
    error_code = detail.get("error") if isinstance(detail, dict) else None

    # Only log audit event if endpoint has not already emitted a specific audit record
    if error_code not in ALREADY_LOGGED_ERRORS and exc.status_code in (401, 403):
        action = "UNAUTHORIZED_ACCESS" if exc.status_code == 401 else "FORBIDDEN_ACCESS"
        result = "FAILED" if exc.status_code == 401 else "DENIED"
        log_audit(
            actor_id=None,
            role="ANONYMOUS",
            action=action,
            object_id=request.url.path,
            result=result,
            source_ip=get_source_ip(request),
            correlation_id=cid,
            session_id=request.cookies.get(settings.SESSION_COOKIE_NAME),
            details={"detail": detail, "path": request.url.path, "method": request.method}
        )

    headers = dict(getattr(exc, "headers", {}) or {})
    headers["X-Correlation-ID"] = cid
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": detail},
        headers=headers
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Global handler for Pydantic schema validation failures (HTTP 422).
    Sanitizes raw input in error structures to prevent cardholder/secret leakage into audit trails.
    """
    cid = getattr(request.state, "correlation_id", "unknown")
    sanitized_errors = sanitize_payload(exc.errors())
    log_audit(
        actor_id=None,
        role="ANONYMOUS",
        action="VALIDATION_ERROR",
        object_id=request.url.path,
        result="FAILED",
        source_ip=get_source_ip(request),
        correlation_id=cid,
        session_id=request.cookies.get(settings.SESSION_COOKIE_NAME),
        details={"errors": sanitized_errors, "path": request.url.path}
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()},
        headers={"X-Correlation-ID": cid}
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Global catch-all handler for unhandled runtime exceptions (HTTP 500).
    Logs the exception and emits an audit record without leaking stack traces to the client.
    """
    cid = getattr(request.state, "correlation_id", "unknown")
    logger.exception(f"Unhandled exception occurred (correlation_id={cid}): {exc}")
    log_audit(
        actor_id=None,
        role="SYSTEM",
        action="INTERNAL_SERVER_ERROR",
        object_id=request.url.path,
        result="FAILED",
        source_ip=get_source_ip(request),
        correlation_id=cid,
        session_id=request.cookies.get(settings.SESSION_COOKIE_NAME),
        details={"error_type": exc.__class__.__name__}
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": {"error": "INTERNAL_SERVER_ERROR", "message": "An internal server error occurred."}},
        headers={"X-Correlation-ID": cid}
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
