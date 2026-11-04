"""
FastAPI Dependencies for Session Auth, RBAC, Database, and Audit Context
Location: app/api/deps.py

Provides:
- get_current_session: Validates session cookie, enforces idle/absolute timeout
- require_role: RBAC guard factory returning 403 on unauthorized role and logging DENIED audit event
- get_correlation_id: Extracts correlation_id from request.state
- get_source_ip: Extracts client IP
- get_db: Re-exported canonical database session dependency
"""

from typing import Any, Callable, Dict, List, Optional
from fastapi import Cookie, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from app.core.audit import log_audit
from app.core.config import settings
from app.core.redis import get_session, touch_session
from app.db.database import get_db  # Re-exported canonical DB dependency


def get_correlation_id(request: Request) -> str:
    """Extract correlation_id set by CorrelationIdMiddleware."""
    return getattr(request.state, "correlation_id", "unknown")


def get_source_ip(request: Request) -> str:
    """Extract client IP, checking X-Forwarded-For for proxied requests."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def get_current_session(
    request: Request,
    session_id: Optional[str] = Cookie(None, alias="session_id")
) -> Dict[str, Any]:
    """
    Validates session from cookie:
    1. Session must exist in Redis
    2. mfa_verified must be True (post-MFA session only)
    3. Touches session to reset idle timeout (capped by absolute timeout)

    Returns session data dict on success.
    Raises 401 on missing/invalid/expired session.
    """
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "SESSION_REQUIRED", "message": "Authentication required"}
        )

    session_data = await get_session(session_id)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "SESSION_EXPIRED", "message": "Session expired or invalid"}
        )

    # Enforce post-MFA only
    if not session_data.get("mfa_verified", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "MFA_NOT_VERIFIED", "message": "MFA verification required"}
        )

    # Touch session to reset idle timeout (bounded by absolute timeout)
    touched = await touch_session(session_id, ttl=settings.SESSION_IDLE_TIMEOUT_SECONDS)
    if not touched:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "SESSION_EXPIRED", "message": "Session absolute timeout reached"}
        )

    # Inject session_id into session data for downstream use
    session_data["_session_id"] = session_id
    return session_data


def require_role(allowed_roles: List[str]) -> Callable:
    """
    RBAC dependency factory. Returns a FastAPI dependency that:
    1. Gets the current authenticated session
    2. Checks if user role is in allowed_roles
    3. Returns session data if authorized
    4. Raises 403 FORBIDDEN and logs audit event result=DENIED if role not permitted
    """
    async def _check_role(
        request: Request,
        session: Dict[str, Any] = Depends(get_current_session),
        correlation_id: str = Depends(get_correlation_id),
        source_ip: str = Depends(get_source_ip),
    ) -> Dict[str, Any]:
        user_role = session.get("role", "")
        if user_role not in allowed_roles:
            log_audit(
                actor_id=session.get("user_id"),
                role=user_role,
                action="RBAC_ACCESS_DENIED",
                object_id=request.url.path,
                result="DENIED",
                source_ip=source_ip,
                correlation_id=correlation_id,
                session_id=session.get("_session_id"),
                details={
                    "path": request.url.path,
                    "method": request.method,
                    "required_roles": allowed_roles,
                    "actual_role": user_role
                }
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "ACCESS_DENIED",
                    "message": f"Role '{user_role}' is not authorized for this action",
                    "required_roles": allowed_roles
                }
            )
        return session
    return _check_role
