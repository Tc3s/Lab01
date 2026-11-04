"""
Admin Management API Routes
Location: app/api/v1/admin.py

Endpoints:
- GET  /admin/users                 - List registered users (sensitive data omitted)
- GET  /admin/sessions              - View active sessions with masked token and SHA-256 hash
- POST /admin/revoke-user-sessions  - Emergency revocation of all sessions for a user
- POST /admin/users/{id}/revoke-sessions - Legacy path alias for session revocation
- GET  /admin/audit-logs            - Inspect SIEM audit log entries with filters and pagination
"""

import hashlib
import json
import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DBSession

from app.api.deps import (
    get_correlation_id,
    get_db,
    get_source_ip,
    require_role,
)
from app.core.audit import log_audit
from app.core.config import settings
from app.core.redis import get_redis_client, revoke_all_user_sessions
from app.db.models import User, UserRole

router = APIRouter(prefix="/admin", tags=["Admin"])


class RevokeUserSessionsRequest(BaseModel):
    user_id: int = Field(..., gt=0, description="Target User ID whose active sessions should be terminated")


class RevokeSessionsResponse(BaseModel):
    message: str
    user_id: int
    revoked_count: int


class ActiveSessionItem(BaseModel):
    session_id_masked: str
    session_id_hash: str
    user_id: Optional[int] = None
    username: Optional[str] = None
    role: Optional[str] = None
    mfa_verified: bool = False
    created_at: Optional[float] = None
    ttl_seconds: int


class ActiveSessionsResponse(BaseModel):
    total_active_sessions: int
    sessions: List[ActiveSessionItem]


@router.get("/users")
async def list_users(
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(require_role([UserRole.ADMIN.value])),
):
    """
    List all registered users.
    Strictly excludes password hashes and TOTP secrets from the payload.
    """
    users = db.query(User).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "mfa_enabled": u.mfa_enabled,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]


@router.get("/sessions", response_model=ActiveSessionsResponse)
async def list_active_sessions(
    request: Request,
    session: Dict[str, Any] = Depends(require_role([UserRole.ADMIN.value])),
    correlation_id: str = Depends(get_correlation_id),
    source_ip: str = Depends(get_source_ip),
):
    """
    List all active sessions currently maintained in Redis.
    Restricted to ADMIN role.
    Session IDs are cryptographically hashed and masked to prevent administrative token theft.
    Uses non-blocking asynchronous scan_iter to protect Redis performance.
    """
    client = await get_redis_client()
    session_items: List[ActiveSessionItem] = []

    # Asynchronously scan all session keys without blocking
    async for key in client.scan_iter(match="session:*", count=100):
        raw_data = await client.get(key)
        ttl = await client.ttl(key)
        if not raw_data or ttl <= 0:
            continue

        try:
            data = json.loads(raw_data)
            raw_sid = key.replace("session:", "")
            sid_hash = hashlib.sha256(raw_sid.encode("utf-8")).hexdigest()
            sid_masked = f"{raw_sid[:6]}...{raw_sid[-4:]}" if len(raw_sid) >= 10 else "***"

            session_items.append(
                ActiveSessionItem(
                    session_id_masked=sid_masked,
                    session_id_hash=sid_hash,
                    user_id=data.get("user_id"),
                    username=data.get("username"),
                    role=data.get("role"),
                    mfa_verified=bool(data.get("mfa_verified", False)),
                    created_at=data.get("created_at"),
                    ttl_seconds=ttl,
                )
            )
        except Exception:
            continue

    # Sort sessions by created_at descending (newest first)
    session_items.sort(key=lambda s: s.created_at or 0, reverse=True)

    # Log administrative audit event
    log_audit(
        actor_id=session.get("user_id"),
        role=session.get("role"),
        action="ADMIN_VIEW_SESSIONS",
        object_id=None,
        result="SUCCESS",
        source_ip=source_ip,
        correlation_id=correlation_id,
        session_id=session.get("_session_id"),
        details={"total_active_sessions": len(session_items)}
    )

    return ActiveSessionsResponse(
        total_active_sessions=len(session_items),
        sessions=session_items
    )


@router.post("/revoke-user-sessions", response_model=RevokeSessionsResponse)
async def revoke_user_sessions(
    request: Request,
    body: Optional[RevokeUserSessionsRequest] = None,
    user_id: Optional[int] = Query(None, description="Target User ID"),
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(require_role([UserRole.ADMIN.value])),
    correlation_id: str = Depends(get_correlation_id),
    source_ip: str = Depends(get_source_ip),
):
    """
    Emergency session revocation: Terminates all active sessions for a target user across all devices.
    Restricted to ADMIN role.
    Accepts target user_id in JSON body or query parameter.
    """
    target_user_id = body.user_id if body else user_id
    if not target_user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "INVALID_INPUT", "message": "user_id is required either in request body or query parameter"}
        )

    # Validate target user existence
    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "USER_NOT_FOUND", "message": f"User with ID {target_user_id} does not exist"}
        )

    # Execute atomic bulk revocation in Redis
    revoked_count = await revoke_all_user_sessions(target_user_id)

    # Audit log entry with full traceability
    log_audit(
        actor_id=session.get("user_id"),
        role=session.get("role"),
        action="ADMIN_REVOKE_USER_SESSIONS",
        object_id=str(target_user_id),
        result="SUCCESS",
        source_ip=source_ip,
        correlation_id=correlation_id,
        session_id=session.get("_session_id"),
        details={
            "target_user_id": target_user_id,
            "target_username": target_user.username,
            "revoked_count": revoked_count,
        }
    )

    return RevokeSessionsResponse(
        message=f"Successfully revoked {revoked_count} active sessions for user {target_user.username} (ID: {target_user_id})",
        user_id=target_user_id,
        revoked_count=revoked_count
    )


@router.post("/users/{user_id}/revoke-sessions", response_model=RevokeSessionsResponse)
async def admin_revoke_user_sessions_legacy(
    user_id: int,
    request: Request,
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(require_role([UserRole.ADMIN.value])),
    correlation_id: str = Depends(get_correlation_id),
    source_ip: str = Depends(get_source_ip),
):
    """Path-based alias for revoke-user-sessions (backward compatibility)."""
    return await revoke_user_sessions(
        request=request,
        body=RevokeUserSessionsRequest(user_id=user_id),
        user_id=user_id,
        db=db,
        session=session,
        correlation_id=correlation_id,
        source_ip=source_ip
    )


@router.get("/audit-logs")
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=500, description="Max number of log lines to retrieve"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    action: Optional[str] = Query(None, description="Filter by audit action"),
    result: Optional[str] = Query(None, description="Filter by result outcome (e.g. SUCCESS, DENIED, REPLAY_DETECTED)"),
    actor_id: Optional[str] = Query(None, description="Filter by actor ID"),
    correlation_id: Optional[str] = Query(None, description="Filter by correlation ID"),
    session: Dict[str, Any] = Depends(require_role([UserRole.ADMIN.value])),
):
    """
    Retrieve audit log entries from the persistent SIEM log file.
    Restricted to ADMIN role.
    Supports filtering and reverse chronological retrieval (newest first).
    """
    log_file = getattr(settings, "AUDIT_LOG_FILE", "logs/audit.log")
    if not os.path.exists(log_file):
        return []

    lines: List[Dict[str, Any]] = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    record = json.loads(line)
                    # Apply optional filters
                    if action and record.get("action") != action:
                        continue
                    if result and record.get("result") != result:
                        continue
                    if actor_id and str(record.get("actor_id")) != str(actor_id):
                        continue
                    if correlation_id and record.get("correlation_id") != correlation_id:
                        continue
                    lines.append(record)
                except Exception:
                    pass

    # Reverse so latest records come first
    lines.reverse()
    return lines[offset : offset + limit]
