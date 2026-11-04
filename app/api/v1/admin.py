"""
Admin Management API Routes
Location: app/api/v1/admin.py
"""

import json
import os
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session as DBSession

from app.api.deps import require_role
from app.core.config import settings
from app.core.redis import revoke_all_user_sessions
from app.db.database import get_db
from app.db.models import User, UserRole

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/users")
async def list_users(
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(require_role([UserRole.ADMIN.value])),
):
    """List all registered users (passwords and secrets omitted)."""
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


@router.post("/users/{user_id}/revoke-sessions")
async def admin_revoke_user_sessions(
    user_id: int,
    session: Dict[str, Any] = Depends(require_role([UserRole.ADMIN.value])),
):
    """Admin forcefully revokes all sessions of any user."""
    count = await revoke_all_user_sessions(user_id)
    return {"message": f"Revoked {count} sessions for user {user_id}", "revoked_count": count}


@router.get("/audit-logs")
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    session: Dict[str, Any] = Depends(require_role([UserRole.ADMIN.value])),
):
    """Retrieve the most recent audit log entries."""
    log_file = getattr(settings, "AUDIT_LOG_FILE", "logs/audit.log")
    if not os.path.exists(log_file):
        return []

    lines: List[Dict[str, Any]] = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    lines.append(json.loads(line))
                except Exception:
                    pass

    return lines[-limit:]
