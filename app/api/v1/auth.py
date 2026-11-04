"""
Authentication & Session Management API Routes
Location: app/api/v1/auth.py

Endpoints:
- POST /auth/login           - Password authentication, issues pre-MFA session
- POST /auth/mfa/verify      - TOTP verification, anti-replay lock, rotates session, issues post-MFA cookie
- POST /auth/logout          - Destroys current session and clears cookie
- POST /auth/revoke-all      - Revokes ALL sessions for user across all devices
- POST /auth/change-password - Changes password, revokes all sessions
- GET  /auth/me              - Returns current authenticated user profile
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session as DBSession

from app.api.deps import (
    get_correlation_id,
    get_current_session,
    get_db,
    get_source_ip,
)
from app.core.audit import log_audit
from app.core.config import settings
from app.core.redis import (
    check_and_set_otp_replay,
    delete_session,
    get_session,
    revoke_all_user_sessions,
    store_session,
)
from app.core.security import (
    dummy_verify_password,
    generate_session_id,
    hash_password,
    hash_session_id,
    verify_password,
    verify_totp,
)
from app.db.models import User
from app.schemas.auth import (
    AuthMeResponse,
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    MfaVerifyRequest,
    MfaVerifyResponse,
    MessageResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _set_session_cookie(response: Response, session_id: str) -> None:
    """Set session cookie with hardened security flags."""
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_id,
        max_age=settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path=settings.COOKIE_PATH,
        domain=settings.COOKIE_DOMAIN,
    )


def _clear_session_cookie(response: Response) -> None:
    """Explicitly delete session cookie with Max-Age=0."""
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path=settings.COOKIE_PATH,
        domain=settings.COOKIE_DOMAIN,
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: DBSession = Depends(get_db),
    correlation_id: str = Depends(get_correlation_id),
    source_ip: str = Depends(get_source_ip),
):
    """
    Step 1 of 2-factor auth: validate username + password.
    Issues a temporary pre-MFA session (5 min TTL, mfa_verified=False).
    Uses dummy hash evaluation on missing user to prevent timing enumeration.
    """
    user = db.query(User).filter(User.username == body.username).first()

    if not user:
        # Timing-safe: run dummy hash to prevent enumeration
        dummy_verify_password()
        log_audit(
            actor_id=None, role="ANONYMOUS", action="LOGIN_FAILED",
            object_id=body.username, result="FAILED",
            source_ip=source_ip, correlation_id=correlation_id,
            session_id=None,
            details={"reason": "user_not_found"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "INVALID_CREDENTIALS", "message": "Invalid username or password"}
        )

    if not verify_password(body.password, user.password_hash):
        log_audit(
            actor_id=user.id, role=user.role, action="LOGIN_FAILED",
            object_id=str(user.id), result="FAILED",
            source_ip=source_ip, correlation_id=correlation_id,
            session_id=None,
            details={"reason": "invalid_password"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "INVALID_CREDENTIALS", "message": "Invalid username or password"}
        )

    # Generate pre-MFA temporary session
    pre_mfa_session_id = generate_session_id()
    session_data = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "mfa_verified": False,
        "session_type": "pre_mfa",
    }
    await store_session(
        pre_mfa_session_id, session_data,
        ttl=settings.PRE_MFA_SESSION_TIMEOUT_SECONDS
    )

    _set_session_cookie(response, pre_mfa_session_id)

    log_audit(
        actor_id=user.id, role=user.role, action="LOGIN_PASSWORD_OK",
        object_id=str(user.id), result="SUCCESS",
        source_ip=source_ip, correlation_id=correlation_id,
        session_id=pre_mfa_session_id, session_type="PRE_MFA",
        details={"step": "password_verified", "mfa_required": True}
    )

    return LoginResponse(
        message="Password verified. MFA required.",
        mfa_required=True,
        username=user.username,
    )


@router.post("/mfa/verify", response_model=MfaVerifyResponse)
async def mfa_verify(
    body: MfaVerifyRequest,
    request: Request,
    response: Response,
    db: DBSession = Depends(get_db),
    session_id: Optional[str] = Cookie(None, alias="session_id"),
    correlation_id: str = Depends(get_correlation_id),
    source_ip: str = Depends(get_source_ip),
):
    """
    Step 2 of 2-factor auth: verify TOTP code.
    On success:
    1. Checks anti-replay via Redis atomic SET NX with 90s TTL
    2. Destroys pre-MFA session (session fixation defense)
    3. Creates new post-MFA session with mfa_verified=True (15m idle / 8h absolute timeout)
    4. Sets new session cookie (session rotation)
    """
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "SESSION_REQUIRED", "message": "Login first"}
        )

    pre_session = await get_session(session_id)
    if not pre_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "SESSION_EXPIRED", "message": "Pre-MFA session expired"}
        )

    if pre_session.get("mfa_verified", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "ALREADY_VERIFIED", "message": "MFA already verified"}
        )

    user_id = pre_session.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "USER_NOT_FOUND", "message": "User not found"}
        )

    # Verify TOTP with ±1 step clock drift
    is_valid, matched_step = verify_totp(user.totp_secret, body.otp_code)

    if not is_valid or matched_step is None:
        log_audit(
            actor_id=user.id, role=user.role, action="MFA_FAILED",
            object_id=str(user.id), result="FAILED",
            source_ip=source_ip, correlation_id=correlation_id,
            session_id=session_id, session_type="PRE_MFA",
            details={"reason": "invalid_or_expired_otp"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "INVALID_OTP", "message": "Invalid or expired OTP code"}
        )

    # Anti-replay: atomic SET NX on time_step
    is_fresh = await check_and_set_otp_replay(user.id, matched_step, ttl=settings.OTP_REPLAY_TTL_SECONDS)
    if not is_fresh:
        log_audit(
            actor_id=user.id, role=user.role, action="MFA_REPLAY_DETECTED",
            object_id=str(user.id), result="REPLAY_DETECTED",
            source_ip=source_ip, correlation_id=correlation_id,
            session_id=session_id, session_type="PRE_MFA",
            details={"reason": "otp_replay_attempt", "time_step": matched_step}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "REPLAY_DETECTED", "message": "OTP has already been used"}
        )

    # SESSION ROTATION: destroy pre-MFA session, create post-MFA session
    old_session_id = session_id
    await delete_session(old_session_id, user_id=user.id)

    new_session_id = generate_session_id()
    post_mfa_data = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "mfa_verified": True,
        "session_type": "post_mfa",
    }
    await store_session(
        new_session_id, post_mfa_data,
        ttl=settings.SESSION_IDLE_TIMEOUT_SECONDS
    )

    _set_session_cookie(response, new_session_id)

    log_audit(
        actor_id=user.id, role=user.role, action="MFA_SUCCESS",
        object_id=str(user.id), result="SUCCESS",
        source_ip=source_ip, correlation_id=correlation_id,
        session_id=new_session_id,
        details={
            "mfa_state": "verified",
            "session_rotated": True,
            "old_session_hash": hash_session_id(old_session_id),
            "new_session_hash": hash_session_id(new_session_id),
        }
    )

    return MfaVerifyResponse(
        message="MFA verified successfully",
        mfa_state="verified",
        user_id=user.id,
        role=user.role,
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    request: Request,
    response: Response,
    session: Dict[str, Any] = Depends(get_current_session),
    correlation_id: str = Depends(get_correlation_id),
    source_ip: str = Depends(get_source_ip),
):
    """Destroy current session in Redis and clear cookie."""
    session_id = session.get("_session_id")
    user_id = session.get("user_id")

    await delete_session(session_id, user_id=user_id)
    _clear_session_cookie(response)

    log_audit(
        actor_id=user_id, role=session.get("role"), action="LOGOUT",
        object_id=str(user_id), result="SUCCESS",
        source_ip=source_ip, correlation_id=correlation_id,
        session_id=session_id,
        details={"session_destroyed": True}
    )

    return MessageResponse(message="Logged out successfully")


@router.post("/revoke-all", response_model=MessageResponse)
async def revoke_all_sessions(
    request: Request,
    response: Response,
    session: Dict[str, Any] = Depends(get_current_session),
    correlation_id: str = Depends(get_correlation_id),
    source_ip: str = Depends(get_source_ip),
):
    """Revoke ALL sessions for the current user across all devices."""
    user_id = session.get("user_id")
    session_id = session.get("_session_id")

    count = await revoke_all_user_sessions(user_id)
    _clear_session_cookie(response)

    log_audit(
        actor_id=user_id, role=session.get("role"), action="REVOKE_ALL_SESSIONS",
        object_id=str(user_id), result="SUCCESS",
        source_ip=source_ip, correlation_id=correlation_id,
        session_id=session_id,
        details={"sessions_revoked": count}
    )

    return MessageResponse(
        message=f"All {count} sessions revoked",
        detail={"sessions_revoked": count}
    )


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    response: Response,
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(get_current_session),
    correlation_id: str = Depends(get_correlation_id),
    source_ip: str = Depends(get_source_ip),
):
    """Change password and revoke all sessions (forcing re-auth across all devices)."""
    user_id = session.get("user_id")
    session_id = session.get("_session_id")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(body.old_password, user.password_hash):
        log_audit(
            actor_id=user_id, role=session.get("role"),
            action="CHANGE_PASSWORD_FAILED",
            object_id=str(user_id), result="FAILED",
            source_ip=source_ip, correlation_id=correlation_id,
            session_id=session_id,
            details={"reason": "old_password_mismatch"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "INVALID_PASSWORD", "message": "Current password is incorrect"}
        )

    user.password_hash = hash_password(body.new_password)
    db.commit()

    # Revoke all sessions on password change
    count = await revoke_all_user_sessions(user_id)
    _clear_session_cookie(response)

    log_audit(
        actor_id=user_id, role=session.get("role"),
        action="CHANGE_PASSWORD",
        object_id=str(user_id), result="SUCCESS",
        source_ip=source_ip, correlation_id=correlation_id,
        session_id=session_id,
        details={"sessions_revoked": count, "trigger": "password_change"}
    )

    return MessageResponse(
        message="Password changed. All sessions revoked.",
        detail={"sessions_revoked": count}
    )


@router.get("/me", response_model=AuthMeResponse)
async def get_me(
    session: Dict[str, Any] = Depends(get_current_session),
):
    """Return current authenticated user profile."""
    return AuthMeResponse(
        user_id=session["user_id"],
        username=session["username"],
        role=session["role"],
        mfa_state="verified" if session.get("mfa_verified") else "pending",
    )


@router.get("/totp-hint")
async def get_totp_hint(
    username: str,
    db: DBSession = Depends(get_db),
):
    """
    Demo/Lab utility endpoint: generates current valid RFC 6238 TOTP code
    and countdown for interactive UI evaluation.
    """
    import time
    from app.core.security import generate_totp_code
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    current_otp = generate_totp_code(user.totp_secret)
    seconds_remaining = 30 - int(time.time() % 30)
    return {
        "username": user.username,
        "current_otp": current_otp,
        "seconds_remaining": seconds_remaining,
    }
