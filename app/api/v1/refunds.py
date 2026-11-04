"""
Refund Management API Routes (SoD Enforcement)
Location: app/api/v1/refunds.py

Segregation of Duties (SoD):
- CSKH: Creates refund request (POST /refunds).
- KETOAN: Approves refund request (POST /refunds/{id}/approve).
- Direct call by CSKH to approve endpoint MUST yield 403 Forbidden with audit result=DENIED.
- Cardholder data protection: PAN masked to last-4, CVV stripped immediately, never persisted or logged.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from app.api.deps import (
    get_correlation_id,
    get_current_session,
    get_source_ip,
    require_role,
)
from app.core.audit import log_audit
from app.db.database import get_db
from app.db.models import RefundRequest, RefundStatus, UserRole
from app.schemas.refund import (
    RefundApproveResponse,
    RefundCreateRequest,
    RefundResponse,
)

router = APIRouter(prefix="/refunds", tags=["Refunds"])


@router.post("", response_model=RefundResponse, status_code=status.HTTP_201_CREATED)
async def create_refund(
    body: RefundCreateRequest,
    request: Request,
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(require_role([UserRole.CSKH.value, UserRole.ADMIN.value])),
    correlation_id: str = Depends(get_correlation_id),
    source_ip: str = Depends(get_source_ip),
):
    """
    Create a refund request.
    Restricted to CSKH role (and ADMIN).
    Masks PAN (stores only last 4 digits) and completely discards CVV.
    """
    actor_id = session.get("user_id")
    actor_role = session.get("role")
    session_id = session.get("_session_id")

    # Extract last-4 digits of PAN
    pan_digits = "".join(filter(str.isdigit, body.pan))
    if len(pan_digits) < 13 or len(pan_digits) > 19:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "INVALID_PAN", "message": "PAN must be between 13 and 19 digits"}
        )
    pan_last4 = pan_digits[-4:]

    # Create refund record (CVV discarded, never stored)
    refund = RefundRequest(
        order_id=body.order_id,
        customer_name=body.customer_name,
        amount=body.amount,
        reason=body.reason,
        pan_last4=pan_last4,
        status=RefundStatus.PENDING.value,
        created_by_id=actor_id,
    )
    db.add(refund)
    db.commit()
    db.refresh(refund)

    # Audit logging - details are sanitized by log_audit (PAN masked, CVV removed)
    log_audit(
        actor_id=actor_id,
        role=actor_role,
        action="REFUND_CREATE",
        object_id=str(refund.id),
        result="SUCCESS",
        source_ip=source_ip,
        correlation_id=correlation_id,
        session_id=session_id,
        details={
            "order_id": refund.order_id,
            "amount": refund.amount,
            "pan": body.pan,       # Sanitizer will mask to ************last4
            "cvv": body.cvv,       # Sanitizer will completely eliminate CVV
            "reason": refund.reason,
            "status": refund.status,
        }
    )

    return RefundResponse(
        id=refund.id,
        order_id=refund.order_id,
        customer_name=refund.customer_name,
        amount=refund.amount,
        reason=refund.reason,
        pan_last4=refund.pan_last4,
        status=refund.status,
        created_by_id=refund.created_by_id,
        approved_by_id=refund.approved_by_id,
    )


@router.post("/{refund_id}/approve", response_model=RefundApproveResponse)
async def approve_refund(
    refund_id: str,
    request: Request,
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(require_role([UserRole.KETOAN.value])),
    correlation_id: str = Depends(get_correlation_id),
    source_ip: str = Depends(get_source_ip),
):
    """
    Approve a refund request.
    Strict Segregation of Duties: ONLY KETOAN role can approve.
    CSKH calling this endpoint receives 403 Forbidden + audit result=DENIED.
    """
    actor_id = session.get("user_id")
    actor_role = session.get("role")
    session_id = session.get("_session_id")

    refund = db.query(RefundRequest).filter(RefundRequest.id == refund_id).first()
    if not refund:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "NOT_FOUND", "message": f"Refund request {refund_id} not found"}
        )

    if refund.status != RefundStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "INVALID_STATE", "message": f"Cannot approve refund in status '{refund.status}'"}
        )

    # Approve refund
    refund.status = RefundStatus.APPROVED.value
    refund.approved_by_id = actor_id
    db.commit()

    log_audit(
        actor_id=actor_id,
        role=actor_role,
        action="REFUND_APPROVE",
        object_id=str(refund.id),
        result="SUCCESS",
        source_ip=source_ip,
        correlation_id=correlation_id,
        session_id=session_id,
        details={
            "order_id": refund.order_id,
            "amount": refund.amount,
            "approved_by_id": actor_id,
            "previous_status": RefundStatus.PENDING.value,
            "new_status": RefundStatus.APPROVED.value,
        }
    )

    return RefundApproveResponse(
        id=refund.id,
        status=refund.status,
        approved_by_id=actor_id,
        message="Refund approved successfully"
    )


@router.get("", response_model=List[RefundResponse])
async def list_refunds(
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(get_current_session),
):
    """List all refunds (accessible to authenticated staff: CSKH, KETOAN, ADMIN)."""
    refunds = db.query(RefundRequest).order_by(RefundRequest.created_at.desc()).all()
    return [
        RefundResponse(
            id=r.id,
            order_id=r.order_id,
            customer_name=r.customer_name,
            amount=r.amount,
            reason=r.reason,
            pan_last4=r.pan_last4,
            status=r.status,
            created_by_id=r.created_by_id,
            approved_by_id=r.approved_by_id,
        )
        for r in refunds
    ]


@router.get("/{refund_id}", response_model=RefundResponse)
async def get_refund(
    refund_id: str,
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(get_current_session),
):
    """Get single refund by ID."""
    refund = db.query(RefundRequest).filter(RefundRequest.id == refund_id).first()
    if not refund:
        raise HTTPException(status_code=404, detail="Refund not found")
    return RefundResponse(
        id=refund.id,
        order_id=refund.order_id,
        customer_name=refund.customer_name,
        amount=refund.amount,
        reason=refund.reason,
        pan_last4=refund.pan_last4,
        status=refund.status,
        created_by_id=refund.created_by_id,
        approved_by_id=refund.approved_by_id,
    )
