"""
Refund Management API Routes (SoD & PCI-DSS Enforcement)
Location: app/api/v1/refunds.py

Segregation of Duties (SoD):
- CSKH: Creates refund request (POST /refunds). Only CSKH can create refunds.
- KETOAN: Approves (POST /refunds/{id}/approve) or rejects (POST /refunds/{id}/reject) refund requests.
- Direct call by CSKH to approve/reject endpoint MUST yield 403 Forbidden with audit result=DENIED.
- Cardholder data protection: PAN masked to last-4, CVV stripped immediately, never persisted or logged.
- Collusion defense: Creator cannot approve or reject their own refund request.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session as DBSession

from app.api.deps import (
    get_correlation_id,
    get_current_session,
    get_db,
    get_source_ip,
    require_role,
)
from app.core.audit import log_audit
from app.db.models import RefundRequest, RefundStatus, UserRole
from app.schemas.refund import (
    RefundApproveResponse,
    RefundCreateRequest,
    RefundRejectRequest,
    RefundRejectResponse,
    RefundResponse,
)

router = APIRouter(prefix="/refunds", tags=["Refunds"])


@router.post("", response_model=RefundResponse, status_code=status.HTTP_201_CREATED)
async def create_refund(
    body: RefundCreateRequest,
    request: Request,
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(require_role([UserRole.CSKH.value])),
    correlation_id: str = Depends(get_correlation_id),
    source_ip: str = Depends(get_source_ip),
):
    """
    Create a refund request.
    Strict Segregation of Duties (SoD): CSKH role ONLY.
    Accounting (KETOAN) cannot create refunds; non-CSKH callers receive 403 Forbidden.
    Data Protection:
    - PAN is extracted to last-4 digits strictly.
    - CVV is stripped immediately and never persisted to the database.
    - Audit logging records the transaction with recursive PCI-DSS data masking.
    """
    actor_id = session.get("user_id")
    actor_role = session.get("role")
    session_id = session.get("_session_id")

    pan_last4 = body.get_pan_last4()

    # Create refund record (CVV discarded, never stored in DB)
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

    # Audit logging - details are sanitized by log_audit (PAN masked, CVV eliminated)
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
        created_at=refund.created_at,
        updated_at=refund.updated_at,
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
    Strict Segregation of Duties (SoD): ONLY KETOAN role can approve.
    CSKH calling this endpoint receives 403 Forbidden + audit result=DENIED.
    Creator self-approval defense: If creator attempts to approve their own refund, returns 403.
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

    # Segregation of Duties: Creator cannot approve their own refund
    if refund.created_by_id == actor_id:
        log_audit(
            actor_id=actor_id,
            role=actor_role,
            action="REFUND_APPROVE_SELF_COLLUSION",
            object_id=str(refund.id),
            result="DENIED",
            source_ip=source_ip,
            correlation_id=correlation_id,
            session_id=session_id,
            details={"error": "Creator cannot approve own refund request"}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "SOD_VIOLATION", "message": "Creator cannot approve their own refund"}
        )

    if refund.status != RefundStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "INVALID_STATE", "message": f"Cannot approve refund in status '{refund.status}'"}
        )

    # State transition: PENDING -> APPROVED
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


@router.post("/{refund_id}/reject", response_model=RefundRejectResponse)
async def reject_refund(
    refund_id: str,
    request: Request,
    body: Optional[RefundRejectRequest] = None,
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(require_role([UserRole.KETOAN.value])),
    correlation_id: str = Depends(get_correlation_id),
    source_ip: str = Depends(get_source_ip),
):
    """
    Reject a refund request.
    Strict Segregation of Duties: ONLY KETOAN role can reject.
    CSKH calling this endpoint receives 403 Forbidden + audit result=DENIED.
    Creator self-rejection defense: If creator attempts to reject their own refund, returns 403.
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

    # Segregation of Duties: Creator cannot reject their own refund
    if refund.created_by_id == actor_id:
        log_audit(
            actor_id=actor_id,
            role=actor_role,
            action="REFUND_REJECT_SELF_COLLUSION",
            object_id=str(refund.id),
            result="DENIED",
            source_ip=source_ip,
            correlation_id=correlation_id,
            session_id=session_id,
            details={"error": "Creator cannot reject own refund request"}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "SOD_VIOLATION", "message": "Creator cannot reject their own refund request"}
        )

    if refund.status != RefundStatus.PENDING.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "INVALID_STATE", "message": f"Cannot reject refund in status '{refund.status}'"}
        )

    rejection_reason = body.reason if body else None

    # State transition: PENDING -> REJECTED
    refund.status = RefundStatus.REJECTED.value
    refund.approved_by_id = actor_id  # Records the reviewer who processed rejection
    db.commit()

    log_audit(
        actor_id=actor_id,
        role=actor_role,
        action="REFUND_REJECT",
        object_id=str(refund.id),
        result="SUCCESS",
        source_ip=source_ip,
        correlation_id=correlation_id,
        session_id=session_id,
        details={
            "order_id": refund.order_id,
            "amount": refund.amount,
            "rejected_by_id": actor_id,
            "rejection_reason": rejection_reason,
            "previous_status": RefundStatus.PENDING.value,
            "new_status": RefundStatus.REJECTED.value,
        }
    )

    return RefundRejectResponse(
        id=refund.id,
        status=refund.status,
        rejected_by_id=actor_id,
        message="Refund rejected successfully",
        rejection_reason=rejection_reason,
    )


@router.get("", response_model=List[RefundResponse])
async def list_refunds(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: PENDING, APPROVED, REJECTED"),
    limit: int = Query(50, ge=1, le=200, description="Max items to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(get_current_session),
):
    """
    List all refunds.
    Accessible to authenticated staff (CSKH, KETOAN, ADMIN).
    Supports status filtering and pagination.
    """
    query = db.query(RefundRequest)
    if status_filter:
        query = query.filter(RefundRequest.status == status_filter.upper())

    refunds = query.order_by(RefundRequest.created_at.desc()).offset(offset).limit(limit).all()

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
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in refunds
    ]


@router.get("/{refund_id}", response_model=RefundResponse)
async def get_refund(
    refund_id: str,
    db: DBSession = Depends(get_db),
    session: Dict[str, Any] = Depends(get_current_session),
):
    """
    Get single refund by ID.
    Accessible to authenticated staff (CSKH, KETOAN, ADMIN).
    """
    refund = db.query(RefundRequest).filter(RefundRequest.id == refund_id).first()
    if not refund:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "NOT_FOUND", "message": f"Refund request {refund_id} not found"}
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
        created_at=refund.created_at,
        updated_at=refund.updated_at,
    )
