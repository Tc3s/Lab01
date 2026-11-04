"""
Pydantic Schemas for Refund Management & Cardholder Data Protection
Location: app/schemas/refund.py
"""

from datetime import datetime
import re
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class RefundCreateRequest(BaseModel):
    """
    Schema for creating a refund request.
    Strictly validates cardholder information according to PCI DSS principles:
    - PAN is validated (13 to 19 digits, allowing formatting hyphens and spaces)
    - CVV is validated (3 to 4 digits) but marked exclude=True to prevent serialization
    - Sensitive string representations are overridden to prevent accidental leaks
    """
    order_id: str = Field(..., min_length=1, max_length=50, description="Unique merchant order reference")
    customer_name: str = Field(..., min_length=1, max_length=100, description="Customer full name")
    amount: float = Field(..., gt=0, description="Refund transaction amount, strictly positive")
    reason: str = Field(..., min_length=1, max_length=500, description="Business justification for refund")
    pan: str = Field(
        ...,
        min_length=13,
        max_length=23,
        description="Primary Account Number (PAN) - will be masked to last-4 before storage and logging"
    )
    cvv: Optional[str] = Field(
        None,
        exclude=True,
        description="Card Verification Value - transiently validated, never stored or logged (PCI-DSS §3.2)"
    )

    @field_validator("pan")
    @classmethod
    def validate_and_clean_pan(cls, v: str) -> str:
        cleaned = v.strip()
        # Allow only digits, hyphens, and spaces
        if not re.match(r"^[\d\s\-]+$", cleaned):
            raise ValueError("PAN contains invalid characters. Only digits, hyphens, and spaces are allowed.")
        digits = re.sub(r"\D", "", cleaned)
        if not (13 <= len(digits) <= 19):
            raise ValueError(f"PAN must contain between 13 and 19 digits (got {len(digits)} digits).")
        return cleaned

    @field_validator("cvv")
    @classmethod
    def validate_cvv(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        cleaned = v.strip()
        if not re.match(r"^\d{3,4}$", cleaned):
            raise ValueError("CVV must be exactly 3 or 4 digits.")
        return cleaned

    def get_pan_last4(self) -> str:
        """Extracts the last 4 digits of the PAN safely."""
        digits = re.sub(r"\D", "", self.pan)
        return digits[-4:]

    def __repr__(self) -> str:
        """Defense-in-depth: Mask PAN and strip CVV in string representations."""
        masked_pan = f"************{self.get_pan_last4()}"
        return (
            f"RefundCreateRequest(order_id={self.order_id!r}, "
            f"customer_name={self.customer_name!r}, "
            f"amount={self.amount}, "
            f"pan={masked_pan!r}, "
            f"cvv='[STRIPPED]')"
        )

    def __str__(self) -> str:
        return self.__repr__()


class RefundResponse(BaseModel):
    """
    Public representation of a refund request.
    Strictly omits full PAN and CVV. Only pan_last4 is exposed.
    """
    id: str
    order_id: str
    customer_name: str
    amount: float
    reason: str
    pan_last4: str
    status: str
    created_by_id: int
    approved_by_id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class RefundApproveResponse(BaseModel):
    """Response returned upon successful approval by Kế toán."""
    id: str
    status: str = "APPROVED"
    approved_by_id: int
    message: str = "Refund approved successfully"


class RefundRejectRequest(BaseModel):
    """Optional payload when Kế toán rejects a refund request."""
    reason: Optional[str] = Field(None, max_length=255, description="Reason or internal note for rejection")


class RefundRejectResponse(BaseModel):
    """Response returned upon successful rejection by Kế toán."""
    id: str
    status: str = "REJECTED"
    rejected_by_id: int
    message: str = "Refund rejected successfully"
    rejection_reason: Optional[str] = None


class RefundListResponse(BaseModel):
    """Paginated response for refund listings."""
    items: List[RefundResponse]
    total: int
