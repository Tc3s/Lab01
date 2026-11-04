"""
Pydantic Schemas for Refund Management
"""

from typing import Optional
from pydantic import BaseModel, Field


class RefundCreateRequest(BaseModel):
    order_id: str = Field(..., min_length=1, max_length=50)
    customer_name: str = Field(..., min_length=1, max_length=100)
    amount: float = Field(..., gt=0)
    reason: str = Field(..., min_length=1)
    pan: str = Field(..., min_length=13, max_length=19, description="Full PAN - will be masked before storage")
    cvv: Optional[str] = Field(None, description="CVV - will be stripped entirely, never stored or logged")


class RefundResponse(BaseModel):
    id: str
    order_id: str
    customer_name: str
    amount: float
    reason: str
    pan_last4: str
    status: str
    created_by_id: int
    approved_by_id: Optional[int] = None


class RefundApproveResponse(BaseModel):
    id: str
    status: str
    approved_by_id: int
    message: str = "Refund approved successfully"

