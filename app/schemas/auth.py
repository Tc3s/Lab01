"""
Pydantic Schemas for Authentication
"""

from typing import Optional
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1)


class MfaVerifyRequest(BaseModel):
    otp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


class LoginResponse(BaseModel):
    message: str
    mfa_required: bool = True
    username: Optional[str] = None


class MfaVerifyResponse(BaseModel):
    message: str
    mfa_state: str = "verified"
    user_id: Optional[int] = None
    role: Optional[str] = None


class AuthMeResponse(BaseModel):
    user_id: int
    username: str
    role: str
    mfa_state: str


class MessageResponse(BaseModel):
    message: str
    detail: Optional[dict] = None

