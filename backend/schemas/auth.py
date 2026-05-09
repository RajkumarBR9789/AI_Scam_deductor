"""
Pydantic v2 schemas for authentication request / response payloads.
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


# ==================== Request Schemas ====================

class SignUpRequest(BaseModel):
    """Payload for POST /signup."""
    firstName: str = Field(..., min_length=1, max_length=50)
    lastName: str = Field(..., min_length=1, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)


class LoginRequest(BaseModel):
    """Payload for POST /login."""
    email: EmailStr
    password: str = Field(..., min_length=1)
    remember_me: bool = False


class OTPRequest(BaseModel):
    """Payload for POST /resend-otp and POST /forgot-password."""
    email: EmailStr


class VerifyOTPRequest(BaseModel):
    """Payload for POST /verify-otp and POST /verify-reset-token."""
    email: EmailStr
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")
    remember_me: bool = False


class ResetPasswordRequest(BaseModel):
    """Payload for POST /reset-password."""
    email: EmailStr
    token: str
    new_password: str = Field(..., min_length=8)


class RefreshRequest(BaseModel):
    """Optional body for POST /refresh (alternative to cookie)."""
    refresh_token: Optional[str] = None


# ==================== Response Schemas ====================

class UserInfo(BaseModel):
    """User info embedded in token responses."""
    id: str
    email: str
    name: Optional[str] = None
    plan_type: str = "FREE"
    is_pro: bool = False


class TokenResponse(BaseModel):
    """Successful login / OTP-verify / refresh response."""
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int
    user: UserInfo


class SignUpResponse(BaseModel):
    """Response after signup or resend-otp."""
    message: str
    email: str
    requires_verification: bool = True
    email_sent: bool = False


class UserResponse(BaseModel):
    """Full user profile returned by GET /me."""
    id: uuid.UUID
    email: str
    full_name: Optional[str] = None
    is_active: bool
    is_verified: bool
    created_at: datetime
    subscription_type: str

    model_config = {"from_attributes": True}


class TokenPayload(BaseModel):
    """Decoded JWT claims."""
    sub: str
    exp: int
