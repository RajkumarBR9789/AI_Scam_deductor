"""
FastAPI router for authentication endpoints.
Prefix: /api/v1/auth
"""

from typing import Optional

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.user import User
from schemas.auth import (
    LoginRequest,
    OTPRequest,
    RefreshRequest,
    ResetPasswordRequest,
    SignUpRequest,
    SignUpResponse,
    TokenResponse,
    UserResponse,
    VerifyOTPRequest,
)
from services.auth_service import (
    forgot_password_service,
    get_current_user,
    login,
    logout_service,
    refresh_token_service_with_body,
    resend_otp_service,
    reset_password_service,
    signup,
    verify_otp_service,
    verify_reset_token_service,
    verify_token_service,
    REFRESH_COOKIE_NAME,
)

from utils.rate_limiter import limiter

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


# ── POST /signup ──
@router.post("/signup", response_model=SignUpResponse, status_code=201)
@limiter.limit("5/minute")
async def signup_endpoint(request: Request, request_obj: SignUpRequest, db: AsyncSession = Depends(get_db)):
    return await signup(request_obj, db)


# ── POST /login ──
@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login_endpoint(
    credentials: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    return await login(credentials, response, db)


# ── POST /verify-otp ──
@router.post("/verify-otp", response_model=TokenResponse)
async def verify_otp_endpoint(
    request_obj: VerifyOTPRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    return await verify_otp_service(request_obj, response, db)


# ── POST /resend-otp ──
@router.post("/resend-otp", response_model=SignUpResponse)
async def resend_otp_endpoint(request_obj: OTPRequest, request: Request, db: AsyncSession = Depends(get_db)):
    return await resend_otp_service(request_obj, db)


# ── POST /refresh ──
@router.post("/refresh", response_model=TokenResponse)
async def refresh_endpoint(
    request: Request,
    response: Response,
    body: RefreshRequest = None,
    db: AsyncSession = Depends(get_db),
):
    # Prefer body token, fall back to cookie
    raw_token = None
    if body and body.refresh_token:
        raw_token = body.refresh_token
    if not raw_token:
        raw_token = request.cookies.get(REFRESH_COOKIE_NAME)
    if not raw_token:
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token missing")
    return await refresh_token_service_with_body(raw_token, response, db)


# ── POST /logout ──
@router.post("/logout")
@limiter.limit("10/minute")
async def logout_endpoint(
    request: Request,
    response: Response,
    body: Optional[RefreshRequest] = None,
    db: AsyncSession = Depends(get_db),
):
    body_token = body.refresh_token if body else None
    return await logout_service(request, response, db, body_token=body_token)


# ── GET /me ──
@router.get("/me", response_model=UserResponse)
async def me_endpoint(current_user: User = Depends(get_current_user)):
    return current_user


# ── POST /verify-token ──
@router.post("/verify-token")
async def verify_token_endpoint(
    current_user: User = Depends(get_current_user),
):
    return verify_token_service(current_user)


# ── POST /forgot-password ──
@router.post("/forgot-password")
async def forgot_password_endpoint(request_obj: OTPRequest, request: Request, db: AsyncSession = Depends(get_db)):
    return await forgot_password_service(request_obj, db)


# ── POST /verify-reset-token ──
@router.post("/verify-reset-token")
async def verify_reset_token_endpoint(
    request_obj: VerifyOTPRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    return await verify_reset_token_service(request_obj, db)


# ── POST /reset-password ──
@router.post("/reset-password")
async def reset_password_endpoint(
    request_obj: ResetPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    return await reset_password_service(request_obj, db)

