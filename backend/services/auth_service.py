"""
Business logic for authentication: sign-up, login, logout, OTP, password-reset,
refresh-token management.
"""

import hashlib
import logging
import random
import string
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.user import OtpToken, RefreshToken, User
from schemas.auth import (
    LoginRequest,
    OTPRequest,
    ResetPasswordRequest,
    SignUpRequest,
    SignUpResponse,
    TokenPayload,
    TokenResponse,
    UserInfo,
    UserResponse,
    VerifyOTPRequest,
)
from services.email_service import send_otp_email, send_reset_password_email
from utils.jwt_handler import create_access_token, decode_access_token

logger = logging.getLogger(__name__)

# ==================== Computed constants ====================
ACCESS_TOKEN_EXPIRES_IN_SECONDS = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
REFRESH_COOKIE_NAME = settings.AUTH_COOKIE_NAME
REFRESH_COOKIE_PATH = settings.AUTH_COOKIE_PATH or "/"
REFRESH_COOKIE_DOMAIN = settings.AUTH_COOKIE_DOMAIN or None
REFRESH_COOKIE_SECURE = settings.AUTH_COOKIE_SECURE
REFRESH_COOKIE_SAMESITE = settings.AUTH_COOKIE_SAMESITE.lower()
OTP_EXPIRE_MINUTES = settings.OTP_EXPIRE_MINUTES
RESET_CODE_LENGTH = 6
RESET_TOKEN_EXPIRE_MINUTES = settings.RESET_TOKEN_EXPIRE_MINUTES
RESET_TOKEN_EXPIRE_LABEL = (
    "1 minute" if RESET_TOKEN_EXPIRE_MINUTES == 1
    else f"{RESET_TOKEN_EXPIRE_MINUTES} minutes"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")


# ==================== Password helpers ====================

def hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt (truncated to 72 bytes)."""
    truncated = plain.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(truncated, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches the bcrypt *hashed* password."""
    truncated = plain.encode("utf-8")[:72]
    return bcrypt.checkpw(truncated, hashed.encode("utf-8"))


def validate_password(password: str) -> tuple[bool, str]:
    """Validate password meets complexity requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not (has_upper and has_lower and has_digit):
        return False, "Password must contain at least 1 uppercase, 1 lowercase, and 1 number"
    return True, ""


# ==================== User queries ====================

async def get_user_by_email(email: str, db: AsyncSession) -> User | None:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalars().first()


async def get_user_by_id(user_id: str, db: AsyncSession) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalars().first()


async def authenticate_user(email: str, password: str, db: AsyncSession) -> User | None:
    user = await get_user_by_email(email, db)
    if user is None:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


# ==================== OTP helpers ====================

def _generate_otp() -> str:
    return "".join(random.choices(string.digits, k=RESET_CODE_LENGTH))


async def _get_or_create_otp_record(db: AsyncSession, user: User) -> OtpToken:
    result = await db.execute(select(OtpToken).where(OtpToken.user_id == user.id))
    rec = result.scalars().first()
    if rec is None:
        rec = OtpToken(user_id=user.id)
        db.add(rec)
        await db.flush()
    return rec


# ==================== Constants ====================
MAX_FAILED_LOGINS = 5
LOCKOUT_DURATION_MINUTES = 15

def _get_plan_info(user: User) -> dict:
    is_pro = user.subscription_type.lower() == "pro"
    return {
        "plan_type": user.subscription_type.upper(),
        "is_pro": is_pro,
    }


def _build_user_info(user: User) -> UserInfo:
    plan = _get_plan_info(user)
    return UserInfo(
        id=str(user.id),
        email=user.email,
        name=user.full_name,
        plan_type=plan["plan_type"],
        is_pro=plan["is_pro"],
    )


# ==================== Refresh-token helpers ====================

def _hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _refresh_token_expiry(remember_me: bool) -> datetime:
    days = settings.REFRESH_TOKEN_REMEMBER_DAYS if remember_me else settings.REFRESH_TOKEN_EXPIRE_DAYS
    return datetime.now(timezone.utc) + timedelta(days=days)


def _set_refresh_cookie(response: Response, token: str, expires_at: datetime) -> None:
    if expires_at.tzinfo is None:
        expires_utc = expires_at.replace(tzinfo=timezone.utc)
    else:
        expires_utc = expires_at.astimezone(timezone.utc)
    now_utc = datetime.now(timezone.utc)
    max_age = max(0, int((expires_utc - now_utc).total_seconds()))
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=REFRESH_COOKIE_SECURE,
        samesite=REFRESH_COOKIE_SAMESITE,
        max_age=max_age,
        expires=expires_utc,
        path=REFRESH_COOKIE_PATH,
        domain=REFRESH_COOKIE_DOMAIN,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path=REFRESH_COOKIE_PATH,
        domain=REFRESH_COOKIE_DOMAIN,
    )


async def _persist_refresh_token(
    db: AsyncSession,
    *,
    user: User,
    token: str,
    expires_at: datetime,
    remember_me: bool,
    previous: Optional[RefreshToken] = None,
) -> RefreshToken:
    token_hash = _hash_refresh_token(token)
    record = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        remember_me=remember_me,
    )
    db.add(record)

    if previous is not None:
        previous.revoked_at = datetime.now(timezone.utc)
        previous.replaced_by_token_hash = token_hash

    # Cleanup expired/revoked tokens for this user
    now = datetime.now(timezone.utc)
    stale_result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user.id,
            (RefreshToken.revoked_at.isnot(None)) | (RefreshToken.expires_at <= now),
        )
    )
    for old in stale_result.scalars().all():
        await db.delete(old)

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    await db.refresh(record)
    return record


async def _issue_refresh_token(
    db: AsyncSession,
    *,
    user: User,
    remember_me: bool,
    previous: Optional[RefreshToken] = None,
) -> tuple[str, datetime, RefreshToken]:
    raw_token = token_urlsafe(48)
    expires_at = _refresh_token_expiry(remember_me)
    record = await _persist_refresh_token(
        db,
        user=user,
        token=raw_token,
        expires_at=expires_at,
        remember_me=remember_me,
        previous=previous,
    )
    return raw_token, expires_at, record


# ==================== Token builder ====================

async def _build_token_response(
    db: AsyncSession,
    user: User,
    remember_me: bool,
    response: Response,
    previous_refresh: Optional[RefreshToken] = None,
) -> TokenResponse:
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    raw_refresh, refresh_expires_at, _ = await _issue_refresh_token(
        db,
        user=user,
        remember_me=remember_me,
        previous=previous_refresh,
    )
    _set_refresh_cookie(response, raw_refresh, refresh_expires_at)

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRES_IN_SECONDS,
        user=_build_user_info(user),
    )


# ==================== Current user dependency ====================

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        user_id: str = payload.sub
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await get_user_by_id(user_id, db)
    if user is None:
        raise credentials_exception
    return user


# ==================== Auth operations ====================

async def signup(request: SignUpRequest, db: AsyncSession) -> SignUpResponse:
    existing = await get_user_by_email(request.email, db)
    full_name = f"{request.firstName} {request.lastName}".strip()

    if existing:
        if not existing.is_verified:
            # Unverified user — update info and resend OTP
            is_valid, error_msg = validate_password(request.password)
            if not is_valid:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

            existing.hashed_password = hash_password(request.password)
            existing.full_name = full_name

            otp = _generate_otp()
            logger.info("[OTP] Generated OTP for unverified re-signup %s: %s", request.email, otp)
            otp_rec = await _get_or_create_otp_record(db, existing)
            otp_rec.otp = otp
            otp_rec.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)
            await db.commit()

            logger.info("Resend OTP for unverified user %s", request.email)
            email_sent = send_otp_email(request.email, otp, full_name)
            return SignUpResponse(
                message="Account exists but not verified. New OTP sent to your email.",
                email=request.email,
                requires_verification=True,
                email_sent=email_sent,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists and is verified. Please login instead.",
            )

    # New user
    is_valid, error_msg = validate_password(request.password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    otp = _generate_otp()
    logger.info("[OTP] Generated OTP for new signup %s: %s", request.email, otp)
    db_user = User(
        email=request.email,
        full_name=full_name,
        hashed_password=hash_password(request.password),
        is_active=True,
        is_verified=False,
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)

    otp_rec = OtpToken(
        user_id=db_user.id,
        otp=otp,
        otp_expires_at=datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES),
    )
    db.add(otp_rec)
    await db.commit()

    logger.info("OTP sent to %s (expires in %d minutes)", request.email, OTP_EXPIRE_MINUTES)
    email_sent = send_otp_email(request.email, otp, full_name)

    return SignUpResponse(
        message="Signup successful! Please verify your email with the OTP sent.",
        email=request.email,
        requires_verification=True,
        email_sent=email_sent,
    )


async def login(credentials: LoginRequest, response: Response, db: AsyncSession) -> TokenResponse:
    user = await get_user_by_email(credentials.email, db)

    # --- Account lockout check ---
    if user:
        now = datetime.now(timezone.utc)
        if user.locked_until:
            lock_ts = user.locked_until
            if lock_ts.tzinfo is None:
                lock_ts = lock_ts.replace(tzinfo=timezone.utc)
            if now < lock_ts:
                remaining = int((lock_ts - now).total_seconds() // 60) + 1
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Account locked due to too many failed attempts. Try again in {remaining} minute(s).",
                )
            # Lock expired — reset
            user.locked_until = None
            user.failed_login_attempts = 0
            await db.commit()

    # --- Authenticate ---
    authenticated = await authenticate_user(credentials.email, credentials.password, db) if user else None
    if not authenticated:
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= MAX_FAILED_LOGINS:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                await db.commit()
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to {MAX_FAILED_LOGINS} failed attempts.",
                )
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = authenticated
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

    if not user.is_verified:
        # Send new OTP for unverified user
        otp = _generate_otp()
        logger.info("[OTP] Generated OTP for unverified login %s: %s", user.email, otp)
        otp_rec = await _get_or_create_otp_record(db, user)
        otp_rec.otp = otp
        otp_rec.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)
        await db.commit()
        logger.info("Login OTP sent to %s", user.email)
        send_otp_email(user.email, otp, user.full_name or "")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email first. A new OTP has been sent to your email.",
        )

    # Update last login + clear lockout counters
    user.last_login = datetime.now(timezone.utc)
    user.login_count = (user.login_count or 0) + 1
    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()
    await db.refresh(user)

    logger.info("User logged in: %s", user.email)
    return await _build_token_response(db, user, credentials.remember_me, response)


async def verify_otp_service(
    request: VerifyOTPRequest, response: Response, db: AsyncSession
) -> TokenResponse:
    user = await get_user_by_email(request.email, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    otp_rec = await _get_or_create_otp_record(db, user)
    if not otp_rec.otp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP not found or expired")

    now = datetime.now(timezone.utc)
    otp_exp = otp_rec.otp_expires_at
    if otp_exp and otp_exp.tzinfo is None:
        otp_exp = otp_exp.replace(tzinfo=timezone.utc)
    if otp_exp and now > otp_exp:
        otp_rec.otp = None
        otp_rec.otp_expires_at = None
        await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP expired. Please request a new one.")

    if otp_rec.otp != request.otp:
        logger.warning("Invalid OTP attempt for %s", request.email)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")

    # OTP verified — mark user as verified
    user.is_verified = True
    user.last_login = datetime.now(timezone.utc)
    user.login_count = (user.login_count or 0) + 1
    otp_rec.otp = None
    otp_rec.otp_expires_at = None
    await db.commit()
    await db.refresh(user)

    logger.info("OTP verified for %s", request.email)
    return await _build_token_response(db, user, request.remember_me, response)


async def resend_otp_service(request: OTPRequest, db: AsyncSession) -> SignUpResponse:
    user = await get_user_by_email(request.email, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.is_verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already verified. Please login.")

    otp = _generate_otp()
    logger.info("[OTP] Generated OTP for resend %s: %s", request.email, otp)
    otp_rec = await _get_or_create_otp_record(db, user)
    otp_rec.otp = otp
    otp_rec.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)
    await db.commit()

    logger.info("OTP resent to %s", request.email)
    email_sent = send_otp_email(request.email, otp, user.full_name or "")
    return SignUpResponse(
        message="OTP resent successfully",
        email=request.email,
        requires_verification=True,
        email_sent=email_sent,
    )


async def refresh_token_service(
    request: Request, response: Response, db: AsyncSession
) -> TokenResponse:
    # Try cookie first, then request body
    raw_token = request.cookies.get(REFRESH_COOKIE_NAME)
    if not raw_token:
        try:
            body = None
            # Will be handled by router passing body param
        except Exception:
            pass
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token missing")

    token_hash = _hash_refresh_token(raw_token)
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    record = result.scalars().first()

    if not record or not record.is_active():
        if record and record.revoked_at is None:
            record.revoked_at = datetime.now(timezone.utc)
            try:
                await db.commit()
            except Exception:
                await db.rollback()
                raise
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    user_result = await db.execute(select(User).where(User.id == record.user_id))
    user = user_result.scalars().first()
    if not user or not user.is_active:
        record.revoked_at = datetime.now(timezone.utc)
        try:
            await db.commit()
        except Exception:
            await db.rollback()
            raise
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    logger.info("Token refreshed for user %s (%s)", user.id, user.email)
    return await _build_token_response(db, user, record.remember_me, response, previous_refresh=record)


async def refresh_token_service_with_body(
    raw_token: str, response: Response, db: AsyncSession
) -> TokenResponse:
    """Refresh using a token value (from body or cookie)."""
    token_hash = _hash_refresh_token(raw_token)
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    record = result.scalars().first()

    if not record or not record.is_active():
        if record and record.revoked_at is None:
            record.revoked_at = datetime.now(timezone.utc)
            try:
                await db.commit()
            except Exception:
                await db.rollback()
                raise
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    user_result = await db.execute(select(User).where(User.id == record.user_id))
    user = user_result.scalars().first()
    if not user or not user.is_active:
        record.revoked_at = datetime.now(timezone.utc)
        try:
            await db.commit()
        except Exception:
            await db.rollback()
            raise
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    logger.info("Token refreshed for user %s (%s)", user.id, user.email)
    return await _build_token_response(db, user, record.remember_me, response, previous_refresh=record)


async def logout_service(request: Request, response: Response, db: AsyncSession, body_token: str | None = None) -> dict:
    raw_token = request.cookies.get(REFRESH_COOKIE_NAME) or body_token
    if raw_token:
        token_hash = _hash_refresh_token(raw_token)
        result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
        record = result.scalars().first()
        if record and record.revoked_at is None:
            record.revoked_at = datetime.now(timezone.utc)
            record.replaced_by_token_hash = None
            try:
                await db.commit()
            except Exception:
                await db.rollback()
                raise
    _clear_refresh_cookie(response)
    return {"message": "Logged out"}


def verify_token_service(current_user: User) -> dict:
    plan = _get_plan_info(current_user)
    return {
        "valid": True,
        "user": {
            "id": str(current_user.id),
            "email": current_user.email,
            "name": current_user.full_name,
            "plan_type": plan["plan_type"],
            "is_pro": plan["is_pro"],
        },
    }


# ==================== Forgot Password ====================

async def forgot_password_service(request: OTPRequest, db: AsyncSession) -> dict:
    user = await get_user_by_email(request.email, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found for this email. Please create an account.",
        )
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please verify your email before requesting a password reset.",
        )

    now = datetime.now(timezone.utc)
    otp_rec = await _get_or_create_otp_record(db, user)

    # Reuse existing valid token if present
    reuse = (
        otp_rec.reset_token
        and otp_rec.reset_token_expires_at
        and otp_rec.reset_token_expires_at.replace(tzinfo=timezone.utc)
            if otp_rec.reset_token_expires_at and otp_rec.reset_token_expires_at.tzinfo is None
            else otp_rec.reset_token_expires_at
    )
    if not (otp_rec.reset_token and reuse and reuse > now):
        reset_token = _generate_otp()
    else:
        reset_token = otp_rec.reset_token

    otp_rec.reset_token = reset_token
    otp_rec.reset_token_expires_at = now + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)

    try:
        await db.commit()
        await db.refresh(user)
    except Exception:
        await db.rollback()
        raise

    logger.info("Password reset token for %s: %s", request.email, reset_token)
    email_sent = send_reset_password_email(request.email, reset_token, user.full_name or "")

    if not email_sent:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send password reset email. Please try again later.",
        )

    return {
        "message": f"OTP sent successfully! Expires in {RESET_TOKEN_EXPIRE_LABEL}.",
        "email_sent": email_sent,
    }


async def verify_reset_token_service(request: VerifyOTPRequest, db: AsyncSession) -> dict:
    user = await get_user_by_email(request.email, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    provided_token = request.otp.strip()
    if not provided_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Enter the 6-digit code sent to your email.")
    if len(provided_token) != RESET_CODE_LENGTH or not provided_token.isdigit():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Enter a valid 6-digit numeric code.")

    otp_rec_result = await db.execute(select(OtpToken).where(OtpToken.user_id == user.id))
    otp_rec = otp_rec_result.scalars().first()
    if not otp_rec or not otp_rec.reset_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP expired. Please request a new code.")

    now = datetime.now(timezone.utc)
    exp = otp_rec.reset_token_expires_at
    if exp and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp and now > exp:
        otp_rec.reset_token = None
        otp_rec.reset_token_expires_at = None
        await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP expired. Please request a new code.")

    if otp_rec.reset_token != provided_token:
        logger.warning("Invalid reset token attempt for %s", request.email)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP invalid.")

    # Token verified — clear expiry to indicate "verified" state
    otp_rec.reset_token_expires_at = None
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    logger.info("Reset token verified for %s", request.email)
    return {
        "message": "Token verified successfully",
        "email": request.email,
        "token": provided_token,
    }


async def reset_password_service(request: ResetPasswordRequest, db: AsyncSession) -> dict:
    user = await get_user_by_email(request.email, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    provided_token = (request.token or "").strip()
    if not provided_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please verify the OTP before resetting your password.")
    if len(provided_token) != RESET_CODE_LENGTH or not provided_token.isdigit():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Enter a valid 6-digit numeric code.")

    otp_rec_result = await db.execute(select(OtpToken).where(OtpToken.user_id == user.id))
    otp_rec = otp_rec_result.scalars().first()
    if not otp_rec or not otp_rec.reset_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP expired. Please request a new code.")

    # Check token expiration (if reset_token_expires_at is set, it means not yet verified)
    now = datetime.now(timezone.utc)
    if otp_rec.reset_token_expires_at:
        exp = otp_rec.reset_token_expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if now > exp:
            otp_rec.reset_token = None
            otp_rec.reset_token_expires_at = None
            await db.commit()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP expired. Please request a new code.")

    if otp_rec.reset_token != provided_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP invalid.")

    # Validate new password
    is_valid, error_msg = validate_password(request.new_password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    # Update password and clear reset token
    user.hashed_password = hash_password(request.new_password)
    otp_rec.reset_token = None
    otp_rec.reset_token_expires_at = None
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    logger.info("Password reset successful for %s", request.email)
    return {"message": "Password reset successful. You can now login with your new password."}

