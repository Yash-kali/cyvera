import logging
from datetime import datetime, timezone, timedelta
from typing import Union
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import or_, func

from app.database import get_db
from app.models import User
from app.schemas import (
    UserCreate,
    UserLogin,
    UserResponse,
    Token,
    PasswordChangeRequest,
    UserProfileUpdate
)
from app.auth import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_websocket_ticket,
    get_current_user
)
from app.config import settings

logger = logging.getLogger("autopentest.auth")

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


def validate_password_strength(password: str) -> None:
    """
    Enforce security policy on user passwords:
    - Min length 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 number
    - At least 1 special character
    """
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )
    if not any(c.isupper() for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one uppercase letter."
        )
    if not any(c.islower() for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one lowercase letter."
        )
    if not any(c.isdigit() for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one number."
        )
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>/?~`'\""
    if not any(c in special_chars for c in password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one special character."
        )


@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Register a new user in AutoPentest AI.
    If public registration is disabled, requires a valid administrator bootstrap token.
    """
    if not settings.ALLOW_PUBLIC_REGISTRATION:
        admin_token = user_in.admin_invite_token
        if not settings.ADMIN_BOOTSTRAP_TOKEN or admin_token != settings.ADMIN_BOOTSTRAP_TOKEN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Public registration is disabled. Please contact your administrator for an account."
            )

    # Validate password complexity
    validate_password_strength(user_in.password)

    # Check if username or email already exists
    stmt = select(User).where(
        or_(User.username == user_in.username, User.email == user_in.email)
    )
    result = await db.execute(stmt)
    existing_user = result.scalars().first()
    
    if existing_user:
        if existing_user.email == user_in.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email address already exists."
            )
        if existing_user.username == user_in.username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username is already taken."
            )
            
    # Hash password & create user
    hashed_pwd = get_password_hash(user_in.password)
    db_user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hashed_pwd,
        password_version=1
    )
    
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    
    # Generate Access Token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.username, "user_id": db_user.id, "email": db_user.email, "pwd_ver": 1},
        expires_delta=access_token_expires
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(db_user)
    )


@router.post("/login", response_model=Token)
async def login(request: Request, credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    """
    Authenticate user with email or username and password (JSON payload).
    Returns JWT access_token on success.
    Phase 8: Rate-limited per client IP; security events logged explicitly.
    """
    from app.main import login_rate_limiter
    client_ip = request.client.host if request.client else "unknown"

    # Phase 8: Per-IP rate limit check
    if not login_rate_limiter.check_and_record(client_ip):
        logger.warning(
            f"SECURITY | LOGIN_RATE_LIMITED | ip={client_ip} | identifier={credentials.email_or_username[:50]!r}"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait before trying again.",
            headers={"Retry-After": str(settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS)},
        )

    clean_identifier = credentials.email_or_username.strip()
    stmt = select(User).where(
        or_(
            func.lower(User.email) == clean_identifier.lower(),
            func.lower(User.username) == clean_identifier.lower()
        )
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not verify_password(credentials.password, user.hashed_password):
        logger.warning(
            f"SECURITY | LOGIN_FAILED | ip={client_ip} | identifier={clean_identifier[:50]!r}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Successful login: clear rate limit counter and log security event
    login_rate_limiter.clear(client_ip)
    logger.info(
        f"SECURITY | LOGIN_SUCCESS | ip={client_ip} | user={user.username!r} | user_id={user.id}"
    )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    pwd_ver = getattr(user, "password_version", 1) or 1
    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id, "email": user.email, "pwd_ver": pwd_ver},
        expires_delta=access_token_expires
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.post("/login/form", response_model=Token, include_in_schema=False)
async def login_form(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """OAuth2 Compatible Form Login Endpoint (Phase 8: rate-limited)."""
    from app.main import login_rate_limiter
    client_ip = request.client.host if request.client else "unknown"

    if not login_rate_limiter.check_and_record(client_ip):
        logger.warning(
            f"SECURITY | LOGIN_RATE_LIMITED | ip={client_ip} | form_user={form_data.username[:50]!r}"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait before trying again.",
            headers={"Retry-After": str(settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS)},
        )

    clean_identifier = form_data.username.strip()
    stmt = select(User).where(
        or_(
            func.lower(User.email) == clean_identifier.lower(),
            func.lower(User.username) == clean_identifier.lower()
        )
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning(
            f"SECURITY | LOGIN_FAILED | ip={client_ip} | identifier={clean_identifier[:50]!r}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    login_rate_limiter.clear(client_ip)
    logger.info(
        f"SECURITY | LOGIN_SUCCESS | ip={client_ip} | user={user.username!r} | user_id={user.id}"
    )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    pwd_ver = getattr(user, "password_version", 1) or 1
    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id, "email": user.email, "pwd_ver": pwd_ver},
        expires_delta=access_token_expires
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """
    Get Current Authenticated User details from JWT token.
    Protected endpoint.
    """
    return current_user


@router.post("/change-password")
async def change_password(
    req: PasswordChangeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Secure password change endpoint for authenticated users.
    Enforces current password verification, prevents reuse of current password,
    hashes the new password via bcrypt, bumps password_version, and audit logs without revealing secrets.
    """
    # 1. Verify current password
    if not verify_password(req.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect."
        )

    # 2. Check for password reuse
    if req.current_password == req.new_password or verify_password(req.new_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password cannot be identical to your current password."
        )

    # 3. Hash new password securely and bump password_version to revoke other sessions
    new_hashed = get_password_hash(req.new_password)
    current_user.hashed_password = new_hashed
    current_user.password_version = (getattr(current_user, "password_version", 1) or 1) + 1

    await db.commit()

    # 4. Audit logging (NEVER log password or hash)
    logger.info("Password changed successfully for user id=%s. Sessions invalidated.", current_user.id)

    return {"status": "success", "message": "Password changed successfully."}


@router.patch("/profile", response_model=UserResponse)
async def update_profile(
    profile_in: UserProfileUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update profile details (username, email) for the authenticated user.
    """
    if profile_in.username and profile_in.username != current_user.username:
        # Check uniqueness
        stmt = select(User).where(User.username == profile_in.username, User.id != current_user.id)
        res = await db.execute(stmt)
        if res.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username is already taken."
            )
        current_user.username = profile_in.username

    if profile_in.email and profile_in.email != current_user.email:
        # Check uniqueness
        stmt = select(User).where(User.email == profile_in.email, User.id != current_user.id)
        res = await db.execute(stmt)
        if res.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email address already exists."
            )
        current_user.email = profile_in.email

    await db.commit()
    await db.refresh(current_user)
    logger.info("Profile updated for user id=%s", current_user.id)
    return current_user


@router.post("/ws-ticket")
async def get_websocket_ticket(
    current_user: User = Depends(get_current_user)
):
    """
    Issue a short-lived (60s) single-purpose WebSocket ticket.
    Mitigates credential leakage: long-lived REST API JWTs never appear in WebSocket URLs,
    browser history, access logs, or proxy traces.
    """
    ticket = create_websocket_ticket(current_user)
    return {"ticket": ticket, "expires_in": 60}


