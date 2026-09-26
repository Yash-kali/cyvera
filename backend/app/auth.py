from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.config import settings
from app.database import get_db
from app.models import User
from app.schemas import TokenData

# CryptContext setup for bcrypt password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 Scheme specifying token endpoint URL
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate bcrypt hash for plain password."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Encode payload dict into JWT access token with exp timestamp."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc)
    })
    
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_websocket_ticket(user: User) -> str:
    """
    Generate a 60-second short-lived JWT ticket specifically scoped for WebSocket stream handshakes.
    Prevents long-lived REST API access tokens from being exposed in WebSocket connection URLs.
    """
    now = datetime.now(timezone.utc)
    to_encode = {
        "sub": user.username,
        "user_id": user.id,
        "scope": "websocket_scan",
        "pwd_ver": getattr(user, "password_version", 1) or 1,
        "exp": now + timedelta(seconds=60),
        "iat": now
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_websocket_token(token: str) -> Optional[TokenData]:
    """
    Decode and validate a JWT access token or short-lived WebSocket ticket.
    Permits both standard access tokens and scoped 'websocket_scan' tickets.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        scope: Optional[str] = payload.get("scope")
        if not username or not user_id:
            return None
        if scope and scope not in ["websocket_scan", "access"]:
            return None
        return TokenData(username=username, user_id=user_id)
    except Exception:
        return None


def verify_access_token(token: str) -> Optional[TokenData]:
    """Decode and validate a JWT access token returning TokenData or None."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        scope: Optional[str] = payload.get("scope")
        # Reject WebSocket-only tickets if presented as REST access tokens
        if scope == "websocket_scan":
            return None
        if not username:
            return None
        return TokenData(username=username, user_id=user_id)
    except Exception:
        return None


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """FastAPI Dependency: Decodes JWT token and fetches current user from DB."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or token expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        token_pwd_ver = payload.get("pwd_ver")
        scope = payload.get("scope")

        # Security control: Short-lived WebSocket tickets cannot authenticate general REST API endpoints
        if scope == "websocket_scan":
            raise credentials_exception
        
        if username is None or user_id is None:
            raise credentials_exception
            
        token_data = TokenData(username=username, user_id=user_id)
    except jwt.PyJWTError:
        raise credentials_exception
        
    result = await db.execute(select(User).where(User.id == token_data.user_id))
    user = result.scalars().first()
    
    if user is None:
        raise credentials_exception

    # Session revocation check: verify token's password version against current user state
    user_pwd_ver = getattr(user, "password_version", 1) or 1
    if token_pwd_ver is not None and token_pwd_ver != user_pwd_ver:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired due to a password reset or change. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if token_pwd_ver is None and user_pwd_ver > 1:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired due to a password reset or change. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    return user
