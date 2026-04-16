from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError
from slowapi import Limiter
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token, create_refresh_token, decode_token, hash_password, verify_password
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenResponse
from app.services.audit import log_audit_event

router = APIRouter(prefix="/auth", tags=["auth"])


def rate_limit_key(request: Request) -> str:
    """Generate rate limit key from request, preferring client IP with port."""
    if hasattr(request.state, "rate_limit_key") and request.state.rate_limit_key:
        return request.state.rate_limit_key
    # Check for X-Forwarded-For header when behind reverse proxy
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP from the chain (original client)
        return forwarded_for.split(",")[0].strip()
    # Use client IP:port for better granularity
    if request.client:
        return f"{request.client.host}:{request.client.port}"
    return "unknown"


limiter = Limiter(key_func=rate_limit_key)


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.register_rate_limit)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(email=payload.email, password_hash=hash_password(payload.password), role="user")
    db.add(user)
    db.commit()
    db.refresh(user)
    access = create_access_token(str(user.id), user.role)
    refresh, jti, expires_at = create_refresh_token(str(user.id), user.role)
    db.add(RefreshToken(user_id=user.id, token_jti=jti, expires_at=expires_at))
    db.commit()
    log_audit_event(db, action="user_registered", user_id=user.id, ip_address=request.client.host if request.client else None)
    return TokenResponse(access_token=access, refresh_token=refresh)


@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.login_rate_limit)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access = create_access_token(str(user.id), user.role)
    refresh, jti, expires_at = create_refresh_token(str(user.id), user.role)
    db.add(RefreshToken(user_id=user.id, token_jti=jti, expires_at=expires_at))
    db.commit()
    log_audit_event(
        db,
        action="user_login",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata_json={"email": user.email},
    )
    return TokenResponse(access_token=access, refresh_token=refresh)


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit(settings.refresh_rate_limit)
def refresh_token(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    try:
        claims = decode_token(payload.refresh_token)
    except (JWTError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from exc

    if claims.get("token_type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_id = claims.get("sub")
    token_jti = claims.get("jti")
    if not user_id or not token_jti:
        raise HTTPException(status_code=401, detail="Malformed refresh token")

    stored = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_jti == token_jti, RefreshToken.user_id == int(user_id))
        .first()
    )
    if not stored or stored.is_revoked or stored.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token revoked or expired")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    stored.is_revoked = True
    access = create_access_token(str(user.id), user.role)
    refresh, new_jti, expires_at = create_refresh_token(str(user.id), user.role)
    db.add(RefreshToken(user_id=user.id, token_jti=new_jti, expires_at=expires_at))
    db.commit()

    log_audit_event(
        db,
        action="token_refreshed",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
    )
    return TokenResponse(access_token=access, refresh_token=refresh)
