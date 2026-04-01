<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import create_access_token, create_refresh_token, decode_token, hash_password, verify_password
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenResponse
from app.services.audit import log_audit_event
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.security import create_access_token, get_password_hash, verify_password
from app.db.session import get_db
from app.models.models import User
from app.schemas.schemas import Token, UserCreate, UserOut
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs

router = APIRouter(prefix="/auth", tags=["auth"])


<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
def rate_limit_key(request: Request) -> str:
    if hasattr(request.state, "rate_limit_key") and request.state.rate_limit_key:
        return request.state.rate_limit_key
    return get_remote_address(request)


limiter = Limiter(key_func=rate_limit_key)


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
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
@limiter.limit("20/minute")
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
@limiter.limit("30/minute")
def refresh_token(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    try:
        claims = decode_token(payload.refresh_token)
    except JWTError as exc:
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
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
@router.post("/register", response_model=UserOut)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=payload.email, hashed_password=get_password_hash(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    return Token(access_token=create_access_token(user.email))
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
