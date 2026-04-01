from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from jose import jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(subject: str, role: str, expires_delta: timedelta | None = None) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode: dict[str, Any] = {"sub": subject, "role": role, "exp": expire, "token_type": "access"}
    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(subject: str, role: str, expires_delta: timedelta | None = None) -> tuple[str, str, datetime]:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.refresh_token_expire_minutes)
    )
    jti = uuid4().hex
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "jti": jti,
        "exp": expire,
        "token_type": "refresh",
    }
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, jti, expire


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
