"""
Authentication, Authorization, and JWT Management.
Provides role-based access control (RBAC) and tenant context extraction.
"""

from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone
import base64
import json
import hmac
import hashlib

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from cloud_controller.config import (
    JWT_SECRET_KEY,
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
)
from cloud_controller.database import (
    get_user_by_username,
    get_user_by_id,
    verify_password,
)

security = HTTPBearer(auto_error=False)


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def _base64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4)) if (len(data) % 4) != 0 else ''
    return base64.urlsafe_b64decode((data + padding).encode('utf-8'))


def create_access_token(user: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a signed JWT-compatible token."""
    header = {"alg": "HS256", "typ": "JWT"}
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": user["id"],
        "username": user["username"],
        "tenant_id": user["tenant_id"],
        "role": user["role"],
        "exp": int(expire.timestamp()),
    }

    hdr_b64 = _base64url_encode(json.dumps(header).encode('utf-8'))
    pay_b64 = _base64url_encode(json.dumps(payload).encode('utf-8'))
    message = f"{hdr_b64}.{pay_b64}".encode('utf-8')

    sig = hmac.new(JWT_SECRET_KEY.encode('utf-8'), message, hashlib.sha256).digest()
    sig_b64 = _base64url_encode(sig)

    return f"{hdr_b64}.{pay_b64}.{sig_b64}"


def decode_access_token(token: str) -> Dict[str, Any]:
    """Validates signature and expiration, returns token payload."""
    parts = token.split('.')
    if len(parts) != 3:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    hdr_b64, pay_b64, sig_b64 = parts
    message = f"{hdr_b64}.{pay_b64}".encode('utf-8')
    expected_sig = hmac.new(JWT_SECRET_KEY.encode('utf-8'), message, hashlib.sha256).digest()
    actual_sig = _base64url_decode(sig_b64)

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = json.loads(_base64url_decode(pay_b64).decode('utf-8'))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload JSON",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check expiration
    exp = payload.get("exp")
    if not exp or datetime.now(timezone.utc).timestamp() > exp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Dict[str, Any]:
    """
    FastAPI dependency extracting authenticated user from Bearer header or cookie.
    """
    token = None
    if credentials:
        token = credentials.credentials
    elif "access_token" in request.cookies:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    user = get_user_by_id(payload["sub"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_role(roles: list[str]):
    """Decorator / dependency factory enforcing specific user roles."""
    async def role_checker(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        if user["role"] not in roles and user["role"] != "superadmin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: insufficient permissions (required: {', '.join(roles)})",
            )
        return user
    return role_checker
