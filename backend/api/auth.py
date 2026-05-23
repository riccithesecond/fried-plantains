"""
api/auth.py — JWT authentication endpoints.

Token strategy:
  - Access token: 15-minute expiry, signed HS256 JWT, returned in response body
  - Refresh token: 7-day expiry, stored in httpOnly cookie set by this API
  - Revocation: in-memory set per process (production: Redis or DB-backed)

MVP user store: single admin user from ADMIN_USERNAME + ADMIN_PASSWORD_HASH env vars.
Production upgrade: replace _get_user() with a database query and add user management.

Security notes:
  - Token values are never logged — only username and action are logged
  - ADMIN_PASSWORD_HASH must be a bcrypt hash (passlib.hash.bcrypt)
  - Tokens expire by design — the refresh flow handles silent renewal
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from jose.jwt import get_unverified_claims
from passlib.context import CryptContext
from pydantic import BaseModel

from backend.config import settings
from backend.exceptions import AuthException
from backend.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
_ALGORITHM = "HS256"

# In-memory refresh token revocation store: token → expiry (Unix timestamp).
# Production: replace with Redis SET with TTL equal to refresh token expiry.
# Tokens forgotten on server restart — acceptable for MVP.
_revoked_refresh_tokens: dict[str, float] = {}


def _revoke_token(token: str) -> None:
    """Add a token to the revocation store, recording its expiry for pruning."""
    try:
        exp = float(get_unverified_claims(token).get("exp", 0))
    except Exception:
        exp = 0.0
    _revoked_refresh_tokens[token] = exp


def _prune_revoked_tokens() -> None:
    """Remove expired entries — they can no longer be used regardless."""
    now = datetime.now(timezone.utc).timestamp()
    expired = [t for t, exp in _revoked_refresh_tokens.items() if exp < now]
    for t in expired:
        del _revoked_refresh_tokens[t]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


def _get_user(username: str) -> User | None:
    """Return the user if username matches the configured admin.

    Production upgrade: query users table by username.
    """
    if username == settings.ADMIN_USERNAME:
        return User(username=username, is_admin=True)
    return None


def _verify_password(plain: str, hashed: str) -> bool:
    try:
        return _pwd_context.verify(plain, hashed)
    except Exception:
        # Passlib bcrypt has a detect_wrap_bug() incompatibility on Python 3.13+.
        # Fall back to the underlying bcrypt library directly.
        try:
            import bcrypt as _bcrypt
            return _bcrypt.checkpw(plain.encode(), hashed.encode())
        except Exception as exc:
            logger.error("bcrypt verify failed (both passlib and direct): %s", exc)
            return False


def _create_token(data: dict, expires_delta: timedelta) -> str:
    payload = {
        **data,
        "exp": datetime.now(timezone.utc) + expires_delta,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=_ALGORITHM)


def _create_access_token(username: str) -> str:
    return _create_token(
        {"sub": username, "type": "access"},
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def _create_refresh_token(username: str) -> str:
    return _create_token(
        {"sub": username, "type": "refresh"},
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )


async def get_current_user(token: str = Depends(_oauth2_scheme)) -> User:
    """FastAPI dependency — validate JWT and return the current user.

    Raises HTTP 401 on any token failure. The error message is generic to
    avoid leaking information about why validation failed.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[_ALGORITHM])
        username: str = payload.get("sub", "")
        token_type: str = payload.get("type", "")
        if not username or token_type != "access":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = _get_user(username)
    if user is None:
        raise credentials_exception
    return user


@router.post("/token", response_model=TokenResponse)
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> TokenResponse:
    """Authenticate and issue access + refresh tokens.

    The refresh token is set as an httpOnly cookie — not accessible to
    JavaScript, which prevents XSS from stealing it.
    """
    user = _get_user(form_data.username)
    if user is None or not _verify_password(form_data.password, settings.ADMIN_PASSWORD_HASH):
        logger.warning("Failed login attempt for username: %s", form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
        )

    access_token = _create_access_token(user.username)
    refresh_token = _create_refresh_token(user.username)

    # httpOnly cookie — JS cannot read this, XSS cannot steal it
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,   # Set True in production with HTTPS
        samesite="strict",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path="/api/v1/auth/refresh",
    )

    logger.info("Login successful: user=%s", user.username)
    return TokenResponse(
        access_token=access_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request, response: Response) -> TokenResponse:
    """Exchange a valid refresh token for a new access token."""
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token.")

    _prune_revoked_tokens()
    if refresh_token in _revoked_refresh_tokens:
        raise HTTPException(status_code=401, detail="Token has been revoked.")

    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[_ALGORITHM])
        username: str = payload.get("sub", "")
        token_type: str = payload.get("type", "")
        if not username or token_type != "refresh":
            raise JWTError("Invalid token type")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")

    user = _get_user(username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found.")

    new_access = _create_access_token(user.username)
    new_refresh = _create_refresh_token(user.username)

    # Rotate refresh token — revoke old, issue new
    _revoke_token(refresh_token)
    response.set_cookie(
        key="refresh_token",
        value=new_refresh,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path="/api/v1/auth/refresh",
    )

    logger.info("Token refreshed: user=%s", username)
    return TokenResponse(
        access_token=new_access,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Revoke the refresh token and clear the cookie."""
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        _revoke_token(refresh_token)
    response.delete_cookie("refresh_token", path="/api/v1/auth/refresh")
    logger.info("Logout: user=%s", current_user.username)
    return {"detail": "Logged out."}
