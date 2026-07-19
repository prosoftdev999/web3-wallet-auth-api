from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from jose import JWTError, jwt

from app.core.config import settings


class TokenError(Exception):
    """Raised when a JWT cannot be created or decoded."""


def create_access_token(wallet_address: str) -> str:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(
        minutes=settings.access_token_expire_minutes
    )

    payload = {
        "sub": wallet_address,
        "jti": uuid4().hex,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError as exc:
        raise TokenError("Invalid or expired access token") from exc

    if payload.get("type") != "access":
        raise TokenError("Invalid token type")

    wallet_address = payload.get("sub")
    token_id = payload.get("jti")

    if not wallet_address or not token_id:
        raise TokenError("Token is missing required claims")

    return payload