from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.models.revoked_token import RevokedToken
from app.models.user import User
from app.services.token_service import TokenError, decode_access_token


bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
    db: AsyncSession = Depends(get_db),
) -> User:
    authentication_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise authentication_error

    if credentials.scheme.lower() != "bearer":
        raise authentication_error

    try:
        payload = decode_access_token(credentials.credentials)
    except TokenError as exc:
        raise authentication_error from exc

    wallet_address = payload.get("sub")
    token_id = payload.get("jti")

    if not wallet_address or not token_id:
        raise authentication_error

    revoked_result = await db.execute(
        select(RevokedToken).where(
            RevokedToken.jti == token_id
        )
    )

    if revoked_result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_result = await db.execute(
        select(User).where(
            User.wallet_address == wallet_address
        )
    )

    user = user_result.scalar_one_or_none()

    if user is None:
        raise authentication_error

    return user