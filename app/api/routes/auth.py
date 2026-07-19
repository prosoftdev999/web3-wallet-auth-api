from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.core.config import settings
from app.db.database import get_db
from app.models.nonce import LoginNonce
from app.models.revoked_token import RevokedToken
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    LogoutResponse,
    NonceRequest,
    NonceResponse,
    TokenResponse,
)
from app.services.siwe_service import (
    SiweVerificationError,
    build_siwe_message,
    generate_nonce,
    normalize_wallet_address,
    verify_siwe_message,
)
from app.services.token_service import (
    TokenError,
    create_access_token,
    decode_access_token,
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

bearer_scheme = HTTPBearer(auto_error=False)


@router.post(
    "/nonce",
    response_model=NonceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_nonce(
    payload: NonceRequest,
    db: AsyncSession = Depends(get_db),
) -> NonceResponse:
    try:
        wallet_address = normalize_wallet_address(
            payload.wallet_address
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    await db.execute(
        update(LoginNonce)
        .where(
            LoginNonce.wallet_address == wallet_address,
            LoginNonce.used.is_(False),
        )
        .values(used=True)
    )

    nonce = generate_nonce()
    message = build_siwe_message(
        wallet_address=wallet_address,
        nonce=nonce,
    )

    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.nonce_expire_minutes
    )

    login_nonce = LoginNonce(
        wallet_address=wallet_address,
        nonce=nonce,
        message=message,
        expires_at=expires_at,
        used=False,
    )

    db.add(login_nonce)
    await db.commit()

    return NonceResponse(
        nonce=nonce,
        message=message,
        expires_in=settings.nonce_expire_minutes * 60,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
)
async def login(
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    result = await db.execute(
        select(LoginNonce)
        .where(LoginNonce.message == payload.message)
        .with_for_update()
    )

    login_nonce = result.scalar_one_or_none()

    if login_nonce is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login message was not issued by this server",
        )

    if login_nonce.used:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nonce has already been used",
        )

    now = datetime.now(timezone.utc)

    if login_nonce.expires_at <= now:
        login_nonce.used = True
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nonce has expired",
        )

    try:
        wallet_address = verify_siwe_message(
            message=payload.message,
            signature=payload.signature,
            expected_nonce=login_nonce.nonce,
        )
    except (SiweVerificationError, ValueError) as exc:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    if wallet_address != login_nonce.wallet_address:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Signed wallet does not match nonce wallet",
        )

    user_result = await db.execute(
        select(User).where(
            User.wallet_address == wallet_address
        )
    )

    user = user_result.scalar_one_or_none()

    if user is None:
        user = User(
            wallet_address=wallet_address,
            ens_name=None,
        )
        db.add(user)

    login_nonce.used = True
    await db.commit()

    access_token = create_access_token(
        wallet_address=wallet_address
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
)
async def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> LogoutResponse:
    del current_user

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(
            credentials.credentials
        )
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    token_id = payload["jti"]
    expires_at = datetime.fromtimestamp(
        payload["exp"],
        tz=timezone.utc,
    )

    existing_result = await db.execute(
        select(RevokedToken).where(
            RevokedToken.jti == token_id
        )
    )

    existing_revocation = existing_result.scalar_one_or_none()

    if existing_revocation is None:
        db.add(
            RevokedToken(
                jti=token_id,
                expires_at=expires_at,
            )
        )
        await db.commit()

    return LogoutResponse(
        message="Successfully logged out"
    )