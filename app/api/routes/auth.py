from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import get_db
from app.models.nonce import LoginNonce
from app.schemas.auth import NonceRequest, NonceResponse
from app.services.siwe_service import (
    build_siwe_message,
    generate_nonce,
    normalize_wallet_address,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


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

    # Invalidate previous unused nonces for this wallet.
    await db.execute(
        update(LoginNonce)
        .where(
            LoginNonce.wallet_address == wallet_address,
            LoginNonce.used.is_(False),
        )
        .values(used=True)
    )

    nonce = generate_nonce()
    message = build_siwe_message(wallet_address, nonce)

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