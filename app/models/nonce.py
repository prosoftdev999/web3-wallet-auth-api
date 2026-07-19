from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class LoginNonce(Base):
    __tablename__ = "login_nonces"

    id: Mapped[int] = mapped_column(primary_key=True)
    wallet_address: Mapped[str] = mapped_column(
        String(42),
        nullable=False,
        index=True,
    )
    nonce: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )
    message: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    used: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )