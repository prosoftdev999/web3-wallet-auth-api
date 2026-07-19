from pydantic import BaseModel, Field


class NonceRequest(BaseModel):
    wallet_address: str


class NonceResponse(BaseModel):
    nonce: str
    message: str
    expires_in: int


class LoginRequest(BaseModel):
    message: str = Field(min_length=1)
    signature: str = Field(min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"