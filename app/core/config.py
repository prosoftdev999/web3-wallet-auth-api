from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Web3 Wallet Authentication API"
    debug: bool = False

    database_url: str

    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    siwe_domain: str
    siwe_uri: str
    siwe_chain_id: int = 1
    siwe_statement: str = "Sign in to Web3 Wallet Authentication API"

    nonce_expire_minutes: int = 10

    redis_url: str = "redis://redis:6379/0"

    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()