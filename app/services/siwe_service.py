import secrets
from datetime import datetime, timedelta, timezone

from eth_account import Account
from eth_account.messages import encode_defunct
from siwe import SiweMessage
from web3 import Web3

from app.core.config import settings


class SiweVerificationError(Exception):
    """Raised when a SIWE message or signature is invalid."""


def normalize_wallet_address(address: str) -> str:
    
    if not Web3.is_address(address):
        raise ValueError("Invalid Ethereum wallet address")

    return Web3.to_checksum_address(address)


def generate_nonce() -> str:
    
    return secrets.token_hex(16)


def build_siwe_message(wallet_address: str, nonce: str) -> str:
    """
    Build a Sign-In with Ethereum message.
    """
    checksum_address = normalize_wallet_address(wallet_address)

    now = datetime.now(timezone.utc)
    expiration_time = now + timedelta(
        minutes=settings.nonce_expire_minutes
    )

    message = SiweMessage(
        domain=settings.siwe_domain,
        address=checksum_address,
        statement=settings.siwe_statement,
        uri=settings.siwe_uri,
        version="1",
        chain_id=settings.siwe_chain_id,
        nonce=nonce,
        issued_at=now.isoformat().replace("+00:00", "Z"),
        expiration_time=expiration_time.isoformat().replace(
            "+00:00",
            "Z",
        ),
    )

    return message.prepare_message()


def recover_signer(message: str, signature: str) -> str:
    """
    Recover the Ethereum address that signed the message.
    """
    try:
        encoded_message = encode_defunct(text=message)

        recovered_address = Account.recover_message(
            encoded_message,
            signature=signature,
        )

        return normalize_wallet_address(recovered_address)

    except Exception as exc:
        raise SiweVerificationError(
            "Unable to recover wallet from signature"
        ) from exc


def verify_siwe_message(
    message: str,
    signature: str,
    expected_nonce: str,
) -> str:
    """
    Verify the SIWE message fields and Ethereum signature.

    Returns the verified checksum wallet address.
    """
    try:
        siwe_message = SiweMessage.from_message(message)
    except Exception as exc:
        raise SiweVerificationError(
            "Invalid SIWE message format"
        ) from exc

    if siwe_message.domain != settings.siwe_domain:
        raise SiweVerificationError("Invalid SIWE domain")

    if str(siwe_message.uri) != settings.siwe_uri:
        raise SiweVerificationError("Invalid SIWE URI")

    if int(siwe_message.chain_id) != settings.siwe_chain_id:
        raise SiweVerificationError("Invalid SIWE chain ID")

    if siwe_message.nonce != expected_nonce:
        raise SiweVerificationError("Invalid SIWE nonce")

    declared_address = normalize_wallet_address(
        siwe_message.address
    )

    recovered_address = recover_signer(
        message=message,
        signature=signature,
    )

    if recovered_address != declared_address:
        raise SiweVerificationError(
            "Signature does not match wallet address"
        )

    return recovered_address