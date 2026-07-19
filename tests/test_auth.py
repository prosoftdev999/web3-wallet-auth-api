import httpx
from eth_account import Account
from eth_account.messages import encode_defunct
from app.services.siwe_service import generate_nonce

API_URL = "http://localhost:8001"
REQUEST_TIMEOUT = 10.0


def test_health() -> None:
    response = httpx.get(
        f"{API_URL}/health",
        timeout=REQUEST_TIMEOUT,
    )

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_invalid_wallet_rejected() -> None:
    response = httpx.post(
        f"{API_URL}/auth/nonce",
        json={
            "wallet_address": "invalid-wallet",
        },
        timeout=REQUEST_TIMEOUT,
    )

    assert response.status_code == 422


def test_complete_wallet_authentication_flow() -> None:
    # Create a temporary development wallet in memory.
    account = Account.create()

    # 1. Request a SIWE nonce and message.
    nonce_response = httpx.post(
        f"{API_URL}/auth/nonce",
        json={
            "wallet_address": account.address,
        },
        timeout=REQUEST_TIMEOUT,
    )

    assert nonce_response.status_code == 201

    nonce_data = nonce_response.json()

    assert nonce_data["nonce"]
    assert nonce_data["message"]
    assert nonce_data["expires_in"] == 600

    message = nonce_data["message"]

    # 2. Sign the SIWE message with the temporary wallet.
    signed_message = account.sign_message(
        encode_defunct(text=message)
    )

    signature = signed_message.signature.hex()

    if not signature.startswith("0x"):
        signature = f"0x{signature}"

    # 3. Log in and receive a JWT.
    login_response = httpx.post(
        f"{API_URL}/auth/login",
        json={
            "message": message,
            "signature": signature,
        },
        timeout=REQUEST_TIMEOUT,
    )

    assert login_response.status_code == 200, login_response.text

    token_data = login_response.json()

    assert token_data["access_token"]
    assert token_data["token_type"] == "bearer"

    access_token = token_data["access_token"]

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    # 4. Access the protected wallet profile.
    profile_response = httpx.get(
        f"{API_URL}/me",
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )

    assert profile_response.status_code == 200

    profile_data = profile_response.json()

    assert profile_data["wallet_address"] == account.address
    assert profile_data["ens_name"] is None
    assert profile_data["id"]
    assert profile_data["created_at"]

    # 5. The same nonce and signature must not be reusable.
    replay_response = httpx.post(
        f"{API_URL}/auth/login",
        json={
            "message": message,
            "signature": signature,
        },
        timeout=REQUEST_TIMEOUT,
    )

    assert replay_response.status_code == 401
    assert replay_response.json()["detail"] == (
        "Nonce has already been used"
    )

    # 6. Logout and revoke the JWT.
    logout_response = httpx.post(
        f"{API_URL}/auth/logout",
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )

    assert logout_response.status_code == 200
    assert logout_response.json() == {
        "message": "Successfully logged out",
    }

    # 7. The revoked JWT must no longer access /me.
    revoked_response = httpx.get(
        f"{API_URL}/me",
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )

    assert revoked_response.status_code == 401
    assert revoked_response.json()["detail"] == (
        "Authentication token has been revoked"
    )


def test_me_requires_authentication() -> None:
    response = httpx.get(
        f"{API_URL}/me",
        timeout=REQUEST_TIMEOUT,
    )

    assert response.status_code == 401


def test_login_rejects_invalid_signature() -> None:
    account = Account.create()
    wrong_account = Account.create()

    nonce_response = httpx.post(
        f"{API_URL}/auth/nonce",
        json={
            "wallet_address": account.address,
        },
        timeout=REQUEST_TIMEOUT,
    )

    assert nonce_response.status_code == 201

    message = nonce_response.json()["message"]

    wrong_signature = wrong_account.sign_message(
        encode_defunct(text=message)
    ).signature.hex()

    if not wrong_signature.startswith("0x"):
        wrong_signature = f"0x{wrong_signature}"

    login_response = httpx.post(
        f"{API_URL}/auth/login",
        json={
            "message": message,
            "signature": wrong_signature,
        },
        timeout=REQUEST_TIMEOUT,
    )

    assert login_response.status_code == 401

def test_generated_nonce_is_siwe_compatible() -> None:
    nonce = generate_nonce()

    assert len(nonce) >= 8
    assert nonce.isalnum()