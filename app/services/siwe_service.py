def normalize_wallet_address(address: str) -> str:
    ...

def generate_nonce() -> str:
    ...

def build_siwe_message(wallet_address: str, nonce: str) -> str:
    ...

def recover_signer(message: str, signature: str) -> str:
    ...

def verify_siwe_message(
    message: str,
    signature: str,
    expected_nonce: str,
) -> str:
    ...