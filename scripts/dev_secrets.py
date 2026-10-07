"""Creates throw-away development secrets in ./secrets (cross-platform twin of dev_secrets.sh).

Never use them in production. Needs the `cryptography` package for the JWT key pair.
"""

import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DIR = Path("secrets")
TEXT = {
    "database_url": "postgresql://aicheck_app:aicheck-dev-password@postgres:5432/aicheck",
    "owner_url": "postgresql://postgres:postgres-dev-password@postgres:5432/aicheck",
    "llm_api_key": "dev-llm-key",
    "callback_hmac_secret": secrets.token_hex(32),
}


def main() -> None:
    DIR.mkdir(exist_ok=True)
    for name, value in TEXT.items():
        path = DIR / name
        if not path.exists():
            path.write_text(value, encoding="ascii", newline="")
    if not (DIR / "jwt_private_key.pem").exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        (DIR / "jwt_private_key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (DIR / "jwt_public_key.pem").write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    print("secrets created in ./secrets")


if __name__ == "__main__":
    main()
