"""Mints a development JWT for local calls: python scripts/dev_token.py hse-backend|ai-admin."""

import sys
import time
from pathlib import Path

import jwt

ROLE = sys.argv[1] if len(sys.argv) > 1 else "hse-backend"
KEY = Path(sys.argv[2] if len(sys.argv) > 2 else "secrets/jwt_private_key.pem").read_text(
    encoding="utf-8"
)
claims = {
    "iss": "https://idp.dev.local",
    "aud": "ai-check",
    "sub": "dev-" + ROLE,
    "roles": [ROLE],
    "exp": int(time.time()) + 3600,
}
if ROLE == "ai-admin":
    claims["amr"] = ["pwd", "mfa"]
sys.stdout.write(jwt.encode(claims, KEY, algorithm="RS256") + "\n")
