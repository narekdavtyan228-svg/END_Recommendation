#!/bin/sh
# Creates throw-away development secrets in ./secrets (never use them in production).
set -e
mkdir -p secrets
umask 077
[ -f secrets/database_url ] || echo "postgresql://aicheck_app:aicheck-dev-password@postgres:5432/aicheck" > secrets/database_url
[ -f secrets/owner_url ] || echo "postgresql://postgres:postgres-dev-password@postgres:5432/aicheck" > secrets/owner_url
[ -f secrets/llm_api_key ] || echo "dev-llm-key" > secrets/llm_api_key
[ -f secrets/callback_hmac_secret ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > secrets/callback_hmac_secret
if [ ! -f secrets/jwt_private_key.pem ]; then
  openssl genrsa -out secrets/jwt_private_key.pem 2048 2>/dev/null
  openssl rsa -in secrets/jwt_private_key.pem -pubout -out secrets/jwt_public_key.pem 2>/dev/null
fi
chmod 644 secrets/*
echo "secrets created in ./secrets"
