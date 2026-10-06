"""JWT authentication: service tokens (RS256, public key) and user tokens (IdP JWKS)."""

import json
import threading
import time
from dataclasses import dataclass

import jwt

from aicheck import metrics
from aicheck.config import Settings
from aicheck.errors import Forbidden, Unauthorized, Unavailable
from aicheck.logging import security_event
from aicheck.outbound import OutboundDenied, guarded_client

JWKS_TTL_S = 600


@dataclass(frozen=True)
class Principal:
    sub: str
    roles: frozenset[str]
    service: bool
    mfa: bool

    @property
    def role(self) -> str:
        return sorted(self.roles)[0] if self.roles else "user"


def _deny(reason: str, error: Unauthorized | Forbidden) -> Unauthorized | Forbidden:
    metrics.AUTH_DENIED.labels(reason=reason).inc()
    security_event("auth_denied", reason=reason)
    return error


class Jwks:
    """IdP signing keys, fetched through the guarded client and cached."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._keys: dict[str, jwt.PyJWK] = {}
        self._loaded = 0.0
        self._lock = threading.Lock()

    def key(self, kid: str) -> jwt.PyJWK:
        with self._lock:
            if kid not in self._keys or time.monotonic() - self._loaded > JWKS_TTL_S:
                self._fetch()
            if kid not in self._keys:
                raise _deny("unknown_key", Unauthorized("invalid token"))
            return self._keys[kid]

    def _fetch(self) -> None:
        s = self._settings
        try:
            with guarded_client(s.allowed_outbound_hosts, timeout=5.0) as client:
                data = json.loads(client.get(s.idp_jwks_url).raise_for_status().text)
        except (OutboundDenied, ValueError, OSError) as exc:
            raise Unavailable("identity provider is unavailable") from exc
        except Exception as exc:  # noqa: BLE001 - httpx errors must not leak details
            raise Unavailable("identity provider is unavailable") from exc
        self._keys = {k["kid"]: jwt.PyJWK(k) for k in data.get("keys", []) if "kid" in k}
        self._loaded = time.monotonic()


def _bearer(header: str | None) -> str:
    if not header or not header.lower().startswith("bearer "):
        raise _deny("missing_token", Unauthorized("authentication required"))
    return header[7:].strip()


def _roles(claims: dict[str, object]) -> frozenset[str]:
    raw = claims.get("roles", claims.get("role", []))
    items = [raw] if isinstance(raw, str) else list(raw) if isinstance(raw, list) else []
    return frozenset(str(r) for r in items)


def _principal(claims: dict[str, object], service: bool) -> Principal:
    amr = claims.get("amr", [])
    return Principal(
        sub=str(claims.get("sub", "")),
        roles=_roles(claims),
        service=service,
        mfa=isinstance(amr, list) and "mfa" in amr,
    )


def authenticate(header: str | None, settings: Settings, jwks: Jwks | None) -> Principal:
    token = _bearer(header)
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        issuer = unverified.get("iss")
        if issuer == settings.jwt_issuer:
            claims = jwt.decode(
                token,
                settings.jwt_public_key,
                algorithms=["RS256"],
                audience=settings.jwt_audience,
                issuer=settings.jwt_issuer,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
            return _principal(claims, True)
        if jwks and settings.idp_issuer and issuer == settings.idp_issuer:
            return _principal(_decode_user(token, settings, jwks), False)
    except jwt.ExpiredSignatureError as exc:
        raise _deny("expired", Unauthorized("token expired")) from exc
    except jwt.PyJWTError as exc:
        raise _deny("invalid_token", Unauthorized("invalid token")) from exc
    raise _deny("unknown_issuer", Unauthorized("invalid token"))


def _decode_user(token: str, settings: Settings, jwks: Jwks) -> dict[str, object]:
    kid = jwt.get_unverified_header(token).get("kid", "")
    key = jwks.key(kid)
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience=settings.idp_audience or None,
        issuer=settings.idp_issuer,
        options={"require": ["exp", "iss", "sub"]},
    )


def require_service(principal: Principal) -> Principal:
    if not (principal.service and "hse-backend" in principal.roles):
        raise _deny("role", Forbidden("insufficient role"))
    return principal


def require_service_or_user(principal: Principal) -> Principal:
    if principal.service:
        return require_service(principal)
    return principal


def require_admin(principal: Principal) -> Principal:
    if not (principal.service and "ai-admin" in principal.roles):
        raise _deny("role", Forbidden("insufficient role"))
    if not principal.mfa:
        raise _deny("mfa_required", Forbidden("multi-factor authentication is required"))
    return principal
