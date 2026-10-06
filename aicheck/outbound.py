"""The only way to make outbound HTTP calls: hosts must be on the allow-list, TLS is verified."""

import ssl
from collections.abc import Iterable

import httpx

from aicheck.config import host_of


class OutboundDenied(Exception):
    """The target host is not in ALLOWED_OUTBOUND_HOSTS; no request has been sent."""


def check_url(url: str, allowed: Iterable[str]) -> None:
    if host_of(url) not in {h.lower() for h in allowed}:
        raise OutboundDenied("outbound host is not allowed")


def tls_context(ca_bundle: str | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca_bundle)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def guarded_client(
    allowed: Iterable[str],
    *,
    timeout: float,
    ca_bundle: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    allowed_hosts = tuple(allowed)

    def verify_request(request: httpx.Request) -> None:
        check_url(str(request.url), allowed_hosts)

    return httpx.Client(
        timeout=timeout,
        verify=tls_context(ca_bundle),
        transport=transport,
        follow_redirects=False,
        event_hooks={"request": [verify_request]},
    )
