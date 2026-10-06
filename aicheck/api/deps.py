"""FastAPI dependencies: runtime, authentication and role checks."""

from typing import Annotated

from fastapi import Depends, Header, Request

from aicheck.api import auth
from aicheck.api.auth import Principal
from aicheck.runs import Actor
from aicheck.runtime import Runtime


def get_rt(request: Request) -> Runtime:
    rt: Runtime = request.app.state.rt
    return rt


def get_principal(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> Principal:
    return auth.authenticate(authorization, request.app.state.rt.settings, request.app.state.jwks)


def service_only(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
    return auth.require_service(principal)


def service_or_user(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
    return auth.require_service_or_user(principal)


def admin_only(principal: Annotated[Principal, Depends(get_principal)]) -> Principal:
    return auth.require_admin(principal)


def to_actor(principal: Principal) -> Actor:
    return Actor(principal.sub, principal.role, principal.service)


Rt = Annotated[Runtime, Depends(get_rt)]
ServiceP = Annotated[Principal, Depends(service_only)]
AnyP = Annotated[Principal, Depends(service_or_user)]
AdminP = Annotated[Principal, Depends(admin_only)]
