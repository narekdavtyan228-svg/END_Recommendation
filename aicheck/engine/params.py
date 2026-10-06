"""Typed access to the machine-readable parameters (`data` of P09-P15) of the rule package."""

from typing import Any

from aicheck.contracts import Risk
from aicheck.engine.context import CheckContext

SEVERITY_TO_P13 = {"high": "high", "medium": "medium", "low": "low"}


def data(ctx: CheckContext, code: str) -> dict[str, Any] | None:
    return ctx.ruleset.config(code)


def r_value(b: int | None, p: int | None) -> int | None:
    return b * p if b is not None and p is not None else None


def scale(ctx: CheckContext, axis: str) -> tuple[int, int] | None:
    """Allowed range of B or P (parameter P10)."""
    cfg = data(ctx, "P10")
    if not cfg:
        return None
    limits = cfg["scale"][axis]
    return int(limits["min"]), int(limits["max"])


def zone_of(ctx: CheckContext, r: int | None) -> str | None:
    """Code of the risk zone of R (acceptable / needs_controls / unacceptable)."""
    cfg = data(ctx, "P10")
    if not cfg or r is None:
        return None
    for zone in cfg["zones"]:
        if int(zone["from"]) <= r <= int(zone["to"]):
            return str(zone["code"])
    return None


def initial_r(risk: Risk) -> int | None:
    return r_value(risk.b1, risk.p1)


def residual_r(ctx: CheckContext, risk: Risk) -> int | None:
    """R after additional controls; without controls it equals the initial R (P10)."""
    own = r_value(risk.b2, risk.p2)
    if own is not None:
        return own
    cfg = data(ctx, "P10") or {}
    if (
        not risk.additionalControlIds
        and cfg.get("residual_if_no_additional_controls") == "equals_initial"
    ):
        return initial_r(risk)
    return None


def before_start_ids(ctx: CheckContext) -> set[int]:
    """IDs of «when to implement» values that mean «before the work starts» (parameter P15)."""
    cfg = data(ctx, "P15") or {}
    return {int(i) for i in cfg.get("implement_before_start_ids", [])}
