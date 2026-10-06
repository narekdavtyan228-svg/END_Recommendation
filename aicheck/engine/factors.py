"""Factor resolution: answers -> section 2 flags -> description stems -> unit profile."""

from dataclasses import dataclass

from aicheck.catalog.model import Catalog
from aicheck.contracts import CheckRequest
from aicheck.engine.normalize import find_stem
from aicheck.rules.loader import Ruleset


@dataclass(frozen=True)
class FactorValue:
    value: str  # yes | no | unknown
    source: str  # answer | flag | description | profile | none


def resolve_factors(
    request: CheckRequest, ruleset: Ruleset, catalog: Catalog
) -> dict[str, FactorValue]:
    profile = catalog.profiles.get(request.context.unitCode or "", {})
    profile_factors: dict[str, str] = profile.get("factors", {})
    from_description = _from_description(request.context.description, ruleset)
    result: dict[str, FactorValue] = {}
    for code in ruleset.factors:
        result[code] = _resolve_one(code, request, from_description, profile_factors)
    return result


def _resolve_one(
    code: str, request: CheckRequest, from_description: set[str], profile: dict[str, str]
) -> FactorValue:
    answer = request.factorAnswers.get(code, "unknown")
    if answer != "unknown":
        return FactorValue(answer, "answer")
    if code == "F03" and request.context.flags.gasAirControl:
        return FactorValue("yes", "flag")
    if code in from_description:
        return FactorValue("yes", "description")
    if profile.get(code) in ("yes", "no"):
        return FactorValue(profile[code], "profile")
    return FactorValue("unknown", "none")


def _from_description(description: str, ruleset: Ruleset) -> set[str]:
    """Marker groups tied to exactly one factor imply that factor when found in the text."""
    found: set[str] = set()
    for group in ruleset.markers:
        if len(group.factors) == 1 and find_stem(description, group.stems):
            found.update(group.factors)
    return found


def factor_state(codes: list[str], factors: dict[str, FactorValue]) -> str:
    """Combine several factors: yes if any is yes, no if all are no, otherwise unknown."""
    values = [factors[c].value if c in factors else "unknown" for c in codes]
    if "yes" in values:
        return "yes"
    return "no" if values and all(v == "no" for v in values) else "unknown"
