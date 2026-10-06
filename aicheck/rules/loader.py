"""Loading and validation of the rule package (omg_ai_check_rules.json)."""

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aicheck.rules.patterns import PATTERNS

DATA_FILE = Path(__file__).parent / "data" / "omg_ai_check_rules.json"
REQUIRED_KEYS = (
    "version",
    "syntax",
    "inapplicability",
    "matrix",
    "category_rules",
    "factors",
    "markers",
    "stoplist",
    "parameters",
    "sources",
    "risk_rules",
    "hazards",
)
SEVERITY = {
    "Критично": "critical",
    "Существенно": "significant",
    "Рекомендация": "recommendation",
    "Вопрос": "question",
}
FACTOR_CODE = re.compile(r"F\d+")
CASE_INSENSITIVE = {"S02", "S12"}  # the only rules whose text says "без учёта регистра"
CATEGORY_CODE = re.compile(r"\b[A-Z]{2}\b")


class RulesError(Exception):
    """The package is invalid and must not be activated."""


@dataclass(frozen=True)
class MarkerGroup:
    name: str
    stems: tuple[str, ...]
    categories: frozenset[str]
    factors: frozenset[str]
    handled_by: str  # "" or the rule that owns the group (N10)


@dataclass(frozen=True)
class Ruleset:
    raw: dict[str, Any]
    version: str
    sha256: str
    syntax: dict[str, dict[str, Any]]
    inapplicability: dict[str, dict[str, Any]]
    category_rules: dict[str, dict[str, Any]]
    risk_rules: dict[str, dict[str, Any]]
    matrix: dict[tuple[str, str], dict[str, Any]]
    factors: dict[str, dict[str, Any]]
    markers: tuple[MarkerGroup, ...]
    hazards: tuple[dict[str, Any], ...]
    sources: dict[str, dict[str, Any]]
    category_names: dict[str, str]
    patterns: dict[str, list[re.Pattern[str]]] = field(default_factory=dict)
    foreign_norms: tuple[re.Pattern[str], ...] = ()
    params: dict[str, dict[str, Any]] = field(default_factory=dict)

    def rule(self, code: str) -> dict[str, Any]:
        for group in (self.syntax, self.inapplicability, self.category_rules, self.risk_rules):
            if code in group:
                return group[code]
        raise KeyError(code)

    def has_rule(self, code: str) -> bool:
        return any(
            code in g
            for g in (self.syntax, self.inapplicability, self.category_rules, self.risk_rules)
        )

    def config(self, code: str) -> dict[str, Any] | None:
        """Machine-readable parameter value (the `data` object), None while unset."""
        cfg = self.params.get(code, {}).get("data")
        return cfg if isinstance(cfg, dict) and cfg else None


def severity_of(rule: dict[str, Any]) -> str | None:
    return SEVERITY.get(str(rule.get("severity", "")).strip())


def check_type(rule: dict[str, Any]) -> str:
    """code | code_llm | llm | none, derived from the `executor` column."""
    executor = str(rule.get("executor", rule.get("detect", ""))).lower()
    has_code, has_llm = "код" in executor, "llm" in executor
    if has_code and has_llm:
        return "code_llm"
    if has_llm:
        return "llm"
    return "code" if has_code else "none"


def _index(items: list[dict[str, Any]], key: str, section: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if key not in item:
            raise RulesError(f"{section}: record without '{key}'")
        if item[key] in result:
            raise RulesError(f"{section}: duplicate id {item[key]}")
        result[item[key]] = item
    return result


def _compile_patterns(syntax: dict[str, dict[str, Any]]) -> dict[str, list[re.Pattern[str]]]:
    compiled: dict[str, list[re.Pattern[str]]] = {}
    for code, pieces in PATTERNS.items():
        detect = str(syntax.get(code, {}).get("detect", ""))
        for piece in pieces:
            if piece not in detect:
                raise RulesError(f"{code}: pattern is not present in the rule text")
        try:
            flags = re.IGNORECASE if code in CASE_INSENSITIVE else 0
            compiled[code] = [re.compile(p, flags) for p in pieces]
        except re.error as exc:
            raise RulesError(f"{code}: regex does not compile") from exc
    return compiled


def _markers(items: list[dict[str, Any]]) -> tuple[MarkerGroup, ...]:
    groups = []
    for item in items:
        stems = tuple(s.strip() for s in str(item["stems"]).split(",") if s.strip())
        factors = str(item["allowed_factors"])
        groups.append(
            MarkerGroup(
                name=item["group"],
                stems=stems,
                categories=frozenset(CATEGORY_CODE.findall(str(item["allowed_categories"]))),
                factors=frozenset(FACTOR_CODE.findall(factors)),
                handled_by="N10" if "N10" in factors else "",
            )
        )
    return tuple(groups)


def _foreign_norms(stoplist: list[dict[str, Any]]) -> tuple[re.Pattern[str], ...]:
    patterns: list[re.Pattern[str]] = []
    for group in stoplist:
        if group.get("rule") != "N11":
            continue
        for token in _split_tokens(str(group["values"])):
            patterns.append(_token_pattern(token))
    return tuple(patterns)


def _split_tokens(values: str) -> list[str]:
    return [t.strip().strip("«»").replace(" (РФ)", "").strip("» ") for t in values.split(", ")]


def _token_pattern(token: str) -> re.Pattern[str]:
    """Phrase match; inflected endings are allowed after a long last word (Ростехнадзора)."""
    body = re.escape(token).replace(r"\ ", r"\s+")
    if re.fullmatch(r"\d+н?", token):  # bare order numbers need their context
        body = rf"(?:приказ\w*\s*)?№\s*{body}"
    last_word = re.split(r"\s+", token)[-1]
    strict = len(last_word) <= 3 or last_word[-1].isdigit()
    tail = r"(?!\w)" if strict and not token.endswith("-") else ""
    return re.compile(rf"(?<!\w){body}{tail}", re.IGNORECASE)


def parse_ruleset(text: str | bytes) -> Ruleset:
    try:
        raw = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise RulesError("rule package is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise RulesError("rule package must be a JSON object")
    missing = [k for k in REQUIRED_KEYS if k not in raw]
    if missing:
        raise RulesError("missing sections: " + ", ".join(missing))
    try:
        syntax = _index(raw["syntax"], "id", "syntax")
        matrix = {(m["code"], m["section"]): m for m in raw["matrix"]}
        names = {m["code"]: m["category"] for m in raw["matrix"]}
        sha = hashlib.sha256(text if isinstance(text, bytes) else text.encode()).hexdigest()
        return Ruleset(
            raw=raw,
            version=str(raw["version"]),
            sha256=sha,
            syntax=syntax,
            inapplicability=_index(raw["inapplicability"], "id", "inapplicability"),
            category_rules=_index(raw["category_rules"], "id", "category_rules"),
            risk_rules=_index(raw["risk_rules"], "id", "risk_rules"),
            matrix=matrix,
            factors=_index(raw["factors"], "code", "factors"),
            markers=_markers(raw["markers"]),
            hazards=tuple(raw["hazards"]),
            sources=_index(raw["sources"], "code", "sources"),
            category_names=names,
            patterns=_compile_patterns(syntax),
            foreign_norms=_foreign_norms(raw["stoplist"]),
            params=_index(raw["parameters"], "code", "parameters"),
        )
    except (KeyError, TypeError) as exc:
        raise RulesError("rule package has an invalid structure") from exc


def load_packaged() -> Ruleset:
    return parse_ruleset(DATA_FILE.read_bytes())
