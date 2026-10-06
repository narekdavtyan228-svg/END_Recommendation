"""Builders for requests, catalogs and rule packages used by tests."""

import copy
import json
from typing import Any

from aicheck.catalog.model import Catalog
from aicheck.contracts import CheckRequest
from aicheck.hashing import content_hash
from aicheck.rules.loader import DATA_FILE, Ruleset, parse_ruleset

CATALOG_BODY: dict[str, Any] = {
    "version": "omg-cat-test-1",
    "orgCode": "OMG",
    "measures": [
        {
            "id": 1042,
            "section": "5.3",
            "text_ru": "Установить заглушки на трубопроводе",
            "category": "GP",
            "item_type": "core",
        },
        {
            "id": 1017,
            "section": "5.2",
            "text_ru": "Отключить электрооборудование в зоне работ",
            "category": "GP",
            "item_type": "conditional",
            "factors": ["F09"],
        },
        {
            "id": 2001,
            "section": "5.5",
            "text_ru": "Оградить место работ сигнальной лентой",
            "category": "GP",
            "item_type": "core",
        },
    ],
    "hints": {"5.1": "Остановить технику и оборудование", "5.4": "Взять пробу воздушной среды"},
    "hazards": [
        {
            "id": 311,
            "category": "ZR",
            "name": "Обрушение грунта стенок выемки",
            "required": "always",
            "min_severity_level": "high",
            "victim_ids": [12],
            "harm_ids": [45, 46],
            "typical_existing_control_ids": [801, 802],
            "typical_additional_control_ids": [],
            "linked_sections": ["5.6", "5.10"],
            "severity_if_missing": "critical",
        },
        {
            "id": 312,
            "category": "ZR",
            "name": "Повреждение подземных коммуникаций",
            "required": "factor",
            "factors": ["F27"],
            "min_severity_level": "high",
            "severity_if_missing": "critical",
        },
        {
            "id": 313,
            "category": "ZR",
            "name": "Падение в выемку",
            "required": "always",
            "min_severity_level": "medium",
            "severity_if_missing": "significant",
        },
        {
            "id": 320,
            "category": "GP",
            "name": "Падение груза",
            "required": "always",
            "min_severity_level": "high",
            "severity_if_missing": "critical",
        },
        {
            "id": 321,
            "category": "GP",
            "name": "Опрокидывание ГПМ",
            "required": "always",
            "min_severity_level": "high",
            "severity_if_missing": "critical",
        },
        {
            "id": 322,
            "category": "GP",
            "name": "Защемление, удар грузом",
            "required": "always",
            "min_severity_level": "medium",
            "severity_if_missing": "significant",
        },
        {
            "id": 323,
            "category": "GP",
            "name": "Нарушение связи и сигнализации",
            "required": "always",
            "min_severity_level": "medium",
            "severity_if_missing": "significant",
        },
        {
            "id": 324,
            "category": "GP",
            "name": "Поражение током при приближении к ВЛ",
            "required": "factor",
            "factors": ["F02"],
            "min_severity_level": "high",
            "severity_if_missing": "critical",
        },
    ],
    "controls": [
        {
            "id": 801,
            "name": "Откосы по проекту",
            "hierarchy_level": "engineering",
            "affects": "P",
            "linked_section": "5.5",
        },
        {"id": 802, "name": "Крепление стенок", "hierarchy_level": "engineering", "affects": "PB"},
        {
            "id": 915,
            "name": "Инструктаж бригады",
            "hierarchy_level": "administrative",
            "affects": "P",
        },
        {"id": 916, "name": "Применение СИЗ", "hierarchy_level": "ppe", "affects": "P"},
        {"id": 917, "name": "Откосы по проекту.", "hierarchy_level": "engineering", "affects": "P"},
    ],
    "victims": [{"id": 12, "name": "Работники в выемке"}, {"id": 13, "name": "Посторонние"}],
    "harms": [
        {"id": 45, "name": "Завал"},
        {"id": 46, "name": "Травмы"},
        {"id": 47, "name": "Ожоги"},
    ],
    "roles": [{"id": 4, "name": "Производитель работ"}],
    "implement_when": [{"id": 1, "name": "До начала работ"}, {"id": 2, "name": "В ходе работ"}],
    "profiles": [
        {"unitCode": "NGDU-2", "objects": [], "factor_defaults": {"F10": "no", "F03": "no"}}
    ],
}

PARAMS: dict[str, dict[str, Any]] = {
    "P09": {
        "timezone": "+05:00",
        "warm": {"from": "04-15", "to": "10-15"},
        "cold": {"from": "11-15", "to": "03-15"},
    },
    "P10": {
        "scale": {"B": {"min": 1, "max": 5}, "P": {"min": 1, "max": 5}},
        "zones": [
            {"code": "acceptable", "from": 1, "to": 4},
            {"code": "needs_controls", "from": 5, "to": 14},
            {"code": "unacceptable", "from": 15, "to": 25},
        ],
        "residual_if_no_additional_controls": "equals_initial",
        "high_zone_for_RA23": "unacceptable",
    },
    "P11": {
        "category": "OG",
        "flag": "fireService",
        "required_value": True,
        "when_any_factor_yes": ["F03", "F31", "F34"],
        "severity": "significant",
    },
    "P13": {"high": 4, "medium": 3, "low": 1},
    "P14": {"min_R": 5},
    "P15": {"implement_before_start_ids": [1]},
}


def ruleset(with_params: bool = False) -> Ruleset:
    raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    for param in raw["parameters"]:
        if param["code"] in PARAMS:  # without parameters the dependent rules stay silent
            param.pop("data", None)
            if with_params:
                param["data"] = PARAMS[param["code"]]
    return parse_ruleset(json.dumps(raw, ensure_ascii=False))


def catalog(**overrides: Any) -> Catalog:
    body = copy.deepcopy(CATALOG_BODY)
    body.update(overrides)
    return Catalog.from_body(body)


def request(
    category: str = "GP",
    measures: list[dict[str, Any]] | None = None,
    risks: list[dict[str, Any]] | None = None,
    **context: Any,
) -> CheckRequest:
    """A request whose contentHash is computed from the content."""
    ctx: dict[str, Any] = {
        "workType": "RPO",
        "categoryCode": category,
        "unitCode": "NGDU-2",
        "description": "Грузоподъемная работа на скважине 9665",
        "startAt": "2026-09-18T10:41:00+05:00",
        "endAt": "2026-09-21T00:00:00+05:00",
        "flags": {
            "adjacentApproval": True,
            "gasAirControl": True,
            "fireService": True,
            "contractorStaff": False,
        },
        "attachments": [{"kind": "scheme", "count": 1}],
        "catalogVersion": "omg-cat-test-1",
    }
    ctx.update(context)
    body: dict[str, Any] = {
        "schemaVersion": "1.0",
        "tenant": {"orgCode": "OMG"},
        "end": {
            "endRef": "end_1",
            "snapshotVersion": 1,
            "contentHash": "sha256:" + "0" * 64,
            "mode": "full",
        },
        "context": ctx,
        "measures": [
            {"rowId": f"m{i}", "origin": "manual", "notApplicable": False, **m}
            for i, m in enumerate(measures or [])
        ],
        "risks": [{"rowId": f"r{i}", **r} for i, r in enumerate(risks or [])],
        "factorAnswers": {},
        "locale": "ru",
        "requestedBy": {"userRef": "u_1", "role": "issuer"},
    }
    req = CheckRequest.model_validate(body)
    body["end"]["contentHash"] = content_hash(req)
    return CheckRequest.model_validate(body)


def with_answers(req: CheckRequest, answers: dict[str, str]) -> CheckRequest:
    body = req.model_dump(mode="json")
    body["factorAnswers"] = answers
    return CheckRequest.model_validate(body)
