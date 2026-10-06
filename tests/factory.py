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
    "measures": [
        {
            "id": 1042,
            "section": "5.3",
            "text": "Установить заглушки на трубопроводе",
            "categories": ["GP", "GO"],
        },
        {
            "id": 1017,
            "section": "5.2",
            "text": "Отключить электрооборудование в зоне работ",
            "categories": ["ZR", "GP"],
        },
        {
            "id": 2001,
            "section": "5.5",
            "text": "Оградить место работ сигнальной лентой",
            "categories": ["ZR", "GP", "VS"],
        },
    ],
    "hints": {"5.1": "Остановить технику и оборудование", "5.4": "Взять пробу воздушной среды"},
    "hazards": [
        {
            "id": 311,
            "name": "Обрушение грунта стенок выемки",
            "categories": ["ZR"],
            "victim_ids": [12],
            "harm_ids": [45, 46],
            "control_ids": [801, 802],
        },
        {"id": 312, "name": "Повреждение подземных коммуникаций", "categories": ["ZR"]},
        {"id": 313, "name": "Падение в выемку", "categories": ["ZR"]},
        {"id": 320, "name": "Падение груза", "categories": ["GP"]},
        {"id": 321, "name": "Опрокидывание ГПМ", "categories": ["GP"]},
        {"id": 322, "name": "Защемление, удар грузом", "categories": ["GP"]},
        {"id": 323, "name": "Нарушение связи и сигнализации", "categories": ["GP"]},
        {"id": 324, "name": "Поражение током при приближении к ВЛ", "categories": ["GP"]},
    ],
    "controls": [
        {
            "id": 801,
            "text": "Откосы по проекту",
            "level": "инженерная",
            "affects": "П",
            "section": "5.5",
        },
        {"id": 802, "text": "Крепление стенок", "level": "инженерная", "affects": "П+В"},
        {"id": 915, "text": "Инструктаж бригады", "level": "организационная", "affects": "П"},
        {"id": 916, "text": "Применение СИЗ", "level": "СИЗ", "affects": "П"},
        {"id": 917, "text": "Откосы по проекту.", "level": "инженерная", "affects": "П"},
    ],
    "victims": [{"id": 12, "name": "Работники в выемке"}, {"id": 13, "name": "Посторонние"}],
    "harms": [
        {"id": 45, "name": "Завал"},
        {"id": 46, "name": "Травмы"},
        {"id": 47, "name": "Ожоги"},
    ],
    "implement_when": [{"id": 1, "before_start": True}, {"id": 2, "before_start": False}],
    "profiles": {"NGDU-2": {"objects": [], "factors": {"F10": "no", "F03": "no"}}},
}

PARAMS: dict[str, dict[str, Any]] = {
    "P09": {"warm_from": "04-01", "warm_to": "10-31"},
    "P10": {
        "scale_min": 1,
        "scale_max": 5,
        "zones": {"requires_measures": 6, "high": 12, "unacceptable": 15},
    },
    "P11": {"fire_service": True},
    "P13": {"Высокая": 4, "Средняя": 3},
    "P14": {"threshold": 6},
}


def ruleset(with_params: bool = False) -> Ruleset:
    raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    if with_params:
        for param in raw["parameters"]:
            if param["code"] in PARAMS:
                param["config"] = PARAMS[param["code"]]
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
