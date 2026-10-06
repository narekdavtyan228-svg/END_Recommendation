"""Stage 1: contracts. Examples are taken from the architecture document."""

import copy

import pytest
from pydantic import ValidationError

from aicheck.contracts import ActionRequest, CheckRequest, CheckResult
from aicheck.hashing import canonical_bytes, content_hash

pytestmark = pytest.mark.stage1
HASH = "sha256:" + "9b1" * 21 + "9"

REQUEST = {
    "schemaVersion": "1.0",
    "tenant": {"orgCode": "OMG"},
    "end": {"endRef": "end_4f2a", "snapshotVersion": 7, "contentHash": HASH, "mode": "full"},
    "context": {
        "workType": "RPO",
        "categoryCode": "GP",
        "unitCode": "NGDU-2",
        "shopCode": "CPPD",
        "description": "Грузоподъемная работа на скважине 9665",
        "startAt": "2026-09-18T10:41:00+05:00",
        "endAt": "2026-09-21T00:00:00+05:00",
        "flags": {
            "adjacentApproval": False,
            "gasAirControl": False,
            "fireService": False,
            "contractorStaff": False,
        },
        "attachments": [{"kind": "scheme", "count": 1}],
        "catalogVersion": "omg-cat-2026.10.01-3",
    },
    "measures": [
        {
            "rowId": "c40d",
            "section": "5.2",
            "text": "Тест",
            "catalogItemId": None,
            "origin": "manual",
            "notApplicable": False,
        }
    ],
    "risks": [
        {
            "rowId": "a91e",
            "hazardId": 311,
            "victimIds": [12],
            "harmIds": [45],
            "existingControlIds": [801],
            "b1": 2,
            "p1": 3,
            "additionalControlIds": [915],
            "b2": 1,
            "p2": 2,
            "controlResponsibleRoleId": 4,
            "implementWhenId": 1,
        }
    ],
    "factorAnswers": {"F02": "unknown"},
    "locale": "ru",
    "requestedBy": {"userRef": "u_7a3c", "role": "issuer"},
}

RESPONSE = {
    "runId": "r_01J",
    "status": "code_done",
    "llm": "pending",
    "rulesetVersion": "omg-1.1.0",
    "contentHash": HASH,
    "findings": [
        {
            "findingId": "f_8c2",
            "ruleCode": "S02",
            "severity": "critical",
            "kind": "issue",
            "source": "rules",
            "target": {"type": "measure", "section": "5.2", "rowId": "c40d"},
            "title": {"ru": "Тестовое значение", "kk": "…"},
            "message": {"ru": "В пункте 5.2 указано тестовое значение «Тест».", "kk": "…"},
            "evidence": "Тест",
            "recommendation": {
                "mode": "replace",
                "text": {"ru": "…", "kk": "…"},
                "catalogItemIds": [1017],
                "generated": False,
            },
            "basis": {
                "doc": "Правила № 344",
                "clause": "заполнение граф",
                "url": "https://adilet.zan.kz/rus/docs/V2000021151",
                "status": "verified",
            },
            "confidence": 1.0,
        }
    ],
    "questions": [
        {
            "factorCode": "F02",
            "text": {"ru": "Есть ли ВЛ ближе 30 м от крана?", "kk": "…"},
            "options": ["yes", "no"],
        }
    ],
    "autofixes": [{"rowId": "c40d", "ruleCode": "S07", "before": "a", "after": "b"}],
}


def test_architecture_request_example_passes() -> None:
    req = CheckRequest.model_validate(REQUEST)
    assert req.context.startAt and req.context.startAt.utcoffset().total_seconds() == 5 * 3600


def test_architecture_response_example_passes() -> None:
    result = CheckResult.model_validate(RESPONSE)
    assert result.findings[0].message.ru.startswith("В пункте 5.2")


def test_unknown_fields_are_rejected_at_every_level() -> None:
    for path in (
        [],
        ["end"],
        ["context"],
        ["context", "flags"],
        ["measures", 0],
        ["risks", 0],
        ["requestedBy"],
    ):
        body = copy.deepcopy(REQUEST)
        node = body
        for key in path:
            node = node[key]
        node["unexpected"] = 1
        with pytest.raises(ValidationError):
            CheckRequest.model_validate(body)
    with pytest.raises(ValidationError):
        ActionRequest.model_validate({"action": "accept", "extra": 1})


def test_limits() -> None:
    body = copy.deepcopy(REQUEST)
    body["measures"][0]["text"] = "а" * 2001
    with pytest.raises(ValidationError):
        CheckRequest.model_validate(body)
    body = copy.deepcopy(REQUEST)
    body["measures"] = [{**REQUEST["measures"][0], "rowId": f"r{i}"} for i in range(31)]
    with pytest.raises(ValidationError):
        CheckRequest.model_validate(body)
    body = copy.deepcopy(REQUEST)
    body["risks"] = [{**REQUEST["risks"][0], "rowId": f"r{i}"} for i in range(51)]
    with pytest.raises(ValidationError):
        CheckRequest.model_validate(body)


def test_section_and_hash_formats_are_checked() -> None:
    for section in ("5.0", "5.11", "6.1", "5"):
        body = copy.deepcopy(REQUEST)
        body["measures"][0]["section"] = section
        with pytest.raises(ValidationError):
            CheckRequest.model_validate(body)
    body = copy.deepcopy(REQUEST)
    body["end"]["contentHash"] = "md5:1"
    with pytest.raises(ValidationError):
        CheckRequest.model_validate(body)


def test_new_actions_and_modes_exist() -> None:
    assert ActionRequest.model_validate({"action": "reopen"}).action == "reopen"
    result = copy.deepcopy(RESPONSE)
    result["findings"][0]["recommendation"]["mode"] = "not_applicable"
    result["findings"][0]["generated"] = True
    assert CheckResult.model_validate(result).findings[0].generated


def test_canonical_hash_is_stable_and_order_independent() -> None:
    a = CheckRequest.model_validate(REQUEST)
    body = copy.deepcopy(REQUEST)
    body["measures"] = [
        {**REQUEST["measures"][0], "rowId": "b", "section": "5.1"},
        REQUEST["measures"][0],
    ]
    b = CheckRequest.model_validate(body)
    body["measures"].reverse()
    c = CheckRequest.model_validate(body)
    assert content_hash(a) == content_hash(a) and content_hash(b) == content_hash(c)
    assert content_hash(a) != content_hash(b)
    assert canonical_bytes(a).decode().startswith('{"categoryCode":"GP"')


def test_canonical_hash_normalises_strings_and_ignores_service_fields() -> None:
    base = CheckRequest.model_validate(REQUEST)
    body = copy.deepcopy(REQUEST)
    body["measures"][0]["text"] = "  Тест  "
    body["context"]["description"] = "Грузоподъемная работа на скважине 9665\r\n"
    body["requestedBy"]["userRef"] = "other"
    body["end"]["snapshotVersion"] = 99
    body["risks"][0]["additionalControlIds"] = [915]
    other = CheckRequest.model_validate(body)
    assert content_hash(base) == content_hash(other)
    body["measures"][0]["text"] = "Тест2"
    assert content_hash(CheckRequest.model_validate(body)) != content_hash(base)
