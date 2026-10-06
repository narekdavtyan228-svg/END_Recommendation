"""Generates tests/golden/hash_vectors.json: 10 inputs and the expected contentHash for HSE."""

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from aicheck.contracts import CheckRequest  # noqa: E402
from aicheck.hashing import canonical_bytes, content_hash  # noqa: E402

BASE = {
    "schemaVersion": "1.0",
    "tenant": {"orgCode": "OMG"},
    "end": {
        "endRef": "end_1",
        "snapshotVersion": 1,
        "contentHash": "sha256:" + "0" * 64,
        "mode": "full",
    },
    "context": {
        "workType": "RPO",
        "categoryCode": "GP",
        "unitCode": "NGDU-2",
        "shopCode": None,
        "description": "Грузоподъемная работа",
        "startAt": "2026-09-18T10:41:00+05:00",
        "endAt": None,
        "flags": {
            "adjacentApproval": True,
            "gasAirControl": False,
            "fireService": None,
            "contractorStaff": False,
        },
        "attachments": [],
        "catalogVersion": "v1",
    },
    "measures": [
        {
            "rowId": "b",
            "section": "5.10",
            "text": "Инструктаж бригады",
            "origin": "manual",
            "notApplicable": False,
        },
        {
            "rowId": "a",
            "section": "5.2",
            "text": "Отключить кабель",
            "origin": "catalog",
            "notApplicable": False,
        },
    ],
    "risks": [
        {
            "rowId": "r2",
            "hazardId": 5,
            "victimIds": [3, 1],
            "harmIds": [2],
            "existingControlIds": [9, 7],
            "b1": 3,
            "p1": 2,
            "additionalControlIds": [],
            "b2": None,
            "p2": None,
            "controlResponsibleRoleId": None,
            "implementWhenId": None,
        }
    ],
    "factorAnswers": {"F05": "no", "F02": "yes"},
    "locale": "ru",
    "requestedBy": {"userRef": "u", "role": "issuer"},
}


def variant(title: str, edit) -> dict:
    body = copy.deepcopy(BASE)
    edit(body)
    request = CheckRequest.model_validate(body)
    return {
        "title": title,
        "input": body,
        "canonical": canonical_bytes(request).decode(),
        "contentHash": content_hash(request),
    }


def main() -> None:
    vectors = [
        variant("base", lambda b: None),
        variant("rows are sorted by section then rowId", lambda b: b["measures"].reverse()),
        variant(
            "string normalisation: edges and CRLF",
            lambda b: b["measures"][0].update(text="  Инструктаж\r\nбригады \n"),
        ),
        variant(
            "Unicode NFC (decomposed letter)",
            lambda b: b["context"].update(description="Кра\u0438\u0306ний пункт работ"),
        ),
        variant(
            "not applicable row without text",
            lambda b: b["measures"].append(
                {
                    "rowId": "c",
                    "section": "5.7",
                    "text": "",
                    "origin": "manual",
                    "notApplicable": True,
                }
            ),
        ),
        variant(
            "id arrays are sorted",
            lambda b: b["risks"][0].update(victimIds=[1, 3], existingControlIds=[7, 9]),
        ),
        variant("null scalars stay null", lambda b: b["risks"][0].update(b2=None, p2=None)),
        variant(
            "answers are sorted by factor code",
            lambda b: b.update(factorAnswers={"F02": "yes", "F05": "no"}),
        ),
        variant(
            "non-ASCII text is not escaped",
            lambda b: b["measures"][1].update(text="Кабель «№ 5» — отключить"),
        ),
        variant(
            "service fields do not change the hash",
            lambda b: (
                b["requestedBy"].update(userRef="other"),
                b["end"].update(snapshotVersion=42),
            ),
        ),
    ]
    out = Path(__file__).parent / "hash_vectors.json"
    out.write_text(json.dumps(vectors, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{len(vectors)} vectors")  # noqa: T201


if __name__ == "__main__":
    main()
