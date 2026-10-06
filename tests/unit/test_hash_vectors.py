"""contentHash: the shared vectors and an independent implementation of the written rules."""

import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from aicheck.contracts import CheckRequest
from aicheck.hashing import content_hash

pytestmark = pytest.mark.stage4
VECTORS = json.loads(
    (Path(__file__).parents[1] / "golden" / "hash_vectors.json").read_text(encoding="utf-8")
)


def reference(body: dict[str, Any]) -> str:
    """Written independently of aicheck.hashing, straight from the rules of the specification."""

    def s(value: Any) -> Any:
        if value is None:
            return None
        return unicodedata.normalize("NFC", value).replace("\r\n", "\n").strip()

    ctx = body["context"]
    flags = ctx.get("flags") or {}
    obj = {
        "orgCode": s(body["tenant"]["orgCode"]),
        "workType": s(ctx["workType"]),
        "categoryCode": s(ctx["categoryCode"]),
        "description": s(ctx.get("description")),
        "flags": {
            k: flags.get(k)
            for k in ("adjacentApproval", "contractorStaff", "fireService", "gasAirControl")
        },
        "measures": [
            {
                "rowId": s(m["rowId"]),
                "section": m["section"],
                "text": s(m.get("text")),
                "notApplicable": m.get("notApplicable"),
            }
            for m in sorted(body["measures"], key=lambda m: (m["section"], m["rowId"]))
        ],
        "risks": [
            {
                "rowId": s(r["rowId"]),
                "hazardId": r.get("hazardId"),
                "victimIds": sorted(r.get("victimIds") or []),
                "harmIds": sorted(r.get("harmIds") or []),
                "existingControlIds": sorted(r.get("existingControlIds") or []),
                "b1": r.get("b1"),
                "p1": r.get("p1"),
                "additionalControlIds": sorted(r.get("additionalControlIds") or []),
                "b2": r.get("b2"),
                "p2": r.get("p2"),
                "controlResponsibleRoleId": r.get("controlResponsibleRoleId"),
                "implementWhenId": r.get("implementWhenId"),
            }
            for r in sorted(body["risks"], key=lambda r: r["rowId"])
        ],
        "factorAnswers": body.get("factorAnswers") or {},
    }
    text = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_there_are_ten_vectors() -> None:
    assert len(VECTORS) == 10 and len({v["title"] for v in VECTORS}) == 10


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["title"])
def test_vector_matches_the_service_and_the_reference(vector: dict[str, Any]) -> None:
    request = CheckRequest.model_validate(vector["input"])
    assert content_hash(request) == vector["contentHash"] == reference(vector["input"])
    assert vector["canonical"].encode("utf-8") and "\\u" not in vector["canonical"]


def test_the_hash_changes_when_the_content_changes_and_not_for_service_fields() -> None:
    by_title = {v["title"]: v["contentHash"] for v in VECTORS}
    assert (
        by_title["base"]
        == by_title["rows are sorted by section then rowId"]
        == by_title["service fields do not change the hash"]
    )
    assert (
        by_title["base"]
        == by_title["id arrays are sorted"]
        == by_title["answers are sorted by factor code"]
    )
    assert by_title["base"] != by_title["string normalisation: edges and CRLF"]
    assert len(set(by_title.values())) == 5
