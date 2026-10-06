"""Stage 6: document base: upload, parse, edit, activate, diff, links, retrieval, SEC-14."""

import dataclasses
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from aicheck.api.app import create_app
from aicheck.db import kb_queries
from aicheck.db.engine import Database
from aicheck.kb import ingest, retrieve
from aicheck.runtime import Runtime
from tests import factory, kbfiles

pytestmark = pytest.mark.stage6
META = {
    "code": "RK-355",
    "title": "Правила ПБ для ОПО",
    "number": "355",
    "layer": "law",
    "source_url": "https://adilet.zan.kz/rus/docs/V1400010250",
    "categories": [],
    "org_codes": [],
    "work_types": [],
}


def upload(
    client: TestClient, admin: dict[str, str], data: bytes, name: str = "law.txt", **meta: Any
) -> Any:
    return client.post(
        "/v1/admin/kb/documents",
        headers=admin,
        files={"file": (name, data, "application/octet-stream")},
        data={"meta": json.dumps({**META, **meta})},
    )


def parsed(
    client: TestClient,
    admin: dict[str, str],
    rt: Runtime,
    data: bytes | None = None,
    name: str = "law.txt",
    **meta: Any,
) -> int:
    doc_id = upload(client, admin, kbfiles.txt() if data is None else data, name, **meta).json()[
        "id"
    ]
    assert ingest.process_next(rt) is True
    return doc_id


def doc(client: TestClient, admin: dict[str, str], doc_id: int) -> dict[str, Any]:
    return client.get(f"/v1/admin/kb/documents/{doc_id}", headers=admin).json()


def clause_id(d: dict[str, Any], no: str) -> int:
    return next(c["id"] for c in d["clauses"] if c["clause_no"] == no)


def test_upload_creates_a_draft_and_a_parse_job(
    client: TestClient, admin: dict[str, str], rt: Runtime
) -> None:
    r = upload(client, admin, kbfiles.txt())
    assert r.status_code == 201 and r.json()["status"] == "draft"
    assert doc(client, admin, r.json()["id"])["parse_report"] is None  # not parsed yet
    assert ingest.process_next(rt) is True and ingest.process_next(rt) is False
    d = doc(client, admin, r.json()["id"])
    assert d["parse_report"]["clauses"] == 6 and len(d["clauses"]) == 6 and d["version_no"] == 1
    assert "file_bytes" not in d


def test_pdf_and_docx_documents_are_parsed(
    client: TestClient, admin: dict[str, str], rt: Runtime
) -> None:
    for data, name in ((kbfiles.pdf(), "law.pdf"), (kbfiles.docx(), "law.docx")):
        d = doc(client, admin, parsed(client, admin, rt, data, name, code=f"D-{name}"))
        assert {"1", "33", "128"} <= {c["clause_no"] for c in d["clauses"]}


def test_scanned_pdf_gives_a_clear_error_and_cannot_be_activated(
    client: TestClient, admin: dict[str, str], rt: Runtime
) -> None:
    doc_id = parsed(client, admin, rt, kbfiles.pdf_without_text(), "scan.pdf")
    d = doc(client, admin, doc_id)
    assert "нет текстового слоя" in d["parse_report"]["error"]
    r = client.post(f"/v1/admin/kb/documents/{doc_id}/activate", headers=admin)
    assert r.status_code == 409 and r.json()["error"]["code"] == "not_parsed"


def test_sec14_upload_requires_admin_with_mfa(
    client: TestClient, hse: dict[str, str], token: Any
) -> None:
    files = {"file": ("a.txt", kbfiles.txt(), "text/plain")}
    assert (
        client.post(
            "/v1/admin/kb/documents", headers=hse, files=files, data={"meta": json.dumps(META)}
        ).status_code
        == 403
    )
    no_mfa = {"Authorization": "Bearer " + token(["ai-admin"], mfa=False)}
    assert (
        client.post(
            "/v1/admin/kb/documents", headers=no_mfa, files=files, data={"meta": json.dumps(META)}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/v1/admin/kb/documents", files=files, data={"meta": json.dumps(META)}
        ).status_code
        == 401
    )
    assert client.get("/v1/admin/kb/documents", headers=hse).status_code == 403


def test_sec14_file_type_is_checked_by_signature_and_size(
    client: TestClient, admin: dict[str, str], rt: Runtime
) -> None:
    assert (
        upload(client, admin, b"not a pdf at all", "a.pdf").json()["error"]["code"]
        == "file_type_invalid"
    )
    assert upload(client, admin, b"PK\x03\x04 not a docx", "a.docx").status_code == 422
    assert upload(client, admin, b"zip\x00bytes", "a.txt").status_code == 422
    assert upload(client, admin, kbfiles.pdf(), "a.exe").status_code == 422
    assert (
        upload(client, admin, kbfiles.txt(), "a.pdf").status_code == 422
    )  # extension and content disagree
    small = dataclasses.replace(rt.settings, kb_max_file_mb=1)
    limited = TestClient(create_app(Runtime(settings=small, db=rt.db)))
    big = b"1. text\n" * 190_000  # about 1.5 MB: above the file limit, below the body limit
    r = upload(limited, admin, big)
    assert r.status_code == 422 and r.json()["error"]["code"] == "file_too_large"
    huge = b"x" * (3 * 1024 * 1024)
    assert upload(limited, admin, huge).status_code == 413


def test_sec14_bad_metadata_is_rejected(client: TestClient, admin: dict[str, str]) -> None:
    for meta in (
        {"code": "bad code!"},
        {"layer": "other"},
        {"source_url": "http://insecure"},
        {"unknown": 1},
    ):
        assert upload(client, admin, kbfiles.txt(), **meta).status_code == 422
    files = {"file": ("a.txt", kbfiles.txt(), "text/plain")}
    assert (
        client.post(
            "/v1/admin/kb/documents", headers=admin, files=files, data={"meta": "{bad"}
        ).status_code
        == 422
    )


def test_sec14_every_change_is_in_kb_event(
    client: TestClient, admin: dict[str, str], rt: Runtime, db: Database
) -> None:
    doc_id = parsed(client, admin, rt)
    d = doc(client, admin, doc_id)
    client.patch(
        f"/v1/admin/kb/clauses/{clause_id(d, '2')}",
        headers=admin,
        json={"body": "Исправленный текст пункта"},
    )
    client.patch(f"/v1/admin/kb/documents/{doc_id}", headers=admin, json={"categories": ["OG"]})
    client.post(f"/v1/admin/kb/documents/{doc_id}/activate", headers=admin)
    client.put(
        "/v1/admin/kb/rule-refs",
        headers=admin,
        json={"refs": [{"rule_code": "OG-01", "doc_code": "RK-355", "clause_no": "1"}]},
    )
    with db.tx() as conn:
        actions = [
            r[0] for r in conn.execute(text("SELECT action FROM aicheck.kb_event ORDER BY id"))
        ]
    assert actions == ["upload", "parse", "clause_edit", "doc_edit", "activate", "rule_refs"]


def test_expert_edits_clauses_in_a_draft_only(
    client: TestClient, admin: dict[str, str], rt: Runtime
) -> None:
    doc_id = parsed(client, admin, rt)
    d = doc(client, admin, doc_id)
    cid = clause_id(d, "2")
    assert (
        client.patch(
            f"/v1/admin/kb/clauses/{cid}",
            headers=admin,
            json={"clause_no": "2a", "body": "Новый текст"},
        ).status_code
        == 200
    )
    assert (
        client.patch(
            f"/v1/admin/kb/clauses/{clause_id(d, '1')}", headers=admin, json={"excluded": True}
        ).status_code
        == 200
    )
    after = doc(client, admin, doc_id)
    edited = next(c for c in after["clauses"] if c["id"] == cid)
    assert (
        edited["clause_no"] == "2a"
        and edited["body"] == "Новый текст"
        and edited["body_sha256"] != next(c for c in d["clauses"] if c["id"] == cid)["body_sha256"]
    )
    client.post(f"/v1/admin/kb/documents/{doc_id}/activate", headers=admin)
    assert (
        client.patch(
            f"/v1/admin/kb/clauses/{cid}", headers=admin, json={"body": "Поздно"}
        ).status_code
        == 409
    )
    assert (
        client.patch("/v1/admin/kb/clauses/999999", headers=admin, json={"body": "x"}).status_code
        == 404
    )
    assert (
        client.patch(f"/v1/admin/kb/clauses/{cid}", headers=admin, json={"nope": 1}).status_code
        == 422
    )


def test_activation_archives_the_previous_version(
    client: TestClient, admin: dict[str, str], rt: Runtime
) -> None:
    first = parsed(client, admin, rt)
    assert (
        client.post(f"/v1/admin/kb/documents/{first}/activate", headers=admin).json()["status"]
        == "active"
    )
    assert (
        client.post(f"/v1/admin/kb/documents/{first}/activate", headers=admin).status_code == 409
    )  # not a draft any more
    second = parsed(client, admin, rt, kbfiles.txt(kbfiles.LAW + "129. Новый пункт.\n"))
    assert doc(client, admin, second)["version_no"] == 2
    client.post(f"/v1/admin/kb/documents/{second}/activate", headers=admin)
    assert (
        doc(client, admin, first)["status"] == "archived"
        and doc(client, admin, second)["status"] == "active"
    )
    listed = client.get("/v1/admin/kb/documents", params={"status": "active"}, headers=admin).json()
    assert [d["id"] for d in listed] == [second]
    assert client.post("/v1/admin/kb/documents/999/activate", headers=admin).status_code == 404


def test_diff_lists_changes_and_affected_rules(
    client: TestClient, admin: dict[str, str], rt: Runtime
) -> None:
    first = parsed(client, admin, rt)
    client.post(f"/v1/admin/kb/documents/{first}/activate", headers=admin)
    client.put(
        "/v1/admin/kb/rule-refs",
        headers=admin,
        json={
            "refs": [
                {"rule_code": "ZR-04", "doc_code": "RK-355", "clause_no": "33"},
                {"rule_code": "ZR-03", "doc_code": "RK-355", "clause_no": "128"},
                {"rule_code": "OG-01", "doc_code": "RK-355", "clause_no": "1"},
            ]
        },
    )
    changed = (
        kbfiles.LAW.replace("не менее одного метра", "не менее полутора метров")
        .replace("2. Перед началом газоопасных работ", "2. Перед началом любых газоопасных работ")
        .replace("33. Работы", "34. Работы")
    )
    second = parsed(client, admin, rt, kbfiles.txt(changed))
    d = client.get(f"/v1/admin/kb/documents/{second}/diff", headers=admin).json()
    assert d["code"] == "RK-355" and d["against"] == first
    assert "34" in d["added"] and "33" in d["removed"] and {"2", "128"} <= set(d["changed"])
    affected = {(r["rule_code"], r["clause_no"]) for r in d["affected_rules"]}
    assert affected == {("ZR-04", "33"), ("ZR-03", "128")}  # OG-01 clause 1 did not change


def test_diff_of_a_first_version_has_everything_added(
    client: TestClient, admin: dict[str, str], rt: Runtime
) -> None:
    first = parsed(client, admin, rt)
    d = client.get(f"/v1/admin/kb/documents/{first}/diff", headers=admin).json()
    assert d["against"] is None and len(d["added"]) == 6 and d["removed"] == []
    assert client.get("/v1/admin/kb/documents/999/diff", headers=admin).status_code == 404


def test_broken_links_are_reported(client: TestClient, admin: dict[str, str], rt: Runtime) -> None:
    refs = {
        "refs": [
            {"rule_code": "ZR-04", "doc_code": "RK-355", "clause_no": "33"},
            {"rule_code": "ZR-03", "doc_code": "RK-355", "clause_no": "999"},
            {"rule_code": "OG-01", "doc_code": "NO-DOC", "clause_no": "1"},
        ]
    }
    assert client.put("/v1/admin/kb/rule-refs", headers=admin, json=refs).json() == {"count": 3}
    broken = client.get("/v1/admin/kb/rule-refs/broken", headers=admin).json()
    assert len(broken) == 3  # nothing is active yet
    first = parsed(client, admin, rt)
    client.post(f"/v1/admin/kb/documents/{first}/activate", headers=admin)
    broken = client.get("/v1/admin/kb/rule-refs/broken", headers=admin).json()
    assert {(b["rule_code"], b["clause_no"]) for b in broken} == {("ZR-03", "999"), ("OG-01", "1")}
    client.put(
        "/v1/admin/kb/rule-refs",
        headers=admin,
        json={
            "refs": [
                {"rule_code": "ZR-03", "doc_code": "RK-355", "clause_no": "128"},
                {"rule_code": "OG-01", "doc_code": "RK-355", "clause_no": "1"},
            ]
        },
    )
    assert client.get("/v1/admin/kb/rule-refs/broken", headers=admin).json() == []


def test_excluded_clauses_break_links_and_are_not_served(
    client: TestClient, admin: dict[str, str], rt: Runtime, hse: dict[str, str]
) -> None:
    doc_id = parsed(client, admin, rt)
    d = doc(client, admin, doc_id)
    client.patch(
        f"/v1/admin/kb/clauses/{clause_id(d, '128')}", headers=admin, json={"excluded": True}
    )
    client.post(f"/v1/admin/kb/documents/{doc_id}/activate", headers=admin)
    client.put(
        "/v1/admin/kb/rule-refs",
        headers=admin,
        json={"refs": [{"rule_code": "ZR-03", "doc_code": "RK-355", "clause_no": "128"}]},
    )
    assert len(client.get("/v1/admin/kb/rule-refs/broken", headers=admin).json()) == 1
    assert client.get("/v1/kb/clauses/RK-355/128", headers=hse).status_code == 404


def test_clause_text_endpoint_for_the_finding_card(
    client: TestClient, admin: dict[str, str], rt: Runtime, hse: dict[str, str]
) -> None:
    long_clause = "9. " + "Слово " * 1000
    doc_id = parsed(client, admin, rt, kbfiles.txt(kbfiles.LAW + long_clause))
    client.post(f"/v1/admin/kb/documents/{doc_id}/activate", headers=admin)
    r = client.get("/v1/kb/clauses/RK-355/33", headers=hse).json()
    assert (
        r["code"] == "RK-355"
        and r["clauseNo"] == "33"
        and "траншеях" in r["text"]
        and r["url"].startswith("https://")
    )
    assert client.get("/v1/kb/clauses/RK-355/33.1)", headers=hse).status_code == 200  # a sub-clause
    assert client.get("/v1/kb/clauses/RK-355/33.9)", headers=hse).status_code == 404
    assert (
        client.get("/v1/kb/clauses/RK-355/9/1", headers=hse).status_code == 200
    )  # a split clause "9/1"
    assert client.get("/v1/kb/clauses/NOPE/1", headers=hse).status_code == 404


def package(
    db: Database,
    rt: Runtime,
    rules: list[str],
    cat: str = "GP",
    wt: str = "RPO",
    texts: list[str] | None = None,
    limit: int = 8,
    chars: int = 12000,
) -> list[retrieve.ClauseRef]:
    with db.tx() as conn:
        return retrieve.build_package(
            conn, rules, "OMG", wt, cat, texts or [], fts_limit=limit, max_chars=chars
        )


def test_package_follows_bindings_links_and_full_text_search(
    client: TestClient, admin: dict[str, str], rt: Runtime, db: Database
) -> None:
    a = parsed(
        client,
        admin,
        rt,
        kbfiles.txt(),
        code="RK-355",
        categories=["GP", "VS"],
        org_codes=["OMG"],
        work_types=[],
    )
    b = parsed(
        client,
        admin,
        rt,
        kbfiles.txt("1. Пункт для сварки и огневых работ в газоопасных местах.\n"),
        code="OTHER",
        categories=["OG"],
    )
    c = parsed(
        client,
        admin,
        rt,
        kbfiles.txt("1. Стандарт организации о газоанализе в замкнутых пространствах.\n"),
        code="ORG-1",
        layer="org",
    )
    for doc_id in (a, b, c):
        client.post(f"/v1/admin/kb/documents/{doc_id}/activate", headers=admin)
    client.put(
        "/v1/admin/kb/rule-refs",
        headers=admin,
        json={
            "refs": [
                {"rule_code": "GP-04", "doc_code": "RK-355", "clause_no": "33"},
                {"rule_code": "GP-04", "doc_code": "OTHER", "clause_no": "1"},
            ]
        },
    )
    linked = package(db, rt, ["GP-04"], limit=0)
    assert [r.ref for r in linked] == [
        "RK-355:33"
    ]  # the OG-only document is filtered out by category
    assert package(db, rt, ["GP-04"], cat="OG", limit=0)[0].ref == "OTHER:1"
    found = package(db, rt, [], texts=["Проверить газоанализ воздуха в траншее"], limit=8)
    refs = {r.ref for r in found}
    assert {
        "ORG-1:1",
        "RK-355:33",
    } <= refs and "OTHER:1" not in refs  # FTS also honours the bindings
    combined = package(db, rt, ["GP-04"], texts=["газоанализ воздуха"], limit=8)
    assert combined[0].ref == "RK-355:33" and len({r.ref for r in combined}) == len(combined)


def test_package_limits_count_and_size(
    client: TestClient, admin: dict[str, str], rt: Runtime, db: Database
) -> None:
    text_ = "".join(
        f"{n}. Газоанализ воздуха выполняется перед началом работ пункт номер {n}.\n"
        for n in range(1, 21)
    )
    doc_id = parsed(client, admin, rt, kbfiles.txt(text_), code="BIG")
    client.post(f"/v1/admin/kb/documents/{doc_id}/activate", headers=admin)
    assert len(package(db, rt, [], texts=["газоанализ воздуха"], limit=8)) == 8
    assert len(package(db, rt, [], texts=["газоанализ воздуха"], limit=3)) == 3
    small = package(db, rt, [], texts=["газоанализ воздуха"], limit=8, chars=200)
    assert sum(len(r.text) for r in small) <= 200 and 0 < len(small) < 8
    assert package(db, rt, [], texts=["совсем другое слово"], limit=8) == []
    assert (
        retrieve.search_query(["а б в", "Газоанализ воздуха газоанализ"]) == "газоанализ or воздуха"
    )


def test_package_is_filtered_by_work_type(
    client: TestClient, admin: dict[str, str], rt: Runtime, db: Database
) -> None:
    doc_id = parsed(client, admin, rt, work_types=["RPO"])
    client.post(f"/v1/admin/kb/documents/{doc_id}/activate", headers=admin)
    client.put(
        "/v1/admin/kb/rule-refs",
        headers=admin,
        json={"refs": [{"rule_code": "GP-04", "doc_code": "RK-355", "clause_no": "33"}]},
    )
    assert package(db, rt, ["GP-04"], wt="RPO", limit=0) and not package(
        db, rt, ["GP-04"], wt="OTHER", limit=0
    )


def test_code_findings_show_the_basis_from_the_linked_clause(
    client: TestClient, admin: dict[str, str], hse: dict[str, str], rt: Runtime
) -> None:
    doc_id = parsed(client, admin, rt)
    client.post(f"/v1/admin/kb/documents/{doc_id}/activate", headers=admin)
    client.put(
        "/v1/admin/kb/rule-refs",
        headers=admin,
        json={"refs": [{"rule_code": "S02", "doc_code": "RK-355", "clause_no": "2"}]},
    )
    body = factory.request("GP", [{"section": "5.1", "text": "Тест"}]).model_dump(mode="json")
    data = client.post(
        "/v1/checks", json=body, headers={**hse, "Idempotency-Key": body["end"]["contentHash"]}
    ).json()
    s02 = next(f for f in data["findings"] if f["ruleCode"] == "S02")
    assert (
        s02["basis"]["status"] == "linked"
        and s02["basis"]["doc"] == "RK-355"
        and s02["basis"]["clause"] == "2"
    )
    assert (
        s02["basis"]["title"] == "Правила ПБ для ОПО"
        and len(s02["basis"]["excerpt"]) <= 300
        and s02["basis"]["url"]
    )
    s04 = [f for f in data["findings"] if f["ruleCode"] == "N06"]
    assert all(
        f["basis"]["status"] != "linked" for f in s04
    )  # rules without a link keep the JSON basis


def test_linked_basis_lifts_the_severity_cap(
    client: TestClient, admin: dict[str, str], hse: dict[str, str], rt: Runtime
) -> None:
    body = factory.request("GP", [], flags={"adjacentApproval": False}).model_dump(mode="json")
    body["factorAnswers"] = {"F02": "yes"}
    from aicheck.contracts import CheckRequest
    from aicheck.hashing import content_hash

    body["end"]["contentHash"] = content_hash(CheckRequest.model_validate(body))

    def severity() -> str:
        r = client.post(
            "/v1/checks", json=body, headers={**hse, "Idempotency-Key": body["end"]["contentHash"]}
        ).json()
        return next(f["severity"] for f in r["findings"] if f["ruleCode"] == "GP-01")

    assert severity() == "significant"  # the basis says "сверить пункт"
    doc_id = parsed(client, admin, rt)
    client.post(f"/v1/admin/kb/documents/{doc_id}/activate", headers=admin)
    client.put(
        "/v1/admin/kb/rule-refs",
        headers=admin,
        json={"refs": [{"rule_code": "GP-01", "doc_code": "RK-355", "clause_no": "1"}]},
    )
    body["end"]["endRef"] = "end_2"  # a new run: the old one is kept as it was
    assert severity() == "critical"


def test_llm_references_outside_the_package_are_dropped_in_the_worker(
    client: TestClient, admin: dict[str, str], hse: dict[str, str], rt: Runtime
) -> None:
    from aicheck.jobs.worker import LlmWorker
    from aicheck.llm.client import LlmClient
    from tests.fakes import fake_llm

    doc_id = parsed(client, admin, rt)
    client.post(f"/v1/admin/kb/documents/{doc_id}/activate", headers=admin)
    client.put(
        "/v1/admin/kb/rule-refs",
        headers=admin,
        json={"refs": [{"rule_code": "GP-04", "doc_code": "RK-355", "clause_no": "33"}]},
    )
    body = factory.request(
        "GP",
        [
            {
                "section": "5.5",
                "text": "Оградить зону работ сигнальной лентой и выставить знаки безопасности",
            }
        ],
    ).model_dump(mode="json")
    first = client.post(
        "/v1/checks", json=body, headers={**hse, "Idempotency-Key": body["end"]["contentHash"]}
    ).json()
    fake = fake_llm.FakeLlm("ok")
    original = fake_llm.answer

    def with_refs(scenario: str, task: dict[str, Any]) -> dict[str, Any]:
        result = original(scenario, task)
        result["findings"][0].update(rule_code="GP-04", basis_refs=["RK-355:33", "FAKE:1"])
        return result

    fake_llm.answer = with_refs  # type: ignore[assignment]
    try:
        LlmWorker(rt, LlmClient(rt.settings, transport=fake.transport())).step()
    finally:
        fake_llm.answer = original  # type: ignore[assignment]
    user = fake.calls[0]["messages"][1]["content"]
    sent = json.loads(user.split("\nCLAUSES\n", 1)[1].split("\n", 1)[0])
    refs = [k["ref"] for k in sent]
    assert (
        refs[0] == "RK-355:33" and "FAKE:1" not in refs
    )  # the linked clause comes first; FTS may add more
    ai = [
        f
        for f in client.get(f"/v1/checks/{first['runId']}", headers=hse).json()["findings"]
        if f["source"] == "ai"
    ]
    assert ai[0]["basis"]["status"] == "linked" and ai[0]["basis"]["clause"] == "33"


def test_parse_timeout_kills_the_child_process() -> None:
    state, message, _ = ingest.parse_with_timeout("a.txt", kbfiles.txt(), timeout_s=0.001)
    assert state == "error" and "timeout" in message


def test_failed_parse_job_is_marked_failed(
    client: TestClient, admin: dict[str, str], rt: Runtime, db: Database
) -> None:
    doc_id = parsed(client, admin, rt, kbfiles.pdf_without_text(), "scan.pdf")
    with db.tx() as conn:
        assert (
            conn.execute(
                text("SELECT state FROM aicheck.kb_job WHERE document_id = :d"), {"d": doc_id}
            ).scalar()
            == "failed"
        )
        assert kb_queries.kb_version(conn) >= 2


def test_document_listing_filters(client: TestClient, admin: dict[str, str], rt: Runtime) -> None:
    a = parsed(client, admin, rt, categories=["GP"], code="A-1")
    b = parsed(client, admin, rt, categories=["OG"], code="B-1")
    by_cat = client.get("/v1/admin/kb/documents", params={"category": "OG"}, headers=admin).json()
    assert [d["id"] for d in by_cat] == [b]
    assert {d["id"] for d in client.get("/v1/admin/kb/documents", headers=admin).json()} == {a, b}
    assert client.get("/v1/admin/kb/documents/999", headers=admin).status_code == 404
