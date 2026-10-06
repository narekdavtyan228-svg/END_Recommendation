"""LLM worker: `python -m aicheck.jobs.worker`."""

import hashlib
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import httpx

from aicheck.config import load_settings, validate_outbound
from aicheck.contracts import CheckRequest, Finding
from aicheck.db import queries
from aicheck.db.engine import Database
from aicheck.engine.context import CheckContext, build_context
from aicheck.jobs import callback, queue
from aicheck.kb import ingest, retrieve
from aicheck.llm import payload
from aicheck.llm.client import LlmClient, LlmInvalid, LlmUnavailable
from aicheck.llm.residue import Residue, build_residue
from aicheck.llm.schema import LlmAnswer
from aicheck.llm.verify import VerifyInput, verify
from aicheck.logging import configure
from aicheck.outbound import guarded_client
from aicheck.results import build_result, finding_to_row, new_id, row_to_finding
from aicheck.runtime import Runtime

log = logging.getLogger(__name__)


@dataclass
class CallOutcome:
    state: str  # ok | unavailable | invalid
    answer: LlmAnswer | None = None


class LlmWorker:
    def __init__(self, rt: Runtime, llm: LlmClient, http: httpx.Client | None = None) -> None:
        self.rt = rt
        self.llm = llm
        self.http = http or guarded_client(rt.settings.allowed_outbound_hosts, timeout=10.0)
        self._linked: dict[tuple[Any, ...], list[retrieve.ClauseRef]] = {}

    # --- one job ---------------------------------------------------------------------------

    def process(self, job: dict[str, Any]) -> None:
        started = time.perf_counter()
        run, ctx, code_findings = self._load(str(job["run_id"]))
        residue = build_residue(ctx, code_findings)
        outcomes = self._ask_all(ctx, residue)
        ai = self._verify(ctx, residue, code_findings, outcomes)
        states = [o.state for o in outcomes.values()]
        llm_status = (
            "skipped"
            if not states
            else "done"
            if "ok" in states
            else ("invalid" if "invalid" in states else "unavailable")
        )
        self._finish(run, ai, llm_status, int((time.perf_counter() - started) * 1000))

    def _load(self, run_id: str) -> tuple[dict[str, Any], CheckContext, list[Finding]]:
        with self.rt.db.tx() as conn:
            run = queries.get_run(conn, run_id)
            assert run is not None  # noqa: S101 - the job references an existing run
            rows = queries.list_findings(conn, run_id)
        ruleset = self.rt.ruleset_by_id(run["ruleset_id"])
        catalog = self.rt.catalog(run["catalog_version"])
        assert ruleset is not None and catalog is not None  # noqa: S101 - stored with the run
        request = CheckRequest.model_validate(run["request"])
        ctx = build_context(request, ruleset, catalog, self.rt.kb_basis())
        code_findings = [row_to_finding(r) for r in rows if r["source"] == "rules"]
        return run, ctx, code_findings

    # --- calls -----------------------------------------------------------------------------

    def _kb_package(self, ctx: CheckContext, texts: list[str]) -> list[retrieve.ClauseRef]:
        s = self.rt.settings
        rule_codes = [
            c for c in ctx.ruleset.category_rules if c.startswith(ctx.category_code + "-")
        ]
        rule_codes += list(ctx.ruleset.inapplicability) + list(ctx.ruleset.risk_rules)
        with self.rt.db.tx() as conn:
            version = retrieve.kb_version(conn)
            key = (s.org_code, ctx.request.context.workType, ctx.category_code, version)
            if key not in self._linked:
                self._linked = {
                    key: retrieve.build_package(
                        conn, rule_codes, *key[:3], [], fts_limit=0, max_chars=s.kb_context_chars
                    )
                }
            linked = self._linked[key]
            extra = retrieve.build_package(
                conn, [], *key[:3], texts, fts_limit=s.kb_fts_limit, max_chars=s.kb_context_chars
            )
        known = {c.ref for c in linked}
        merged = linked + [c for c in extra if c.ref not in known]
        return retrieve._within(merged, s.kb_context_chars)

    def _ask_all(self, ctx: CheckContext, residue: Residue) -> dict[str, CallOutcome]:
        tasks: dict[str, tuple[str, str, str]] = {}
        token = payload.new_token()
        version = self.rt.settings.prompt_version
        if residue.needs_measures:
            kb = self._kb_package(ctx, [r.text for r in residue.measure_rows])
            system, user = payload.measures_task(ctx, residue, kb, version, token)
            tasks["measures"] = (system, user, self._key(ctx, "measures", residue, kb))
        if residue.risk_rows:
            kb = self._kb_package(ctx, [])
            system, user = payload.risks_task(ctx, residue, kb, version, token)
            tasks["risks"] = (system, user, self._key(ctx, "risks", residue, kb))
        outcomes: dict[str, CallOutcome] = {}
        to_call: dict[str, tuple[str, str, str]] = {}
        for kind, task in tasks.items():  # database work stays in this thread
            cached = self._cached(task[2])
            if cached is not None:
                outcomes[kind] = CallOutcome("ok", cached)
            else:
                to_call[kind] = task
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {k: pool.submit(self._call, t[0], t[1]) for k, t in to_call.items()}
            for kind, future in futures.items():
                outcomes[kind] = future.result()
                if outcomes[kind].answer is not None:
                    self._store(to_call[kind][2], outcomes[kind].answer)
        return outcomes

    def _key(
        self, ctx: CheckContext, kind: str, residue: Residue, kb: list[retrieve.ClauseRef]
    ) -> str:
        """Cache key: the content that decides the answer, not the random delimiter."""
        s = self.rt.settings
        rows = [(r.row_id, r.section, r.text) for r in residue.measure_rows]
        data = [
            kind,
            ctx.category_code,
            ctx.request.context.unitCode,
            rows,
            [r.model_dump_json() for r in residue.risk_rows],
            {c: f.value for c, f in ctx.factors.items()},
            ctx.ruleset.sha256,
            s.llm_model,
            s.prompt_version,
            [c.ref for c in kb],
        ]
        return hashlib.sha256(
            json.dumps(data, ensure_ascii=False, default=str).encode()
        ).hexdigest()

    def _cached(self, key: str) -> LlmAnswer | None:
        with self.rt.db.tx() as conn:
            cached = queries.get_cache(conn, key)
        return LlmAnswer.model_validate(cached) if cached is not None else None

    def _store(self, key: str, answer: LlmAnswer | None) -> None:
        if answer is not None:
            with self.rt.db.tx() as conn:
                queries.put_cache(conn, key, answer.model_dump(mode="json"))

    def _call(self, system: str, user: str) -> CallOutcome:
        """Network only: runs in a pool thread."""
        try:
            return CallOutcome(
                "ok", self.llm.ask(system, user, LlmAnswer, schema=payload.output_schema())
            )
        except LlmUnavailable:
            return CallOutcome("unavailable")
        except LlmInvalid:
            return CallOutcome("invalid")

    # --- result ----------------------------------------------------------------------------

    def _verify(
        self,
        ctx: CheckContext,
        residue: Residue,
        code_findings: list[Finding],
        outcomes: dict[str, CallOutcome],
    ) -> list[Finding]:
        found: list[Finding] = []
        s = self.rt.settings
        kb = self._kb_package(ctx, [])
        scopes = {
            "measures": (
                {r["id"] for r in residue.measure_rules},
                {r.row_id: r.section for r in residue.measure_rows + residue.reason_rows},
            ),
            "risks": (
                {r["id"] for r in residue.risk_rules},
                {r.rowId: "" for r in residue.risk_rows},
            ),
        }
        for kind, outcome in outcomes.items():
            if outcome.answer is None:
                continue
            codes, rows = scopes[kind]
            vin = VerifyInput(ctx, code_findings, kb, codes, rows, s.llm_min_confidence)
            found.extend(verify(outcome.answer, vin))
        return found

    def _finish(
        self, run: dict[str, Any], ai: list[Finding], llm_status: str, duration_ms: int
    ) -> None:
        s = self.rt.settings
        run_id = str(run["id"])
        for finding in ai:
            finding.findingId = new_id()
        status = "done" if llm_status in ("done", "skipped") else "llm_unavailable"
        with self.rt.db.tx() as conn:
            queries.insert_findings(conn, run_id, [finding_to_row(f) for f in ai])
            queries.insert_event(
                conn,
                run_id,
                status,
                llm_status,
                model=s.llm_model,
                prompt_version=s.prompt_version,
                duration_ms=duration_ms,
            )
            ruleset = self.rt.ruleset_by_id(run["ruleset_id"])
            result = build_result(conn, run, ruleset.version if ruleset else "")
            if s.hse_callback_url:
                queries.insert_outbox(
                    conn, run_id, {"endRef": run["end_ref"], **result.model_dump(mode="json")}
                )

    # --- loop ------------------------------------------------------------------------------

    def step(self) -> bool:
        """One iteration; True when a job was processed."""
        for failed in queue.recover_stale(self.rt.db):
            self._fail(failed)
        job = queue.take(self.rt.db)
        if job is None:
            callback.deliver_due(self.rt.db, self.rt.settings, self.http)
            return ingest.process_next(self.rt)
        try:
            self.process(job)
            queue.done(self.rt.db, job["id"])
        except Exception as exc:  # noqa: BLE001 - a broken job must not stop the worker
            log.error("job failed", extra={"job_id": job["id"], "error_type": type(exc).__name__})
        return True

    def _fail(self, job: dict[str, Any]) -> None:
        with self.rt.db.tx() as conn:
            queries.insert_event(conn, str(job["run_id"]), "llm_unavailable", "unavailable")

    def run_forever(self) -> None:  # pragma: no cover - the service loop
        while True:
            if not self.step():
                time.sleep(self.rt.settings.poll_interval_s)


def main() -> None:  # pragma: no cover - entry point
    settings = load_settings()
    configure(settings.log_level)
    validate_outbound(settings)
    rt = Runtime(settings=settings, db=Database(settings.database_url))
    LlmWorker(rt, LlmClient(settings)).run_forever()


if __name__ == "__main__":  # pragma: no cover
    main()
