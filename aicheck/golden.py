"""Golden set: expected findings per case, quality metrics and model comparison reports."""

import json
import statistics
import time
from pathlib import Path
from typing import Any

from aicheck.catalog.model import Catalog
from aicheck.config import Settings
from aicheck.contracts import CheckRequest, Finding
from aicheck.engine.run import check
from aicheck.llm import payload
from aicheck.llm.client import LlmClient, LlmInvalid, LlmUnavailable
from aicheck.llm.residue import build_residue
from aicheck.llm.schema import LlmAnswer
from aicheck.llm.verify import VerifyInput, verify
from aicheck.rules.loader import DATA_FILE, Ruleset, parse_ruleset

Key = tuple[str, str, str]


def finding_key(rule: str, target: dict[str, Any], severity: str) -> Key:
    clean = {k: v for k, v in target.items() if v is not None}
    return (rule, json.dumps(clean, sort_keys=True, ensure_ascii=False), severity)


def _target_of(f: Finding) -> dict[str, Any]:
    return f.target.model_dump(exclude_none=True)


def _keys(findings: list[Finding]) -> set[Key]:
    return {
        finding_key(f.ruleCode, _target_of(f), f.severity)
        for f in findings
        if not f.hidden and f.kind != "suggestion"
    }


def _expected(items: list[dict[str, Any]]) -> set[Key]:
    return {finding_key(i["rule"], i.get("target", {}), i["severity"]) for i in items}


def load_ruleset(golden_dir: Path, with_params: bool) -> Ruleset:
    raw = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    if with_params:
        params = json.loads((golden_dir / "params.json").read_text(encoding="utf-8"))
        for param in raw["parameters"]:
            if param["code"] in params:
                param["data"] = params[param["code"]]
    return parse_ruleset(json.dumps(raw, ensure_ascii=False))


def load_catalog(golden_dir: Path) -> Catalog:
    return Catalog.from_body(json.loads((golden_dir / "catalog.json").read_text(encoding="utf-8")))


def load_cases(cases_dir: Path) -> list[dict[str, Any]]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(cases_dir.glob("*.json"))]


def evaluate_case(
    case: dict[str, Any], golden_dir: Path
) -> tuple[set[Key], set[Key], list[Finding]]:
    request = CheckRequest.model_validate(case["request"])
    ruleset = load_ruleset(golden_dir, case.get("params", True))
    _, findings = check(request, ruleset, load_catalog(golden_dir))
    return _keys(findings), _expected(case["expected"]), findings


def metrics_of(found: set[Key], expected: set[Key]) -> dict[str, float]:
    critical = {k for k in expected if k[2] == "critical"}
    recall = len(critical & found) / len(critical) if critical else 1.0
    precision = len(found & expected) / len(found) if found else 1.0
    return {"critical_recall": recall, "precision": precision}


def run(cases_dir: Path, report_path: Path) -> dict[str, Any]:
    golden_dir = cases_dir.parent
    rows, found_all, expected_all = [], set(), set()
    for case in load_cases(cases_dir):
        found, expected, _ = evaluate_case(case, golden_dir)
        ok = found == expected
        rows.append((case["id"], ok, sorted(expected - found), sorted(found - expected)))
        found_all |= {(case["id"], *k) for k in found}
        expected_all |= {(case["id"], *k) for k in expected}
    critical_exp = {k for k in expected_all if k[3] == "critical"}
    recall = len(critical_exp & found_all) / len(critical_exp) if critical_exp else 1.0
    precision = len(found_all & expected_all) / len(found_all) if found_all else 1.0
    passed = sum(1 for r in rows if r[1])
    summary = f"golden: {passed}/{len(rows)} cases match, critical recall {recall:.3f}, precision {precision:.3f}"
    lines = [
        "# Golden set report",
        "",
        summary,
        "",
        "| case | match | missing | unexpected |",
        "|---|---|---|---|",
    ]
    for case_id, ok, missing, extra in rows:
        lines.append(f"| {case_id} | {'yes' if ok else 'NO'} | {len(missing)} | {len(extra)} |")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"ok": passed == len(rows), "summary": summary, "recall": recall, "precision": precision}


# --- LLM evaluation (no database: documents and cache are not used) -------------------------------


Task = tuple[tuple[str, str], set[str], dict[str, str]]


def _tasks(ctx: Any, residue: Any, settings: Settings) -> list[Task]:
    """(prompt, rule ids, rows) of every model call this case needs."""
    token, version = payload.new_token(), settings.prompt_version
    tasks: list[Task] = []
    if residue.needs_measures:
        rows = {r.row_id: r.section for r in residue.measure_rows + residue.reason_rows}
        tasks.append(
            (
                payload.measures_task(ctx, residue, [], version, token),
                {r["id"] for r in residue.measure_rules},
                rows,
            )
        )
    if residue.risk_rows:
        tasks.append(
            (
                payload.risks_task(ctx, residue, [], version, token),
                {r["id"] for r in residue.risk_rules},
                {r.rowId: "" for r in residue.risk_rows},
            )
        )
    return tasks


def llm_pass(
    case: dict[str, Any],
    golden_dir: Path,
    client: LlmClient,
    settings: Settings,
    model: str | None = None,
) -> dict[str, Any]:
    """One case through the LLM stage; returns findings and call statistics."""
    request = CheckRequest.model_validate(case["request"])
    ruleset = load_ruleset(golden_dir, case.get("params", True))
    ctx, code_findings = check(request, ruleset, load_catalog(golden_dir))
    stats: dict[str, Any] = {
        "calls": 0,
        "valid": 0,
        "times": [],
        "dropped": 0,
        "kept": 0,
        "findings": [],
    }
    for (system, user), codes, rows in _tasks(ctx, build_residue(ctx, code_findings), settings):
        started = time.perf_counter()
        stats["calls"] += 1
        try:
            answer = client.ask(system, user, LlmAnswer, model, payload.output_schema())
        except (LlmUnavailable, LlmInvalid):
            stats["times"].append(time.perf_counter() - started)
            continue
        stats["times"].append(time.perf_counter() - started)
        stats["valid"] += 1
        vin = VerifyInput(ctx, code_findings, [], codes, rows, settings.llm_min_confidence)
        verified = verify(answer, vin)
        stats["dropped"] += sum(vin.dropped.values())
        stats["kept"] += len([f for f in verified if not f.hidden])
        stats["findings"].extend(verified)
    return stats


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def _summarize_model(
    model: str, cases: list[dict[str, Any]], golden_dir: Path, client: LlmClient, settings: Settings
) -> dict[str, Any]:
    totals = {"calls": 0, "valid": 0, "dropped": 0, "kept": 0}
    times: list[float] = []
    tp = fp = fn = 0
    for case in cases:
        stats = llm_pass(case, golden_dir, client, settings, model)
        for key in totals:
            totals[key] += stats[key]
        times += stats["times"]
        got = {
            (f.ruleCode, f.target.model_dump_json(exclude_none=True))
            for f in stats["findings"]
            if not f.hidden
        }
        want = {
            (e["rule"], json.dumps(e.get("target", {}), sort_keys=True))
            for e in case.get("expected_ai", [])
        }
        got_norm = {(r, json.dumps(json.loads(t), sort_keys=True)) for r, t in got}
        tp += len(got_norm & want)
        fp += len(got_norm - want)
        fn += len(want - got_norm)
    produced = totals["kept"] + totals["dropped"]
    return {
        "model": model,
        "valid_json": totals["valid"] / totals["calls"] if totals["calls"] else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "dropped_share": totals["dropped"] / produced if produced else 0.0,
        "p50": statistics.median(times) if times else 0.0,
        "p95": _percentile(times, 0.95),
    }


def _write_models(path: Path, title: str, rows: list[dict[str, Any]]) -> None:
    lines = [
        f"# {title}",
        "",
        "| model | valid JSON | precision | recall | dropped | p50, s | p95, s |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['model']} | {r['valid_json']:.2f} | {r['precision']:.2f} | {r['recall']:.2f} | "
            f"{r['dropped_share']:.2f} | {r['p50']:.2f} | {r['p95']:.2f} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def llm_cases(cases_dir: Path, limit: int | None = None) -> list[dict[str, Any]]:
    """Cases with expert marks for the LLM stage (`expected_ai`); all cases if there are none."""
    cases = load_cases(cases_dir)
    marked = [c for c in cases if "expected_ai" in c]
    return (marked or cases)[:limit]


def compare_models(
    settings: Settings, cases_dir: Path, report_path: Path, client: LlmClient | None = None
) -> dict[str, Any]:
    models = [m for m in (settings.llm_model, settings.llm_model_alt) if m]
    own = client or LlmClient(settings)
    cases = llm_cases(cases_dir)
    rows = [_summarize_model(m, cases, cases_dir.parent, own, settings) for m in models]
    _write_models(report_path, "Model comparison on the golden set", rows)
    return {"rows": rows, "summary": f"compared {len(rows)} model(s) on {len(cases)} cases"}


def smoke_llm(
    settings: Settings,
    cases_dir: Path,
    report_path: Path,
    count: int = 5,
    client: LlmClient | None = None,
) -> dict[str, Any]:
    own = client or LlmClient(settings)
    cases = llm_cases(cases_dir, count)
    row = _summarize_model(settings.llm_model, cases, cases_dir.parent, own, settings)
    _write_models(report_path, "Smoke test on the local model", [row])
    return {
        "rows": [row],
        "summary": f"smoke: {len(cases)} cases, p95 {row['p95']:.2f}s, dropped {row['dropped_share']:.2f}",
    }
