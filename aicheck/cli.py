"""Command line: python -m aicheck.cli <command>."""

import argparse
import json
import sys
from pathlib import Path

from aicheck import golden
from aicheck.api.app import create_app
from aicheck.config import load_settings
from aicheck.db import kb_queries, migrate, queries
from aicheck.db.engine import Database
from aicheck.rules.loader import DATA_FILE, parse_ruleset
from aicheck.runtime import Runtime


def say(text: str) -> None:
    sys.stdout.write(text + "\n")


def _runtime() -> Runtime:
    settings = load_settings()
    return Runtime(settings=settings, db=Database(settings.database_url))


def cmd_migrate(args: argparse.Namespace) -> int:
    migrate.upgrade(args.owner_url)
    say("migrated")
    return 0


def cmd_import_rules(args: argparse.Namespace) -> int:
    """Load a rule package as a draft; --activate makes it the active one."""
    rt = _runtime()
    raw = Path(args.file or DATA_FILE).read_bytes()
    ruleset = parse_ruleset(raw)
    with rt.db.tx() as conn:
        new_id = queries.insert_ruleset(
            conn, rt.settings.org_code, ruleset.version, json.loads(raw), ruleset.sha256
        )
        if new_id < 0:
            row = conn.exec_driver_sql(
                "SELECT id FROM aicheck.ruleset WHERE org_code = %s AND version = %s",
                (rt.settings.org_code, ruleset.version),
            ).first()
            new_id = int(row[0]) if row else -1
        active = queries.get_active_ruleset(conn, rt.settings.org_code)
        if args.activate and (active is None or args.force or active["id"] != new_id):
            queries.activate_ruleset(conn, new_id, rt.settings.org_code)
    say(f"ruleset {ruleset.version} id={new_id}")
    return 0


def cmd_run_golden(args: argparse.Namespace) -> int:
    report = golden.run(Path(args.cases), Path(args.report))
    say(report["summary"])
    return 0 if report["ok"] else 1


def cmd_compare_models(args: argparse.Namespace) -> int:
    rt = _runtime()
    report = golden.compare_models(rt.settings, Path(args.cases), Path(args.report))
    say(report["summary"])
    return 0


def cmd_smoke_llm(args: argparse.Namespace) -> int:
    rt = _runtime()
    report = golden.smoke_llm(rt.settings, Path(args.cases), Path(args.report), args.count)
    say(report["summary"])
    return 0


def cmd_openapi(args: argparse.Namespace) -> int:
    """Write the OpenAPI contract of the service (the saved copy is compared in tests)."""
    Path(args.out).write_text(
        json.dumps(create_app().openapi(), ensure_ascii=False, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


def cmd_purge_cache(args: argparse.Namespace) -> int:
    rt = _runtime()
    with rt.db.tx() as conn:
        say(f"purged {queries.purge_cache(conn, args.days)}")
    return 0


def cmd_retention_report(args: argparse.Namespace) -> int:
    """Journal size and age: input for the information security retention procedure."""
    rt = _runtime()
    with rt.db.tx() as conn:
        # `table` comes from this fixed tuple, never from input.
        for table in ("check_run", "run_event", "finding", "finding_action", "kb_event"):
            row = conn.exec_driver_sql(
                f"SELECT count(*), min(created_at), max(created_at) FROM aicheck.{table}"  # nosec B608
            ).first()
            say(f"{table}: rows={row[0]} oldest={row[1]} newest={row[2]}")  # type: ignore[index]
        say(f"kb_version={kb_queries.kb_version(conn)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aicheck.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("migrate")
    p.add_argument("--owner-url", required=True)
    p.set_defaults(func=cmd_migrate)
    p = sub.add_parser("import-rules")
    p.add_argument("--file")
    p.add_argument("--activate", action="store_true")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_import_rules)
    for name, func in (
        ("run-golden", cmd_run_golden),
        ("compare-models", cmd_compare_models),
        ("smoke-llm", cmd_smoke_llm),
    ):
        p = sub.add_parser(name)
        p.add_argument("--cases", default="tests/golden/cases")
        p.add_argument("--report", default=f"reports/{name}.md")
        p.add_argument("--count", type=int, default=5)
        p.set_defaults(func=func)
    p = sub.add_parser("openapi")
    p.add_argument("--out", default="openapi.json")
    p.set_defaults(func=cmd_openapi)
    p = sub.add_parser("purge-cache")
    p.add_argument("--days", type=int, default=30)
    p.set_defaults(func=cmd_purge_cache)
    p = sub.add_parser("retention-report")
    p.set_defaults(func=cmd_retention_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
