"""Coverage thresholds of the specification: engine >= 90, llm >= 85, whole package >= 80."""

import argparse
import json
import sys
from pathlib import Path


def percent(files: dict[str, dict[str, dict[str, int]]], prefix: str) -> float | None:
    chosen = [f["summary"] for name, f in files.items() if name.startswith(prefix)]
    statements = sum(s["num_statements"] for s in chosen)
    covered = sum(s["covered_lines"] for s in chosen)
    return 100.0 * covered / statements if statements else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="reports/coverage.json")
    parser.add_argument("--engine", type=float, default=0)
    parser.add_argument("--llm", type=float, default=0)
    parser.add_argument("--total", type=float, default=0)
    args = parser.parse_args()
    data = json.loads(Path(args.file).read_text(encoding="utf-8"))
    files = data["files"]
    checks = [
        ("engine", percent(files, "aicheck/engine/"), args.engine),
        ("llm", percent(files, "aicheck/llm/"), args.llm),
        ("total", data["totals"]["percent_covered"], args.total),
    ]
    failed = False
    for name, value, limit in checks:
        ok = limit == 0 or (value is not None and value >= limit)
        sys.stdout.write(
            f"coverage {name}: {value:.1f}% (threshold {limit}%) {'ok' if ok else 'FAIL'}\n"
        )
        failed = failed or not ok
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
