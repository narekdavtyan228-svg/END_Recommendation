"""Static rules of the specification: forbidden constructs, size limits, secrets in sources.

Run: python scripts/check_code.py  (part of `make sec`). Exit code 1 when a rule is broken.
"""

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "aicheck"
ASYNC_ALLOWED = {PACKAGE / "api" / "asgi.py"}  # ASGI glue: size limit and request id
FORBIDDEN_IMPORTS = {
    "langchain",
    "llama_index",
    "chromadb",
    "faiss",
    "pinecone",
    "sentence_transformers",
    "celery",
    "kombu",
    "pika",
    "kafka",
    "redis",
    "pickle",
    "marshal",
    "requests",
    "urllib3",
}
FORBIDDEN_TEXT = {
    r"verify\s*=\s*False": "TLS verification must stay on",
    r"\beval\s*\(": "eval is forbidden",
    r"\bexec\s*\(": "exec is forbidden",
    r"\bpickle\b": "pickle is forbidden",
    r"declarative_base|sqlalchemy\.orm": "no ORM",
    r"^\s*print\s*\(": "use logging, not print",
    r"ssl\._create_unverified_context|CERT_NONE": "TLS verification must stay on",
}
SECRET_PATTERNS = {
    "private key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "api key": r"\bsk-[A-Za-z0-9]{20,}",
    "cloud key": r"\bAKIA[0-9A-Z]{16}\b",
    "bearer token": r"Bearer\s+eyJ[A-Za-z0-9_\-]{20,}",
}
MAX_FUNCTION_LINES = 40
MAX_MODULE_LINES = 400


def files() -> list[Path]:
    return sorted(p for p in PACKAGE.rglob("*.py") if "__pycache__" not in p.parts)


def check_file(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    problems: list[str] = []
    name = path.relative_to(ROOT)
    if len(text.splitlines()) > MAX_MODULE_LINES:
        problems.append(f"{name}: module is longer than {MAX_MODULE_LINES} lines")
    for pattern, message in FORBIDDEN_TEXT.items():
        if re.search(pattern, text, re.MULTILINE):
            problems.append(f"{name}: {message}")
    for label, pattern in SECRET_PATTERNS.items():
        if re.search(pattern, text):
            problems.append(f"{name}: looks like a {label} in the source")
    tree = ast.parse(text)
    for node in ast.walk(tree):
        problems += check_node(node, path, name)
    return problems


def check_node(node: ast.AST, path: Path, name: Path) -> list[str]:
    found: list[str] = []
    if isinstance(node, ast.AsyncFunctionDef | ast.Await) and path not in ASYNC_ALLOWED:
        found.append(f"{name}:{node.lineno}: async/await is forbidden")
    if isinstance(node, ast.Import):
        found += [
            f"{name}: forbidden import {a.name}"
            for a in node.names
            if a.name.split(".")[0] in FORBIDDEN_IMPORTS
        ]
    if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in FORBIDDEN_IMPORTS:
        found.append(f"{name}: forbidden import {node.module}")
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.end_lineno:
        length = node.end_lineno - node.lineno + 1
        if length > MAX_FUNCTION_LINES:
            found.append(
                f"{name}:{node.lineno}: function {node.name} has {length} lines (limit {MAX_FUNCTION_LINES})"
            )
    return found


def main() -> int:
    problems = [p for path in files() for p in check_file(path)]
    sys.stdout.write("\n".join(problems) + ("\n" if problems else ""))
    sys.stdout.write(f"checked {len(files())} files, {len(problems)} problem(s)\n")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
