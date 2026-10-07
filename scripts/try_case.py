"""Sends an example case to a running service and prints the findings.

python scripts/try_case.py [case file] [base url]   (needs: pip install pyjwt cryptography pydantic)
"""

import json
import sys
import time
import urllib.request
from pathlib import Path

import jwt

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aicheck.contracts import CheckRequest
from aicheck.hashing import content_hash

CASE = sys.argv[1] if len(sys.argv) > 1 else "tests/golden/official/cases/case_01.json"
BASE = (sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8000").rstrip("/")
CATALOG = Path("tests/golden/official/test_catalog.json")
KEY = Path("secrets/jwt_private_key.pem").read_text(encoding="utf-8")


def token(role: str) -> str:
    claims = {"iss": "https://idp.dev.local", "aud": "ai-check", "sub": "dev-" + role,
              "roles": [role], "exp": int(time.time()) + 3600}
    if role == "ai-admin":
        claims["amr"] = ["pwd", "mfa"]
    return jwt.encode(claims, KEY, algorithm="RS256")


def call(method: str, path: str, body: object = None, role: str = "hse-backend", key: str = "") -> dict:
    headers = {"Authorization": "Bearer " + token(role), "Content-Type": "application/json"}
    if key:
        headers["Idempotency-Key"] = key
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode()
    req = urllib.request.Request(BASE + path, data, headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as err:
        sys.exit(f"{method} {path}: HTTP {err.code} {err.read().decode()}")


def main() -> None:
    case = json.loads(Path(CASE).read_text(encoding="utf-8"))
    request = case["request"]
    request["end"]["contentHash"] = "sha256:" + "0" * 64
    request["end"]["contentHash"] = content_hash(CheckRequest.model_validate(request))
    call("POST", "/v1/admin/catalog", json.loads(CATALOG.read_text(encoding="utf-8")), "ai-admin")
    result = call("POST", "/v1/checks", request, key=request["end"]["contentHash"])
    run_id = result.get("runId") or result.get("run_id")
    for _ in range(60):
        result = call("GET", f"/v1/checks/{run_id}")
        if result.get("llm") != "pending":
            break
        time.sleep(2)
    print(f"case: {case.get('title')}\nrun: {run_id}\nstatus: {result['status']}, llm: {result['llm']}")
    for f in result.get("findings", []):
        print(f"- [{f['severity']}] {f['ruleCode']} ({f['source']}): {f['title']['ru']}\n    {f['message']['ru']}")
    print("вопросы:", [q["factorCode"] for q in result.get("questions", [])])


if __name__ == "__main__":
    main()
