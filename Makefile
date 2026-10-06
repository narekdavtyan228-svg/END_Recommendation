# Quality gates of the specification. Stages: make test-stage N=0..7
PY ?= python
PYTEST = $(PY) -m pytest
STAGES = $(shell seq -s ' or ' -f 'stage%g' 0 $(N))
SKIP_PERF = and not perf
WORKERS ?= auto

.PHONY: lint typecheck sec test test-stage test-serial golden perf compare-models smoke-llm openapi cases lock sbom dev-secrets up down

lint:
	$(PY) -m ruff check aicheck tests scripts
	$(PY) -m ruff format --check aicheck tests scripts

typecheck:
	$(PY) -m mypy aicheck

sec:
	$(PY) -m bandit -r aicheck -ll -q
	$(PY) -m pip_audit -r requirements.lock --strict --disable-pip
	$(PY) scripts/check_code.py

test-stage:
	@test -n "$(N)" || (echo "usage: make test-stage N=<0..7>"; exit 2)
	$(PYTEST) -n $(WORKERS) -m "($(STAGES)) $(SKIP_PERF)" --cov=aicheck --cov-report=json:reports/coverage.json --cov-report=term:skip-covered
	@if [ "$(N)" -ge 7 ]; then $(PY) scripts/check_coverage.py --engine 90 --llm 85 --total 80; \
	 elif [ "$(N)" -ge 5 ]; then $(PY) scripts/check_coverage.py --engine 90 --llm 85; \
	 elif [ "$(N)" -ge 2 ]; then $(PY) scripts/check_coverage.py --engine 90; fi

test:
	$(PYTEST) -n $(WORKERS) -m "not perf"

test-serial:
	$(PYTEST) -n 0 -m "not perf"

golden:
	$(PY) -m aicheck.cli run-golden --cases tests/golden/cases --report reports/golden.md

perf:
	$(PYTEST) -n 0 -m perf

compare-models:
	$(PY) -m aicheck.cli compare-models --cases tests/golden/cases --report reports/models.md

smoke-llm:
	$(PY) -m aicheck.cli smoke-llm --cases tests/golden/cases --report reports/smoke-llm.md --count 5

openapi:
	$(PY) -m aicheck.cli openapi --out openapi.json

cases:
	$(PY) tests/golden/make_cases.py
	$(PY) tests/golden/make_hash_vectors.py

lock:
	uv pip compile pyproject.toml --python-version 3.12 --generate-hashes -o requirements.lock
	uv pip compile pyproject.toml --extra dev --python-version 3.12 --generate-hashes -o requirements-dev.lock

sbom:
	$(PY) -m pip_audit -r requirements.lock --disable-pip -f cyclonedx-json -o reports/sbom.cdx.json

dev-secrets:
	./scripts/dev_secrets.sh

up: dev-secrets
	docker compose up --build

down:
	docker compose down
