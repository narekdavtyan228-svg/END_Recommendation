#!/bin/sh
# CI order of the specification: every step fails fast. Usage: scripts/ci.sh [stage]
set -e
STAGE="${1:-7}"
make lint
make typecheck
make sec
make test-stage N="$STAGE"
make golden
[ -z "$RELEASE_TAG" ] || make perf
