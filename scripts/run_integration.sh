#!/usr/bin/env bash
# Build in a fresh directory and scan both fixture sets with Kubescape.
# run_rule_tests.py checks each Rego rule without assembling the framework.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBESCAPE_BIN="${KUBESCAPE_BIN:-kubescape}"
ARTIFACTS_DIR="$(mktemp -d)"
trap 'rm -rf "$ARTIFACTS_DIR"' EXIT

mkdir -p "$ROOT/dist"
DIST_DIR="$ARTIFACTS_DIR" python3 "$ROOT/scripts/build_artifacts.py"

# The allow list is a control input, not a value the scanned objects can set.
# The compliant fixture uses registry.internal/; the noncompliant fixture uses
# docker.io/.
printf '%s\n' '{"imageRepositoryAllowList": ["registry.internal/"]}' \
  > "$ARTIFACTS_DIR/controls-inputs.json"

"$KUBESCAPE_BIN" scan framework ism-kubernetes \
  "$ROOT/tests/integration/noncompliant" \
  --use-artifacts-from "$ARTIFACTS_DIR" \
  --keep-local \
  --format json \
  --output "$ROOT/dist/integration-noncompliant.json"

"$KUBESCAPE_BIN" scan framework ism-kubernetes \
  "$ROOT/tests/integration/compliant" \
  --use-artifacts-from "$ARTIFACTS_DIR" \
  --keep-local \
  --format json \
  --output "$ROOT/dist/integration-compliant.json"

# Assert the noncompliant fixtures failed every control and the compliant
# fixtures passed every control.
python3 - "$ROOT/dist/integration-noncompliant.json" "$ROOT/dist/integration-compliant.json" <<'PY'
import json
import sys
from pathlib import Path

noncompliant, compliant = (json.loads(Path(path).read_text()) for path in sys.argv[1:])
assert noncompliant["summaryDetails"]["status"] == "failed"
assert {item["status"] for item in noncompliant["summaryDetails"]["controls"].values()} == {"failed"}
assert compliant["summaryDetails"]["status"] == "passed"
assert {item["status"] for item in compliant["summaryDetails"]["controls"].values()} == {"passed"}
PY

echo "Integration scans written to $ROOT/dist"
