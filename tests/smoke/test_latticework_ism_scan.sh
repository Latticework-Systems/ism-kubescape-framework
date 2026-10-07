#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
FAKE_BIN="$TMP_DIR/bin"
EVIDENCE_DIR="$TMP_DIR/evidence"
ARTIFACTS_DIR="$TMP_DIR/dist"
KUBECTL_LOG="$TMP_DIR/kubectl.log"
RBAC_SNAPSHOT="$TMP_DIR/created-rbac.yaml"
RBAC_NAMES_LOG="$TMP_DIR/rbac-names.log"
scan_stdout="$TMP_DIR/scan.out"
scan_stderr="$TMP_DIR/scan.err"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$FAKE_BIN" "$EVIDENCE_DIR"

bundle_dir="$TMP_DIR/bundled-artifacts"
DIST_DIR="$bundle_dir" python3 "$ROOT/scripts/build_artifacts.py"
test -f "$bundle_dir/ism-kubernetes.json"
test -f "$bundle_dir/controls-inputs.json"
test "$(cat "$bundle_dir/exceptions.json")" = '[]'

python3 - "$bundle_dir/ism-kubernetes.json" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
assert payload["ControlsIDs"] == [
    "ISM-K8S-ALLOWED-REGISTRIES",
    "ISM-K8S-DEFAULT-SERVICE-ACCOUNTS",
    "ISM-K8S-DROP-ALL-CAPABILITIES",
    "ISM-K8S-NETWORK-POLICY-COVERAGE",
    "ISM-K8S-NO-CLUSTER-ADMIN-BINDING",
    "ISM-K8S-NO-HOST-ACCESS",
    "ISM-K8S-NO-PRIVILEGE-ESCALATION",
    "ISM-K8S-NO-PRIVILEGED-CONTAINERS",
    "ISM-K8S-NO-WILDCARD-PERMISSIONS",
    "ISM-K8S-NON-ROOT-CONTAINERS",
    "ISM-K8S-POD-SECURITY-STANDARDS",
    "ISM-K8S-READONLY-ROOT-FILESYSTEM",
    "ISM-K8S-SECCOMP-PROFILE",
]
assert all(control["rules"] for control in payload["controls"])
allowed_registries = next(
    control for control in payload["controls"]
    if control["controlID"] == "ISM-K8S-ALLOWED-REGISTRIES"
)
assert all(
    "ConfigMap" not in match["resources"]
    for match in allowed_registries["rules"][0]["match"]
)
PY

cat > "$FAKE_BIN/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

log_file="${KUBECTL_LOG:?}"
printf '%s\n' "$*" >> "$log_file"

if [[ "${1:-}" == "config" && "${2:-}" == "current-context" ]]; then
  printf 'admin@test-cluster\n'
  exit 0
fi

if [[ "${1:-}" == "config" && "${2:-}" == "view" ]]; then
  if [[ "$*" == *"cluster.server"* ]]; then
    printf 'https://example.invalid'
    exit 0
  fi

  if [[ "$*" == *"certificate-authority-data"* ]]; then
    printf 'ZmFrZS1jYQ=='
    exit 0
  fi

  if [[ "$*" == *"context.cluster"* ]]; then
    printf 'demo-cluster'
    exit 0
  fi
fi

if [[ "${1:-}" == "--context" && "${3:-}" == "create" && "${4:-}" == "-f" ]]; then
  cp "$5" "${RBAC_SNAPSHOT:?}"
  awk '$1 == "name:" && $2 ~ /^ism-scan-reader-/ { print $2; exit }' "$5" >> "${RBAC_NAMES_LOG:?}"
  [[ "${FAIL_RBAC_CREATE:-false}" != "true" ]]
  exit
fi

if [[ "${1:-}" == "--context" && "${5:-}" == "create" && "${6:-}" == "token" ]]; then
  printf 'fake-scan-token\n'
  exit 0
fi

if [[ "${1:-}" == "config" && ( "${2:-}" == "set-credentials" || "${2:-}" == "set-context" ) ]]; then
  exit 0
fi

if [[ "${1:-}" == "--context" && "${3:-}" == "get" && "${4:-}" == "ns" ]]; then
  printf 'NAME\n'
  printf 'default\n'
  exit 0
fi

if [[ "${1:-}" == "--context" && "${4:-}" == "get" && "${5:-}" == "configmap" ]]; then
  exit 1
fi

if [[ "${1:-}" == "--context" && "${3:-}" == "delete" && "${4:-}" == "-f" ]]; then
  cmp -s "$5" "${RBAC_SNAPSHOT:?}"
  exit 0
fi

printf 'Unexpected kubectl invocation: %s\n' "$*" >&2
exit 1
EOF
chmod +x "$FAKE_BIN/kubectl"

cat > "$FAKE_BIN/kubescape" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=""
artifacts_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    --use-artifacts-from)
      artifacts_dir="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

python3 - <<'PY' "$artifacts_dir/controls-inputs.json" "$output"
import json
import os
import stat
import sys
from pathlib import Path

controls = json.loads(Path(sys.argv[1]).read_text())
expected = ["docker.io/", "ghcr.io/", "quay.io/", "registry.k8s.io/"]
assert controls.get("imageRepositoryAllowList") == expected, controls

kubeconfig_path = Path(os.environ["KUBECONFIG"])
kubeconfig = json.loads(kubeconfig_path.read_text())
assert stat.S_IMODE(kubeconfig_path.stat().st_mode) == 0o600
assert len(kubeconfig["clusters"]) == 1
assert len(kubeconfig["users"]) == 1
assert len(kubeconfig["contexts"]) == 1
context_name = kubeconfig["current-context"]
assert context_name.startswith("ism-scan-reader-")
assert kubeconfig["users"][0]["name"] == context_name
assert kubeconfig["users"][0]["user"] == {"token": "fake-scan-token"}

output_path = Path(sys.argv[2])
output_path.parent.mkdir(parents=True, exist_ok=True)
payload = {
    "clusterName": "",
    "generationTime": "0001-01-01T00:00:00Z",
    "summaryDetails": {
        "status": "passed",
        "ResourceCounters": {
            "failedResources": 0,
            "passedResources": 1,
            "skippedResources": 0,
            "excludedResources": 0,
        },
        "controls": {
            "ISM-K8S-ALLOWED-REGISTRIES": {
                "name": "Allowed registries",
                "status": "passed",
                "severity": "High",
                "complianceScore": 100,
                "ResourceCounters": {
                    "failedResources": 0,
                    "passedResources": 1,
                    "skippedResources": 0,
                    "excludedResources": 0,
                },
                "statusInfo": {"status": "passed"},
            }
        },
    },
    "results": [],
    "metadata": {
        "targetMetadata": {
            "clusterContextMetadata": {
                "contextName": "ism-scan-reader"
            }
        }
    },
}
output_path.write_text(json.dumps(payload))
PY

[[ "${FAIL_SCAN:-false}" != "true" ]]
EOF
chmod +x "$FAKE_BIN/kubescape"

export PATH="$FAKE_BIN:$PATH"
export KUBECTL_LOG
export RBAC_SNAPSHOT
export RBAC_NAMES_LOG

ARTIFACTS_DIR="$ARTIFACTS_DIR" bash "$ROOT/scripts/latticework_ism_scan.sh" \
  --target-context admin@test-cluster \
  --yes \
  --evidence-dir "$EVIDENCE_DIR" \
  >"$scan_stdout" 2>"$scan_stderr"

json_output="$(find "$EVIDENCE_DIR" -name 'cluster-scan-*.json' -print -quit)"

test -n "$json_output"
grep -qE '^[[:space:]]+- serviceaccounts$' "$RBAC_SNAPSHOT"
! grep -qE '^[[:space:]]+- secrets$' "$RBAC_SNAPSHOT"
test -z "$(find "$ARTIFACTS_DIR" -mindepth 1 -maxdepth 1 -name 'latticework-ism-scan-*' -print -quit)"

grep -q 'Falling back to the default registry allow list' "$scan_stderr"
grep -q 'Import the JSON into Latticework Posture' "$scan_stdout"
grep -q 'Temporary scan RBAC and local files removed' "$scan_stdout"

grep -q -- '--context admin@test-cluster create -f' "$KUBECTL_LOG"
grep -q -- '--context admin@test-cluster delete -f' "$KUBECTL_LOG"

ARTIFACTS_DIR="$ARTIFACTS_DIR" bash "$ROOT/scripts/latticework_ism_scan.sh" \
  --target-context admin@test-cluster \
  --yes \
  --evidence-dir "$EVIDENCE_DIR" \
  >/dev/null 2>>"$scan_stderr"

test "$(find "$EVIDENCE_DIR" -name 'cluster-scan-*.json' | wc -l | tr -d ' ')" = "2"
test -z "$(find "$ARTIFACTS_DIR" -mindepth 1 -maxdepth 1 -name 'latticework-ism-scan-*' -print -quit)"
test "$(grep -c -- '--context admin@test-cluster create -f' "$KUBECTL_LOG")" = "2"
test "$(grep -c -- '--context admin@test-cluster delete -f' "$KUBECTL_LOG")" = "2"

if ARTIFACTS_DIR="$ARTIFACTS_DIR" FAIL_SCAN=true bash "$ROOT/scripts/latticework_ism_scan.sh" \
  --target-context admin@test-cluster \
  --yes \
  --evidence-dir "$EVIDENCE_DIR" \
  >/dev/null 2>>"$scan_stderr"; then
  printf 'Expected the simulated scan failure to propagate.\n' >&2
  exit 1
fi

test -z "$(find "$ARTIFACTS_DIR" -mindepth 1 -maxdepth 1 -name 'latticework-ism-scan-*' -print -quit)"
test "$(grep -c -- '--context admin@test-cluster create -f' "$KUBECTL_LOG")" = "3"
test "$(grep -c -- '--context admin@test-cluster delete -f' "$KUBECTL_LOG")" = "3"
test "$(sort -u "$RBAC_NAMES_LOG" | wc -l | tr -d ' ')" = "3"

if ARTIFACTS_DIR="$ARTIFACTS_DIR" FAIL_RBAC_CREATE=true bash "$ROOT/scripts/latticework_ism_scan.sh" \
  --target-context admin@test-cluster \
  --yes \
  --evidence-dir "$EVIDENCE_DIR" \
  >/dev/null 2>>"$scan_stderr"; then
  printf 'Expected the simulated RBAC creation failure to propagate.\n' >&2
  exit 1
fi

test -z "$(find "$ARTIFACTS_DIR" -mindepth 1 -maxdepth 1 -name 'latticework-ism-scan-*' -print -quit)"
test "$(grep -c -- '--context admin@test-cluster create -f' "$KUBECTL_LOG")" = "4"
test "$(grep -c -- '--context admin@test-cluster delete -f' "$KUBECTL_LOG")" = "4"
test "$(sort -u "$RBAC_NAMES_LOG" | wc -l | tr -d ' ')" = "4"

printf 'Smoke test passed.\n'
