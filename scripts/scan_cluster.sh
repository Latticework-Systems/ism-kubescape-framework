#!/usr/bin/env bash
# Scan with an existing kube context. Use latticework_ism_scan.sh for a
# temporary least-privilege identity.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUBESCAPE_BIN="${KUBESCAPE_BIN:-kubescape}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$ROOT/dist}"
KUBE_CONTEXT="${KUBE_CONTEXT:-$(kubectl config current-context)}"
QUIET_SUMMARY="${QUIET_SUMMARY:-false}"

# Replace characters unsafe in a filename (/, :, @) with underscores, so a
# kube context name can be used in the default output filename.
sanitize() {
  printf '%s' "$1" | tr '/:@' '___'
}

timestamp="$(date +%Y%m%d-%H%M%S)"
default_output="$ARTIFACTS_DIR/cluster-scan-$(sanitize "$KUBE_CONTEXT")-$timestamp.json"
OUTPUT_PATH="${OUTPUT_PATH:-$default_output}"

DIST_DIR="$ARTIFACTS_DIR" python3 "$ROOT/scripts/build_artifacts.py"

mkdir -p "$(dirname "$OUTPUT_PATH")"

"$KUBESCAPE_BIN" scan framework ism-kubernetes \
  --kube-context "$KUBE_CONTEXT" \
  --use-artifacts-from "$ARTIFACTS_DIR" \
  --keep-local \
  --format json \
  --output "$OUTPUT_PATH" \
  "$@"

if [[ "$QUIET_SUMMARY" != "true" ]]; then
  echo "Cluster scan written to $OUTPUT_PATH"
fi
