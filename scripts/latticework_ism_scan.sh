#!/usr/bin/env bash
# Guided read-only live-cluster scan.
#
# Creates per-run RBAC from examples/scan-reader-rbac.yaml and, when Kyverno
# is installed, examples/scan-reader-kyverno-role.yaml. It mints a short-lived
# token, writes a mode-0600 kubeconfig containing that token, runs Kubescape,
# writes JSON under evidence/, and removes the temporary RBAC, kubeconfig, and
# build artifacts. Run via `make latticework-ism-scan`.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$ROOT/dist}"
EVIDENCE_DIR="${EVIDENCE_DIR:-$ROOT/evidence}"
RBAC_TEMPLATE="$ROOT/examples/scan-reader-rbac.yaml"
KYVERNO_ROLE_TEMPLATE="$ROOT/examples/scan-reader-kyverno-role.yaml"
KYVERNO_ROLE_INCLUDED="false"
SCAN_CONTEXT=""
SCAN_NAMESPACE=""
SCAN_SERVICE_ACCOUNT=""
DEFAULT_REGISTRY_CSV="docker.io/,ghcr.io/,quay.io/,registry.k8s.io/"
# Where the approved-registry allow list lives, as NAMESPACE/NAME[:KEY].
# Override with --registry-configmap when the Kyverno deployment names it
# differently. KEY defaults to "registries".
DEFAULT_REGISTRY_CONFIGMAP="kyverno/ism-approved-registries:registries"
REGISTRY_CONFIGMAP="${REGISTRY_CONFIGMAP:-}"
CONFIGMAP_NAMESPACE=""
CONFIGMAP_NAME=""
CONFIGMAP_KEY=""
CONFIGMAP_EXPLICIT="false"
TARGET_CONTEXT="${TARGET_CONTEXT:-}"
AUTO_YES="${AUTO_YES:-false}"
USE_CONFIGMAP_SOURCE=""
REGISTRY_CSV="${REGISTRY_CSV:-}"
TEMP_KUBECONFIG=""
TEMP_ARTIFACTS_DIR=""
TEMP_RBAC_MANIFEST=""
SCAN_RBAC_CREATED="false"

# Print the --help text.
usage() {
  cat <<'EOF'
Usage: scripts/latticework_ism_scan.sh [options]

Guided setup for a read-only scan identity plus Kubescape scan/report generation.

Options:
  --target-context NAME       Existing kube context to use as the source cluster
  --registries CSV            Comma-separated approved registries to use for the scan
  --registry-configmap REF    ConfigMap holding the allow list, as NAMESPACE/NAME[:KEY]
                              (default: kyverno/ism-approved-registries:registries)
  --evidence-dir PATH         Where to write durable Kubescape JSON output (default: ./evidence)
  --yes                       Non-interactive where possible
  --help                      Show this help
EOF
}

# Give each run its own Kubernetes objects so cleanup cannot alter a
# pre-existing scan namespace, service account, role, or binding.
init_run_names() {
  local suffix
  suffix="$(date +%s)-$$"
  SCAN_NAMESPACE="ism-scan-$suffix"
  SCAN_SERVICE_ACCOUNT="ism-scan-reader-$suffix"
  SCAN_CONTEXT="$SCAN_SERVICE_ACCOUNT"
}

# Ask a yes/no question interactively (defaulting to $2 on empty input), or
# auto-answer with the default when AUTO_YES=true.
prompt_yes_no() {
  local message="$1"
  local default_answer="${2:-yes}"
  local answer

  if [[ "$AUTO_YES" == "true" ]]; then
    [[ "$default_answer" == "yes" ]]
    return
  fi

  if [[ "$default_answer" == "yes" ]]; then
    read -r -p "$message [Y/n] " answer
    [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]]
  else
    read -r -p "$message [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]]
  fi
}

# Exit with an error if kubectl, kubescape, or python3 is missing from PATH.
require_prereqs() {
  local missing=()
  for cmd in kubectl kubescape python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    printf 'Missing required commands: %s\n' "${missing[*]}" >&2
    printf 'Install them first, then rerun make latticework-ism-scan.\n' >&2
    printf 'This script validates prerequisites but does not install kubectl, kubescape, or python3 for you.\n' >&2
    exit 1
  fi
}

# Parse CLI flags into the script's global option variables.
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target-context)
        TARGET_CONTEXT="$2"
        shift 2
        ;;
      --registries)
        REGISTRY_CSV="$2"
        shift 2
        ;;
      --registry-configmap)
        REGISTRY_CONFIGMAP="$2"
        shift 2
        ;;
      --evidence-dir)
        EVIDENCE_DIR="$2"
        shift 2
        ;;
      --yes)
        AUTO_YES="true"
        shift
        ;;
      --help)
        usage
        exit 0
        ;;
      *)
        printf 'Unknown option: %s\n' "$1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done
}

# Split the NAMESPACE/NAME[:KEY] ConfigMap reference. Validate namespace and
# name against Kubernetes DNS-1123 rules before passing them to kubectl.
parse_configmap_ref() {
  local ref="${REGISTRY_CONFIGMAP:-$DEFAULT_REGISTRY_CONFIGMAP}"
  local location="${ref%%:*}"
  local key="registries"

  # Set through either the flag or the REGISTRY_CONFIGMAP environment variable.
  if [[ -n "$REGISTRY_CONFIGMAP" ]]; then
    CONFIGMAP_EXPLICIT="true"
  fi

  if [[ "$ref" == *:* ]]; then
    key="${ref##*:}"
  fi

  if [[ "$location" != */* ]]; then
    printf 'Expected --registry-configmap as NAMESPACE/NAME[:KEY], got: %s\n' "$ref" >&2
    exit 1
  fi

  CONFIGMAP_NAMESPACE="${location%%/*}"
  CONFIGMAP_NAME="${location#*/}"
  CONFIGMAP_KEY="$key"

  local dns_label='^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
  local dns_subdomain='^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$'
  if [[ ! "$CONFIGMAP_NAMESPACE" =~ $dns_label ]]; then
    printf 'Invalid ConfigMap namespace: %s\n' "$CONFIGMAP_NAMESPACE" >&2
    exit 1
  fi
  if [[ ! "$CONFIGMAP_NAME" =~ $dns_subdomain ]]; then
    printf 'Invalid ConfigMap name: %s\n' "$CONFIGMAP_NAME" >&2
    exit 1
  fi
  # Reject jsonpath metacharacters before interpolating the key.
  if [[ ! "$CONFIGMAP_KEY" =~ ^[-._a-zA-Z0-9]+$ ]]; then
    printf 'Invalid ConfigMap key: %s\n' "$CONFIGMAP_KEY" >&2
    exit 1
  fi
}

# Use an explicit target context or prompt from the current context.
resolve_target_context() {
  if [[ -n "$TARGET_CONTEXT" ]]; then
    return
  fi

  TARGET_CONTEXT="$(kubectl config current-context)"

  if [[ "$AUTO_YES" != "true" ]]; then
    printf 'Detected current kube context: %s\n' "$TARGET_CONTEXT"
    read -r -p "Enter the source cluster context to use [${TARGET_CONTEXT}]: " response
    if [[ -n "$response" ]]; then
      TARGET_CONTEXT="$response"
    fi
  fi
}

# Look up the cluster name backing a given kube context.
context_cluster_name() {
  local context_name="$1"
  kubectl config view -o "jsonpath={.contexts[?(@.name==\"$context_name\")].context.cluster}"
}

# True if the target cluster has a kyverno namespace, i.e. the optional
# namespaced ConfigMap Role can be created.
kyverno_namespace_present() {
  kubectl --context "$TARGET_CONTEXT" get namespace "$CONFIGMAP_NAMESPACE" >/dev/null 2>&1
}

# Render the example manifests with per-run resource names. Append the Kyverno
# Role only when its namespace exists.
create_temp_rbac_manifest() {
  local sources=("$RBAC_TEMPLATE")

  if kyverno_namespace_present; then
    sources+=("$KYVERNO_ROLE_TEMPLATE")
    KYVERNO_ROLE_INCLUDED="true"
  fi

  mkdir -p "$ARTIFACTS_DIR"
  TEMP_RBAC_MANIFEST="$(mktemp "$ARTIFACTS_DIR/latticework-ism-scan-rbac.XXXXXX")"

  python3 - "$TEMP_RBAC_MANIFEST" "$SCAN_NAMESPACE" "$SCAN_SERVICE_ACCOUNT" \
    "$CONFIGMAP_NAMESPACE" "$CONFIGMAP_NAME" "${sources[@]}" <<'PY'
import os
import sys
from pathlib import Path

target = Path(sys.argv[1])
namespace, service_account, cm_namespace, cm_name = sys.argv[2:6]
sources = [Path(item) for item in sys.argv[6:]]
payload = "---\n".join(source.read_text() for source in sources)

# Required in every rendering.
replacements = [
    ("name: ism-scan-reader\n", f"name: {service_account}\n"),
    ("name: ism-scan\n", f"name: {namespace}\n"),
    ("namespace: ism-scan\n", f"namespace: {namespace}\n"),
]
for old, new in replacements:
    if old not in payload:
        raise ValueError(f"RBAC template is missing expected value: {old.strip()}")
    payload = payload.replace(old, new)

# Retarget the optional Role to the requested ConfigMap. A Role that names the
# default ConfigMap would grant no access when the cluster uses another name.
optional = [
    ("namespace: kyverno\n", f"namespace: {cm_namespace}\n"),
    ("- ism-approved-registries\n", f"- {cm_name}\n"),
]
for old, new in optional:
    payload = payload.replace(old, new)

target.write_text(payload)
os.chmod(target, 0o600)
PY
}

# Create unique read-only scan RBAC after confirmation.
create_scan_rbac() {
  if ! prompt_yes_no "Create temporary read-only scan RBAC from examples/scan-reader-rbac.yaml in ${TARGET_CONTEXT}?" "yes"; then
    printf 'Scan cancelled before creating temporary RBAC.\n' >&2
    exit 1
  fi

  create_temp_rbac_manifest
  SCAN_RBAC_CREATED="true"
  kubectl --context "$TARGET_CONTEXT" create -f "$TEMP_RBAC_MANIFEST"
}

# Write a mode-0600 temporary kubeconfig under dist/ with one cluster, one
# token-backed user, and one context. Read cluster name, server, and CA data
# ($1-$3) from the caller's kubeconfig. Use the freshly minted scan token ($4)
# as the only credential.
create_temp_kubeconfig() {
  local cluster_name="$1"
  local server="$2"
  local ca_data="$3"
  local token="$4"

  mkdir -p "$ARTIFACTS_DIR"
  umask 077
  TEMP_KUBECONFIG="$(mktemp "$ARTIFACTS_DIR/latticework-ism-scan-kubeconfig.XXXXXX")"

  # Pass the token through the environment. Process arguments are visible in
  # ps and /proc/<pid>/cmdline.
  SCAN_TOKEN="$token" python3 - "$TEMP_KUBECONFIG" "$cluster_name" "$server" "$ca_data" "$SCAN_CONTEXT" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
cluster_name, server, ca_data, context_name = sys.argv[2:]
token = os.environ["SCAN_TOKEN"]
payload = {
    "apiVersion": "v1",
    "kind": "Config",
    "clusters": [{
        "name": cluster_name,
        "cluster": {
            "server": server,
            "certificate-authority-data": ca_data,
        },
    }],
    "users": [{"name": context_name, "user": {"token": token}}],
    "contexts": [{
        "name": context_name,
        "context": {"cluster": cluster_name, "user": context_name},
    }],
    "current-context": context_name,
}

flags = os.O_WRONLY | os.O_CREAT
if path.exists():
    flags |= os.O_TRUNC
else:
    flags |= os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW

fd = os.open(path, flags, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2)
    handle.write("\n")
os.chmod(path, 0o600)
PY
}

# Create a scratch directory under dist/ for temporary framework artifacts.
create_temp_artifacts_dir() {
  mkdir -p "$ARTIFACTS_DIR"
  TEMP_ARTIFACTS_DIR="$(mktemp -d "$ARTIFACTS_DIR/latticework-ism-scan-artifacts-XXXXXX")"
}

# Resolve the target cluster endpoint and CA data, mint a short-lived token
# with `kubectl create token`, and build the scan-only kubeconfig.
setup_scan_context() {
  local cluster_name server ca_data token
  cluster_name="$(context_cluster_name "$TARGET_CONTEXT")"
  server="$(kubectl config view --context="$TARGET_CONTEXT" --minify --flatten --raw -o 'jsonpath={.clusters[0].cluster.server}')"
  ca_data="$(kubectl config view --context="$TARGET_CONTEXT" --minify --flatten --raw -o 'jsonpath={.clusters[0].cluster.certificate-authority-data}')"

  if [[ -z "$cluster_name" || -z "$server" || -z "$ca_data" ]]; then
    printf 'Could not resolve the selected cluster name, endpoint, and CA data for context %s.\n' "$TARGET_CONTEXT" >&2
    exit 1
  fi

  token="$(kubectl --context "$TARGET_CONTEXT" -n "$SCAN_NAMESPACE" create token "$SCAN_SERVICE_ACCOUNT")"
  if [[ -z "$token" ]]; then
    printf 'The scan-reader token command returned an empty token.\n' >&2
    exit 1
  fi
  create_temp_kubeconfig "$cluster_name" "$server" "$ca_data" "$token"

  printf 'Created scan-only temporary kubeconfig context: %s\n' "$SCAN_CONTEXT"
  KUBECONFIG="$TEMP_KUBECONFIG" kubectl --context "$SCAN_CONTEXT" get ns >/dev/null
}

# Check whether the scan identity can read the selected registry ConfigMap.
configmap_source_available() {
  KUBECONFIG="$TEMP_KUBECONFIG" kubectl --context "$SCAN_CONTEXT" \
    -n "$CONFIGMAP_NAMESPACE" get configmap "$CONFIGMAP_NAME" >/dev/null 2>&1
}

# Read the approved-registry allow list with the scan identity and return CSV.
#
# The rule reads control inputs, not this ConfigMap in the scanned objects. A
# scanned ConfigMap could otherwise widen the allow list for the same scan.
read_configmap_registries() {
  KUBECONFIG="$TEMP_KUBECONFIG" kubectl --context "$SCAN_CONTEXT" \
    -n "$CONFIGMAP_NAMESPACE" get configmap "$CONFIGMAP_NAME" \
    -o "jsonpath={.data['$CONFIGMAP_KEY']}" |
    tr '\n' ',' |
    sed -e 's/,\{2,\}/,/g' -e 's/^,//' -e 's/,$//'
}

# Report differences between the cluster allow list and the list the scan would
# otherwise use.
report_registry_drift() {
  local cluster_csv="$1"
  local local_csv="$2"
  local local_label="$3"

  python3 - "$cluster_csv" "$local_csv" "$local_label" <<'PY'
import sys

cluster_csv, local_csv, label = sys.argv[1:4]


def entries(csv):
    return {item.strip().rstrip("*") for item in csv.split(",") if item.strip()}


cluster, local = entries(cluster_csv), entries(local_csv)
only_cluster = sorted(cluster - local)
only_local = sorted(local - cluster)

if not only_cluster and not only_local:
    print(f"Registry allow list matches {label}; no drift.")
else:
    print(f"Registry allow-list drift against {label}:")
    for item in only_cluster:
        print(f"  + {item}  (cluster ConfigMap only)")
    for item in only_local:
        print(f"  - {item}  ({label} only)")
PY
}

# Merge the approved-registry allow list (REGISTRY_CSV, comma-separated)
# into the temporary artifacts' controls-inputs.json as
# imageRepositoryAllowList, preserving any other keys already there.
write_registry_inputs() {
  mkdir -p "$TEMP_ARTIFACTS_DIR"

  python3 - "$TEMP_ARTIFACTS_DIR/controls-inputs.json" "$REGISTRY_CSV" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
registries = [item.strip() for item in sys.argv[2].split(",") if item.strip()]

payload = {}
if path.exists():
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError:
        payload = {}

payload["imageRepositoryAllowList"] = registries
path.write_text(json.dumps(payload, indent=2) + "\n")
PY
}

# Select the approved-registry source: the cluster ConfigMap, a user-supplied
# CSV, or the built-in default. Write every result to controls-inputs.json.
configure_registry_source() {
  local cluster_csv
  local configmap_ref="$CONFIGMAP_NAMESPACE/$CONFIGMAP_NAME"

  create_temp_artifacts_dir

  if ! configmap_source_available; then
    # An explicit ConfigMap must be readable. The default location may be
    # absent because many clusters do not run Kyverno.
    if [[ "$CONFIGMAP_EXPLICIT" == "true" ]]; then
      printf 'Cannot read ConfigMap %s with the scan identity.\n' "$configmap_ref" >&2
      printf 'Check the name, the namespace, and that examples/scan-reader-kyverno-role.yaml covers it.\n' >&2
      exit 1
    fi
  else
    if prompt_yes_no "Reuse $configmap_ref from the cluster as the registry source?" "yes"; then
      cluster_csv="$(read_configmap_registries)"
      if [[ -z "$cluster_csv" ]]; then
        printf 'ConfigMap %s has no usable %s key.\n' "$configmap_ref" "$CONFIGMAP_KEY" >&2
        exit 1
      fi

      if [[ -n "$REGISTRY_CSV" ]]; then
        report_registry_drift "$cluster_csv" "$REGISTRY_CSV" "the supplied --registries list"
      else
        report_registry_drift "$cluster_csv" "$DEFAULT_REGISTRY_CSV" "the default allow list"
      fi

      USE_CONFIGMAP_SOURCE="true"
      REGISTRY_CSV="$cluster_csv"
      write_registry_inputs
      return
    fi
  fi

  if [[ -z "$REGISTRY_CSV" && "$AUTO_YES" != "true" ]]; then
    read -r -p "Enter approved registries as a comma-separated list (for example ghcr.io/your-org/,registry.internal/,docker.io/library/): " REGISTRY_CSV
  fi

  if [[ -z "$REGISTRY_CSV" ]]; then
    REGISTRY_CSV="$DEFAULT_REGISTRY_CSV"
    printf 'No approved registries provided and cluster ConfigMap source not selected.\n' >&2
    printf 'Falling back to the default registry allow list: %s\n' "$REGISTRY_CSV" >&2
  fi

  write_registry_inputs
}

# Human-readable description of the registry allow-list source.
registry_source_label() {
  if [[ -n "$USE_CONFIGMAP_SOURCE" ]]; then
    printf 'Cluster ConfigMap %s/%s key %s (%s)' \
      "$CONFIGMAP_NAMESPACE" "$CONFIGMAP_NAME" "$CONFIGMAP_KEY" "$REGISTRY_CSV"
    return
  fi

  if [[ "$REGISTRY_CSV" == "$DEFAULT_REGISTRY_CSV" ]]; then
    printf 'Default allow list (%s)' "$DEFAULT_REGISTRY_CSV"
    return
  fi

  printf 'User-supplied allow list (%s)' "$REGISTRY_CSV"
}

# Run Kubescape through scripts/scan_cluster.sh with the scan-only context and
# temporary artifacts. Write JSON under evidence/ and print its path.
run_scan() {
  local timestamp sanitized output_path

  mkdir -p "$EVIDENCE_DIR"
  timestamp="$(date +%Y%m%d-%H%M%S)-$$"
  sanitized="$(printf '%s' "$SCAN_CONTEXT" | tr '/:@' '___')"
  output_path="$EVIDENCE_DIR/cluster-scan-${sanitized}-${timestamp}.json"

  printf 'Running scan with context: %s\n' "$SCAN_CONTEXT"
  KUBECONFIG="$TEMP_KUBECONFIG" QUIET_SUMMARY="true" ARTIFACTS_DIR="$TEMP_ARTIFACTS_DIR" OUTPUT_PATH="$output_path" KUBE_CONTEXT="$SCAN_CONTEXT" "$ROOT/scripts/scan_cluster.sh"

  printf '\nContext: %s\nRegistry source: %s\nJSON: %s\n' \
    "$SCAN_CONTEXT" "$(registry_source_label)" "$output_path"

  cat <<EOF

Next step:
  Import the JSON into Latticework Posture, or correlate the findings with
  the companion ISM-to-Kubernetes mapping and Kyverno policy repository.
EOF
}

# EXIT trap: remove everything this run created, on success or failure.
cleanup() {
  local exit_code="$1"
  local cleanup_failed="false"

  trap - EXIT

  if [[ "$SCAN_RBAC_CREATED" == "true" && -n "$TARGET_CONTEXT" && -f "$TEMP_RBAC_MANIFEST" ]]; then
    if ! kubectl --context "$TARGET_CONTEXT" delete -f "$TEMP_RBAC_MANIFEST" --ignore-not-found; then
      printf 'Failed to remove temporary scan RBAC from %s.\n' "$TARGET_CONTEXT" >&2
      cleanup_failed="true"
    fi
  fi

  if [[ -n "$TEMP_KUBECONFIG" && -f "$TEMP_KUBECONFIG" ]]; then
    if ! rm -f "$TEMP_KUBECONFIG"; then
      printf 'Failed to remove temporary kubeconfig: %s\n' "$TEMP_KUBECONFIG" >&2
      cleanup_failed="true"
    fi
  fi

  if [[ -n "$TEMP_ARTIFACTS_DIR" && -d "$TEMP_ARTIFACTS_DIR" ]]; then
    if ! rm -rf "$TEMP_ARTIFACTS_DIR"; then
      printf 'Failed to remove temporary build artifacts: %s\n' "$TEMP_ARTIFACTS_DIR" >&2
      cleanup_failed="true"
    fi
  fi

  if [[ -n "$TEMP_RBAC_MANIFEST" && -f "$TEMP_RBAC_MANIFEST" ]]; then
    if ! rm -f "$TEMP_RBAC_MANIFEST"; then
      printf 'Failed to remove temporary RBAC manifest: %s\n' "$TEMP_RBAC_MANIFEST" >&2
      cleanup_failed="true"
    fi
  fi

  if [[ "$cleanup_failed" == "true" ]]; then
    exit 1
  fi

  [[ "$SCAN_RBAC_CREATED" != "true" && -z "$TEMP_KUBECONFIG" && -z "$TEMP_ARTIFACTS_DIR" && -z "$TEMP_RBAC_MANIFEST" ]] ||
    printf 'Temporary scan RBAC and local files removed.\n'
  exit "$exit_code"
}

# Entry point: validate prerequisites, parse args, resolve the target
# context, apply RBAC, set up the scan-only context, configure the
# registry source, and run the scan.
main() {
  trap 'cleanup "$?"' EXIT
  require_prereqs
  parse_args "$@"
  parse_configmap_ref
  init_run_names
  resolve_target_context

  printf 'Source cluster context: %s\n' "$TARGET_CONTEXT"
  create_scan_rbac
  setup_scan_context
  configure_registry_source
  run_scan
}

main "$@"
