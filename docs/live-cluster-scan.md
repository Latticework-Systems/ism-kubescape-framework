# Live Cluster Scan

The workflow produces raw Kubescape JSON. Latticework Posture owns reporting and assessment UX; the companion ISM-to-Kubernetes repository owns mappings and admission enforcement.

Start with `make latticework-ism-scan`. The command builds the scanner artifacts, so `make build` is not required first.

## Prerequisites

- `bash`
- `kubectl`
- `kubescape`
- `python3`
- a selected Kubernetes context that can create and delete the temporary scan RBAC

The starter identity in [examples/scan-reader-rbac.yaml](../examples/scan-reader-rbac.yaml) can read the workload, namespace, NetworkPolicy, and RBAC resources needed by the current rules. A separate namespaced Role grants `get` access to the selected registry ConfigMap only. The identity cannot list ConfigMaps or read Secrets.

## Guided scan

Confirm the current context:

```bash
kubectl config current-context
```

Then run:

```bash
make latticework-ism-scan
```

The script confirms creation of uniquely named RBAC, creates a scan-only temporary kubeconfig from the selected cluster endpoint and CA data, mints a short-lived token, runs Kubescape, prints the resulting JSON path, and removes the temporary RBAC and local files.

For a specified non-interactive run:

```bash
make latticework-ism-scan \
  TARGET_CONTEXT=<cluster-context> \
  REGISTRY_CSV='ghcr.io/your-org/,registry.example/' \
  AUTO_YES=true
```

With no registry list, the script uses the companion `kyverno/ism-approved-registries` ConfigMap when available and reports the built-in list otherwise.

The temporary scan identity reads the ConfigMap through an authenticated API call. The script writes the value into `controls-inputs.json` as a control input. The Rego rule reads control inputs rather than ConfigMaps in the scanned objects. A scanned ConfigMap could otherwise authorise images for the same scan.

Point the script at a differently named ConfigMap with `--registry-configmap NAMESPACE/NAME[:KEY]`, or the `REGISTRY_CONFIGMAP` variable. `KEY` defaults to `registries`.

```bash
make latticework-ism-scan REGISTRY_CONFIGMAP='policy/approved-images:allowed.txt'
```

The script retargets the temporary Role in `examples/scan-reader-kyverno-role.yaml` to the selected ConfigMap. The scan identity receives `get` on that ConfigMap only. An explicit reference must be readable; otherwise the run fails. The default reference may be absent because many clusters do not run Kyverno.

When the scan uses the ConfigMap, the output shows differences between the cluster list and the list the scan would otherwise use:

```
Registry allow-list drift against the supplied --registries list:
  + registry.internal/     (cluster ConfigMap only)
  - ghcr.io/your-org/      (the supplied --registries list only)
```

The script writes durable scan output under `evidence/`. It creates temporary framework artifacts and the scan-only kubeconfig under `dist/`, then removes them on success or failure. The temporary reader also has read-only access to `nodes`, which Kubescape uses for cloud-provider detection; it has no write or Secret access.

Treat raw scan JSON as sensitive operational evidence. It can contain cluster resource names, image references, RBAC subjects, and ConfigMap data even though the scan identity cannot read Secrets. Review and sanitise it before sharing it outside the assessed environment.

## Lower-level scan

To use an existing context without the guided identity setup:

```bash
KUBE_CONTEXT=<cluster-context> scripts/scan_cluster.sh
```

`scripts/scan_cluster.sh` builds the local artifacts. Use this path when you accept the existing context's permissions.

Useful Kubescape arguments can be passed through the lower-level helper, for example:

```bash
KUBE_CONTEXT=<cluster-context> \
  scripts/scan_cluster.sh --include-namespaces default,apps
```

## Result interpretation

Prioritise false negatives first, then false positives. Reproduce every scanner bug with a fixture under `rules/*/test/` and run:

```bash
make test
make integration
```

The scan covers the included automated rules and the resources visible to the scan identity. It does not constitute an ISM assessment.
