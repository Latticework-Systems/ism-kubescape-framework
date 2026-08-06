# Contributing

Contributions that improve the accuracy of Kubernetes-observable scanner rules are welcome.

## Boundaries

- Keep the repository focused on raw Kubescape scan generation.
- Put canonical ISM mappings and Kyverno admission policies in the companion mapping repository.
- Do not add manual-review controls, exception registers, assessment checklists, report renderers, customer material, or environment-specific runbooks.
- Describe a passing result as a bounded scanner observation, not proof of compliance.
- Use official ASD material and upstream project documentation for provenance.
- Treat upstream controls as exemplars. Do not add runtime imports from upstream frameworks.

## Development flow

```bash
make build
make test
make smoke
```

If Kubescape is installed, also run:

```bash
make integration
```

Pull requests should identify the scanner control being changed, explain the Kubernetes-observable behaviour, add or update pass and fail fixtures, and cite any authoritative sources used.

Framework and control metadata is generated. Import a reviewed, immutable [`ism-kubernetes-controls`](https://github.com/Latticework-Systems/ism-kubernetes-controls) release with `make update-mapping CONTROLS_VERSION=<tag>`; do not hand-edit generated files under `controls/` or `frameworks/`.
