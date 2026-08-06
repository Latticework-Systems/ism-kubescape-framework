OPA ?= opa
KUBESCAPE ?= kubescape
KUBE_CONTEXT ?=
OUTPUT_PATH ?=
SCAN_ARGS ?=
CONTROLS_REPO ?= Latticework-Systems/ism-kubernetes-controls
CONTROLS_VERSION ?=

.PHONY: generate update-mapping build test integration smoke raw-cluster-scan latticework-ism-scan clean

generate:
	python3 scripts/generate_framework.py

update-mapping:
	@set -eu; \
	test -n "$(CONTROLS_VERSION)" || { echo "Set CONTROLS_VERSION to an immutable controls release tag, for example v0.2.0."; exit 1; }; \
	command -v curl >/dev/null || { echo "Install curl first."; exit 1; }; \
	tmp_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp_dir"' EXIT; \
	base_url="https://github.com/$(CONTROLS_REPO)/releases/download/$(CONTROLS_VERSION)"; \
	curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --retry 3 \
		--output "$$tmp_dir/kubescape.json" "$$base_url/kubescape.json"; \
	curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --retry 3 \
		--output "$$tmp_dir/kubescape.json.sha256" "$$base_url/kubescape.json.sha256"; \
	expected="$$(awk 'NF { print $$1; exit }' "$$tmp_dir/kubescape.json.sha256")"; \
	printf '%s\n' "$$expected" | grep -Eq '^[0-9a-fA-F]{64}$$' || { echo "Invalid mapping checksum." >&2; exit 1; }; \
	if command -v sha256sum >/dev/null; then actual="$$(sha256sum "$$tmp_dir/kubescape.json" | awk '{ print $$1 }')"; else actual="$$(shasum -a 256 "$$tmp_dir/kubescape.json" | awk '{ print $$1 }')"; fi; \
	test "$$actual" = "$$expected" || { echo "Mapping checksum mismatch." >&2; exit 1; }; \
	cp "$$tmp_dir/kubescape.json" mapping/kubescape.json
	$(MAKE) build test

build: generate
	python3 scripts/build_artifacts.py

test:
	@set -e; for rule in rules/*/raw.rego; do $(OPA) check --strict --v0-compatible "$$rule"; done
	python3 scripts/run_rule_tests.py --opa $(OPA)

integration: generate
	KUBESCAPE_BIN=$(KUBESCAPE) scripts/run_integration.sh

smoke:
	bash tests/smoke/test_latticework_ism_scan.sh

raw-cluster-scan:
	KUBESCAPE_BIN=$(KUBESCAPE) KUBE_CONTEXT="$(KUBE_CONTEXT)" OUTPUT_PATH="$(OUTPUT_PATH)" scripts/scan_cluster.sh $(SCAN_ARGS)

latticework-ism-scan:
	AUTO_YES="$(AUTO_YES)" TARGET_CONTEXT="$(TARGET_CONTEXT)" REGISTRY_CSV="$(REGISTRY_CSV)" REGISTRY_CONFIGMAP="$(REGISTRY_CONFIGMAP)" EVIDENCE_DIR="$(EVIDENCE_DIR)" bash scripts/latticework_ism_scan.sh

clean:
	rm -f dist/*.json
