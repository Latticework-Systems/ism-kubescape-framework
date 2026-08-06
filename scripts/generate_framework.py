#!/usr/bin/env python3
"""Generate control, framework, and rule metadata from mapping/kubescape.json.

Run through `make generate` or `make build`.
"""

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MAPPING_PATH = ROOT / "mapping/kubescape.json"
CONTROLS_DIR = ROOT / "controls"
FRAMEWORKS_DIR = ROOT / "frameworks"
RULES_DIR = ROOT / "rules"


def load_json(path: Path):
    return json.loads(path.read_text())


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def control_id(rule_id: str) -> str:
    return "ISM-K8S-" + rule_id.removeprefix("ism-").upper()


def alert_score(rego: str) -> float:
    scores = set(re.findall(r'"alertScore"\s*:\s*([0-9]+)', rego))
    if len(scores) != 1:
        raise ValueError(f"expected one alertScore value, got {sorted(scores)}")
    return float(scores.pop())


def main() -> None:
    mapping = load_json(MAPPING_PATH)
    mapping_sha = hashlib.sha256(MAPPING_PATH.read_bytes()).hexdigest()
    mapped = {check["rule_id"]: check for check in mapping["checks"]}
    excluded = {check["rule_id"] for check in mapping["excluded_unmapped_rules"]}
    metadata_paths = {load_json(path)["name"]: path for path in RULES_DIR.glob("*/rule.metadata.json")}

    unaccounted = set(metadata_paths) - set(mapped) - excluded
    missing = set(mapped) - set(metadata_paths)
    if unaccounted or missing:
        raise ValueError(f"rule inventory mismatch: unaccounted={sorted(unaccounted)} missing={sorted(missing)}")

    controls = []
    for rule_id, check in sorted(mapped.items()):
        metadata_path = metadata_paths[rule_id]
        metadata = load_json(metadata_path)
        ism_ids = sorted(control["ism_id"] for control in check["ism_controls"])
        metadata.setdefault("attributes", {})["ismControls"] = ism_ids
        metadata["attributes"]["provenance"] = check["provenance"]
        write_json(metadata_path, metadata)

        rego = (metadata_path.parent / "raw.rego").read_text()
        references = ["https://www.cyber.gov.au/ism/oscal/latest-version/artifacts/ISM_catalog.json"]
        upstream = check["provenance"].get("upstream")
        if upstream:
            references.append(f"{upstream['repository']}/tree/{upstream['ref']}")

        control = {
            "controlID": control_id(rule_id),
            "name": rule_id.removeprefix("ism-").replace("-", " ").capitalize(),
            "description": metadata["description"],
            "long_description": " ".join(
                f"{item['ism_id']} ({item['coverage']}): {item['evidence_note']}" for item in check["ism_controls"]
            ),
            "remediation": metadata["remediation"],
            "rulesNames": [rule_id],
            "references": references,
            "attributes": {
                "controlTypeTags": ["compliance"],
                "ismControls": ism_ids,
                "mappingRelease": mapping["source"]["ism_release"],
                "mappingSourceSha256": mapping_sha,
                "provenance": check["provenance"],
            },
            "baseScore": alert_score(rego),
            "category": {
                "name": "Access control"
                if any("rbac.authorization.k8s.io" in match.get("apiGroups", []) for match in metadata["match"])
                else "Workload"
            },
            "scanningScope": {"matches": ["cluster", "file"]},
        }
        controls.append(control)

    for path in CONTROLS_DIR.glob("*.json"):
        path.unlink()
    for control in controls:
        write_json(CONTROLS_DIR / f"{control['controlID'].lower()}.json", control)

    for path in FRAMEWORKS_DIR.glob("*.json"):
        path.unlink()
    framework = {
        "name": "ism-kubernetes",
        "description": "Standalone Kubernetes-observable controls mapped to the Australian Signals Directorate Information Security Manual.",
        "attributes": {
            "frameworkOwner": "Latticework Systems",
            "frameworkVersion": "0.1.0",
            "mappingRelease": mapping["source"]["ism_release"],
            "mappingSourceSha256": mapping_sha,
        },
        "scanningScope": {"matches": ["cluster", "file"]},
        "typeTags": ["compliance"],
        "activeControls": [{"controlID": control["controlID"]} for control in controls],
    }
    write_json(FRAMEWORKS_DIR / "ism-kubernetes.json", framework)


if __name__ == "__main__":
    main()
