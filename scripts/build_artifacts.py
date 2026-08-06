#!/usr/bin/env python3
"""Bundle framework, control, and Rego sources under dist/ for Kubescape.

Run after generate_framework.py through `make build`.
"""

import copy
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FRAMEWORKS_DIR = ROOT / "frameworks"
CONTROLS_DIR = ROOT / "controls"
RULES_DIR = ROOT / "rules"
DIST_DIR = Path(os.environ.get("DIST_DIR", ROOT / "dist"))


def load_json(path: Path):
    return json.loads(path.read_text())


def load_rules():
    rules = {}
    for metadata_path in sorted(RULES_DIR.glob("*/rule.metadata.json")):
      rule_dir = metadata_path.parent
      rule = load_json(metadata_path)
      rule["rule"] = (rule_dir / "raw.rego").read_text()
      filter_path = rule_dir / "filter.rego"
      if filter_path.exists():
        rule["resourceEnumerator"] = filter_path.read_text()
      rules[rule["name"]] = rule
    return rules


def load_controls(rules):
    controls = {}
    for control_path in sorted(CONTROLS_DIR.glob("*.json")):
      control = load_json(control_path)
      bundled = copy.deepcopy(control)
      bundled["rules"] = []
      for rule_name in control.get("rulesNames", []):
        bundled["rules"].append(copy.deepcopy(rules[rule_name]))
      controls[control["controlID"]] = bundled
    return controls


def bundle_frameworks(controls):
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    for framework_path in sorted(FRAMEWORKS_DIR.glob("*.json")):
      framework = load_json(framework_path)
      bundled = copy.deepcopy(framework)
      bundled["version"] = "0.1.0"
      bundled["controls"] = []
      bundled["ControlsIDs"] = []
      for active in framework["activeControls"]:
        control = copy.deepcopy(controls[active["controlID"]])
        for key, value in active.get("patch", {}).items():
          control[key] = value
        bundled["controls"].append(control)
        bundled["ControlsIDs"].append(control["controlID"])
      del bundled["activeControls"]
      (DIST_DIR / framework_path.name).write_text(json.dumps(bundled, indent=2) + "\n")


def write_controls_inputs():
    controls_inputs_path = DIST_DIR / "controls-inputs.json"
    if not controls_inputs_path.exists():
      controls_inputs = {}
      controls_inputs_path.write_text(json.dumps(controls_inputs, indent=2) + "\n")
    (DIST_DIR / "exceptions.json").write_text("[]\n")


def main():
    rules = load_rules()
    controls = load_controls(rules)
    bundle_frameworks(controls)
    write_controls_inputs()


if __name__ == "__main__":
    main()
