#!/usr/bin/env python3
"""Check every rule's JSON fixtures with `opa eval`.

Run through `make test`; run_integration.sh tests the assembled framework.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"


def run_case(opa_path: str, rule_dir: Path, case_dir: Path) -> None:
    input_path = case_dir / "input.json"
    data_path = case_dir / "data.json"
    expected_path = case_dir / "expected.json"

    cmd = [
      opa_path,
      "eval",
      "--v0-compatible",
      "--format",
      "json",
      "--fail-defined",
      "--data",
      str(rule_dir / "raw.rego"),
      "--input",
      str(input_path),
      "data.armo_builtins.deny",
    ]
    if data_path.exists():
      cmd.extend(["--data", str(data_path)])

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in {0, 1}:
      raise RuntimeError(f"{case_dir}: opa eval failed\n{result.stderr}")

    payload = json.loads(result.stdout)
    value = payload["result"][0]["expressions"][0]["value"] if payload.get("result") else []
    expected = json.loads(expected_path.read_text())

    alerts = sorted(item["alertMessage"] for item in value)
    if len(value) != expected["count"] or alerts != sorted(expected["alerts"]):
      raise AssertionError(
        f"{case_dir}: expected count={expected['count']} alerts={expected['alerts']} got count={len(value)} alerts={alerts}"
      )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opa", default="opa")
    args = parser.parse_args()

    failures = []
    for rule_dir in sorted(RULES_DIR.iterdir()):
      test_dir = rule_dir / "test"
      if not test_dir.is_dir():
        continue
      for case_dir in sorted(test_dir.iterdir()):
        try:
          run_case(args.opa, rule_dir, case_dir)
          print(f"PASS {case_dir.relative_to(ROOT)}")
        except Exception as exc:
          failures.append(str(exc))
          print(f"FAIL {case_dir.relative_to(ROOT)}", file=sys.stderr)

    if failures:
      print("\n".join(failures), file=sys.stderr)
      return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
