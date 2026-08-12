#!/usr/bin/env python3
"""Parse every workflow file. A workflow with broken YAML does not fail loudly -
GitHub lists the run under the file path instead of its name and produces no
jobs at all, which reads like a queue problem rather than a syntax error."""
import glob
import sys

try:
    import yaml
except ImportError:
    sys.exit("pyyaml is not installed; skipping (CI has it)")

failed = False
# *.y*ml: GitHub honours .yaml too, and an unglobbed one would skip every check.
for path in sorted(glob.glob(".github/workflows/*.y*ml")):
    try:
        doc = yaml.safe_load(open(path))
        for job, spec in (doc.get("jobs") or {}).items():
            for step in spec.get("steps", []):
                if "uses" in step and "@" in step["uses"]:
                    ref = step["uses"].split("@")[1]
                    if not (len(ref) == 40 and all(c in "0123456789abcdef" for c in ref)):
                        print(f"{path}: {job}: {step['uses']} is not pinned to a commit SHA")
                        failed = True
        print(f"{path}: ok")
    except Exception as e:
        print(f"{path}: {e}")
        failed = True
sys.exit(1 if failed else 0)
