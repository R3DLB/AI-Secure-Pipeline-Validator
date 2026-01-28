#!/usr/bin/env python3
import glob
import json
import os
import sys


def _die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def _load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        _die(f"file not found: {path}")
    except json.JSONDecodeError as e:
        _die(f"invalid json in {path}: {e}")


def _load_policy(path: str):
    policy = _load_json(path)
    max_findings = policy.get("max_findings", {})
    allowlist = policy.get("allowlist", {}).get("rule_ids", [])
    fail_on_unknown = policy.get("fail_on_unknown_severity", True)
    return max_findings, set(allowlist), fail_on_unknown


def _collect_findings(paths):
    findings = []
    for path in paths:
        data = _load_json(path)
        if isinstance(data, list):
            findings.extend(data)
        else:
            _die(f"expected list in {path}")
    return findings


def main(argv):
    policy_path = argv[1] if len(argv) > 1 else ".security/policy.json"
    max_findings, allowlist, fail_on_unknown = _load_policy(policy_path)

    evidence_paths = glob.glob("evidence/**/normalized/*.json", recursive=True)
    if not evidence_paths:
        _die("no normalized evidence found under evidence/**/normalized/*.json")

    findings = _collect_findings(evidence_paths)

    counts = {}
    unknown = 0
    filtered = 0
    for f in findings:
        rule_id = f.get("rule_id") or "unknown"
        if rule_id in allowlist:
            filtered += 1
            continue
        sev = (f.get("severity") or "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1
        if sev not in max_findings:
            unknown += 1

    failed = False
    for sev, max_allowed in max_findings.items():
        if max_allowed is None:
            continue
        if isinstance(max_allowed, int) and max_allowed >= 0:
            if counts.get(sev, 0) > max_allowed:
                failed = True

    if fail_on_unknown and unknown > 0:
        failed = True

    print("Policy evaluation")
    print(f"  Evidence files: {len(evidence_paths)}")
    print(f"  Findings total: {len(findings)}")
    print(f"  Findings filtered (allowlist): {filtered}")
    for sev in sorted(counts.keys()):
        print(f"  {sev}: {counts[sev]}")
    if fail_on_unknown:
        print(f"  Unknown severity count: {unknown}")

    if failed:
        print("Result: FAIL")
        sys.exit(1)
    print("Result: PASS")
    return 0


if __name__ == "__main__":
    main(sys.argv)
