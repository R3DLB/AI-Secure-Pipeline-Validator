#!/usr/bin/env python3
import json
import sys


def _load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        print(f"error: invalid json in {path}: {e}", file=sys.stderr)
        return None


def _print_gitleaks(path: str):
    data = _load_json(path)
    if data is None:
        print("- Gitleaks: no report found")
        return
    findings = data if isinstance(data, list) else data.get("results", []) or data.get("findings", []) or []
    print(f"- Gitleaks findings: {len(findings)}")
    for f in findings[:10]:
        rule_id = f.get("RuleID") or f.get("Rule") or "unknown"
        file_path = f.get("File") or f.get("file") or "unknown"
        line = f.get("StartLine") or f.get("line") or 0
        desc = f.get("Description") or f.get("Message") or ""
        print(f"  - [{rule_id}] {file_path}:{line} {desc}")
    if len(findings) > 10:
        print(f"  - ... {len(findings) - 10} more")


def _print_semgrep(path: str):
    data = _load_json(path)
    if data is None:
        print("- Semgrep: no report found")
        return
    results = data.get("results", []) or []
    print(f"- Semgrep findings: {len(results)}")
    for r in results[:10]:
        extra = r.get("extra", {}) or {}
        sev = (extra.get("severity") or "UNKNOWN").upper()
        rule_id = r.get("check_id") or "unknown"
        file_path = r.get("path") or "unknown"
        start = r.get("start", {}) or {}
        line = start.get("line") or 0
        msg = extra.get("message") or ""
        print(f"  - [{sev}] {rule_id} {file_path}:{line} {msg}")
    if len(results) > 10:
        print(f"  - ... {len(results) - 10} more")


def main():
    print("Quality gate (manual review)")
    _print_gitleaks("evidence/gitleaks/gitleaks.json")
    _print_semgrep("evidence/semgrep/semgrep.json")
    print("Result: MANUAL REVIEW REQUIRED")


if __name__ == "__main__":
    main()
