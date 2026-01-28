#!/usr/bin/env python3
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


def _write_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")


def _normalize_semgrep(data):
    results = data.get("results", []) or []
    out = []
    for r in results:
        extra = r.get("extra", {}) or {}
        severity = (extra.get("severity") or "UNKNOWN").upper()
        start = r.get("start", {}) or {}
        out.append(
            {
                "gate": "sast",
                "tool": "semgrep",
                "severity": severity,
                "rule_id": r.get("check_id") or "unknown",
                "path": r.get("path") or "unknown",
                "line": start.get("line") or 0,
                "message": extra.get("message") or "",
            }
        )
    return out


def _normalize_gitleaks(data):
    results = data if isinstance(data, list) else data.get("findings", []) or data.get("results", []) or []
    out = []
    for r in results:
        out.append(
            {
                "gate": "secrets",
                "tool": "gitleaks",
                "severity": "HIGH",
                "rule_id": r.get("RuleID") or r.get("Rule") or "unknown",
                "path": r.get("File") or r.get("file") or "unknown",
                "line": r.get("StartLine") or r.get("line") or 0,
                "message": r.get("Description") or r.get("Message") or "",
            }
        )
    return out


def main(argv):
    if len(argv) != 4:
        _die("usage: normalize_evidence.py <tool> <input_json> <output_json>")
    tool, input_path, output_path = argv[1], argv[2], argv[3]
    data = _load_json(input_path)
    if tool == "semgrep":
        normalized = _normalize_semgrep(data)
    elif tool == "gitleaks":
        normalized = _normalize_gitleaks(data)
    else:
        _die(f"unsupported tool: {tool}")
    _write_json(output_path, normalized)


if __name__ == "__main__":
    main(sys.argv)
