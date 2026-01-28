#!/usr/bin/env python3
import json
import sys


def _short(text, limit):
    s = str(text)
    if len(s) <= limit:
        return s
    return s[: max(0, limit - 1)] + "…"


def _rel_path(path: str):
    if path.startswith("/repo/"):
        return path[len("/repo/") :]
    return path


def _table(title, headers, rows, max_widths=None):
    print(f"{title}")
    widths = [len(h) for h in headers]
    if max_widths is None:
        max_widths = [60] * len(headers)
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    widths = [min(widths[i], max_widths[i]) for i in range(len(headers))]
    line = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    print(line)
    print("| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)) + " |")
    print(line)
    for row in rows:
        print(
            "| "
            + " | ".join(
                _short(str(row[i]), widths[i]).ljust(widths[i]) for i in range(len(headers))
            )
            + " |"
        )
    print(line)


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
        _table("Gitleaks", ["Status"], [["no report found"]])
        return
    findings = data if isinstance(data, list) else data.get("results", []) or data.get("findings", []) or []
    print(f"Gitleaks summary: {len(findings)} findings")
    rows = []
    for f in findings[:10]:
        rule_id = f.get("RuleID") or f.get("Rule") or "unknown"
        file_path = _rel_path(f.get("File") or f.get("file") or "unknown")
        line = f.get("StartLine") or f.get("line") or 0
        desc = f.get("Description") or f.get("Message") or ""
        match = f.get("Match") or f.get("Secret") or f.get("secret") or ""
        rows.append([rule_id, f"{file_path}:{line}", match, desc])
    if not rows:
        rows = [["-", "-", "-", "no findings"]]
    _table(
        "Gitleaks",
        ["Rule", "Location", "Match", "Message"],
        rows,
        max_widths=[22, 28, 24, 60],
    )
    if len(findings) > 10:
        print(f"... {len(findings) - 10} more\n")


def _print_semgrep(path: str):
    data = _load_json(path)
    if data is None:
        _table("Semgrep", ["Status"], [["no report found"]])
        return
    results = data.get("results", []) or []
    print(f"Semgrep summary: {len(results)} findings")
    rows = []
    for r in results[:10]:
        extra = r.get("extra", {}) or {}
        sev = (extra.get("severity") or "UNKNOWN").upper()
        rule_id = r.get("check_id") or "unknown"
        file_path = _rel_path(r.get("path") or "unknown")
        start = r.get("start", {}) or {}
        line = start.get("line") or 0
        msg = extra.get("message") or ""
        meta = extra.get("metadata", {}) or {}
        vuln_class = (
            (meta.get("vulnerability_class") or [""])[0]
            or meta.get("category")
            or (meta.get("owasp") or [""])[0]
            or (meta.get("cwe") or [""])[0]
            or "n/a"
        )
        rows.append([sev, vuln_class, rule_id, f"{file_path}:{line}", msg])
    if not rows:
        rows = [["-", "-", "-", "-", "no findings"]]
    _table(
        "Semgrep",
        ["Severity", "Class", "Rule", "Location", "Message"],
        rows,
        max_widths=[8, 18, 36, 28, 60],
    )
    if len(results) > 10:
        print(f"... {len(results) - 10} more\n")


def main():
    print("Quality gate (manual review)\n")
    _print_gitleaks("evidence/gitleaks/gitleaks.json")
    _print_semgrep("evidence/semgrep/semgrep.json")
    print("Result: MANUAL REVIEW REQUIRED")


if __name__ == "__main__":
    main()
