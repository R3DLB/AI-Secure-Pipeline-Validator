# Gate 02 — SAST (Semgrep)

## Goal
Detect common security issues and unsafe code patterns early in the pipeline.

This gate analyzes source code to identify:
- injection risks (SQL, command, template)
- hardcoded credentials or weak crypto usage
- insecure deserialization
- SSRF / path traversal patterns
- generic OWASP Top 10 patterns

If a high-confidence issue is detected, the pipeline must fail **before** the change is merged.

---

## Why it matters (Threat model)
Static analysis catches classes of bugs that often become:
- remote code execution
- data exfiltration
- privilege escalation

This gate enforces a baseline:
✅ “No known high-risk patterns in code.”

---

## What it checks
The gate runs Semgrep with the `p/ci` ruleset against the repository content, and only evaluates findings with `ERROR` severity.

By default:
- it runs on `push` and `pull_request`
- it scans the code currently in the repo
- it outputs JSON findings for evidence
- on pull requests, it uses a baseline to report only new findings vs the base commit

---

## PASS / FAIL logic
- ✅ **PASS** if no findings are detected
- ✅ **PASS** on pull requests when findings exist only in the baseline
- ❌ **FAIL** if at least one new `ERROR` finding is detected

Semgrep exits non-zero when findings are present, which fails the job.

---

## Evidence output
This gate generates:

- `evidence/semgrep.json`

The evidence is uploaded as a GitHub Actions artifact:
- `evidence-semgrep`

Example JSON fields:
- `check_id`: rule identifier
- `path`, `start`, `end`: where the issue was found
- `extra.message`: human-readable description

---

## Baseline behavior (PRs only)
When the workflow runs on a pull request, it compares results to the base commit and reports only new findings. This keeps legacy findings from blocking the pipeline while still preventing regressions. Only `ERROR` findings are considered for pass/fail.

Note: on `push` events (including `main`), the scan is full and all findings will fail the job.

---

## Example output
```json
{
  "results": [
    {
      "check_id": "python.lang.security.injection.os-system.os-system",
      "path": "app/main.py",
      "start": { "line": 12 },
      "end": { "line": 12 },
      "extra": {
        "message": "Use of os.system can lead to command injection."
      }
    }
  ]
}
```
