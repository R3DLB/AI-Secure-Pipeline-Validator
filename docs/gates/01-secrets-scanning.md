# Gate 01 — Secrets Scanning (Gitleaks)

## Goal
Prevent accidental leakage of secrets in source code repositories.

This gate detects credentials such as:
- API keys
- tokens (GitHub, GitLab, Slack, etc.)
- private keys
- cloud secrets (AWS/GCP/Azure patterns)
- generic high-entropy secrets

If a secret is committed, the pipeline must fail **before** the change is merged.

---

## Why it matters (Threat model)
Accidental secret commits are one of the most common root causes of:
- account takeover
- unauthorized API usage
- cloud cost abuse
- data breach / lateral movement

This gate reduces risk by enforcing a strict baseline:
✅ “No secrets in code.”

---

## What it checks
The gate scans the repository content (working tree) and searches for secrets using Gitleaks rules.

By default:
- it runs on `push` and `pull_request`
- it scans the code currently in the repo
- it redacts secrets in logs

---

## PASS / FAIL logic
- ✅ **PASS** if no secrets are detected
- ❌ **FAIL** if at least one secret is detected

The job fails with non-zero exit code (CI becomes red) to block merges.

---

## Evidence output
This gate generates:

- `evidence/gitleaks.json`

The evidence is uploaded as a GitHub Actions artifact:
- `evidence-gitleaks`

Example JSON fields:
- `RuleID`: which rule triggered
- `File`, `StartLine`, `EndLine`: where the secret was found
- `Match`: redacted match
- `Fingerprint`: stable identifier for tracking

---

## Example output (redacted)
```json
[
  {
    "RuleID": "generic-api-key",
    "File": "/repo/tmp_secret_test.txt",
    "StartLine": 1,
    "Match": "AWS_SECRET_ACCESS_KEY=REDACTED"
  }
]
```
