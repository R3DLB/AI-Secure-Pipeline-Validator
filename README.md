# AI Secure Pipeline Validator
A reusable **security CI pipeline** for AI/ML/LLM projects (and general software repos), designed for:
- **shift-left security**
- **evidence-based validation**
- easy integration via **GitHub Actions reusable workflows**

---

## What this project is
This repository provides a **reusable GitHub Actions workflow** that teams can import into their own projects to automatically run security gates on every `push` and `pull_request`.

It runs a sequence of **Security Gates** that decide if a project is:
- ✅ **PASS** (promotable)
- ❌ **FAIL** (blocked)

---

## What is a GATE?
A **Gate** is:
1. A security control  
2. An automated tool execution  
3. A pass/fail rule  
4. Evidence output  

**Tools are replaceable. Gates are the product.**

---

## Gates documentation
- [Gate 01 — Secrets Scanning (Gitleaks)](docs/gates/01-secrets-scanning.md)

---

## Current Status
| Version | Gate | Why it matters | Tool | Output |
| --- | --- | --- | --- | --- |
| v0.1 | Secrets Scanning | Prevents accidental credential leakage | Gitleaks | `evidence/gitleaks.json` |

---

## Roadmap
AI/ML/LLM projects have additional artifacts beyond code:
- **DATA** (datasets / RAG documents)
- **MODELS** (weights, configs…)
- **EVAL** (LLM behavior, jailbreak resilience, prompt injection)

Planned Gates:
- SAST Gate
- Dependency Gate
- Data Gate
- Model Gate
- Eval Gate
- SBOM Gate + CVE artifact scan
- Provenance / Signing

---

## Quickstart (Add to your repo)
1. Create this file: `.github/workflows/security.yml`
2. Add this snippet:

```yaml
name: Security Pipeline

on: [push, pull_request]

jobs:
  security:
    uses: R3DLB/AI-Secure-Pipeline-Validator/.github/workflows/security.yml@v0.1.1
```
3. ✅ Done.
