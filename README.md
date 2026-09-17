# API Security Testing & Fuzzing Framework

An automated scanner that discovers REST API endpoints from an OpenAPI/Swagger
spec and checks selected authorization and input-handling risks from the
**OWASP API Security Top 10 (2023)**, plus isolated demonstrations for selected
OWASP LLM Top 10 risks.

Built as a capstone project sitting at the intersection of **QA automation**
and **application security** — the tool is designed to slot into a CI/CD
pipeline the same way a linter or test suite would, so vulnerable API
behavior can be caught on every pull request rather than in a once-a-year
pentest.

## What it actually tests

| Module | OWASP Category | What it checks |
|---|---|---|
| `bola.py` | API1:2023 — Broken Object Level Authorization | Can Account A read/modify a resource that belongs to Account B, using only Account A's own token? |
| `broken_auth.py` | API2:2023 — Broken Authentication | Do endpoints marked as requiring auth actually reject requests with no token / a malformed token? |
| `mass_assignment.py` | API3:2023 — Broken Object Property Level Authorization | Does the API accept and apply client-supplied fields (`isAdmin`, `role`, etc.) that aren't part of its own declared schema? |
| `function_auth.py` | API5:2023 — Broken Function Level Authorization | Can an authenticated low-privilege account call an OpenAPI operation marked with `x-required-role`? |
| `excessive_agency.py` | LLM06:2025 — Excessive Agency | Can an indirect prompt make the local demo agent use a destructive tool it does not need? This probe deletes demo order 2 and is skipped in read-only mode. |
| `injection.py` | Heuristic input-safety probe | Does a harmless marker sent in a declared query parameter get reflected in a successful response? Reflection is a low-severity review signal, not proof of SQL injection or XSS. |
| `system_prompt_leakage.py` | LLM07:2025 — System Prompt Leakage | Does the local rule-based demo agent reveal its internal system scope when asked? |
| `security_misconfiguration.py` | API8:2023 — Security Misconfiguration | Checks sampled GET responses for missing `X-Content-Type-Options`, wildcard CORS, versioned `Server` headers, and obvious stack traces. |
| `resource_consumption.py` | API4:2023 — Unrestricted Resource Consumption | Optional 3–10 request sample on one GET route; success is only an inconclusive signal. Enable with `--check-rate-limits`. |

Coverage is intentionally partial. The API checks currently include API1,
API2, API3, API4 (opt-in), API5, and selected API8 response checks; the LLM checks are demonstrations against the bundled
rule-based mock agent, not tests of a production generative model. See
**Limitations** for checks that remain out of scope.

## How it works

1. **`parser.py`** reads the OpenAPI spec and flattens it into a list of
   `Endpoint` objects: path, method, parameters, whether auth is required,
   and the declared request/response schema.
2. **`http_client.py`** provides a thin wrapper for firing requests as one
   of two test accounts, or with no/garbage auth, without raising on
   non-2xx responses (the interesting responses ARE the 401s and 403s).
3. Each **attack module** (`fuzzer/modules/`) takes the endpoint list and
   the HTTP client, runs its specific test strategy, and returns a list of
   `Finding` objects.
4. **`scoring.py`** maps each finding to an OWASP category and severity.
5. **`report.py`** renders findings as both a JSON report (for CI/CD
   tooling to parse) and a styled HTML report (for a human-readable
   deliverable).
6. **`cli.py`** orchestrates all of the above and exits non-zero when a
   finding at/above a configurable severity is detected — this is the hook
   a CI pipeline uses to fail a build.

## Quick start

```bash
pip install -r requirements.txt

# 1. Start a target to scan. For a fast local sanity check, this repo
#    ships a tiny deliberately-vulnerable mock server:
python3 sample_apis/mock_vulnerable_server.py &

# 2. Run the scanner against it
python3 -m fuzzer.cli \
  --spec sample_apis/demo_openapi.json \
  --base-url http://localhost:8123 \
  --token-a token-a --user-id-a 1 \
  --token-b token-b --user-id-b 2 \
  --local-llm-demos \
  --out reports/scan

# 3. Open the report
open reports/scan.html   # or just open the file in a browser
```

Expected output against the included mock server: **14 findings** — BOLA
on two endpoints, broken auth on one, broken function authorization on one,
mass assignment on one, four prompt-injection cases, one system-prompt
leakage finding, and one excessive-agency finding. The latter intentionally
deletes demo order 2; restart the mock server to reset its in-memory data.
The LLM demos are disabled by default; use `--local-llm-demos` only against
the bundled mock API.
The input-reflection probe reports no finding on this mock API. Run
`python -m pytest -q` for the automated checks.
Reports escape untrusted finding content before rendering it as HTML.

The optional rate-limit sample is disabled by default. Only enable it on an
authorized target where a small burst is acceptable; it sends at most ten
requests to one GET endpoint. LLM10 is not claimed as implemented: this
rule-based agent has no model inference, token billing, or cost controls to
measure.

## Explicitly out of scope

- **LLM03 (Supply Chain):** this demo does not load third-party models,
  plugins, or fine-tuned weights. Review dependency provenance separately.
- **LLM04 (Data and Model Poisoning) and LLM08 (Vector/Embedding Weaknesses):**
  there is no training pipeline, embedding model, or retrieval database here.
- **LLM09 (Misinformation):** deterministic keyword rules cannot meaningfully
  measure generative-model hallucination or factuality.
- **LLM10 (Unbounded Consumption):** the mock agent has no inference/token
  billing or model service to meter. The bounded API4 check is not an LLM10
  test.
- **API6, API9, and API10:** sensitive business-flow abuse, inventory/resource
  management, and unsafe consumption of downstream APIs need application-
  specific workflows and ground truth beyond this generic scanner.

The reflected-input probe is an unclassified heuristic, not an API8 finding.
API8 findings come from the separate response-configuration checks.

## Independent validation against OWASP crAPI

The scanner was run against a local OWASP crAPI deployment, independent of
this project's mock API. The upstream checkout was pinned to
`b5fc307f3e5f875809b095b771108ef342a33724` (branch `main`), and its official
OpenAPI document was used. Two throwaway accounts used reserved `example.com`
addresses; credentials and bearer tokens are not stored in this repository.

The run used safe read-only mode against 16 GET operations. It did not enable
the local-only LLM demos, request-body mutation, or rate-limit sampling. The
scanner produced **3 findings**: 1 critical `BROKEN_AUTH` and 2 medium
`SECURITY_MISCONFIGURATION` signals.

| Scanner result | crAPI reference review | Outcome |
| --- | --- | --- |
| `GET /workshop/api/shop/orders/{order_id}` returned HTTP 200 without an Authorization header and exposed an order response | crAPI documents Challenge 14, “Unauthenticated Access” | Direct match to the documented issue class; endpoint behavior was observed in this run |
| Missing `X-Content-Type-Options` and wildcard CORS on two community GET responses | No one-to-one documented challenge was identified; these are scanner configuration heuristics | Signals reported, not counted as confirmed challenge matches |
| BOLA module: 0 findings | crAPI documents vehicle and mechanic-report BOLA challenges | Not validated: the scanner needs real foreign vehicle/report IDs (GUIDs or report IDs), but this run supplied account subjects, not owned resource IDs. A zero result is not evidence those challenges are absent. |

This is a bounded validation, not a claim that the scanner detects all crAPI
vulnerabilities. The challenge guide also covers state-changing workflows,
rate limiting, injection, JWT attacks, and LLM behavior, which this
read-only run did not exercise. Local reports are
`reports/crapi-validation.json` and `reports/crapi-validation.html`; reports
are git-ignored and may contain target response evidence.

### Reproducing the validation

Keep crAPI local, use throwaway accounts and data, and record the exact
upstream commit. Consult the current [crAPI Docker setup](https://github.com/OWASP/crAPI)
and [challenge guide](https://github.com/OWASP/crAPI/blob/main/docs/challenges.md).
This repository includes a conservative Windows runner that uses read-only
operations; supply short-lived tokens and actual resource IDs for two test
accounts:

```powershell
.\scripts\run_crapi_validation.ps1 `
  -TokenA $env:CRAPI_TOKEN_A -ResourceIdA "<account-a-resource-id>" `
  -TokenB $env:CRAPI_TOKEN_B -ResourceIdB "<account-b-resource-id>" `
  -CrApiRef "<reviewed-crAPI-commit>"
```

The runner does not create accounts or infer resource IDs. Manually review
findings against crAPI's challenge guide and record confirmed matches, false
positives, misses, and unsupported cases. A finding is not confirmed merely
because its category exists in crAPI.

## CI/CD integration

`.github/workflows/api-security-scan.yml` shows the scanner wired into a
GitHub Actions pipeline: it runs the automated test suite and scans the
included local demo API on every pull request. The demo deliberately has
critical findings, so the workflow uses `--fail-on never`; change the
target and threshold when integrating a real authorized staging API. This is the piece that makes
the project a **QA automation** tool rather than just a security script —
point this at your target's staging environment and it becomes a
merge-blocking security gate.

## Project structure

```
fuzzer/
  parser.py              OpenAPI spec -> Endpoint objects
  http_client.py          HTTP wrapper + test account abstraction
  scoring.py               Finding structure, OWASP mapping, severity
  report.py                 JSON + HTML report generation
  cli.py                    orchestration + CI/CD exit-code gating
  modules/
    bola.py
    function_auth.py       API5 check for routes marked x-required-role
    excessive_agency.py    local-only LLM06 destructive-action demonstration
    broken_auth.py
    mass_assignment.py
    injection.py          harmless reflected-input heuristic
    system_prompt_leakage.py local mock-agent disclosure check
    resource_consumption.py bounded API4 sample
    security_misconfiguration.py API8 response checks
tests/
  test_scanner.py          parser, report-safety, and offline end-to-end tests
sample_apis/
  demo_openapi.json         spec used by the mock server
  mock_vulnerable_server.py  offline test target (for quick validation)
.github/workflows/
  api-security-scan.yml     CI/CD gating example
```


- This tool is intended for testing APIs **you own or have explicit
  permission to test**. Running it against third-party production systems
  without authorization would be unauthorized access testing, not a QA
  exercise.
