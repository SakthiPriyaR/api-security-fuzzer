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

The bundled mock API is useful for a fast, repeatable integration test, but
it is not independent evidence: this project controls both the scanner and
the mock vulnerabilities. A separate validation against
[OWASP crAPI](https://github.com/OWASP/crAPI) is planned and has **not yet
been run**. crAPI is an independently maintained, intentionally vulnerable
API learning project; its documented challenges provide a reference for
checking scanner results. Do not present the mock-server results as proof
that the scanner detects vulnerabilities in an independent target.

Budget a focused evening for this validation. Keep the target local, use
throwaway accounts and data, and record the crAPI release or Git commit used.
The upstream deployment instructions and OpenAPI document can change, so
follow the current [crAPI Docker setup](https://github.com/OWASP/crAPI) and
use the [OpenAPI spec published by crAPI](https://github.com/OWASP/crAPI/blob/develop/openapi-spec/crapi-openapi-spec.json)
rather than assuming the mock spec or endpoint IDs will transfer directly.

On Windows, the upstream repository currently documents this Docker Compose
flow (check the linked instructions for any updates before running it):

```powershell
curl.exe -L -o crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
tar -xf .\crapi.zip
Set-Location .\crAPI-main\deploy\docker
docker compose pull
docker compose -f docker-compose.yml --compatibility up -d
```

Before scanning, confirm the containers are healthy, inspect the OpenAPI
spec, and create two separate low-privilege test accounts using crAPI's
normal signup/login flow. Adapt the scanner inputs to the actual crAPI
authentication and resource-ID model; the current BOLA module assumes the
provided account user ID is also a valid resource ID, which may not hold.
Only run checks against this local instance and avoid destructive requests
or real personal data.

This repository includes a conservative Windows runner. It downloads
crAPI's published spec for the selected ref and only probes read-only
operations; request-body mutation and the mock-only prompt-injection
simulation are disabled. Supply short-lived tokens and resource IDs for
two throwaway accounts (the IDs must correspond to resources that each
account can legitimately read):

```powershell
.\scripts\run_crapi_validation.ps1 `
  -TokenA $env:CRAPI_TOKEN_A -ResourceIdA "<account-a-resource-id>" `
  -TokenB $env:CRAPI_TOKEN_B -ResourceIdB "<account-b-resource-id>" `
  -CrApiRef "<reviewed-crAPI-commit-or-branch>"
```

The default ref is `develop`; for repeatability, use a reviewed commit SHA
and record it. The runner does not create accounts or infer resource IDs:
complete those steps manually using crAPI's normal workflow first. It
produces scanner reports, not an automatic proof of detection. Review each
result against crAPI's published challenge documentation and record
confirmed matches, false positives, misses, and unsupported cases.

For a credible evaluation, save the exact scanner command, crAPI version or
commit, sanitized JSON/HTML reports, and a results table that maps each
finding to an independently documented crAPI challenge. Manually verify
each match, and record false positives, documented vulnerabilities missed,
and checks that could not be exercised. A finding is not confirmed merely
because its category exists in crAPI. Until this run is completed, describe
crAPI validation as **planned**, not as a completed result.

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
