# API Security Testing & Fuzzing Framework

An automated scanner that discovers REST API endpoints from an OpenAPI/Swagger
spec and tests them against three of the most common and highest-impact
vulnerability classes in the **OWASP API Security Top 10 (2023)**.

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
| `injection.py` | Heuristic input-safety probe | Does a harmless marker sent in a declared query parameter get reflected in a successful response? Reflection is a low-severity review signal, not proof of SQL injection or XSS. |

These three were chosen deliberately over attempting full Top-10 coverage:
they are the most-documented, most demoable, and have mature intentionally-
vulnerable reference APIs to validate against. Broader coverage (injection,
rate-limiting, SSRF, etc.) is noted as future work — see **Limitations** below.

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
  --out reports/scan

# 3. Open the report
open reports/scan.html   # or just open the file in a browser
```

Expected output against the included mock server: **8 findings** — BOLA
on two endpoints, broken auth on one, mass assignment on one, and four
prompt-injection cases. The injection probe reports no finding on this mock
API. Run `python -m pytest -q` for the automated unit and end-to-end checks.
Reports escape untrusted finding content before rendering it as HTML.

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
    broken_auth.py
    mass_assignment.py
    injection.py          harmless reflected-input heuristic
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
