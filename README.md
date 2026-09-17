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

## Validating against a real vulnerable API (recommended for your writeup)

The mock server above is a fast offline sanity check. For your actual
capstone validation and evidence, run this against **OWASP crAPI**
(a full intentionally-vulnerable API built specifically to teach these
exact vulnerability classes):

```bash
git clone https://github.com/OWASP/crAPI.git
cd crAPI
docker-compose up -d
```

crAPI exposes its own OpenAPI spec and has documented, known BOLA and mass
assignment issues — running the scanner against it and cross-checking your
findings against crAPI's own vulnerability documentation is exactly the
kind of "does automated detection match known-ground-truth" evaluation a
capstone panel wants to see, and is much stronger evidence than the mock
server alone.

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

## Limitations (be upfront about these in your report/viva)

- **Coverage is 3 of the 10 OWASP API categories**, not all ten. Injection,
  excessive data exposure, rate-limiting/resource consumption, SSRF, and
  the remaining categories are explicitly out of scope for this build —
  documented here as future work rather than silently omitted.
- **BOLA detection relies on a heuristic**: it assumes a test account's
  `user_id` doubles as a valid resource ID for that account's own data.
  This holds for many REST APIs (crAPI included) but not all — a more
  general version would need an account to first *create* a resource and
  use the ID it gets back, rather than guessing.
- **Mass assignment detection is reflection-based**: it only flags a field
  as accepted if the API echoes it back in the response body. An API that
  silently accepts a privileged field without reflecting it (e.g. an
  async worker that applies it later) would be missed by this version.
- **No fuzzing of query/header-based auth schemes** — the tool assumes
  bearer-token auth, since that's the dominant pattern for modern REST
  APIs, but doesn't yet handle API-key-in-header or OAuth flows generically.
- This tool is intended for testing APIs **you own or have explicit
  permission to test**. Running it against third-party production systems
  without authorization would be unauthorized access testing, not a QA
  exercise.
