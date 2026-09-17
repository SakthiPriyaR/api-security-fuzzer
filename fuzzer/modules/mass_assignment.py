"""
modules/mass_assignment.py

Tests for Mass Assignment / Broken Object Property Level Authorization
(OWASP API3:2023). The idea: many APIs bind incoming JSON directly onto
an internal model, so if the model has a field like `isAdmin` or `role`,
and the API doesn't explicitly block clients from setting it, an
attacker can just add that field to their request body - fields the UI
never exposes but the backend still accepts.

Detection strategy:
  1. For POST/PUT/PATCH endpoints, build a request body from the spec's
     declared schema (using safe placeholder values for declared fields).
  2. Inject a set of known "privileged" field names that are NOT part
     of the declared schema.
  3. Send the request, then read the response body (many APIs echo the
     created/updated object back). If any injected field is reflected
     back with the value we sent, the field was accepted server-side.
  4. Flag as a finding - the API accepted a client-supplied field that
     was not part of its own declared, documented schema.
"""

from fuzzer.scoring import Finding, REMEDIATION_TEXT


# Fields that should almost never be settable directly by an API client.
SUSPICIOUS_FIELDS = {
    "isAdmin": True,
    "is_admin": True,
    "role": "admin",
    "admin": True,
    "verified": True,
    "is_verified": True,
    "balance": 999999,
    "credit": 999999,
    "permissions": ["admin"],
}


def _placeholder_for_type(schema_type: str):
    return {
        "string": "test",
        "integer": 1,
        "number": 1.0,
        "boolean": True,
        "array": [],
        "object": {},
    }.get(schema_type, "test")


def _build_base_body(schema: dict) -> dict:
    """Build a minimal valid-looking body from a declared JSON schema
    so the request has a reasonable chance of being processed rather
    than rejected outright for missing required fields."""
    if not schema:
        return {}
    props = schema.get("properties", {})
    body = {}
    for name, prop_schema in props.items():
        body[name] = _placeholder_for_type(prop_schema.get("type"))
    return body


def run(endpoints, client, account):
    """
    endpoints: list[Endpoint]
    client: ApiClient
    account: TestAccount - a single legitimate low-privilege account
    """
    findings = []

    candidates = [ep for ep in endpoints if ep.requires_auth and ep.has_body]

    for ep in candidates:
        base_body = _build_base_body(ep.request_body_schema)
        declared_fields = set(base_body.keys())

        injected = {
            k: v for k, v in SUSPICIOUS_FIELDS.items() if k not in declared_fields
        }
        if not injected:
            continue

        body = {**base_body, **injected}
        path_values = {p.name: account.user_id for p in ep.id_parameters}

        resp = client.call(ep.method, ep.path, account=account,
                            path_values=path_values, json_body=body)

        if resp.status_code < 200 or resp.status_code >= 300:
            continue  # rejected outright - not vulnerable via this path

        try:
            resp_body = resp.json()
        except Exception:
            resp_body = {}

        reflected = {
            k: v for k, v in injected.items()
            if isinstance(resp_body, dict) and resp_body.get(k) == v
        }

        if reflected:
            findings.append(Finding(
                vuln_type="MASS_ASSIGNMENT",
                severity="high",
                endpoint=f"{ep.method.upper()} {ep.path}",
                description=(
                    f"Endpoint accepted and reflected back client-supplied "
                    f"field(s) not part of its declared schema: "
                    f"{list(reflected.keys())}. This suggests the request "
                    f"body is bound directly to an internal model without "
                    f"an allow-list."
                ),
                evidence={
                    "injected_fields": injected,
                    "reflected_fields": reflected,
                    "response_status": resp.status_code,
                },
                remediation=REMEDIATION_TEXT["MASS_ASSIGNMENT"],
            ))

    return findings
