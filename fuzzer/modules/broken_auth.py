"""
modules/broken_auth.py

Tests for Broken Authentication (OWASP API2:2023). Checks whether
endpoints that are DECLARED as requiring authentication in the spec
actually enforce it at runtime. Two checks per endpoint:

  1. No-token test: call the endpoint with zero Authorization header.
     A correctly-secured endpoint should return 401 (or 403).
  2. Malformed-token test: call it with an obviously invalid/garbage
     bearer token. Should also return 401.

If either test gets a 2xx back with a real body, the endpoint is
accessible without valid authentication despite being marked as
protected in its own spec - a direct contradiction that's very hard
to argue away in a demo.
"""

from fuzzer.scoring import Finding, REMEDIATION_TEXT

GARBAGE_TOKEN = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJoYWNrZXIifQ."  # malformed/unsigned-looking JWT


def _looks_authenticated_bypass(resp) -> bool:
    if resp.status_code < 200 or resp.status_code >= 300:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    return bool(body)


def run(endpoints, client, sample_id_value="1"):
    """
    endpoints: list[Endpoint]
    client: ApiClient
    sample_id_value: fallback value used to fill any {id}-style path
        params so we can actually hit the endpoint (we don't need a
        REAL id here - we're testing whether auth is checked at all,
        which should happen before the app even looks up the resource).
    """
    findings = []
    candidates = [ep for ep in endpoints if ep.requires_auth]

    for ep in candidates:
        path_values = {p.name: sample_id_value for p in ep.parameters if p.location == "path"}

        # Test 1: no Authorization header at all
        no_auth_resp = client.call(
            ep.method, ep.path, path_values=path_values, override_headers={}
        )

        if _looks_authenticated_bypass(no_auth_resp):
            findings.append(Finding(
                vuln_type="BROKEN_AUTH",
                severity="critical",
                endpoint=f"{ep.method.upper()} {ep.path}",
                description=(
                    "Endpoint is documented as requiring authentication but "
                    "returned a successful response with no Authorization "
                    "header present at all."
                ),
                evidence={
                    "test": "no_token",
                    "response_status": no_auth_resp.status_code,
                    "response_snippet": str(getattr(no_auth_resp, "text", ""))[:300],
                },
                remediation=REMEDIATION_TEXT["BROKEN_AUTH"],
            ))
            continue  # no need to also test malformed token, already broken

        # Test 2: malformed / garbage bearer token
        bad_token_resp = client.call(
            ep.method, ep.path, path_values=path_values,
            override_headers={"Authorization": f"Bearer {GARBAGE_TOKEN}"},
        )

        if _looks_authenticated_bypass(bad_token_resp):
            findings.append(Finding(
                vuln_type="BROKEN_AUTH",
                severity="high",
                endpoint=f"{ep.method.upper()} {ep.path}",
                description=(
                    "Endpoint accepted a malformed/garbage bearer token as "
                    "if it were valid, returning a successful response."
                ),
                evidence={
                    "test": "malformed_token",
                    "token_used": GARBAGE_TOKEN,
                    "response_status": bad_token_resp.status_code,
                },
                remediation=REMEDIATION_TEXT["BROKEN_AUTH"],
            ))

    return findings
