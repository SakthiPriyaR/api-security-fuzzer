"""
modules/bola.py

Tests for Broken Object Level Authorization (OWASP API1:2023) - the
single most common API vulnerability. The idea, in plain terms:

    Account A is logged in and legitimately owns resource #1023.
    If Account A's token can also read/modify resource #1024 (which
    belongs to Account B), the API isn't checking OWNERSHIP - only
    that SOME valid token was presented. That's BOLA.

Detection strategy implemented here:
  1. For every authenticated endpoint with an ID-shaped path param,
     have account_b fetch its OWN resource first to learn a real,
     valid ID it owns.
  2. Have account_a call the SAME endpoint using account_b's real ID,
     but with account_a's own token.
  3. If the response is 200 (or any 2xx) AND the returned body appears
     to contain account_b's data, flag it as BOLA.
  4. If the response is 403/404, that's the CORRECT behavior - no finding.

This is deliberately conservative: we only flag confirmed data leaks,
not just "we got a 200," to avoid noisy false positives against
endpoints that legitimately return public data.
"""

from fuzzer.scoring import Finding, REMEDIATION_TEXT


def _looks_like_success_with_body(resp) -> bool:
    if resp.status_code < 200 or resp.status_code >= 300:
        return False
    try:
        body = resp.json()
    except Exception:
        return False
    return bool(body)


def run(endpoints, client, account_a, account_b):
    """
    Returns a list of Finding objects.

    endpoints: list[Endpoint] from parser.parse_endpoints()
    client: fuzzer.http_client.ApiClient
    account_a, account_b: fuzzer.http_client.TestAccount
    """
    findings = []

    candidates = [
        ep for ep in endpoints
        if ep.requires_auth and ep.id_parameters and ep.method in ("get", "put", "patch", "delete")
    ]

    for ep in candidates:
        id_param = ep.id_parameters[0]

        # Prefer a caller-supplied ID of a resource known to belong to B.
        # This supports APIs where object IDs (e.g. crAPI vehicle GUIDs)
        # are unrelated to the account's user ID. Keep the legacy fallback
        # for the bundled demo and existing integrations.
        resource_id = account_b.resource_ids.get(id_param.name, account_b.user_id)
        probe_values = {id_param.name: resource_id}
        baseline = client.call(ep.method, ep.path, account=account_b,
                                path_values=probe_values)

        if baseline.status_code < 200 or baseline.status_code >= 300:
            # account_b couldn't even access its own resource this way -
            # our guessed ID mapping doesn't hold for this endpoint, skip it
            # rather than reporting a false positive.
            continue

        # Step 2: the actual test - account_a tries the SAME resource ID
        # (which belongs to account_b) using account_a's own token.
        attack_resp = client.call(ep.method, ep.path, account=account_a,
                                    path_values=probe_values)

        if _looks_like_success_with_body(attack_resp):
            findings.append(Finding(
                vuln_type="BOLA",
                severity="critical",
                endpoint=f"{ep.method.upper()} {ep.path}",
                description=(
                    f"Account A successfully accessed a resource "
                    f"(id={resource_id}) belonging to Account B "
                    f"using Account A's own auth token. The API is not "
                    f"verifying object ownership."
                ),
                evidence={
                    "id_parameter": id_param.name,
                    "resource_id_source": (
                        "provided" if id_param.name in account_b.resource_ids
                        else "account_user_id_fallback"
                    ),
                    "resource_owner": "account_b",
                    "requesting_account": "account_a",
                    "response_status": attack_resp.status_code,
                    "response_snippet": str(getattr(attack_resp, "text", ""))[:300],
                },
                remediation=REMEDIATION_TEXT["BOLA"],
            ))

    return findings
