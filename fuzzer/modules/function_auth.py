"""Check declared privileged functions using a low-privilege account.

Operations opt in through the OpenAPI vendor extension ``x-required-role``.
This focused check does not guess which routes are administrative.
"""

from fuzzer.scoring import Finding, REMEDIATION_TEXT


def run(endpoints, client, low_privilege_account):
    findings = []
    for endpoint in endpoints:
        if not endpoint.required_role or not endpoint.requires_auth:
            continue
        path_values = {
            parameter.name: low_privilege_account.user_id
            for parameter in endpoint.parameters
            if parameter.location == "path"
        }
        response = client.call(
            endpoint.method,
            endpoint.path,
            account=low_privilege_account,
            path_values=path_values,
        )
        try:
            body = response.json()
        except Exception:
            body = None
        if 200 <= response.status_code < 300 and body:
            findings.append(Finding(
                vuln_type="BROKEN_FUNCTION_AUTH",
                severity="high",
                endpoint=f"{endpoint.method.upper()} {endpoint.path}",
                description=(
                    f"An authenticated low-privilege account successfully called "
                    f"a function documented as requiring role '{endpoint.required_role}'."
                ),
                evidence={
                    "required_role": endpoint.required_role,
                    "requesting_account": low_privilege_account.label,
                    "response_status": response.status_code,
                    "response_snippet": str(getattr(response, "text", ""))[:300],
                },
                remediation=REMEDIATION_TEXT["BROKEN_FUNCTION_AUTH"],
            ))
    return findings
