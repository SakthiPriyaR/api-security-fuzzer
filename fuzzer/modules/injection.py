"""Low-impact reflected-input probes for common API injection indicators.

Only probes query parameters declared in the OpenAPI document. The scanner
does not send shell commands or destructive payloads; it checks whether a
unique harmless marker is returned verbatim in a successful response.
This is a heuristic signal for manual review, not proof of exploitable SQLi
or XSS.
"""

from fuzzer.scoring import Finding, REMEDIATION_TEXT


PROBE = "codex_probe_7f3a9c"


def run(endpoints, client, account):
    findings = []
    for endpoint in endpoints:
        query_parameters = [p for p in endpoint.parameters if p.location == "query"]
        if not query_parameters:
            continue

        query = {p.name: "probe" for p in query_parameters}
        query[query_parameters[0].name] = PROBE
        path_values = {
            p.name: account.user_id
            for p in endpoint.parameters
            if p.location == "path"
        }
        response = client.call(
            endpoint.method,
            endpoint.path,
            account=account if endpoint.requires_auth else None,
            path_values=path_values,
            query_params=query,
        )
        if not 200 <= response.status_code < 300:
            continue
        if PROBE not in str(getattr(response, "text", "")):
            continue

        findings.append(Finding(
            vuln_type="INJECTION",
            severity="low",
            endpoint=f"{endpoint.method.upper()} {endpoint.path}",
            description=(
                "A unique harmless query marker was reflected in the response. "
                "This may indicate unsafe input handling; reflection alone does "
                "not prove an injection vulnerability. Manually verify context "
                "and server-side handling."
            ),
            evidence={
                "parameter": query_parameters[0].name,
                "probe": PROBE,
                "response_status": response.status_code,
            },
            remediation=REMEDIATION_TEXT["INJECTION"],
        ))
    return findings
