"""Passive-response checks for common API security misconfiguration signals."""

import re

from fuzzer.scoring import Finding, REMEDIATION_TEXT


STACK_TRACE_MARKERS = re.compile(
    r"Traceback \(most recent call last\)| at [\w.$]+\([^\n]+:\d+\)|"
    r"NullReferenceException|django\.core\.exceptions|/usr/local/lib/python",
    re.IGNORECASE,
)


def run(endpoints, client, account, max_endpoints=25):
    findings = []
    candidates = [ep for ep in endpoints if ep.method == "get"][:max_endpoints]
    for endpoint in candidates:
        path_values = {
            p.name: account.user_id
            for p in endpoint.parameters
            if p.location == "path"
        }
        response = client.call(
            "get", endpoint.path,
            account=account if endpoint.requires_auth else None,
            path_values=path_values,
        )
        if response.status_code < 0:
            continue

        headers = {key.lower(): value for key, value in response.headers.items()}
        issues = []
        if "x-content-type-options" not in headers:
            issues.append("missing X-Content-Type-Options")
        if "access-control-allow-origin" in headers and headers["access-control-allow-origin"] == "*":
            issues.append("wildcard Access-Control-Allow-Origin")
        server_header = headers.get("server", "")
        if re.search(r"\b(?:python|apache|nginx|php|express)/?\d", server_header, re.I):
            issues.append(f"technology/version disclosed by Server header: {server_header[:120]}")
        if response.status_code >= 500 and STACK_TRACE_MARKERS.search(response.text or ""):
            issues.append("server error response appears to contain a stack trace")

        if issues:
            findings.append(Finding(
                vuln_type="SECURITY_MISCONFIGURATION",
                severity="low" if len(issues) == 1 else "medium",
                endpoint=f"GET {endpoint.path}",
                description="; ".join(issues),
                evidence={"response_status": response.status_code, "issues": issues},
                remediation=REMEDIATION_TEXT["SECURITY_MISCONFIGURATION"],
            ))
    return findings
