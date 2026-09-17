"""Bounded API4 request-rate sample. Does not attempt denial of service."""

from fuzzer.scoring import Finding, REMEDIATION_TEXT


def run(endpoints, client, account, request_count=5):
    if not 3 <= request_count <= 10:
        raise ValueError("request_count must be between 3 and 10")

    endpoint = next((
        ep for ep in endpoints
        if ep.method == "get" and not any(
            p.required and p.location == "query" for p in ep.parameters
        )
    ), None)
    if endpoint is None:
        return []

    path_values = {
        p.name: account.user_id
        for p in endpoint.parameters
        if p.location == "path"
    }
    responses = [
        client.call(endpoint.method, endpoint.path,
                    account=account if endpoint.requires_auth else None,
                    path_values=path_values)
        for _ in range(request_count)
    ]
    statuses = [response.status_code for response in responses]
    if any(status == 429 for status in statuses):
        return []

    if not all(200 <= status < 300 for status in statuses):
        return []

    return [Finding(
        vuln_type="RESOURCE_CONSUMPTION",
        severity="low",
        endpoint=f"{endpoint.method.upper()} {endpoint.path}",
        description=(
            f"All {request_count} requests in a small consecutive sample succeeded "
            "without an observed 429 response. This is an inconclusive signal, "
            "not proof that rate limiting is absent."
        ),
        evidence={"sample_size": request_count, "response_statuses": statuses},
        remediation=REMEDIATION_TEXT["RESOURCE_CONSUMPTION"],
    )]
