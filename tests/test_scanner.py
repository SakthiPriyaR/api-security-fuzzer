import json
import threading
from http.server import HTTPServer
from pathlib import Path

from fuzzer.http_client import ApiClient, TestAccount as Account, fill_path
from fuzzer.cli import build_arg_parser
from fuzzer.modules import bola, broken_auth, mass_assignment, prompt_injection, injection
from fuzzer.parser import load_spec, parse_endpoints
from fuzzer.report import generate_html_report, generate_json_report
from fuzzer.scoring import Finding
from fuzzer.parser import Endpoint, Parameter
from sample_apis.mock_vulnerable_server import Handler


ROOT = Path(__file__).resolve().parents[1]


class LiveMockAPI:
    def __enter__(self):
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.client = ApiClient(self.base_url)
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def test_path_substitution_and_openapi_security_override():
    assert fill_path("/orders/{order_id}", {"order_id": "a b"}) == "/orders/a b"
    spec = {
        "security": [{"bearerAuth": []}],
        "paths": {
            "/public": {"get": {"security": [], "responses": {}}},
            "/private": {"get": {"responses": {}}},
        },
    }
    endpoints = {endpoint.path: endpoint for endpoint in parse_endpoints(spec)}
    assert endpoints["/public"].requires_auth is False
    assert endpoints["/private"].requires_auth is True


def test_read_only_validation_flag_is_available():
    args = build_arg_parser().parse_args([
        "--spec", "spec.json",
        "--base-url", "http://127.0.0.1:8888",
        "--token-a", "a", "--user-id-a", "1",
        "--token-b", "b", "--user-id-b", "2",
        "--safe-read-only",
    ])
    assert args.safe_read_only is True


def test_demo_scan_detects_documented_vulnerabilities():
    spec = load_spec(str(ROOT / "sample_apis" / "demo_openapi.json"))
    endpoints = parse_endpoints(spec)
    account_a = Account("A", "token-a", "1")
    account_b = Account("B", "token-b", "2")

    with LiveMockAPI() as api:
        findings = []
        findings.extend(bola.run(endpoints, api.client, account_a, account_b))
        findings.extend(broken_auth.run(endpoints, api.client))
        findings.extend(mass_assignment.run(endpoints, api.client, account_a))
        findings.extend(prompt_injection.run(api.client, account_a, account_b))
        findings.extend(injection.run(endpoints, api.client, account_a))

    counts = {}
    for finding in findings:
        counts[finding.vuln_type] = counts.get(finding.vuln_type, 0) + 1
    assert counts == {
        "BOLA": 2,
        "BROKEN_AUTH": 1,
        "MASS_ASSIGNMENT": 1,
        "PROMPT_INJECTION": 4,
    }


def test_reports_escape_untrusted_content(tmp_path):
    finding = Finding(
        vuln_type="BOLA",
        severity="critical",
        endpoint='GET /x?value="<script>alert(1)</script>',
        description="<img src=x onerror=alert(1)>",
        evidence={"payload": "<script>bad()</script>"},
        remediation="Use <strong>authorization</strong>.",
    )
    html_path = tmp_path / "report.html"
    json_path = tmp_path / "report.json"
    generate_html_report([finding], '<target & "quoted">', str(html_path))
    generate_json_report([finding], "local", str(json_path))

    html = html_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["total_findings"] == 1
    assert report["findings"][0]["owasp_id"] == "API1:2023"


def test_reflected_input_probe_is_a_review_signal_not_exploit_claim():
    endpoint = Endpoint(
        path="/search",
        method="get",
        operation_id="search",
        parameters=[Parameter("q", "query", True, "string")],
    )

    class Response:
        status_code = 200
        text = "results for codex_probe_7f3a9c"

    class Client:
        def call(self, *args, **kwargs):
            return Response()

    findings = injection.run([endpoint], Client(), Account("A", "token-a", "1"))
    assert len(findings) == 1
    assert findings[0].vuln_type == "INJECTION"
    assert findings[0].severity == "low"
    assert "does not prove" in findings[0].description
