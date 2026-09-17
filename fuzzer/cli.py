"""
cli.py

Command-line entry point. This is the single command you run live in
your demo/defense:

    python -m fuzzer.cli \\
        --spec sample_apis/crapi_openapi.json \\
        --base-url http://localhost:8888 \\
        --token-a "$TOKEN_A" --user-id-a "1" \\
        --token-b "$TOKEN_B" --user-id-b "2" \\
        --out reports/scan

It wires together: spec parsing -> attack modules -> scoring ->
JSON + HTML report generation, and exits non-zero if any critical
finding was detected (this is the hook a CI/CD pipeline would use to
fail a build).
"""

import argparse
import sys

from fuzzer.parser import load_spec, parse_endpoints, summarize
from fuzzer.http_client import ApiClient, TestAccount
from fuzzer.modules import bola, mass_assignment, broken_auth, prompt_injection, injection
from fuzzer.modules import function_auth, system_prompt_leakage, excessive_agency
from fuzzer.modules import resource_consumption, security_misconfiguration
from fuzzer.report import generate_json_report, generate_html_report
from fuzzer.scoring import summarize_counts


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="API Security Testing & Fuzzing Framework - "
                     "OWASP API Top 10 automated scanner."
    )
    p.add_argument("--spec", required=True, help="Path to OpenAPI/Swagger spec (JSON or YAML)")
    p.add_argument("--base-url", required=True, help="Base URL of the running target API")
    p.add_argument("--token-a", required=True, help="Bearer token for test account A")
    p.add_argument("--user-id-a", required=True, help="Resource/user id for account A")
    p.add_argument("--token-b", required=True, help="Bearer token for test account B")
    p.add_argument("--user-id-b", required=True, help="Resource/user id for account B")
    p.add_argument("--out", default="reports/scan", help="Output path prefix (no extension)")
    p.add_argument(
        "--safe-read-only",
        action="store_true",
        help=("Only probe GET/HEAD/OPTIONS endpoints and disable the local-only "
              "prompt-injection simulation; use for an isolated validation target."),
    )
    p.add_argument(
        "--local-llm-demos",
        action="store_true",
        help="Opt in to LLM demo probes for the bundled mock API (includes a simulated destructive DELETE).",
    )
    p.add_argument(
        "--check-rate-limits",
        action="store_true",
        help="Opt in to a bounded 3-10 request API4 sample against one GET endpoint.",
    )
    p.add_argument("--rate-limit-sample", type=int, choices=range(3, 11), default=5,
                   help="Request count for --check-rate-limits (3-10; default: 5)")
    p.add_argument("--skip", nargs="*", default=[],
                    choices=["bola", "mass_assignment", "broken_auth", "prompt_injection", "injection", "function_auth", "system_prompt_leakage", "excessive_agency", "resource_consumption", "security_misconfiguration"],
                    help="Skip one or more modules")
    p.add_argument("--fail-on", default="critical",
                    choices=["critical", "high", "medium", "low", "never"],
                    help="Exit non-zero if a finding at/above this severity is found "
                         "(used for CI/CD gating). 'never' always exits 0.")
    return p


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def main(argv=None):
    args = build_arg_parser().parse_args(argv)

    print(f"[*] Loading spec: {args.spec}")
    spec = load_spec(args.spec)
    endpoints = parse_endpoints(spec)
    local_demo_modules = ("prompt_injection", "system_prompt_leakage", "excessive_agency")
    if not args.local_llm_demos:
        for module_name in local_demo_modules:
            if module_name not in args.skip:
                args.skip.append(module_name)
        print("[*] Skipping local-only LLM demos; pass --local-llm-demos only for the bundled mock API")
    if args.safe_read_only:
        endpoints = [ep for ep in endpoints if ep.method in ("get", "head", "options")]
        if "prompt_injection" not in args.skip:
            print("[*] Safe read-only mode: disabling local prompt-injection simulation")
            args.skip.append("prompt_injection")
        if "system_prompt_leakage" not in args.skip:
            args.skip.append("system_prompt_leakage")
        if "excessive_agency" not in args.skip:
            args.skip.append("excessive_agency")
        if "mass_assignment" not in args.skip:
            print("[*] Safe read-only mode: disabling request-body mutation probes")
            args.skip.append("mass_assignment")
    print(summarize(endpoints))

    client = ApiClient(base_url=args.base_url)
    account_a = TestAccount(label="A", token=args.token_a, user_id=args.user_id_a)
    account_b = TestAccount(label="B", token=args.token_b, user_id=args.user_id_b)

    all_findings = []

    if "bola" not in args.skip:
        print("\n[*] Running BOLA module (API1:2023)...")
        findings = bola.run(endpoints, client, account_a, account_b)
        print(f"    -> {len(findings)} finding(s)")
        all_findings += findings

    if "broken_auth" not in args.skip:
        print("[*] Running Broken Authentication module (API2:2023)...")
        findings = broken_auth.run(endpoints, client)
        print(f"    -> {len(findings)} finding(s)")
        all_findings += findings

    if "function_auth" not in args.skip:
        print("[*] Running Broken Function Level Authorization module (API5:2023)...")
        findings = function_auth.run(endpoints, client, account_a)
        print(f"    -> {len(findings)} finding(s)")
        all_findings += findings

    if "mass_assignment" not in args.skip:
        print("[*] Running Mass Assignment module (API3:2023)...")
        findings = mass_assignment.run(endpoints, client, account_a)
        print(f"    -> {len(findings)} finding(s)")
        all_findings += findings

    if "prompt_injection" not in args.skip:
        print("[*] Running Prompt Injection module (LLM01:2025)...")
        findings = prompt_injection.run(client, account_a, account_b)
        print(f"    -> {len(findings)} finding(s)")
        all_findings += findings

    if "system_prompt_leakage" not in args.skip:
        print("[*] Running System Prompt Leakage check (LLM07:2025)...")
        findings = system_prompt_leakage.run(client, account_a)
        print(f"    -> {len(findings)} finding(s)")
        all_findings += findings

    if "excessive_agency" not in args.skip:
        print("[*] Running local-only Excessive Agency demo (LLM06:2025)...")
        findings = excessive_agency.run(client, account_a)
        print(f"    -> {len(findings)} finding(s)")
        all_findings += findings

    if "injection" not in args.skip:
        print("[*] Running safe reflected-input probe (API8:2023 heuristic)...")
        findings = injection.run(endpoints, client, account_a)
        print(f"    -> {len(findings)} finding(s)")
        all_findings += findings

    print("[*] Running API8 response configuration checks...")
    findings = security_misconfiguration.run(endpoints, client, account_a)
    print(f"    -> {len(findings)} finding(s)")
    all_findings += findings

    if args.check_rate_limits and "resource_consumption" not in args.skip:
        print(f"[*] Running bounded API4 sample ({args.rate_limit_sample} requests, one GET endpoint)...")
        findings = resource_consumption.run(
            endpoints, client, account_a, request_count=args.rate_limit_sample
        )
        print(f"    -> {len(findings)} tentative signal(s)")
        all_findings += findings

    json_path = generate_json_report(all_findings, args.base_url, f"{args.out}.json")
    html_path = generate_html_report(all_findings, args.base_url, f"{args.out}.html")

    counts = summarize_counts(all_findings)
    print(f"\n[*] Scan complete. {len(all_findings)} total finding(s).")
    print(f"    Critical: {counts['critical']}  High: {counts['high']}  "
          f"Medium: {counts['medium']}  Low: {counts['low']}")
    print(f"[*] JSON report: {json_path}")
    print(f"[*] HTML report: {html_path}")

    if args.fail_on != "never":
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] >= threshold for f in all_findings):
            print(f"\n[!] Findings at/above '{args.fail_on}' severity detected - failing.")
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
