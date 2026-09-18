"""
report.py

Turns a list of Finding objects into multiple deliverables:
  - a machine-readable JSON report (for CI/CD gating, diffing runs, etc.)
  - an interactive, modern HTML report with search, severity filtering,
    remediation advice, and copyable cURL reproducers
  - a SARIF v2.1.0 report (for GitHub Advanced Security & Code Scanning upload)
  - a JUnit XML report (for test runner integration in GitLab/Jenkins/Azure DevOps)
"""

import json
import xml.etree.ElementTree as ET
from html import escape
from datetime import datetime, timezone
from fuzzer.scoring import sort_findings, summarize_counts

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
}

SEVERITY_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def build_curl_reproducer(f, target_base_url: str) -> str:
    """Generates an accurate, copy-pasteable curl command to reproduce a finding."""
    endpoint = f.endpoint.strip()
    ev = f.evidence or {}
    base_url = target_base_url.rstrip("/")

    # Check for direct HTTP method + path in endpoint (e.g. "GET /orders/{id}")
    parts = endpoint.split(" ", 1)
    if len(parts) == 2 and parts[0].upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        method = parts[0].upper()
        path = parts[1]
    else:
        method = "GET"
        path = endpoint if endpoint.startswith("/") else f"/{endpoint}"

    # Replace parameter templates if concrete values are in evidence
    for k in ("order_id", "id", "userId", "vehicleId"):
        if k in ev and f"{{{k}}}" in path:
            path = path.replace(f"{{{k}}}", str(ev[k]))

    target_url = f"{base_url}{path}"
    curl_parts = [f"curl -i -X {method} \"{target_url}\""]

    # Authentication header
    if "token" in ev:
        curl_parts.append(f"-H \"Authorization: Bearer {ev['token']}\"")
    elif "attacker_token" in ev:
        curl_parts.append(f"-H \"Authorization: Bearer {ev['attacker_token']}\"")
    elif "token_used" in ev:
        curl_parts.append(f"-H \"Authorization: Bearer {ev['token_used']}\"")

    # Request Body
    if "payload" in ev:
        payload_str = json.dumps(ev["payload"]) if isinstance(ev["payload"], (dict, list)) else str(ev["payload"])
        curl_parts.append(f"-H \"Content-Type: application/json\" --data '{payload_str}'")
    elif "injected_body" in ev:
        payload_str = json.dumps(ev["injected_body"]) if isinstance(ev["injected_body"], (dict, list)) else str(ev["injected_body"])
        curl_parts.append(f"-H \"Content-Type: application/json\" --data '{payload_str}'")

    return " \\\n  ".join(curl_parts)


def generate_json_report(findings: list, target: str, out_path: str) -> str:
    ordered = sort_findings(findings)
    report = {
        "tool": "API Security Testing & Fuzzing Framework",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "summary": summarize_counts(ordered),
        "total_findings": len(ordered),
        "findings": [f.to_dict() for f in ordered],
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return out_path


def generate_sarif_report(findings: list, target: str, out_path: str) -> str:
    """Export findings in SARIF v2.1.0 format for GitHub Code Scanning."""
    rules = {}
    results = []

    for f in findings:
        rule_id = f.vuln_type
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.owasp_name.replace(" ", ""),
                "shortDescription": {"text": f"{f.owasp_id}: {f.owasp_name}"},
                "fullDescription": {"text": f.remediation or f.description},
                "defaultConfiguration": {
                    "level": SEVERITY_SARIF_LEVEL.get(f.severity, "warning")
                },
                "help": {"text": f"Remediation: {f.remediation}"},
                "properties": {
                    "tags": ["security", "owasp", f.owasp_id.lower()],
                    "problem.severity": f.severity,
                },
            }

        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_SARIF_LEVEL.get(f.severity, "warning"),
            "message": {
                "text": f"[{f.severity.upper()}] {f.description} (Endpoint: {f.endpoint})"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target or "api-spec.json"
                        },
                        "region": {"startLine": 1}
                    }
                }
            ],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "api-security-fuzzer",
                        "informationUri": "https://github.com/SakthiPriyaR/api-security-fuzzer",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    return out_path


def generate_junit_report(findings: list, target: str, out_path: str) -> str:
    """Export findings as standard JUnit XML test suite report."""
    testsuite = ET.Element(
        "testsuite",
        name="api_security_fuzzer",
        tests=str(len(findings)),
        failures=str(len(findings)),
        errors="0",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    for idx, f in enumerate(findings):
        testcase = ET.SubElement(
            testsuite,
            "testcase",
            classname=f"OWASP.{f.owasp_id.replace(':', '_')}",
            name=f"{f.vuln_type} - {f.endpoint}",
        )
        failure = ET.SubElement(
            testcase,
            "failure",
            message=f"[{f.severity.upper()}] {f.description}",
            type=f.vuln_type,
        )
        failure.text = (
            f"Vulnerability: {f.vuln_type} ({f.owasp_id} - {f.owasp_name})\n"
            f"Severity: {f.severity.upper()}\n"
            f"Endpoint: {f.endpoint}\n"
            f"Description: {f.description}\n"
            f"Evidence: {json.dumps(f.evidence, indent=2)}\n"
            f"Remediation: {f.remediation}\n"
        )

    tree = ET.ElementTree(testsuite)
    tree.write(out_path, encoding="utf-8", xml_declaration=True)
    return out_path


def _finding_card(f, idx: int, target_base_url: str) -> str:
    color = SEVERITY_COLORS.get(f.severity, "#64748b")
    curl_cmd = build_curl_reproducer(f, target_base_url)

    evidence_rows = "".join(
        f"<tr><td><strong>{escape(str(k))}</strong></td><td><code>{escape(json.dumps(v, indent=2) if isinstance(v, (dict, list)) else str(v))}</code></td></tr>"
        for k, v in f.evidence.items()
    ) if f.evidence else "<tr><td colspan=\"2\">No extra evidence metadata recorded.</td></tr>"

    return f"""
    <div class="finding-card" data-severity="{escape(f.severity)}" data-owasp="{escape(f.owasp_id)}" data-text="{escape(f.endpoint + ' ' + f.description + ' ' + f.vuln_type).lower()}">
      <div class="card-header" onclick="toggleCard({idx})">
        <div class="header-left">
          <span class="badge" style="background-color: {color}15; color: {color}; border: 1px solid {color}40;">
            {f.severity.upper()}
          </span>
          <span class="owasp-tag">{escape(f.owasp_id)} &middot; {escape(f.owasp_name)}</span>
        </div>
        <div class="header-right">
          <code class="endpoint-pill">{escape(f.endpoint)}</code>
          <span class="chevron" id="chevron-{idx}">▼</span>
        </div>
      </div>
      <div class="card-body" id="card-body-{idx}">
        <p class="description">{escape(f.description)}</p>

        <div class="section-title">Evidence & Reproduction</div>
        <table class="evidence-table">
          <tbody>{evidence_rows}</tbody>
        </table>

        <div class="curl-box">
          <div class="curl-header">
            <span>Reproduce via cURL</span>
            <button class="copy-btn" onclick="copyCurl('curl-{idx}', this)">Copy</button>
          </div>
          <pre id="curl-{idx}"><code>{escape(curl_cmd)}</code></pre>
        </div>

        <div class="remediation-box">
          <strong>Remediation Recommendation:</strong>
          <p>{escape(f.remediation)}</p>
        </div>
      </div>
    </div>
    """


def generate_html_report(findings: list, target: str, out_path: str) -> str:
    ordered = sort_findings(findings)
    counts = summarize_counts(ordered)
    cards = "".join(_finding_card(f, i, target) for i, f in enumerate(ordered)) or (
        "<div class=\"empty-state\"><h3>No vulnerabilities detected</h3><p>All automated checks passed!</p></div>"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Security Assessment Dashboard</title>
<style>
  :root {{
    --bg-page: #f8fafc;
    --card-bg: #ffffff;
    --text-primary: #0f172a;
    --text-muted: #64748b;
    --border-color: #e2e8f0;
    --primary: #3b82f6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-page);
    color: var(--text-primary);
    line-height: 1.5;
    padding: 30px 20px;
  }}
  .container {{ max-width: 1060px; margin: 0 auto; }}
  
  header {{
    margin-bottom: 24px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border-color);
  }}
  .title-row {{ display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 12px; }}
  h1 {{ font-size: 26px; font-weight: 800; color: #0f172a; letter-spacing: -0.5px; }}
  .meta-tag {{ font-size: 14px; color: var(--text-muted); }}
  .meta-tag code {{ background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-size: 13px; color: #1e293b; }}

  /* Metric Summary Counters */
  .metrics-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 14px;
    margin-bottom: 26px;
  }}
  .metric-card {{
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    padding: 16px;
    border-radius: 10px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    text-align: center;
  }}
  .metric-card.active {{
    border-color: #94a3b8;
    background: #f1f5f9;
  }}
  .metric-val {{ font-size: 32px; font-weight: 800; line-height: 1; margin-bottom: 6px; }}
  .metric-label {{ font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }}

  /* Controls: Search & Filter */
  .controls-bar {{
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
    flex-wrap: wrap;
  }}
  .search-input {{
    flex: 1;
    min-width: 240px;
    padding: 10px 14px;
    border-radius: 8px;
    border: 1px solid var(--border-color);
    font-size: 14px;
    outline: none;
    transition: border-color 0.2s;
  }}
  .search-input:focus {{ border-color: var(--primary); }}
  .filter-btn {{
    padding: 8px 14px;
    background: white;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    cursor: pointer;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-muted);
    transition: all 0.2s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    background: #0f172a;
    color: white;
    border-color: #0f172a;
  }}

  /* Finding Cards */
  .finding-card {{
    background: var(--card-bg);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    margin-bottom: 14px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    overflow: hidden;
    transition: box-shadow 0.2s ease;
  }}
  .finding-card:hover {{
    box-shadow: 0 4px 10px rgba(0,0,0,0.06);
  }}
  .card-header {{
    padding: 14px 18px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    user-select: none;
    background: #ffffff;
    gap: 12px;
    flex-wrap: wrap;
  }}
  .header-left, .header-right {{ display: flex; align-items: center; gap: 10px; }}
  .badge {{
    font-size: 11px;
    font-weight: 800;
    padding: 3px 8px;
    border-radius: 6px;
    letter-spacing: 0.5px;
  }}
  .owasp-tag {{ font-weight: 600; font-size: 14px; color: #334155; }}
  .endpoint-pill {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    background: #f1f5f9;
    padding: 3px 8px;
    border-radius: 6px;
    font-size: 13px;
    color: #0f172a;
  }}
  .chevron {{ font-size: 11px; color: var(--text-muted); transition: transform 0.2s; }}
  
  .card-body {{
    padding: 18px;
    border-top: 1px solid var(--border-color);
    background: #fafafa;
    display: none;
  }}
  .card-body.open {{ display: block; }}
  .description {{ font-size: 14px; margin-bottom: 16px; color: #1e293b; }}
  .section-title {{ font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px; }}

  .evidence-table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    margin-bottom: 16px;
    font-size: 13px;
    overflow: hidden;
  }}
  .evidence-table td {{
    padding: 8px 12px;
    border-bottom: 1px solid var(--border-color);
    vertical-align: top;
  }}
  .evidence-table tr:last-child td {{ border-bottom: none; }}
  .evidence-table td:first-child {{ width: 25%; background: #f8fafc; color: #475569; }}
  .evidence-table pre, .evidence-table code {{
    white-space: pre-wrap;
    word-break: break-all;
    font-family: ui-monospace, Menlo, Monaco, Consolas, monospace;
    font-size: 12px;
  }}

  /* cURL Reproducer Box */
  .curl-box {{
    background: #0f172a;
    border-radius: 8px;
    margin-bottom: 16px;
    overflow: hidden;
  }}
  .curl-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #1e293b;
    padding: 6px 12px;
    font-size: 12px;
    font-weight: 600;
    color: #94a3b8;
  }}
  .copy-btn {{
    background: #334155;
    color: white;
    border: none;
    padding: 3px 8px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 11px;
    font-weight: 600;
  }}
  .copy-btn:hover {{ background: #475569; }}
  .curl-box pre {{
    padding: 12px;
    margin: 0;
    color: #38bdf8;
    font-family: ui-monospace, Menlo, Monaco, Consolas, monospace;
    font-size: 12px;
    overflow-x: auto;
    white-space: pre-wrap;
  }}

  .remediation-box {{
    background: #eff6ff;
    border-left: 4px solid #3b82f6;
    padding: 12px 14px;
    border-radius: 0 6px 6px 0;
    font-size: 13px;
    color: #1e3a8a;
  }}
  .empty-state {{
    text-align: center;
    padding: 60px 20px;
    background: white;
    border-radius: 10px;
    border: 1px dashed var(--border-color);
  }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="title-row">
      <h1>API Security Scan Dashboard</h1>
      <div class="meta-tag">Target: <code>{escape(target)}</code> &middot; Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
    </div>
  </header>

  <div class="metrics-grid">
    <div class="metric-card" onclick="filterSeverity('all')" style="cursor: pointer;">
      <div class="metric-val" style="color: #0f172a;">{len(ordered)}</div>
      <div class="metric-label">Total Findings</div>
    </div>
    <div class="metric-card" onclick="filterSeverity('critical')" style="cursor: pointer;">
      <div class="metric-val" style="color: {SEVERITY_COLORS['critical']};">{counts['critical']}</div>
      <div class="metric-label">Critical</div>
    </div>
    <div class="metric-card" onclick="filterSeverity('high')" style="cursor: pointer;">
      <div class="metric-val" style="color: {SEVERITY_COLORS['high']};">{counts['high']}</div>
      <div class="metric-label">High</div>
    </div>
    <div class="metric-card" onclick="filterSeverity('medium')" style="cursor: pointer;">
      <div class="metric-val" style="color: {SEVERITY_COLORS['medium']};">{counts['medium']}</div>
      <div class="metric-label">Medium</div>
    </div>
    <div class="metric-card" onclick="filterSeverity('low')" style="cursor: pointer;">
      <div class="metric-val" style="color: {SEVERITY_COLORS['low']};">{counts['low']}</div>
      <div class="metric-label">Low</div>
    </div>
  </div>

  <div class="controls-bar">
    <input type="text" id="searchInput" class="search-input" placeholder="Search by endpoint, vulnerability name, or description..." oninput="applyFilters()">
    <button class="filter-btn active" id="btn-all" onclick="filterSeverity('all')">All</button>
    <button class="filter-btn" id="btn-critical" onclick="filterSeverity('critical')">Critical</button>
    <button class="filter-btn" id="btn-high" onclick="filterSeverity('high')">High</button>
    <button class="filter-btn" id="btn-medium" onclick="filterSeverity('medium')">Medium</button>
    <button class="filter-btn" id="btn-low" onclick="filterSeverity('low')">Low</button>
  </div>

  <div id="findingsContainer">
    {cards}
  </div>
</div>

<script>
  let activeSeverity = 'all';

  function toggleCard(idx) {{
    const body = document.getElementById('card-body-' + idx);
    const chevron = document.getElementById('chevron-' + idx);
    const isOpen = body.classList.contains('open');
    if (isOpen) {{
      body.classList.remove('open');
      chevron.style.transform = 'rotate(0deg)';
    }} else {{
      body.classList.add('open');
      chevron.style.transform = 'rotate(180deg)';
    }}
  }}

  function filterSeverity(sev) {{
    activeSeverity = sev;
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    const activeBtn = document.getElementById('btn-' + sev);
    if (activeBtn) activeBtn.classList.add('active');
    applyFilters();
  }}

  function applyFilters() {{
    const query = (document.getElementById('searchInput').value || '').toLowerCase().trim();
    const cards = document.querySelectorAll('.finding-card');

    cards.forEach(card => {{
      const sev = card.getAttribute('data-severity');
      const text = card.getAttribute('data-text');

      const matchesSev = (activeSeverity === 'all') || (sev === activeSeverity);
      const matchesSearch = !query || text.includes(query);

      if (matchesSev && matchesSearch) {{
        card.style.display = 'block';
      }} else {{
        card.style.display = 'none';
      }}
    }});
  }}

  function copyCurl(elemId, btn) {{
    const text = document.getElementById(elemId).innerText;
    navigator.clipboard.writeText(text).then(() => {{
      const orig = btn.innerText;
      btn.innerText = 'Copied!';
      setTimeout(() => {{ btn.innerText = orig; }}, 1600);
    }});
  }}
</script>
</body>
</html>
"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path
