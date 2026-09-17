"""
report.py

Turns a list of Finding objects into two deliverables:
  - a machine-readable JSON report (for CI/CD gating, diffing runs, etc.)
  - a human-readable HTML report (for the security-audit-style deliverable
    you'd actually hand someone, and what you'd screen-share in a demo)

Kept dependency-free (no Jinja2 requirement) using simple string
templates so the tool has minimal install friction.
"""

import json
from html import escape
from datetime import datetime, timezone
from fuzzer.scoring import sort_findings, summarize_counts

SEVERITY_COLORS = {
    "critical": "#b3261e",
    "high": "#e37400",
    "medium": "#b58a00",
    "low": "#4a7c2f",
}


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


def _finding_row(f) -> str:
    color = SEVERITY_COLORS.get(f.severity, "#666")
    evidence_html = "".join(
        f"<li><code>{escape(str(k))}</code>: {escape(str(v))}</li>"
        for k, v in f.evidence.items()
    )
    return f"""
    <div class="finding">
      <div class="finding-header" style="border-left: 5px solid {color};">
        <span class="severity" style="color:{color};">{f.severity.upper()}</span>
        <span class="owasp">{escape(f.owasp_id)} - {escape(f.owasp_name)}</span>
        <span class="endpoint"><code>{escape(f.endpoint)}</code></span>
      </div>
      <p class="description">{escape(f.description)}</p>
      <details>
        <summary>Evidence</summary>
        <ul>{evidence_html}</ul>
      </details>
      <p class="remediation"><strong>Remediation:</strong> {escape(f.remediation)}</p>
    </div>
    """


def generate_html_report(findings: list, target: str, out_path: str) -> str:
    ordered = sort_findings(findings)
    counts = summarize_counts(ordered)
    rows = "".join(_finding_row(f) for f in ordered) or "<p>No findings. All tested checks passed.</p>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>API Security Scan Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 900px;
          margin: 40px auto; padding: 0 20px; color: #1a1a1a; background: #fafafa; }}
  h1 {{ margin-bottom: 4px; }}
  .meta {{ color: #666; margin-bottom: 24px; }}
  .summary {{ display: flex; gap: 16px; margin-bottom: 32px; }}
  .summary-box {{ flex: 1; padding: 16px; border-radius: 8px; background: white;
                   box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
  .summary-box .count {{ font-size: 28px; font-weight: 700; }}
  .finding {{ background: white; border-radius: 8px; margin-bottom: 16px;
              box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }}
  .finding-header {{ padding: 12px 16px; display: flex; gap: 16px; align-items: center; }}
  .severity {{ font-weight: 700; }}
  .owasp {{ color: #444; }}
  .endpoint {{ margin-left: auto; }}
  .description {{ padding: 0 16px; }}
  details {{ padding: 0 16px 12px; }}
  .remediation {{ padding: 0 16px 16px; background: #f5f8ff; }}
  code {{ background: #eee; padding: 2px 5px; border-radius: 4px; }}
</style>
</head>
<body>
  <h1>API Security Scan Report</h1>
  <p class="meta">Target: <code>{escape(target)}</code> &middot; Generated: {datetime.now(timezone.utc).isoformat()}</p>

  <div class="summary">
    <div class="summary-box"><div class="count" style="color:{SEVERITY_COLORS['critical']}">{counts['critical']}</div>Critical</div>
    <div class="summary-box"><div class="count" style="color:{SEVERITY_COLORS['high']}">{counts['high']}</div>High</div>
    <div class="summary-box"><div class="count" style="color:{SEVERITY_COLORS['medium']}">{counts['medium']}</div>Medium</div>
    <div class="summary-box"><div class="count" style="color:{SEVERITY_COLORS['low']}">{counts['low']}</div>Low</div>
  </div>

  {rows}
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path
