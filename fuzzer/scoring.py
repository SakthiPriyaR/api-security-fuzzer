"""
scoring.py

Defines the Finding structure and maps each vulnerability type detected
by the attack modules to:
  - an OWASP API Security Top 10 (2023) category
  - a severity rating

Keeping this mapping centralized (rather than hardcoded per-module) is
what lets the report read like a real audit deliverable instead of a
pile of ad-hoc print statements, and makes it trivial to add a new
attack module later without touching the reporting code.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# OWASP API Security Top 10 (2023) reference:
# https://owasp.org/API-Security/editions/2023/en/0x11-t10/
OWASP_CATEGORIES = {
    "BOLA": ("API1:2023", "Broken Object Level Authorization"),
    "BROKEN_AUTH": ("API2:2023", "Broken Authentication"),
    "MASS_ASSIGNMENT": ("API3:2023", "Broken Object Property Level Authorization"),
    "INJECTION": ("API8:2023", "Security Misconfiguration"),
    # From the separate OWASP Top 10 for LLM Applications list, since
    # this vulnerability class lives at the AI-agent layer rather than
    # the raw API layer that the three categories above cover.
    "PROMPT_INJECTION": ("LLM01:2025", "Prompt Injection"),
}

SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass
class Finding:
    vuln_type: str              # "BOLA" | "BROKEN_AUTH" | "MASS_ASSIGNMENT"
    severity: str                # "critical" | "high" | "medium" | "low"
    endpoint: str                # e.g. "GET /orders/{id}"
    description: str
    evidence: dict = field(default_factory=dict)
    remediation: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def owasp_id(self) -> str:
        return OWASP_CATEGORIES.get(self.vuln_type, ("UNKNOWN", "Unknown"))[0]

    @property
    def owasp_name(self) -> str:
        return OWASP_CATEGORIES.get(self.vuln_type, ("UNKNOWN", "Unknown"))[1]

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "owasp_id": self.owasp_id,
            "owasp_name": self.owasp_name,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }


REMEDIATION_TEXT = {
    "BOLA": (
        "Enforce object-level authorization checks on every request that "
        "accesses a resource by ID. Verify the authenticated user actually "
        "owns or is permitted to access the specific object_id/user_id in "
        "the request, server-side, on every call - never trust the client."
    ),
    "BROKEN_AUTH": (
        "Reject requests to protected endpoints when no token, an expired "
        "token, or a malformed token is presented. Ensure authentication "
        "middleware runs before route handlers on every protected path, "
        "and return a uniform 401 rather than leaking partial data."
    ),
    "MASS_ASSIGNMENT": (
        "Use an explicit allow-list of fields that can be set from client "
        "input for each endpoint, rather than binding the request body "
        "directly to an internal model. Never let client-supplied fields "
        "like isAdmin, role, or verified reach privileged model fields."
    ),
    "INJECTION": (
        "Validate and contextually encode all untrusted input before using it "
        "in database queries, templates, shell commands, or downstream systems. "
        "Prefer parameterized queries and avoid reflecting executable input."
    ),
    "PROMPT_INJECTION": (
        "Never let an LLM agent treat third-party or user-generated content "
        "(support tickets, reviews, tool results) as trusted instructions. "
        "Keep a strict separation between the system prompt/authenticated "
        "user intent and any text the agent merely reads. Apply the same "
        "server-side authorization checks to agent-initiated API calls as "
        "you would to any direct API call - never trust the agent's own "
        "judgment as the sole access control."
    ),
}


def sort_findings(findings: list) -> list:
    """Highest severity first, useful for both the report and console output."""
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity, -1),
        reverse=True,
    )


def summarize_counts(findings: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
