"""
llm_agent.py

Simulates an AI assistant that has been given access to call this
project's demo API on a user's behalf - e.g. a customer-support chatbot
that can look up a user's own orders when asked in plain English.

This is intentionally a SIMPLIFIED, rule-based stand-in for a real LLM
(no external API calls, fully offline, fully reproducible for a demo).
It mimics the SAME structural weakness that real LLM-driven agents can
have: it cannot reliably tell the difference between

  (a) trusted instructions - the system prompt defining what it's
      allowed to do, and the logged-in user's own direct request, vs.
  (b) untrusted content it is merely reading - e.g. text pulled from a
      support ticket, a product review, or any other user-generated
      content that gets passed into its context.

If (b) contains something that LOOKS like an instruction, this naive
agent may follow it anyway. That confusion between "data" and
"instructions" is the root cause of prompt injection - the #1 entry on
the OWASP Top 10 for LLM Applications (LLM01:2025).

This is NOT a jailbreak generator and does not produce or enable any
attack against real, external systems - it is a local, self-contained
scenario built purely to demonstrate and test for the weakness, using
only the sample data already shipped in this repo.
"""

import re
from dataclasses import dataclass, field

# Phrases that a naive agent might mistake for a legitimate instruction
# override, regardless of WHERE in the input they appear. A properly
# hardened agent would ignore these when they show up inside content
# it's merely reading (e.g. a pasted support message) rather than in
# the system prompt or the authenticated user's own direct request.
INJECTION_TRIGGER_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"disregard (the )?(above|prior) instructions",
    r"system\s*[:\-]\s*",
    r"debug mode",
    r"admin mode",
    r"you are now",
    r"reveal (the )?(admin|system) (token|password|secret)",
    r"show (me )?(all|every) users?['\u2019]? orders?",
]

ORDER_ID_PATTERN = re.compile(r"\border\s*#?\s*(\d+)\b", re.IGNORECASE)


@dataclass
class AgentResponse:
    action_taken: str            # e.g. "lookup_order"
    order_id_accessed: str = None
    followed_injected_instruction: bool = False
    matched_trigger: str = None
    raw_tool_result: dict = field(default_factory=dict)
    explanation: str = ""


class MockSupportAgent:
    """
    A stand-in for an LLM-powered support assistant wired to this
    project's demo API. It is scoped, in its system prompt, to only
    ever look up the CURRENTLY LOGGED IN user's own orders - but its
    intent-detection is naive keyword matching, which is exactly the
    class of weakness real prompt-injection attacks exploit.
    """

    SYSTEM_SCOPE = (
        "You are a support assistant. You may only look up the current "
        "logged-in user's OWN orders. Never access another user's data."
    )

    def __init__(self, api_client, account):
        self.client = api_client
        self.account = account  # the currently logged-in TestAccount

    def _detect_injection_trigger(self, text: str):
        lowered = text.lower()
        for pattern in INJECTION_TRIGGER_PATTERNS:
            if re.search(pattern, lowered):
                return pattern
        return None

    def handle(self, user_prompt: str, embedded_content: str = "") -> AgentResponse:
        """
        user_prompt: what the logged-in user typed directly, e.g.
            "can you check on order 1 for me?"
        embedded_content: untrusted text the agent is ALSO reading as
            part of handling the request - e.g. the body of a support
            ticket, a pasted review, a field from another API response.
            A hardened agent should NOT treat this as instructions.

        This naive implementation scans BOTH user_prompt and
        embedded_content for order-id mentions and injection trigger
        phrases, without distinguishing where the text came from -
        which is the vulnerability under test.
        """
        full_context = f"{user_prompt}\n{embedded_content}"
        # Check both the direct user prompt and any embedded content for
        # a trigger phrase - the point being that this naive agent makes
        # NO distinction between the two when deciding whether to comply.
        trigger = (
            self._detect_injection_trigger(embedded_content)
            or self._detect_injection_trigger(user_prompt)
        )

        # Naive intent detection: find ANY order id mentioned anywhere
        # in the combined context, trusted or not.
        match = ORDER_ID_PATTERN.search(full_context)
        requested_order_id = match.group(1) if match else self.account.user_id

        # The agent calls the underlying order-lookup endpoint using the
        # CURRENT user's auth token, but whatever order id it picked up
        # from the (possibly untrusted) text - mirroring exactly how a
        # real over-permissive agent would blindly pass along an
        # attacker-influenced parameter to a tool call.
        resp = self.client.call(
            "get", "/orders/{order_id}",
            account=self.account,
            path_values={"order_id": requested_order_id},
        )

        try:
            body = resp.json()
        except Exception:
            body = {}

        followed_injection = bool(trigger) and requested_order_id != self.account.user_id

        return AgentResponse(
            action_taken="lookup_order",
            order_id_accessed=requested_order_id,
            followed_injected_instruction=followed_injection,
            matched_trigger=trigger,
            raw_tool_result=body,
            explanation=(
                f"Agent looked up order '{requested_order_id}' "
                f"(logged in as account '{self.account.user_id}')."
            ),
        )
