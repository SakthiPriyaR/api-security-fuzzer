"""
http_client.py

A thin wrapper around `requests` that:
  - substitutes path parameters (e.g. /orders/{id} -> /orders/1023)
  - attaches bearer tokens for a given test account
  - never raises on non-2xx (we WANT to inspect 401/403/500 etc.)

Two TestAccount objects (account_a, account_b) represent two distinct,
unprivileged users. Almost every BOLA-style test is really just:
"can account A use its own token to read/write account B's data?"
"""

import re
import requests
from dataclasses import dataclass
from typing import Optional


@dataclass
class TestAccount:
    label: str            # "A" or "B", used in findings for readability
    token: str            # bearer token for this account
    user_id: str          # this account's own resource/user id
    extra_headers: dict = None

    def headers(self) -> dict:
        h = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        if self.extra_headers:
            h.update(self.extra_headers)
        return h


PATH_PARAM_RE = re.compile(r"{(\w+)}")


def fill_path(path_template: str, values: dict) -> str:
    """Replace {param} placeholders in an OpenAPI path with real values."""
    def _sub(match):
        name = match.group(1)
        return str(values.get(name, match.group(0)))
    return PATH_PARAM_RE.sub(_sub, path_template)


class ApiClient:
    def __init__(self, base_url: str, timeout: float = 8.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def call(self, method: str, path: str, account: Optional[TestAccount] = None,
              path_values: dict = None, json_body: dict = None,
              query_params: dict = None, override_headers: dict = None):
        """
        Fire a single request and return the raw requests.Response.
        Never raises on HTTP error status - callers inspect status_code
        themselves since a 401/403/500 IS the interesting data point.
        """
        url = self.base_url + fill_path(path, path_values or {})
        headers = account.headers() if account else {}
        if override_headers is not None:
            # override_headers=None means "use account headers normally";
            # override_headers={} explicitly means "send NO auth at all"
            # (used by the broken-auth module to simulate an anonymous caller)
            headers = override_headers

        try:
            resp = self.session.request(
                method.upper(),
                url,
                headers=headers,
                json=json_body,
                params=query_params,
                timeout=self.timeout,
            )
            return resp
        except requests.RequestException as e:
            return _FailedResponse(str(e))


class _FailedResponse:
    """Stand-in returned when the request itself couldn't complete
    (connection refused, timeout, DNS failure, etc.) so downstream
    code can treat it uniformly instead of crashing on None."""
    def __init__(self, error: str):
        self.status_code = -1
        self.error = error
        self.text = f"<request failed: {error}>"

    def json(self):
        return {}
