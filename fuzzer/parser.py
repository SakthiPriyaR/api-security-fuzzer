"""
parser.py

Reads an OpenAPI/Swagger spec (JSON or YAML) and converts it into a flat,
easy-to-iterate list of "Endpoint" objects that the attack modules can
consume. This is the foundation of the whole tool: every other module
depends on this producing a clean, predictable structure regardless of
how messy the input spec is.
"""

import json
import yaml
from dataclasses import dataclass, field
from typing import Optional


# Heuristics for spotting parameters that look like resource IDs.
# Used later by the BOLA module to decide which params are worth swapping.
ID_PARAM_HINTS = ("id", "uuid", "pk", "user_id", "account_id", "order_id")

# HTTP methods that typically carry a request body worth fuzzing
# (used by the mass-assignment module).
BODY_METHODS = ("post", "put", "patch")


@dataclass
class Parameter:
    name: str
    location: str          # "path", "query", "header", "cookie"
    required: bool
    schema_type: Optional[str] = None

    @property
    def looks_like_id(self) -> bool:
        lowered = self.name.lower()
        return any(hint in lowered for hint in ID_PARAM_HINTS)


@dataclass
class Endpoint:
    path: str
    method: str             # "get", "post", "put", "patch", "delete"
    operation_id: Optional[str]
    parameters: list = field(default_factory=list)   # list[Parameter]
    requires_auth: bool = False
    request_body_schema: Optional[dict] = None
    response_schema: Optional[dict] = None
    required_role: Optional[str] = None

    @property
    def id_parameters(self):
        return [p for p in self.parameters if p.looks_like_id]

    @property
    def has_body(self):
        return self.method.lower() in BODY_METHODS

    def __repr__(self):
        return f"<Endpoint {self.method.upper()} {self.path} auth={self.requires_auth}>"


def load_spec(path: str) -> dict:
    """Load a JSON or YAML OpenAPI spec from disk."""
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return yaml.safe_load(raw)


def _extract_body_schema(operation: dict) -> Optional[dict]:
    body = operation.get("requestBody", {})
    content = body.get("content", {})
    json_body = content.get("application/json", {})
    return json_body.get("schema")


def _extract_response_schema(operation: dict) -> Optional[dict]:
    responses = operation.get("responses", {})
    for status in ("200", "201"):
        resp = responses.get(status)
        if resp:
            content = resp.get("content", {})
            json_resp = content.get("application/json", {})
            return json_resp.get("schema")
    return None


def _operation_requires_auth(operation: dict, global_security: list) -> bool:
    # A per-operation "security: []" explicitly disables auth even if
    # global security is set. Otherwise inherit from global, or from
    # any operation-level security scheme.
    if "security" in operation:
        return len(operation["security"]) > 0
    return len(global_security) > 0


def parse_endpoints(spec: dict) -> list:
    """
    Walk the OpenAPI 'paths' object and produce a flat list of Endpoint
    objects. Handles both OpenAPI 3.x and (loosely) Swagger 2.0 shaped
    specs since both use the same paths/parameters/responses skeleton.
    """
    endpoints = []
    global_security = spec.get("security", [])
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        # Parameters defined at the path level apply to every method
        # under that path unless overridden.
        shared_params_raw = path_item.get("parameters", [])

        for method, operation in path_item.items():
            if method.lower() not in (
                "get", "post", "put", "patch", "delete", "head", "options"
            ):
                continue  # skip non-HTTP-method keys like "parameters"

            if not isinstance(operation, dict):
                continue

            op_params_raw = operation.get("parameters", [])
            all_params_raw = shared_params_raw + op_params_raw

            parameters = []
            for p in all_params_raw:
                schema = p.get("schema", {})
                parameters.append(
                    Parameter(
                        name=p.get("name", ""),
                        location=p.get("in", "query"),
                        required=p.get("required", False),
                        schema_type=schema.get("type"),
                    )
                )

            endpoints.append(
                Endpoint(
                    path=path,
                    method=method.lower(),
                    operation_id=operation.get("operationId"),
                    parameters=parameters,
                    requires_auth=_operation_requires_auth(operation, global_security),
                    request_body_schema=_extract_body_schema(operation),
                    response_schema=_extract_response_schema(operation),
                    required_role=operation.get("x-required-role"),
                )
            )

    return endpoints


def summarize(endpoints: list) -> str:
    """Human-readable summary, handy for a sanity-check print after parsing."""
    lines = [f"Discovered {len(endpoints)} endpoints:"]
    for ep in endpoints:
        auth_tag = "AUTH" if ep.requires_auth else "open"
        id_params = [p.name for p in ep.id_parameters]
        id_tag = f" id_params={id_params}" if id_params else ""
        lines.append(f"  [{auth_tag:4}] {ep.method.upper():6} {ep.path}{id_tag}")
    return "\n".join(lines)
