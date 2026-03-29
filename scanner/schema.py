"""
schema.py — SPECTRE Shared Data Contract
=========================================
This file defines what one discovered API endpoint looks like.
Every member imports from this file. Nobody defines their own format.

VALID SOURCE VALUES:
  "nginx_config"      → found in an Nginx config file
  "kong_gateway"      → found in a Kong config file
  "code_repository"   → found by scanning Python source code
  "network_traffic"   → observed by mitmproxy traffic capture
  "kubernetes"        → found in a Docker/Kubernetes manifest

VALID STATE VALUES (to be set by classification step):
  "active"   → known, documented, recently used
  "shadow"   → receiving traffic but not in any gateway or repo
  "zombie"   → in gateway/repo but no traffic in 90+ days
  "rogue"    → not registered, no auth, suspicious
  "unknown"  → default before classification runs

VALID AUTH TYPE VALUES:
  "none"     → no authentication detected
  "jwt"      → JWT / Bearer token
  "basic"    → HTTP Basic Auth
  "api_key"  → API key in header or query param
  "oauth2"   → OAuth2
  "unknown"  → auth detected but type unclear
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
import hashlib
import json


VALID_SOURCES = {
    "nginx_config",
    "kong_gateway",
    "code_repository",
    "network_traffic",
    "kubernetes",
}

VALID_STATES = {
    "active",
    "shadow",
    "zombie",
    "rogue",
    "unknown",
}

VALID_AUTH_TYPES = {
    "none",
    "jwt",
    "basic",
    "api_key",
    "oauth2",
    "unknown",
}

VALID_METHODS = {
    "GET", "POST", "PUT", "DELETE",
    "PATCH", "OPTIONS", "HEAD", "ANY",
}


@dataclass
class APIEndpoint:
    """
    One discovered API endpoint.
    Fields grouped by who fills them in:
      - Identity + Discovery: Member 1 (scanner)
      - Classification: Member 2
    """

    # Identity
    id: str
    method: str
    path: str
    service_name: str

    # Discovery — Member 1
    sources: list = field(default_factory=list)
    in_repo: bool = False
    in_gateway: bool = False
    seen_in_traffic: bool = False
    auth_detected: bool = False
    auth_type: str = "none"
    status_codes: list = field(default_factory=list)
    last_seen: Optional[str] = None
    tags: list = field(default_factory=list)
    raw_context: str = ""
    also_found_in_conflict_with: Optional[str] = None

    # Classification — Member 2
    state: str = "unknown"
    owasp_flags: list = field(default_factory=list)
    risk_reason: str = ""


def create_endpoint(method, path, service_name, source, **kwargs):
    """
    Create a new APIEndpoint.
    Generates stable ID, sets source flags automatically.
    """
    method = method.upper()
    if not path.startswith("/"):
        path = "/" + path

    endpoint_id = hashlib.md5(
        f"{method}:{path}".encode()
    ).hexdigest()[:12]

    in_gateway = source in ("nginx_config", "kong_gateway")
    in_repo = source == "code_repository"
    seen_in_traffic = source == "network_traffic"

    return APIEndpoint(
        id=endpoint_id,
        method=method,
        path=path,
        service_name=service_name,
        sources=[source],
        in_gateway=in_gateway,
        in_repo=in_repo,
        seen_in_traffic=seen_in_traffic,
        **kwargs
    )


def merge_endpoint(existing, new_source):
    """
    Update an existing endpoint when found in a second source.
    Do NOT create a duplicate — update the existing record instead.
    """
    if new_source not in existing.sources:
        existing.sources.append(new_source)

    if new_source in ("nginx_config", "kong_gateway"):
        existing.in_gateway = True
    elif new_source == "code_repository":
        existing.in_repo = True
    elif new_source == "network_traffic":
        existing.seen_in_traffic = True

    return existing


def save_endpoints(endpoints, filepath):
    """Save a list of APIEndpoint objects to a JSON file."""
    import os
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    data = [asdict(ep) for ep in endpoints]
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[schema] Saved {len(endpoints)} endpoints → {filepath}")


def load_endpoints(filepath):
    """Load APIEndpoint objects from a JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [APIEndpoint(**ep) for ep in data]


def validate_endpoint(ep):
    """Check one endpoint for errors. Returns list of error strings."""
    errors = []

    if not ep.id or len(ep.id) != 12:
        errors.append(f"id must be 12 characters, got '{ep.id}'")
    if ep.method not in VALID_METHODS:
        errors.append(f"invalid method '{ep.method}'")
    if not ep.path.startswith("/"):
        errors.append(f"path must start with '/', got '{ep.path}'")
    if "?" in ep.path:
        errors.append(f"path must not contain query params")
    if not ep.sources:
        errors.append("sources list is empty")
    for s in ep.sources:
        if s not in VALID_SOURCES:
            errors.append(f"invalid source '{s}'")
    if ep.auth_type not in VALID_AUTH_TYPES:
        errors.append(f"invalid auth_type '{ep.auth_type}'")
    if ep.auth_detected and ep.auth_type == "none":
        errors.append("auth_detected is True but auth_type is 'none'")
    if not ep.auth_detected and ep.auth_type != "none":
        errors.append("auth_type is set but auth_detected is False")
    if ep.state not in VALID_STATES:
        errors.append(f"invalid state '{ep.state}'")
    for code in ep.status_codes:
        if not (100 <= code <= 599):
            errors.append(f"invalid HTTP status code: {code}")

    return errors


def validate_all(endpoints):
    """Validate a full list. Prints errors. Returns True if all valid."""
    all_valid = True
    for ep in endpoints:
        errors = validate_endpoint(ep)
        if errors:
            all_valid = False
            print(f"\n[INVALID] {ep.method} {ep.path}")
            for e in errors:
                print(f"  - {e}")
    if all_valid:
        print(f"[schema] All {len(endpoints)} endpoints valid.")
    return all_valid


if __name__ == "__main__":
    ep = create_endpoint(
        method="GET",
        path="/api/v1/users",
        service_name="user-service",
        source="nginx_config",
        auth_detected=False,
        auth_type="none",
        tags=["nginx", "internal"],
        raw_context="location /api/v1/users { proxy_pass http://user-service; }"
    )
    print(json.dumps(asdict(ep), indent=2))
    merge_endpoint(ep, "code_repository")
    print(f"\nsources: {ep.sources}")
    errors = validate_endpoint(ep)
    print("Valid!" if not errors else f"Errors: {errors}")
