"""
nginx_parser.py — Nginx Config Parser
Reads Nginx config files and extracts all location blocks as API endpoints.
"""

import re
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from scanner.schema import create_endpoint, validate_endpoint


def parse_nginx_config(filepath):
    """
    Read an Nginx config file and return a list of APIEndpoint objects.
    One endpoint per location block found.
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    pattern = r'location\s+([^\s{]+)\s*\{([^}]+)\}'
    matches = re.finditer(pattern, content, re.DOTALL)

    results = []

    for match in matches:
        path = match.group(1).strip()
        block = match.group(2).strip()

        auth_detected, auth_type = detect_auth(block)
        service_name = extract_service_name(block)

        endpoint = create_endpoint(
            method="ANY",
            path=path,
            service_name=service_name,
            source="nginx_config",
            auth_detected=auth_detected,
            auth_type=auth_type,
            tags=["nginx"],
            raw_context=block[:300]
        )

        results.append(endpoint)

    return results


def detect_auth(block_content):
    """
    Look for auth-related keywords inside a location block.
    Returns (auth_detected: bool, auth_type: str)
    """
    block_lower = block_content.lower()

    if 'auth_jwt' in block_lower or 'auth_bearer' in block_lower:
        return True, "jwt"
    if 'auth_basic' in block_lower:
        return True, "basic"
    if 'auth_request' in block_lower:
        return True, "unknown"
    if 'proxy_set_header authorization' in block_lower:
        return True, "unknown"

    return False, "none"


def extract_service_name(block_content):
    """
    Pull the service name from a proxy_pass line.
    e.g. proxy_pass http://user-service:8000 → user-service
    """
    match = re.search(r'proxy_pass\s+https?://([^:/;\s]+)', block_content)
    if match:
        return match.group(1)
    return "unknown"


if __name__ == "__main__":
    from dataclasses import asdict
    import json

    print("Running Nginx parser test...\n")
    endpoints = parse_nginx_config("test_files/test_nginx.conf")
    print(f"Found {len(endpoints)} endpoints:\n")

    for ep in endpoints:
        errors = validate_endpoint(ep)
        if errors:
            print(f"INVALID: {ep.method} {ep.path} — {errors}")
        else:
            print(f"OK: {ep.method} {ep.path}")
            print(f"   auth: {ep.auth_detected} ({ep.auth_type})")
            print(f"   service: {ep.service_name}")
            print()

    from scanner.schema import save_endpoints
    save_endpoints(endpoints, "output/sample_nginx_endpoints.json")
