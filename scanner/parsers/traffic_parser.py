"""
traffic_parser.py — mitmproxy Traffic Capture Script

HOW TO RUN:
    mitmdump -s scanner/parsers/traffic_parser.py --listen-port 8080

This script runs INSIDE mitmproxy. It is called automatically
for every HTTP request that flows through the proxy.

Output: output/traffic_log.json
"""

import json
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path

OUTPUT_FILE = "output/traffic_log.json"
IGNORE_PATHS = {"/health", "/favicon.ico", "/robots.txt", "/ping"}


def load_log():
    path = Path(OUTPUT_FILE)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}


def save_log(data):
    Path("output").mkdir(exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def request(flow):
    """Called by mitmproxy for every intercepted request."""
    method = flow.request.method
    path = flow.request.path

    if "?" in path:
        path = path.split("?")[0]

    if path in IGNORE_PATHS:
        return

    host = flow.request.pretty_host
    now = datetime.now(timezone.utc).isoformat()

    endpoint_id = hashlib.md5(
        f"{method}:{path}".encode()
    ).hexdigest()[:12]

    headers_lower = {k.lower(): v for k, v in flow.request.headers.items()}
    auth_detected = "authorization" in headers_lower
    if auth_detected:
        auth_header = headers_lower["authorization"].lower()
        if auth_header.startswith("bearer"):
            auth_type = "jwt"
        elif auth_header.startswith("basic"):
            auth_type = "basic"
        else:
            auth_type = "unknown"
    else:
        auth_type = "none"

    log = load_log()

    if endpoint_id not in log:
        log[endpoint_id] = {
            "id": endpoint_id,
            "method": method,
            "path": path,
            "service_name": host,
            "sources": ["network_traffic"],
            "in_repo": False,
            "in_gateway": False,
            "seen_in_traffic": True,
            "auth_detected": auth_detected,
            "auth_type": auth_type,
            "status_codes": [],
            "last_seen": now,
            "tags": ["traffic"],
            "raw_context": f"Observed at {host} on {now}",
            "also_found_in_conflict_with": None,
            "state": "unknown",
            "owasp_flags": [],
            "risk_reason": ""
        }
        print(f"[traffic] NEW endpoint: {method} {path}")
    else:
        log[endpoint_id]["last_seen"] = now
        print(f"[traffic] Updated: {method} {path}")

    save_log(log)


def response(flow):
    """Called by mitmproxy for every response — captures status codes."""
    method = flow.request.method
    path = flow.request.path
    if "?" in path:
        path = path.split("?")[0]
    if path in IGNORE_PATHS:
        return

    endpoint_id = hashlib.md5(f"{method}:{path}".encode()).hexdigest()[:12]
    status_code = flow.response.status_code
    log = load_log()

    if endpoint_id in log:
        codes = log[endpoint_id].get("status_codes", [])
        if status_code not in codes:
            codes.append(status_code)
            log[endpoint_id]["status_codes"] = codes
            save_log(log)
