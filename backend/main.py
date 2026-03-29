"""
backend/main.py — SPECTRE Discovery Engine API
================================================
FastAPI backend that runs your real Python scanner.
Deployed to Render (free tier).

GET  /ping          → wake-up check
POST /scan/sample   → runs real parsers on bundled test files
POST /scan/upload   → runs real parsers on user-uploaded files
"""

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dataclasses import asdict
from pathlib import Path
from typing import Optional
import tempfile
import shutil
import json
import sys
import os

# Add root to path so we can import scanner modules
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from scanner.parsers.nginx_parser import parse_nginx_config
from scanner.parsers.kong_parser import parse_kong_config
from scanner.parsers.ast_parser import parse_python_routes
from scanner.schema import merge_endpoint

app = FastAPI(
    title="SPECTRE Discovery Engine",
    description="Finds every API endpoint — including shadow APIs",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths to bundled sample files
SAMPLE_DIR   = ROOT / "test_files"
SAMPLE_NGINX = SAMPLE_DIR / "test_nginx.conf"
SAMPLE_KONG  = SAMPLE_DIR / "test_kong.yml"
SAMPLE_PY    = SAMPLE_DIR

# The planted shadow API — only visible in traffic, not in any config or code
SHADOW_ENDPOINT = {
    "id": "a9f3c2d11e4b",
    "method": "GET",
    "path": "/api/v2/internal/users",
    "service_name": "shadow-service",
    "sources": ["network_traffic"],
    "in_repo": False,
    "in_gateway": False,
    "seen_in_traffic": True,
    "auth_detected": False,
    "auth_type": "none",
    "status_codes": [200],
    "last_seen": "2025-03-17T10:22:41Z",
    "tags": ["traffic"],
    "raw_context": "Observed at shadow-service — not in any config or codebase",
    "also_found_in_conflict_with": None,
    "state": "shadow",
    "owasp_flags": ["API2", "API9"],
    "risk_reason": "Endpoint observed in traffic only — not registered in any gateway or codebase."
}


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def merge_into(existing: dict, new_eps: list, source: str) -> int:
    new_count = 0
    for ep in new_eps:
        if ep.id not in existing:
            existing[ep.id] = ep
            new_count += 1
        else:
            merge_endpoint(existing[ep.id], source)
    return new_count


def build_response(all_endpoints: dict, traffic_eps: list = None) -> dict:
    """
    Convert merged endpoints to a clean JSON response.
    Applies basic classification rules so state is meaningful.
    """
    result = []

    for ep in all_endpoints.values():
        d = asdict(ep)

        # Basic classification logic
        # (Full classifier lives in Member 2's module — this is a preview)
        if d["seen_in_traffic"] and not d["in_gateway"] and not d["in_repo"]:
            d["state"] = "shadow"
            d["owasp_flags"] = ["API2", "API9"]
            d["risk_reason"] = "Endpoint in traffic only — not registered anywhere."
        elif d["in_gateway"] or d["in_repo"]:
            if not d["auth_detected"]:
                d["owasp_flags"] = ["API2"]
                d["risk_reason"] = "No authentication detected on this endpoint."
            d["state"] = "active"

        result.append(d)

    # Add traffic-only endpoints (shadow APIs)
    if traffic_eps:
        result.extend(traffic_eps)

    total = len(result)
    shadows = sum(1 for e in result if e.get("state") == "shadow")
    no_auth = sum(1 for e in result if not e.get("auth_detected"))
    sources_seen = set()
    for e in result:
        sources_seen.update(e.get("sources", []))

    return {
        "total": total,
        "shadow_count": shadows,
        "no_auth_count": no_auth,
        "sources_scanned": len(sources_seen),
        "endpoints": result
    }


# ─────────────────────────────────────────────
# GET /ping — wake-up check
# ─────────────────────────────────────────────

@app.get("/ping")
def ping():
    return {"status": "ok", "service": "SPECTRE Discovery Engine"}


# ─────────────────────────────────────────────
# POST /scan/sample — run on bundled test files
# ─────────────────────────────────────────────

@app.post("/scan/sample")
def scan_sample():
    """
    Run the real parsers on the bundled test files.
    This is what 99% of users will hit.
    """
    all_endpoints = {}
    errors = []

    try:
        if SAMPLE_NGINX.exists():
            eps = parse_nginx_config(str(SAMPLE_NGINX))
            merge_into(all_endpoints, eps, "nginx_config")
    except Exception as e:
        errors.append(f"Nginx parser: {str(e)}")

    try:
        if SAMPLE_KONG.exists():
            eps = parse_kong_config(str(SAMPLE_KONG))
            merge_into(all_endpoints, eps, "kong_gateway")
    except Exception as e:
        errors.append(f"Kong parser: {str(e)}")

    try:
        if SAMPLE_PY.exists():
            eps = parse_python_routes(str(SAMPLE_PY))
            merge_into(all_endpoints, eps, "code_repository")
    except Exception as e:
        errors.append(f"AST parser: {str(e)}")

    response = build_response(all_endpoints, [SHADOW_ENDPOINT])
    if errors:
        response["warnings"] = errors

    return JSONResponse(response)


# ─────────────────────────────────────────────
# POST /scan/upload — run on user-uploaded files
# ─────────────────────────────────────────────

@app.post("/scan/upload")
async def scan_upload(
    nginx:   Optional[UploadFile] = File(None),
    kong:    Optional[UploadFile] = File(None),
    py:      Optional[UploadFile] = File(None),
    traffic: Optional[UploadFile] = File(None),
):
    """
    Accept uploaded files from the user and run the real parsers on them.
    Falls back to sample file for any source not uploaded.
    """
    all_endpoints = {}
    errors = []
    tmpdir = tempfile.mkdtemp()

    try:
        # ── Nginx ──────────────────────────────
        if nginx and nginx.filename:
            try:
                nginx_path = os.path.join(tmpdir, "nginx.conf")
                with open(nginx_path, "wb") as f:
                    f.write(await nginx.read())
                eps = parse_nginx_config(nginx_path)
                merge_into(all_endpoints, eps, "nginx_config")
            except Exception as e:
                errors.append(f"Nginx parse failed: {str(e)}")
        else:
            # Fall back to sample
            try:
                eps = parse_nginx_config(str(SAMPLE_NGINX))
                merge_into(all_endpoints, eps, "nginx_config")
            except Exception:
                pass

        # ── Kong ───────────────────────────────
        if kong and kong.filename:
            try:
                kong_path = os.path.join(tmpdir, "kong.yml")
                with open(kong_path, "wb") as f:
                    f.write(await kong.read())
                eps = parse_kong_config(kong_path)
                merge_into(all_endpoints, eps, "kong_gateway")
            except Exception as e:
                errors.append(f"Kong parse failed: {str(e)}")
        else:
            try:
                eps = parse_kong_config(str(SAMPLE_KONG))
                merge_into(all_endpoints, eps, "kong_gateway")
            except Exception:
                pass

        # ── Python file ────────────────────────
        if py and py.filename:
            try:
                py_dir = os.path.join(tmpdir, "pyfiles")
                os.makedirs(py_dir, exist_ok=True)
                py_path = os.path.join(py_dir, py.filename)
                with open(py_path, "wb") as f:
                    f.write(await py.read())
                eps = parse_python_routes(py_dir)
                merge_into(all_endpoints, eps, "code_repository")
            except Exception as e:
                errors.append(f"AST parse failed: {str(e)}")

        # ── Traffic log ────────────────────────
        traffic_eps = []
        if traffic and traffic.filename:
            try:
                content = await traffic.read()
                traffic_data = json.loads(content)
                if isinstance(traffic_data, dict):
                    traffic_eps = list(traffic_data.values())
                elif isinstance(traffic_data, list):
                    traffic_eps = traffic_data
            except Exception as e:
                errors.append(f"Traffic log parse failed: {str(e)}")

        response = build_response(all_endpoints, traffic_eps)
        if errors:
            response["warnings"] = errors

        return JSONResponse(response)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
