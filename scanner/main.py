"""
main.py — SPECTRE Scanner Entry Point

Runs all parsers and combines output into one file:
    output/discovered_endpoints.json

Usage:
    python scanner/main.py
"""

import json
import os
import sys
from pathlib import Path
from dataclasses import asdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.schema import (
    save_endpoints,
    validate_all,
    merge_endpoint,
    APIEndpoint,
)
from scanner.parsers.nginx_parser import parse_nginx_config
from scanner.parsers.ast_parser import parse_python_routes
from scanner.parsers.kong_parser import parse_kong_config

SCAN_CONFIG = {
    "nginx_configs": ["test_files/test_nginx.conf"],
    "kong_configs":  ["test_files/test_kong.yml"],
    "python_repos":  ["test_files"],
    "traffic_log":   "output/traffic_log.json",
}

OUTPUT_FILE = "output/discovered_endpoints.json"


def run_scanner(config):
    all_endpoints = {}

    print("\n[scanner] Running Nginx parser...")
    for filepath in config.get("nginx_configs", []):
        if not Path(filepath).exists():
            print(f"  Skipping {filepath} — not found")
            continue
        eps = parse_nginx_config(filepath)
        count = merge_into(all_endpoints, eps, "nginx_config")
        print(f"  {filepath} → {len(eps)} found, {count} new")

    print("\n[scanner] Running Kong parser...")
    for filepath in config.get("kong_configs", []):
        if not Path(filepath).exists():
            print(f"  Skipping {filepath} — not found")
            continue
        eps = parse_kong_config(filepath)
        count = merge_into(all_endpoints, eps, "kong_gateway")
        print(f"  {filepath} → {len(eps)} found, {count} new")

    print("\n[scanner] Running AST parser...")
    for dirpath in config.get("python_repos", []):
        if not Path(dirpath).exists():
            print(f"  Skipping {dirpath} — not found")
            continue
        eps = parse_python_routes(dirpath)
        count = merge_into(all_endpoints, eps, "code_repository")
        print(f"  {dirpath} → {len(eps)} found, {count} new")

    print("\n[scanner] Loading traffic log...")
    traffic_log_path = config.get("traffic_log")
    if traffic_log_path and Path(traffic_log_path).exists():
        with open(traffic_log_path, "r", encoding="utf-8") as f:
            traffic_data = json.load(f)
        traffic_endpoints = [APIEndpoint(**ep) for ep in traffic_data.values()]
        count = merge_into(all_endpoints, traffic_endpoints, "network_traffic")
        print(f"  traffic_log.json → {len(traffic_endpoints)} observed, {count} new")
    else:
        print("  No traffic log found — skipping")

    final_list = list(all_endpoints.values())
    print(f"\n[scanner] Total unique endpoints: {len(final_list)}")
    print("\n[scanner] Validating...")
    valid = validate_all(final_list)
    if not valid:
        print("\n[scanner] WARNING: Fix errors before handing off to Member 2.")

    save_endpoints(final_list, OUTPUT_FILE)
    print(f"\n[scanner] Done → {OUTPUT_FILE}\n")
    return final_list


def merge_into(existing_dict, new_endpoints, source):
    new_count = 0
    for ep in new_endpoints:
        if ep.id not in existing_dict:
            existing_dict[ep.id] = ep
            new_count += 1
        else:
            merge_endpoint(existing_dict[ep.id], source)
    return new_count


if __name__ == "__main__":
    print("=" * 50)
    print("  SPECTRE — API Discovery Scanner")
    print("=" * 50)

    results = run_scanner(SCAN_CONFIG)

    print("\n[scanner] Summary by source:")
    source_counts = {}
    for ep in results:
        for s in ep.sources:
            source_counts[s] = source_counts.get(s, 0) + 1
    for source, count in sorted(source_counts.items()):
        print(f"  {source}: {count} endpoints")

    print("\n[scanner] Shadow APIs detected:")
    shadow_count = 0
    for ep in results:
        if ep.seen_in_traffic and not ep.in_gateway and not ep.in_repo:
            shadow_count += 1
            print(f"  !! {ep.method} {ep.path}")
    if shadow_count == 0:
        print("  None detected")
