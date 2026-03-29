"""
ast_parser.py — Python AST Route Parser
Walks Python source files and extracts FastAPI/Flask route definitions.
"""

import ast
import os
import sys
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from scanner.schema import create_endpoint, validate_endpoint


def parse_python_routes(directory):
    """
    Walk a directory, find all .py files,
    extract FastAPI/Flask route definitions from each one.
    Returns a list of APIEndpoint objects.
    """
    results = []
    directory = Path(directory)

    for py_file in directory.rglob("*.py"):
        if py_file.name == "__init__.py":
            continue
        # Don't scan our own scanner files
        if "scanner" in str(py_file) or "backend" in str(py_file):
            continue

        try:
            with open(py_file, "r", encoding="utf-8") as f:
                source = f.read()

            tree = ast.parse(source)
            file_routes = extract_routes(tree, str(py_file))
            results.extend(file_routes)

        except SyntaxError:
            print(f"  [ast_parser] Skipping {py_file} — syntax error")
            continue
        except UnicodeDecodeError:
            print(f"  [ast_parser] Skipping {py_file} — encoding error")
            continue

    return results


def extract_routes(tree, filepath):
    """Walk a parsed AST and find all route decorators."""
    routes = []
    filename = Path(filepath).stem

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue

        for decorator in node.decorator_list:
            route_info = get_route_from_decorator(decorator)
            if not route_info:
                continue

            path, method = route_info
            auth_detected, auth_type = check_auth_in_function(node)

            endpoint = create_endpoint(
                method=method,
                path=path,
                service_name=filename,
                source="code_repository",
                auth_detected=auth_detected,
                auth_type=auth_type,
                tags=["python", "fastapi"],
                raw_context=f"File: {filepath} | Function: {node.name}"
            )

            routes.append(endpoint)

    return routes


def get_route_from_decorator(decorator):
    """
    Check if a decorator is a FastAPI route.
    Returns (path, method) if yes, None if not.
    Handles @app.get("/path"), @router.post("/path") etc.
    """
    if not isinstance(decorator, ast.Call):
        return None

    func = decorator.func
    if not isinstance(func, ast.Attribute):
        return None

    method = func.attr.upper()
    valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH"}
    if method not in valid_methods:
        return None

    if not decorator.args:
        return None

    path_node = decorator.args[0]
    if not isinstance(path_node, ast.Constant):
        return None

    path = path_node.value
    if not isinstance(path, str):
        return None

    return (path, method)


def check_auth_in_function(func_node):
    """
    Check if a function uses authentication via its arguments.
    Returns (auth_detected: bool, auth_type: str)
    """
    auth_keywords = [
        "token", "auth", "credentials",
        "current_user", "oauth2_scheme",
        "api_key", "bearer", "jwt"
    ]

    for arg in func_node.args.args:
        if any(kw in arg.arg.lower() for kw in auth_keywords):
            return True, "unknown"

    for default in func_node.args.defaults:
        if isinstance(default, ast.Call):
            default_str = ast.dump(default).lower()
            if any(kw in default_str for kw in auth_keywords):
                return True, "unknown"

    return False, "none"


if __name__ == "__main__":
    print("Running AST parser test...\n")
    endpoints = parse_python_routes("test_files")
    print(f"Found {len(endpoints)} endpoints:\n")

    all_valid = True
    for ep in endpoints:
        errors = validate_endpoint(ep)
        if errors:
            all_valid = False
            print(f"INVALID: {ep.method} {ep.path} — {errors}")
        else:
            print(f"OK: {ep.method} {ep.path}")
            print(f"   auth: {ep.auth_detected} ({ep.auth_type})")
            print()

    if all_valid:
        from scanner.schema import save_endpoints
        save_endpoints(endpoints, "output/sample_ast_endpoints.json")
