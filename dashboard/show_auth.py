#!/usr/bin/env python3
"""Show declared authentication methods and presence flags from /api/auth.

Values and arbitrary server errors are never printed. This is an offline status
view; it does not establish client compatibility or live account access.
"""
import argparse
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        raise ValueError("status redirect refused")


def render_auth(data, manifest):
    if not isinstance(data, dict) or data.get("error"):
        raise ValueError("authentication status unavailable")
    source = data.get("providers", [])
    if not isinstance(source, list):
        raise ValueError("authentication status malformed")
    providers = {row.get("id"): row for row in source if isinstance(row, dict) and isinstance(row.get("id"), str)}
    methods = manifest["methods"]
    active = data.get("active") if isinstance(data.get("active"), dict) else {}
    lines = ["Authentication inputs (client and provider access remain unverified)"]
    for spec in manifest["providers"]:
        pid = spec["id"]
        row = providers.get(pid, {})
        lines.append(pid + (": local inputs set" if row.get("configured") is True else ": setup needed or unavailable"))
        settings = {item.get("key"): item for item in row.get("settings", []) if isinstance(item, dict) and isinstance(item.get("key"), str)}
        for setting in spec.get("settings", []):
            key = setting["key"]
            lines.append(f"  shared setting {key}: " + ("set" if settings.get(key, {}).get("set") is True else "not set"))
        secrets = {item.get("name"): item for item in row.get("secrets", []) if isinstance(item, dict) and isinstance(item.get("name"), str)}
        for name in spec.get("secrets", []):
            lines.append(f"  shared credential {name}: " + ("present" if secrets.get(name, {}).get("set") is True else "not set"))
        returned_methods = {item.get("id"): item for item in row.get("methods", []) if isinstance(item, dict) and isinstance(item.get("id"), str)}
        for method in methods:
            if method["provider"] != pid:
                continue
            mid = method["id"]
            configured = returned_methods.get(mid, {}).get("configured") is True
            selected = "; selected preference" if active.get(method["cli"]) == mid else ""
            own = ", ".join(item["key"] for item in method.get("settings", [])) or "none"
            lines.append(f"  {mid}: " + ("local inputs set" if configured else "setup needed or unavailable") + selected)
            lines.append(f"    method settings: {own}; live qualification pending")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8787, help="local dashboard port")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    try:
        manifest = json.loads(Path(__file__).with_name("auth.json").read_text())
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(f"http://127.0.0.1:{args.port}/api/auth", timeout=15) as response:
            body = response.read(65537)
            if len(body) > 65536:
                raise ValueError("status response too large")
            data = json.loads(body)
        print(render_auth(data, manifest))
    except (OSError, ValueError, TypeError, KeyError):
        print("Authentication status unavailable. Check the local dashboard; no status values were printed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
