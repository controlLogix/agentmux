#!/usr/bin/env python3
"""Preview a Claude Code permission rule for this checkout.

Run with no arguments (or --check) to preview. Only the operator should apply
this permission: rerun with --apply followed by the exact displayed rule.
Existing settings and a private backup are preserved. No client is launched.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile

from taskmgmt.provider_setup import SetupError, read_json, read_local, write_local


def permission_rule(repo: Path) -> str:
    repo = repo.resolve(strict=True)
    launcher = repo / "agentmux.sh"
    if launcher.is_symlink() or not launcher.is_file():
        raise SetupError("the checkout has no regular agentmux.sh launcher")
    if not re.fullmatch(r"[A-Za-z0-9_./ -]+", str(launcher)):
        raise SetupError("checkout path cannot be represented by an exact permission rule")
    return f"Bash(bash {shlex.quote(str(launcher))}:*)"


def proposed_settings(original: bytes, rule: str) -> tuple[bytes, bool]:
    data = read_json(original)
    permissions = data.setdefault("permissions", {})
    if not isinstance(permissions, dict):
        raise SetupError("permissions must be an object; settings were preserved")
    allow = permissions.setdefault("allow", [])
    if not isinstance(allow, list) or any(not isinstance(item, str) for item in allow):
        raise SetupError("permissions.allow must be a string list; settings were preserved")
    if rule in allow:
        return original, False
    allow.append(rule)
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"), True


def update_permission(settings: Path, repo: Path, approved_rule: str | None = None) -> dict:
    rule = permission_rule(repo)
    if approved_rule is not None and approved_rule != rule:
        raise SetupError("approved rule does not exactly match this checkout; nothing was changed")
    original = read_local(settings, private=False)
    proposed, changed = proposed_settings(original, rule)
    result = {"rule": rule, "state": "present" if not changed else "preview", "backup": None}
    if approved_rule is None or not changed:
        return result
    # Create a new, private backup without overwriting any earlier backup.
    fd, backup = tempfile.mkstemp(prefix=f"{settings.name}.bak-", dir=settings.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(original)
            handle.flush()
            os.fsync(handle.fileno())
        write_local(settings, proposed, expected=original, private_existing=False)
    except BaseException:
        # Retain the original bytes even when replacement fails.
        raise
    result.update(state="applied", backup=Path(backup).name)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="preview only (the default)")
    parser.add_argument("--apply", metavar="EXACT_RULE", help="operator approval of the exact proposed rule")
    parser.add_argument("--settings", type=Path, help="explicit user settings file")
    args = parser.parse_args(argv)
    if args.check and args.apply is not None:
        parser.error("--check and --apply cannot be combined")
    settings = args.settings or Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "settings.json"
    try:
        result = update_permission(settings, Path(__file__).resolve().parent, args.apply)
    except (SetupError, OSError):
        print("Permission setup failed. Check the settings file, checkout path and exact rule; existing settings were preserved.", file=sys.stderr)
        return 1
    print("Proposed rule:", result["rule"])
    if result["state"] == "preview":
        print("Preview only. Review this rule, then apply it yourself with:")
        print("  python3", shlex.quote(str(Path(__file__).resolve())), "--apply", shlex.quote(result["rule"]), "--settings", shlex.quote(str(settings)))
    elif result["state"] == "applied":
        print("Applied the exact approved rule. Private backup:", result["backup"])
    else:
        print("The exact rule is already present. No file was changed.")
    print("Client permission matching has not been qualified by this offline check.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
