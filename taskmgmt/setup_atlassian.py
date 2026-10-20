#!/usr/bin/env python3
"""Interactive, non-echoing setup for ~/.agentmux/atlassian.json.

Run this IN YOUR OWN TERMINAL, not through an agent:

    python3 taskmgmt/setup_atlassian.py

The API token is read with getpass, so it is never echoed, never becomes a
command argument (so it cannot land in shell history or `ps`), and the file is
written 0600 under a 077 umask so it is never briefly world-readable.

Cloud needs an API token from https://id.atlassian.com/manage-profile/security/api-tokens
Server/DC needs a Personal Access Token instead, and no email.
"""

from __future__ import annotations

import getpass
import json
import os
import pathlib
import stat
import sys
import tempfile
import warnings

try:
    from taskmgmt.atlassian import AtlassianError, validate_config
except ModuleNotFoundError:
    from atlassian import AtlassianError, validate_config

# AGENTMUX_HOME, like every sibling module. This file resolved the home directly
# from $HOME, so an isolated run still read and wrote the operator's real one.
CONFIG = pathlib.Path(
    os.environ.get("AGENTMUX_HOME") or pathlib.Path.home() / ".agentmux"
) / "atlassian.json"


def ask(label: str, default: str = "", required: bool = True) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"  {label}{suffix}: ").strip() or default
        if value or not required:
            return value
        print("    required.")


def main() -> int:
    print(__doc__)

    original = None
    existing = {}
    if os.path.lexists(CONFIG):
        # Never follow a link to another owner's configuration, including a
        # dangling link. Read only this small setup document before confirmation.
        try:
            fd = os.open(CONFIG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as fh:
                info = os.fstat(fh.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != os.getuid()):
                    raise ValueError
                original = fh.read(65537)
            if len(original) > 65536:
                raise ValueError
            existing = json.loads(original)
            if not isinstance(existing, dict):
                raise ValueError
        except (OSError, ValueError):
            print("  Existing configuration could not be safely read. Left unchanged; inspect it in your terminal.")
            return 1
        print(f"  {CONFIG} already exists.")
        print("  This updates the setup fields and keeps unrelated keys. Finish other edits to this file before continuing.")
        if ask("overwrite? (yes/no)", "no").lower() not in ("y", "yes"):
            print("  left unchanged.")
            return 0

    def prior(key, default=""):
        value = existing.get(key)
        return value if isinstance(value, str) and not any(ord(c) < 32 or ord(c) == 127 for c in value) else default

    previous_deployment = prior("deployment", "cloud")
    if previous_deployment not in ("cloud", "server"):
        previous_deployment = "cloud"
    previous_url = prior("base_url")
    if previous_url:
        try:
            validate_config({"deployment": "server", "base_url": previous_url,
                             "api_token": "validation-only"})
        except AtlassianError:
            # Do not display a malformed saved URL that may contain credentials.
            previous_url = ""

    deployment = ""
    while deployment not in ("cloud", "server"):
        deployment = ask("deployment (cloud|server)", previous_deployment).lower()

    while True:
        base_url = ask("base_url (e.g. https://yourorg.atlassian.net)", previous_url).rstrip("/")
        try:
            validate_config({"deployment": "server", "base_url": base_url, "api_token": "validation-only"})
            break
        except AtlassianError:
            print("    use an HTTPS site URL without credentials, query or fragment")

    email = ask("email (Atlassian account)", prior("email")) if deployment == "cloud" else prior("email")

    token = ""
    while not token:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                token = getpass.getpass("  api_token (not echoed): ").strip()
        except getpass.GetPassWarning:
            print("  Secret input needs a terminal that can disable echo. Nothing was written.")
            return 1
        if not token:
            print("    required.")

    def optional(key, label, fallback="", uppercase=False):
        previous = prior(key, fallback)
        value = ask(label + " (blank keeps it; - clears it)", previous, required=False)
        if value == "-":
            return ""
        return value.upper() if uppercase and value != previous else value

    jira_project = optional("jira_project", "jira_project key", uppercase=True)
    confluence_space = optional("confluence_space", "confluence_space key")
    done_transition = optional("done_transition", "done transition name/regex",
                               "done|closed|complete|resolve")

    # Replace fields owned by this setup form, retaining unrelated extensions.
    owned = {"deployment", "base_url", "api_token", "email", "jira_project",
             "confluence_space", "done_transition"}
    cfg = {key: value for key, value in existing.items() if key not in owned}
    cfg.update(deployment=deployment, base_url=base_url, api_token=token)
    if email:
        cfg["email"] = email
    if jira_project:
        cfg["jira_project"] = jira_project
    if confluence_space:
        cfg["confluence_space"] = confluence_space
    if done_transition:
        cfg["done_transition"] = done_transition

    try:
        cfg = validate_config(cfg)
    except AtlassianError as error:
        print(f"  {error}. Nothing was written.")
        return 1

    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    old_umask = os.umask(0o077)
    try:
        # Write via a temp file in the same directory, then rename: a reader can
        # never see a partial credential file, and the mode is right from creation.
        handle, temporary = tempfile.mkstemp(dir=CONFIG.parent, prefix=f".{CONFIG.name}.")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                json.dump(cfg, fh, indent=2)
                fh.write("\n")
            if original is None:
                # A configuration created while prompts were open belongs to
                # its writer. Publish atomically only if the name is still free.
                try:
                    os.link(temporary, CONFIG)
                except FileExistsError:
                    print("  Configuration appeared during setup. Left unchanged; run setup again to review it.")
                    return 1
            else:
                # Detect edits made during the prompts. Replacement remains the
                # explicitly confirmed operation; concurrent external writers
                # must finish before this interactive update is used.
                try:
                    fd = os.open(CONFIG, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd, "rb") as fh:
                        info = os.fstat(fh.fileno())
                        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                                or info.st_uid != os.getuid()):
                            raise ValueError
                        current = fh.read(65537)
                    if current != original:
                        raise ValueError
                except (OSError, ValueError):
                    print("  Configuration changed during setup. Left unchanged; run setup again to review it.")
                    return 1
                os.replace(temporary, CONFIG)
        finally:
            # Remove only the file created by this call, including after a failed
            # write or replacement. A successful replacement already moved it.
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    finally:
        os.umask(old_umask)

    mode = stat.S_IMODE(CONFIG.stat().st_mode)
    print(f"\n  wrote {CONFIG} (mode {mode:o})")
    if mode != 0o600:
        print(f"  WARNING: expected 600. Run: chmod 600 {CONFIG}")

    print("\n  Verify with:")
    print(f"    python3 {pathlib.Path(__file__).parent / 'task.py'} whoami")
    print("  Dry-run anything first, e.g.:")
    print(f"    python3 {pathlib.Path(__file__).parent / 'task.py'} --dry-run "
          f"create --summary 'test'")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n  aborted; nothing written.")
        raise SystemExit(130)
