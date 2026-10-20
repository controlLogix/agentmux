#!/usr/bin/env python3
"""Configure agentmux authentication without echoing credentials or passing them as arguments.

    python3 taskmgmt/setup_auth.py --list
    python3 taskmgmt/setup_auth.py --provider vertex      # shared: project + region
    python3 taskmgmt/setup_auth.py codex-custom           # method: gateway + model
    python3 taskmgmt/setup_auth.py --verify codex-custom
    python3 taskmgmt/setup_auth.py --select codex-custom

TWO LEVELS, and the split is the point
--------------------------------------
A region or an API key belongs to a PROVIDER, not to each CLI that uses it, so
a provider is configured once and every CLI on it inherits the value. Only what
is genuinely method-specific - a model id, and for codex a gateway URL - is stored
per method, namespaced by method id.

An earlier version stored everything flat, so two methods sharing one provider both
wrote a bare `model` key and each silently clobbered the other.

WHERE THINGS GO
---------------
  $AGENTMUX_HOME/auth.json  0600  non-secret settings and the active method per CLI:
                                  { active: {}, providers: {}, methods: {} }
  $AGENTMUX_HOME/env        0600  secret environment exports only.
                                  ($AGENTMUX_HOME defaults to ~/.agentmux.)

Separate files because the dashboard may READ and display the first and must never
touch the second. agentmux SOURCES the env file into each pane rather than
interpolating it into the tmux command, so a key never lands in `ps`, in
`pane_start_command`, or in shell history.

Setup parses literal env assignments without sourcing them. Secrets require a
non-echoing terminal and are never printed back. Default checks make no model call.
"""

import argparse
import importlib.util
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

try:
    from taskmgmt import provider_setup
except ModuleNotFoundError as error:
    if error.name != "taskmgmt":
        raise
    # The dashboard loads this file by path, so its import path need not contain
    # either the repository root or taskmgmt. Resolve this sibling explicitly.
    helper_spec = importlib.util.spec_from_file_location(
        "_agentmux_provider_setup", Path(__file__).with_name("provider_setup.py"))
    provider_setup = importlib.util.module_from_spec(helper_spec)
    sys.modules[helper_spec.name] = provider_setup
    helper_spec.loader.exec_module(provider_setup)

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "dashboard" / "auth.json"
# AGENTMUX_HOME, like every sibling module. This file resolved the home directly
# from $HOME, so an isolated run still read and wrote the operator's real one.
ROOT = Path(os.environ.get("AGENTMUX_HOME") or Path.home() / ".agentmux")
SETTINGS = ROOT / "auth.json"
ENV_FILE = ROOT / "env"

class EndpointValidator:
    """Share syntax and host/port validation with the dashboard's match caller."""

    shape = re.compile(r"https?://[A-Za-z0-9._:\[\]-]+(/[A-Za-z0-9._~/-]*)?\Z")

    def match(self, value):
        if not isinstance(value, str) or len(value) > 300:
            return None
        matched = self.shape.fullmatch(value)
        if not matched:
            return None
        try:
            endpoint = urlsplit(value)
            host = endpoint.hostname
            if not host or endpoint.port == 0:
                return None
            if ":" in host or re.fullmatch(r"[0-9.]+", host):
                ipaddress.ip_address(host)
            elif any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                     for label in host.rstrip(".").split(".")):
                return None
        except ValueError:
            return None
        return matched

    fullmatch = match


# Validators named by settings[].validate in the manifest.
VALIDATORS = {
    "base_url": (
        EndpointValidator(),
        "must be an http(s) URL with a valid host and port, no query string or credentials",
    ),
    "gcp_region": (re.compile(r"[a-z]{2}(-[a-z]+)+[0-9]\Z"), "must look like us-east5"),
    "gcp_project": (re.compile(r"[a-z][a-z0-9-]{4,62}\Z"),
                    "lowercase letters, digits and dashes"),
    "model": (re.compile(r"[A-Za-z0-9][A-Za-z0-9._:\[\]/-]{0,200}\Z"),
              "letters, digits and . _ : / - [ ] only"),
    "text": (re.compile(r"[^\x00-\x1f]{1,300}\Z"), "no control characters"),
}
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")


def die(message):
    sys.exit(f"setup_auth: {message}")


class Manifest:
    def __init__(self):
        try:
            with MANIFEST.open(encoding="utf-8") as fh:
                data = json.load(fh)
        except OSError as err:
            die(f"cannot read {MANIFEST}: {err}")
        except ValueError as err:
            die(f"{MANIFEST} is not valid JSON: {err}")
        self.providers = {p["id"]: p for p in data.get("providers", [])
                          if isinstance(p, dict) and p.get("id")}
        self.methods = {m["id"]: m for m in data.get("methods", [])
                        if isinstance(m, dict) and m.get("id")}
        if not self.providers or not self.methods:
            die("auth.json declares no providers or no methods")
        for method in self.methods.values():
            if method.get("provider") not in self.providers:
                die(f"method {method['id']} names an unknown provider "
                    f"{method.get('provider')!r}")
        self.credential_references = {}
        for provider_id, provider in self.providers.items():
            secrets = provider.get("secrets", [])
            references = provider.get("credential_references", [])
            if (not isinstance(secrets, list) or any(not isinstance(name, str) for name in secrets)
                    or len(secrets) != len(set(secrets)) or not isinstance(references, list)):
                die(f"provider {provider_id} has invalid credential declarations")
            declared = {}
            for raw in references:
                if not isinstance(raw, dict) or set(raw) != {"kind", "provider", "name"}:
                    die(f"provider {provider_id} has an invalid credential reference")
                try:
                    reference = provider_setup.LocalSecretReference(**raw)
                except (TypeError, provider_setup.SetupError):
                    die(f"provider {provider_id} has an unsupported credential reference")
                if reference.provider != provider_id or reference.name in declared:
                    die(f"provider {provider_id} has a mismatched credential reference")
                declared[reference.name] = reference
            if set(declared) != set(secrets):
                die(f"provider {provider_id} must declare one credential reference per secret")
            self.credential_references.update(
                ((provider_id, name), reference) for name, reference in declared.items())

    def provider_of(self, method_id):
        return self.providers[self.methods[method_id]["provider"]]

    def credential_reference(self, provider_id, name):
        try:
            return self.credential_references[(provider_id, name)]
        except KeyError:
            die(f"provider {provider_id} does not declare a credential reference for {name}")


class SettingsDocument(dict):
    """Keep the original bytes so setup can refuse a concurrent settings change."""

    def __init__(self, data, original):
        super().__init__(data)
        self.original = original


def load_settings():
    try:
        original = provider_setup.read_local(SETTINGS, missing=True)
        data = provider_setup.read_json(original) if original is not None else {
            "version": 2, "active": {}, "providers": {}, "methods": {}}
    except provider_setup.SetupError as error:
        die(str(error))
    if data.get("version", 1) not in (1, 2):
        die("settings use an unsupported version; the file was preserved")
    for key in ("active", "providers", "methods"):
        if not isinstance(data.setdefault(key, {}), dict):
            die("settings contain an invalid section; the file was preserved")
    if any(not isinstance(value, str) for value in data["active"].values()):
        die("active method settings are invalid; the file was preserved")
    for key in ("providers", "methods"):
        if any(not isinstance(value, dict) for value in data[key].values()):
            die("provider or method settings are invalid; the file was preserved")
    if "settings" in data and data.get("version") != 2:
        if "_v1_settings" not in data:
            data["_v1_settings"] = data.pop("settings")
        # If both legacy fields already exist, retain both, including conflicts.
        print("  Legacy settings were preserved. Confirm them under each provider or method.")
        data["version"] = 2
    return SettingsDocument(data, original)


def write_private(path, text):
    """Write an owned private file atomically without following symlinks."""
    try:
        original = provider_setup.read_local(path, missing=True)
        provider_setup.write_local(path, text.encode("utf-8"), expected=original)
    except provider_setup.SetupError as error:
        die(str(error))


def save_settings(data):
    try:
        original = data.original if isinstance(data, SettingsDocument) else provider_setup.read_local(SETTINGS, missing=True)
        content = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
        provider_setup.write_local(SETTINGS, content, expected=original)
        if isinstance(data, SettingsDocument):
            data.original = content
    except provider_setup.SetupError as error:
        die(str(error))
    print("  saved private authentication settings (0600)")


def read_env_names_and_lines():
    """Return literal values locally; callers may print only the variable names."""
    try:
        content = provider_setup.read_local(ENV_FILE, missing=True)
        entries = provider_setup.env_values(content or b"")
    except provider_setup.SetupError as error:
        die(str(error))
    return {name for name, value in entries.items() if value.strip()}, entries


def save_env(entries):
    """Merge explicitly changed entries into the current private env file."""
    try:
        original = provider_setup.read_local(ENV_FILE, missing=True)
        current = provider_setup.env_values(original or b"")
        changes = {name: value for name, value in entries.items() if current.get(name) != value}
        content = provider_setup.replace_env_values(original or b"", changes)
        provider_setup.write_local(ENV_FILE, content, expected=original)
    except provider_setup.SetupError as error:
        die(str(error))
    print("  saved private credential entries (0600); values are not shown")


def save_credentials(entries):
    """Store values selected through exact typed references."""
    replacements = {}
    for reference, value in entries.items():
        if not isinstance(reference, provider_setup.LocalSecretReference):
            die("a typed local credential reference is required")
        replacements[reference.name] = value
    save_env(replacements)


def shell_quote(value):
    return provider_setup.shell_quote(value)


def ask_setting(spec):
    key = spec["key"]
    pattern, hint = VALIDATORS.get(spec.get("validate", "text"), VALIDATORS["text"])
    label = spec.get("label", key)
    example = f" (e.g. {spec['example']})" if spec.get("example") else ""
    while True:
        value = input(f"  {label}{example}: ").strip()
        if pattern.match(value):
            return value
        print(f"    rejected: {hint}")


def ask_secret(name):
    try:
        return provider_setup.prompt_secret(name)
    except provider_setup.SetupError as error:
        die(str(error))


def collect(specs, store, label):
    """Prompt for any of `specs` not already in `store`. Returns True if changed."""
    changed = False
    for spec in specs:
        key = spec["key"]
        if key in store:
            valid = valid_setting(spec, store[key])
            print(f"  {label} {key}: {'already set' if valid else 'saved value is invalid'}")
            if valid and input("  keep it? [Y/n] ").strip().lower() in ("", "y", "yes"):
                continue
        store[key] = ask_setting(spec)
        changed = True
    return changed


def codex_home():
    return Path(os.environ.get("CODEX_HOME") or (Path.home() / ".codex"))


def require_new_codex_profile(method):
    path = codex_home() / f"{method['id']}.config.toml"
    if os.path.lexists(path):
        die("Codex profile already exists; it was preserved. Review and back up "
            "the existing profile in your terminal before choosing a new setup.")
    return path


def write_codex_profile(method, method_values):
    """Create the legacy custom-provider profile without replacing native files.

    Native client acceptance must be checked separately; writing TOML does not
    establish that the installed client supports this profile format.
    """
    for setting in method.get("settings", []):
        value = method_values.get(setting["key"])
        pattern = VALIDATORS.get(setting.get("validate", "text"), VALIDATORS["text"])[0]
        if not isinstance(value, str) or not pattern.fullmatch(value):
            die("profile settings are missing or invalid; existing files were preserved")
    spec = method["codex_profile"]
    provider = spec["provider_id"]
    path = require_new_codex_profile(method)
    text = f'''# Generated by agentmux: taskmgmt/setup_auth.py {method['id']}
# Existing profiles are preserved. Review changes in your own terminal.
#
# This profile requests the OpenAI Responses API. The endpoint must support it.
# Check profile compatibility with the installed client in your own terminal.
#
# No credential appears in this file. env_key names an environment variable that
# agentmux sources from ~/.agentmux/env (0600) into the pane.

model_provider = "{provider}"
model = "{method_values[spec['model_from']]}"

[model_providers.{provider}]
name = "{spec['provider_name']}"
base_url = "{method_values[spec['base_url_from']]}"
wire_api = "{spec['wire_api']}"
env_key = "{spec['env_key']}"
'''
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            fh.write(text)
        try:
            # Publish the complete file only if the destination is still absent.
            os.link(temporary, path)
        except FileExistsError:
            die("Codex profile appeared during setup; it was preserved. "
                "Review it in your terminal before retrying.")
    finally:
        os.unlink(temporary)
    print(f"  wrote {path}")


def missing_for(manifest, method_id, settings, env_names):
    method = manifest.methods[method_id]
    provider = manifest.provider_of(method_id)
    gaps = []
    provider_values = settings["providers"].get(provider["id"], {})
    for spec in provider.get("settings", []):
        if spec["key"] not in provider_values:
            gaps.append(f"{provider['id']}.{spec['key']}")
        elif not valid_setting(spec, provider_values[spec["key"]]):
            gaps.append(f"{provider['id']}.{spec['key']} (invalid)")
    for name in provider.get("secrets", []):
        if name not in env_names:
            gaps.append(name)
    method_values = settings["methods"].get(method_id, {})
    for spec in method.get("settings", []):
        if spec["key"] not in method_values:
            gaps.append(f"{method_id}.{spec['key']}")
        elif not valid_setting(spec, method_values[spec["key"]]):
            gaps.append(f"{method_id}.{spec['key']} (invalid)")
    return gaps


def valid_setting(spec, value):
    pattern = VALIDATORS.get(spec.get("validate", "text"), VALIDATORS["text"])[0]
    return isinstance(value, str) and bool(pattern.fullmatch(value))


def configure_provider(provider_id, manifest):
    provider = manifest.providers[provider_id]
    print(f"Configuring provider {provider_id} — {provider.get('label', '')}")
    for note in provider.get("notes", []):
        print(f"  note: {note}")
    users = sorted(m["cli"] for m in manifest.methods.values()
                   if m["provider"] == provider_id)
    if users:
        print(f"  shared by: {', '.join(users)}")

    settings = load_settings()
    store = settings["providers"].setdefault(provider_id, {})
    collect(provider.get("settings", []), store, f"{provider_id}")

    secrets = provider.get("secrets", [])
    if secrets:
        env_names, _ = read_env_names_and_lines()
        changed_entries = {}
        for name in secrets:
            if not ENV_NAME.match(name):
                die(f"manifest declares an invalid env var name: {name}")
            if name in env_names:
                print(f"  {name} is already set")
                if input("  replace it? [y/N] ").strip().lower() not in ("y", "yes"):
                    continue
            reference = manifest.credential_reference(provider_id, name)
            changed_entries[reference] = ask_secret(name)
        if changed_entries:
            save_credentials(changed_entries)
    elif provider.get("kind") == "oauth":
        print("  nothing to store: the CLI owns this login.")
        for action in provider.get("setup", []):
            print(f"  run: {action['command']}")

    save_settings(settings)
    print(f"\nProvider {provider_id} configured. Methods that use it:")
    env_names, _ = read_env_names_and_lines()
    for method in manifest.methods.values():
        if method["provider"] != provider_id:
            continue
        gaps = missing_for(manifest, method["id"], settings, env_names)
        state = "local inputs set; client unverified" if not gaps else f"still needs {', '.join(gaps)}"
        print(f"  {method['id']:<20} {state}")
    return 0


def configure_method(method_id, manifest):
    method = manifest.methods[method_id]
    if "codex_profile" in method:
        # Refuse existing profiles before prompts or provider/settings writes.
        require_new_codex_profile(method)
    provider = manifest.provider_of(method_id)
    print(f"Configuring {method_id} — {method.get('label', '')}")
    print(f"  provider: {provider['id']} ({provider.get('label', '')})")
    for note in method.get("notes", []):
        print(f"  note: {note}")

    settings = load_settings()
    env_names, _ = read_env_names_and_lines()

    # Shared attributes are the provider's job. Point at it rather than asking here,
    # so the same region or key is never entered twice.
    provider_gaps = [
        g for g in missing_for(manifest, method_id, settings, env_names)
        if not g.startswith(f"{method_id}.")
    ]
    if provider_gaps:
        print(f"\n  Provider {provider['id']} is not configured yet "
              f"(missing {', '.join(provider_gaps)}).")
        print(f"  Configure it once for every CLI that uses it:")
        print(f"    python3 taskmgmt/setup_auth.py --provider {provider['id']}")
        if input("  do that now? [Y/n] ").strip().lower() in ("", "y", "yes"):
            configure_provider(provider["id"], manifest)
            settings = load_settings()
        else:
            print("  continuing; this method will report as not configured.")

    store = settings["methods"].setdefault(method_id, {})
    collect(method.get("settings", []), store, method_id)

    if "codex_profile" in method:
        spec = method["codex_profile"]
        needed = [spec["base_url_from"], spec["model_from"]]
        if all(k in store for k in needed):
            write_codex_profile(method, store)
        else:
            print(f"  skipping the codex profile: missing {', '.join(needed)}")

    settings["active"][method["cli"]] = method_id
    save_settings(settings)

    print()
    print(f"Active method for {method['cli']} is now {method_id}.")
    print(f"  agentmux spawn <name> --cli {method['cli']} --auth {method_id}")
    print(f"  (or omit --auth, since it is this CLI's default now)")
    return verify(method_id, manifest)


def verify(method_id, manifest):
    """Check local settings without starting a client or provider operation."""
    method = manifest.methods[method_id]
    settings = load_settings()
    env_names, _ = read_env_names_and_lines()
    problems = missing_for(manifest, method_id, settings, env_names)

    for name in manifest.provider_of(method_id).get("secrets", []):
        if name in env_names:
            print(f"  {name}: present (value not shown)")

    if "codex_profile" in method:
        path = codex_home() / f"{method_id}.config.toml"
        try:
            import tomllib
            handle = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(handle, "rb") as fh:
                if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                    raise ValueError("not a regular file")
                content = fh.read(65537)
                if len(content) > 65536:
                    raise ValueError("profile too large")
                tomllib.loads(content.decode("utf-8"))
            print("  profile TOML syntax is valid; native client acceptance was not checked")
        except ImportError:
            print("  UNKNOWN: TOML syntax check requires Python 3.11 or later")
        except (OSError, ValueError):
            problems.append("Codex profile is missing, unreadable, unsafe, too large or invalid TOML")

    if problems:
        for problem in problems:
            print(f"  MISSING: {problem}")
        return 1
    if "codex_profile" in method:
        print("  UNKNOWN: native Codex configuration and authentication were not checked. "
              "Use the installed client's supported checks in your terminal.")
        return 2
    print(f"  {method_id}: local inputs are present")
    print("  UNKNOWN: client selection and live authentication were not checked.")
    return 2


def select(method_id, manifest):
    settings = load_settings()
    env_names, _ = read_env_names_and_lines()
    gaps = missing_for(manifest, method_id, settings, env_names)
    if gaps:
        die(f"{method_id} is not configured (missing {', '.join(gaps)}). "
            f"Run: python3 taskmgmt/setup_auth.py {method_id}")
    settings["active"][manifest.methods[method_id]["cli"]] = method_id
    save_settings(settings)
    print(f"  active method for {manifest.methods[method_id]['cli']} is now {method_id}")
    return 0


def show_list(manifest):
    settings = load_settings()
    env_names, _ = read_env_names_and_lines()
    by_provider = {}
    for method in manifest.methods.values():
        by_provider.setdefault(method["provider"], []).append(method)

    for provider_id in sorted(by_provider):
        provider = manifest.providers[provider_id]
        shared = settings["providers"].get(provider_id, {})
        bits = [f"{spec['key']}={'set' if spec['key'] in shared else 'NOT SET'}"
                for spec in provider.get("settings", [])]
        bits += [f"{s}={'set' if s in env_names else 'NOT SET'}"
                 for s in provider.get("secrets", [])]
        print(f"\n{provider_id}  [{provider.get('label', '')}]"
              + (f"\n  shared: {', '.join(bits)}" if bits else ""))
        for method in sorted(by_provider[provider_id], key=lambda m: m["id"]):
            gaps = missing_for(manifest, method["id"], settings, env_names)
            marks = []
            if settings["active"].get(method["cli"]) == method["id"]:
                marks.append("ACTIVE")
            elif not settings["active"].get(method["cli"]) and method.get("default"):
                marks.append("cli default")
            marks.append("local inputs set; client unverified" if not gaps else f"needs {', '.join(gaps)}")
            print(f"    {method['id']:<20} {method['cli']:<7} [{', '.join(marks)}]")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Configure agentmux authentication (providers and methods).")
    parser.add_argument("method", nargs="?", help="method id from dashboard/auth.json")
    parser.add_argument("--provider", metavar="ID",
                        help="configure a provider's shared attributes (region, API key)")
    parser.add_argument("--list", action="store_true", help="show everything and its state")
    parser.add_argument("--verify", metavar="ID", help="check local inputs only; exit 2 means live support is unverified")
    parser.add_argument("--select", metavar="ID", help="make a configured method the default")
    args = parser.parse_args()

    manifest = Manifest()
    if args.list or not any((args.method, args.provider, args.verify, args.select)):
        show_list(manifest)
        return 0
    if args.provider:
        if args.provider not in manifest.providers:
            die(f"unknown provider: {args.provider}. Run --list.")
        return configure_provider(args.provider, manifest)
    for value in (args.verify, args.select, args.method):
        if value and value not in manifest.methods:
            die(f"unknown method: {value}. Run --list.")
    if args.verify:
        return verify(args.verify, manifest)
    if args.select:
        return select(args.select, manifest)
    return configure_method(args.method, manifest)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit("\nsetup_auth: cancelled; earlier completed setup changes remain saved")
    except OSError:
        sys.exit("setup_auth: local file operation failed; review the private setup files before retrying")
