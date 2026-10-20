"""Local credential storage and offline checks for legacy setup commands.

The exported env file remains compatible with existing launchers. This module
reads it as data and never evaluates shell syntax. LocalSecretReference is setup
metadata, not an admitted PluginContext capability. Owner integration must supply
its own admitted reference and must never send the resolved value in shared data.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import getpass
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import warnings

MAX_FILE_BYTES = 65536
ENV_ASSIGNMENT = re.compile(r"^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
PROVIDER_SECRETS = {
    "openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY",
    "xai": "XAI_API_KEY", "custom": "CODEX_CUSTOM_API_KEY",
}


class SetupError(ValueError):
    """A closed diagnostic that never includes file content or a credential."""


@dataclass(frozen=True)
class LocalSecretReference:
    provider: str
    name: str
    kind: str = "local_env"

    def __post_init__(self):
        if (not isinstance(self.provider, str) or not isinstance(self.name, str)
                or self.kind != "local_env" or PROVIDER_SECRETS.get(self.provider) != self.name):
            raise SetupError("unsupported local credential reference")


def private_root() -> Path:
    return Path(os.environ.get("AGENTMUX_HOME") or Path.home() / ".agentmux")


def read_local(path: Path, *, private: bool = True, missing: bool = False) -> bytes | None:
    """Read a bounded, owned regular file without following its final symlink."""
    try:
        parent = path.parent.lstat()
    except FileNotFoundError:
        if missing:
            return None
        raise SetupError("local directory is missing") from None
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) & 0o022):
        raise SetupError("local directory is not owned or permits writes by others")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if missing and not path.is_symlink():
            return None
        raise SetupError("local file is missing or unsafe") from None
    except OSError:
        raise SetupError("local file is unreadable or unsafe") from None
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or (private and stat.S_IMODE(info.st_mode) & 0o077)):
            raise SetupError("local file must be an owned regular file with private permissions")
        content = source.read(MAX_FILE_BYTES + 1)
        if len(content) > MAX_FILE_BYTES:
            raise SetupError("local file exceeds the size limit")
        return content


def decode_text(content: bytes) -> str:
    try:
        return content.decode("utf-8")
    except UnicodeError:
        raise SetupError("local file is not valid UTF-8") from None


def read_json(content: bytes) -> dict:
    def nonfinite(_):
        raise SetupError("JSON contains a non-finite number")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SetupError("JSON contains duplicate keys; the file was preserved")
            result[key] = value
        return result
    try:
        data = json.loads(decode_text(content), object_pairs_hook=pairs, parse_constant=nonfinite)
    except (ValueError, RecursionError):
        raise SetupError("local file is not a valid JSON object") from None
    if not isinstance(data, dict):
        raise SetupError("local file is not a JSON object")
    return data


def write_local(path: Path, content: bytes, *, expected: bytes | None,
                private_existing: bool = True) -> None:
    """Replace an owned file privately, refusing a changed or unsafe destination."""
    if len(content) > MAX_FILE_BYTES:
        raise SetupError("local file exceeds the size limit")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) & 0o022):
        raise SetupError("local directory is not owned or permits writes by others")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        current = read_local(path, private=private_existing, missing=True)
        if current != expected:
            raise SetupError("local file changed during setup; retry after reviewing it")
        if expected is None:
            try:
                os.link(temporary, path)
            except FileExistsError:
                raise SetupError("local file appeared during setup; it was preserved") from None
        else:
            os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def validate_secret(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SetupError("credential is empty")
    if len(value) > 16384 or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise SetupError("credential contains control characters or exceeds the size limit")
    return value


def shell_quote(value: str) -> str:
    return "'" + validate_secret(value).replace("'", "'\\''") + "'"


def literal_value(raw: str) -> str:
    """Decode literal shell assignment syntax without expansion or execution."""
    result = []
    quote = None
    index = 0
    while index < len(raw):
        char = raw[index]
        if quote == "'":
            if char == "'":
                quote = None
            else:
                result.append(char)
        elif char in "'\"" and (quote is None or char == quote):
            quote = None if quote else char
        elif char == "\\":
            index += 1
            if index >= len(raw):
                raise SetupError("env entry is not a literal assignment")
            if quote == '"' and raw[index] not in '$`"\\':
                result.append("\\")
            result.append(raw[index])
        elif char in "$`" or (quote is None and char in ";&|<>()~"):
            raise SetupError("env entry contains shell expansion or commands; it was not evaluated")
        elif quote is None and char in " \t":
            tail = raw[index:].lstrip(" \t")
            if tail and not tail.startswith("#"):
                raise SetupError("env entry is not a literal assignment")
            break
        else:
            result.append(char)
        index += 1
    if quote:
        raise SetupError("env entry has an unfinished quote")
    value = "".join(result)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise SetupError("env entry contains control characters")
    return value


def env_values(content: bytes) -> dict[str, str]:
    values = {}
    for line in decode_text(content).split("\n"):
        line = line.removesuffix("\r")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = ENV_ASSIGNMENT.fullmatch(line)
        if not match:
            raise SetupError("env file contains unsupported syntax; it was not evaluated")
        values[match[1]] = literal_value(match[2])
    return values


def replace_env_values(content: bytes, replacements: dict[str, str]) -> bytes:
    """Change selected entries while preserving every unrelated byte and comment."""
    for name, value in replacements.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", name):
            raise SetupError("invalid credential variable name")
        validate_secret(value)
    # Older launchers source this file. Do not retain executable statements while
    # reporting that a migrated file is safe to use.
    env_values(content)
    remaining = dict(replacements)
    lines = []
    parts = decode_text(content).split("\n")
    for index, part in enumerate(parts):
        line = part + "\n" if index < len(parts) - 1 else part
        match = ENV_ASSIGNMENT.fullmatch(line.rstrip("\r\n"))
        if match and match[1] in replacements:
            if match[1] in remaining:
                ending = "\r\n" if line.endswith("\r\n") else "\n"
                lines.append(f"export {match[1]}={shell_quote(remaining.pop(match[1]))}{ending}")
        else:
            lines.append(line)
    if remaining and lines and not lines[-1].endswith("\n"):
        lines.append("\n")
    lines.extend(f"export {name}={shell_quote(value)}\n" for name, value in remaining.items())
    return "".join(lines).encode("utf-8")


def store_secret(path: Path, reference: LocalSecretReference, value: str) -> None:
    if not isinstance(reference, LocalSecretReference):
        raise SetupError("a typed local credential reference is required")
    before = read_local(path, missing=True)
    updated = replace_env_values(before or b"", {reference.name: value})
    write_local(path, updated, expected=before)


def prompt_secret(name: str) -> str:
    """Require a non-echoing terminal, including when getpass would fall back."""
    while True:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                first = getpass.getpass(f"  {name} (not echoed): ")
                try:
                    validate_secret(first)
                except SetupError:
                    print("  Rejected: enter a non-empty single-line credential.")
                    continue
                second = getpass.getpass("  repeat to confirm: ")
        except (getpass.GetPassWarning, EOFError):
            raise SetupError("a terminal with hidden input is required; no credential was stored") from None
        if first == second:
            return first
        print("  The entries differ. Try again; no credential was stored.")


def verify_grok(root: Path) -> int:
    """Report local credential presence; never contact xAI or launch a client."""
    try:
        content = read_local(root / "env")
        values = env_values(content)
        if not values.get("XAI_API_KEY", "").strip():
            raise SetupError("XAI_API_KEY is missing or empty")
    except SetupError as error:
        print(f"FAIL: {error}")
        return 1
    except OSError:
        print("FAIL: the private local credential file is unreadable")
        return 1
    print("XAI_API_KEY is present in the private local store; its value is not shown.")
    print("UNKNOWN: provider access and Grok client compatibility were not checked.")
    print("Live qualification requires an approved account, client version and capped budget.")
    return 2


def exposure_metadata(paths: list[Path]) -> list[dict[str, str]]:
    """Inspect file metadata only, without opening or resolving credentials."""
    rows = []
    for path in paths:
        row = {"path": str(path)}
        try:
            info = path.lstat()
            row["mode"] = f"{stat.S_IMODE(info.st_mode):03o}"
            if stat.S_ISLNK(info.st_mode):
                row["state"] = "symlink; target not inspected"
            elif not stat.S_ISREG(info.st_mode):
                row["state"] = "not a regular file"
            elif info.st_uid != os.getuid():
                row["state"] = "owned by another user"
            elif info.st_nlink != 1:
                row["state"] = "file has multiple hard links"
            elif stat.S_IMODE(info.st_mode) & 0o077:
                row["state"] = "group or other users have file permissions"
            else:
                row["state"] = "private file permissions"
        except FileNotFoundError:
            row["state"] = "absent"
        except OSError:
            row["state"] = "metadata unavailable"
        rows.append(row)
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Store a local xAI key or check its presence offline.")
    parser.add_argument("command", choices=("enter-key", "verify-grok", "check-exposure"))
    parser.add_argument("--path", action="append", type=Path, help="explicit file for a metadata-only exposure check")
    args = parser.parse_args(argv)
    if args.command == "check-exposure":
        paths = args.path or [private_root() / "env", private_root() / "auth.json"]
        for row in exposure_metadata(paths):
            print(json.dumps(row, ensure_ascii=True))
        print("Metadata only: no credential content was read.")
        return 0
    if args.path:
        parser.error("--path is only available for check-exposure")
    if args.command == "verify-grok":
        return verify_grok(private_root())
    try:
        reference = LocalSecretReference("xai", "XAI_API_KEY")
        store_secret(private_root() / "env", reference, prompt_secret(reference.name))
    except (SetupError, OSError):
        print("Key entry failed; review the private local file and terminal, then retry.", file=sys.stderr)
        return 1
    print("Stored XAI_API_KEY privately. Other env entries were preserved. No provider call was made.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Key entry cancelled.", file=sys.stderr)
        raise SystemExit(130)
