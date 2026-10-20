"""Opt-in bundled profile packages, separate from project team approval.

Profiles describe intent. Neither their prose nor their package labels grant an
operation. Original bytes and resolved fields stay separate from derived edits.
"""
from dataclasses import asdict, replace
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat

try:
    from . import agentdefs
    from . import definition_team
    from .profile_owner import (ProfileError, admit_project, record_directory, read_record)
except ImportError:
    import agentdefs
    import definition_team
    from profile_owner import ProfileError, admit_project, record_directory, read_record

BUNDLE_ROOT = Path(__file__).resolve().parents[1]
PACKAGES = {
    "example.survey": ("catalog-lead", "scan-dev", "scan-host", "scan-user"),
    "example.agora": ("agora-brain", "agora-defect", "agora-lead", "agora-perf",
                      "agora-release", "agora-review", "agora-ui", "agora-unreal"),
    "example.orchestration": ("ccc-orchestrator",),
    "example.network-review": ("netcap-reviewer",),
}
NAMES = frozenset(name for names in PACKAGES.values() for name in names)
PATH_PATTERN = re.compile(r"(?:[A-Za-z]:[/\\]|/Users/|/home/|/mnt/|~/|\.\./)")
PATH_REFERENCE = re.compile(r'''(?:[A-Za-z]:[/\\]|/(?:Users|home|mnt)/|~/|\.\./)[^\s`"<>|,;)\]]{0,255}''')
RECORD_LIMIT = 1 << 20


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def catalogue():
    """Read each fixed source once through the existing checked parser seam."""
    result, problems = {}, []
    for package, names in PACKAGES.items():
        for name in names:
            path = BUNDLE_ROOT / ".agentmux/agents" / (name + ".md")
            try:
                raw = agentdefs._read_source(path)
                fields, persona = agentdefs._frontmatter(raw)
                unknown = sorted(fields.keys() - agentdefs.KEYS)
                if unknown:
                    problems.append({"name": name, "code": "profile_unknown_keys", "keys": unknown})
                spec = agentdefs._spec(path, "repo", raw, fields, persona, "codex", {}, {"methods": []})
                if spec.name != name:
                    raise ProfileError("profile_source_name_mismatch")
                manifest = definition_team.DefinitionManifest("1.0.0", package, None, spec, raw)
                result[name] = manifest
            except (OSError, ValueError, UnicodeError):
                problems.append({"name": name, "code": "profile_source_invalid"})
    return result, problems


def is_bundled_directory(path):
    return Path(path).resolve() == (BUNDLE_ROOT / ".agentmux/agents").resolve()


def client_facts(clients):
    """Snapshot explicitly selected executables; do not execute or qualify them."""
    if not isinstance(clients, dict) or not clients or set(clients) - {"codex", "claude", "grok"}:
        raise ProfileError("profile_explicit_clients_required")
    facts = {}
    for name, supplied in sorted(clients.items()):
        path = Path(supplied) if isinstance(supplied, str) else Path()
        if isinstance(supplied, str):
            agentdefs._string(supplied, "client path")
        if not path.is_absolute() or path.resolve() != path or str(path) != os.path.normpath(str(path)):
            raise ProfileError("profile_client_path_invalid")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, os.geteuid())
                    or before.st_mode & 0o22 or not before.st_mode & 0o111
                    or not 0 < before.st_size <= 128 << 20):
                raise ProfileError("profile_client_path_invalid")
            sha, size = hashlib.sha256(), 0
            while size <= 128 << 20:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                sha.update(chunk)
                size += len(chunk)
            after = os.fstat(fd)
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or size != before.st_size or not os.path.samestat(before, path.stat(follow_symlinks=False))):
                raise ProfileError("profile_client_changed")
            facts[name] = {"path": str(path), "checksum": "sha256:" + sha.hexdigest(),
                           "qualification": "selected executable; provider behavior not tested"}
        finally:
            try:
                from .profile_owner import _close_all
            except ImportError:
                from profile_owner import _close_all
            _close_all([fd])
    return {"os": platform.system(), "arch": platform.machine(), "clients": facts}


def _derive(spec, options):
    if not isinstance(options, dict) or set(options) - {"paths", "execution"}:
        raise ProfileError("profile_overrides_invalid")
    paths, execution = options.get("paths", {}), options.get("execution")
    if not isinstance(paths, dict) or len(paths) > 32:
        raise ProfileError("profile_path_overrides_invalid")
    persona, description = spec.persona, spec.description
    for old, new in paths.items():
        if (not isinstance(old, str) or not old or not PATH_PATTERN.search(old)
                or old not in persona + description or not isinstance(new, str)
                or not Path(new).is_absolute() or len(new) > 1024):
            raise ProfileError("profile_path_overrides_invalid")
        agentdefs._string(old, "source path")
        agentdefs._string(new, "derived path")
    if paths:
        replacements = re.compile("|".join(re.escape(old) for old in sorted(paths, key=lambda key: (-len(key), key))))
        persona = replacements.sub(lambda match: paths[match.group()], persona)
        description = replacements.sub(lambda match: paths[match.group()], description)
    if (not isinstance(execution, dict) or set(execution) != {"posture", "worktree", "maxInstances"}
            or execution["posture"] not in ("read-only", "workspace-write")
            or execution["worktree"] not in ("none", "integration", "per-member")
            or type(execution["maxInstances"]) is not int or not 1 <= execution["maxInstances"] <= 8):
        raise ProfileError("profile_bounded_execution_required")
    effective = replace(spec, persona=persona, description=description,
                        posture=execution["posture"], worktree=execution["worktree"],
                        max_instances=execution["maxInstances"])
    # Reuse every stored-field validation, including persona limits.
    definition_team.load_spec(definition_team.dump_spec(effective))
    return effective


def _record(raw, project):
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
        if (set(value) != {"schemaVersion", "projectRoot", "projectDevice", "projectInode", "ownerUid", "profiles"}
                or value["schemaVersion"] != "1.0.0" or value["projectRoot"] != str(project)
                or type(value["ownerUid"]) is not int or value["ownerUid"] != os.geteuid()
                or (value["projectDevice"], value["projectInode"]) != (project.stat().st_dev, project.stat().st_ino)
                or not isinstance(value["profiles"], list) or len(value["profiles"]) > 14):
            raise ProfileError("profile_record_invalid")
        names = set()
        for item in value["profiles"]:
            if set(item) != {"packageId", "relationship", "parentPackage", "name", "source", "sourceChecksum", "original", "overrides", "derived", "derivedChecksum", "hostFacts"}:
                raise ProfileError("profile_record_invalid")
            _package_identity(item)
            if item["name"] in names:
                raise ProfileError("profile_record_duplicate")
            names.add(item["name"])
            source = base64.b64decode(item["source"], validate=True)
            if len(source) > agentdefs.MAX_BYTES or digest(source) != item["sourceChecksum"]:
                raise ProfileError("profile_record_source_invalid")
            original = definition_team.load_spec(json.dumps({"schemaVersion": "1.0.0", "spec": item["original"]}))
            fields, persona = agentdefs._frontmatter(source)
            parsed = agentdefs._spec(Path(original.path), "repo", source, fields, persona, "codex", {}, {"methods": []})
            if parsed != original or original.name != item["name"] or original.checksum != item["sourceChecksum"]:
                raise ProfileError("profile_record_source_invalid")
            derived = _derive(original, item["overrides"])
            if item["derived"] != json.loads(definition_team.dump_spec(derived))["spec"] or item["derivedChecksum"] != definition_team.snapshot_digest(derived):
                raise ProfileError("profile_record_derived_invalid")
        return value
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ProfileError("profile_record_invalid") from None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProfileError("profile_duplicate_key")
        result[key] = value
    return result


def _package_identity(item):
    if (item.get("packageId") not in PACKAGES or item.get("name") not in PACKAGES[item["packageId"]]
            or item.get("relationship") not in ("independent", "parent-owned")
            or (item["relationship"] == "independent" and item.get("parentPackage") is not None)
            or (item["relationship"] == "parent-owned" and
                (not isinstance(item.get("parentPackage"), str)
                 or not re.fullmatch(r"[a-z][a-z0-9.-]{0,127}", item["parentPackage"])
                 or item["parentPackage"] == item["packageId"]))):
        raise ProfileError("profile_package_identity_invalid")


def record_snapshot(owner):
    try:
        with record_directory(owner) as fd:
            raw, _ = read_record(fd)
    except FileNotFoundError:
        raw = None
    return (_record(raw, owner.project) if raw is not None else None), digest(raw or b"")


def adopted(project):
    specs, problems, _, _ = adopted_catalog(project)
    return specs, problems


def adopted_catalog(project):
    """Only the checked private record can make shipped profiles eligible."""
    project = Path(project).absolute()
    if not os.path.lexists(project / ".agentmux/profile-adoptions"):
        return {}, [], {}, {}
    try:
        with admit_project(project) as owner:
            record, _ = record_snapshot(owner)
        rows = (record or {}).get("profiles", [])
        return ({row["name"]: definition_team.load_spec(json.dumps({"schemaVersion": "1.0.0", "spec": row["derived"]}))
                 for row in rows}, [], {row["name"]: base64.b64decode(row["source"]) for row in rows},
                {row["name"]: {key: row[key] for key in
                    ("packageId", "relationship", "parentPackage", "sourceChecksum", "derivedChecksum")}
                 for row in rows})
    except (OSError, ValueError):
        return {}, [{"path": str(project / ".agentmux/profile-adoptions/record.json"),
                     "scope": "repo", "error": "project profile adoption record is unavailable or invalid"}], {}, {}


def preview(project, selections, clients, *, owner=None):
    """Return metadata and an exact approval checksum; never return personas."""
    project = Path(project).absolute()
    manifests, problems = catalogue()
    host = client_facts(clients) if clients else {"os": platform.system(), "arch": platform.machine(), "clients": {}}
    if owner is not None:
        _, revision = record_snapshot(owner)
    else:
        revision = None
    rows = []
    for name, manifest in sorted(manifests.items()):
        spec = manifest.spec
        rows.append({"name": name, "packageId": manifest.package_name, "sourceChecksum": spec.checksum,
                     "scope": "project opt-in only", "appliesTo": str(project),
                     "role": spec.role, "client": spec.cli, "supportedHosts": ["macos-arm64"],
                     "clientAvailable": spec.cli in host["clients"],
                     "incompatibleCapabilities": ([] if spec.cli == "claude" else list(spec.tools + spec.tools_deny)),
                     "permissions": {"posture": spec.posture, "tools": list(spec.tools), "toolsDeny": list(spec.tools_deny),
                                     "capabilities": list(spec.capabilities), "grants": []},
                     "machinePathReviewRequired": bool(PATH_PATTERN.search(manifest.source.decode("utf-8"))),
                     "machineReferences": sorted(set(PATH_REFERENCE.findall(manifest.source.decode("utf-8"))))[:32],
                     "exampleProject": {"example.survey": "machine survey", "example.agora": "agora",
                                        "example.orchestration": "orchestration", "example.network-review": "nettraffic"}[manifest.package_name],
                     "legacyTaskAliases": sorted(set(re.findall(r"\b(?:TM|EP|ADR|SP|CAP)-[0-9]+\b", spec.persona + spec.description))),
                     "aliasDisposition": "reference only; no task import or current project assignment",
                     "instructionsAreData": True})
    if selections is None:
        selections = []
    if not isinstance(selections, list) or not 0 <= len(selections) <= 14:
        raise ProfileError("profile_selections_invalid")
    prepared, seen = [], set()
    for selection in selections:
        if not isinstance(selection, dict) or set(selection) != {"packageId", "name", "relationship", "parentPackage", "sourceChecksum", "overrides"}:
            raise ProfileError("profile_selection_invalid")
        _package_identity(selection)
        name = selection["name"]
        if name in seen or name not in manifests or manifests[name].spec.checksum != selection["sourceChecksum"]:
            raise ProfileError("profile_source_changed")
        seen.add(name)
        manifest = manifests[name]
        if manifest.spec.cli not in host["clients"] or host["os"] != "Darwin" or host["arch"] != "arm64":
            raise ProfileError("profile_client_unavailable")
        derived = _derive(manifest.spec, selection["overrides"])
        prepared.append({**selection, "source": base64.b64encode(manifest.source).decode(),
                         "original": json.loads(definition_team.dump_spec(manifest.spec))["spec"],
                         "derived": json.loads(definition_team.dump_spec(derived))["spec"],
                         "derivedChecksum": definition_team.snapshot_digest(derived), "hostFacts": host})
    result = {"schemaVersion": "1.0.0", "projectRoot": str(project), "profiles": rows, "problems": problems,
              "recordChecksum": revision, "hostFacts": host,
              "selectionCount": len(prepared), "approvalChecksum": None}
    # The checksum binds the full private candidate too; it reveals no source bytes.
    result["approvalChecksum"] = digest(encoded({"preview": result, "candidate": prepared}))
    return result, prepared
