"""Definition and team domain adapters over the existing Markdown rules.

These values describe imported definitions and proposed teams. The owning project
service authorizes changes and stores approval; this module does not grant access.
"""
from dataclasses import asdict, dataclass
import json
import hashlib

try:
    from . import agentdefs
except ImportError:
    import agentdefs


@dataclass(frozen=True)
class DefinitionRevision:
    name: str
    scope: str
    path: str
    checksum: str
    snapshot_digest: str

    @classmethod
    def of(cls, spec):
        return cls(spec.name, spec.scope, spec.path, spec.checksum, snapshot_digest(spec))


@dataclass(frozen=True)
class DefinitionMembership:
    package_id: str
    relationship: str
    parent_package: str | None
    source_checksum: str
    derived_checksum: str


@dataclass(frozen=True)
class DefinitionManifest:
    schema_version: str
    package_name: str
    parent_package: str | None
    spec: agentdefs.AgentSpec
    source: bytes
    membership: DefinitionMembership | None = None

    @property
    def revision(self):
        return DefinitionRevision.of(self.spec)


class DefinitionPlugin:
    """Import compatible Markdown without rereading an admitted source path."""
    name = "definitions"

    def __init__(self, repo_root, *, home, global_root):
        self.repo_root = repo_root
        self.home = home
        self.global_root = global_root

    def import_all(self, *, package_name, parent_package=None):
        if not isinstance(package_name, str) or not package_name:
            raise ValueError("definition package name is required")
        if parent_package is not None and (not isinstance(parent_package, str) or not parent_package):
            raise ValueError("parent package name must be a nonempty string")
        specs, problems, sources, membership = agentdefs._load_catalog(
            self.repo_root, home=self.home, global_root=self.global_root, _with_membership=True)
        manifests = tuple(DefinitionManifest("1.0.0", package_name, parent_package,
                                            specs[name], sources[name],
                                            DefinitionMembership(
                                                membership[name]["packageId"], membership[name]["relationship"],
                                                membership[name]["parentPackage"], membership[name]["sourceChecksum"],
                                                membership[name]["derivedChecksum"])
                                            if name in membership else None)
                          for name in sorted(specs))
        return manifests, problems


@dataclass(frozen=True)
class TeamProposal:
    members: tuple[agentdefs.AgentSpec, ...]
    gaps: tuple[str, ...]
    approved_lead: bool

    def revision_changes(self, specs):
        """Report edits or absence without replacing any saved member persona."""
        return tuple((member.name, "unavailable" if member.name not in specs else "changed")
                     for member in self.members
                     if member.name not in specs or
                     DefinitionRevision.of(member) != DefinitionRevision.of(specs[member.name]))


class TeamPlugin:
    """Expose strict project proposals and the explicit legacy compatibility path."""
    name = "teams"

    def propose_legacy(self, task, specs, cfg, cli_override=None, *, dependencies=None, lead=None):
        """Preserve legacy proposal rules without granting member approval.

        The board owns approval and saved revisions. Its compatibility workflow
        may propose discovered workers and use the existing built-in lead; this
        is deliberately separate from the approved-revision interface below.
        """
        return agentdefs.choose_roster(task, specs, cfg, cli_override=cli_override,
                                       dependencies=dependencies, approved_lead=lead)

    def propose(self, task, specs, cfg, *, lead, members, dependencies=None):
        if lead is None:
            return TeamProposal((), ("Project lead approval is required",), False)
        allowed = {}
        for revision in (lead, *members):
            spec = specs.get(revision.name)
            if spec is None or DefinitionRevision.of(spec) != revision:
                raise ValueError("project definition revision is unavailable or changed")
            allowed[spec.name] = spec
        selected_lead = allowed[lead.name]
        if selected_lead.role != "lead":
            raise ValueError("project lead must have the lead role")
        selected = agentdefs.choose_roster(task, allowed, cfg,
                                          dependencies=dependencies,
                                          approved_lead=selected_lead)
        return TeamProposal(tuple(selected), tuple(selected.gaps), True)


def tool_intent(spec, *, host_tools=()):
    """Separate requested tools from names the host can actually enforce.

    Host support is not permission. Effective grants remain the host's decision;
    an empty support list never claims that a CLI flag enforces a restriction.
    """
    supported = frozenset(host_tools)
    return {"desired": tuple(spec.tools), "denied": tuple(spec.tools_deny),
            "hostEnforceable": tuple(t for t in spec.tools if t in supported),
            "hostEnforceableDenied": tuple(t for t in spec.tools_deny if t in supported),
            "advisory": tuple(t for t in (*spec.tools, *spec.tools_deny) if t not in supported)}


def dump_spec(spec):
    """Private roster storage; never include this persona-bearing JSON in lists."""
    return json.dumps({"schemaVersion": "1.0.0", "spec": asdict(spec)},
                      sort_keys=True, separators=(",", ":"))


def snapshot_digest(spec):
    """Identify all resolved fields without publishing the saved persona."""
    return "sha256:" + hashlib.sha256(dump_spec(spec).encode("utf-8")).hexdigest()


def load_spec(raw):
    value = json.loads(raw)
    if set(value) != {"schemaVersion", "spec"} or value["schemaVersion"] != "1.0.0":
        raise ValueError("unsupported roster definition snapshot")
    fields = value["spec"]
    if not isinstance(fields, dict) or set(fields) != set(agentdefs.AgentSpec.__dataclass_fields__):
        raise ValueError("invalid roster definition snapshot")
    for key in ("name", "scope", "path", "description", "cli", "posture", "persona",
                "role", "worktree", "checksum"):
        if not isinstance(fields[key], str):
            raise ValueError("invalid roster definition snapshot")
        agentdefs._string(fields[key], key, multiline=key == "persona")
    for key in ("model", "auth"):
        if fields[key] is not None:
            agentdefs._string(fields[key], key)
    if (not agentdefs.NAME_RE.fullmatch(fields["name"])
            or fields["scope"] not in agentdefs.SCOPES
            or not agentdefs.CLI_RE.fullmatch(fields["cli"])
            or fields["role"] not in ("lead", "worker", "reviewer", "researcher")
            or fields["posture"] not in ("read-only", "workspace-write", "unrestricted")
            or fields["worktree"] not in ("per-member", "integration", "none")
            or type(fields["max_instances"]) is not int
            or not 1 <= fields["max_instances"] <= 8
            or len(fields["persona"]) > 4096
            or not fields["description"] or len(fields["description"]) > 2048):
        raise ValueError("invalid roster definition snapshot")
    if fields["checksum"] and not agentdefs.re.fullmatch(r"sha256:[0-9a-f]{64}", fields["checksum"]):
        raise ValueError("invalid roster definition snapshot")
    for key in ("tools", "tools_deny", "capabilities"):
        if not isinstance(fields[key], list) or not all(isinstance(v, str) for v in fields[key]):
            raise ValueError("invalid roster definition snapshot")
        for item in fields[key]:
            agentdefs._string(item, key)
        fields[key] = tuple(fields[key])
    return agentdefs.AgentSpec(**fields)
