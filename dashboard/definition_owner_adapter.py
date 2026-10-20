"""Prepare definition effects against a retained owner revision; never execute them.

This module is not an authenticated command handler or a persistence layer. The
receiving owner must read its retained mapping, serialize name ownership, evaluate
current authority under its mutation lock and commit recoverable intent. Until
that integration exists, these preparations cannot enable a new edit route.
"""
from dataclasses import dataclass
import hashlib
import re

from agentmux_contracts import canonical_bytes, strict_loads, validate
from definition_service import DefinitionService, _WRITE_LOCK
import ccboard

MAX_VERSION = 9007199254740991


@dataclass(frozen=True, repr=False)
class RetainedDefinitionRevision:
    """Read model for the future owner adapter, not a locally persisted counter."""
    definition_id: str
    name: str
    scope: str
    project_id: str | None
    version: int
    checksum: str | None
    deleted: bool

    def __post_init__(self):
        if (not isinstance(self.definition_id, str) or
                not re.fullmatch(r"[a-z][a-z0-9_-]{0,95}", self.definition_id) or
                not isinstance(self.name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", self.name) or
                self.scope not in ("repo", "global") or
                type(self.version) is not int or not 1 <= self.version <= MAX_VERSION or
                type(self.deleted) is not bool or
                (self.scope == "global" and self.project_id is not None) or
                (self.scope == "repo" and (not isinstance(self.project_id, str) or not self.project_id)) or
                (self.deleted and self.checksum is not None) or
                (not self.deleted and (not isinstance(self.checksum, str) or
                    not re.fullmatch(r"sha256:[0-9a-f]{64}", self.checksum)))):
            raise ccboard.Invalid("invalid retained definition revision")

    def __repr__(self):
        return "<RetainedDefinitionRevision private>"


@dataclass(frozen=True, repr=False)
class PreparedDefinitionChange:
    """Candidate only. A version here is not a committed owner outcome."""
    previous: RetainedDefinitionRevision | None
    candidate: RetainedDefinitionRevision
    effect: object

    def __repr__(self):
        return "<PreparedDefinitionChange private; not committed>"


def prepare_retained_change(service, contract, payload, expected_version, retained):
    """Read/check/encode only; no filesystem, board audit or broker mutation.

    `retained` must eventually come from STATE-01, never a request body or a file
    counter. This function does not authenticate that source or claim name
    uniqueness across IDs. The receiving owner must enforce those guarantees.
    It must repeat these checks under its retained mutation lock before commit.
    """
    if not isinstance(service, DefinitionService) or contract not in ("definition-save", "definition-drop"):
        raise ccboard.Invalid("unsupported definition owner preparation")
    if type(expected_version) is not int or not 0 <= expected_version < MAX_VERSION:
        raise ccboard.Invalid("invalid definition version")
    # Copy the closed payload before reading files, so caller mutations cannot
    # change the target or encoded content during preparation.
    body = strict_loads(canonical_bytes(payload))
    validate(contract, body)
    project_id = service.scope.project_id if body["scope"] == "repo" else None
    if retained is None:
        if expected_version != 0 or body["expectedChecksum"] is not None or contract == "definition-drop":
            raise ccboard.Refused("definition has no retained revision; import or reload it first", [])
    else:
        if not isinstance(retained, RetainedDefinitionRevision):
            raise ccboard.Invalid("invalid retained definition revision")
        if (retained.definition_id, retained.name, retained.scope, retained.project_id) != (
                body["definitionId"], body["name"], body["scope"], project_id):
            raise ccboard.Refused("definition identity or scope does not match the retained owner", [])
        if retained.version != expected_version or retained.checksum != body["expectedChecksum"]:
            raise ccboard.Refused("definition revision changed; reload before editing", [])
        if retained.deleted and contract == "definition-drop":
            raise ccboard.Refused("definition is already deleted", [])
    action = contract.removeprefix("definition-")
    legacy = {**body.get("definition", {}), "name": body["name"], "scope": body["scope"],
              "checksum": body["expectedChecksum"]}
    with _WRITE_LOCK:
        effect = service._preflight_locked(action, legacy)
    checksum = "sha256:" + hashlib.sha256(effect.raw).hexdigest() if effect.raw is not None else None
    candidate = RetainedDefinitionRevision(body["definitionId"], body["name"], body["scope"], project_id,
                                           expected_version + 1, checksum, action == "drop")
    return PreparedDefinitionChange(retained, candidate, effect)


@dataclass(frozen=True, repr=False)
class CatalogPreparation:
    """A candidate for one retained catalog, never an append or file command."""
    snapshot_sequence: int
    aggregate_version: int
    current_state: bytes
    change: PreparedDefinitionChange

    def __repr__(self):
        return "<CatalogPreparation private; not committed>"

    def candidate_state(self, content_ref=None):
        state = strict_loads(self.current_state)
        candidate = self.change.candidate
        if candidate.deleted:
            if content_ref is not None:
                raise ccboard.Invalid("deleted definitions cannot retain a current content reference")
        else:
            # References come from OwnerArtifacts, not from the signed command.
            # The stored definition checksum is the digest of these exact bytes.
            content_ref = strict_loads(canonical_bytes(content_ref))
            if (not isinstance(content_ref, dict) or content_ref.get("digest") != candidate.checksum or
                    content_ref.get("bytes") != len(self.change.effect.raw)):
                raise ccboard.Invalid("definition content reference does not match prepared bytes")
        entry = {"definitionId": candidate.definition_id, "name": candidate.name,
                 "targetScope": candidate.scope, "version": candidate.version,
                 "checksum": candidate.checksum, "deleted": candidate.deleted, "contentRef": content_ref}
        entries = state["definitions"]
        for index, existing in enumerate(entries):
            if existing["definitionId"] == candidate.definition_id:
                entries[index] = entry
                break
        else:
            entries.append(entry)
        _validate_catalog(state)
        return state


def _validate_catalog(state):
    validate("definition-catalog-state", state)
    identities, targets = set(), set()
    for entry in state["definitions"]:
        identity = entry["definitionId"]
        target = (entry["targetScope"], entry["name"])
        if identity in identities or target in targets:
            raise ccboard.Invalid("retained definition catalog contains duplicate identity or target")
        identities.add(identity)
        targets.add(target)
        if not entry["deleted"] and entry["contentRef"]["digest"] != entry["checksum"]:
            raise ccboard.Invalid("retained definition content digest does not match checksum")


def catalog_head_for_worker(snapshot):
    """Detach the immutable head before leaving the history owner's thread.

    SQLite-backed records stay on the owner loop. Preparation only needs these
    bytes and the verified cursor; this bounded value never stands in for the
    complete history passed to the ledger's append or recovery checks.
    """
    from state_owner.ledger import Snapshot
    if not isinstance(snapshot, Snapshot):
        raise ccboard.Invalid("a retained definition catalog snapshot is required")
    latest = snapshot.latest
    return Snapshot(() if latest is None else (latest,), snapshot.sequence)


def prepare_catalog_change(service, snapshot, binding, contract, payload, expected_version):
    """Bridge the agreed STATE-01 snapshot to the definition preflight.

    The receiving owner obtains this snapshot directly from OwnerLedger.current,
    which verifies retained history. Only the bounded latest record is read here.
    An arbitrary Snapshot does not establish authority: this helper returns only
    a proposal and performs no append, artifact upload or file mutation.
    """
    from state_owner.ledger import OwnerBinding, Snapshot, validate_record

    if (not isinstance(binding, OwnerBinding) or binding.entity_kind != "definition-catalog" or
            not isinstance(snapshot, Snapshot)):
        raise ccboard.Invalid("a retained definition catalog binding is required")
    if type(snapshot.sequence) is not int or not 0 <= snapshot.sequence <= MAX_VERSION:
        raise ccboard.Invalid("invalid retained definition catalog cursor")
    latest = snapshot.latest
    if (latest is None) != (snapshot.sequence == 0):
        raise ccboard.Invalid("retained definition catalog cursor does not match its latest record")
    scope = strict_loads(binding.scope)
    if scope["projectId"] is not None and scope["projectId"] != service.scope.project_id:
        raise ccboard.Invalid("definition catalog belongs to another project")
    if latest is None:
        state = {"schemaVersion": "1.0.0", "scope": scope, "definitions": []}
        aggregate_version = 0
    else:
        record = validate_record(latest.record, binding)
        if (latest.sequence != snapshot.sequence or record['entityVersion'] != snapshot.sequence
                or record['previousRevision'] != snapshot.sequence - 1):
            raise ccboard.Invalid("retained definition catalog cursor does not match its latest record")
        state = record["state"]
        aggregate_version = record["entityVersion"]
    _validate_catalog(state)
    if state["scope"] != scope:
        raise ccboard.Invalid("definition catalog scope does not match its owner")
    # Validate before indexing fields; retain closed payload semantics.
    body = strict_loads(canonical_bytes(payload))
    validate(contract, body)
    target_scope = "global" if scope["projectId"] is None else "repo"
    if body["scope"] != target_scope:
        raise ccboard.Invalid("definition command scope does not match its catalog")
    retained = None
    for entry in state["definitions"]:
        same_identity = entry["definitionId"] == body["definitionId"]
        same_target = (entry["targetScope"], entry["name"]) == (body["scope"], body["name"])
        if same_identity != same_target:
            raise ccboard.Refused("definition identity or name is already bound in this catalog", [])
        if same_identity:
            retained = RetainedDefinitionRevision(entry["definitionId"], entry["name"], entry["targetScope"],
                                                  scope["projectId"], entry["version"], entry["checksum"], entry["deleted"])
    change = prepare_retained_change(service, contract, body, expected_version, retained)
    return CatalogPreparation(snapshot.sequence, aggregate_version, canonical_bytes(state), change)
