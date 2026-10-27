"""Scoped definition reads and one checksum-guarded file writer.

Composition supplies roots and verified identities. This module does not authenticate
HTTP requests. The legacy adapter keeps its historical audit labels separate.
"""

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import sys
import stat
import tempfile
import threading
import time
import secrets

import ccboard

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "taskmgmt"))
import agentdefs
from definition_team import DefinitionPlugin, tool_intent
import profile_packages
from profile_owner import (LocalOwner, ProfileError, check_owner, record_directory,
                           read_record, assert_record, assert_directory, _native)

# Shared by every service instance and the legacy facade in this process.
_WRITE_LOCK = threading.Lock()
# Local claims plus a persisted deny fence exclude legacy writers. Neither is
# enrollment or business-state authority; every retained command still admits
# current authority. Startup must bind its enrolled owner before serving edits.
_WRITER_CLAIMS = {}
# A live retained owner holds an exclusive lock on .owner-lease for the rest
# of its process lifetime. Retirement proves the owner stopped by taking it.
_WRITER_LEASES = {}
# A retired fence keeps legacy writes denied until the next owner claims it.
_RETIRED = 'retiredOwner'


def _fence_owner(raw):
    """The hub a fence names, or None for a malformed or foreign fence."""
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    hub = value.get('hubId') if isinstance(value, dict) else None
    return hub if isinstance(hub, str) and hub else None


def _retired_owner(raw):
    """The retired hub a retirement record names, or None."""
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(value, dict) or set(value) != {_RETIRED} or not isinstance(value[_RETIRED], dict):
        return None
    return _fence_owner(json.dumps(value[_RETIRED]))


@dataclass(frozen=True, repr=False)
class _DefinitionWriterClaim:
    directory: Path
    owner: bytes

    def __repr__(self):
        return '<DefinitionWriterClaim private>'


@dataclass(frozen=True, repr=False)
class _DefinitionSource:
    identity: tuple | None
    raw: bytes | None
    checksum: str | None

    def __repr__(self):
        return "<_DefinitionSource private>"


@dataclass(frozen=True, repr=False)
class _PreparedDefinitionEffect:
    service_scope: object
    action: str
    path: Path
    scope: str
    name: str
    source: _DefinitionSource
    raw: bytes | None
    spec: object

    def __repr__(self):
        return "<_PreparedDefinitionEffect private>"


@dataclass(frozen=True)
class DefinitionScope:
    project_root: Path
    home: Path
    global_root: Path
    project_id: str

    def __post_init__(self):
        for name in ("project_root", "home", "global_root"):
            object.__setattr__(self, name, Path(getattr(self, name)).absolute())
        if not isinstance(self.project_id, str) or not self.project_id.strip():
            raise ValueError("project identity is required")

    @classmethod
    def legacy(cls):
        home = Path.home()
        repo = Path.cwd()
        root = Path(os.environ.get("AGENTMUX_HOME", str(home / ".agentmux")))
        return cls(repo, home, root, str(repo.resolve()))


@dataclass(frozen=True)
class EditIdentity:
    """Identity already checked by trusted composition, never decoded from a body.

    Constructing this value is not authentication. A request adapter must establish
    the human and project binding before calling the scoped edit interface.
    """
    user_id: str
    project_id: str


@dataclass(frozen=True)
class DefinitionService:
    scope: DefinitionScope

    def __post_init__(self):
        if not isinstance(self.scope, DefinitionScope):
            raise TypeError("definition scope is required")

    def claim_retained_writer(self, scope, owner):
        """Explicit host handoff, serialized after every in-flight legacy write.

        Call from a worker thread. A private persisted fence keeps legacy writes
        denied after receiver or process loss. It cannot authorize new writes.
        Enrolled startup must repeat the handoff before exposing edit routes.
        This exclusion step does not import existing legacy definitions.
        """
        if scope not in ('repo', 'global') or type(owner) is not bytes or not owner or len(owner) > 4096:
            raise ccboard.Invalid('invalid retained writer binding')
        with _WRITE_LOCK, self._writer_lock(scope):
            directory = self._writer_directory(scope)
            lexical = next(path for path, kind in self._directories() if kind == scope).absolute()
            existing = _WRITER_CLAIMS.get(lexical) or _WRITER_CLAIMS.get(directory)
            if existing is not None and (existing.owner != owner or existing.directory != directory):
                raise ccboard.Refused('definition directory already has another retained owner', [])
            fence = self._read_writer_fence(scope)
            retired = fence is not None and _retired_owner(fence) is not None
            if fence is not None and fence != owner and not retired:
                raise ccboard.Refused('definition directory already has another retained owner', [])
            lease = None
            if existing is None and directory not in _WRITER_LEASES:
                lease = self._take_lease(directory)
                if lease is None:
                    raise ccboard.Refused('definition directory already has another retained owner', [])
            try:
                if fence is None:
                    # Never replace or roll back a fence after an uncertain write.
                    # Its only legacy effect is denial, including malformed fences.
                    fd = os.open(directory / '.owner-fence', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(owner)
                        stream.flush()
                        os.fsync(stream.fileno())
                elif retired:
                    # Only an explicit retirement record is ever replaced, and
                    # atomically, so legacy writes stay denied throughout.
                    self._replace_fence(directory, owner)
            except BaseException:
                if lease is not None:
                    os.close(lease)
                raise
            if lease is not None:
                _WRITER_LEASES[directory] = lease
            # Persist newly created ancestor entries as well as the fence.
            # Repeat after an uncertain prior handoff before admitting a writer.
            root = self.scope.project_root if scope == 'repo' else self.scope.global_root
            parent = next(path for path, kind in self._directories() if kind == scope)
            while True:
                fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | (0 if parent == root else os.O_NOFOLLOW))
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
                if parent == root:
                    break
                parent = parent.parent
            if existing is not None:
                _WRITER_CLAIMS[lexical] = existing
                return existing
            claim = _DefinitionWriterClaim(directory, owner)
            _WRITER_CLAIMS[directory] = claim
            _WRITER_CLAIMS[lexical] = claim
            return claim

    def retire_retained_writer(self, scope, hub_id, *, apply=False):
        """Owner-supported retirement of a stopped retained owner's fence.

        The fence must name hub_id, and no live owner may hold the lease, in
        this or any other process. Retirement rewrites the fence as a
        retirement record: legacy writes stay denied, and the next retained
        owner claims the directory atomically. Without apply nothing changes.
        """
        if scope not in ('repo', 'global') or type(hub_id) is not str or not hub_id or len(hub_id) > 128:
            raise ccboard.Invalid('invalid retained writer binding')
        with _WRITE_LOCK, self._writer_lock(scope):
            directory = self._writer_directory(scope)
            lexical = next(path for path, kind in self._directories() if kind == scope).absolute()
            fence = self._read_writer_fence(scope)
            if fence is None:
                raise ccboard.Refused('definition_owner_fence_absent', [])
            if _retired_owner(fence) == hub_id:
                return {'outcome': 'already_retired', 'hubId': hub_id}
            if _fence_owner(fence) != hub_id:
                raise ccboard.Refused('definition_owner_fence_mismatch', [])
            if (_WRITER_CLAIMS.get(lexical) or _WRITER_CLAIMS.get(directory)) is not None:
                raise ccboard.Refused('definition_owner_running', [])
            lease = self._take_lease(directory)
            if lease is None:
                raise ccboard.Refused('definition_owner_running', [])
            try:
                if not apply:
                    return {'outcome': 'retirable', 'hubId': hub_id}
                retired = json.dumps({_RETIRED: json.loads(fence)}, sort_keys=True, separators=(',', ':')).encode()
                self._replace_fence(directory, retired)
                return {'outcome': 'retired', 'hubId': hub_id}
            finally:
                os.close(lease)

    def _take_lease(self, directory):
        """Return the held owner lease, or None while another owner holds it."""
        import fcntl
        fd = os.open(directory / '.owner-lease', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ccboard.Refused('definition writer fence requires reconciliation', [])
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return None
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _replace_fence(self, directory, raw):
        staged = directory / '.owner-fence.replacing'
        try:
            os.unlink(staged)
        except FileNotFoundError:
            pass
        fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(staged, directory / '.owner-fence')
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _writer_directory(self, scope):
        return next(directory for directory, kind in self._directories() if kind == scope).resolve()

    @contextmanager
    def _writer_lock(self, scope):
        import fcntl
        lexical = next(path for path, kind in self._directories() if kind == scope)
        root = self.scope.project_root if scope == 'repo' else self.scope.global_root
        # The configured root is host-owned. Reject redirects below that root
        # before creating either control file, including an intermediate parent.
        components = []
        parent = lexical
        while parent != root:
            components.append(parent)
            parent = parent.parent
        for component in components:
            if component.is_symlink():
                raise ccboard.Invalid('definition writer directory must not be a symlink')
        lexical.mkdir(parents=True, exist_ok=True)
        for component in components:
            if component.is_symlink():
                raise ccboard.Invalid('definition writer directory must not be a symlink')
        fd = os.open(lexical / '.writer-lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ccboard.Invalid('invalid definition writer lock')
            deadline = time.monotonic() + 3
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ccboard.Refused('definition writer is busy', []) from None
                    time.sleep(.01)
            linked = (lexical / '.writer-lock').lstat()
            if (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino):
                raise ccboard.Refused('definition writer lock changed', [])
            yield
        finally:
            os.close(fd)

    def _read_writer_fence(self, scope):
        path = next(directory for directory, kind in self._directories() if kind == scope) / '.owner-fence'
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        except OSError:
            raise ccboard.Refused('definition writer fence requires reconciliation', []) from None
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ccboard.Refused('definition writer fence requires reconciliation', [])
            raw = stream.read(4097)
        if not raw or len(raw) > 4096:
            raise ccboard.Refused('definition writer fence requires reconciliation', [])
        return raw

    def _check_writer_locked(self, scope, claim=None):
        directory = self._writer_directory(scope)
        lexical = next(path for path, kind in self._directories() if kind == scope).absolute()
        active = _WRITER_CLAIMS.get(lexical) or _WRITER_CLAIMS.get(directory)
        fence = self._read_writer_fence(scope)
        if claim is None:
            if active is not None or fence is not None:
                raise ccboard.Refused('definition edits require the retained owner', [])
        elif active is not claim or claim.directory != directory or fence != claim.owner:
            raise ccboard.Refused('retained definition writer is not active', [])

    def check_retained_writer(self, scope, claim):
        if claim is None:
            raise ccboard.Refused('retained definition writer is not active', [])
        with _WRITE_LOCK:
            self._check_writer_locked(scope, claim)

    def _identity(self, identity):
        if (not isinstance(identity, EditIdentity)
                or not isinstance(identity.user_id, str)
                or not identity.user_id.strip()
                or any(ord(c) < 32 for c in identity.user_id)
                or identity.project_id != self.scope.project_id):
            raise ccboard.Invalid("verified user and matching project identity are required")
        return identity.user_id, {"project_id": identity.project_id}

    def save(self, db, body, identity):
        actor, audit = self._identity(identity)
        return self._save(db, body, actor, audit)

    def drop(self, db, body, identity):
        actor, audit = self._identity(identity)
        return self._drop(db, body, actor, audit)

    def legacy_save(self, db, body):
        return self._save(db, body, body.get("actor") if isinstance(body, dict) else None, {})

    def legacy_drop(self, db, body):
        return self._drop(db, body, body.get("actor") if isinstance(body, dict) else None, {})

    def preview_profiles(self):
        """HTTP is deliberately limited to a metadata-only catalogue preview."""
        result, _ = profile_packages.preview(self.scope.project_root, None, None)
        return result

    def adopt_profiles(self, owner, selections, clients, approval_checksum, record_checksum):
        """The explicit local-owner command is the sole adoption writer.

        This records OS ownership, not an enrolled human or team approval. A
        caller body cannot be converted to LocalOwner by this service.
        """
        check_owner(owner)
        if owner.project != self.scope.project_root:
            raise ProfileError("profile_project_mismatch")
        with _WRITE_LOCK:
            result, candidate = profile_packages.preview(owner.project, selections, clients, owner=owner)
            if result["approvalChecksum"] != approval_checksum or result["recordChecksum"] != record_checksum:
                raise ProfileError("profile_approval_changed")
            selected_names = {row["name"] for row in candidate}
            for directory, _ in self._directories():
                for name in selected_names:
                    target = directory / (name + ".md")
                    if ((target.exists() or target.is_symlink())
                            and not profile_packages.is_bundled_directory(directory)):
                        raise ProfileError("profile_definition_collision")
            value = {"schemaVersion": "1.0.0", "projectRoot": str(owner.project),
                     "projectDevice": owner.project_identity[0], "projectInode": owner.project_identity[1],
                     "ownerUid": owner.uid, "profiles": candidate}
            raw = profile_packages.encoded(value)
            if len(raw) > profile_packages.RECORD_LIMIT:
                raise ProfileError("profile_record_too_large")
            profile_packages._record(raw, owner.project)
            with record_directory(owner, create=True, exclusive=True) as fd:
                current, revision = read_record(fd)
                if profile_packages.digest(current or b"") != record_checksum:
                    raise ProfileError("profile_record_changed")
                # Refresh exact source and executable facts immediately before
                # the atomic mutation, rather than trusting a prior browser view.
                fresh, _ = profile_packages.preview(owner.project, selections, clients, owner=owner)
                if fresh["approvalChecksum"] != approval_checksum:
                    raise ProfileError("profile_approval_changed")
                temporary = ".record-" + secrets.token_hex(16)
                try:
                    child = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                    0o600, dir_fd=fd)
                    with os.fdopen(child, "wb") as stream:
                        _native(stream.fileno(), True)
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                        _native(stream.fileno(), True)
                    assert_directory(owner, fd)
                    assert_record(fd, revision)
                    os.replace(temporary, "record.json", src_dir_fd=fd, dst_dir_fd=fd)
                    os.fsync(fd)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=fd)
                    except FileNotFoundError:
                        pass
            return {"schemaVersion": "1.0.0", "status": "adopted", "projectRoot": str(owner.project),
                    "ownerUid": owner.uid, "recordChecksum": profile_packages.digest(raw),
                    "profileCount": len(candidate), "teamApproval": "unchanged"}

    def agents(self, db, params):
        """Return the discovered roster, or one full definition for editing."""
        name = None
        if "name" in params:
            values = params["name"]
            if (len(values) != 1 or not isinstance(values[0], str)
                    or not agentdefs.NAME_RE.fullmatch(values[0])):
                raise ccboard.Invalid("name must match ^[a-z][a-z0-9-]{0,63}$")
            name = values[0]

        # This identifier describes a local compatibility import. It does not
        # assert package registration, enrollment or execution authority.
        manifests, problems = DefinitionPlugin(self.scope.project_root,
                home=self.scope.home, global_root=self.scope.global_root).import_all(
                    package_name="legacy-local-markdown")
        specs = {manifest.spec.name: manifest.spec for manifest in manifests}
        memberships = {manifest.spec.name: manifest.membership for manifest in manifests
                       if manifest.membership is not None}

        def payload(spec):
            row = asdict(spec)
            for field in ("tools", "tools_deny", "capabilities"):
                row[field] = list(row[field])
            row["toolIntent"] = {key: list(value) for key, value in tool_intent(spec).items()}
            row["editable"] = spec.scope != "claude" and spec.name not in memberships
            if spec.name in memberships:
                row["profileMembership"] = asdict(memberships[spec.name])
            return row

        if name is not None:
            if name not in specs:
                raise ccboard.NotFound("agent not found: " + name)
            return payload(specs[name])

        rows = []
        for key in sorted(specs):
            row = payload(specs[key])
            del row["persona"]
            rows.append(row)
        return {"agents": rows, "scopes": list(agentdefs.SCOPES),
                "problems": problems, "count": len(rows)}


    def _directories(self):
        return ((self.scope.project_root / ".agentmux/agents", "repo"),
                (self.scope.global_root / "agents", "global"),
                (self.scope.project_root / ".claude/agents", "claude"),
                (self.scope.home / ".claude/agents", "claude"))


    def _target(self, body):
        if not isinstance(body, dict):
            raise ccboard.Invalid("definition must be an object")
        name, scope = body.get("name"), body.get("scope")
        if not isinstance(name, str) or not agentdefs.NAME_RE.fullmatch(name):
            raise ccboard.Invalid("name must match ^[a-z][a-z0-9-]{0,63}$")
        if scope not in ("repo", "global"):
            raise ccboard.Invalid("scope must be repo or global; claude definitions are read-only")
        directory = next(d for d, s in self._directories() if s == scope)
        if profile_packages.is_bundled_directory(directory) and name in profile_packages.NAMES:
            raise ccboard.Invalid("bundled profile sources are read-only; adopt a project revision")
        path = directory / (name + ".md")
        # Reject redirected agent directories and leaf symlinks, including dangling ones.
        if directory.is_symlink() or path.is_symlink():
            raise ccboard.Invalid("definition path must not be a symlink")
        if "path" in body:
            supplied = body["path"]
            if (not isinstance(supplied, str) or "\x00" in supplied
                    or Path(supplied).absolute() != path or Path(supplied).resolve() != path.resolve()):
                raise ccboard.Invalid("path must name the definition in its agent directory")
        if path.exists() and not path.is_file():
            raise ccboard.Invalid("definition must be a regular file")
        return path, scope


    def _conflict(self, message, path):
        raise ccboard.Refused(message, [{"field": "name", "hint": str(path)}])


    def _check_collisions(self, path):
        for directory, _ in self._directories():
            other = directory / path.name
            if other.absolute() == path.absolute():
                continue
            if other.exists() or other.is_symlink():
                # Discovery also deduplicates aliased directories.
                if directory.resolve() == path.parent.resolve():
                    continue
                self._conflict("agent name already taken: " + path.stem, other)


    @staticmethod
    def _file_identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    @contextmanager
    def _checked_source(self, path, body):
        checksum = body.get("checksum")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            if checksum not in (None, ""):
                self._conflict("definition no longer exists; reload before saving", path)
            yield _DefinitionSource(None, None, None)
            return
        except OSError:
            raise ccboard.Invalid("definition must be a regular file, not a symlink") from None
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ccboard.Invalid("definition must be a regular file")
            raw = stream.read(agentdefs.MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
            if len(raw) > agentdefs.MAX_BYTES:
                raise ccboard.Invalid("definition exceeds 64 KiB")
            identity = self._file_identity(after)
            if self._file_identity(before) != identity:
                self._conflict("definition changed; reload before saving", path)
            actual = "sha256:" + hashlib.sha256(raw).hexdigest()
            if checksum != actual:
                self._conflict("definition changed or name already taken; reload before saving", path)
            yield _DefinitionSource(identity, raw, actual)

    @contextmanager
    def _checked_revision(self, path, body):
        with self._checked_source(path, body) as source:
            yield source.identity

    def _assert_revision(self, path, identity):
        try:
            info = path.lstat()
        except FileNotFoundError:
            info = None
        if ((identity is None and info is not None)
                or (identity is not None and (info is None
                    or not stat.S_ISREG(info.st_mode)
                    or self._file_identity(info) != identity))):
            self._conflict("definition changed; reload before saving", path)
        # This closes accidental/external substitution before mutation. A malicious
        # same-user directory writer can still race this final check and pathname
        # mutation; this legacy file store is not an isolation boundary against it.


    def _encode(self, body, path, scope):
        fields = {}
        try:
            for key in agentdefs.KEYS:
                value = body.get("tools_deny" if key == "tools-deny" else key)
                if value is None:
                    continue
                if key in ("tools", "tools-deny", "capabilities"):
                    if not isinstance(value, list) or any(
                            not isinstance(item, str) or not item.strip() or "," in item
                            for item in value):
                        raise ValueError(f"{key} must be a list of nonempty strings without commas")
                    value = ", ".join(value)
                elif key == "max_instances":
                    if type(value) is not int:
                        raise ValueError("max_instances must be an integer from 1 to 8")
                    value = str(value)
                fields[key] = agentdefs._string(value, key)
            persona = agentdefs._string(body.get("persona", ""), "persona", multiline=True)
            raw = ("---\n" + "".join(f"{key}: {json.dumps(value, ensure_ascii=False)}\n"
                                    for key, value in sorted(fields.items()))
                   + "---\n" + persona).encode("utf-8")
            if len(raw) > agentdefs.MAX_BYTES:
                raise ValueError("definition exceeds 64 KiB")
            defaults = agentdefs._defaults(self._directories()[1][0].parent, lambda *args: None)
            parsed, parsed_persona = agentdefs._frontmatter(raw)
            spec = agentdefs._spec(path, scope, raw, parsed, parsed_persona, *defaults)
        except (ValueError, TypeError) as exc:
            raise ccboard.Invalid(str(exc)) from exc
        return raw, spec


    def _preflight_locked(self, action, body):
        """Prepare exact bytes without effects. Caller must hold _WRITE_LOCK.

        This validates file state, not authority. A future owner must retain its
        own integer revision and intent before applying the prepared file effect.
        """
        if action not in ("save", "drop"):
            raise ccboard.Invalid("unknown definition action")
        path, scope = self._target(body)
        if action == "save":
            self._check_collisions(path)
        elif not path.exists():
            raise ccboard.NotFound("agent not found: " + body["name"])
        with self._checked_source(path, body) as source:
            raw, spec = self._encode(body, path, scope) if action == "save" else (None, None)
            return _PreparedDefinitionEffect(self.scope, action, path, scope, body["name"], source, raw, spec)

    def _apply_locked(self, db, prepared, actor, audit):
        """Apply through the sole legacy writer; caller keeps _WRITE_LOCK.

        Preparing this value never grants permission. The caller supplies its
        admitted audit identity. File mutation and board audit are separate
        effects: audit failure after mutation must not be reported as rollback.
        """
        self._mutate_locked(prepared)
        if prepared.action == "save":
            ccboard._record(db, None, "agentdef", actor, None,
                            {"scope": prepared.scope, "name": prepared.name, **audit})
            row = asdict(prepared.spec)
            for name in ("tools", "tools_deny", "capabilities"):
                row[name] = list(row[name])
            row["toolIntent"] = {key: list(value) for key, value in tool_intent(prepared.spec).items()}
            return dict(row, editable=True)
        ccboard._record(db, None, "agentdrop", actor, None,
                        {"scope": prepared.scope, "name": prepared.name, **audit})
        return {"ok": True, "scope": prepared.scope, "name": prepared.name}

    def _mutate_locked(self, prepared, *, before_commit=None, writer=None):
        """The one file mutation implementation; callers own admission and audit.

        Legacy callers use the board audit. The retained owner commits its audit
        and effect intent first. Neither audit makes the file write atomic with it.
        """
        if (not isinstance(prepared, _PreparedDefinitionEffect) or prepared.service_scope != self.scope
                or prepared.action not in ("save", "drop")):
            raise ccboard.Invalid("definition preparation belongs to another scope")
        with self._writer_lock(prepared.scope):
            self._check_writer_locked(prepared.scope, writer)
            self._mutate_file_locked(prepared, before_commit)

    def _mutate_file_locked(self, prepared, before_commit):
        path, scope = self._target({"name": prepared.name, "scope": prepared.scope})
        if path != prepared.path:
            raise ccboard.Invalid("definition target changed")
        if prepared.action == "save":
            self._check_collisions(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(prepared.raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, 0o600)
                if before_commit is not None:
                    before_commit()
                self._assert_revision(path, prepared.source.identity)
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            return
        if before_commit is not None:
            before_commit()
        self._assert_revision(path, prepared.source.identity)
        path.unlink()

    def _save(self, db, body, actor, audit):
        with _WRITE_LOCK:
            if isinstance(body, dict) and body.get('scope') in ('repo', 'global'):
                self._check_writer_locked(body['scope'])
            return self._apply_locked(db, self._preflight_locked("save", body), actor, audit)

    def _drop(self, db, body, actor, audit):
        with _WRITE_LOCK:
            if isinstance(body, dict) and body.get('scope') in ('repo', 'global'):
                self._check_writer_locked(body['scope'])
            return self._apply_locked(db, self._preflight_locked("drop", body), actor, audit)
