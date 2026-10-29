"""agentmux-hub: the one process that owns hub.db. See docs/PROTOCOL.md 7-9.

Run:  python3 hub/server.py [--foreground]      (normally via `agentmux hub start`)

Concurrency model: asyncio for the socket and the loops; every Store call runs on ONE
dedicated thread (the only writing connection); blocking terminal I/O (doorbells)
runs on a small pool, at most one in flight per agent.

Identity (R-ID-1): a caller is identified by walking its process ancestry to a
registered agent's pane pid (SO_PEERCRED on the unix socket). $AGENTMUX_AGENT is never
consulted - the codex shared daemon proved an env var is not an identity (C8).
"""
from __future__ import annotations

import asyncio
import concurrent.futures as cf
import hashlib
import fcntl
import hmac
import json
import re
import os
import secrets
import signal
import socket
import struct
import subprocess
import sys
import time
import tomllib
import weakref
from contextvars import ContextVar
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager, nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import Event

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hub import deliver, names, profiles  # noqa: E402
from hub.store import HubError, Store, now  # noqa: E402
from hub.bridge import Bridge  # noqa: E402
from hub.fed.runtime import Federation  # noqa: E402
from hub.profile_context import ProfileContext  # noqa: E402
from hub.receipts import ReceiptScanner  # noqa: E402
from hub.transport import TmuxTransport, TmuxBufferCleanupFailure  # noqa: E402
from hub import native_check_timing  # noqa: E402
from agentmux_windows import command as windows_command

ROOT = os.environ.get("AGENTMUX_HOME") or os.path.expanduser("~/.agentmux")
HUBDIR = os.path.join(ROOT, "hub")
SOCK = os.path.join(HUBDIR, "hub.sock")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_ROLES = {
    "lead": {"description": "Owns a team's work: decomposes team items into role items and integrates results.",
             "capabilities": ["plan", "review", "python", "bash"], "may_claim": ["team", "work"], "max_active": 3,
             "lease_s": 1800,
             "instructions": "As a lead: when you claim a team item, split it into work items for roles in your team "
                             "(agentmux hub work add --to role:team:<repo>/<team>/<role> --parent <id> ...), wait for "
                             "their results to arrive in your inbox, integrate/verify, then `agentmux hub done <id>`."},
    "worker": {"description": "Implements a work item.", "capabilities": ["python", "bash", "code"], "max_active": 1,
               "lease_s": 1200,
               "instructions": "As a worker: claim one item, do exactly what it says in the repo checkout, run its "
                               "tests, then `agentmux hub done <id> --result \"<what changed, test result>\"`."},
    "reviewer": {"description": "Reviews a submission against its acceptance criteria.",
                 "capabilities": ["review", "python", "bash"], "max_active": 1, "lease_s": 900,
                 "instructions": "As a reviewer: claim a review item, inspect the named change, run the tests, then "
                                 "`agentmux hub done <id> --result \"APPROVE: ...\"` or \"REJECT: <reasons>\"."},
    "researcher": {"description": "Answers a question with sources.", "capabilities": ["research"], "max_active": 1,
                   "lease_s": 1200, "instructions": "As a researcher: answer the item's question and cite sources."},
}

DEFAULT_CONFIG = {"node": "local", "bell_every_s": 90, "poll_s": 1.5, "max_attempts": 12,
                  "operator": "virtual:operator",
                  # TM-217: hourly online backups (24 kept), daily retention pass.
                  "backup_every_s": 3600, "backup_keep": 24,
                  "prune_every_s": 86400, "retention_events_days": 14, "retention_messages_days": 30,
                  # TM-218: set nats_url (e.g. "nats://127.0.0.1:4222") to federate this hub.
                  "nats_url": ""}


def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


def load_toml(p):
    try:
        with open(p, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}


def parent_pid(pid, *, qualified=False):
    """Parent of `pid`, or None. /proc on Linux; macOS has none, so ask ps."""
    try:
        if os.path.isdir("/proc"):
            with open(f"/proc/{pid}/stat") as f:
                return int(f.read().rsplit(")", 1)[1].split()[1])
        result = subprocess.run(["ps", "-o", "ppid=", "-p", str(pid)], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=5)
        if qualified and result.returncode != 0:
            return None
        return int(result.stdout.strip())
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None


def ancestors(pid):
    out, seen = [], set()
    while pid and pid > 1 and pid not in seen:
        seen.add(pid)
        out.append(pid)
        pid = parent_pid(pid)
    return out


def toml_dump(d):
    lines = []
    for k, v in d.items():
        lines.append(f"{k} = {json.dumps(v)}")
    return "\n".join(lines) + "\n"


class CallerClassificationUnavailable(HubError):
    """The local process could not be classified for a qualified operation."""


class HubCleanupFailure(HubError):
    """Keep the exact Hub when its cleanup cannot release borrowed sessions."""
    def __init__(self, owner):
        super().__init__('Hub cleanup is incomplete')
        self.owner = owner
        self.cleanup_owners = (owner,)
        self.sessions = ()


class AuthenticatedLocalCaller:
    """Opaque single-use proof held only inside the authenticated Hub process."""
    __slots__ = ('__weakref__',)

    def __new__(cls):
        raise TypeError('Hub authentication is required')

    def __repr__(self):
        return '<AuthenticatedLocalCaller private>'


@dataclass(frozen=True, repr=False)
class _AuthenticatedLocalRequest:
    authenticated_caller: str
    caller: str
    requested_attribution: str | None
    request: bytes
    request_digest: str
    expires_monotonic: float
    dispatch_task: object = None
    work_source_preflight: object = None

    def __repr__(self):
        return '<AuthenticatedLocalRequest private>'


def _work_request_refusal(stage, admitted):
    try:
        import math
        stages = {'current-before-expired', 'tcp-operator-changed', 'tcp-agent-changed',
            'unix-uid-changed', 'unix-identity-changed', 'current-after-expired',
            'reply-current-refused', 'retained-request-changed', 'shutdown-expired'}
        remaining = (admitted.expires_monotonic - time.monotonic()
            if type(admitted) is _AuthenticatedLocalRequest else None)
        log('authenticated work refusal', json.dumps({
            'stage': stage if type(stage) is str and stage in stages else 'other',
            'proofRemaining': remaining if type(remaining) in (int, float)
                and math.isfinite(remaining) else None}))
    except BaseException:
        pass
    return HubError('authenticated work request changed or expired')


def _kill_reply_sample(record, stage):
    """Keep a bounded private timing sample without changing the request."""
    try:
        import math
        if record is None or len(record['samples']) >= 9:
            return
        if stage not in ('late-source-start', 'late-source-return', 'dispatch-return', 'gate-request', 'maintenance-acquired', 'gate-acquired',
                         'db-submit', 'db-entry', 'check-return', 'check-refused'):
            return
        remaining = record['proof'].expires_monotonic - time.monotonic()
        if math.isfinite(remaining):
            record['samples'].append({'stage': stage, 'proofRemaining': remaining})
    except BaseException:
        pass


class _CodeShareInvocationKey:
    __slots__ = ('__weakref__',)

    def __new__(cls):
        raise TypeError('Hub dispatch is required')


@dataclass(frozen=True, repr=False)
class _CodeShareInvocation:
    request: bytes
    dispatched_request: dict
    reader: object
    writer: object
    tcp: bool
    task: object
    authenticated_caller: str
    caller: str
    request_digest: str
    proofs: set
    refreshed: set
    purpose_proofs: dict = field(default_factory=dict)
    claimed_purposes: set = field(default_factory=set)

    def __repr__(self):
        return '<CodeShareInvocation private>'

    def dispose(self):
        # Do not retain the original token or connection through a traceback.
        object.__setattr__(self, 'request', b'')
        object.__setattr__(self, 'dispatched_request', None)
        object.__setattr__(self, 'reader', None)
        object.__setattr__(self, 'writer', None)
        self.proofs.clear()
        self.purpose_proofs.clear()
        self.claimed_purposes.clear()


@dataclass(frozen=True, repr=False)
class _WorkBellRead:
    """Carry one signed readiness read through its actual terminal use."""
    commands: object
    pending: tuple
    targets: tuple
    service: object
    session: object

    def _check_service(self):
        commands = self.commands
        federation = self.service._federation
        if (self.service._client is not commands or commands._hub.fed is not federation
                or federation._work_commands is not self.service or federation.session is not self.session):
            raise HubError('work bell service changed')
        if self.session is not None:
            self.session.check_open()

    def check(self):
        commands = self.commands
        self._check_service()
        commands._disclose(None, *self.pending)
        # This method runs on the owned delivery worker, never the Store worker.
        commands._hub.dbx.submit(commands._hub._check_work_request_current,
            self.targets, None).result()
        self._check_service()
        commands._disclose(None, *self.pending)


class _WorkBellTransport(deliver._CheckedTransport):
    """Preserve terminal fencing and check the original work read at each use."""
    def __init__(self, transport, session, handle, pane_pid, cancel, work_read):
        super().__init__(transport, session, handle, pane_pid, cancel)
        self.work_read = work_read

    def check(self):
        super().check()
        self.work_read.check()
        super().check()


class Hub:
    def __init__(self, *, profile_context: ProfileContext | None = None, selected_endpoint=None, native_core=None,
                 legacy_identity=None, authority_switch_recovery=None, message_sessions=None, knowledge_sessions=None,
                 peer_control_sessions=None, policy_sessions=None, code_sessions=None, work_sessions=None):
        if native_core is not None:
            from hub.native_core_context import NativeCoreContext
            if type(native_core) is not NativeCoreContext:
                raise HubError('native core context required')
            native_core.require_operator(deadline=time.monotonic()+10)
        self._native_core = native_core
        # The protected caller supplies only display values after registration
        # and selection admission. Configuration and environment supply none.
        if selected_endpoint is not None:
            from hub.core_endpoint import CoreEndpoint
            if type(selected_endpoint) is not CoreEndpoint:
                raise HubError('selected core endpoint required')
        self._selected_endpoint = selected_endpoint
        if profile_context is not None and type(profile_context) is not ProfileContext:
            raise ValueError("invalid profile context")
        if legacy_identity is not None:
            from identity.legacy_identity import LegacyIdentityAdapter
            from hub.legacy_identity_client import EnrolledLegacyIdentityResolver
            if type(legacy_identity) not in (LegacyIdentityAdapter, EnrolledLegacyIdentityResolver):
                raise ValueError("invalid legacy identity adapter")
        self._profile_context = profile_context
        self._message_commands = None
        if message_sessions is not None:
            from capability_owner.legacy_messages_client import LegacyMessageCommandClient
            self._message_commands = LegacyMessageCommandClient(self, message_sessions)
        self._knowledge_commands = None
        if knowledge_sessions is not None:
            from capability_owner.legacy_knowledge_client import LegacyKnowledgeCommandClient
            self._knowledge_commands = LegacyKnowledgeCommandClient(self, knowledge_sessions)
            from hub.fed.config import load as load_federation_config
            settings = load_federation_config(HUBDIR)['federation']
            if self._message_commands is None and (settings.get('capture', True) or settings.get('notify_findings', True)):
                raise ValueError('qualified knowledge capture and notifications need message routes')
        self._code_commands = None
        if code_sessions is not None:
            from capability_owner.legacy_code_client import LegacyCodeCommandClient
            self._code_commands = LegacyCodeCommandClient(self, code_sessions)
        self._peer_control_commands = None
        if peer_control_sessions is not None:
            from capability_owner.peer_control_client import PeerControlCommandClient
            self._peer_control_commands = PeerControlCommandClient(self, peer_control_sessions)
        self._policy_commands = None
        if policy_sessions is not None:
            from capability_owner.legacy_policy_client import LegacyPolicyCommandClient
            self._policy_commands = LegacyPolicyCommandClient(self, policy_sessions)
        if any(client is not None for client in
                (self._message_commands, self._knowledge_commands, self._code_commands,
                 self._peer_control_commands, self._policy_commands)):
            from agentmux_contracts import strict_loads
            profiles = {tuple(strict_loads(raw)[key] for key in ('hubId', 'profileId', 'authorityId'))
                for client in (self._message_commands, self._knowledge_commands, self._code_commands,
                               self._peer_control_commands, self._policy_commands)
                if client is not None
                for _, raw in client._routes}
            if len(profiles) > 1:
                raise ValueError('qualified domain profiles do not match')
        self._legacy_identity = legacy_identity
        self._authenticated_callers = weakref.WeakKeyDictionary()
        self._authenticated_caller_context = ContextVar('hub_authenticated_caller', default=None)
        self._code_share_invocations = weakref.WeakKeyDictionary()
        self._code_share_invocation_context = ContextVar('hub_code_share_invocation', default=None)
        os.makedirs(HUBDIR, exist_ok=True)
        self.cfg = {**DEFAULT_CONFIG, **load_toml(os.path.join(HUBDIR, "config.toml"))}
        self.dbx = cf.ThreadPoolExecutor(max_workers=1, thread_name_prefix="hubdb")
        self.io = cf.ThreadPoolExecutor(max_workers=8, thread_name_prefix="hubio")
        self._authority_switch_recovery = authority_switch_recovery
        try:
            if work_sessions is None:
                self.store: Store = self.dbx.submit(Store, os.path.join(HUBDIR, "hub.db"),
                    migration_recovery=authority_switch_recovery).result()
            else:
                from hub.store import APP_ID, MIGRATIONS
                self.store = self.dbx.submit(Store.open_existing, os.path.join(HUBDIR, 'hub.db'),
                    application_id=APP_ID, user_version=len(MIGRATIONS), owner_uid=os.getuid(),
                    migration_recovery=authority_switch_recovery).result()
        except BaseException:
            self.dbx.shutdown(wait=True)
            self.io.shutdown(wait=True)
            raise
        if legacy_identity is None:
            identity_source_hub, signed_identity_expiry = None, False
        else:
            from hub.legacy_identity_client import EnrolledLegacyIdentityResolver
            identity_source_hub = legacy_identity.local_source_hub_id
            signed_identity_expiry = type(legacy_identity) is EnrolledLegacyIdentityResolver
        self.dbx.submit(self.store.configure_identity_fencing,
                        identity_source_hub, signed_identity_expiry).result()
        self.tp = TmuxTransport(logdir=os.path.join(ROOT, "logs"), native_core=native_core)
        self.inflight: set[str] = set()
        self.rings: dict[str, tuple[asyncio.Task, Event]] = {}
        self.kills: set[asyncio.Task] = set()
        self.terminating: set[str] = set()
        self.bell: dict[str, dict] = {}         # session -> {sig, at, next_check}
        self.marks: dict[str, int] = {}
        self.started: dict[str, float] = {}
        self.stop = asyncio.Event()
        self._work_storage_commands = self._local_work_commands = self._work_rpc = None
        self._work_source_binding = None
        self._work_maintenance = self._legacy_work_notices = None
        if work_sessions is not None:
            from capability_owner.legacy_work_client import LegacyWorkCommandClient
            from capability_owner.local_work_client import LocalWorkClient
            try:
                self._work_storage_commands = LegacyWorkCommandClient(self, work_sessions)
                self._local_work_commands = LocalWorkClient(self, self._work_storage_commands)
                from agentmux_contracts import strict_loads
                profiles = {tuple(strict_loads(raw)[key] for key in ('hubId', 'profileId', 'authorityId'))
                    for client in (self._message_commands, self._knowledge_commands, self._code_commands,
                                   self._peer_control_commands, self._policy_commands, self._work_storage_commands)
                    if client is not None
                    for _, raw in client._routes}
                if len(profiles) != 1:
                    raise ValueError('qualified domain profiles do not match')
            except BaseException:
                self.dbx.submit(self.store.db.close).result()
                self.dbx.shutdown(wait=True)
                self.io.shutdown(wait=True)
                raise
        self.subscribers = 0
        self.operator_sha = self._operator_token()
        self.receipts = ReceiptScanner()
        self.awaiting: dict[str, dict] = {}     # session -> first unreceived bell (TM-213)
        self.bridge = Bridge(self, self.cfg["nats_url"], names.check_part(self.cfg["node"], "node"), log) \
            if self.cfg.get("nats_url") else None
        # EP-032: cross-user federation (docs/FEDERATION.md). Always constructed so its
        # verbs answer; it only connects when federation.toml says enabled.
        try:
            self.fed = Federation(self, HUBDIR, log, profile_context=self.profile_context,
                qualified_messages=self._message_commands is not None, message_commands=self._message_commands,
                qualified_knowledge=self._knowledge_commands is not None, knowledge_commands=self._knowledge_commands,
                qualified_code=self._code_commands is not None, code_commands=self._code_commands,
                qualified_work=self._work_storage_commands is not None, work_commands=self._work_storage_commands)
            if self._peer_control_commands is not None:
                self._peer_control_commands.bind(self.fed)
            if self._policy_commands is not None:
                self._policy_commands.bind(self.fed)
            if self._work_storage_commands is not None:
                from capability_owner.work_rpc import WorkRpc
                self._work_rpc = WorkRpc(self, self._work_storage_commands, self._local_work_commands)
                from capability_owner.work_source import HubWorkSourceBinding
                self._work_source_binding = HubWorkSourceBinding(self._work_storage_commands)
        except BaseException:
            # Construction has not submitted an async command or started a
            # listener. Keep the synchronous source close on its original worker.
            for client in (self._work_storage_commands, self._peer_control_commands,
                    self._policy_commands, self._knowledge_commands, self._code_commands,
                    self._message_commands, self._work_rpc):
                if client is not None:
                    client._closed = True
            self.dbx.submit(self.store.db.close).result()
            self.dbx.shutdown(wait=True)
            self.io.shutdown(wait=True)
            raise
        self._work_start_cleanup = None
        if self._work_source_binding is None:
            self._seed_roles()

    @property
    def profile_context(self):
        return self._profile_context

    def _operator_token(self):
        p = os.path.join(HUBDIR, "operator.token")
        if not os.path.exists(p):
            write_secret(p, secrets.token_urlsafe(32))
        with open(p) as f:
            return hashlib.sha256(f.read().strip().encode()).hexdigest()

    async def db(self, fn, *a, **kw):
        source = getattr(self, '_work_source_binding', None)
        def original():
            if source is not None:
                source.check(physical=False)
                source.pin.read()
            value = fn(*a, **kw)
            if source is not None:
                source.pin.read()
                source.check(physical=False)
            return value
        future = asyncio.get_running_loop().run_in_executor(self.dbx, original)
        if source is None:
            return await future
        source.pending.add(future)
        try:
            return await asyncio.shield(future)
        except asyncio.CancelledError:
            while not future.done():
                try:
                    await asyncio.wait({future})
                except asyncio.CancelledError:
                    continue
            if not future.cancelled():
                future.exception()
            raise
        finally:
            if future.done():
                source.pending.discard(future)

    def _migration_capture(self, source_ref, application_version, expected_digest=None):
        """Capture on the sole writer executor and optionally compare a baseline."""
        from state_owner.task_migration import capture_tasks
        directory = os.path.join(HUBDIR, 'migration-captures')
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        path = os.path.join(directory, 'hub-'+secrets.token_hex(16)+'.db')
        snapshot = capture_tasks(self.store, path, source_ref=source_ref,
            application_version=application_version)
        try:
            inventory = snapshot.inventory()
            # The durable fence row changes between the baseline and fenced
            # capture. Exclude only that control row while comparing the full
            # logical SQLite dump; every product and plugin row remains.
            comparison = hashlib.sha256()
            fence_insert = 'INSERT INTO "fed_state" VALUES(\'migration.legacy-writer-fence\','
            for line in snapshot._db.iterdump():
                if line.startswith(fence_insert):
                    continue
                comparison.update(line.encode())
                comparison.update(b'\n')
            database_digest = 'sha256:' + comparison.hexdigest()
            inventory['databaseComparisonDigest'] = database_digest
            token = hashlib.sha256(b'amx-legacy-writer-fence-comparison-v1\0')
            fields = (json.dumps(inventory['sourceRef'], sort_keys=True,
                separators=(',', ':')).encode(),
                inventory['applicationVersion'].encode(), database_digest.encode())
            for field in fields:
                token.update(len(field).to_bytes(8, 'big'))
                token.update(field)
            inventory['comparisonDigest'] = 'sha256:' + token.hexdigest()
        finally:
            snapshot.close()
        if expected_digest is not None and inventory['comparisonDigest'] != expected_digest:
            raise HubError('legacy source changed before migration fence')
        return {'path': path, 'inventory': inventory}

    async def capture_legacy_migration_baseline(self, *, source_ref, application_version):
        """Create the immutable comparison point without fencing the source."""
        return await self.db(self._migration_capture, source_ref, application_version)

    async def fence_legacy_writer_and_capture(self, *, source_ref, application_version,
                                                expected_digest):
        """Fence after earlier writes, then capture and compare on the same executor."""
        if (type(expected_digest) is not str or len(expected_digest) != 71
                or not expected_digest.startswith('sha256:')):
            raise HubError('legacy migration comparison digest is invalid')
        try:
            bytes.fromhex(expected_digest[7:])
        except ValueError:
            raise HubError('legacy migration comparison digest is invalid') from None
        def fenced_capture():
            fence = self.store.fence_legacy_writer()
            captured = self._migration_capture(source_ref, application_version, expected_digest)
            return {'fence': fence, 'capture': captured}
        return await self.db(fenced_capture)

    async def recover_legacy_writer(self, fence_id, permit=None):
        """Recover an aborted pre-cutover fence through the original writer owner."""
        if getattr(self, '_authority_switch_recovery', None) is None:
            return await self.db(self.store.recover_legacy_writer, fence_id)
        fence = await self.db(self.store.migration_fence_status)
        token = await self._authority_switch_recovery.authorize(
            self.store, fence, fence_id, permit)
        return await self.db(self.store.recover_legacy_writer, fence_id, token)

    async def legacy_writer_fence_status(self):
        """Return the durable recovery handle after a failed fenced capture."""
        return await self.db(self.store.migration_fence_status)

    @staticmethod
    def _identity_bindings(resolution):
        """Return bindings for display while retaining signed envelopes for writes."""
        from identity.legacy_identity import VerifiedLegacyAliasResolution
        return resolution.bindings if type(resolution) is VerifiedLegacyAliasResolution else resolution

    async def _resolve_identity_target(self, target, *, allow_remote=False):
        """Resolve through the live Store, then bind its exact registration generation."""
        if self._legacy_identity is not None:
            from agentmux_contracts import ContractError
            # A direct address carries an exact alias. Keep it before canonical
            # routing replaces a legacy name with its session. Role and team
            # addresses have no alias, so their expanded registrations remain
            # eligible for any active mapping of the same generation.
            direct_registration = await self.db(self.store.registration, target, True)
        else:
            direct_registration = None
        try:
            canonical = await self.db(self.store.canonical_target, target, self.virtual_names())
        except HubError:
            if (self._legacy_identity is None or not allow_remote
                    or type(target) is not str or not target.startswith('agent:')):
                raise
            try:
                canonical = str(names.parse_address(target))
            except (TypeError, ValueError):
                raise HubError('invalid remote agent address') from None
        if self._legacy_identity is None or canonical.startswith('virtual:'):
            return canonical, ()
        try:
            if direct_registration is not None:
                return canonical, await self._legacy_identity.bind((direct_registration,))
            try:
                registrations = await self.db(self.store.recipient_registrations, canonical)
            except HubError:
                if not (allow_remote and canonical.startswith('agent:')):
                    raise
                registrations = ()
            if registrations:
                return canonical, await self._legacy_identity.bind(registrations)
            if allow_remote and canonical.startswith('agent:'):
                return canonical, await self._legacy_identity.bind((), remote_address=canonical)
            raise HubError('no enrolled identity satisfies recipient')
        except ContractError as exc:
            raise HubError(exc.code) from None

    async def ingest_message(self, envelope):
        """Admit a remote message through current authority before store mutation."""
        if self._legacy_identity is None:
            return await self.db(self.store.ingest_message, envelope)
        from agentmux_contracts import ContractError
        try:
            registration = await self.db(self.store.registration, envelope.get('target', ''))
            if registration is None:
                return None
            resolution = await self._legacy_identity.admit_remote(
                registration, envelope.get('legacyIdentity'))
            from identity.legacy_identity import VerifiedLegacyAliasResolution
            supplied = resolution if type(resolution) is VerifiedLegacyAliasResolution else (resolution,)
            return await self.db(self.store.ingest_message, envelope, supplied)
        except (ContractError, HubError, AttributeError, TypeError):
            return None

    async def _current_identity_target(self, target, *, allow_remote=False):
        """Read current authority twice and retain the original requested alias."""
        selected, _ = await self._resolve_identity_target(target, allow_remote=allow_remote)
        current, bindings = await self._resolve_identity_target(target, allow_remote=allow_remote)
        if current != selected:
            raise HubError('legacy identity recipient changed')
        return current, bindings

    async def _post_current(self, sender, target, kind, body, ref=None, work_id=None,
                            idem_key=None, *, _work_reply=False, _registration_guard=None, **kwargs):
        """Post an internal Hub message through the same enrolled recipient fence."""
        selected, bindings = await self._current_identity_target(
            target, allow_remote=bool(kwargs.get('remote_ok')))
        if _work_reply:
            commands = self._work_storage_commands
            pending = commands._disclosures.get(asyncio.current_task())
            if pending is None:
                raise HubError('work notification authority is unavailable')
            self._check_work_response()
            targets = tuple(getattr(self, '_work_read_targets', {}).get(asyncio.current_task(), {}).items())
            identity = getattr(self, '_work_reply_identity', {}).get(asyncio.current_task())
            def post_result():
                self._check_work_request_current(targets, identity)
                commands._disclose(None, *pending)
                return self.store.post(sender, selected, kind, body, ref, work_id, idem_key,
                    identity_bindings=bindings, **kwargs)
            async with self._native_work_check_turn():
                result = await commands._owned_db(post_result)
            self._check_work_response()
            return result
        if _registration_guard is not None:
            session, generation = _registration_guard
            def post_registration():
                with self.store.tx():
                    current = self.store.agent(session)
                    if current is None or current['generation'] != generation:
                        raise HubError('registration changed before its control message')
                    return self.store.post(sender, selected, kind, body, ref, work_id, idem_key,
                        identity_bindings=bindings, **kwargs)
            return await self.db(post_registration)
        return await self.db(self.store.post, sender, selected, kind, body, ref, work_id,
            idem_key, identity_bindings=bindings, **kwargs)

    # -- roles --------------------------------------------------------------------------
    def _seed_roles(self):
        d = os.path.join(ROOT, "roles")
        os.makedirs(d, exist_ok=True)
        for name, spec in DEFAULT_ROLES.items():
            p = os.path.join(d, f"{name}.toml")
            if not os.path.exists(p):
                with open(p, "w") as f:
                    f.write(toml_dump({"name": name, **spec}))

    def resolve_role(self, repo, role):
        g = load_toml(os.path.join(ROOT, "roles", f"{role}.toml"))
        o = load_toml(os.path.join(ROOT, "repos", repo, "roles", f"{role}.toml"))
        if not g and not o:
            raise HubError(f"unknown role {role!r}: create {ROOT}/roles/{role}.toml")
        return {**g, **o, "name": role, "override": bool(o)}

    # -- identity ------------------------------------------------------------------------
    def peer(self, sock: socket.socket):
        if hasattr(socket, "SO_PEERCRED"):
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, _gid = struct.unpack("3i", creds)
            return pid, uid
        # macOS has no SO_PEERCRED. The kernel still vouches, in two calls at SOL_LOCAL (0):
        # LOCAL_PEERPID (2) for the pid, LOCAL_PEERCRED (1) for a struct xucred whose
        # second field is the uid. Python names only the latter, so both are spelled out.
        pid = struct.unpack("i", sock.getsockopt(0, 2, struct.calcsize("i")))[0]
        _version, uid = struct.unpack("2I", sock.getsockopt(0, socket.LOCAL_PEERCRED, 76)[:8])
        return pid, uid

    def identify(self, pid):
        """(session|None, in_pane:bool). A caller inside ANY tmux pane that is not a
        registered agent is 'unregistered' - it may not act as the operator."""
        if getattr(self, '_native_core', None) is not None:
            return self.identify_qualified(pid)
        chain = set(ancestors(pid))
        by_pid = {a["pane_pid"]: a["session"] for a in self.store.agents(live_only=True) if a["pane_pid"]}
        for p in chain:
            if p in by_pid:
                return by_pid[p], True
        try:
            out = subprocess.run(["tmux", "-L", self.tp.socket, "list-panes", "-a", "-F", "#{pane_pid}"],
                                 capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=5).stdout
            pane_pids = {int(x) for x in out.split()}
        except Exception:
            pane_pids = set()
        return None, bool(chain & pane_pids)

    # -- socket server ------------------------------------------------------------------
    def identify_qualified(self, pid):
        """Require complete ancestry and a successful pane classification."""
        native_core = getattr(self, '_native_core', None)
        if native_core is not None:
            return self._identify_native_core(pid, native_core)
        chain, seen = [], set()
        if type(pid) is not int or pid <= 1:
            raise CallerClassificationUnavailable('caller ancestry unavailable')
        while pid > 1:
            if pid in seen or len(chain) >= 256:
                raise CallerClassificationUnavailable('caller ancestry unavailable')
            seen.add(pid)
            chain.append(pid)
            pid = parent_pid(pid, qualified=True)
            if type(pid) is not int or pid < 0:
                raise CallerClassificationUnavailable('caller ancestry unavailable')
        by_pid = {a['pane_pid']:a['session'] for a in self.store.agents(live_only=True) if a['pane_pid']}
        for ancestor in chain:
            if ancestor in by_pid:
                return by_pid[ancestor], True
        try:
            result = subprocess.run(['tmux','-L',self.tp.socket,'list-panes','-a','-F','#{pane_pid}'],
                capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=5)
            if result.returncode != 0:
                raise ValueError()
            pane_pids = {int(value) for value in result.stdout.split()}
            if any(value <= 0 for value in pane_pids):
                raise ValueError()
        except (OSError, ValueError, subprocess.SubprocessError):
            raise CallerClassificationUnavailable('caller pane classification unavailable') from None
        return None, bool(set(chain) & pane_pids)

    def _identify_native_core(self, pid, native_core):
        sample = native_check_timing.sample
        sample('identify-start')
        try:
            with native_core.classification(deadline=time.monotonic()+10):
                return self._classify_native_caller(pid, native_core, sample)
        except Exception:
            sample('identify-refused')
            raise CallerClassificationUnavailable('caller pane classification unavailable') from None

    def _classify_native_caller(self, pid, native_core, sample):
        """Classify inside one bracketed native recheck; any failure refuses."""
        proof = native_core.caller(pid, deadline=time.monotonic()+10)
        sample('caller-return')
        chain = {item.pid for item in proof.processes}
        by_pid = {agent['pane_pid']: agent['session']
                  for agent in self.store.agents(live_only=True) if agent['pane_pid']}
        sample('agents-return')
        for item in proof.processes:
            if item.pid in by_pid:
                sample('identify-return')
                return by_pid[item.pid], True
        if proof.in_pane:
            sample('identify-return')
            return None, True
        result = native_core.tmux(self.tp.socket, ('list-panes', '-a', '-F', '#{pane_pid}'), timeout=5)
        if result.returncode == 0:
            pane_pids = {int(value) for value in result.stdout.split()}
            if any(value <= 0 for value in pane_pids):
                raise ValueError()
            sample('identify-return')
            return None, bool(chain & pane_pids)
        # Outside-pane authority comes from the admitted complete chain above.
        # A non-connectable endpoint is not a dead server or empty inventory.
        sample('not-connectable-start')
        if not native_core.transport_not_connectable(self.tp.socket):
            raise ValueError()
        sample('not-connectable-return')
        fresh = native_core.caller(pid, deadline=time.monotonic()+10)
        sample('fresh-caller-return')
        if fresh != proof or fresh.in_pane:
            raise ValueError()
        sample('identify-return')
        return None, False

    async def caller_of(self, req, writer, tcp):
        """Who is calling. Unix socket: the kernel vouches (process ancestry, R-ID-1).
        TCP: nothing vouches, so a token is required and `as` is never honored."""
        _, caller = await self._caller_identity(req, writer, tcp, qualified=False)
        return caller

    async def authenticate_caller(self, req, writer, tcp):
        """Authenticate existing socket/token credentials, retaining operator identity."""
        if not isinstance(req, dict):
            raise HubError('invalid request')
        # Snapshot before authentication awaits; no caller mutation can change it.
        encoded = json.dumps(req, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(encoded) > 65536:
            raise HubError('request too large')
        req = json.loads(encoded)
        binding = getattr(self, '_work_source_binding', None)
        preflight = None
        selected_ping = (not tcp and req.get('verb') == 'ping'
                         and self._selected_core_context() is not None)
        selected_spawn = (not tcp and req.get('verb') == 'spawn'
                          and getattr(self, '_native_core', None) is not None
                          and self._selected_core_context() is not None)
        if not tcp and (req.get('verb') == 'adopt' or selected_ping or selected_spawn) and binding is not None:
            _, uid = self.peer(writer.get_extra_info("socket"))
            if uid != os.getuid():
                raise HubError("wrong uid")
            await binding.verify()
            preflight = binding
        authenticated, caller = await self._caller_identity(req, writer, tcp, qualified=True)
        if preflight is not None:
            preflight.check()
        selected = self._selected_core_context()
        expires = time.monotonic() + 5
        if selected is not None and selected.expires_monotonic is not None:
            expires = min(expires, selected.expires_monotonic)
        snapshot = {key:value for key,value in req.items() if key != 'token'}
        retained = json.dumps(snapshot, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        proof = object.__new__(AuthenticatedLocalCaller)
        self._authenticated_callers[proof] = _AuthenticatedLocalRequest(authenticated, caller, req.get('as'),
            retained, hashlib.sha256(retained).hexdigest(), expires,
            weakref.ref(asyncio.current_task()), preflight)
        return proof

    async def _caller_identity(self, req, writer, tcp, *, qualified):
        if tcp:
            tok = req.get("token") or ""
            if not tok:
                raise HubError("token required on TCP (agentmux hub token shows where yours is)")
            sha = hashlib.sha256(tok.encode()).hexdigest()
            if hmac.compare_digest(sha, self.operator_sha):
                authenticated = 'operator'
            else:
                row = await self.db(self.store.q1, "SELECT session FROM agents WHERE token_sha=? AND state<>'dead'", (sha,))
                if not row:
                    raise HubError("invalid or revoked token")
                authenticated = row['session']
            caller = authenticated
        else:
            pid, uid = self.peer(writer.get_extra_info("socket"))
            if uid != os.getuid():
                raise HubError("wrong uid")
            async with self._native_work_check_turn():
                session, in_pane = await self.db(self.identify_qualified if qualified else self.identify, pid)
            authenticated = session or ('unregistered' if in_pane else 'operator')
            if req.get('as') and in_pane:
                raise HubError("--as is only for the operator, not from inside an agent pane (R-ID-1)")
            caller = req.get('as') or authenticated
        return authenticated, caller

    def _consume_authenticated_caller(self, proof, *, purpose=None):
        if type(proof) is not AuthenticatedLocalCaller:
            raise HubError('authenticated caller proof required')
        panel = getattr(self, '_panel_proof_owners', {}).get(proof)
        owner = getattr(self, '_code_share_proof_owners', {}).get(proof)
        if panel is not None:
            group, expected = panel
            if (purpose != expected or not group['active']
                    or group['task']() is not asyncio.current_task()):
                raise HubError('authenticated caller proof purpose mismatch')
        elif owner is not None:
            invocation, expected = owner
            if purpose != expected or self._current_code_share_invocation() is not invocation:
                raise HubError('authenticated caller proof purpose mismatch')
        elif purpose is not None:
            raise HubError('authenticated caller proof purpose mismatch')
        record = self._authenticated_callers.get(proof)
        if (panel is None and owner is None and record is not None
                and json.loads(record.request).get('verb') == 'fed_panel'):
            self._check_panel_dispatch(proof, record)
        admitted = self._authenticated_callers.pop(proof, None)
        if admitted is None or time.monotonic() >= admitted.expires_monotonic:
            raise HubError('authenticated caller proof unavailable')
        return admitted

    def _check_panel_dispatch(self, proof, record):
        held = getattr(self, '_panel_dispatches', {}).get(proof)
        if (held is None or record.dispatch_task is None
                or record.dispatch_task() is not asyncio.current_task()
                or held[0]() is not asyncio.current_task() or held[1] != record.request_digest):
            raise HubError('original panel dispatch is required')

    @contextmanager
    def _panel_callers(self, caller):
        """Split this exact panel dispatch into fixed-expiry domain read proofs."""
        original = self.current_authenticated_caller()
        record = self._authenticated_callers.get(original)
        if (record is None or record.dispatch_task is None
                or record.dispatch_task() is not asyncio.current_task()):
            raise HubError('original panel dispatch is required')
        self._check_panel_dispatch(original, record)
        admitted = self._consume_authenticated_caller(original)
        request = json.loads(admitted.request)
        if request.get('verb') != 'fed_panel' or admitted.caller != caller:
            raise HubError('original panel dispatch is required')
        owners = getattr(self, '_panel_proof_owners', None)
        if owners is None:
            owners = self._panel_proof_owners = weakref.WeakKeyDictionary()
        group = {'active': True, 'task': admitted.dispatch_task}
        proofs = {}
        token = self._authenticated_caller_context.set(None)
        try:
            for domain in ('knowledge', 'code', 'work'):
                proof = object.__new__(AuthenticatedLocalCaller)
                self._authenticated_callers[proof] = admitted
                owners[proof] = (group, 'panel-' + domain)
                proofs[domain] = proof
            yield proofs
        finally:
            group['active'] = False
            for proof in proofs.values():
                self._authenticated_callers.pop(proof, None)
                owners.pop(proof, None)
            self._authenticated_caller_context.reset(token)

    def current_authenticated_caller(self):
        """Return this dispatch's proof to a trusted adapter, never to wire data."""
        proof = self._authenticated_caller_context.get()
        admitted = self._authenticated_callers.get(proof) if proof is not None else None
        if admitted is None or time.monotonic() >= admitted.expires_monotonic:
            raise HubError('authenticated caller proof unavailable')
        return proof

    def _admit_local_work(self, verb, arguments, caller):
        """Bind an owner read to this exact authenticated local request."""
        admitted = self._consume_authenticated_caller(self.current_authenticated_caller())
        request = json.loads(admitted.request)
        if (admitted.dispatch_task is None or admitted.dispatch_task() is not asyncio.current_task()
                or admitted.caller != caller or request.get('verb') != verb
                or request.get('args', {}) != arguments):
            raise HubError('authenticated work request does not match')
        remaining = admitted.expires_monotonic - time.monotonic()
        if remaining <= 0:
            raise HubError('authenticated work request expired')
        self._work_storage_commands._remember((), datetime.now(timezone.utc) + timedelta(seconds=remaining))
        return admitted

    async def _work_on_behalf(self, admitted):
        if admitted.authenticated_caller == admitted.caller:
            return None
        if admitted.authenticated_caller != 'operator':
            raise HubError('authenticated work caller does not match')
        target = self.need_agent(admitted.caller)
        row = await self._work_storage_commands._owned_db(self.store.agent, target)
        if (row is None or row['state'] == 'dead'
                or time.monotonic() >= admitted.expires_monotonic):
            raise HubError('work target is unavailable or request expired')
        if not hasattr(self, '_work_read_targets'):
            self._work_read_targets = weakref.WeakKeyDictionary()
        targets = self._work_read_targets.setdefault(asyncio.current_task(), {})
        if target in targets and targets[target] != row['generation']:
            raise HubError('work target registration changed')
        targets[target] = row['generation']
        self._local_work_commands.confirm_disclosure()
        return {'session': target, 'generation': row['generation']}

    async def _qualified_work_readiness(self, actor, target, repository=None):
        commands = self._work_storage_commands
        original = await commands._owned_db(self.store.agent, target)
        if original is None or original['state'] == 'dead':
            raise HubError('work target is unavailable')
        if not hasattr(self, '_work_read_targets'):
            self._work_read_targets = weakref.WeakKeyDictionary()
        targets = self._work_read_targets.setdefault(asyncio.current_task(), {})
        if target in targets and targets[target] != original['generation']:
            raise HubError('work target registration changed')
        targets[target] = original['generation']
        result = await self._local_work_commands.readiness(actor, target, repository)
        await self._check_work_targets()
        return self._local_work_commands.confirm_disclosure(result)

    @asynccontextmanager
    async def _native_work_check_turn(self, *, foreground=False):
        commands = getattr(self, '_work_storage_commands', None)
        if getattr(self, '_native_core', None) is None or commands is None:
            yield
            return
        # Never hold this interval across a signed Work call or process launch.
        # Finish whole maintenance reads before taking individual transports.
        async with self._maintenance_for_work().native_check_turn(foreground=foreground):
            if foreground:
                try:
                    task = asyncio.current_task()
                    timing = getattr(self, '_kill_reply_timings', {}).get(task)
                    identity = getattr(self, '_work_reply_identity', {}).get(task)
                    if timing is not None and identity is not None and timing['proof'] is identity[0]:
                        _kill_reply_sample(timing, 'maintenance-acquired')
                except BaseException:
                    pass
            async with commands.native_check_turn():
                yield

    async def _check_work_targets(self, *, kill_request=None):
        targets = tuple(getattr(self, '_work_read_targets', {}).get(asyncio.current_task(), {}).items())
        identity = getattr(self, '_work_reply_identity', {}).get(asyncio.current_task())
        if not targets and identity is None:
            return
        timing = None
        try:
            candidate = getattr(self, '_kill_reply_timings', {}).get(asyncio.current_task())
            if candidate is not None and identity is not None and candidate['proof'] is identity[0]:
                timing = candidate
        except BaseException:
            pass
        foreground = False
        completion = None
        if kill_request is not None:
            if (identity is None or identity[0] is not kill_request or identity[1]
                    or kill_request.dispatch_task is None
                    or kill_request.dispatch_task() is not asyncio.current_task()
                    or getattr(self, '_native_core', None) is None
                    or self._selected_core_context() is None
                    or json.loads(kill_request.request).get('verb') != 'kill'):
                raise HubError('authenticated work request is required')
            foreground = True
            maintenance = self._maintenance_for_work()
            reservation = maintenance._kill_admission_turn
            task = asyncio.current_task()
            if reservation is not None and reservation['owner'] is task and 'completed' in reservation:
                completion = (maintenance, reservation, task, reservation['completed'], reservation['identities'])
        _kill_reply_sample(timing, 'gate-request')
        async with self._native_work_check_turn(foreground=foreground):
            _kill_reply_sample(timing, 'gate-acquired')
            if timing is None and completion is None:
                await self._work_storage_commands._owned_db(self._check_work_request_current, targets, identity)
            else:
                def checked():
                    _kill_reply_sample(timing, 'db-entry')
                    native = None
                    if timing is not None:
                        native = timing.setdefault('native', {'proof': timing['proof'], 'samples': []})
                    try:
                        with native_check_timing.recording(native):
                            result = self._check_work_request_current(targets, identity)
                        if completion is not None:
                            owner, reservation, task, expected, identities = completion
                            if (owner._kill_admission_turn is not reservation or reservation['owner'] is not task
                                    or owner._completed_kill(expected['physical']['target']['session'], identities) != expected):
                                raise HubError('completed termination changed before disclosure')
                            if time.monotonic() >= identity[0].expires_monotonic:
                                raise _work_request_refusal('current-after-expired', identity[0])
                    except BaseException:
                        _kill_reply_sample(timing, 'check-refused')
                        raise
                    _kill_reply_sample(timing, 'check-return')
                    return result
                _kill_reply_sample(timing, 'db-submit')
                await self._work_storage_commands._owned_db(checked)
        self._local_work_commands.confirm_disclosure()

    def _check_work_request_current(self, targets, identity):
        """Check local request authority on the original Store worker."""
        if identity is None or native_check_timing.active():
            return self._check_work_request_current_once(targets, identity)
        # Every caller without its own record (kill keeps one) logs a refused
        # check's private native timing once. The check itself is unchanged.
        native = {'proof': identity[0], 'samples': []}
        try:
            with native_check_timing.recording(native):
                native_check_timing.sample('current-start')
                return self._check_work_request_current_once(targets, identity)
        except BaseException:
            try:
                if native['samples']:
                    log('native check timing', json.dumps({'refused': True, 'samples': native['samples'],
                        'request': native_check_timing.request_samples(identity[0])}))
            except BaseException:
                pass
            raise

    def _check_work_request_current_once(self, targets, identity):
        if identity is not None:
            admitted, tcp, credential = identity
            if time.monotonic() >= admitted.expires_monotonic:
                raise _work_request_refusal('current-before-expired', admitted)
            if tcp:
                if admitted.authenticated_caller == 'operator':
                    if not hmac.compare_digest(credential, self.operator_sha):
                        raise _work_request_refusal('tcp-operator-changed', admitted)
                else:
                    row = self.store.q1("SELECT session FROM agents WHERE token_sha=? AND state<>'dead'", (credential,))
                    if row is None or row['session'] != admitted.authenticated_caller:
                        raise _work_request_refusal('tcp-agent-changed', admitted)
            else:
                pid, uid = credential
                if uid != os.getuid():
                    raise _work_request_refusal('unix-uid-changed', admitted)
                session, in_pane = self.identify_qualified(pid)
                authenticated = session or ('unregistered' if in_pane else 'operator')
                caller = admitted.requested_attribution or authenticated
                if ((authenticated, caller) != (admitted.authenticated_caller, admitted.caller)
                        or in_pane and admitted.requested_attribution):
                    raise _work_request_refusal('unix-identity-changed', admitted)
        for target, generation in targets:
            row = self.store.agent(target)
            if row is None or row['state'] == 'dead' or row['generation'] != generation:
                raise HubError('work target registration changed')
        if identity is not None and time.monotonic() >= admitted.expires_monotonic:
            raise _work_request_refusal('current-after-expired', admitted)

    async def _qualified_work_gate(self, arguments, caller):
        admitted = self._admit_local_work('fed_gate', arguments, caller)
        who = arguments.get('session') if caller == 'operator' and arguments.get('session') else caller
        actor = admitted.authenticated_caller
        active = (set() if who in ('operator', 'virtual:operator') else
            {row['id'] for row in (await self._qualified_work_readiness(actor, who))['active']})
        rows = await self._local_work_commands.list(actor)
        await self._check_work_targets()
        remote = []
        for row in rows:
            if row['id'] in active and row.get('origin_peer'):
                flags = json.loads(row.get('fed_flags') or '{}')
                remote.append({'id': row['id'], 'title': row['title'], 'peer': row['origin_peer'],
                    'privileged_ok': bool(flags.get('privileged_ok'))})
        return self._local_work_commands.confirm_disclosure({'session': who, 'remote_work': remote,
            'privileged_allowed': all(row['privileged_ok'] for row in remote)})

    def _check_work_response(self, value=None, *, finish=False):
        commands = getattr(self, '_work_storage_commands', None)
        if commands is None or asyncio.current_task() not in commands._disclosures:
            return value
        identity = getattr(self, '_work_reply_identity', {}).get(asyncio.current_task())
        if identity is not None:
            admitted, tcp, credential = identity
            if (time.monotonic() >= admitted.expires_monotonic
                    or tcp and admitted.authenticated_caller == 'operator'
                        and not hmac.compare_digest(credential, self.operator_sha)):
                raise _work_request_refusal('reply-current-refused', admitted)
        rpc = getattr(self, '_work_rpc', None)
        if rpc is not None and rpc.operation_id is not None:
            result = rpc.check_response(value, finish=finish)
        else:
            result = commands.finish_disclosure(value) if finish else commands.confirm_disclosure(value)
        if finish:
            getattr(self, '_work_read_targets', {}).pop(asyncio.current_task(), None)
            getattr(self, '_work_reply_identity', {}).pop(asyncio.current_task(), None)
        return result

    def code_share_dispatch_active(self):
        context = getattr(self, '_code_share_invocation_context', None)
        key = None if context is None else context.get()
        invocations = getattr(self, '_code_share_invocations', {})
        invocation = invocations.get(key) if type(key) is _CodeShareInvocationKey else None
        return invocation is not None and invocation.task is asyncio.current_task()

    def _current_code_share_invocation(self):
        if not self.code_share_dispatch_active():
            raise HubError('original code-share connection is required')
        key = self._code_share_invocation_context.get()
        invocation = self._code_share_invocations[key]
        if (not invocation.request or invocation.writer.is_closing() or invocation.reader.at_eof()
                or json.dumps(invocation.dispatched_request, sort_keys=True,
                    separators=(',', ':'), allow_nan=False).encode() != invocation.request):
            raise HubError('original code-share connection is unavailable')
        return invocation

    async def code_share_caller(self, purpose):
        """Use one authentication for two bounded, purpose-specific admissions."""
        if purpose not in ('storage', 'handoff'):
            raise HubError('code-share caller purpose unavailable')
        invocation = self._current_code_share_invocation()
        verb = json.loads(invocation.request).get('verb')
        if verb == 'fed_code_fetch' and purpose != 'storage':
            raise HubError('code caller purpose unavailable')
        if purpose in invocation.claimed_purposes:
            raise HubError('code-share caller proof was already used')
        if not invocation.refreshed:
            # Set before authentication yields. A failure cannot authorize a
            # second refresh or preserve an older proof from this invocation.
            invocation.refreshed.add(True)
            for original in invocation.proofs:
                self._authenticated_callers.pop(original, None)
            proof = await self.authenticate_caller(json.loads(invocation.request), invocation.writer, invocation.tcp)
            invocation.proofs.add(proof)
            try:
                if self._current_code_share_invocation() is not invocation:
                    raise HubError('original code-share connection is unavailable')
                current = self._authenticated_callers[proof]
                if ((current.authenticated_caller, current.caller, current.request_digest) != (
                        invocation.authenticated_caller, invocation.caller, invocation.request_digest)):
                    raise HubError('code-share caller changed; retry the command')
                owners = getattr(self, '_code_share_proof_owners', None)
                if owners is None:
                    owners = self._code_share_proof_owners = weakref.WeakKeyDictionary()
                for selected in (('storage',) if verb == 'fed_code_fetch' else ('storage', 'handoff')):
                    bounded = object.__new__(AuthenticatedLocalCaller)
                    invocation.proofs.add(bounded)
                    invocation.purpose_proofs[selected] = bounded
                    self._authenticated_callers[bounded] = current
                    owners[bounded] = (invocation, selected)
            finally:
                self._authenticated_callers.pop(proof, None)
        proof = invocation.purpose_proofs.get(purpose)
        admitted = None if proof is None else self._authenticated_callers.get(proof)
        if admitted is None or time.monotonic() >= admitted.expires_monotonic:
            raise HubError('code-share caller proof unavailable')
        invocation.claimed_purposes.add(purpose)
        self._authenticated_caller_context.set(proof)
        return proof

    async def reauthenticate_code_share_caller(self):
        """Return the handoff proof from this invocation's single refresh."""
        return await self.code_share_caller('handoff')

    async def handle_conn(self, reader, writer, tcp=False):
        try:
            async with AsyncExitStack() as request_stack:
                return await self._handle_conn(reader, writer, tcp, request_stack)
        finally:
            # Original DB/source work and request reservations have joined before
            # this single private emission. Missing stages stay unobserved.
            try:
                timing = getattr(self, '_kill_reply_timings', {}).pop(asyncio.current_task(), None)
                if timing is not None:
                    log('kill reply timing', json.dumps({'connection': timing['connection'],
                        'samples': timing['samples']}))
                    native = timing.get('native')
                    if native is not None and native['samples']:
                        log('native check timing', json.dumps({'connection': timing['connection'],
                            'samples': native['samples']}))
            except BaseException:
                pass

    async def _handle_conn(self, reader, writer, tcp, request_stack):
        caller = None
        request_reserved = False
        work_rpc = getattr(self, '_work_rpc', None)
        work_operation_id = None
        authenticated_request = None
        proof = context_token = None
        code_key = code_token = invocation = None
        try:
            raw = await asyncio.wait_for(reader.readline(), 30)
            req = json.loads(raw or b"{}")
            if (isinstance(req, dict) and req.get('verb') in ('spawn', 'adopt', 'kill')
                    and getattr(self, '_work_storage_commands', None) is not None):
                arguments = req.get('args', {})
                if not isinstance(arguments, dict):
                    raise HubError('invalid lifecycle arguments')
                if 'operation_id' in arguments:
                    operation_id = arguments.pop('operation_id')
                    if 'operationId' in req and req['operationId'] != operation_id:
                        raise HubError('conflicting lifecycle operation IDs')
                    req['operationId'] = operation_id
                work_operation_id = req.setdefault('operationId', secrets.token_hex(16))
            if isinstance(req, dict):
                if req.get('verb') in ('work_add', 'claim', 'heartbeat', 'release',
                        'work_cancel', 'claim_path', 'fed_work_add'):
                    arguments = req.get('args', {})
                    if not isinstance(arguments, dict):
                        raise HubError('invalid work arguments')
                    if work_rpc is None and ('operationId' in req or 'operation_id' in arguments):
                        raise HubError('this Hub does not support work operation recovery IDs')
                    if 'operation_id' in arguments:
                        operation_id = arguments.pop('operation_id')
                        if 'operationId' in req and req['operationId'] != operation_id:
                            raise HubError('conflicting work operation IDs')
                        req['operationId'] = operation_id
                    if work_rpc is not None:
                        work_operation_id = req.setdefault('operationId', secrets.token_hex(16))
                    if work_rpc is not None and (not isinstance(work_operation_id, str)
                            or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', work_operation_id) is None):
                        raise HubError('invalid work operation ID')
            if isinstance(req, dict) and req.get('verb') in ('fed_code_share', 'fed_code_fetch'):
                arguments = req.get('args', {})
                if isinstance(arguments, dict) and 'operation_id' in arguments:
                    operation_id = arguments.pop('operation_id')
                    if 'operationId' in req and req['operationId'] != operation_id:
                        raise HubError('conflicting code operation IDs')
                    req['operationId'] = operation_id
                if 'operationId' in req:
                    if (not isinstance(req['operationId'], str)
                            or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', req['operationId']) is None):
                        raise HubError('invalid code operation ID')
                    if getattr(self, '_code_commands', None) is None:
                        raise HubError('this Hub does not support code operation recovery IDs')
            original_request = (json.dumps(req, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
                if isinstance(req, dict) and req.get('verb') in ('fed_code_share', 'fed_code_fetch') else None)
            native_discovery = (not tcp and isinstance(req, dict) and req.get('verb') == 'ping'
                and getattr(self, '_native_core', None) is not None
                and self._selected_core_context() is not None)
            native_spawn = (not tcp and isinstance(req, dict) and req.get('verb') == 'spawn'
                and getattr(self, '_native_core', None) is not None
                and self._selected_core_context() is not None)
            native_kill = (not tcp and isinstance(req, dict) and req.get('verb') == 'kill'
                and getattr(self, '_native_core', None) is not None
                and self._selected_core_context() is not None)
            if not tcp and isinstance(req, dict) and (req.get('verb') == 'adopt'
                    or native_discovery or native_spawn or native_kill):
                maintenance = self._maintenance_for_work()
                if maintenance is not None:
                    encoded = json.dumps(req, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
                    if len(encoded) > 65536:
                        raise HubError('request too large')
                    if self.peer(writer.get_extra_info('socket'))[1] != os.getuid():
                        raise HubError('wrong uid')
                    retained = {key: value for key, value in req.items() if key != 'token'}
                    encoded = json.dumps(retained, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
                    turn = (maintenance.discovery_request_turn(encoded) if native_discovery
                            else maintenance.spawn_request_turn(encoded) if native_spawn
                            else maintenance.kill_admission_turn(encoded) if native_kill
                            else maintenance.adoption_request_turn(encoded))
                    await request_stack.enter_async_context(turn)
                    request_reserved = True
                    self._selected_core_context()
            try:
                proof = await self.authenticate_caller(req, writer, tcp)
                authenticated_request = self._authenticated_callers[proof]
                native_check_timing.start_request(authenticated_request)
                caller = authenticated_request.caller
                if native_kill:
                    try:
                        if not hasattr(self, '_kill_reply_timings'):
                            self._kill_reply_timings = weakref.WeakKeyDictionary()
                        self._kill_reply_timings[asyncio.current_task()] = {
                            'proof': authenticated_request, 'connection': secrets.token_hex(8), 'samples': []}
                    except BaseException:
                        pass
                if work_operation_id is not None or getattr(self, '_selected_endpoint', None) is not None:
                    if not hasattr(self, '_work_reply_identity'):
                        self._work_reply_identity = weakref.WeakKeyDictionary()
                    credential = (hashlib.sha256((req.get('token') or '').encode()).hexdigest() if tcp
                        else self.peer(writer.get_extra_info('socket')))
                    self._work_reply_identity[asyncio.current_task()] = (authenticated_request, tcp, credential)
            except CallerClassificationUnavailable:
                # Legacy commands retain their prior classification behavior.
                # Qualified adapters receive no proof and must refuse admission.
                caller = await self.caller_of(req, writer, tcp)
            context_token = self._authenticated_caller_context.set(proof)
            if isinstance(req, dict) and req.get('verb') == 'fed_panel' and proof is not None:
                if not hasattr(self, '_panel_dispatches'):
                    self._panel_dispatches = weakref.WeakKeyDictionary()
                self._panel_dispatches[proof] = (weakref.ref(asyncio.current_task()),
                    self._authenticated_callers[proof].request_digest)
            if original_request is not None and proof is not None:
                if not hasattr(self, '_code_share_invocations'):
                    self._code_share_invocations = weakref.WeakKeyDictionary()
                    self._code_share_invocation_context = ContextVar('hub_code_share_invocation', default=None)
                admitted = self._authenticated_callers[proof]
                code_key = object.__new__(_CodeShareInvocationKey)
                invocation = _CodeShareInvocation(original_request, req, reader, writer, tcp,
                    asyncio.current_task(), admitted.authenticated_caller, admitted.caller,
                    admitted.request_digest, {proof}, set())
                self._code_share_invocations[code_key] = invocation
                code_token = self._code_share_invocation_context.set(code_key)
                original_request = None
            if req.get("verb") == "subscribe":
                return await self.subscribe(writer, caller, req.get("args", {}), request=req, tcp=tcp, reader=reader)
            native_check_timing.request_sample('dispatch-start')
            res = await self.dispatch(req.get("verb", ""), req.get("args", {}), caller)
            native_check_timing.request_sample('dispatch-return')
            try:
                _kill_reply_sample(getattr(self, '_kill_reply_timings', {}).get(asyncio.current_task()),
                    'dispatch-return')
            except BaseException:
                pass
            commands = getattr(self, '_work_storage_commands', None)
            if commands is not None and asyncio.current_task() in commands._disclosures:
                if authenticated_request is None:
                    raise HubError('authenticated work request is required')
                if not hasattr(self, '_work_reply_identity'):
                    self._work_reply_identity = weakref.WeakKeyDictionary()
                credential = (hashlib.sha256((req.get('token') or '').encode()).hexdigest() if tcp
                    else self.peer(writer.get_extra_info('socket')))
                previous = self._work_reply_identity.get(asyncio.current_task())
                if (req.get('as') != authenticated_request.requested_attribution
                        or previous is not None and (
                            previous[0] is not authenticated_request
                            or previous[1:] != (tcp, credential))):
                    raise _work_request_refusal('retained-request-changed', authenticated_request)
                self._work_reply_identity[asyncio.current_task()] = (authenticated_request, tcp, credential)
                # The original Store worker checks the current caller and targets
                # together. Repeating native classification here spends the same
                # request's remaining validity before that final check.
                if native_kill:
                    await self._check_work_targets(kill_request=authenticated_request)
                else:
                    await self._check_work_targets()
                self._check_work_response()
            resp = {"ok": True, "caller": caller, "result": res}
            if work_operation_id is not None:
                resp['operationId'] = work_operation_id
        except BaseException as e:
            if not isinstance(e, Exception):
                if work_rpc is not None:
                    work_rpc.abort()
                writer.close()
                raise
            if isinstance(e, HubError):
                resp = {"ok": False, "error": str(e)}
            else:
                try:
                    from hub.client_launch_session import ApplicationSessionFailure
                    if type(e) is ApplicationSessionFailure:
                        diagnostic = getattr(e, '_command_diagnostic', None)
                        if diagnostic is not None:
                            log("application command diagnostic", json.dumps(diagnostic))
                except BaseException:
                    pass
                log("error", type(e).__name__, e)
                try:
                    phases = native_check_timing.current_request_samples()
                    if phases:
                        log('request timing', json.dumps({'refused': True, 'request': phases}))
                except BaseException:
                    pass
                resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        finally:
            if code_token is not None:
                self._code_share_invocation_context.reset(code_token)
            if code_key is not None:
                self._code_share_invocations.pop(code_key, None)
            if invocation is not None:
                for replacement in invocation.proofs:
                    self._authenticated_callers.pop(replacement, None)
                invocation.dispatched_request.pop('token', None)
                invocation.dispose()
                invocation = None
            if context_token is not None:
                self._authenticated_caller_context.reset(context_token)
            if proof is not None:
                self._authenticated_callers.pop(proof, None)
                getattr(self, '_panel_dispatches', {}).pop(proof, None)
        shutdown_accepted = False
        try:
            encoded = (json.dumps(resp, default=str) + "\n").encode()
            if resp.get('ok'):
                self._check_work_response()
                if req.get('verb') == 'shutdown':
                    from hub.core_endpoint import selected_core_request
                    selected = selected_core_request.get()
                    if selected is not None:
                        selected.endpoint.check()
                    if (authenticated_request is not None
                            and time.monotonic() >= authenticated_request.expires_monotonic):
                        raise _work_request_refusal('shutdown-expired', authenticated_request)
                    shutdown_accepted = True
            writer.write(encoded)
            if shutdown_accepted:
                # Stop invalidates the original reply guards. Finish this bounded
                # attempt first, then let the existing owner join all cleanup.
                await asyncio.wait_for(writer.drain(), 5)
            elif request_reserved:
                remaining = (5 if authenticated_request is None or not resp.get('ok') else
                    max(0, authenticated_request.expires_monotonic - time.monotonic()))
                await asyncio.wait_for(writer.drain(), remaining)
            else:
                await writer.drain()
            if resp.get('ok'):
                self._check_work_response(finish=True)
                if work_rpc is not None and work_rpc.operation_id is not None:
                    await work_rpc.delivered()
            code_commands = getattr(self, '_code_commands', None)
            if (code_commands is not None and resp.get('ok')
                    and req.get('verb') in ('fed_code_share', 'fed_code_fetch')):
                await code_commands.confirm_local_reply()
        finally:
            try:
                if work_rpc is not None:
                    work_rpc.abort()
                writer.close()
            finally:
                if shutdown_accepted:
                    self.stop.set()

    async def subscribe(self, writer, caller, a, *, request=None, tcp=False, reader=None):
        """A long-lived stream: one JSON line per event, until the client hangs up.
          mail   (default) new deliveries for the caller, plus claimable-work changes
          events the audit trail (operator only) - what the dashboard follows
        The first line acknowledges the subscription. Nothing is marked received by a
        subscription: only `inbox` (the agent reading its mail) is evidence of that."""
        stream = a.get("stream", "mail")
        who = "virtual:operator" if caller == "operator" else caller
        if caller == "unregistered":
            raise HubError("unregistered pane")
        if stream == "events" and caller != "operator":
            raise HubError("the events stream is operator-only")
        if getattr(self, '_work_storage_commands', None) is not None:
            return await self._subscribe_work(writer, caller, a, request, tcp, reader)
        self.subscribers += 1

        async def send(obj):
            writer.write((json.dumps(obj, default=str) + "\n").encode())
            await writer.drain()

        try:
            await send({"ok": True, "caller": caller, "subscribed": stream})
            if stream == "events":
                since = int(a.get("since", 0))
                while not self.stop.is_set():
                    for e in await self.db(self.store.events, since, 500):
                        since = e["seq"]
                        await send({"event": e})
                    await asyncio.sleep(0.5)
            else:
                seen, claim_sig = set(), None
                while not self.stop.is_set():
                    for d in await self.db(self.store.pending_for, who):
                        if d["message_id"] not in seen:
                            seen.add(d["message_id"])
                            m = await self.db(self.store.q1, "SELECT id, sender, kind, ref, body, body_ref, created "
                                              "FROM messages WHERE id=?", (d["message_id"],))
                            await send({"message": m})
                    if not who.startswith("virtual:"):
                        cl = await self.db(self.store.claimable, who)
                        sig = tuple(c["id"] for c in cl)
                        if sig != claim_sig:
                            claim_sig = sig
                            await send({"claimable": cl})
                    await asyncio.sleep(0.5)
        except (ConnectionError, BrokenPipeError):
            pass
        finally:
            self.subscribers -= 1
            try:
                writer.close()
            except Exception:
                pass

    async def _joined_work_poll(self, awaitable):
        """Cancel and join this exact poll before its stream or loop ends."""
        original = asyncio.create_task(awaitable)
        cancelled = None
        while not original.done():
            try:
                await asyncio.shield(original)
            except asyncio.CancelledError as failure:
                cancelled = failure
                original.cancel()
        if cancelled is not None:
            try:
                original.result()
            except BaseException:
                pass
            raise cancelled
        return original.result()

    def _discard_work_read(self):
        """End private metadata for an abandoned read without renewing it."""
        task = asyncio.current_task()
        self._work_storage_commands._disclosures.pop(task, None)
        getattr(self, '_work_read_targets', {}).pop(task, None)
        getattr(self, '_work_reply_identity', {}).pop(task, None)

    async def _subscribe_work(self, writer, caller, arguments, request, tcp, reader):
        original = self._consume_authenticated_caller(self.current_authenticated_caller())
        if (request is None or reader is None or original.dispatch_task() is not asyncio.current_task()
                or original.caller != caller or json.loads(original.request) !=
                    {key: value for key, value in request.items() if key != 'token'}):
            raise HubError('original subscription request is required')
        # Retain the original credentials privately; no wire frame receives them.
        request = json.loads(json.dumps(request, allow_nan=False))
        stream = arguments.get('stream', 'mail')
        state = {'first': True, 'seen': set(), 'claim_sig': None,
            'since': int(arguments.get('since', 0)) if stream == 'events' else 0}
        self.subscribers += 1
        try:
            while not self.stop.is_set() and not writer.is_closing() and not reader.at_eof():
                await self._joined_work_poll(self._subscription_work_poll(
                    writer, caller, arguments, request, tcp, original, stream, state, reader))
                await asyncio.sleep(0.5)
        except (ConnectionError, BrokenPipeError):
            pass
        finally:
            self.subscribers -= 1
            writer.close()

    async def _subscription_work_poll(self, writer, caller, arguments, request, tcp,
                                      original, stream, state, reader):
        proof = None
        context = None
        try:
            proof = await self.authenticate_caller(request, writer, tcp)
            admitted = self._authenticated_callers[proof]
            if (admitted.authenticated_caller, admitted.caller, admitted.request_digest) != (
                    original.authenticated_caller, original.caller, original.request_digest):
                raise HubError('subscription caller changed')
            context = self._authenticated_caller_context.set(proof)
            self._admit_local_work('subscribe', arguments, caller)
            if not hasattr(self, '_work_reply_identity'):
                self._work_reply_identity = weakref.WeakKeyDictionary()
            credential = (hashlib.sha256((request.get('token') or '').encode()).hexdigest() if tcp
                else self.peer(writer.get_extra_info('socket')))
            self._work_reply_identity[asyncio.current_task()] = (admitted, tcp, credential)

            async def send(value):
                await self._check_work_targets()
                encoded = (json.dumps(value, default=str) + '\n').encode()
                self._check_work_response()
                if writer.is_closing() or reader.at_eof():
                    raise ConnectionError('subscription connection closed')
                writer.write(encoded)
                await writer.drain()
                self._check_work_response()

            if state['first']:
                await send({'ok': True, 'caller': caller, 'subscribed': stream})
                state['first'] = False
            commands = self._work_storage_commands
            if stream == 'events':
                for event in await commands._owned_db(self.store.events, state['since'], 500):
                    await send({'event': event})
                    state['since'] = event['seq']
            else:
                who = 'virtual:operator' if caller == 'operator' else caller
                for delivery in await commands._owned_db(self.store.pending_for, who):
                    if delivery['message_id'] not in state['seen']:
                        message = await commands._owned_db(self.store.q1,
                            'SELECT id, sender, kind, ref, body, body_ref, created FROM messages WHERE id=?',
                            (delivery['message_id'],))
                        await send({'message': message})
                        state['seen'].add(delivery['message_id'])
                if not who.startswith('virtual:'):
                    value = await self._qualified_work_readiness(admitted.authenticated_caller, who)
                    claimable = value['claimable']
                    signature = tuple(row['id'] for row in claimable)
                    if signature != state['claim_sig']:
                        await send({'claimable': claimable})
                        state['claim_sig'] = signature
            await self._check_work_targets()
            self._check_work_response(finish=True)
        finally:
            if context is not None:
                self._authenticated_caller_context.reset(context)
            if proof is not None:
                self._authenticated_callers.pop(proof, None)
            self._discard_work_read()

    def need_agent(self, caller):
        if caller in ("operator", "unregistered") or caller.startswith("virtual:"):
            raise HubError(f"this verb needs a registered agent; caller is {caller}")
        return caller

    def need_operator(self, caller):
        if caller != "operator":
            raise HubError(f"operator-only verb; caller is {caller}")

    def sender_of(self, caller):
        if caller == "unregistered":
            raise HubError("unregistered pane: spawn agents with `agentmux hub spawn` (or adopt them)")
        if caller == "operator":
            return "virtual:operator"
        return caller if caller.startswith("virtual:") else f"agent:{caller}"

    def _selected_core_context(self):
        from hub.core_endpoint import selected_core_request, SelectedCoreRequest, CoreSetupRequired
        selected = selected_core_request.get()
        if selected is None:
            return None
        if (type(selected) is not SelectedCoreRequest
                or selected.endpoint is not self._selected_endpoint
                or selected.task is not asyncio.current_task()
                or selected.endpoint.route.binding['repositories'].get(selected.root) != selected.repository):
            raise HubError('selected repository context changed')
        selected.endpoint.check()
        if (selected.expires_monotonic is not None
                and time.monotonic() >= selected.expires_monotonic):
            raise CoreSetupRequired()
        return selected

    def _selected_core_repository(self, caller):
        selected = self._selected_core_context()
        if selected is None:
            return None
        proof = self.current_authenticated_caller()
        admitted = self._authenticated_callers[proof]
        if admitted.caller != caller or caller == 'unregistered':
            raise HubError('selected repository caller is unavailable')
        if self._local_work_commands is None or self._work_rpc is None:
            raise HubError('selected repository owners are unavailable')
        self._work_storage_commands._remember((), datetime.now(timezone.utc)
            + timedelta(seconds=admitted.expires_monotonic - time.monotonic()))
        return selected.repository

    async def _selected_address_guard(self, address):
        """Keep current identity authority and the exact expanded registrations."""
        target, bindings = await self._current_identity_target(address)
        recipients = await self.db(self.store.recipients, target)
        registrations = []
        for recipient in recipients:
            if recipient.startswith('virtual:'):
                continue
            row = await self.db(self.store.registration, recipient)
            if row is None:
                raise HubError('selected message registration is unavailable')
            registrations.append(row)
        repositories = {row.repository for row in registrations}

        def check():
            if self.store.canonical_target(address, self.virtual_names()) != target:
                raise HubError('selected message address changed')
            if self.store.recipients(target) != recipients:
                raise HubError('selected message recipients changed')
            for original in registrations:
                if self.store.registration(original.canonical_session) != original:
                    raise HubError('selected message registration changed')
            self.store._check_identity_bindings(target, recipients, bindings, False)
            return list(recipients)
        return repositories, check

    async def _selected_message_guard(self, rows, caller, repository, *, actor=None, classify=False):
        """Check stored message relationships; an opaque ref never supplies scope."""
        if actor is None:
            proof = self.current_authenticated_caller()
            actor = self._authenticated_callers[proof].authenticated_caller
        addresses, guards, eligible = {}, [], True
        for row in rows:
            repositories = set()
            for address in (row['sender'], row['target']):
                if address not in addresses:
                    addresses[address] = await self._selected_address_guard(address)
                scopes, guard = addresses[address]
                repositories.update(scopes)
                guards.append(guard)
            foreign = bool(repositories) and repository not in repositories
            if row.get('work_id') and not (classify and foreign):
                work = await self._local_work_commands.show(actor, row['work_id'], repository=repository)
                if work is None:
                    raise HubError('selected message Work link is unavailable')
                repositories.add(work['repo'])
            if classify and foreign:
                eligible = False
            elif repositories != {repository}:
                raise HubError('message does not belong to the selected repository')
            if row.get('id'):
                recipients = await self.db(self.store._recips_of, row['id'])
                def check_deliveries(mid=row['id'], original=recipients):
                    if self.store._recips_of(mid) != original:
                        raise HubError('selected message recipients changed')
                guards.append(check_deliveries)
                for recipient in recipients:
                    address = recipient if recipient.startswith('virtual:') else 'agent:' + recipient
                    if address not in addresses:
                        addresses[address] = await self._selected_address_guard(address)
                    scopes, guard = addresses[address]
                    if scopes - {repository} and not (classify and foreign):
                        raise HubError('message has recipients outside the selected repository')
                    guards.append(guard)

        commands = self._work_storage_commands
        task = asyncio.current_task()
        pending = commands._disclosures.get(task)
        identity = getattr(self, '_work_reply_identity', {}).get(task)
        targets = tuple(getattr(self, '_work_read_targets', {}).get(task, {}).items())
        if pending is None or identity is None:
            raise HubError('selected message authority is unavailable')

        def check():
            self._check_work_request_current(targets, identity)
            commands._disclose(None, *pending)
            for guard in guards:
                guard()
        return (check, eligible) if classify else check

    async def _selected_ack(self, who, ids, caller, repository, *, actor=None):
        # This includes acknowledged and dead deliveries and does not page by age.
        # Keep the original ids for Store.ack's duplicate, ordering and no-op rules.
        def read():
            if not ids:
                return []
            return self.store.q('SELECT m.*, d.recipient, d.state AS delivery_state '
                'FROM messages m JOIN deliveries d ON d.message_id=m.id '
                'WHERE d.recipient=? AND m.id IN (' + ','.join('?' for _ in ids) + ')',
                (who, *ids))
        rows = await self.db(read)
        guard = await self._selected_message_guard(rows, caller, repository, actor=actor)
        def acknowledge():
            with self.store.tx():
                guard()
                if read() != rows:
                    raise HubError('selected message delivery changed')
                return self.store.ack(who, ids)
        async with self._native_work_check_turn():
            return await self.db(acknowledge)

    async def _selected_status_events(self, verb, arguments, caller, repository):
        """Project original Hub records and authorized Work into one repository."""
        admitted = self._admit_local_work(verb, arguments, caller)
        work = await self._local_work_commands.list(admitted.authenticated_caller, repository=repository)
        work_ids = {row['id'] for row in work}
        commands = self._work_storage_commands
        pending = commands._disclosures[asyncio.current_task()]
        identity = self._work_reply_identity[asyncio.current_task()]

        def read():
            self._check_work_request_current((), identity)
            commands._disclose(None, *pending)
            s = self.store
            with s.tx():
                agents = {row['session']: row for row in s.agents()}
                deliveries = s.q('SELECT * FROM deliveries ORDER BY updated DESC, message_id, recipient')
                by_message = {}
                for delivery in deliveries:
                    by_message.setdefault(delivery['message_id'], []).append(delivery)

                def agent_repository(session):
                    row = agents.get(session)
                    return {row['repo']} if row is not None else set()

                def address_repositories(address):
                    try:
                        parsed = names.parse_address(address)
                    except (TypeError, ValueError):
                        return set()
                    if parsed.kind == 'agent':
                        return agent_repository(parsed.name)
                    if parsed.kind == 'team':
                        return {parsed.scope}
                    if parsed.kind == 'role':
                        if parsed.scope.startswith('team:'):
                            return {parsed.scope[5:].split('/')[0]}
                        if parsed.scope != '*' and not parsed.scope.startswith('group:'):
                            return {parsed.scope}
                    return set()

                selected_messages = set()
                for message in s.q('SELECT id, sender, target, work_id FROM messages'):
                    scopes = address_repositories(message['sender']) | address_repositories(message['target'])
                    for delivery in by_message.get(message['id'], ()):
                        scopes.update(agent_repository(delivery['recipient']))
                    if message['work_id'] in work_ids:
                        scopes.add(repository)
                    elif message['work_id']:
                        # An unresolved typed link must not acquire address scope.
                        continue
                    if scopes == {repository}:
                        selected_messages.add(message['id'])
                selected_deliveries = [row for row in deliveries if row['message_id'] in selected_messages]
                if verb == 'events':
                    delivery_ids = {row['message_id'] + '>' + row['recipient'] for row in selected_deliveries}
                    rows = s.events(int(arguments.get('since', 0)), -1, arguments.get('entity'), False)
                    rows = [row for row in rows if
                        row['entity'] == 'work' and row['entity_id'] in work_ids
                        or row['entity'] in ('agent', 'bell') and agent_repository(row['entity_id']) == {repository}
                        or row['entity'] == 'delivery' and row['entity_id'] in delivery_ids]
                    limit = int(arguments.get('limit', 200))
                    if limit >= 0:
                        rows = rows[-limit:] if arguments.get('tail') and limit else rows[:limit]
                    return rows
                counts, work_counts = {}, {}
                for row in selected_deliveries:
                    counts[row['state']] = counts.get(row['state'], 0) + 1
                for row in work:
                    work_counts[row['state']] = work_counts.get(row['state'], 0) + 1
                return {
                    'agents': [{key: row[key] for key in ('session', 'cli', 'state', 'state_note',
                        'last_output', 'last_bell')} for row in agents.values() if row['repo'] == repository],
                    'deliveries': counts, 'work': work_counts,
                    'dead': [{key: row[key] for key in ('message_id', 'recipient', 'last_error')}
                        for row in selected_deliveries if row['state'] == 'dead'][:20],
                    'repos': [row['repo'] for row in s.q('SELECT repo FROM repos WHERE repo=?', (repository,))],
                    'teams': s.q('SELECT repo, team, lead_role FROM teams WHERE repo=? ORDER BY team', (repository,)),
                }
        async with self._native_work_check_turn():
            result = await self.db(read)
        return self._local_work_commands.confirm_disclosure(result)

    async def dispatch(self, verb, a, caller):
        repository = self._selected_core_repository(caller)
        message_admission = None
        if self._work_source_binding is not None:
            binding = self._work_source_binding
            proof = self._authenticated_caller_context.get()
            admitted = self._authenticated_callers.get(proof) if type(proof) is AuthenticatedLocalCaller else None
            retained = json.loads(admitted.request) if admitted is not None else {}
            if ((verb == 'adopt' or verb == 'ping' and repository is not None
                    or verb == 'spawn' and repository is not None
                    and getattr(self, '_native_core', None) is not None)
                    and admitted is not None
                    and admitted.authenticated_caller == admitted.caller == caller == 'operator'
                    and admitted.expires_monotonic > time.monotonic()
                    and admitted.dispatch_task is not None
                    and admitted.dispatch_task() is asyncio.current_task()
                    and admitted.work_source_preflight is binding
                    and retained.get('verb') == verb and retained.get('args') == a):
                # Only this original request completed its source read before authentication.
                # Signed effects and disclosures still check their current authority and source.
                binding.check()
            else:
                timing = None
                try:
                    timing = getattr(self, '_kill_reply_timings', {}).get(asyncio.current_task())
                    if timing is not None and timing['proof'] is not admitted:
                        timing = None
                except BaseException:
                    timing = None
                _kill_reply_sample(timing, 'late-source-start')
                await binding.verify()
                _kill_reply_sample(timing, 'late-source-return')
        if repository is not None:
            if a.get('repo') not in (None, repository):
                raise HubError('selected repository does not match')
            if verb in ('spawn', 'adopt') and a.get('repo') != repository:
                raise HubError('selected repository does not match')
            if verb == 'kill':
                target = await self.db(self.store.agent, a.get('session'))
                if target is None or target['repo'] != repository:
                    raise HubError('selected repository does not match')
            if verb in ('post', 'inbox', 'ack') and caller not in ('operator', 'federation'):
                # Carry a signed worker read through the existing message guards.
                # A retained caller deadline alone does not grant message access.
                message_admission = self._admit_local_work(verb, a, caller)
                await self._qualified_work_readiness(message_admission.authenticated_caller, caller, repository)
        if verb in ('spawn', 'adopt', 'kill'):
            maintenance = self._maintenance_for_work()
            if maintenance is not None:
                await maintenance.admit(verb, a, caller)
        s = self.store
        rpc = getattr(self, '_work_rpc', None)
        if rpc is not None:
            from capability_owner.work_rpc import WORK_RPC_VERBS
            if verb in WORK_RPC_VERBS:
                result = await rpc.execute(self.current_authenticated_caller(), verb, a, caller,
                    **({} if repository is None else {'repository': repository}))
                if not rpc.replayed() and verb == 'release':
                    await self._notify_work_owner(result, caller, repository=repository)
                    await self.fed.local_event('work_released', result, require_completion=True)
                return await rpc.complete(result)
        if verb.startswith("fed_"):
            return await self.fed.dispatch(verb, a, caller)
        if verb == "ping":
            result = {"pong": now(), "caller": caller}
            if rpc is not None:
                result['workOperationIds'] = True
            if self._work_storage_commands is not None:
                result['lifecycleOperationIds'] = True
            return result
        if verb == "token":
            # Where the caller's own token lives - never the token itself over the wire.
            if caller == "operator":
                return {"path": os.path.join(HUBDIR, "operator.token")}
            ag = await self.db(s.agent, self.need_agent(caller))
            return {"path": os.path.join(ROOT, "repos", ag["repo"], "agents", f"{ag['role']}-{ag['agent']}", "run", "token")}
        if verb == "whoami":
            ag = await self.db(s.agent, caller) if caller not in ("operator", "unregistered") else None
            return {"caller": caller, "agent": ag,
                    "eligible": await self.db(s.eligible_targets, caller) if ag else []}
        if verb == "status" and a.get("bridge"):
            if repository is not None:
                raise HubError('bridge status is shared; use the explicit Hub administration route')
            b = self.bridge
            return {"node": self.cfg["node"], "nats_url": self.cfg.get("nats_url") or None,
                    "connected": bool(b and b.connected), "stats": b.stats if b else {},
                    "role_subjects": sorted(b.role_subs) if b else []}
        if verb == "status":
            if repository is not None:
                return await self._selected_status_events(verb, a, caller, repository)
            if getattr(self, '_local_work_commands', None) is not None:
                admitted = self._admit_local_work(verb, a, caller)
                result = await self.db(s.status, include_work=False)
                native_check_timing.request_sample('status-db-return')
                rows = await self._local_work_commands.list(admitted.authenticated_caller, repository=repository)
                native_check_timing.request_sample('work-list-return')
                for row in rows:
                    result['work'][row['state']] = result['work'].get(row['state'], 0) + 1
                return self._local_work_commands.confirm_disclosure(result)
            return await self.db(s.status)
        if verb == "events":
            if repository is not None:
                return await self._selected_status_events(verb, a, caller, repository)
            return await self.db(s.events, int(a.get("since", 0)), int(a.get("limit", 200)), a.get("entity"),
                                 bool(a.get("tail")))
        if verb == 'migration_capture':
            self.need_operator(caller)
            return await self.capture_legacy_migration_baseline(source_ref=a['sourceRef'],
                application_version=a['applicationVersion'])
        if verb == 'migration_fence':
            self.need_operator(caller)
            return await self.fence_legacy_writer_and_capture(source_ref=a['sourceRef'],
                application_version=a['applicationVersion'], expected_digest=a['expectedDigest'])
        if verb == 'migration_status':
            self.need_operator(caller)
            return await self.legacy_writer_fence_status()
        if verb == 'migration_recover':
            self.need_operator(caller)
            return await self.recover_legacy_writer(a['fenceId'])
        if verb == "repo_add":
            self.need_operator(caller)
            repo = names.check_part(a["repo"], "repo", a.get("accept_normalized", False))
            paths = [os.path.realpath(p) for p in a.get("paths", [])]
            aliases = list(a.get("aliases", []))
            for p in paths:
                rem = subprocess.run(["git", "-C", p, "remote", "get-url", "origin"], capture_output=True, text=True)
                if rem.returncode == 0 and rem.stdout.strip():
                    aliases.append(normalize_remote(rem.stdout.strip()))
            r = await self.db(s.repo_add, repo, a.get("title"), paths, aliases, a.get("groups", []))
            os.makedirs(os.path.join(ROOT, "repos", repo, "agents"), exist_ok=True)
            os.makedirs(os.path.join(ROOT, "repos", repo, "roles"), exist_ok=True)
            os.makedirs(os.path.join(ROOT, "repos", repo, "teams"), exist_ok=True)
            with open(os.path.join(ROOT, "repos", repo, "repo.toml"), "w") as f:
                f.write(toml_dump({"repo": repo, "title": a.get("title") or repo, "paths": paths,
                                   "aliases": sorted(set(aliases)), "groups": a.get("groups", [])}))
            return r
        if verb == "team_add":
            if caller != "operator":
                me = await self.db(s.agent, caller)
                if not me or me["role"] != "lead":
                    raise HubError("only the operator or a lead may create teams")
            t = await self.db(s.team_add, a["repo"], a["team"], a.get("members", []), a.get("lead_role", "lead"))
            with open(os.path.join(ROOT, "repos", a["repo"], "teams", f"{a['team']}.toml"), "w") as f:
                f.write(toml_dump({"team": t["team"], "lead_role": t["lead_role"], "members": t["members"]}))
            return t
        if verb == "spawn":
            self.need_operator(caller)
            return await self._owned_lifecycle_call('spawn', a)
        if verb == "kill":
            self.need_operator(caller)
            ag = await self.db(s.agent, a["session"])
            if not ag:
                raise HubError(f"no such agent {a['session']}")
            sess = ag["session"]
            # Keep this operation owned through cancellation, including its final
            # store update. A replacement registration must not inherit the result.
            if self.stop.is_set():
                raise HubError("hub is stopping")
            maintenance = self._maintenance_for_work()
            if maintenance is not None and await maintenance.confirm_completed_kill(ag):
                return {"killed": sess}
            task = asyncio.create_task(self._kill_agent(ag, a.get("reason", "operator")))
            maintenance = self._maintenance_for_work()
            if maintenance is not None:
                maintenance.inherit(task)
            if not hasattr(self, "kills"):
                self.kills = set()
            self.kills.add(task)
            task.add_done_callback(self.kills.discard)
            cancelled = False
            while True:
                try:
                    result = await asyncio.shield(task)
                    break
                except asyncio.CancelledError:
                    if task.done():
                        raise
                    cancelled = True
            if cancelled:
                raise asyncio.CancelledError
            return result
        if verb == "agents":
            rows = await self.db(s.agents, bool(a.get("live")))
            return rows if repository is None else [row for row in rows if row['repo'] == repository]
        if verb == "resolve":
            if repository is not None:
                scopes, guard = await self._selected_address_guard(a['address'])
                if scopes != {repository}:
                    raise HubError('address does not belong to the selected repository')
                return {'address': a['address'], 'recipients': await self.db(guard)}
            target, bindings = await self._resolve_identity_target(a["address"])
            bindings = self._identity_bindings(bindings)
            recipients = ([binding.canonical_session for binding in bindings] if bindings
                          else await self.db(s.recipients, target))
            return {"address": a["address"], "recipients": recipients}
        if verb == "adopt":
            self.need_operator(caller)
            return await self._owned_lifecycle_call('adopt', a)
        if verb == "retire_courier":
            self.need_operator(caller)
            return await self.retire_courier(bool(a.get("dry_run")))
        if verb == "post" and str(a.get("to", "")).startswith("peer:"):
            if repository is not None:
                raise HubError('selected repository remote messages are unavailable')
            # Another person's agent, role or operator: the federation messages plugin.
            return await self.fed.guarded(self.fed.send_message(
                caller, a["to"], a.get("kind", "note"), a.get("body", ""), a.get("ref")))
        if verb == "post":
            sender = self.sender_of(caller)
            requested_target = a["to"]
            target, bindings = await self._resolve_identity_target(requested_target, allow_remote=self.bridge is not None)
            a = {**a, "to": target}
            message_guard, previous = None, None
            if repository is not None:
                if a.get('idem_key'):
                    previous = await self.db(s.q1, 'SELECT * FROM messages WHERE sender=? AND idem_key=?',
                        (sender, a['idem_key']))
                message_guard = await self._selected_message_guard(
                    [{'sender': sender, 'target': target, 'work_id': a.get('work_id')}]
                    + ([previous] if previous else []), caller, repository,
                    actor=None if message_admission is None else message_admission.authenticated_caller)
            body = a.get("body", "")
            body_ref = None
            if message_guard is None and len(body.encode()) > int(self.cfg.get("inline_max", 4096)):
                body_ref = self._write_brief(a["to"], body)
            # The identity owner and Hub store are separate consistency domains.
            # Read current authority again immediately before the store mutation;
            # the store transaction then fences the exact registration generation.
            fresh_target, bindings = await self._resolve_identity_target(
                requested_target, allow_remote=self.bridge is not None)
            if fresh_target != a['to']:
                raise HubError('legacy identity recipient changed')
            if message_guard is not None:
                def post_selected():
                    with s.tx():
                        message_guard()
                        if a.get('idem_key') and s.q1('SELECT * FROM messages WHERE sender=? AND idem_key=?',
                                (sender, a['idem_key'])) != previous:
                            raise HubError('selected message operation changed')
                        brief = self._write_brief(target, body) if len(body.encode()) > int(
                            self.cfg.get('inline_max', 4096)) else None
                        return s.post(sender, target, a.get('kind', 'note'), body, a.get('ref'),
                            a.get('work_id'), a.get('idem_key'), brief, node=self.cfg['node'],
                            identity_bindings=bindings)
                async with self._native_work_check_turn():
                    return await self.db(post_selected)
            r = await self.db(s.post, sender, a["to"], a.get("kind", "note"), body, a.get("ref"), a.get("work_id"),
                              a.get("idem_key"), body_ref, remote_ok=self.bridge is not None,
                              node=self.cfg["node"], identity_bindings=bindings)
            return r
        if verb == "inbox":
            work_admission = message_admission or (self._admit_local_work(verb, a, caller)
                if getattr(self, '_local_work_commands', None) is not None else None)
            who = a.get("session") if caller == "operator" and a.get("session") else caller
            if who == "operator":
                who = "virtual:operator"
            if who == "unregistered":
                raise HubError("unregistered pane")
            # An operator peeking at an agent's inbox must not mark it received: only
            # the agent reading its own mail is evidence it got the message.
            peek = caller == "operator" and who != "virtual:operator"
            if peek:
                a = {**a, "ack": False}
            acked = []
            if repository is not None:
                limit = int(a.get('limit', 20))
                # Apply the selected limit after checking repository membership.
                # An older foreign page must not hide this repository's mail.
                pending = await self.db(s.inbox, who, -1, False)
                msgs, message_guards = [], []
                for row in pending:
                    guard, eligible = await self._selected_message_guard([row], caller, repository,
                        actor=work_admission.authenticated_caller, classify=True)
                    message_guards.append(guard)
                    if eligible and (limit < 0 or len(msgs) < limit):
                        msgs.append(row)
                def read_selected():
                    with s.tx():
                        for guard in message_guards:
                            guard()
                        if s.inbox(who, -1, False) != pending:
                            raise HubError('selected inbox changed')
                        ids = [m['id'] for m in msgs]
                        if not peek:
                            for mid in ids:
                                s.db.execute("UPDATE deliveries SET state='received', updated=? "
                                    "WHERE message_id=? AND recipient=? AND state NOT IN ('acked','dead','received')",
                                    (now(), mid, who))
                        done = s.ack(who, ids) if a.get('ack') else []
                        return msgs, done
                async with self._native_work_check_turn():
                    msgs, acked = await self.db(read_selected)
            else:
                msgs = await self.db(s.inbox, who, int(a.get("limit", 20)), not peek)
                if a.get("ack") and msgs:
                    acked = await self.db(s.ack, who, [m["id"] for m in msgs])
            out = {"session": who, "messages": msgs, "acked": acked}
            if not who.startswith("virtual:"):
                if work_admission is not None:
                    ready = await self._qualified_work_readiness(work_admission.authenticated_caller, who, repository)
                    out.update(claimable=ready['claimable'], active=ready['active'])
                else:
                    out["claimable"] = await self.db(s.claimable, who)
                    out["active"] = await self.db(s.q, "SELECT id, title, lease_until FROM work_items WHERE claimed_by=? "
                                                  "AND state IN ('claimed','waiting_children')", (who,))
            return out
        if verb == "ack":
            who = "virtual:operator" if caller == "operator" else self.need_agent(caller)
            if repository is not None:
                return {"acked": await self._selected_ack(who, a['ids'], caller, repository,
                    actor=None if message_admission is None else message_admission.authenticated_caller)}
            return {"acked": await self.db(s.ack, who, a["ids"])}
        if verb == "work_add" and a.get("federate") and self.fed.enabled:
            # EP-032 supersedes the TM-218 queue group when federation is configured.
            req = a.get("requirements")
            return await self.fed.guarded(self.fed.add_work(
                caller, a["to"], a["title"], a.get("body"), a.get("task_key"), req,
                int(a.get("priority", 100))))
        if verb == "work_add":
            sender = self.sender_of(caller)
            repo = a.get("repo") or self._repo_of_target(a["to"], caller)
            return await self.db(s.work_create, sender, repo, a["to"], a["title"], a.get("body"), a.get("task_key"),
                                 a.get("requirements"), int(a.get("priority", 100)), a.get("parent"),
                                 int(a.get("max_attempts", 3)), federate=bool(a.get("federate")),
                                 node=self.cfg["node"])
        if verb == "claim":
            me = self.need_agent(caller)
            return await self.db(s.claim, me, a.get("lease_s"), a.get("work_id"))
        if verb == "heartbeat":
            return {"renewed": await self.db(s.heartbeat, self.need_agent(caller), a.get("lease_s"))}
        if verb == "release":
            me = self.need_agent(caller)
            w = await self.db(s.release, me, a["work_id"], a["outcome"], a.get("result"), self.cfg["node"])
            await self._notify_work_owner(w, me)
            await self.fed.local_event("work_released", w)
            return w
        if verb == "work_cancel":
            self.need_operator(caller)
            return {"cancelled": await self.db(s.cancel, a["work_id"], a.get("reason") or "cancelled by operator")}
        if verb == "work_show":
            if getattr(self, '_local_work_commands', None) is not None:
                admitted = self._admit_local_work(verb, a, caller)
                return await self._local_work_commands.show(admitted.authenticated_caller, a['work_id'],
                    **({} if repository is None else {'repository': repository}))
            return await self.db(s.work, a["work_id"])
        if verb == "work_list":
            if getattr(self, '_local_work_commands', None) is not None:
                admitted = self._admit_local_work(verb, a, caller)
                return await self._local_work_commands.list(admitted.authenticated_caller,
                    a.get('state'), repository if repository is not None else a.get('repo'))
            return await self.db(s.work, None, a.get("state"), a.get("repo"))
        if verb == "claim_path":
            me = self.need_agent(caller)
            ag = await self.db(s.agent, me)
            return await self.db(s.claim_path, me, a.get("repo") or ag["repo"], a["path"], a.get("work_id"))
        if verb == "shutdown":
            self.need_operator(caller)
            return {"stopping": True}
        raise HubError(f"unknown verb {verb!r}")

    def _repo_of_target(self, target, caller):
        ad = names.parse_address(target)
        if ad.kind == "agent":
            return names.split_session(ad.name)[0]
        if ad.kind == "team":
            return ad.scope
        if ad.kind == "role":
            sc = ad.scope
            if sc.startswith("team:"):
                return sc[5:].split("/")[0]
            if not sc.startswith("group:") and sc != "*":
                return sc
        if caller not in ("operator", "unregistered"):
            return names.split_session(caller)[0]
        raise HubError("cannot infer repo for this target; pass --repo")

    async def _notify_work_owner(self, w, me, *, repository=None):
        """When an item finishes, tell whoever created it - and the parent's holder."""
        if not w:
            return
        body = f"work {w['id']} \"{w['title']}\" is {w['state']} (by {me})"
        if w.get("result"):
            body += f"\nresult: {w['result']}"
        targets = set()
        if w["created_by"] and w["created_by"] != f"agent:{me}":
            targets.add(w["created_by"])
        if w.get("parent_id"):
            local = getattr(self, '_local_work_commands', None)
            if local is None:
                p = await self.db(self.store.work, w["parent_id"])
            else:
                rpc = getattr(self, '_work_rpc', None)
                state = rpc._state() if rpc is not None and rpc.operation_id is not None else None
                actor = state['admitted'].authenticated_caller if state is not None else me
                p = await local.show(actor, w['parent_id'],
                    **({} if repository is None else {'repository': repository}))
            if p and p.get("claimed_by") and p["claimed_by"] != me:
                targets.add(f"agent:{p['claimed_by']}")
        for t in targets:
            if t.startswith("peer:"):
                continue                    # federated: the work plugin sends the result envelope
            try:
                await self._post_current("virtual:hub", t, "result", body, w["id"], w["id"],
                    f"result:{w['id']}:{w['state']}:{t}",
                    _work_reply=getattr(self, '_work_storage_commands', None) is not None)
            except HubError as e:
                if getattr(self, '_work_rpc', None) is not None and self._work_rpc.operation_id is not None:
                    raise
                log("notify failed", t, e)

    def _write_brief(self, to, body):
        import hashlib
        h = hashlib.sha256(body.encode()).hexdigest()[:16]
        d = os.path.join(ROOT, "briefs")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, f"{h}.md")
        with open(p, "w") as f:
            f.write(body)
        return p

    async def _kill_agent(self, ag, reason):
        sess = ag["session"]
        terminating = getattr(self, "terminating", None)
        if terminating is None:
            self.terminating = terminating = set()
        if sess in terminating:
            raise HubError("termination already in progress")
        terminating.add(sess)
        if not hasattr(self, 'kills'):
            self.kills = set()
        kill_owner = asyncio.current_task()
        self.kills.add(kill_owner)
        cancelled = False

        async def joined(awaitable):
            nonlocal cancelled
            owner = asyncio.ensure_future(awaitable)
            maintenance = self._maintenance_for_work()
            if maintenance is not None:
                maintenance.inherit(owner)
            while True:
                try:
                    return await asyncio.shield(owner)
                except asyncio.CancelledError:
                    if owner.done():
                        raise
                    cancelled = True

        try:
            maintenance = self._maintenance_for_work()
            retained = self.rings.get(sess)
            if retained:
                retained[1].set()
                await joined(retained[0])
            record, physical, request_expires = (None, True, None) if maintenance is None else await joined(
                maintenance.begin_kill(ag, reason))
            if physical:
                def terminate_original():
                    if maintenance is not None:
                        maintenance.check_kill_dispatch(record, request_expires)
                    return self.harness("kill", term(ag), expected_agent=ag)
                ok = await joined(asyncio.get_running_loop().run_in_executor(self.io, terminate_original))
                if not ok:
                    raise HubError("termination unconfirmed; registration retained")
                if maintenance is not None:
                    await joined(maintenance.confirm_kill(record))
            if not await joined(self._apply_kill(ag, reason)):
                raise HubError("registration changed; termination result not applied")
            if cancelled:
                raise asyncio.CancelledError
            return {"killed": sess}
        finally:
            terminating.discard(sess)
            self.kills.discard(kill_owner)

    async def finish_kills(self):
        """Join retained termination owners before the final store checkpoint."""
        joined = asyncio.gather(*tuple(getattr(self, "kills", ())), return_exceptions=True)
        cancelled = False
        while True:
            try:
                await asyncio.shield(joined)
                break
            except asyncio.CancelledError:
                if joined.done():
                    raise
                cancelled = True
        if cancelled:
            raise asyncio.CancelledError

    async def _apply_kill(self, ag, reason):
        maintenance = self._maintenance_for_work()
        if maintenance is None:
            return await self.db(self._record_kill, ag, reason)
        key = maintenance.metadata_key('kill-metadata',
            f"kill:{ag['session']}:{ag['generation']}:{reason}")
        prior = await self.db(self.store.q1, 'SELECT v FROM fed_state WHERE k=?', (key,))
        if prior is not None:
            current = await self.db(self.store.agent, ag['session'])
            if not self._same_registration(current, ag):
                return False
            from agentmux_contracts import strict_loads
            await maintenance.confirm_operation(strict_loads(prior['v'])['operationId'])
            return True
        # A state change during physical termination is not a replacement
        # terminal. A confirmed no-op observation may use a new authorized try.
        for attempt in range(3):
            phase = 'kill-state-' + str(attempt)
            exists, result = await maintenance.recover_phase(phase,
                'state:' + ag['session'] + ':' + str(ag['generation']))
            if exists:
                if result:
                    return await self.db(self._record_kill, ag, reason, key, maintenance.last_operation_id())
                continue
            current = await self.db(self.store.agent, ag['session'])
            if not self._same_registration(current, ag):
                return False
            if await maintenance.state(current, 'dead', 'killed by operator', phase=phase):
                return await self.db(self._record_kill, ag, reason, key, maintenance.last_operation_id())
        return False

    @staticmethod
    def _same_registration(current, original):
        return current is not None and all(current[key] == original[key]
            for key in ('handle', 'pane_pid', 'created', 'generation'))

    def _record_kill(self, ag, reason, metadata_key=None, operation_id=None):
        with self.store.tx():
            current = self.store.agent(ag["session"])
            if current is None or any(current[key] != ag[key] for key in ("handle", "pane_pid", "created")):
                return False
            qualified = getattr(self, '_work_storage_commands', None) is not None
            if qualified and (metadata_key is None or not self._same_registration(current, ag)):
                raise HubError('qualified lifecycle changes require the work owner')
            if metadata_key is not None and self.store.q1('SELECT 1 FROM fed_state WHERE k=?', (metadata_key,)):
                return True
            if not qualified:
                self.store.set_state(ag["session"], "dead", "killed by operator")
            self.store.event("agent", ag["session"], "kill", "operator", {"reason": reason})
            if metadata_key is not None:
                self.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
                    (metadata_key, json.dumps({'operationId': operation_id})))
        return True

    def harness(self, verb, *args, expected_agent=None):
        """Keep close-out and sidecar cleanup in the harness. A fallback may only
        terminate the exact original target and never confirms sidecar cleanup."""
        cmd = [os.environ.get("AGENTMUX_BIN", os.path.expanduser("~/.local/bin/agentmux")), verb, *args]
        env = {k: v for k, v in os.environ.items() if k not in ("AGENTMUX_AGENT", "AGENTMUX_KILL_EXPECTED_TARGET")}
        native_core = getattr(self, '_native_core', None)
        if native_core is not None:
            selected = native_core.harness_command(verb, args, hub_home=ROOT, socket_name=self.tp.socket)
            cmd, env = selected.arguments, selected.environment
        target = None
        if verb == "kill":
            try:
                target = self.tp.termination_target(args[0])
                if expected_agent is None or self.tp.handle(args[0]) != (expected_agent["handle"], expected_agent["pane_pid"]):
                    return False
                env["AGENTMUX_KILL_EXPECTED_TARGET"] = target
            except (OSError, RuntimeError, subprocess.SubprocessError):
                return False
        unavailable = False
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=120)
            ok = r.returncode == 0
        except FileNotFoundError:
            ok, unavailable = False, True
        except (OSError, subprocess.TimeoutExpired):
            ok = False
        if unavailable and target is not None:
            # Preserve the old fallback, but serialize it with spawn and refuse a
            # changed or unknown target. Its uncertain close-out keeps hub state.
            try:
                with open(os.path.join(ROOT, ".spawn.lock"), "a") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.tp.kill(args[0], expected=target)
            except (OSError, RuntimeError, subprocess.SubprocessError):
                pass
        return ok

    def virtual_names(self):
        return tuple(x for x in os.environ.get("AGENTMUX_VIRTUAL_AGENTS", "orchestrator").split(",") if x)

    # -- courier retirement (TM-214, PROTOCOL section 10) ---------------------------------
    async def adopt(self, a):
        legacy = a["legacy"]
        h = await asyncio.get_running_loop().run_in_executor(self.io, self.tp.handle, legacy)
        if not h:
            raise HubError(f"no live tmux session named {legacy!r} to adopt")
        repo = names.check_part(a["repo"], "repo")
        role = names.check_part(a["role"], "role")
        agent = names.check_part(a["agent"], "agent", a.get("accept_normalized", False))
        cli = a.get("cli")
        if not cli:
            try:
                with open(os.path.join(ROOT, "run", f"{legacy}.cli")) as f:
                    cli = f.read().strip() or "shell"
            except OSError:
                cli = "shell"
        snap = self.resolve_role(repo, role)
        maintenance = self._maintenance_for_work()
        adir = os.path.join(ROOT, "repos", repo, "agents", f"{role}-{agent}")
        token_path = os.path.join(adir, 'run', 'token')
        pending_token = None
        if maintenance is None:
            token = secrets.token_urlsafe(32)
        else:
            token, pending_token = await maintenance.registration_token(names.session_name(repo, role, agent), token_path)
        if maintenance is None:
            session = await self.db(self.store.adopt, legacy, repo, role, agent, cli, snap, h[0], h[1],
                                    hashlib.sha256(token.encode()).hexdigest())
        else:
            session, generation = await maintenance.register(repo, role, agent, cli, snap,
                handle=h[0], pane_pid=h[1], legacy=legacy, token_sha=hashlib.sha256(token.encode()).hexdigest())
            registered = await self.db(self.store.agent, session)
            if registered is None or registered['generation'] != generation:
                raise HubError('registration changed during adoption')
            recovered, ready = await maintenance.recover_phase('adopt-ready',
                'state:' + session + ':' + str(generation))
            if not recovered:
                ready = await maintenance.state(registered, 'ready', phase='adopt-ready')
            if not ready:
                raise HubError('registration changed during adoption')
            await self.db(self._registration_metadata, session, generation, legacy=legacy)
        for sub in ("run", "logs", "briefs", "cli"):
            os.makedirs(os.path.join(adir, sub), exist_ok=True)
        write_secret(os.path.join(adir, "run", "token"), token)
        if pending_token is not None:
            await maintenance.token_installed(pending_token, token)
        lp = os.path.join(adir, "logs", "pane.log")
        if not os.path.lexists(lp):
            os.symlink(os.path.join(ROOT, "logs", f"{legacy}.log"), lp)
        self.started[session] = 0
        cwd = (await self.db(self.store.q1, "SELECT path FROM repo_paths WHERE repo=? ORDER BY path", (repo,)) or {}).get("path", "")
        await self._post_current("virtual:hub", legacy, "control",
            welcome(session, repo, role, cwd, snap) + f"\n(You were adopted: your tmux session is still "
            f"'{legacy}', and messages to '{legacy}' reach you.)", None, None, f"welcome:{session}",
            **({} if maintenance is None else {'_registration_guard': (session, generation)}))
        result = {"session": session, "legacy": legacy, "handle": h[0], "cli": cli}
        return result

    async def retire_courier(self, dry_run=False):
        """Hand the courier's undelivered backlog to the hub, then stop the courier for
        good. Idempotent: every imported line carries an idem key built from its outbox
        inode and byte offset, so a second run imports nothing twice."""
        qdir, cdir = os.path.join(ROOT, "queue"), os.path.join(ROOT, "courier")
        report = {"imported": 0, "duplicate": 0, "unresolved": [], "no_cursor": [], "outboxes": 0}
        todo = []
        for fn in sorted(os.listdir(qdir)) if os.path.isdir(qdir) else []:
            if not fn.endswith(".jsonl") or fn == "courier.jsonl":
                continue
            path, sender = os.path.join(qdir, fn), fn[:-6]
            report["outboxes"] += 1
            try:
                st = os.lstat(path)
                with open(os.path.join(cdir, f"{sender}.cursor")) as f:
                    cur = json.load(f)
            except (OSError, ValueError):
                report["no_cursor"].append(sender)       # the courier never read it: leave it be
                continue
            off = int(cur["offset"]) if int(cur.get("ino", -1)) == st.st_ino else 0
            with open(path, "rb") as f:
                f.seek(off)
                pos = off
                for raw in f:
                    todo.append((sender, st.st_ino, pos, raw))
                    pos += len(raw)
        try:
            with open(os.path.join(cdir, "pending.jsonl"), "rb") as f:
                for i, raw in enumerate(f):
                    todo.append(("pending", 0, i, raw))
        except OSError:
            pass
        for sender, ino, pos, raw in todo:
            try:
                rec = json.loads(raw)
                rec = rec.get("message", rec) if isinstance(rec, dict) else {}
            except ValueError:
                continue
            rcpt, src = rec.get("recipient"), rec.get("sender") or sender
            if not rcpt:
                continue
            try:
                to, bindings = await self._resolve_identity_target(rcpt, allow_remote=self.bridge is not None)
            except HubError:
                report["unresolved"].append(f"{src}->{rcpt}")
                continue
            src_ag = await self.db(self.store.agent, src)
            frm = f"agent:{src_ag['session']}" if src_ag else f"virtual:legacy_{names.normalize(src) or 'unknown'}"
            kind = rec.get("kind") if await self.db(self.store.q1, "SELECT 1 FROM message_kinds WHERE kind=?",
                                                    (rec.get("kind"),)) else "note"
            if dry_run:
                report["imported"] += 1
                continue
            try:
                fresh_to, bindings = await self._resolve_identity_target(
                    rcpt, allow_remote=self.bridge is not None)
            except HubError:
                report['unresolved'].append(f"{src}->{rcpt}")
                continue
            if fresh_to != to:
                report['unresolved'].append(f"{src}->{rcpt}")
                continue
            r = await self.db(self.store.post, frm, to, kind, rec.get("body") or "", rec.get("ref"), None,
                              f"import:{sender}:{ino}:{pos}", identity_bindings=bindings)
            report["duplicate" if r["duplicate"] else "imported"] += 1
        if not dry_run:
            report["courier_stopped"] = await asyncio.get_running_loop().run_in_executor(
                self.io, self.harness, "courier", "stop")
            with open(os.path.join(HUBDIR, "courier-retired"), "w") as f:
                json.dump({**report, "at": now()}, f)
        return report

    # -- spawn --------------------------------------------------------------------------
    async def _owned_lifecycle_call(self, verb, arguments):
        if verb not in ('spawn', 'adopt'):
            raise HubError('unsupported lifecycle call')
        maintenance = self._maintenance_for_work()
        if maintenance is None:
            return await (self.spawn(arguments) if verb == 'spawn' else self.adopt(arguments))
        if not hasattr(self, '_maintenance_calls'):
            self._maintenance_calls = set()
        caller = asyncio.current_task()
        self._maintenance_calls.add(caller)
        async def original():
            try:
                return await execute_original()
            finally:
                if verb == 'spawn':
                    maintenance.release_spawn_preparation(original_finished=True)
        async def execute_original():
            async with (maintenance.adoption_turn() if verb == 'adopt' else nullcontext()):
                refusal = await maintenance.saved_spawn_refusal() if verb == 'spawn' else None
                if refusal is not None:
                    maintenance.retain_spawn_disclosure()
                    await maintenance.confirm_result(verb, refusal)
                    if await maintenance.saved_spawn_refusal() != refusal:
                        raise HubError('original spawn result changed')
                    return refusal
                saved = await maintenance.saved_result(verb)
                if saved is None:
                    result = await (self.spawn(arguments) if verb == 'spawn' else self.adopt(arguments))
                    await maintenance.save_result(verb, result)
                else:
                    result = saved['result']
                    if verb == 'spawn':
                        maintenance.retain_spawn_disclosure()
                await maintenance.confirm_result(verb, result)
                return result
        task = asyncio.create_task(original())
        maintenance.inherit(task)
        if verb == 'adopt':
            maintenance.reserve_adoption_child(task)
        if verb == 'spawn':
            try:
                maintenance.reserve_spawn_child(task)
            except BaseException:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                self._maintenance_calls.discard(caller)
                raise
        try:
            cancelled = False
            while True:
                try:
                    result = await asyncio.shield(task)
                    break
                except asyncio.CancelledError:
                    if task.done():
                        raise
                    cancelled = True
                except BaseException:
                    if cancelled:
                        raise asyncio.CancelledError from None
                    raise
            if cancelled:
                raise asyncio.CancelledError
            return maintenance.finish_result(task, result)
        finally:
            if task.done():
                self._maintenance_calls.discard(caller)
                if not task.cancelled():
                    task.exception()

    async def spawn(self, a):
        # Opt-in for Windows providers; native process-ancestry identity is unchanged.
        native_core = getattr(self, '_native_core', None)
        if native_core is not None:
            async with self._native_work_check_turn():
                native_core.recheck(deadline=time.monotonic()+10)
                if a.get('cli', 'codex') != 'codex':
                    raise HubError('native core provider unavailable')
        selected = os.environ.get("AGENTMUX_WINDOWS_CALLBACKS")
        if native_core is not None and selected is not None:
            raise HubError('native core callbacks require macOS')
        if selected is not None and selected != "1":
            raise HubError("AGENTMUX_WINDOWS_CALLBACKS must be 1 when set")
        windows_callbacks = selected == "1"
        if windows_callbacks:
            try:
                port = int(self.cfg.get("tcp_port", 0) or 0)
            except (TypeError, ValueError):
                raise HubError("Windows callbacks need an integer hub tcp_port")
            if not 1 <= port <= 65535 or not os.environ.get("AGENTMUX_WSL_DISTRO"):
                raise HubError("Windows callbacks need a selected WSL distro and hub tcp_port")
            try:
                windows_command([], {"AGENTMUX_WSL_DISTRO": os.environ["AGENTMUX_WSL_DISTRO"]})
            except ValueError as exc:
                raise HubError(str(exc))
        repo = names.check_part(a["repo"], "repo")
        role = names.check_part(a["role"], "role")
        agent = names.check_part(a["agent"], "agent", a.get("accept_normalized", False))
        cli = a.get("cli", "codex")
        paths = await self.db(self.store.q, "SELECT path FROM repo_paths WHERE repo=? ORDER BY path", (repo,))
        if not paths:
            raise HubError(f"repo {repo} has no checkout path")
        cwd = a.get("cwd") or paths[0]["path"]
        snap = self.resolve_role(repo, role)
        # A per-agent token for callers the kernel cannot vouch for (TCP, later NATS).
        # Only its sha256 is stored; the token itself goes to a 0600 file the agent owns.
        maintenance = self._maintenance_for_work()
        spawn_request = None if maintenance is None else maintenance.spawn_request()
        adir = os.path.join(ROOT, "repos", repo, "agents", f"{role}-{agent}")
        token_path = os.path.join(adir, 'run', 'token')
        pending_token = None
        if maintenance is None:
            token = secrets.token_urlsafe(32)
        else:
            token, pending_token = await maintenance.registration_token(names.session_name(repo, role, agent), token_path)
        generation = None
        if maintenance is None:
            session = await self.db(self.store.register, repo, role, agent, cli, snap,
                                    token_sha=hashlib.sha256(token.encode()).hexdigest())
        else:
            session, generation = await maintenance.register(repo, role, agent, cli, snap,
                token_sha=hashlib.sha256(token.encode()).hexdigest())
        for sub in ("run", "logs", "briefs", "cli"):
            os.makedirs(os.path.join(adir, sub), exist_ok=True)
        write_secret(os.path.join(adir, "run", "token"), token)
        if pending_token is not None:
            await maintenance.token_installed(pending_token, token)
        with open(os.path.join(adir, "agent.toml"), "w") as f:
            f.write(toml_dump({"session": session, "repo": repo, "role": role, "agent": agent, "cli": cli,
                               "model": a.get("model", ""), "cwd": cwd}))
        cmd = [os.environ.get("AGENTMUX_BIN", os.path.expanduser("~/.local/bin/agentmux")), "spawn", session,
               "--cli", cli, "--cwd", cwd]
        if a.get("model"):
            cmd += ["--model", a["model"]]
        env = {**os.environ, "AGENTMUX_IDLE_MINUTES": "0"}
        env.pop("AGENTMUX_AGENT", None)
        env.pop("AGENTMUX_SPAWN_WINDOWS_CALLBACK", None)
        if not windows_callbacks and "AGENTMUX_WINDOWS_CALLBACK" in env:
            # A hub launched from a worker must not pass that worker's identity
            # to a new native pane. Ordinary explicit native settings stay intact.
            for key in ("AGENTMUX_WINDOWS_CALLBACK", "AGENTMUX_HUB_TOKEN", "AGENTMUX_HUB_TOKEN_FILE",
                        "AGENTMUX_HUB_URL", "AGENTMUX_WSL_BIN", "AGENTMUX_WSL_CWD", "AGENTMUX_WSL_DISTRO"):
                env.pop(key, None)
        if windows_callbacks:
            # The token exists before the pane starts; no pane-registration race.
            # Only its path goes into the pane environment, never the secret.
            env.pop("AGENTMUX_HUB_TOKEN", None)
            env.pop("AGENTMUX_WINDOWS_CALLBACK", None)
            env.update({"AGENTMUX_SPAWN_WINDOWS_CALLBACK": "1",
                        "AGENTMUX_HOME": ROOT,
                        "AGENTMUX_HUB_URL": f"tcp://127.0.0.1:{port}",
                        "AGENTMUX_HUB_TOKEN_FILE": os.path.join(adir, "run", "token"),
                        "AGENTMUX_WSL_BIN": os.path.abspath(cmd[0]),
                        "AGENTMUX_WSL_CWD": os.path.abspath(cwd)})
        if native_core is not None:
            if windows_callbacks:
                raise HubError('native core callbacks require macOS')
            async with self._native_work_check_turn():
                selected_command = native_core.harness_command('spawn', cmd[2:], hub_home=ROOT, socket_name=self.tp.socket)
            cmd, env = selected_command.arguments, selected_command.environment
        retained = None if maintenance is None else await maintenance.begin_spawn()
        if maintenance is not None:
            maintenance.release_spawn_preparation()
        if retained is None:
            def launch_original():
                if maintenance is not None:
                    maintenance.check_spawn_dispatch(spawn_request)
                return subprocess.run(cmd, capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL,
                                      timeout=120)
            r = await asyncio.get_running_loop().run_in_executor(self.io, launch_original)
            if maintenance is not None:
                await maintenance.finish_spawn(r)
        else:
            from types import SimpleNamespace
            r = SimpleNamespace(**retained)
        if r.returncode != 0:
            await self._spawn_failed(session, generation, "spawn failed")
            raise HubError(f"spawn failed: {(r.stderr or r.stdout).strip()[-400:]}")
        h = await asyncio.get_running_loop().run_in_executor(self.io, self.tp.handle, session)
        if not h:
            await self._spawn_failed(session, generation, "no pane after spawn")
            raise HubError("spawned but no pane found")
        if maintenance is None:
            await self.db(self.store.set_handle, session, h[0], h[1])
        else:
            await self.db(self._registration_metadata, session, generation, handle=h)
        self.started[session] = time.time()
        with open(os.path.join(adir, "run", "handle"), "w") as f:
            f.write(f"{h[0]} {h[1]}\n")
        lp = os.path.join(adir, "logs", "pane.log")
        if not os.path.lexists(lp):
            os.symlink(os.path.join(ROOT, "logs", f"{session}.log"), lp)
        for t in a.get("teams", []):
            if maintenance is None:
                await self.db(self.store.team_add, repo, t, [session])
            else:
                await self.db(self._registration_team, session, generation, repo, t)
        await self._post_current("virtual:hub", f"agent:{session}", "control",
            welcome(session, repo, role, cwd, snap), None, None,
            f"welcome:{session}:{int(time.time()) if maintenance is None else generation}",
            **({} if maintenance is None else {'_registration_guard': (session, generation)}))
        return {"session": session, "handle": h[0], "pane_pid": h[1], "cwd": cwd, "spawn_out": r.stdout[-300:]}

    def _registration_metadata(self, session, generation, *, handle=None, legacy=None):
        with self.store.tx():
            current = self.store.agent(session)
            if (current is None or current['generation'] != generation
                    or handle is not None and current['state'] == 'dead'):
                raise HubError('registration changed before terminal metadata')
            if handle is not None:
                self.store.set_handle(session, handle[0], handle[1])
            if legacy is not None:
                self.store.db.execute('UPDATE agents SET term_name=? WHERE session=?', (legacy, session))

    def _registration_team(self, session, generation, repository, team):
        with self.store.tx():
            current = self.store.agent(session)
            if current is None or current['generation'] != generation:
                raise HubError('registration changed before team assignment')
            self.store.team_add(repository, team, [session])

    async def _spawn_failed(self, session, generation, note):
        maintenance = self._maintenance_for_work()
        if maintenance is None:
            return await self.db(self.store.set_state, session, 'dead', note)
        recovered, result = await maintenance.recover_phase('spawn-failure',
            'state:' + session + ':' + str(generation))
        if recovered:
            return result
        current = await self.db(self.store.agent, session)
        if current is None or current['generation'] != generation:
            raise HubError('registration changed after spawn')
        return await maintenance.state(current, 'dead', note, phase='spawn-failure')

    def _maintenance_for_work(self):
        if getattr(self, '_work_storage_commands', None) is None:
            return None
        if getattr(self, '_work_maintenance', None) is None:
            from capability_owner.work_maintenance import HubWorkMaintenance
            self._work_maintenance = HubWorkMaintenance(self, self._work_storage_commands)
        return self._work_maintenance

    def _start_work_maintenance(self):
        maintenance = self._maintenance_for_work()
        if maintenance is not None and self._legacy_work_notices is None:
            from capability_owner.legacy_work_notifications import LegacyWorkNotifications
            self._legacy_work_notices = LegacyWorkNotifications(self, self._work_storage_commands)

    async def _close_work_maintenance(self):
        pending = tuple(task for task in getattr(self, '_maintenance_calls', ()) if task is not asyncio.current_task())
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        notices = getattr(self, '_legacy_work_notices', None)
        if notices is not None:
            await notices.close()
        maintenance = getattr(self, '_work_maintenance', None)
        if maintenance is not None:
            await maintenance.close()

    async def _apply_observed_state(self, agent, state, note=None):
        maintenance = self._maintenance_for_work()
        if maintenance is None:
            return await self.db(self._set_observed_state, agent, state, note)
        return await maintenance.state(agent, state, note, phase='observation')

    async def _sweep_work_leases(self):
        maintenance = self._maintenance_for_work()
        if maintenance is not None:
            await maintenance.recover_pending()
        return (await self.db(self.store.sweep_leases) if maintenance is None else await maintenance.sweep())

    async def work_notice_loop(self):
        while not self.stop.is_set():
            try:
                await self._legacy_work_notices.poll()
            except Exception as error:
                log('work notification poll failed', type(error).__name__)
            await asyncio.sleep(5)

    # -- loops --------------------------------------------------------------------------
    async def bell_loop(self):
        while not self.stop.is_set():
            try:
                await self._bell_pass()
            except Exception as e:
                log("bell loop error", type(e).__name__, e)
            await asyncio.sleep(float(self.cfg["poll_s"]))

    async def _bell_pass(self):
        if getattr(self, '_work_storage_commands', None) is not None:
            return await self._work_bell_pass()
        s = self.store
        for ag in await self.db(s.agents, True):
            sess = ag["session"]
            if not ag["handle"] or sess in self.inflight or ag["state"] == "dead":
                continue
            st = self.bell.setdefault(sess, {"sig": None, "at": 0.0, "next": 0.0, "blocked_note": None})
            if time.time() < st["next"]:
                continue
            pend = await self.db(s.pending_for, sess)
            claim = await self.db(s.claimable, sess)
            snap = json.loads(ag["role_snapshot"])
            active = await self.db(s.q, "SELECT count(*) n FROM work_items WHERE claimed_by=? AND state='claimed'", (sess,))
            if active[0]["n"] >= int(snap.get("max_active", 1)):
                claim = []          # at capacity: offering more work is noise
            unrung = [p for p in pend if p["state"] in ("queued", "offered")]
            unacked = [p for p in pend if p["state"] != "acked"]
            if not unacked and not claim:
                continue
            sig = (pend[-1]["message_id"] if pend else None, tuple(c["id"] for c in claim))
            fresh = sig != st["sig"] and (unrung or claim)
            stale = time.time() - st["at"] > float(self.cfg["bell_every_s"])
            if not (fresh or stale):
                continue
            self._start_ring(ag, len(unacked), len(claim), sig, rering=bool(stale and not fresh))

    async def _work_bell_pass(self):
        from agentmux_contracts import strict_loads
        service = self.fed._work_commands
        service.check()
        declared = [strict_loads(raw)['workCommands'] for _, raw in self._work_storage_commands._routes]
        # An explicitly human-only selection grants no background work reads.
        # A selected service route must still pass all of its current checks.
        has_service = any(route['authenticatedCaller'] == 'federation'
            and 'federation-work-read' in route['grantRefs'] for route in declared)
        repositories = service.service_repositories() if has_service else frozenset()
        for agent in await self._work_storage_commands._owned_db(self.store.agents, True):
            session = agent['session']
            if not agent['handle'] or session in self.inflight or agent['state'] == 'dead':
                continue
            state = self.bell.setdefault(session,
                {'sig': None, 'at': 0.0, 'next': 0.0, 'blocked_note': None})
            if time.time() < state['next']:
                continue
            await self._joined_work_poll(self._work_bell_target(agent, state, service, repositories))

    async def _work_bell_target(self, agent, state, service, repositories):
        commands = self._work_storage_commands
        try:
            pending = await commands._owned_db(self.store.pending_for, agent['session'])
            claimable, work_read = [], None
            if agent['repo'] in repositories:
                if not hasattr(self, '_work_read_targets'):
                    self._work_read_targets = weakref.WeakKeyDictionary()
                targets = self._work_read_targets.setdefault(asyncio.current_task(), {})
                targets[agent['session']] = agent['generation']
                capacities = []
                for repository in sorted(repositories):
                    readiness = await service.service_readiness(agent['session'], repo=repository)
                    service.confirm_disclosure()
                    capacities.append(readiness['capacity']['available'])
                    claimable.extend(readiness['claimable'])
                if min(capacities) == 0:
                    claimable = []
                claimable.sort(key=lambda row: (row['priority'], row['id']))
                await self._check_work_targets()
                work_read = _WorkBellRead(commands, commands._disclosures[asyncio.current_task()],
                    tuple(targets.items()), service, service._federation.session)
            unrung = [row for row in pending if row['state'] in ('queued', 'offered')]
            unacked = [row for row in pending if row['state'] != 'acked']
            if not unacked and not claimable:
                return
            signature = (pending[-1]['message_id'] if pending else None,
                tuple(row['id'] for row in claimable))
            fresh = signature != state['sig'] and (unrung or claimable)
            stale = time.time() - state['at'] > float(self.cfg['bell_every_s'])
            if not (fresh or stale):
                return
            if work_read is not None:
                await self._check_work_targets()
                service.confirm_disclosure()
            self._start_ring(agent, len(unacked), len(claimable), signature,
                rering=bool(stale and not fresh), work_read=work_read)
        finally:
            try:
                if asyncio.current_task() in commands._disclosures:
                    service.finish_disclosure()
            finally:
                self._discard_work_read()
                service._sessions.pop(asyncio.current_task(), None)

    def _start_ring(self, ag, n_msg, n_claim, sig, rering=False, *, work_read=None):
        if work_read is not None and (type(work_read) is not _WorkBellRead
                or work_read.commands is not self._work_storage_commands):
            raise HubError('work bell authority is unavailable')
        sess = ag["session"]
        if self.stop.is_set() or sess in self.inflight or sess in getattr(self, "terminating", ()):
            return None
        cancel = Event()
        self.inflight.add(sess)
        task = asyncio.create_task(self._ring(ag, n_msg, n_claim, sig, cancel,
            rering=rering, **({'work_read': work_read} if work_read is not None else {})))
        self.rings[sess] = (task, cancel)

        def release(completed):
            retained = self.rings.get(sess)
            if retained is not None and retained[0] is completed:
                del self.rings[sess]
                self.inflight.discard(sess)

        task.add_done_callback(release)
        return task

    async def finish_deliveries(self):
        """Stop input and join the original delivery tasks before closing the hub."""
        self.stop.set()
        self._cancel_deliveries()
        retained = tuple(self.rings.values())
        joined = asyncio.gather(*(task for task, _ in retained), return_exceptions=True)
        cancelled = False
        while True:
            try:
                await asyncio.shield(joined)
                break
            except asyncio.CancelledError:
                cancelled = True
        self.tp.require_buffer_cleanup()
        if cancelled:
            raise asyncio.CancelledError

    def _cancel_deliveries(self):
        for _, cancel in tuple(self.rings.values()):
            cancel.set()

    async def _ring(self, ag, n_msg, n_claim, sig, cancel, rering=False, *, work_read=None):
        sess = ag["session"]
        st = self.bell[sess]
        prof = profiles.get(ag["cli"])
        text = prof.bell(n_msg=n_msg, n_claim=n_claim, session=sess)
        try:
            transport = (self.tp if work_read is None else _WorkBellTransport(
                self.tp, term(ag), ag['handle'], ag['pane_pid'], cancel, work_read))
            worker = asyncio.get_running_loop().run_in_executor(
                self.io, lambda: deliver.deliver_line(transport, prof, term(ag), ag["handle"], text,
                                                       pane_pid=ag["pane_pid"], cancel=cancel,
                                                       started_at=self.started.get(sess)))
            cancelled = False
            while True:
                try:
                    rc = await asyncio.shield(worker)
                    break
                except asyncio.CancelledError:
                    cancel.set()
                    cancelled = True
                    if worker.done():
                        rc = worker.result()
                        break
            if cancelled:
                raise asyncio.CancelledError
            recorded = await self._apply_ring(ag, rc, sig, rering, st.get("blocked_note"))
            if recorded is None:
                return
            if rc.outcome == "submitted":
                dead = recorded["dead"]
                if dead:
                    await self._tell_operator(f"{len(dead)} message(s) to {sess} went dead: never acked",
                                              f"dead:{sess}:{dead[0]}")
                st.update(sig=sig, at=time.time(), next=time.time() + 2, blocked_note=None)
                upto = sig[0] or ""
                if ag["cli"] in ("codex", "claude", "grok"):
                    # Now wait for the CLI's own log to show it (TM-213). Keep the EARLIEST
                    # unreceived bell time: a hold is measured from the first unseen bell.
                    aw = self.awaiting.get(sess)
                    self.awaiting[sess] = {"at": aw["at"] if aw else time.time(), "upto": upto, "alerted": False}
            elif rc.outcome == "deferred":
                st["next"] = time.time() + (5 if rc.reason == "busy" else 3)
            elif rc.outcome == "blocked":
                st["next"] = time.time() + 30
                if st.get("blocked_note") != rc.reason:
                    st["blocked_note"] = rc.reason
                    await self._tell_operator(f"{sess} is blocked: {rc.reason}. Look at it: agentmux attach {sess}",
                                              f"blocked:{sess}:{rc.reason}:{int(time.time() // 600)}")
            elif rc.outcome != "dead":
                st["next"] = time.time() + 10
        except Exception as e:
            log("ring error", sess, type(e).__name__, e)
            st["next"] = time.time() + 10
        finally:
            self.inflight.discard(sess)

    async def _apply_ring(self, ag, rc, sig, rering, blocked_note):
        maintenance = self._maintenance_for_work()
        metadata_key = None
        if maintenance is not None:
            receipt_id = secrets.token_hex(16)
            metadata_key = 'hub-work-ring:' + receipt_id
            state = ('busy' if rc.outcome == 'submitted' else rc.outcome
                if rc.outcome in ('blocked', 'dead') else None)
            if state is not None and (state != 'blocked' or blocked_note != rc.reason):
                for attempt in range(3):
                    current = await self.db(self.store.agent, ag['session'])
                    if not self._same_registration(current, ag):
                        return None
                    note = current['state_note'] if state == 'busy' else rc.reason
                    if await maintenance.state(current, state, note,
                            phase='ring_' + receipt_id + '_' + str(attempt)):
                        break
                else:
                    return None
        return await self.db(self._record_ring, ag, rc, sig, rering, blocked_note, metadata_key)

    def _record_ring(self, ag, rc, sig, rering, blocked_note, metadata_key=None):
        with self.store.tx():
            return self._record_ring_metadata(ag, rc, sig, rering, blocked_note, metadata_key)

    def _record_ring_metadata(self, ag, rc, sig, rering, blocked_note, metadata_key):
        # One job on the sole Store executor prevents registration from changing
        # between this check and the receipt's database mutations.
        store, sess = self.store, ag["session"]
        current = store.agent(sess)
        if current is None or any(current[key] != ag[key]
                                  for key in ("handle", "pane_pid", "created")):
            return None
        qualified = getattr(self, '_work_storage_commands', None) is not None
        if qualified and (metadata_key is None or not self._same_registration(current, ag)):
            raise HubError('qualified lifecycle changes require the work owner')
        if metadata_key is not None:
            prior = store.q1('SELECT v FROM fed_state WHERE k=?', (metadata_key,))
            if prior is not None:
                return json.loads(prior['v'])
        evidence, dead = rc.as_dict(), []
        store.event("bell", sess, rc.outcome, "hub", evidence)
        if rc.outcome == "submitted":
            if rering:
                # Only a submitted, unacknowledged bell spends an attempt.
                dead = store.bump_attempt(sess, "doorbell submitted, not acked",
                                          int(self.cfg["max_attempts"]))
            # Do not announce mail posted after the bell's original count.
            upto = sig[0] or ""
            for pending in store.pending_for(sess):
                if pending["state"] in ("queued", "offered", "typed") and pending["message_id"] <= upto:
                    store.delivery_report(pending["message_id"], sess, "submitted", evidence)
            if qualified:
                store.db.execute('UPDATE agents SET last_bell=? WHERE session=?', (now(), sess))
            else:
                store.db.execute("UPDATE agents SET last_bell=?, state='busy' WHERE session=?", (now(), sess))
        elif rc.outcome == "blocked":
            if blocked_note != rc.reason and not qualified:
                store.set_state(sess, "blocked", rc.reason)
        elif rc.outcome == "dead":
            if not qualified:
                store.set_state(sess, "dead", rc.reason)
        elif rc.outcome != "deferred":
            store.bump_attempt(sess, f"doorbell {rc.outcome}: {rc.reason}", int(self.cfg["max_attempts"]))
        result = {"dead": dead}
        if metadata_key is not None:
            store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)', (metadata_key, json.dumps(result)))
        return result

    async def _tell_operator(self, body, idem):
        try:
            commands = getattr(self, '_work_storage_commands', None)
            if commands is not None and asyncio.current_task() in commands._disclosures:
                await self._post_current('virtual:hub', 'virtual:operator', 'note', body,
                    idem_key=idem, _work_reply=True)
            else:
                await self.db(self.store.post, "virtual:hub", "virtual:operator", "note", body, None, None, idem)
        except HubError as e:
            log("operator note failed", e)

    def _set_observed_state(self, ag, state, note=None):
        # Runs on the store thread: an old terminal observation must not update
        # a replacement registration created while the observation was pending.
        if getattr(self, '_work_storage_commands', None) is not None:
            raise HubError('qualified lifecycle changes require the work owner')
        current = self.store.agent(ag["session"])
        if current is None or any(current[key] != ag[key] for key in ("handle", "pane_pid", "created", "state")):
            return False
        self.store.set_state(ag["session"], state, note)
        return True

    async def _observe_terminal_alive(self, agent):
        # The native transport checks protected images too. Keep this original
        # observation outside request classification and join it before release.
        async with self._native_work_check_turn():
            future = asyncio.get_running_loop().run_in_executor(self.io, self.tp.alive, term(agent))
            try:
                return await asyncio.shield(future)
            except asyncio.CancelledError:
                while not future.done():
                    try:
                        await asyncio.wait({future})
                    except asyncio.CancelledError:
                        continue
                if not future.cancelled():
                    future.exception()
                raise

    async def live_loop(self):
        while not self.stop.is_set():
            try:
                for ag in await self.db(self.store.agents, True):
                    sess = ag["session"]
                    if not ag["handle"]:
                        # Registered but still being spawned: the row exists before the
                        # terminal does. Orchestration 5 lost a healthy claude to this -
                        # declared dead 70 ms after register, while tmux was creating it.
                        # spawn() itself marks it dead if the terminal never appears.
                        continue
                    alive = await self._observe_terminal_alive(ag)
                    if not alive:
                        if not await self._apply_observed_state(ag, "dead", "terminal gone"):
                            continue
                        await asyncio.get_running_loop().run_in_executor(self.io, self.harness, "reap")
                        await self._tell_operator(f"{sess} died (terminal gone); its leases went back to the queue",
                                                  f"died:{sess}:{ag['created']}")
                        continue
                    mark = self.tp.output_mark(term(ag))
                    if mark is not None and mark != self.marks.get(sess):
                        self.marks[sess] = mark
                        await self.db(self.store.touch_output, sess)
                    if ag["state"] == "starting" and time.time() - self.started.get(sess, 0) > 3:
                        await self._apply_observed_state(ag, "ready")
                    if ag["state"] == "blocked" and not self.bell.get(sess, {}).get("blocked_note"):
                        await self._apply_observed_state(ag, "ready")
                # PROTOCOL 5.3: team work with no live lead is reported, never left to rot.
                local = getattr(self, '_local_work_commands', None)
                team_work = (await self.db(self.store.q, "SELECT id, target, created FROM work_items WHERE state='ready' "
                    "AND target LIKE 'team:%'") if local is None else
                    [row for row in await local.list('federation') if row['state'] == 'ready' and row['target'].startswith('team:')])
                for w in team_work:
                    repo, team = w["target"][5:].split("/", 1)
                    t = await self.db(self.store.team, repo, team)
                    leads = [m for m in (t or {}).get("members", [])
                             if (await self.db(self.store.agent, m) or {}).get("state") not in (None, "dead")
                             and (await self.db(self.store.agent, m))["role"] == (t or {}).get("lead_role")]
                    if not leads:
                        await self._tell_operator(f"work {w['id']} for {w['target']} has no live lead to take it",
                                                  f"nolead:{w['id']}")
                if local is not None:
                    local._commands.finish_disclosure()
            except Exception as e:
                log("live loop error", type(e).__name__, e)
            finally:
                commands = getattr(self, '_work_storage_commands', None)
                if commands is not None:
                    commands._disclosures.pop(asyncio.current_task(), None)
            await asyncio.sleep(3)

    async def receipt_loop(self):
        """TM-213 / C15. Promote submitted deliveries to received when the CLI's own log
        shows the bell, and tell the operator once when a submitted bell has sat unseen
        longer than hold_alert_s - the grok pager-queue hold, made visible."""
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self.io, self.receipts.prime)
        while not self.stop.is_set():
            try:
                for sess, cli, ref in await loop.run_in_executor(self.io, self.receipts.scan):
                    aw = self.awaiting.pop(sess, None)
                    if aw is None:
                        continue                  # a bell we did not send this run, or a quoted one
                    got = await self.db(self.store.mark_received, sess, aw["upto"],
                                        {"cli_receipt": ref, "cli": cli, "after_s": round(time.time() - aw["at"], 1)})
                    log("cli receipt", sess, cli, len(got), "delivery(ies)")
                await self.check_holds(time.time())
            except Exception as e:
                log("receipt loop error", type(e).__name__, e)
            await asyncio.sleep(3)

    async def check_holds(self, t_now):
        limit = float(self.cfg.get("hold_alert_s", 300))
        for sess, aw in list(self.awaiting.items()):
            pend = [p for p in await self.db(self.store.pending_for, sess) if p["message_id"] <= aw["upto"]]
            if not pend:
                self.awaiting.pop(sess, None)     # the agent read and acked: received, by definition
                continue
            if not aw["alerted"] and t_now - aw["at"] > limit:
                aw["alerted"] = True
                await self.db(self.store.event, "agent", sess, "cli_hold", "hub",
                              {"held_s": round(t_now - aw["at"]), "pending": len(pend)})
                await self._tell_operator(
                    f"{sess}: a doorbell was submitted {int(t_now - aw['at'])} s ago but its CLI log shows no user "
                    f"turn yet - the CLI is holding input (C15). {len(pend)} message(s) wait.",
                    f"hold:{sess}:{int(aw['at'])}")

    async def lease_loop(self):
        last_ck = time.time()
        # Back up once at startup, so a hub that never lives an hour still has one.
        last_bk = 0.0
        last_prune = time.time()
        bdir = os.path.join(HUBDIR, "backups")
        while not self.stop.is_set():
            try:
                back = await self._sweep_work_leases()
                for w in back:
                    log("lease expired", w)
                if time.time() - last_ck > 600:
                    await self.db(self.store.checkpoint)
                    last_ck = time.time()
                if time.time() - last_bk >= float(self.cfg["backup_every_s"]):
                    p = await self.db(self.store.backup_to, bdir, int(self.cfg["backup_keep"]), "hourly")
                    log("backup", p)
                    last_bk = time.time()
                if time.time() - last_prune >= float(self.cfg["prune_every_s"]):
                    n = await self.db(self.store.prune, self.cfg["retention_events_days"],
                                      self.cfg["retention_messages_days"])
                    log("pruned", n)
                    last_prune = time.time()
            except Exception as e:
                log("lease loop error", type(e).__name__, e)
            await asyncio.sleep(5)

    async def main(self):
        if self._work_source_binding is not None:
            try:
                await self._work_source_binding.activate()
                self._start_work_maintenance()
                self._seed_roles()
            except BaseException as original:
                try:
                    await self._close_failed_work_start()
                except BaseException as cleanup:
                    raise cleanup from BaseExceptionGroup('Hub startup failure and cleanup',
                        [original, cleanup.__cause__ or cleanup])
                raise
        await self._main()

    async def _close_failed_work_start(self):
        """Join the one retained lifetime cleanup, including repeated cancellation."""
        if self._work_start_cleanup is None:
            self._work_start_cleanup = asyncio.create_task(self._finish_hub_cleanup())
        cancelled = None
        while not self._work_start_cleanup.done():
            try:
                await asyncio.wait({self._work_start_cleanup})
            except asyncio.CancelledError as error:
                cancelled = error
        try:
            self._work_start_cleanup.result()
        except BaseException as failure:
            error = HubCleanupFailure(self)
            raise error from failure
        if cancelled is not None:
            raise cancelled

    async def _finish_hub_cleanup(self):
        self.stop.set()
        failures = []
        async def attempt(action, *args, **kwargs):
            try:
                value = action(*args, **kwargs)
                if hasattr(value, '__await__'):
                    await value
                return True
            except BaseException as error:
                failures.append(error)
                return False

        servers = getattr(self, '_hub_servers', ())
        for server in servers:
            await attempt(server.close)
        await attempt(self._cancel_deliveries)
        tasks = tuple(getattr(self, '_hub_loops', ()))
        for task in tasks:
            task.cancel()
        connections = tuple(getattr(self, '_hub_connections', ()))
        for task in connections:
            task.cancel()
        await attempt(asyncio.gather, *tasks, *connections, return_exceptions=True)
        for server in servers:
            await attempt(server.wait_closed)
        endpoint = getattr(self, '_selected_endpoint', None)
        if endpoint is not None:
            await attempt(endpoint.drain)
        producers_joined = not failures
        producers_joined = await attempt(self.finish_kills) and producers_joined
        producers_joined = await attempt(self.finish_deliveries) and producers_joined
        producers_joined = await attempt(self.fed.finish_cleanup) and producers_joined
        # These clients borrow the Store and enrolled sessions. Do not release
        # them while an earlier producer still has unresolved cleanup ownership.
        self._hub_borrowers_joined = False
        if producers_joined:
            maintenance_closed = await attempt(self._close_work_maintenance)
            rpc_closed = True
            if self._work_rpc is not None:
                rpc_closed = await attempt(self._work_rpc.close, timeout=None)
            if maintenance_closed and rpc_closed and self._work_storage_commands is not None:
                await attempt(self._work_storage_commands.close, timeout=None)
            for client in (self._peer_control_commands, self._policy_commands,
                    self._knowledge_commands, self._code_commands, self._message_commands):
                if client is not None:
                    await attempt(client.close, timeout=None)
            self._hub_borrowers_joined = not failures
        if self._hub_borrowers_joined:
            if getattr(self, '_hub_checkpoint', False):
                if self._work_source_binding is None:
                    await attempt(self.db, self.store.checkpoint)
                else:
                    def final_checkpoint():
                        self._work_source_binding.pin.read()
                        self.store.checkpoint()
                    await attempt(lambda: asyncio.wrap_future(self.dbx.submit(final_checkpoint)))
            await attempt(lambda: asyncio.wrap_future(self.dbx.submit(self.store.db.close)))
            await attempt(self.dbx.shutdown, wait=True)
            await attempt(self.io.shutdown, wait=True)
        if endpoint is not None:
            await attempt(endpoint.close)
        owned = getattr(self, '_hub_socket_identity', None)
        if owned is not None:
            def unlink_owned():
                try:
                    current = os.lstat(SOCK)
                except FileNotFoundError:
                    return
                if (current.st_dev, current.st_ino) != owned:
                    raise HubError('Hub socket was replaced during cleanup')
                os.unlink(SOCK)
            await attempt(unlink_owned)
        for sig in getattr(self, '_hub_signals', ()):
            await attempt(asyncio.get_running_loop().remove_signal_handler, sig)
        if failures:
            raise BaseExceptionGroup('Hub cleanup failures', failures)
        log('hub down')

    def _accept_connection(self, reader, writer, *, tcp=False):
        async def serve():
            try:
                if self.stop.is_set():
                    return
                endpoint = self._selected_endpoint
                if endpoint is not None and not tcp:
                    await endpoint.serve(reader, writer)
                else:
                    await self.handle_conn(reader, writer, tcp=tcp)
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                finally:
                    self._hub_connections.discard(asyncio.current_task())
        task = asyncio.create_task(serve())
        self._hub_connections.add(task)

    async def _main(self):
        self._hub_servers, self._hub_loops, self._hub_signals = [], [], []
        self._hub_connections = set()
        self._hub_socket_identity = None
        self._hub_checkpoint = True
        original = None
        try:
            if os.path.lexists(SOCK):
                before = os.lstat(SOCK)
                import stat
                if not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.getuid():
                    raise HubError('Hub socket is not owned by this user')
                with socket.socket(socket.AF_UNIX) as probe:
                    try:
                        probe.connect(SOCK)
                        raise SystemExit(f'hub already running on {SOCK}')
                    except (ConnectionRefusedError, FileNotFoundError):
                        current = os.lstat(SOCK)
                        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                            raise HubError('Hub socket changed before startup')
                        os.unlink(SOCK)
            old = os.umask(0o077)
            try:
                server = await asyncio.start_unix_server(self._accept_connection,
                    path=SOCK, start_serving=False, cleanup_socket=False)
                self._hub_servers.append(server)
                created = os.lstat(SOCK)
                self._hub_socket_identity = (created.st_dev, created.st_ino)
                if self._selected_endpoint is not None:
                    await self._selected_endpoint.publish(self)
                await server.start_serving()
            finally:
                os.umask(old)
            port = int(self.cfg.get('tcp_port', 0) or 0)
            if port:
                tcp = await asyncio.start_server(
                    lambda r, w: self._accept_connection(r, w, tcp=True), '127.0.0.1', port)
                self._hub_servers.append(tcp)
                log('tcp listening 127.0.0.1:%d' % port)
            with open(os.path.join(HUBDIR, 'hub.pid'), 'w') as stream:
                stream.write(str(os.getpid()))
            for ag in await self.db(self.store.agents, True):
                self.started[ag['session']] = 0
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, self.stop.set)
                self._hub_signals.append(sig)
            log('hub up', SOCK, 'db', self.store.path)
            try:
                from hub import loop_profile
                loop_profile.start(lambda report: log('event loop busy', json.dumps(report)))
            except Exception:
                pass
            loops = [self.bell_loop, self.live_loop, self.lease_loop, self.receipt_loop]
            if self._legacy_work_notices is not None:
                loops.append(self.work_notice_loop)
            if self.bridge:
                loops.append(self.bridge.run)
            loops.append(self.fed.run)
            for run in loops:
                self._hub_loops.append(asyncio.create_task(run()))
            await self.stop.wait()
        except BaseException as error:
            original = error
        try:
            await self._close_failed_work_start()
        except BaseException as cleanup:
            if original is not None:
                raise cleanup from BaseExceptionGroup('Hub failure and cleanup', [original, cleanup.__cause__ or cleanup])
            raise
        if original is not None:
            raise original


def term(ag):
    """The tmux session an agent really lives in: its protocol name, or - for an agent
    adopted from before the protocol - the legacy name it was spawned under."""
    return ag.get("term_name") or ag["session"]


def write_secret(path, value):
    """Create a 0600 file holding a secret; never world- or group-readable, even briefly."""
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value + "\n")
    os.replace(path + ".tmp", path)


def normalize_remote(url):
    u = url.strip()
    for pre in ("https://", "http://", "ssh://", "git://"):
        if u.startswith(pre):
            u = u[len(pre):]
    u = u.split("@", 1)[-1].replace(":", "/")
    if u.endswith(".git"):
        u = u[:-4]
    return u.lower()


def welcome(session, repo, role, cwd, snap):
    return f"""Welcome, {session}. You are an agent in repo '{repo}' (checkout: {cwd}), role '{role}'.
The agentmux hub is how you receive messages and work. Run these in your shell:
  agentmux hub inbox --ack                 read and acknowledge your messages (do this whenever you see a [hub] line)
  agentmux hub claim                       take the next work item offered to you or your role
  agentmux hub work show <id>              show a work item and its children
  agentmux hub done <id> --result "..."    finish a claimed item  (also: fail / return / block <id> --result "why")
  agentmux hub post --to <address> --kind request|reply|note [--ref <id>] "text"
      addresses: agent:<session>   role:<repo>/<role>   team:<repo>/<team>   virtual:operator
  agentmux hub work add --to <address> --title "..." --body "..." [--parent <id>]
  agentmux hub whoami
Rules: acknowledge every message; claim work before doing it; finish with done/fail. Do not reply to this welcome.
If nothing is claimable after reading your inbox, stop and wait - a [hub] line will tell you when there is more.
{snap.get('instructions', '')}"""


def main(*, profile_context: ProfileContext | None = None, selected_endpoint=None, native_core=None,
         legacy_identity=None, authority_switch_recovery=None, message_sessions=None, knowledge_sessions=None,
         peer_control_sessions=None, policy_sessions=None, code_sessions=None, work_sessions=None):
    from hub.fed.conn import ConnectionCleanupFailure
    from hub.fed.session import SessionCleanupFailure
    try:
        asyncio.run(Hub(profile_context=profile_context, selected_endpoint=selected_endpoint, native_core=native_core, legacy_identity=legacy_identity,
            authority_switch_recovery=authority_switch_recovery, message_sessions=message_sessions,
            knowledge_sessions=knowledge_sessions, peer_control_sessions=peer_control_sessions,
            policy_sessions=policy_sessions, code_sessions=code_sessions, work_sessions=work_sessions).main())
    except (ConnectionCleanupFailure, SessionCleanupFailure):
        print("hub shutdown could not complete owned federation cleanup", file=sys.stderr)
        return 1
    except TmuxBufferCleanupFailure:
        print("hub shutdown could not complete owned terminal cleanup", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
