"""Host-owned admission of exact ordinary-secret journals.

The host supplies the policy and a separately signed application-account request.
A plugin supplies neither broker configuration nor administration commands. Close
all OrdinarySecretOwner callers before closing this admission owner. Cancellation
of an observer does not cancel its retained preparation or connection cleanup.
"""
from __future__ import annotations

import asyncio
import base64
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import ssl
from urllib.parse import urlsplit

import nkeys
from nats.js.errors import NotFoundError

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from hub.nats_transport import new_client
from identity.application_account import ApplicationAccountAuthority
from identity.authority import LedgerAuthorityReader, _active, _indexes, _key, evaluate_snapshot
from identity.ordinary_secret import validate_enrollment
from integration_owner.operator_provisioning import (
    _account_seed, _administrator_credential, _close_client, _encoded, _same_resolution)
from native_security.nats_credentials import validate as validate_credential
from native_security.ordinary_secret_custody import OrdinarySecretCustody
from native_security.secret_custody import (
    ScopedSecretCustody, _admit, _open_namespace, _open_root, _read_file)
from native_security.descriptor_admission import DescriptorPurpose
from state_owner.checkpoints import _publish
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import RECORD_CHARGE, Retention
from .secret_consumer import AtlassianAccountCheckEnrollment
from .secret_journal import SecretOperationJournal, enrollment_digest, secret_use_identity


def _fail(code='secret_journal_admission_refused'):
    raise ContractError(code) from None


@dataclass(frozen=True, slots=True, repr=False)
class SecretJournalPolicy:
    """Explicit trusted host configuration; never constructed from plugin input."""
    namespace: str
    scope: bytes
    account_public_key: str
    endpoint: str
    server_name: str
    trust_pem: bytes
    leaf_certificate_sha256: str
    retention: Retention
    max_journals: int
    max_total_bytes: int
    jetstream_domain: str | None = None

    def __post_init__(self):
        try:
            if (type(self.namespace) is not str or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,31}', self.namespace)
                    or type(self.scope) is not bytes
                    or type(self.account_public_key) is not str
                    or not re.fullmatch(r'A[A-Z2-7]{55}', self.account_public_key)
                    or type(self.endpoint) is not str or len(self.endpoint) > 512
                    or type(self.server_name) is not str
                    or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', self.server_name)
                    or type(self.trust_pem) is not bytes or not 0 < len(self.trust_pem) <= 65536
                    or not re.fullmatch(r'sha256:[a-f0-9]{64}', self.leaf_certificate_sha256)
                    or type(self.retention) is not Retention
                    or not 4 * RECORD_CHARGE <= self.retention.max_bytes <= 67_108_864
                    or type(self.max_journals) is not int or not 1 <= self.max_journals <= 64
                    or type(self.max_total_bytes) is not int
                    or not self.retention.max_bytes <= self.max_total_bytes <= 4_294_967_296
                    or self.jetstream_domain is not None and (type(self.jetstream_domain) is not str
                        or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', self.jetstream_domain))):
                raise ValueError
            scope = strict_loads(self.scope)
            OwnerBinding('host-policy', 'ordinary-secret-uses', 'policy', 'effect', self.scope)
            if scope['projectId'] is None:
                raise ValueError
            parsed = urlsplit(self.endpoint)
            if (parsed.scheme != 'tls' or not parsed.hostname or parsed.port is None
                    or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
                raise ValueError
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cadata=self.trust_pem.decode('ascii'))
            object.__setattr__(self, 'scope', canonical_bytes(scope))
        except Exception:
            _fail('secret_journal_policy_invalid')

    def __repr__(self):
        return '<SecretJournalPolicy private>'

    def stream(self, entity):
        return 'AMX_SECRET_' + self.namespace + '_' + entity.removeprefix('secret-use-').upper()

    def pin(self):
        return {'namespace': self.namespace, 'scope': strict_loads(self.scope),
            'account': self.account_public_key, 'endpointDigest': payload_digest(self.endpoint),
            'serverName': self.server_name, 'trustDigest': 'sha256:' + hashlib.sha256(self.trust_pem).hexdigest(),
            'leafPin': self.leaf_certificate_sha256, 'domain': self.jetstream_domain,
            'retention': {'maxBytes': self.retention.max_bytes,
                'reserveBytes': self.retention.reserve_bytes, 'replicas': self.retention.replicas},
            'maxJournals': self.max_journals, 'maxTotalBytes': self.max_total_bytes}


class _Inventory:
    """Trusted selection pins only; use state remains in the NATS ledger."""
    def __init__(self, root, policy, enrollment):
        self._root = Path(root)
        self._fd = _open_root(self._root)
        self._identity = self._identity_of(self._fd)
        self.policy = policy
        try:
            self._namespace = _open_namespace(self._fd, 'secret-journals-' + policy.namespace, create=True)
            expected = {'format': 'agentmux-secret-journal-policy-v1',
                'policy': policy.pin(), 'enrollmentDigest': enrollment_digest(enrollment)}
            self.match(self._namespace, 'policy.json', expected)
            self._expected_policy = expected
        except BaseException:
            if hasattr(self, '_namespace'):
                os.close(self._namespace)
            os.close(self._fd)
            raise

    @staticmethod
    def _identity_of(fd):
        info = os.fstat(fd)
        return info.st_dev, info.st_ino, info.st_uid, info.st_mode

    def check(self):
        if self._fd is None:
            _fail('secret_journal_admission_closed')
        _admit(self._fd, DescriptorPurpose.PRIVATE_DIRECTORY)
        if self.read(self._namespace, 'policy.json') != self._expected_policy:
            _fail('secret_journal_inventory_changed')
        current = _open_root(self._root)
        try:
            if self._identity_of(current) != self._identity:
                _fail('secret_journal_inventory_changed')
            namespace = _open_namespace(current, 'secret-journals-' + self.policy.namespace, create=False)
            try:
                if self._identity_of(namespace) != self._identity_of(self._namespace):
                    _fail('secret_journal_inventory_changed')
            finally:
                os.close(namespace)
        finally:
            os.close(current)

    @contextmanager
    def lock(self):
        self.check()
        fd = os.open('.admission-lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self._namespace)
        try:
            _admit(fd, DescriptorPurpose.PRIVATE_FILE)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _fail('secret_journal_admission_busy')
            yield
            self.check()
        finally:
            os.close(fd)

    @staticmethod
    def read(directory, name):
        try:
            raw = _read_file(directory, name)
        except FileNotFoundError:
            return None
        value = strict_loads(raw)
        if len(raw) > 16384 or canonical_bytes(value) != raw:
            _fail('secret_journal_inventory_changed')
        return value

    @classmethod
    def match(cls, directory, name, value):
        raw = canonical_bytes(value)
        prior = cls.read(directory, name)
        if prior is None:
            try:
                _publish(directory, name, raw, admit=lambda fd: _admit(fd, DescriptorPurpose.PRIVATE_FILE))
            except FileExistsError:
                pass
            prior = cls.read(directory, name)
        if prior != value:
            _fail('secret_journal_assignment_conflict')
        return prior

    @contextmanager
    def entity(self, identifier, *, create=False):
        self.check()
        fd = _open_namespace(self._namespace, identifier, create=create)
        try:
            yield fd
        finally:
            os.close(fd)

    def count(self):
        names = os.listdir(self._namespace)
        if len(names) > self.policy.max_journals + 2:
            _fail('secret_journal_inventory_changed')
        entities = [name for name in names if name.startswith('secret-use-')]
        if any(not re.fullmatch(r'secret-use-[a-f0-9]{64}', name) for name in entities):
            _fail('secret_journal_inventory_changed')
        return len(entities)

    def source(self, entity, *, sequence=None):
        with self.lock(), self.entity(entity) as directory:
            pin = self.read(directory, 'source.json')
            if type(pin) is not dict or set(pin) != {'created', 'token'}:
                _fail('secret_journal_recovery_required')
            floors = os.listdir(directory)
            values = []
            for name in floors:
                if name.startswith('floor-'):
                    if not re.fullmatch(r'floor-[0-9]{16}', name):
                        _fail('secret_journal_inventory_changed')
                    value = self.read(directory, name)
                    if value != {'sequence': int(name[6:])}:
                        _fail('secret_journal_inventory_changed')
                    values.append(value['sequence'])
            floor = max(values, default=0)
            if sequence is not None:
                if type(sequence) is not int or not floor <= sequence <= self.policy.retention.max_bytes // RECORD_CHARGE:
                    _fail('secret_journal_recovery_required')
                if sequence > floor:
                    self.match(directory, 'floor-%016d' % sequence, {'sequence': sequence})
                    floor = sequence
            return StreamIdentity(datetime.fromisoformat(pin['created']), floor), pin['token']

    def close(self):
        if self._fd is not None:
            os.close(self._namespace)
            os.close(self._fd)
            self._fd = None


class _PinnedLedger(OwnerLedger):
    def __init__(self, *args, inventory, entity, **kwargs):
        self._inventory, self._entity = inventory, entity
        self._io_lock, self._io_owner, self._source_closed = asyncio.Lock(), None, False
        super().__init__(*args, **kwargs)

    async def _info(self):
        identity, token = self._inventory.source(self._entity)
        self.require_recovery_identity(identity)
        info = await super()._info()
        # NATS may add informational metadata. Only our exact private creation
        # token establishes provenance; all stream behavior is checked separately.
        if (type(info.config.metadata) is not dict
                or info.config.metadata.get('agentmuxSecretJournal') != token):
            _fail('secret_journal_recovery_required')
        self._inventory.source(self._entity, sequence=info.state.last_seq)
        return info

    @asynccontextmanager
    async def source_access(self):
        task = asyncio.current_task()
        if self._io_owner is task:
            yield
            return
        async with self._io_lock:
            if self._source_closed:
                _fail('secret_journal_admission_closed')
            self._io_owner = task
            try:
                yield
            finally:
                self._io_owner = None

    async def current(self):
        async with self.source_access():
            return await super().current()

    async def append(self, *args, **kwargs):
        async with self.source_access():
            result = await super().append(*args, **kwargs)
            self._inventory.source(self._entity, sequence=self._minimum_sequence)
            return result


def _issue(account_seed, publish, inbox, *, valid_until):
    account = user = None
    try:
        account = nkeys.from_seed(account_seed)
        user = nkeys.from_seed(nkeys.encode_seed(secrets.token_bytes(32), nkeys.PREFIX_BYTE_USER))
        now = int(datetime.now(timezone.utc).timestamp())
        expires = int(valid_until.timestamp())
        if expires <= now:
            _fail('secret_journal_authority_expired')
        claims = {'iat': now, 'exp': expires, 'iss': account.public_key.decode(),
            'sub': user.public_key.decode(), 'name': 'agentmux-secret-journal'}
        claims['jti'] = base64.b32encode(hashlib.new('sha512_256', canonical_bytes(claims)).digest()).decode().rstrip('=')
        claims['nats'] = {'type': 'user', 'version': 2, 'pub': {'allow': list(publish)},
            'sub': {'allow': [inbox + '.>']}, 'subs': -1, 'data': -1, 'payload': -1}
        message = _encoded({'typ': 'JWT', 'alg': 'ed25519-nkey'}) + b'.' + _encoded(claims)
        token = message + b'.' + base64.urlsafe_b64encode(account.sign(message)).rstrip(b'=')
        return (b'-----BEGIN NATS USER JWT-----\n' + token + b'\n------END NATS USER JWT------\n\n'
            + b'-----BEGIN USER NKEY SEED-----\n' + user.seed + b'\n------END USER NKEY SEED------\n')
    finally:
        if account is not None:
            account.wipe()
        if user is not None:
            user.wipe()


class SecretJournalAdmission:
    def __init__(self, *, policy, enrollment, authority, custody, account_custody,
                 inventory_root, observation_root, _client_factory=new_client):
        if (type(policy) is not SecretJournalPolicy or type(enrollment) is not AtlassianAccountCheckEnrollment
                or type(authority) is not LedgerAuthorityReader or type(custody) is not OrdinarySecretCustody
                or custody._reader is not authority or type(account_custody) is not ScopedSecretCustody
                or account_custody._authority is not authority or not callable(_client_factory)):
            _fail('secret_journal_admission_configuration')
        record = strict_loads(enrollment.record)
        scope = strict_loads(policy.scope)
        if (record['ref'] != record['generationRef'] or record['ref']['revision'] != 1
                or record['ref']['ownerHubId'] != authority._hub or record['profileId'] != authority._profile
                or any(record['scope'][k] != scope[k] for k in ('organizationId', 'projectId'))
                or record['scope']['workspaceId'] not in (None, scope['workspaceId'])):
            _fail('secret_journal_admission_configuration')
        self._policy, self._enrollment, self._reader = policy, enrollment, authority
        self._custody, self._account_custody = custody, account_custody
        self._account = ApplicationAccountAuthority(authority)
        try:
            self._inventory = _Inventory(inventory_root, policy, enrollment)
        except ContractError:
            raise
        except Exception:
            _fail('secret_journal_admission_configuration')
        self._observations, self._factory = observation_root, _client_factory
        self._tasks, self._resources, self._clients = set(), {}, []
        self._gate = asyncio.Lock()
        self._closed, self._closing = False, None

    def __repr__(self):
        return '<SecretJournalAdmission private>'

    async def _owned(self, method, *args):
        if self._closed or len(self._tasks) >= 16:
            _fail('secret_journal_admission_closed' if self._closed else 'secret_journal_admission_busy')
        task = asyncio.create_task(self._run(method, *args), name='secret-journal-admission')
        self._tasks.add(task)
        def done(original):
            self._tasks.discard(original)
            if not original.cancelled():
                original.exception()
        task.add_done_callback(done)
        await asyncio.wait((task,))
        return task.result()

    async def _run(self, method, *args):
        try:
            async with self._gate:
                return await method(*args)
        except asyncio.CancelledError:
            raise
        except ContractError:
            raise
        except Exception:
            _fail()

    async def open(self, resolve_envelope, *, account_request, native_proof=None):
        """Admit a fresh original or reopen its exact retained journal, without use."""
        return await self._owned(self._open, resolve_envelope, account_request, native_proof, False)

    async def reopen_query(self, query_envelope, *, account_request, native_proof=None):
        """Open only an existing original under a separate current outcome query."""
        return await self._owned(self._open, query_envelope, account_request, native_proof, True)

    async def _authorize(self, raw, native_proof):
        use = await self._custody.authorize(raw, native_proof=native_proof)
        resolution = await self._custody.check(use)
        if resolution.record != self._enrollment.record or resolution.scope != self._policy.scope:
            _fail()
        await self._custody.recover(use)
        return use, resolution

    async def _account_current(self, request, original=None):
        current = await self._account.resolve(request)
        # Application-account custody belongs to the exact project. Journal use
        # retains its independently authorized, possibly narrower workspace.
        project_scope = {**strict_loads(self._policy.scope), 'workspaceId': None}
        if (current.account_public_key != self._policy.account_public_key
                or current.profile_id != self._reader._profile
                or current.scope != project_scope
                or original is not None and not _same_resolution(original, current)):
            _fail()
        return current

    async def _connect(self, credential, inbox):
        client = self._factory(require_tls=True, leaf_certificate_sha256=self._policy.leaf_certificate_sha256)
        self._clients.append(client)
        errors = []
        async def error(_error):
            errors.append(True)
        def signature(nonce):
            if type(nonce) is not str or not 0 < len(nonce) <= 4096:
                _fail()
            key = nkeys.from_seed(credential.seed)
            try:
                return base64.b64encode(key.sign(nonce.encode('ascii')))
            finally:
                key.wipe()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=self._policy.trust_pem.decode('ascii'))
        try:
            async with asyncio.timeout(5):
                await client.connect(servers=[self._policy.endpoint], tls=context,
                    tls_hostname=self._policy.server_name, tls_handshake_first=True,
                    user_jwt_cb=lambda: credential.jwt.encode('ascii'), signature_cb=signature,
                    inbox_prefix=inbox, allow_reconnect=False, max_reconnect_attempts=0,
                    connect_timeout=3, dont_randomize=True, no_echo=True, error_cb=error)
            if client.is_connected is not True or errors:
                _fail()
            return client
        except BaseException:
            await self._close_broker(client)
            raise

    async def _close_broker(self, client):
        await _close_client(client)
        if client in self._clients:
            self._clients.remove(client)

    async def _prepare(self, binding, assignment, account_request, account, use):
        private = await self._account_custody.resolve(account_request, kind='nats-administrator-credential')
        await self._account_current(account_request, account)
        credential, inbox = _administrator_credential(private.private_copy(),
            account_public_key=account.account_public_key, domain=self._policy.jetstream_domain)
        del private
        client = await self._connect(credential, inbox)
        stream, subject = self._policy.stream(binding.entity_id), owner_subject(binding)
        try:
            js = client.jetstream(domain=self._policy.jetstream_domain, timeout=3)
            with self._inventory.lock():
                count = self._inventory.count()
                exists = binding.entity_id in os.listdir(self._inventory._namespace)
                if not exists and (count >= self._policy.max_journals
                        or (count + 1) * self._policy.retention.max_bytes > self._policy.max_total_bytes):
                    _fail('secret_journal_capacity_exhausted')
                with self._inventory.entity(binding.entity_id, create=True) as directory:
                    prior = self._inventory.read(directory, 'assignment.json')
                    if prior is not None and prior != assignment:
                        _fail('secret_journal_assignment_conflict')
                    pin = self._inventory.read(directory, 'source.json')
                    reservation = self._inventory.read(directory, 'reservation.json')
                    if prior is None:
                        # A stream found before our durable reservation has no trusted provenance.
                        try:
                            await js.stream_info(stream)
                        except NotFoundError:
                            pass
                        else:
                            _fail('secret_journal_unenrolled_stream')
                        self._inventory.match(directory, 'assignment.json', assignment)
                    fresh = reservation is None
                    if fresh:
                        reservation = {'token': secrets.token_hex(32)}
                        self._inventory.match(directory, 'reservation.json', reservation)
                    try:
                        info = await js.stream_info(stream)
                    except NotFoundError:
                        if not fresh or pin is not None:
                            _fail('secret_journal_recovery_required')
                        await self._account_current(account_request, account)
                        await self._custody.check(use)
                        config = self._policy.retention.stream_config(stream=stream, subject=subject)
                        config.metadata = {'agentmuxSecretJournal': reservation['token']}
                        try:
                            info = await js.add_stream(config)
                        except Exception:
                            # This read reconciles only our privately reserved create attempt.
                            info = await js.stream_info(stream)
                    self._policy.retention.validate(info, stream=stream, subject=subject)
                    if (type(info.config.metadata) is not dict
                            or info.config.metadata.get('agentmuxSecretJournal') != reservation['token']):
                        _fail('secret_journal_recovery_required')
                    if pin is None:
                        if info.state.last_seq != 0:
                            _fail('secret_journal_recovery_required')
                        pin = {'created': info.created.isoformat(), 'token': reservation['token']}
                        self._inventory.match(directory, 'source.json', pin)
                    elif pin != {'created': info.created.isoformat(), 'token': reservation['token']}:
                        _fail('secret_journal_recovery_required')
            self._inventory.source(binding.entity_id, sequence=info.state.last_seq)
        finally:
            await self._close_broker(client)

    async def _authorize_query(self, raw, native_proof):
        envelope = strict_loads(raw)
        payload, operation = envelope['payload'], envelope['operation']
        record = strict_loads(self._enrollment.record)
        if (envelope['contractId'] != 'capability-outcome-query'
                or envelope['destinationHubId'] != self._reader._hub
                or envelope['destinationServiceId'] != 'outcome-owner'
                or payload['input']['contractId'] != 'capability-secret-use'
                or operation['operationId'] == payload['input']['operationId']
                or payload['resourceRef'] != record['generationRef']
                or operation['effectiveActorRef'] != record['callerIdentityRef']
                or canonical_bytes(operation['scope']) != self._policy.scope):
            _fail('secret_journal_query_refused')
        snapshot = await self._reader.current()
        now = datetime.now(timezone.utc)
        decision = evaluate_snapshot(snapshot, raw, audience={
            'hubId': self._reader._hub, 'serviceId': 'outcome-owner'}, now=now)
        if (decision.outcome != 'allowed' or decision.operation != canonical_bytes(operation)
                or decision.valid_until is None or now >= decision.valid_until):
            _fail('secret_journal_query_refused')
        if native_proof is not None:
            from identity.ordinary_secret import refresh_secret_query_authority
            snapshot, now = await refresh_secret_query_authority(native_proof, self._reader, snapshot, raw,
                now=now, valid_until=decision.valid_until)
        state = strict_loads(snapshot.record)['state']
        index = _indexes(state, self._reader._hub)
        item = index['ordinarySecretReferences'].get(_key(payload['resourceRef']))
        if item is None or canonical_bytes(item) != self._enrollment.record or not _active(item, now):
            _fail('secret_journal_query_refused')
        validate_enrollment(state, index, item, self._reader._hub)

    async def _data_connection(self, binding, account_request, account):
        private = await self._account_custody.resolve(account_request, kind='nats-account-issuer')
        current = await self._account_current(account_request, account)
        seed = _account_seed(private, current.account_public_key)
        del private
        inbox = '_INBOX.' + secrets.token_hex(16)
        prefixes = ('$JS.API.',) if self._policy.jetstream_domain is None else (
            '$JS.API.', '$JS.' + self._policy.jetstream_domain + '.API.')
        publish = [owner_subject(binding), *(prefix + action + self._policy.stream(binding.entity_id)
            for prefix in prefixes for action in ('STREAM.INFO.', 'STREAM.MSG.GET.'))]
        credential = validate_credential(_issue(seed, publish, inbox, valid_until=current.valid_until),
            account_public_key=current.account_public_key, publish_subjects=publish,
            subscribe_subjects=[inbox + '.>'], private_inbox=True)
        del seed
        return await self._connect(credential, inbox), datetime.fromtimestamp(int(current.valid_until.timestamp()), timezone.utc)

    async def _open(self, raw, account_request, native_proof, query):
        if type(raw) is not bytes or len(raw) > 65536 or type(account_request) is not bytes:
            _fail()
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if canonical_bytes(envelope) != raw:
            _fail()
        if query:
            if envelope['contractId'] != 'capability-outcome-query':
                _fail()
            validate('capability-outcome-query', envelope['payload'])
            await self._authorize_query(raw, native_proof)
            operation_id = envelope['payload']['input']['operationId']
            scope = canonical_bytes(envelope['operation']['scope'])
            if scope != self._policy.scope:
                _fail()
            resolution = use = None
        else:
            use, resolution = await self._authorize(raw, native_proof)
            operation_id = strict_loads(resolution.original_operation)['operationId']
            scope = resolution.scope
        entity = secret_use_identity(strict_loads(scope), operation_id)
        binding = OwnerBinding(self._reader._hub, 'ordinary-secret-uses', entity, 'effect', scope)
        account = await self._account_current(account_request)
        if query:
            # No allocation or use-proof renewal on this branch.
            with self._inventory.entity(entity) as directory:
                assignment = self._inventory.read(directory, 'assignment.json')
                if assignment is None:
                    _fail()
        else:
            assignment = {'scope': strict_loads(scope), 'operation': strict_loads(resolution.original_operation),
                'requestDigest': resolution.original_request_digest, 'enrollmentDigest': enrollment_digest(self._enrollment),
                'entity': entity, 'stream': self._policy.stream(entity)}
            await self._prepare(binding, assignment, account_request, account, use)
        if query:
            if (type(assignment) is not dict or set(assignment) != {
                    'scope', 'operation', 'requestDigest', 'enrollmentDigest', 'entity', 'stream'}
                    or assignment['scope'] != strict_loads(scope) or assignment['entity'] != entity
                    or assignment['stream'] != self._policy.stream(entity)
                    or assignment['enrollmentDigest'] != enrollment_digest(self._enrollment)
                    or assignment['operation']['operationId'] != operation_id
                    or assignment['operation']['payloadDigest'] != envelope['payload']['input']['payloadDigest']):
                _fail('secret_journal_assignment_conflict')
        identity, _ = self._inventory.source(entity)
        if entity in self._resources and self._resources[entity][0]._closed:
            journal, client, _ = self._resources[entity]
            # A caller has joined and closed its consumer owner. Reopen local
            # observation custody over the same original, never a new use.
            await journal.close()
            async with journal._ledger.source_access():
                await self._close_broker(client)
                journal._ledger._source_closed = True
            del self._resources[entity]
        if entity in self._resources:
            journal, client, expires = self._resources[entity]
            if (datetime.now(timezone.utc) >= expires or client.is_connected is not True):
                fresh, fresh_expires = await self._data_connection(binding, account_request, account)
                try:
                    # Join the original source operation before its connection is
                    # closed. Pending HTTP effects keep their existing journal.
                    async with journal._ledger.source_access():
                        await self._account_current(account_request, account)
                        if query:
                            await self._authorize_query(raw, native_proof)
                        else:
                            await self._custody.check(use)
                        await self._close_broker(client)
                        journal._ledger._js = fresh.jetstream(domain=self._policy.jetstream_domain, timeout=3)
                        self._resources[entity] = journal, fresh, fresh_expires
                        client = fresh
                except BaseException:
                    await self._close_broker(fresh)
                    raise
            if query:
                group = await journal.current()
                await journal.authorize_query(raw, group, native_proof=native_proof)
            else:
                await journal.authorize(raw, native_proof=native_proof)
                await journal.current()
                await self._custody.check(use)
            await self._account_current(account_request, account)
            return journal
        client, expires = await self._data_connection(binding, account_request, account)
        journal = None
        try:
            ledger = _PinnedLedger(client.jetstream(domain=self._policy.jetstream_domain, timeout=3),
                stream=self._policy.stream(entity), subject=owner_subject(binding), binding=binding,
                retention=self._policy.retention, stream_identity=identity, require_completion_budget=True,
                inventory=self._inventory, entity=entity)
            journal = SecretOperationJournal(ledger, self._reader,
                enrollment=self._enrollment, observation_root=self._observations)
            if query:
                await journal.authorize_query(raw, native_proof=native_proof)
                group = await journal.current()
                await journal.authorize_query(raw, group, native_proof=native_proof)
            else:
                await journal.authorize(raw, native_proof=native_proof)
                await journal.current()
                await self._custody.check(use)
            await self._account_current(account_request, account)
            self._resources[entity] = (journal, client, expires)
            return journal
        except BaseException:
            if journal is not None:
                await journal.close()
            await self._close_broker(client)
            raise

    async def _close(self):
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)
        for journal, client, _ in reversed(tuple(self._resources.values())):
            await journal.close()
            if not journal._ledger._source_closed:
                async with journal._ledger.source_access():
                    await self._close_broker(client)
                    journal._ledger._source_closed = True
        self._resources.clear()
        for client in tuple(self._clients):
            await self._close_broker(client)
        self._inventory.close()

    async def close(self, *, timeout=5):
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            _fail('secret_journal_cleanup_invalid')
        self._closed = True
        if self._closing is None or self._closing.done() and self._closing.exception() is not None:
            self._closing = asyncio.create_task(self._close(), name='secret-journal-admission-close')
            self._closing.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        done, _ = await asyncio.wait((self._closing,), timeout=timeout)
        if not done:
            _fail('secret_journal_cleanup_incomplete')
        try:
            self._closing.result()
        except Exception:
            _fail('secret_journal_cleanup_incomplete')
