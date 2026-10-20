"""Full federation policies behind one retained configuration aggregate.

The small configuration document is authoritative; encrypted Object Store bytes
are immutable payloads, not a second configuration store. This module never writes
the selected TOML file or admits a storage generation. That belongs to the
selected-source transition after a committed reference has been reconciled.
"""
import asyncio
import base64
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import re
import tomllib

from nacl.secret import SecretBox
from nacl.signing import SigningKey
from nats.js.api import DiscardPolicy, RetentionPolicy, StorageType
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.authority import _active, _indexes, _key
from identity.ingress import EnrolledIngress
from .artifacts import OwnerArtifacts
from .backup import _refs
from .backup_lifecycle import _join
from .configuration import ConfigurationOwner
from .conversation_migration import ConversationKey
from .ledger import OwnerBinding
from .recovery import _binding

MAX_POLICY_BYTES = 65536
MEDIA_TYPE = 'application/vnd.agentmux.federation-policy+toml+secretbox'
SCHEMA_REF = 'federation-policy.json'
_DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')
_REF = {'type': 'object', 'additionalProperties': False,
    'properties': {'id': {'type': 'string', 'pattern': '^[a-z][a-z0-9_-]{0,95}$'},
        'ownerHubId': {'type': 'string', 'pattern': '^[a-z][a-z0-9_-]{0,95}$'},
        'revision': {'type': 'integer', 'minimum': 1, 'maximum': 9007199254740991}},
    'required': ['id', 'ownerHubId', 'revision']}
_ARTIFACT = {'type': 'object', 'additionalProperties': False,
    'properties': {'artifactId': _REF['properties']['id'], 'ownerHubId': _REF['properties']['ownerHubId'],
        'storeRef': _REF, 'version': _REF['properties']['id'],
        'digest': {'type': 'string', 'pattern': '^sha256:[a-f0-9]{64}$'},
        'bytes': {'type': 'integer', 'minimum': SecretBox.NONCE_SIZE + SecretBox.MACBYTES,
            'maximum': MAX_POLICY_BYTES + SecretBox.NONCE_SIZE + SecretBox.MACBYTES},
        'mediaType': {'const': MEDIA_TYPE}},
    'required': ['artifactId', 'ownerHubId', 'storeRef', 'version', 'digest', 'bytes', 'mediaType']}
_POLICY = {'type': 'object', 'additionalProperties': False,
    'properties': {'digest': {'type': 'string', 'pattern': '^sha256:[a-f0-9]{64}$'},
        'bytes': {'type': 'integer', 'minimum': 0, 'maximum': MAX_POLICY_BYTES},
        'artifactRef': _ARTIFACT, 'keyRef': _REF},
    'required': ['digest', 'bytes', 'artifactRef', 'keyRef']}
_TARGET = {'type': 'object', 'additionalProperties': False,
    'properties': {'sourceRef': _REF, 'selectionDigest': {'type': 'string', 'pattern': '^sha256:[a-f0-9]{64}$'},
        'repositoryId': {'type': 'string', 'minLength': 1, 'maxLength': 128}},
    'required': ['sourceRef', 'selectionDigest', 'repositoryId']}
_CHANGE = {'type': 'object', 'additionalProperties': False,
    'properties': {'verb': {'enum': ['trust', 'share', 'unshare']},
        'arguments': {'type': 'object', 'maxProperties': 8}}, 'required': ['verb', 'arguments']}
_INTENT = {'type': 'object', 'additionalProperties': False,
    'properties': {'operationId': _REF['properties']['id'],
        'preparationDigest': {'type': 'string', 'pattern': '^sha256:[a-f0-9]{64}$'},
        'actorRef': _REF, 'callerRef': _REF, 'change': _CHANGE},
    'required': ['operationId', 'preparationDigest', 'actorRef', 'callerRef', 'change']}
FEDERATION_POLICY_SCHEMA = canonical_bytes({'$schema': 'https://json-schema.org/draft/2020-12/schema',
    'type': 'object', 'additionalProperties': False,
    'properties': {'format': {'const': 'amx-federation-policy-v1'}, 'target': _TARGET,
        'previousRevision': {'type': 'integer', 'minimum': 0, 'maximum': 9007199254740990},
        'originDigest': {'type': 'string', 'pattern': '^sha256:[a-f0-9]{64}$'},
        'oldPolicy': _POLICY, 'desiredPolicy': _POLICY, 'projectionIntent': _INTENT},
    'required': ['format', 'target', 'previousRevision', 'originDigest', 'oldPolicy',
        'desiredPolicy', 'projectionIntent']})


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _policy(raw):
    if type(raw) is not bytes or len(raw) > MAX_POLICY_BYTES:
        raise ContractError('federation_policy_size')
    try:
        tomllib.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError):
        raise ContractError('federation_policy_invalid') from None
    return {'digest': _digest(raw), 'bytes': len(raw)}


def _reference(value, hub):
    value = strict_loads(canonical_bytes(value))
    if (type(value) is not dict or set(value) != {'id', 'ownerHubId', 'revision'}
            or type(value['id']) is not str or not _ID.fullmatch(value['id'])
            or value['ownerHubId'] != hub or type(value['revision']) is not int
            or not 1 <= value['revision'] <= 9007199254740991):
        raise ContractError('federation_policy_binding')
    return value


@dataclass(frozen=True, repr=False)
class FederationPolicyTarget:
    """A protected selection, never a path supplied by a command."""
    binding: OwnerBinding
    _selection: bytes = field(repr=False)

    @classmethod
    def selected(cls, binding, *, source_ref, source, repository, local_peer):
        try:
            if (type(binding) is not OwnerBinding
                    or (binding.owner_domain, binding.entity_kind) != ('configuration', 'configuration')
                    or type(source) is not dict or set(source) != {'database', 'policy'}
                    or set(source['database']) != {'path', 'applicationId', 'userVersion'}
                    or set(source['policy']) != {'path', 'sha256'}
                    or not _DIGEST.fullmatch(source['policy']['sha256'])
                    or type(repository) is not dict or set(repository) not in (
                        {'localName', 'repositoryId', 'normalizedRemote'},
                        {'localName', 'repositoryId', 'normalizedRemote', 'counterPrefix'})
                    or any(type(v) is not str or not v for v in repository.values())
                    or type(local_peer) is not str or not local_peer):
                raise ValueError()
            selection = {'binding': _binding(binding), 'sourceRef': _reference(source_ref, binding.hub_id),
                'source': source, 'repository': repository, 'localPeer': local_peer}
            return cls(binding, canonical_bytes(selection))
        except (ValueError, KeyError, TypeError):
            raise ContractError('federation_policy_binding') from None

    @property
    def descriptor(self):
        selected = strict_loads(self._selection)
        return {'sourceRef': selected['sourceRef'], 'selectionDigest': _digest(self._selection),
            'repositoryId': selected['repository']['repositoryId']}

    @property
    def origin_digest(self):
        return strict_loads(self._selection)['source']['policy']['sha256']

    def __repr__(self):
        return '<FederationPolicyTarget private>'


@dataclass(frozen=True, repr=False)
class CommittedFederationPolicy:
    revision: int
    operation_id: str
    payload_digest: str
    _document: bytes = field(repr=False)
    policy_bytes: bytes = field(repr=False)

    @property
    def document(self):
        return strict_loads(self._document)

    def __repr__(self):
        return '<CommittedFederationPolicy private>'


class FederationPolicyCustody:
    """Borrow selected encrypted storage and join every original storage operation."""
    def __init__(self, target, artifacts, key, *, ingress, backup_transport_ref, backup_grant_ref):
        if (type(target) is not FederationPolicyTarget or type(artifacts) is not OwnerArtifacts
                or type(key) is not ConversationKey or type(ingress) is not EnrolledIngress
                or artifacts._owner != target.binding.hub_id
                or artifacts._max_bytes < MAX_POLICY_BYTES + SecretBox.NONCE_SIZE + SecretBox.MACBYTES):
            raise ContractError('federation_policy_custody_configuration')
        self.target, self._artifacts, self._key, self._ingress = target, artifacts, key, ingress
        hub = target.binding.hub_id
        self._key_ref = _reference(strict_loads(key._reference), hub)
        self._transport = _reference(backup_transport_ref, hub)
        self._grant = _reference(backup_grant_ref, hub)
        self._owner = None
        self._pending = set()
        self._store_created = None

    def __repr__(self):
        return '<FederationPolicyCustody private>'

    def bind(self, owner):
        if (not isinstance(owner, FederationPolicyOwner) or self._owner is not None
                or owner._ledger._binding != self.target.binding
                or self._ingress._reader is not owner._authority
                or getattr(self._artifacts._js, '_nc', None) is not owner._connection
                or owner._connection is None
                or getattr(owner._ledger._js, '_nc', None) is not owner._connection
                or type(getattr(owner._ledger._js, '_prefix', None)) is not str
                or self._artifacts._js._prefix != owner._ledger._js._prefix
                or getattr(self._artifacts._store, '_js', None) is not self._artifacts._js
                or getattr(self._artifacts._store, '_name', None) != self._artifacts._bucket):
            raise ContractError('federation_policy_custody_configuration')
        self._owner = owner

    async def _owned(self, awaitable):
        task = asyncio.create_task(awaitable)
        self._pending.add(task)
        try:
            return await _join(task)
        finally:
            if task.done():
                self._pending.discard(task)

    async def join(self):
        for task in tuple(self._pending):
            try:
                await _join(task)
            except BaseException:
                if not task.done() or asyncio.current_task().cancelling():
                    raise

    async def _check_store(self):
        info = await self._owned(self._artifacts._js.stream_info('OBJ_'+self._artifacts._bucket))
        config = info.config
        if (config.name != 'OBJ_'+self._artifacts._bucket
                or sorted(config.subjects or ()) != sorted(('$O.'+self._artifacts._bucket+'.C.>',
                    '$O.'+self._artifacts._bucket+'.M.>'))
                or config.storage != StorageType.FILE or config.retention != RetentionPolicy.LIMITS
                or config.discard != DiscardPolicy.NEW or config.max_age not in (None, 0)
                or config.max_msgs not in (None, -1) or config.max_msgs_per_subject not in (None, -1)
                or type(config.max_bytes) is not int or config.max_bytes < 2*(MAX_POLICY_BYTES+40)
                or getattr(config, 'allow_msg_ttl', False)
                or self._store_created is not None and info.created != self._store_created):
            raise ContractError('federation_policy_retention_invalid')
        self._store_created = info.created

    def check_reference(self, policy):
        try:
            if (set(policy) != {'digest', 'bytes', 'artifactRef', 'keyRef'}
                    or policy['keyRef'] != self._key_ref
                    or type(policy['bytes']) is not int or not 0 <= policy['bytes'] <= MAX_POLICY_BYTES
                    or not _DIGEST.fullmatch(policy['digest'])
                    or policy['artifactRef']['mediaType'] != MEDIA_TYPE
                    or policy['artifactRef']['bytes'] != policy['bytes'] + SecretBox.NONCE_SIZE + SecretBox.MACBYTES):
                raise ValueError()
            self._artifacts._check_ref(policy['artifactRef'])
            self._key.check()
        except (TypeError, ValueError, KeyError):
            raise ContractError('federation_policy_reference_invalid') from None

    async def stage(self, raw):
        plain = _policy(raw)
        await self._check_store()
        encrypted = bytes(SecretBox(self._key.read()).encrypt(raw))
        reference = await self._owned(self._artifacts.upload(encrypted, media_type=MEDIA_TYPE))
        result = dict(plain, artifactRef=reference, keyRef=dict(self._key_ref))
        self.check_reference(result)
        return result

    async def retrieve(self, policy):
        # Only the owner invokes this after current command authorization. No
        # public reference-only retrieval route is supplied by this custody.
        self.check_reference(policy)
        await self._check_store()
        encrypted = await self._owned(self._artifacts.retrieve(policy['artifactRef']))
        try:
            raw = SecretBox(self._key.read()).decrypt(encrypted)
            if _policy(raw) != {name: policy[name] for name in ('digest', 'bytes')}:
                raise ValueError()
            return raw
        except Exception as error:
            if isinstance(error, ContractError):
                raise
            raise ContractError('federation_policy_artifact_invalid') from None

    async def _backup_request(self, prefix):
        owner = self._owner
        if owner is None or owner._closed:
            raise ContractError('federation_policy_unavailable')
        snapshot = await owner._authority.current()
        state = strict_loads(snapshot.record)['state']
        index = _indexes(state, owner._ledger._binding.hub_id)
        now = datetime.now(timezone.utc)
        issuer = index['issuers'].get(_key(strict_loads(owner._issuer)))
        transport = index['transports'].get(_key(self._transport))
        identity = None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
        public = base64.urlsafe_b64encode(bytes(SigningKey(owner._seed).verify_key)).decode().rstrip('=')
        if (issuer is None or transport is None or identity is None or identity['kind'] != 'service'
                or not all(_active(row, now) for row in (issuer, transport, identity))
                or issuer['publicKey'] != public or transport['publicKey'] != public
                or transport['identityRef'] != issuer['identityRef']
                or canonical_bytes(transport['issuerRef']) != self._ingress._issuer_ref):
            raise ContractError('federation_policy_backup_refused')
        end = min(now + timedelta(seconds=30), datetime.fromisoformat(issuer['expiresAt']))
        payload = {'configurationRef': {'id': owner._ledger._binding.entity_id,
            'ownerHubId': owner._ledger._binding.hub_id, 'revision': prefix},
            'owner': strict_loads(owner._owner)}
        operation = 'policy_backup_' + payload_digest({'binding': _binding(owner._ledger._binding),
            'prefix': prefix}).split(':')[1]
        stamp = lambda value: value.isoformat(timespec='microseconds').replace('+00:00', 'Z')
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': owner._ledger._binding.hub_id,
            'profileId': owner._authority._profile, 'authorityId': owner._authority._entity,
            'transportRef': self._transport, 'grantRef': self._grant, 'operationId': operation,
            'expectedVersion': prefix, 'contractId': 'configuration-read', 'payload': payload,
            'approvalRefs': [], 'issuedAt': stamp(now), 'expiresAt': stamp(end)}
        request = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, owner._seed)})
        admitted = await self._ingress.admit(request, cancellation_ref={
            'id': 'cancel_' + operation, 'ownerHubId': owner._ledger._binding.hub_id, 'revision': 1})
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ContractError('federation_policy_backup_refused')
        envelope = strict_loads(admitted.envelope)
        if (envelope['operation']['caller']['kind'] != 'service'
                or envelope['operation']['effectiveActorRef'] != issuer['identityRef']):
            raise ContractError('federation_policy_backup_refused')
        await owner._authorize(admitted.envelope, envelope)
        return admitted.envelope, envelope

    async def retrieve_backup(self, reference):
        owner = self._owner
        if owner is None or owner._closed:
            raise ContractError('federation_policy_unavailable')
        async with owner._policy_call():
            return await self._retrieve_backup(reference)

    async def _retrieve_backup(self, reference):
        owner = self._owner
        snapshot = await owner._ledger.current()
        for stored in snapshot.records:
            owner._retained(stored)
        references = _refs(snapshot.records, owner._ledger._binding, 4096, 1_073_741_824)
        if canonical_bytes(reference) not in references:
            raise ContractError('federation_policy_reference_not_retained')
        raw, envelope = await self._backup_request(snapshot.sequence)
        await self._check_store()
        result = await self._owned(self._artifacts.retrieve(reference))
        current = await owner._ledger.current()
        if current.sequence < snapshot.sequence:
            raise ContractError('federation_policy_reconciliation_required')
        await owner._authorize(raw, envelope)
        # The configuration signer is distinct from its identity ingress. A
        # withdrawn owner key must also refuse after the awaited storage read.
        await self._backup_request(snapshot.sequence)
        return result


class FederationPolicyOwner(ConfigurationOwner):
    """The existing signed configuration commit path with typed policy payloads."""
    def __init__(self, *args, policy_custody, **kwargs):
        if (type(policy_custody) is not FederationPolicyCustody
                or kwargs.get('schema_ref') != SCHEMA_REF
                or kwargs.get('schema_resources') != {SCHEMA_REF: FEDERATION_POLICY_SCHEMA}
                or kwargs.get('require_native_activation', True)):
            raise ContractError('federation_policy_owner_configuration')
        self.custody = policy_custody
        self._preparations = {}
        self._policy_calls = set()
        self._policy_closing = None
        super().__init__(*args, **kwargs)
        policy_custody.bind(self)

    def __repr__(self):
        return '<FederationPolicyOwner private>'

    async def _authorize(self, raw, envelope):
        if getattr(getattr(self, '_host', None), '_closed', False):
            raise ContractError('federation_policy_unavailable')
        decision, snapshot = await super()._authorize(raw, envelope)
        if self._closed or getattr(getattr(self, '_host', None), '_closed', False):
            raise ContractError('federation_policy_unavailable')
        # A federation aggregate cannot be substituted for an ordinary native
        # plugin slot, whose initialization has separate activation obligations.
        if any(self._same_slot(row['owner']) for row in strict_loads(snapshot.record)['state'].get('nativeInstances', ())):
            raise ContractError('federation_policy_owner_configuration')
        if envelope['payload']['owner'] != strict_loads(self._owner):
            raise ContractError('configuration_binding_mismatch')
        return decision, snapshot

    @asynccontextmanager
    async def _policy_call(self):
        if self._closed or len(self._policy_calls) >= 32:
            raise ContractError('federation_policy_unavailable')
        finished = asyncio.get_running_loop().create_future()
        self._policy_calls.add(finished)
        try:
            yield
        finally:
            self._policy_calls.discard(finished)
            finished.set_result(None)

    def _document(self, state):
        raw = super()._document(state)
        document = strict_loads(raw)
        if (document['target'] != self.custody.target.descriptor
                or document['originDigest'] != self.custody.target.origin_digest
                or document['previousRevision'] + 1 != state['revision']
                or state['secretReferences'] != [self.custody._key_ref]
                or len(canonical_bytes(document['projectionIntent']['change'])) > 4096):
            raise ContractError('federation_policy_binding')
        for name in ('oldPolicy', 'desiredPolicy'):
            self.custody.check_reference(document[name])
        return raw

    def _record_artifacts(self, state):
        document = strict_loads(self._document(state))
        references = [document[name]['artifactRef'] for name in ('oldPolicy', 'desiredPolicy')]
        return [strict_loads(full) for full in dict.fromkeys(map(canonical_bytes, references))]

    def preparation_bytes(self, *, previous_revision, old_policy, desired_policy, change):
        """Build a small proposal to authenticate; this grants and commits nothing."""
        old, desired = _policy(old_policy), _policy(desired_policy)
        if (type(previous_revision) is not int or not 0 <= previous_revision <= 9007199254740990
                or type(change) is not dict or set(change) != {'verb', 'arguments'}
                or change['verb'] not in ('trust', 'share', 'unshare')
                or type(change['arguments']) is not dict or len(change['arguments']) > 8
                or len(canonical_bytes(change)) > 4096):
            raise ContractError('federation_policy_preparation_invalid')
        return canonical_bytes({'format': 'amx-federation-policy-preparation-v1',
            'target': self.custody.target.descriptor, 'previousRevision': previous_revision,
            'originDigest': self.custody.target.origin_digest, 'oldPolicy': old,
            'desiredPolicy': desired, 'change': change})

    def _envelope(self, raw, contract):
        if type(raw) is not bytes or len(raw) > 65536:
            raise ContractError('federation_policy_request_invalid')
        envelope = strict_loads(raw)
        validate('message-envelope', envelope)
        if (envelope['kind'] != 'command' or envelope['contractId'] != contract
                or envelope['destinationServiceId'] != 'configuration-owner'):
            raise ContractError('federation_policy_request_invalid')
        validate(contract, envelope['payload'])
        self._target(envelope['payload'])
        return envelope

    async def prepare(self, raw, *, old_policy, desired_policy):
        """Stage bytes only after the actual signed set grant authorizes the proposal.

        The returned descriptor must be signed again as the final configuration-set
        payload. A proposal signature never becomes authority for changed bytes.
        Staging is not an accepted policy change. An uncertain orphan is retained.
        """
        async with self._policy_call():
            return await self._prepare_request(raw, old_policy=old_policy, desired_policy=desired_policy)

    async def _prepare_request(self, raw, *, old_policy, desired_policy):
        envelope = self._envelope(raw, 'configuration-set')
        encoded = envelope['payload']['configurationBytes']
        try:
            proposal = base64.b64decode(encoded, validate=True)
            value = strict_loads(proposal)
            expected = self.preparation_bytes(previous_revision=envelope['operation']['expectedVersion'],
                old_policy=old_policy, desired_policy=desired_policy, change=value['change'])
            if (proposal != expected or base64.b64encode(proposal).decode() != encoded
                    or envelope['payload']['schemaRef'] != self._schema
                    or envelope['payload']['secretReferences'] != [self.custody._key_ref]):
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise ContractError('federation_policy_preparation_invalid') from None
        await self._authorize(raw, envelope)
        key = canonical_bytes(envelope['operation'])
        existing = self._preparations.get(key)
        if existing is None:
            if len(self._preparations) >= 32:
                raise ContractError('federation_policy_preparation_capacity')
            existing = asyncio.create_task(self._prepare(raw, envelope, old_policy, desired_policy, value))
            existing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
            self._preparations[key] = existing
        await asyncio.wait({existing})
        result = existing.result()
        await self._authorize(raw, envelope)
        return result

    async def _prepare(self, raw, envelope, old_policy, desired_policy, proposal):
        revision = proposal['previousRevision']
        snapshot = await self._ledger.current()
        if snapshot.sequence != revision:
            raise ContractError('configuration_revision_conflict')
        if snapshot.latest is None:
            if _digest(old_policy) != self.custody.target.origin_digest:
                raise ContractError('federation_policy_binding')
            await self._authorize(raw, envelope)
            previous = await self.custody.stage(old_policy)
        else:
            state = self._retained(snapshot.latest)
            previous = strict_loads(self._document(state))['desiredPolicy']
            await self._authorize(raw, envelope)
            if await self.custody.retrieve(previous) != old_policy:
                raise ContractError('federation_policy_binding')
        await self._authorize(raw, envelope)
        desired = await self.custody.stage(desired_policy)
        await self._authorize(raw, envelope)
        if (await self._ledger.current()).sequence != revision:
            raise ContractError('configuration_revision_conflict')
        operation = envelope['operation']
        result = canonical_bytes({'format': 'amx-federation-policy-v1', 'target': proposal['target'],
            'previousRevision': revision, 'originDigest': proposal['originDigest'],
            'oldPolicy': previous, 'desiredPolicy': desired,
            'projectionIntent': {'operationId': operation['operationId'],
                'preparationDigest': operation['payloadDigest'],
                'actorRef': operation['effectiveActorRef'],
                'callerRef': operation['caller']['authenticatedIdentityRef'], 'change': proposal['change']}})
        if len(result) > 16384:
            raise ContractError('federation_policy_preparation_invalid')
        return result

    async def _set(self, raw, envelope):
        payload, operation = envelope['payload'], envelope['operation']
        state = {'format': 'amx-configuration-v1', 'owner': payload['owner'], 'schemaRef': payload['schemaRef'],
            'configurationBytes': payload['configurationBytes'], 'secretReferences': payload['secretReferences'],
            'configurationChecksum': _digest(base64.b64decode(payload['configurationBytes'], validate=True)),
            'revision': operation['expectedVersion'] + 1}
        document = strict_loads(self._document(state))
        intent = document['projectionIntent']
        if (intent['operationId'] != operation['operationId'] or intent['actorRef'] != operation['effectiveActorRef']
                or intent['callerRef'] != operation['caller']['authenticatedIdentityRef']):
            raise ContractError('federation_policy_binding')
        existing = await self._ledger.outcome(operation['operationId'], operation['payloadDigest'])
        if existing is None:
            snapshot = await self._ledger.current()
            if snapshot.sequence != document['previousRevision']:
                raise ContractError('configuration_revision_conflict')
            if snapshot.latest is None:
                if document['oldPolicy']['digest'] != self.custody.target.origin_digest:
                    raise ContractError('federation_policy_binding')
            else:
                previous = strict_loads(self._document(self._retained(snapshot.latest)))
                if document['oldPolicy'] != previous['desiredPolicy']:
                    raise ContractError('federation_policy_binding')
        for name in ('oldPolicy', 'desiredPolicy'):
            await self._authorize(raw, envelope)
            await self.custody.retrieve(document[name])
            await self._authorize(raw, envelope)
        result = await super()._set(raw, envelope)
        for key, preparation in tuple(self._preparations.items()):
            if (preparation.done() and strict_loads(key)['operationId'] == operation['operationId']):
                del self._preparations[key]
        return result

    async def reconcile(self, raw, *, operation_id, payload_digest):
        """Resolve one original committed outcome under a fresh signed read grant."""
        async with self._policy_call():
            return await self._reconcile(raw, operation_id=operation_id, payload_digest=payload_digest)

    async def _reconcile(self, raw, *, operation_id, payload_digest):
        envelope = self._envelope(raw, 'configuration-read')
        await self.handle(raw)
        await self._authorize(raw, envelope)
        stored = await self._ledger.outcome(operation_id, payload_digest)
        if stored is None:
            raise ContractError('federation_policy_reconciliation_required')
        return await self._resolve_stored(raw, envelope, stored)

    async def read_current(self, raw):
        """Recover the current original operation when a restarted caller lost it."""
        async with self._policy_call():
            envelope = self._envelope(raw, 'configuration-read')
            await self.handle(raw)
            await self._authorize(raw, envelope)
            snapshot = await self._ledger.current()
            if snapshot.latest is None:
                raise ContractError('federation_policy_reconciliation_required')
            return await self._resolve_stored(raw, envelope, snapshot.latest)

    async def _resolve_stored(self, raw, envelope, stored):
        state = self._retained(stored)
        document = self._document(state)
        policy = strict_loads(document)['desiredPolicy']
        result = await self.custody.retrieve(policy)
        current = await self._ledger.current()
        if current.sequence != stored.sequence or current.latest.record != stored.record:
            raise ContractError('federation_policy_stale')
        await self._authorize(raw, envelope)
        operation = strict_loads(stored.record)['operation']
        return CommittedFederationPolicy(stored.sequence, operation['operationId'], operation['payloadDigest'], document, result)

    async def _close_policy(self):
        # Public calls can be inside authority or ledger I/O before they allocate
        # a blob task. Keep those original callers until their finally blocks run.
        for original in tuple(self._policy_calls):
            try:
                await _join(original)
            except BaseException:
                if not original.done() or asyncio.current_task().cancelling():
                    raise
        # Keep borrowed storage and key custody until every original preparation,
        # upload and read has stopped, including cancelled callers.
        for original in tuple(self._preparations.values()):
            try:
                await _join(original)
            except BaseException:
                if not original.done() or asyncio.current_task().cancelling():
                    raise
        await self.custody.join()
        return await super().close(timeout=None)

    async def close(self, *, timeout=3):
        if timeout is not None and (type(timeout) not in (int, float) or not 0 < timeout <= 10):
            raise ContractError('configuration_cleanup_incomplete')
        self._closed = True
        if self._policy_closing is None or (self._policy_closing.done()
                and not self._policy_closing.cancelled() and self._policy_closing.exception() is not None):
            self._policy_closing = asyncio.create_task(self._close_policy())
            self._policy_closing.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        _, pending = await asyncio.wait({self._policy_closing}, timeout=timeout)
        if pending:
            raise ContractError('configuration_cleanup_incomplete')
        return self._policy_closing.result()
