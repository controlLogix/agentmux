"""Host-enrolled private namespace ownership and retained document reads."""
import asyncio
import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.authority import LedgerAuthorityReader
from identity.capability_service import evaluate_capability_service_request
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject, validate_record
from state_owner.retention import Retention

DOCUMENT_LIMIT = 16_384
_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')


def private_storage_binding_digest(*, binding, plugin_identity_ref, instance_id, package_id,
                                   stream, stream_identity, retention, domain=""):
    """SHA-256 over JCS namespace enrollment, independent of runtime generation."""
    identity = plugin_identity_ref
    if (not isinstance(binding, OwnerBinding) or binding.owner_domain != 'plugin-private'
            or binding.entity_kind != 'plugin-storage' or not isinstance(stream_identity, StreamIdentity)
            or not isinstance(retention, Retention) or type(stream) is not str
            or re.fullmatch(r'[A-Za-z0-9_-]{1,128}',stream) is None
            or any(type(v) is not str or not _ID.fullmatch(v) for v in (instance_id,package_id))
            or type(domain) is not str or (domain and not _ID.fullmatch(domain))
            or type(identity) is not dict or set(identity) != {'id','ownerHubId','revision'}
            or any(type(identity[k]) is not str or not _ID.fullmatch(identity[k]) for k in ('id','ownerHubId'))
            or identity['ownerHubId'] != binding.hub_id or type(identity['revision']) is not int
            or not 0 <= identity['revision'] <= 9_007_199_254_740_991):
        raise ContractError('capability_owner_configuration')
    return payload_digest({'purpose':'agentmux-private-storage-binding-v1',
        'ownerHubId':binding.hub_id,'resourceId':binding.entity_id,
        'ownerDomain':binding.owner_domain,'entityKind':binding.entity_kind,
        'scope':strict_loads(binding.scope),'pluginIdentityRef':identity,
        'instanceId':instance_id,'packageId':package_id,'formatVersion':1,
        'documentLimitBytes':DOCUMENT_LIMIT,'stream':stream,'domain':domain,
        'streamCreated':stream_identity.created.isoformat(timespec='microseconds').replace('+00:00','Z'),
        'minimumSequence':stream_identity.minimum_sequence,'retention':{
            'maxBytes':retention.max_bytes,'reserveBytes':retention.reserve_bytes,'replicas':retention.replicas}})


@dataclass(frozen=True, repr=False)
class PrivateStorageResource:
    """A trusted logical-instance namespace; plugins cannot construct enrollment.

    Identity is canonical reference bytes. Logical instance and package persist over
    restarts; each call still requires the current complete native owner.
    """
    binding: OwnerBinding = field(repr=False)
    ledger: OwnerLedger = field(repr=False)
    plugin_identity: bytes = field(repr=False)
    instance_id: str = field(repr=False)
    package_id: str = field(repr=False)
    domain: str = field(default="", repr=False)
    _binding_digest: str = field(init=False, repr=False)
    _mutation_lock: object = field(init=False, repr=False)

    def __post_init__(self):
        if (not isinstance(self.binding, OwnerBinding)
                or self.binding.owner_domain != 'plugin-private'
                or self.binding.entity_kind != 'plugin-storage'
                or not isinstance(self.ledger, OwnerLedger)
                or self.ledger._binding != self.binding
                or not self.ledger.completion_budget_required
                or type(self.plugin_identity) is not bytes
                or any(type(v) is not str or not _ID.fullmatch(v)
                       for v in (self.instance_id, self.package_id))):
            raise ContractError('capability_owner_configuration')
        identity = strict_loads(self.plugin_identity)
        if (type(identity) is not dict or set(identity) != {'id','ownerHubId','revision'}
                or any(type(identity[k]) is not str or not _ID.fullmatch(identity[k])
                       for k in ('id','ownerHubId'))
                or identity['ownerHubId'] != self.binding.hub_id
                or type(identity['revision']) is not int
                or not 0 <= identity['revision'] <= 9_007_199_254_740_991):
            raise ContractError('capability_owner_configuration')
        object.__setattr__(self, 'plugin_identity', canonical_bytes(identity))
        if type(self.domain) is not str or (self.domain and not _ID.fullmatch(self.domain)):
            raise ContractError('capability_owner_configuration')
        prefix = getattr(self.ledger._js, '_prefix', None)
        expected = '$JS.' + self.domain + '.API' if self.domain else '$JS.API'
        if prefix is not None and prefix != expected:
            raise ContractError('capability_owner_configuration')
        digest = private_storage_binding_digest(binding=self.binding,
            plugin_identity_ref=identity,instance_id=self.instance_id,package_id=self.package_id,
            stream=self.ledger._stream,stream_identity=self.ledger._identity,
            retention=self.ledger._retention,domain=self.domain)
        object.__setattr__(self, '_binding_digest', digest)
        object.__setattr__(self, '_mutation_lock', asyncio.Lock())

    @classmethod
    def open_existing(cls, jetstream, *, binding, stream, stream_identity, retention,
                      plugin_identity_ref, instance_id, package_id, domain=""):
        if not isinstance(binding, OwnerBinding):
            raise ContractError('capability_owner_configuration')
        ledger = OwnerLedger(jetstream, stream=stream, subject=owner_subject(binding),
            binding=binding, stream_identity=stream_identity, retention=retention,
            require_completion_budget=True)
        return cls(binding, ledger, canonical_bytes(plugin_identity_ref), instance_id, package_id, domain)

    def __repr__(self):
        return '<PrivateStorageResource private>'

    @property
    def binding_digest(self):
        return self._binding_digest

    def check_request(self, snapshot, claims):
        """Check namespace ownership against the same admitted authority snapshot."""
        record = strict_loads(snapshot.record)
        rows = [row for row in record['state'].get('nativeInstances', [])
                if row['owner'] == claims['owner']]
        if (record['ownerHubId'] != self.binding.hub_id or len(rows) != 1
                or rows[0]['status'] != 'active'
                or canonical_bytes(rows[0]['identityRef']) != self.plugin_identity
                or rows[0]['owner']['instanceId'] != self.instance_id
                or rows[0]['owner']['pin']['packageId'] != self.package_id
                or canonical_bytes(claims['scope']) != self.binding.scope
                or claims['resourceRef']['id'] != self.binding.entity_id
                or claims['resourceRef']['ownerHubId'] != self.binding.hub_id
                or [item for item in rows[0].get('privateStorageResources', [])
                    if item['resourceId'] == self.binding.entity_id] != [{
                        'resourceId':self.binding.entity_id,'scope':strict_loads(self.binding.scope),
                        'bindingDigest':self.binding_digest}]):
            raise ContractError('capability_access_refused')

    async def authorize(self, authority, inner_raw, service_raw):
        """Require the full signed native wrapper even at a direct receiver call."""
        if (not isinstance(authority, LedgerAuthorityReader)
                or type(service_raw) is not bytes or len(service_raw) > 98_304):
            raise ContractError('capability_access_refused')
        request = strict_loads(service_raw)
        if canonical_bytes(request) != service_raw:
            raise ContractError('capability_access_refused')
        snapshot = await authority.current()
        claims = request['claims']
        decision = evaluate_capability_service_request(snapshot, service_raw,
            service_id=claims['serviceId'], now=datetime.now(timezone.utc))
        if base64.b64decode(claims['envelopeBytes'], validate=True) != inner_raw:
            raise ContractError('capability_access_refused')
        self.check_request(snapshot, claims)
        return decision

    def document(self, raw):
        """Validate private format and stored ownership without exposing metadata."""
        record = validate_record(raw, self.binding)
        state = record['state']
        expected = {'pluginIdentityRef':strict_loads(self.plugin_identity),
                    'instanceId':self.instance_id, 'packageId':self.package_id}
        if (set(state) != {'formatVersion','owner','value'}
                or state['formatVersion'] != 1 or type(state['formatVersion']) is not int
                or canonical_bytes(state['owner']) != canonical_bytes(expected)):
            raise ContractError('capability_resource_stale')
        value = canonical_bytes(state['value'])
        if len(value) > DOCUMENT_LIMIT:
            raise ContractError('capability_resource_stale')
        return record, value

    async def read(self, revision):
        snapshot = await self.ledger.current()
        if snapshot.latest is None:
            raise ContractError('capability_resource_stale')
        record, value = self.document(snapshot.latest.record)
        if record['entityVersion'] != revision:
            raise ContractError('capability_resource_stale')
        return value


    def _receipt(self, stored, expected_operation):
        record, _ = self.document(stored.record)
        operation = record['operation']
        audit = record.get('authorizationDecision')
        if (canonical_bytes(operation) != canonical_bytes(expected_operation)
                or not isinstance(audit, dict) or audit.get('contractId') != 'capability-storage-write'
                or audit.get('operationId') != operation['operationId']
                or canonical_bytes(audit.get('actorRef')) != canonical_bytes(operation['effectiveActorRef'])):
            raise ContractError('capability_access_refused')
        return {'receiptRef':{'id':record['recordId'],'ownerHubId':self.binding.hub_id,
                              'revision':record['entityVersion']},
                'resourceRef':{'id':self.binding.entity_id,'ownerHubId':self.binding.hub_id,
                               'revision':record['entityVersion']},
                'outcome':('applied' if record['outcome']=='committed' else
                           'conflict' if audit['reason']=='version_conflict' else 'rejected')}

    async def write(self, authority, inner_raw, service_raw):
        """Commit this exact operation once; conflicts never reapply the value."""
        async with self._mutation_lock:
            await self.authorize(authority, inner_raw, service_raw)
            envelope = strict_loads(inner_raw)
            if envelope['contractId'] != 'capability-storage-write':
                raise ContractError('capability_access_refused')
            operation, payload = envelope['operation'], envelope['payload']
            value = canonical_bytes(payload['input']['value'])
            if len(value) > DOCUMENT_LIMIT:
                raise ContractError('capability_service_unavailable')
            try:
                existing = await self.ledger.outcome(operation['operationId'], operation['payloadDigest'])
                if existing is not None:
                    return self._receipt(existing, operation)
                snapshot = await self.ledger.current()
                previous = None
                if snapshot.latest is not None:
                    previous, _ = self.document(snapshot.latest.record)
                conflict = (operation['expectedVersion'] != snapshot.sequence
                            or payload['resourceRef']['revision'] != snapshot.sequence)
                if conflict and previous is None:
                    # A rejection cannot invent a private value in an empty namespace.
                    raise ContractError('capability_resource_stale')
                decision = await self.authorize(authority, inner_raw, service_raw)
                identity = canonical_bytes({'resource':self.binding.entity_id,
                    'operationId':operation['operationId'],'payloadDigest':operation['payloadDigest']})
                record = {'schemaVersion':'1.0.0',
                    'recordId':'private_'+hashlib.sha256(identity).hexdigest(),
                    'entityId':self.binding.entity_id,'entityKind':self.binding.entity_kind,
                    'ownerHubId':self.binding.hub_id,'ownerDomain':self.binding.owner_domain,
                    'entityVersion':snapshot.sequence+1,'previousRevision':snapshot.sequence,
                    'operation':operation,'recordedAt':datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),
                    'outcome':'rejected' if conflict else 'committed',
                    'state':previous['state'] if conflict else {'formatVersion':1,'owner':{
                        'pluginIdentityRef':strict_loads(self.plugin_identity),
                        'instanceId':self.instance_id,'packageId':self.package_id},
                        'value':strict_loads(value)},'effects':[],'artifacts':[],'repository':None,
                    'authorizationDecision':{'operationId':operation['operationId'],
                        'decision':'allowed','reason':'version_conflict' if conflict else 'current_authority',
                        'actorRef':operation['effectiveActorRef'],'contractId':'capability-storage-write'}}
                stored = await self.ledger.append(record, expected_sequence=snapshot.sequence,
                    valid_until=decision.valid_until, completion_records=0)
                return self._receipt(stored, operation)
            except ContractError as exc:
                if str(exc) == 'owner_operation_conflict':
                    raise ContractError('capability_outcome_conflict') from None
                if str(exc) == 'owner_revision_conflict':
                    raise ContractError('capability_resource_stale') from None
                raise
