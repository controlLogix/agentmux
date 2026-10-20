"""Read selected retained task artifacts for backup under explicit current authority.

This private backup resolver grants nothing and exposes no public retrieval route.
It borrows the actual task service, identity ingress and selected Object Store.
"""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import re

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.authority import _active, _indexes, _key, evaluate_snapshot
from .artifacts import OwnerArtifacts
from .backup import _refs
from .ledger import OwnerBinding
from .recovery import _binding
from .task_service import TaskService

_CONTRACT = 'task-artifact-backup-read'
_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')


def task_artifact_backup_operation_id(binding, payload):
    """Stable identity for one exact task/prefix/reference maintenance read."""
    if type(binding) is not OwnerBinding:
        raise ContractError('task_artifact_custody_configuration')
    return 'artifact_backup_'+payload_digest({'purpose': 'amx-task-artifact-backup-read-v1',
        'binding': _binding(binding), 'payload': payload}).split(':')[1]


def _reference(value, hub):
    try:
        value = strict_loads(canonical_bytes(value))
        if (set(value) != {'id', 'ownerHubId', 'revision'} or value['ownerHubId'] != hub
                or type(value['id']) is not str or not _ID.fullmatch(value['id'])
                or type(value['revision']) is not int or not 1 <= value['revision'] <= 9007199254740991):
            raise ValueError()
        return value
    except Exception:
        raise ContractError('task_artifact_custody_configuration') from None


class TaskArtifactCustody:
    def __init__(self, service, artifacts, *, transport_ref, grant_ref, approvals_by_operation=None):
        if (type(service) is not TaskService or type(artifacts) is not OwnerArtifacts
                or artifacts._owner != service.owner._ledger._binding.hub_id):
            raise ContractError('task_artifact_custody_configuration')
        self._service, self._artifacts = service, artifacts
        self._ledger = service.owner._ledger
        if (getattr(self._ledger._js, '_nc', None) is not service._connection
                or getattr(artifacts._js, '_nc', None) is not service._connection
                or type(getattr(self._ledger._js, '_prefix', None)) is not str
                or getattr(artifacts._js, '_prefix', None) != self._ledger._js._prefix
                or getattr(artifacts._store, '_js', None) is not artifacts._js
                or getattr(artifacts._store, '_name', None) != artifacts._bucket):
            raise ContractError('task_artifact_custody_configuration')
        hub = self._ledger._binding.hub_id
        self._transport, self._grant = (_reference(value, hub) for value in (transport_ref, grant_ref))
        approvals = {} if approvals_by_operation is None else strict_loads(canonical_bytes(approvals_by_operation))
        if (type(approvals) is not dict or len(approvals) > 1024
                or any(not _ID.fullmatch(key) or type(refs) is not list or len(refs) > 32
                    for key, refs in approvals.items())):
            raise ContractError('task_artifact_custody_configuration')
        self._approvals = {key: [_reference(ref, hub) for ref in refs] for key, refs in approvals.items()}
        self._prefix = None
        self._references = {}

    def __repr__(self):
        return '<TaskArtifactCustody private>'

    def _open(self):
        # Backup startup precedes command readiness. A close fence must still
        # stop both new reads and acceptance of bytes already being retrieved.
        if (self._service._closed or self._service._host is not None and self._service._host._closed):
            raise ContractError('task_artifact_custody_unavailable')

    async def refresh(self, *, max_artifacts=1024, max_total_bytes=1_073_741_824):
        """Pin membership to an actual verified retained task-history watermark."""
        self._open()
        snapshot = await self._ledger.current()
        self._open()
        if snapshot.latest is None:
            raise ContractError('task_artifact_source_unavailable')
        references = _refs(snapshot.records, self._ledger._binding, max_artifacts, max_total_bytes)
        for reference in references.values():
            self._artifacts._check_ref(reference)
        self._prefix, self._references = snapshot.sequence, references

    async def _signer(self, raw=None, envelope=None):
        self._open()
        snapshot = await self._service.owner._authority.current()
        self._open()
        record = strict_loads(snapshot.record)
        index = _indexes(record['state'], self._ledger._binding.hub_id)
        now = datetime.now(timezone.utc)
        identity_ref = strict_loads(self._service._identity)
        signer = index['issuers'].get(_key(strict_loads(self._service._issuer)))
        identity = index['identities'].get(_key(identity_ref))
        transport = index['transports'].get(_key(self._transport))
        public = base64.urlsafe_b64encode(bytes(SigningKey(self._service._seed).verify_key)).decode().rstrip('=')
        if (signer is None or identity is None or transport is None
                or identity['kind'] != 'service' or not _active(identity, now)
                or not _active(signer, now) or signer['identityRef'] != identity_ref
                or signer['instanceId'] != self._service._instance or signer['publicKey'] != public
                or not _active(transport, now) or transport['identityRef'] != identity_ref
                or transport['publicKey'] != public or transport['method'] != 'nats-credential-mapping'
                or canonical_bytes(transport['issuerRef']) != self._service.ingress._issuer_ref):
            raise ContractError('task_artifact_reader_unavailable')
        valid_until = datetime.fromisoformat(signer['expiresAt'])
        if raw is not None:
            # Signer and read authority must come from this same actual current
            # identity snapshot; separate lookups could accept a withdrawn signer.
            decision = evaluate_snapshot(snapshot, raw,
                audience={'hubId':self._ledger._binding.hub_id,'serviceId':'task-owner'}, now=now)
            if (decision.outcome != 'allowed' or decision.valid_until is None or not now < decision.valid_until
                    or decision.operation != canonical_bytes(envelope['operation'])
                    or canonical_bytes(envelope['operation']['scope']) != self._ledger._binding.scope):
                raise ContractError('task_artifact_read_not_authorized')
            valid_until = min(valid_until, decision.valid_until)
        return now, valid_until

    async def retrieve(self, reference):
        """Accept bytes only for the pinned prefix and an exact current read grant."""
        self._open()
        full = canonical_bytes(reference)
        prefix, references = self._prefix, self._references
        if prefix is None or full not in references:
            raise ContractError('task_artifact_reference_not_retained')
        reference = strict_loads(full)
        self._artifacts._check_ref(reference)
        now, signer_end = await self._signer()
        payload = {'taskId': self._ledger._binding.entity_id, 'artifactRef': reference, 'sourceRevision': prefix}
        validate(_CONTRACT, payload)
        operation_id = task_artifact_backup_operation_id(self._ledger._binding, payload)
        end = min(now+timedelta(seconds=30), signer_end)
        if not now < end:
            raise ContractError('task_artifact_reader_unavailable')
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': self._ledger._binding.hub_id,
            'profileId': self._service.owner._authority._profile, 'authorityId': self._service.owner._authority._entity,
            'transportRef': self._transport, 'grantRef': self._grant, 'operationId': operation_id,
            'expectedVersion': prefix, 'contractId': _CONTRACT, 'payload': payload,
            'approvalRefs': self._approvals.get(operation_id, []),
            'issuedAt': now.isoformat(timespec='microseconds').replace('+00:00', 'Z'),
            'expiresAt': end.isoformat(timespec='microseconds').replace('+00:00', 'Z')}
        raw = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, self._service._seed)})
        cancellation = {'id': 'cancel_'+operation_id, 'ownerHubId': self._ledger._binding.hub_id, 'revision': 1}
        admitted = await self._service.ingress.admit(raw, cancellation_ref=cancellation)
        if admitted.envelope is None or admitted.decision.outcome != 'allowed' or admitted.decision.valid_until is None:
            raise ContractError('task_artifact_read_not_authorized')
        envelope = strict_loads(admitted.envelope)
        if (envelope['operation']['caller']['kind'] != 'service'
                or canonical_bytes(envelope['operation']['caller']['authenticatedIdentityRef']) != self._service._identity
                or envelope['operation']['effectiveActorRef'] != strict_loads(self._service._identity)):
            raise ContractError('task_artifact_reader_unavailable')
        _, current_end = await self._signer(admitted.envelope, envelope)
        deadline = min(end, admitted.decision.valid_until, current_end)
        remaining = (deadline-datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            raise ContractError('task_artifact_read_not_authorized')
        async with asyncio.timeout(remaining):
            result = await self._artifacts.retrieve(reference)
        self._open()
        snapshot = await self._ledger.current()
        self._open()
        if snapshot.sequence < prefix:
            raise ContractError('task_artifact_source_unavailable')
        await self._signer(admitted.envelope, envelope)
        return result
