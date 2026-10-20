"""Retained configuration event intents and a host-private replay source."""
import asyncio
from dataclasses import dataclass
from datetime import datetime
import hashlib
import re

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from .ledger import MAX_SEQUENCE, OwnerLedger


def change_payload(binding, state):
    payload = {'configurationRef': {'id': binding.entity_id, 'ownerHubId': binding.hub_id,
        'revision': state['revision']}, 'owner': state['owner'], 'schemaRef': state['schemaRef'],
        'configurationChecksum': state['configurationChecksum']}
    validate('configuration-change', payload)
    return payload


def event_intent(raw):
    if type(raw) is not bytes or canonical_bytes(strict_loads(raw)) != raw:
        raise ContractError('configuration_event_invalid')
    event = strict_loads(raw)
    validate('message-envelope', event)
    validate('configuration-change', event['payload'])
    return {'effectId': event['messageId'], 'contractId': 'configuration-change',
        'payloadDigest': payload_digest(event), 'grantRef': event['operation']['grantRef'],
        'recovery': 'idempotent-retry', 'payload': event}


def retained_event(record, binding, *, start_revision):
    effects = record['effects']
    if record['entityVersion'] < start_revision:
        if effects:
            raise ContractError('configuration_history_invalid')
        return None
    if len(effects) != 1:
        raise ContractError('configuration_event_history_invalid')
    raw = canonical_bytes(effects[0]['payload'])
    expected = event_intent(raw)
    event = expected['payload']
    event_id = 'configuration_event_' + hashlib.sha256(canonical_bytes({
        'operationId': record['operation']['operationId'], 'payload': event['payload']})).hexdigest()
    if (effects[0] != expected or event['contractId'] != 'configuration-change' or event['kind'] != 'event'
            or event['sourceHubId'] != binding.hub_id or event['destinationHubId'] != binding.hub_id
            or event['destinationServiceId'] != 'configuration-owner'
            or event['payload'] != change_payload(binding, record['state'])
            or canonical_bytes(event['operation']['scope']) != binding.scope
            or event['operation']['operationId'] != event_id
            or event['operation']['cancellationRef'] != record['operation']['cancellationRef']
            or event['operation']['payloadDigest'] != payload_digest(event['payload'])
            or event['operation']['expectedVersion'] != record['entityVersion']
            or event['operation']['caller']['kind'] != 'service'
            or datetime.fromisoformat(event['ingressAttestation']['claims']['issuedAt']) > datetime.fromisoformat(record['recordedAt'])
            or datetime.fromisoformat(record['recordedAt']) >= datetime.fromisoformat(event['ingressAttestation']['claims']['expiresAt'])
            or datetime.fromisoformat(event['operation']['deadline']) > datetime.fromisoformat(record['operation']['deadline'])):
        raise ContractError('configuration_event_history_invalid')
    return raw


@dataclass(frozen=True, repr=False)
class ConfigurationEventRoute:
    source_digest: str
    stream_created: str
    start_revision: int
    account_public_key: str
    jetstream_domain: str | None

    @classmethod
    def from_ledger(cls, ledger, *, account_public_key, jetstream_domain, start_revision=1):
        if (not isinstance(ledger, OwnerLedger) or not isinstance(account_public_key, str)
                or not re.fullmatch(r'A[A-Z2-7]{55}', account_public_key)
                or jetstream_domain is not None and (not isinstance(jetstream_domain, str)
                    or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', jetstream_domain))
                or type(start_revision) is not int or not 1 <= start_revision <= MAX_SEQUENCE):
            raise ContractError('configuration_event_route_invalid')
        created = ledger._identity.created.isoformat(timespec='microseconds').replace('+00:00', 'Z')
        digest = payload_digest({'accountPublicKey': account_public_key, 'jetstreamDomain': jetstream_domain,
            'stream': ledger._stream, 'subject': ledger._subject, 'entityKind': ledger._binding.entity_kind,
            'streamCreated': created, 'startRevision': start_revision})
        return cls(digest, created, start_revision, account_public_key, jetstream_domain)

    def cursor(self, sequence):
        if type(sequence) is not int or not self.start_revision - 1 <= sequence <= MAX_SEQUENCE:
            raise ContractError('configuration_event_resync_required')
        return {'sourceDigest': self.source_digest, 'streamCreated': self.stream_created, 'sequence': sequence}

    def position(self, cursor):
        if (type(cursor) is not dict or set(cursor) != {'sourceDigest', 'streamCreated', 'sequence'}
                or cursor != self.cursor(cursor.get('sequence'))):
            raise ContractError('configuration_event_resync_required')
        return cursor['sequence']


@dataclass(frozen=True, repr=False)
class ConfigurationEventDelivery:
    envelope: bytes
    cursor: dict
    valid_until: datetime


class ConfigurationEventSource:
    """Borrow an owner's retained source; subscriber authority belongs to AMUX47.

    This adapter allocates no subscription and advances no private cursor. The
    caller owns each returned position and must separately authorize disclosure.
    """
    def __init__(self, owner, route):
        if (not isinstance(route, ConfigurationEventRoute) or owner._event_producer is None
                or route != ConfigurationEventRoute.from_ledger(owner._ledger,
                    account_public_key=route.account_public_key, jetstream_domain=route.jetstream_domain,
                    start_revision=owner._event_start_revision)):
            raise ContractError('configuration_event_source_invalid')
        self._owner, self.route = owner, route

    async def enrollment_pin(self):
        """Expose actual source metadata to the trusted native provisioner."""
        owner, task = self._owner, asyncio.current_task()
        registered = task in owner._active
        if owner._closed or not registered and len(owner._active) >= 32:
            raise ContractError('configuration_owner_closed')
        if hasattr(owner, '_host'):
            owner._host.check_health()
        if not registered:
            owner._active.add(task)
        try:
            async with asyncio.timeout(5):
                snapshot = await owner._ledger.current()
                if owner._closed:
                    raise ContractError('configuration_owner_closed')
                if snapshot.sequence < self.route.start_revision - 1:
                    raise ContractError('configuration_event_resync_required')
                if snapshot.latest is not None:
                    owner._retained(snapshot.latest)
                return {'configurationRef': {'id': owner._ledger._binding.entity_id,
                    'ownerHubId': owner._ledger._binding.hub_id, 'revision': snapshot.sequence},
                    'schemaRef': owner._schema, 'sourceDigest': self.route.source_digest,
                    'streamCreated': self.route.stream_created}
        finally:
            if not registered:
                owner._active.discard(task)

    async def next(self, cursor):
        owner = self._owner
        task = asyncio.current_task()
        registered = task in owner._active
        if owner._closed or not registered and len(owner._active) >= 32:
            raise ContractError('configuration_owner_closed')
        if hasattr(owner, '_host'):
            owner._host.check_health()
        if not registered:
            owner._active.add(task)
        try:
            async with asyncio.timeout(5):
                return await self._next(cursor)
        finally:
            if not registered:
                owner._active.discard(task)

    async def _next(self, cursor):
        owner = self._owner
        sequence = self.route.position(cursor)
        snapshot = await owner._ledger.current()
        if owner._closed:
            raise ContractError('configuration_owner_closed')
        if sequence > snapshot.sequence:
            raise ContractError('configuration_event_resync_required')
        if sequence == snapshot.sequence:
            return None
        stored = snapshot.records[sequence]
        if stored.sequence != sequence + 1:
            raise ContractError('configuration_event_resync_required')
        owner._retained(stored)
        raw = retained_event(strict_loads(stored.record), owner._ledger._binding,
            start_revision=self.route.start_revision)
        if raw is None:
            raise ContractError('configuration_event_resync_required')
        valid_until = await owner._authorize_publication(raw)
        if owner._closed:
            raise ContractError('configuration_owner_closed')
        return ConfigurationEventDelivery(raw, self.route.cursor(stored.sequence), valid_until)
