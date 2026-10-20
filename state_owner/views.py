"""Host-private, disposable KV copies. Reads never establish authority.

Only verified complete owner snapshots may rebuild a view. A failed or missing
view must keep query readiness stale until its authoritative source is reread.
There is deliberately no effect dispatch or source deletion here.
"""
import asyncio
import hashlib
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from nats.js.errors import KeyNotFoundError, KeyWrongLastSequenceError


MAX_RECORD_BYTES = 65_536
_ID = re.compile(r"[a-z][a-z0-9_-]{0,95}\Z")


class OwnerView:
    def __init__(self, kv, *, owner_hub_id, owner_domain, scope, timeout=5.0):
        if (type(timeout) not in (int, float) or not 0 < timeout <= 30
                or not all(isinstance(v, str) and _ID.fullmatch(v)
                           for v in (owner_hub_id, owner_domain))
                or type(scope) is not dict
                or set(scope) != {'organizationId', 'projectId', 'workspaceId'}
                or not isinstance(scope['organizationId'], str)
                or not _ID.fullmatch(scope['organizationId'])
                or any(v is not None and (not isinstance(v, str) or not _ID.fullmatch(v))
                       for v in (scope['projectId'], scope['workspaceId']))
                or (scope['workspaceId'] is not None and scope['projectId'] is None)):
            raise ContractError('owner_view_configuration')
        self._kv = kv
        self._binding = strict_loads(canonical_bytes({
            'ownerHubId': owner_hub_id, 'ownerDomain': owner_domain, 'scope': scope}))
        self._timeout = timeout

    def __repr__(self):
        return '<OwnerView private>'

    def _key(self, entity_id):
        return 'owner.' + hashlib.sha256(canonical_bytes(
            {**self._binding, 'entityId': entity_id})).hexdigest()

    def _decode(self, raw, entity_id):
        try:
            if type(raw) is not bytes or len(raw) > MAX_RECORD_BYTES + 2048:
                raise ValueError()
            value = strict_loads(raw)
            if (set(value) != {'schemaVersion', 'binding', 'entityId', 'sourceRevision', 'record'}
                    or value['schemaVersion'] != '1.0.0'
                    or value['binding'] != self._binding or value['entityId'] != entity_id
                    or type(value['sourceRevision']) is not int or value['sourceRevision'] < 1):
                raise ValueError()
            record = value['record']
            validate('owner-record', record)
            if len(canonical_bytes(record)) > MAX_RECORD_BYTES:
                raise ValueError()
            if (record['entityId'] != entity_id
                    or record['ownerHubId'] != self._binding['ownerHubId']
                    or record['ownerDomain'] != self._binding['ownerDomain']
                    or record['operation']['scope'] != self._binding['scope']):
                raise ValueError()
            return value
        except (ValueError, KeyError, TypeError):
            raise ContractError('owner_view_corrupt') from None

    async def apply(self, stored):
        """Copy a committed StoredRecord. CAS never replaces a newer source."""
        try:
            if type(stored.record) is not bytes or len(stored.record) > MAX_RECORD_BYTES:
                raise ContractError('owner_view_corrupt')
            record = strict_loads(stored.record)
            entity_id = record['entityId']
            raw = canonical_bytes({'schemaVersion': '1.0.0', 'binding': self._binding,
                                   'entityId': entity_id, 'sourceRevision': stored.sequence,
                                   'record': record})
            incoming = self._decode(raw, entity_id)
            async with asyncio.timeout(self._timeout):
                for _ in range(8):
                    try:
                        entry = await self._kv.get(self._key(entity_id))
                    except KeyNotFoundError:
                        entry = None
                    if entry is not None:
                        current = self._decode(entry.value, entity_id)
                        if current['sourceRevision'] > stored.sequence:
                            return False
                        if current['sourceRevision'] == stored.sequence:
                            if canonical_bytes(current) != canonical_bytes(incoming):
                                raise ContractError('owner_view_conflict')
                            return False
                    try:
                        if entry is None:
                            await self._kv.create(self._key(entity_id), raw)
                        else:
                            await self._kv.update(self._key(entity_id), raw, last=entry.revision)
                        return True
                    except KeyWrongLastSequenceError:
                        continue
                raise ContractError('owner_view_contention')
        except ContractError:
            raise
        except Exception:
            raise ContractError('owner_view_unavailable') from None

    async def rebuild(self, snapshot):
        """Copy a verified snapshot's latest state without invoking any effects."""
        if snapshot.latest is None:
            raise ContractError('owner_view_source_empty')
        return await self.apply(snapshot.latest)

    async def read(self, entity_id, *, expected):
        """Compare against a complete StoredRecord reread from the authoritative owner."""
        if type(expected.sequence) is not int or expected.sequence < 1:
            raise ContractError('owner_view_stale')
        try:
            async with asyncio.timeout(self._timeout):
                entry = await self._kv.get(self._key(entity_id))
            value = self._decode(entry.value, entity_id)
            if type(expected.record) is not bytes or len(expected.record) > MAX_RECORD_BYTES:
                raise ContractError('owner_view_corrupt')
            authoritative = strict_loads(expected.record)
            validate('owner-record', authoritative)
            if (value['sourceRevision'] != expected.sequence
                    or canonical_bytes(value['record']) != canonical_bytes(authoritative)):
                raise ContractError('owner_view_stale')
            return value
        except ContractError:
            raise
        except Exception:
            raise ContractError('owner_view_unavailable') from None
