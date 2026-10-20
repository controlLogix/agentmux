"""Host-private Object Store access with immutable random version names.

The enrolled host must bind the supplied store and JetStream account to its
scope, enforce admission quota, and reauthorize each retrieval. This helper is
not caller authentication. Uploads precede owner commits and are not atomic with
them. No deletion is offered: collection needs a grace period and an authoritative
check of every retained reference, including checkpoints and unresolved work.
"""
import asyncio
import base64
import hashlib
import re
import uuid

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from nats.js.api import ObjectMeta

_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')
_TOKEN = re.compile(r'[A-Za-z0-9_-]+\Z')


class OwnerArtifacts:
    def __init__(self, store, jetstream, *, bucket, owner_hub_id, store_ref,
                 max_bytes, timeout=30.0):
        if (not isinstance(bucket, str) or not _TOKEN.fullmatch(bucket)
                or not isinstance(owner_hub_id, str) or not _ID.fullmatch(owner_hub_id)
                or type(max_bytes) is not int or not 1 <= max_bytes <= 67_108_864
                or type(timeout) not in (int, float) or not 0 < timeout <= 60):
            raise ContractError('owner_artifact_configuration')
        ref = strict_loads(canonical_bytes(store_ref))
        if (not isinstance(ref, dict) or set(ref) != {'id', 'ownerHubId', 'revision'}
                or not isinstance(ref['id'], str) or not _ID.fullmatch(ref['id']) or ref['ownerHubId'] != owner_hub_id
                or type(ref['revision']) is not int or ref['revision'] < 0):
            raise ContractError('owner_artifact_configuration')
        self._store, self._js = store, jetstream
        self._bucket, self._owner, self._ref = bucket, owner_hub_id, ref
        self._max_bytes, self._timeout = max_bytes, timeout

    def __repr__(self):
        return '<OwnerArtifacts private>'

    def _check_ref(self, ref):
        try:
            if (set(ref) != {'artifactId', 'ownerHubId', 'storeRef', 'version',
                             'digest', 'bytes', 'mediaType'}
                    or not _ID.fullmatch(ref['artifactId']) or not _ID.fullmatch(ref['version'])
                    or ref['ownerHubId'] != self._owner or ref['storeRef'] != self._ref
                    or type(ref['bytes']) is not int or not 0 <= ref['bytes'] <= self._max_bytes
                    or not re.fullmatch(r'sha256:[a-f0-9]{64}', ref['digest'])
                    or not isinstance(ref['mediaType'], str) or not 1 <= len(ref['mediaType']) <= 4096):
                raise ValueError()
            return ref['artifactId'] + '.' + ref['version']
        except (TypeError, ValueError, KeyError):
            raise ContractError('owner_artifact_reference') from None

    async def upload(self, data, *, media_type):
        if type(data) is not bytes or len(data) > self._max_bytes:
            raise ContractError('owner_artifact_size')
        ref = {'artifactId': 'a' + uuid.uuid4().hex, 'version': 'v' + uuid.uuid4().hex,
               'ownerHubId': self._owner, 'storeRef': dict(self._ref),
               'digest': 'sha256:' + hashlib.sha256(data).hexdigest(),
               'bytes': len(data), 'mediaType': media_type}
        key = self._check_ref(ref)
        try:
            async with asyncio.timeout(self._timeout):
                await self._store.put(key, data, meta=ObjectMeta(name=key,
                    headers={'amx-media-type': media_type}))
                await self._retrieve(ref)
            return ref
        except ContractError:
            raise
        except Exception:
            # An uncertain upload is retained; never guess that it is safe to delete.
            raise ContractError('owner_artifact_unavailable') from None

    async def retrieve(self, reference):
        """Return verified bytes after the caller has checked current authority."""
        ref = strict_loads(canonical_bytes(reference))
        self._check_ref(ref)
        try:
            async with asyncio.timeout(self._timeout):
                return await self._retrieve(ref)
        except ContractError:
            raise
        except Exception:
            raise ContractError('owner_artifact_unavailable') from None

    async def _retrieve(self, ref):
        key = self._check_ref(ref)
        info = await self._store.get_info(key)
        digest = 'SHA-256=' + base64.urlsafe_b64encode(bytes.fromhex(ref['digest'][7:])).decode()
        if (info.name != key or info.bucket != self._bucket or info.deleted or info.is_link()
                or info.size != ref['bytes'] or info.digest != digest
                or not isinstance(info.nuid, str) or not _TOKEN.fullmatch(info.nuid)
                or type(info.chunks) is not int or info.chunks < 0
                or info.chunks > max(1, ref['bytes'])):
            raise ContractError('owner_artifact_corrupt')
        result = bytearray()
        subject = '$O.' + self._bucket + '.C.' + info.nuid
        cursor = 1
        # Read the metadata's immutable chunk subject without creating consumers.
        for _ in range(info.chunks):
            message = await self._js.get_msg('OBJ_' + self._bucket, seq=cursor,
                                             subject=subject, next=True, direct=False)
            if (message.subject != subject or type(message.seq) is not int
                    or message.seq < cursor or type(message.data) is not bytes
                    or len(result) + len(message.data) > ref['bytes']):
                raise ContractError('owner_artifact_corrupt')
            result.extend(message.data)
            cursor = message.seq + 1
        if len(result) != ref['bytes'] or 'sha256:' + hashlib.sha256(result).hexdigest() != ref['digest']:
            raise ContractError('owner_artifact_corrupt')
        return bytes(result)
