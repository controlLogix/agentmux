"""Offline Object Store tests; these do not qualify broker durability or ACLs."""
import base64
import hashlib
import unittest
from types import SimpleNamespace
from agentmux_contracts import ContractError
from state_owner.artifacts import OwnerArtifacts


class Store:
    async def put(self, key, data, meta):
        self.data = data
        self.info = SimpleNamespace(name=key, bucket='bucket', deleted=False,
            is_link=lambda: False, size=len(data), chunks=int(bool(data)), nuid='ABC123',
            digest='SHA-256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode())

    async def get_info(self, key):
        return self.info


class JS:
    def __init__(self, store):
        self.store = store

    async def get_msg(self, stream, *, seq, subject, next, direct):
        assert stream == 'OBJ_bucket' and next is True and direct is False
        return SimpleNamespace(data=self.store.data, seq=seq, subject=subject)


class ArtifactTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.store = Store()
        self.js = JS(self.store)
        self.artifacts = OwnerArtifacts(self.store, self.js, bucket='bucket', owner_hub_id='hub',
            store_ref={'id': 'artifacts', 'ownerHubId': 'hub', 'revision': 1}, max_bytes=10)

    async def test_round_trip_and_unique_versions(self):
        first = await self.artifacts.upload(b'abc', media_type='text/plain')
        self.assertEqual(await self.artifacts.retrieve(first), b'abc')
        second = await self.artifacts.upload(b'abc', media_type='text/plain')
        self.assertNotEqual(first['version'], second['version'])

    async def test_size_and_digest(self):
        with self.assertRaisesRegex(ContractError, 'owner_artifact_size'):
            await self.artifacts.upload(b'x' * 11, media_type='text/plain')
        ref = await self.artifacts.upload(b'abc', media_type='text/plain')
        self.store.data = b'bad'
        with self.assertRaisesRegex(ContractError, 'owner_artifact_corrupt'):
            await self.artifacts.retrieve(ref)
        self.store.data = b'x' * 11
        with self.assertRaisesRegex(ContractError, 'owner_artifact_corrupt'):
            await self.artifacts.retrieve(ref)

    async def test_reference_scope_links_and_version(self):
        ref = await self.artifacts.upload(b'abc', media_type='text/plain')
        for key, value in [('ownerHubId', 'other'), ('version', 'other')]:
            with self.assertRaises(ContractError):
                await self.artifacts.retrieve({**ref, key: value})
        self.store.info.is_link = lambda: True
        with self.assertRaisesRegex(ContractError, 'owner_artifact_corrupt'):
            await self.artifacts.retrieve(ref)
        self.assertEqual(repr(self.artifacts), '<OwnerArtifacts private>')

    async def test_empty(self):
        ref = await self.artifacts.upload(b'', media_type='text/plain')
        self.assertEqual(await self.artifacts.retrieve(ref), b'')

    async def test_chunk_failure_hides_private_error(self):
        ref = await self.artifacts.upload(b'abc', media_type='text/plain')
        async def fail(*args, **kwargs):
            raise RuntimeError('private credentials')
        self.js.get_msg = fail
        with self.assertRaisesRegex(ContractError, '^owner_artifact_unavailable$'):
            await self.artifacts.retrieve(ref)

    def test_configuration_bounds(self):
        for values in ({'max_bytes': 67108865}, {'timeout': float('nan')},
                       {'timeout': 61}, {'timeout': True}):
            config = dict(bucket='bucket', owner_hub_id='hub',
                          store_ref={'id': 'store', 'ownerHubId': 'hub', 'revision': 1},
                          max_bytes=10)
            config.update(values)
            with self.assertRaisesRegex(ContractError, 'owner_artifact_configuration'):
                OwnerArtifacts(self.store, self.js, **config)
