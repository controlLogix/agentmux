"""Explicit live checks using the existing owned P01 broker fixture.

Run only with a coordinated live slot. These checks do not establish broker ACLs,
multi-host durability, physical disk failure, migration parity or product cutover.
"""
import asyncio
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import platform
import sqlite3
import tempfile
import unittest

import nats
from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from nats.js.api import KeyValueConfig

from tests.storage.run import Broker
from state_owner.artifacts import OwnerArtifacts
from state_owner.checkpoints import export_checkpoint, load_checkpoint
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.recovery import build_checkpoint, restore_backup, write_backup
from state_owner.retention import Retention
from state_owner.test_ledger import BINDING, SUBJECT, SCOPE, record
from state_owner.views import OwnerView


class LiveOwnerTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('AMX_STATE_OWNER_LIVE') != '1':
            raise RuntimeError('A coordinated live slot is required')
        if platform.system() != 'Darwin' or platform.machine() != 'arm64':
            raise RuntimeError('Native macOS ARM64 is required')

    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='agentmux-owner-')
        self.broker = Broker(self.temp.name)
        self.nc = None
        self.addAsyncCleanup(self.cleanup_owned)
        self.broker.config.write_text(self.broker.config.read_text().replace(
            'jetstream {', 'jetstream { sync_interval: always\n'))
        await self.broker.start()
        self.nc = await self.broker.connect()
        self.js = self.nc.jetstream(timeout=3)
        self.policy = Retention(20 * 131_072, 4 * 131_072)
        config = self.policy.stream_config(stream='OWNER', subject=SUBJECT)
        config.duplicate_window = .1
        created = await self.js.add_stream(config)
        self.stream_identity = StreamIdentity(created.created, 0)
        self.owner = self.make_owner(self.js)

    async def cleanup_owned(self):
        try:
            if self.nc is not None:
                await self.nc.close()
        finally:
            self.broker.stop()
            self.temp.cleanup()

    def make_owner(self, js):
        return OwnerLedger(js, stream='OWNER', subject=SUBJECT,
                           binding=BINDING, retention=self.policy, stream_identity=self.stream_identity)

    async def test_indexed_restart_checkpoint_suffix_corruption_and_epoch(self):
        directory = Path(self.temp.name).resolve()
        cache = OwnerHistory(directory / 'history.sqlite', BINDING,
                             stream_identity=self.stream_identity)
        self.addCleanup(cache.close)
        def indexed(history, js=None):
            return OwnerLedger(js or self.js, stream='OWNER', subject=SUBJECT,
                               binding=BINDING, retention=self.policy,
                               stream_identity=self.stream_identity, history=history,
                               max_history_records=1, max_history_bytes=65_536)
        owner = indexed(cache)
        await owner.append(record('first'), expected_sequence=0)
        manifest = directory / 'checkpoint.json'
        digest = export_checkpoint(manifest, cache, BINDING, self.stream_identity)

        class LostAck:
            def __getattr__(self, name):
                return getattr(self.js, name)

            async def publish(self, *args, **kwargs):
                await self.js.publish(*args, **kwargs)
                raise TimeoutError()

        transport = LostAck()
        transport.js = self.js
        second = record('uncertain', 2, 1)
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await indexed(cache, transport).append(second, expected_sequence=1)
        cache.close()
        await self.nc.close()
        self.nc = None
        process, log = self.broker.process, self.broker.log
        process.kill()
        process.wait(timeout=5)
        log.close()
        self.broker.process = self.broker.log = None
        await self.broker.start()
        self.nc = await self.broker.connect()
        self.js = self.nc.jetstream(timeout=3)
        await asyncio.sleep(.2)
        restored = load_checkpoint(manifest, expected_digest=digest, binding=BINDING,
                                   stream_identity=self.stream_identity,
                                   history_path=directory / 'restored.sqlite')
        self.addCleanup(restored.history.close)
        self.assertTrue(restored.reconciliation_required)
        owner = indexed(restored.history)
        self.assertTrue((await owner.prepare_history(batch_size=1)).ready)
        replay = await owner.append(second, expected_sequence=1)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.sequence, 2)
        self.assertEqual((await self.js.stream_info('OWNER')).state.messages, 2)
        with closing(sqlite3.connect(directory / 'restored.sqlite')) as external:
            external.execute("UPDATE records SET payload_digest='corrupt' WHERE position=1")
            external.commit()
        with self.assertRaisesRegex(ContractError, '^owner_history_cache_invalid$'):
            await owner.outcome('missing', record()['operation']['payloadDigest'])
        fresh = OwnerHistory(directory / 'rebuilt.sqlite', BINDING,
                             stream_identity=self.stream_identity)
        self.addCleanup(fresh.close)
        owner = indexed(fresh)
        self.assertFalse((await owner.prepare_history(batch_size=1)).ready)
        self.assertTrue((await owner.prepare_history(batch_size=1)).ready)
        self.assertEqual((await owner.outcome('first', record('first')['operation']['payloadDigest'])).sequence, 1)
        await self.js.delete_stream('OWNER')
        await self.js.add_stream(self.policy.stream_config(stream='OWNER', subject=SUBJECT))
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await owner.current()

    async def test_authorization_deadline_and_catalog_target_versions(self):
        binding = OwnerBinding('hub-one', 'definition', 'catalog-one', 'definition-catalog',
                               canonical_bytes(SCOPE))
        subject = owner_subject(binding)
        info = await self.js.add_stream(self.policy.stream_config(stream='CATALOG', subject=subject))
        owner = OwnerLedger(self.js, stream='CATALOG', subject=subject, binding=binding,
                            retention=self.policy, stream_identity=StreamIdentity(info.created, 0))
        def change(op, sequence, target_version, definitions):
            proposal = record(op, sequence + 1, sequence)
            proposal.update(entityId='catalog-one', entityKind='definition-catalog',
                            ownerDomain='definition', state={'definitions': definitions}, effects=[])
            proposal['operation']['expectedVersion'] = target_version
            proposal['operation']['taskId'] = None
            return proposal
        first = change('create-a', 0, 0, {'a': {'version': 1}})
        with self.assertRaisesRegex(ContractError, '^owner_authorization_expired$'):
            await owner.append(first, expected_sequence=0, expected_target_version=0,
                               valid_until=datetime.now(timezone.utc) - timedelta(seconds=1))
        self.assertEqual((await self.js.stream_info('CATALOG')).state.messages, 0)
        await owner.append(first, expected_sequence=0, expected_target_version=0,
                           valid_until=datetime.now(timezone.utc) + timedelta(seconds=30))
        second = change('create-b', 1, 0, {'a': {'version': 1}, 'b': {'version': 1}})
        result = await owner.append(second, expected_sequence=1, expected_target_version=0)
        self.assertEqual(strict_loads(result.record)['operation']['expectedVersion'], 0)
        stale = change('update-a', 2, 0, {'a': {'version': 2}, 'b': {'version': 1}})
        with self.assertRaisesRegex(ContractError, '^owner_revision_invalid$'):
            await owner.append(stale, expected_sequence=2, expected_target_version=1)
        self.assertEqual((await self.js.stream_info('CATALOG')).state.messages, 2)

    async def test_conditional_race_lost_ack_and_restart_replay(self):
        outcomes = await asyncio.gather(
            self.owner.append(record('race-a'), expected_sequence=0),
            self.make_owner(self.js).append(record('race-b'), expected_sequence=0),
            return_exceptions=True)
        winners = [x for x in outcomes if not isinstance(x, Exception)]
        self.assertEqual(len(winners), 1)
        loser = next(x for x in outcomes if isinstance(x, Exception))
        self.assertIsInstance(loser, ContractError)
        self.assertEqual(loser.code, 'owner_revision_conflict')

        class LostAck:
            def __init__(self, js):
                self.js = js

            def __getattr__(self, name):
                return getattr(self.js, name)

            async def publish(self, *args, **kwargs):
                await self.js.publish(*args, **kwargs)
                raise TimeoutError()

        second = record('lost-ack', 2, 1)
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.make_owner(LostAck(self.js)).append(second, expected_sequence=1)
        await self.nc.close()
        self.nc = None
        # Retain and join the original process and log before restarting it.
        process, log = self.broker.process, self.broker.log
        process.kill()
        process.wait(timeout=5)
        log.close()
        self.broker.process = self.broker.log = None
        await self.broker.start()
        self.nc = await self.broker.connect()
        self.js = self.nc.jetstream(timeout=3)
        await asyncio.sleep(.2)
        self.owner = self.make_owner(self.js)
        replay = await self.owner.append(second, expected_sequence=1)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.sequence, 2)
        self.assertEqual(len((await self.owner.current()).records), 2)
        changed = record('lost-ack', 2, 1)
        changed['operation']['payloadDigest'] = 'sha256:' + '0' * 64
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.owner.append(changed, expected_sequence=1)

    async def test_views_artifacts_and_fenced_backup_restore(self):
        store = await self.js.create_object_store(bucket='EVIDENCE')
        artifacts = OwnerArtifacts(store, self.js, bucket='EVIDENCE', owner_hub_id='hub-one',
                                   store_ref={'id': 'evidence', 'ownerHubId': 'hub-one', 'revision': 1},
                                   max_bytes=131_072)
        content = b'owner artifact bytes' * 4000
        reference = await artifacts.upload(content, media_type='application/octet-stream')
        proposal = record()
        proposal['artifacts'] = [reference]
        committed = await self.owner.append(proposal, expected_sequence=0)
        kv = await self.js.create_key_value(KeyValueConfig(bucket='VIEWS'))
        view = OwnerView(kv, owner_hub_id='hub-one', owner_domain='task', scope=SCOPE)
        self.assertTrue(await view.apply(committed))
        self.assertEqual((await view.read('task-one', expected=committed))['record'], proposal)
        key = view._key('task-one')
        entry = await kv.get(key)
        corrupt = strict_loads(entry.value)
        corrupt['record']['state']['offerId'] = 'tampered'
        await kv.update(key, json.dumps(corrupt).encode(), last=entry.revision)
        with self.assertRaisesRegex(ContractError, '^owner_view_stale$'):
            await view.read('task-one', expected=committed)
        await self.js.delete_key_value('VIEWS')
        kv = await self.js.create_key_value(KeyValueConfig(bucket='VIEWS'))
        view = OwnerView(kv, owner_hub_id='hub-one', owner_domain='task', scope=SCOPE)
        snapshot = await self.owner.current()
        await view.rebuild(snapshot)
        self.assertEqual((await view.read('task-one', expected=committed))['record'], proposal)
        self.assertEqual(await artifacts.retrieve(reference), content)
        path = Path(self.temp.name) / 'checkpoint.backup'
        digest = write_backup(path, build_checkpoint(snapshot, BINDING), BINDING)
        restored = restore_backup(path, BINDING, expected_digest=digest)
        self.assertTrue(restored.reconciliation_required)
        self.assertEqual(restored.snapshot, snapshot)
        self.assertEqual(strict_loads(restored.snapshot.latest.record)['effects'], proposal['effects'])

    async def test_bulk_stops_with_completion_headroom_and_no_eviction(self):
        sequence = 0
        while True:
            try:
                await self.owner.append(record('bulk-' + str(sequence), sequence + 1, sequence),
                                        expected_sequence=sequence)
            except ContractError as exc:
                self.assertEqual(exc.code, 'owner_capacity_reserved')
                break
            sequence += 1
            self.assertLess(sequence, 20)
        await self.owner.append(record('completion', sequence + 1, sequence),
                                expected_sequence=sequence, admission='completion')
        snapshot = await self.owner.current()
        self.assertEqual(snapshot.sequence, sequence + 1)
        self.assertEqual(strict_loads(snapshot.records[0].record)['operation']['operationId'], 'bulk-0')

    async def test_scoped_credentials_deny_other_owner_reads_writes_and_management(self):
        await self.owner.append(record(), expected_sequence=0)
        await self.nc.close()
        self.nc = None
        self.broker.stop()
        # Reuse the exact owned fixture with an owner-specific principal. The
        # secret remains in its existing private config, never in test output.
        permissions = {'publish': {'allow': [SUBJECT, '$JS.API.STREAM.INFO.OWNER',
                                              '$JS.API.STREAM.MSG.GET.OWNER']},
                       'subscribe': {'allow': ['_INBOX.>']}}
        auth = {'users': [{'user': 'owner', 'password': self.broker.token,
                           'permissions': permissions}]}
        config = self.broker.config.read_text()
        old = 'authorization { token: "' + self.broker.token + '" }'
        self.assertIn(old, config)
        self.broker.config.write_text(config.replace(old, 'authorization ' + json.dumps(auth)))
        await self.broker.start()
        errors = []

        async def denied(error):
            # nats-py 2.16.0 reports protocol permission refusals as Error.
            # Retain only the category, never the subject or raw broker detail.
            errors.append('permission' if 'permissions violation' in str(error).lower() else 'other')

        self.nc = await nats.connect(self.broker.url, user='owner', password=self.broker.token,
                                     allow_reconnect=False, connect_timeout=2, error_cb=denied)
        self.js = self.nc.jetstream(timeout=.2)
        owner = self.make_owner(self.js)
        self.assertEqual((await owner.current()).sequence, 1)
        await owner.append(record('authorized', 2, 1), expected_sequence=1)
        with self.assertRaises(Exception):
            await self.js.publish(SUBJECT.replace('org-one', 'other-org'), b'{}', timeout=.2)
        with self.assertRaises(Exception):
            await self.js.get_msg('OTHER_OWNER', seq=1, direct=False)
        with self.assertRaises(Exception):
            await self.js.delete_stream('OWNER')
        self.assertEqual((await owner.current()).sequence, 2)
        self.assertGreaterEqual(errors.count('permission'), 3)

    async def test_recreated_empty_stream_is_not_new_enrollment(self):
        await self.owner.append(record(), expected_sequence=0)
        await self.js.delete_stream('OWNER')
        await self.js.add_stream(self.policy.stream_config(stream='OWNER', subject=SUBJECT))
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await self.make_owner(self.js).current()
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await self.owner.append(record('duplicate-risk'), expected_sequence=0)


if __name__ == '__main__':
    unittest.main()
