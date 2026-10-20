"""Configuration host recovery and owned jobs with actual private local custody."""
import asyncio
import copy
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.authority import LedgerAuthorityReader
from identity.test_authority import ref, SEED
from identity.test_native_bridge import native_row
from state_owner.backup import export_backup
from state_owner.backup_host import BackupHost
from state_owner.checkpoint_host import CheckpointHost
from state_owner.checkpoints import CheckpointReceipt, export_checkpoint_async
from state_owner.configuration_host import ConfigurationHost
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerBinding, OwnerLedger, StoredRecord, StreamIdentity, owner_subject
from state_owner import test_configuration as support
from state_owner import test_configuration_activation as activation_support
from state_owner.test_ledger import CREATED, FakeJetStream


class ConfigurationHostTests(unittest.IsolatedAsyncioTestCase):
    setUp = support.ConfigurationTests.setUp
    new_source = support.ConfigurationTests.new_source
    request = support.ConfigurationTests.request
    call = support.ConfigurationTests.call

    def make_host(self):
        self.admit_native_configuration()
        patch('identity.configuration_events.datetime', support._Clock).start()
        patch('identity.ingress.datetime', support._Clock).start()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.identity = StreamIdentity(CREATED, 0)
        self.history = OwnerHistory(self.root / 'live.sqlite', self.binding, stream_identity=self.identity)
        self.addCleanup(self.history.close)
        checkpoint_root = self.root / 'checkpoints'
        checkpoint_root.mkdir(mode=0o700)
        self.checkpoint = CheckpointHost(checkpoint_root / 'checkpoint', stream='OWNER',
            commit_ref=ref('configuration-checkpoint'), binding=self.binding, stream_identity=self.identity)
        roots = [self.root / name for name in ('backup', 'inventory', 'keys')]
        for root in roots:
            root.mkdir(mode=0o700)
        self.backup = BackupHost(*roots, destination_id='configuration-backup', binding=self.binding,
                                 stream_identity=self.identity)
        self.backup.enroll_key('backup-key')
        self.connection.jetstream = lambda: self.js
        self.now = 1000.0
        authority_scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        authority_binding = OwnerBinding('hub-one', 'identity', 'authority-one', 'identity-authority',
                                         canonical_bytes(authority_scope))
        authority_record = copy.deepcopy(self.record)
        authority_record.update(entityVersion=1, previousRevision=0, effects=[], artifacts=[], repository=None)
        authority_record['operation'].update(scope=authority_scope, expectedVersion=0)
        self.authority_js = FakeJetStream(self.policy)
        self.authority_js.config.subjects = [owner_subject(authority_binding)]
        self.authority_js.messages = [SimpleNamespace(subject=owner_subject(authority_binding), seq=1,
                                                      data=canonical_bytes(authority_record))]
        authority_ledger = OwnerLedger(self.authority_js, stream='OWNER', subject=owner_subject(authority_binding),
            binding=authority_binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 1))
        self.authority = LedgerAuthorityReader(authority_ledger, hub_id='hub-one', entity_id='authority-one',
            profile_id='profile-one', organization_id='org-one')
        self.host = ConfigurationHost.from_enrolled_host(self.connection, authority=self.authority,
            event_producer=activation_support.event_producer(self.authority, strict_loads(self.binding.scope)),
            event_account_public_key='A' * 56,
            stream='OWNER', binding=self.binding, retention=self.policy, stream_identity=self.identity, history=self.history,
            owner=self.owner, schema_ref='config.json', schema_resources={'config.json': b'{"type":"object"}'},
            issuer_ref=ref('issuer'), signing_seed=SEED, reply_prefix='_INBOX.configuration',
            checkpoint_host=self.checkpoint, backup_host=self.backup, backup_key_id='backup-key',
            monotonic=lambda: self.now, clock=lambda: self.now)
        self.ledger = self.host.ledger
        self.addAsyncCleanup(self.host.close)

    def saved_history(self):
        history = OwnerHistory(self.root / 'saved.sqlite', self.binding, stream_identity=self.identity)
        self.addCleanup(history.close)
        for message in self.js.messages:
            history.verify_source(StoredRecord(message.data, message.seq))
        return history

    def admit_native_configuration(self):
        # This production host requires a retained native activation even when
        # its selected owner already equals the request's full owner.
        state = self.record['state']
        host = state['identities'][0]
        host['kind'] = 'service'
        self.envelope['operation']['caller']['kind'] = 'service'
        state['identities'].append({'ref': ref('plugin'), 'principalId': 'plugin-one',
            'kind': 'plugin', 'status': 'active', 'externalIdentity': None})
        row = native_row()
        row['hostIdentityRef'] = host['ref']
        row['configurationChecksum'] = 'sha256:' + hashlib.sha256(b' {"private":1} ').hexdigest()
        scope = strict_loads(self.binding.scope)
        row['facts']['grant']['scope'] = scope
        row['facts']['policy']['scope'] = scope
        row['facts']['secretReferences'] = [ref('secret-reference')]
        state['nativeInstances'] = [row]
        method = copy.deepcopy(state['grants'][-1])
        method.update(ref=ref('configuration-initialize'),
            contractId='native-authority-prepare-configuration-initialization', resourceId='plugin-one')
        state['grants'].append(method)
        activation_support.enroll_event_producer(state, scope)

    async def test_actual_start_write_checkpoint_backup_and_joined_close(self):
        self.make_host()
        with self.assertRaisesRegex(ContractError, '^configuration_host_unavailable$'):
            await self.host.handle(self.request())
        await self.host.start()
        self.host.check_health()
        self.source = self.host.owner
        await self.call(self.request('set'))
        self.assertEqual(self.history.verified_cursor, 1)
        await self.host._backup.run_due()
        self.assertEqual(self.backup.latest().receipt.cursor, 1)
        self.now += 901
        self.host._checkpoint_if_due()
        await self.host._checkpoint_work
        self.assertEqual((await self.checkpoint.resolve()).receipt.cursor, 1)
        self.assertEqual(self.host._cadence._cursor, 1)
        await self.host.close()
        self.assertTrue(self.host.done.is_set())
        self.assertTrue(self.host.owner.done.is_set())
        self.assertTrue(self.host._backup._closing.done())
        self.assertTrue(self.host._timer.done())
        # The installed caller owns this borrowed cache and closes it afterward.
        self.assertFalse(self.history._closed)
        self.assertEqual(self.connection.subscription.drains, 1)

    async def test_checkpoint_floor_is_applied_before_source_replay_or_subscription(self):
        await self.call(self.request('set'))
        await self.call(self.request('set', revision=1))
        self.make_host()
        saved = self.saved_history()
        prefix = self.checkpoint.checkpoint_prefix
        path = prefix.with_name(prefix.name + '.2.' + uuid.uuid4().hex + '.json')
        digest = await export_checkpoint_async(path, saved, self.binding, self.identity)
        await self.checkpoint.committed(CheckpointReceipt(str(path), digest, 2))
        self.js.messages.pop()
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await self.host.start()
        self.assertEqual(self.history.verified_cursor, 0)
        self.assertFalse(self.connection.subscribed.is_set())
        await self.host.close()
        self.assertTrue(self.host.done.is_set())

    async def test_backup_floor_is_applied_before_source_replay_or_subscription(self):
        await self.call(self.request('set'))
        await self.call(self.request('set', revision=1))
        self.make_host()
        saved = self.saved_history()
        receipt = await export_backup(self.backup.backup_directory, saved, self.binding, self.identity,
            key=self.backup.load_key('backup-key'), retrieve_artifact=self.host._unexpected_artifact)
        self.backup.commit(receipt, key_id='backup-key', completed_at=self.now)
        self.js.messages.pop()
        with self.assertRaisesRegex(ContractError, '^owner_recovery_required$'):
            await self.host.start()
        self.assertEqual(self.history.verified_cursor, 0)
        self.assertFalse(self.connection.subscribed.is_set())
        await self.host.close()
        self.assertTrue(self.host.done.is_set())

    async def test_close_timeout_keeps_original_checkpoint_and_borrowed_cache(self):
        self.make_host()
        await self.host.start()
        self.source = self.host.owner
        await self.call(self.request('set'))
        self.now += 901
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.checkpoint.committed
        async def committed(receipt):
            entered.set()
            await release.wait()
            return await original(receipt)
        with patch.object(self.checkpoint, 'committed', side_effect=committed):
            self.host._checkpoint_if_due()
            work = self.host._checkpoint_work
            await asyncio.wait_for(entered.wait(), 2)
            try:
                with self.assertRaisesRegex(ContractError, '^configuration_host_cleanup_incomplete$'):
                    await self.host.close(timeout=0.01)
                self.assertFalse(work.done())
                self.assertFalse(self.host.done.is_set())
                self.assertFalse(self.history._closed)
            finally:
                release.set()
            await self.host.close()
        self.assertIs(self.host._checkpoint_work, work)
        self.assertTrue(work.done())
        self.assertTrue(self.host.done.is_set())
        self.assertEqual((await self.checkpoint.resolve()).receipt.cursor, 1)

    async def test_invalid_retained_configuration_refuses_start_before_backup_or_commands(self):
        await self.call(self.request('set'))
        value = strict_loads(self.js.messages[0].data)
        value['state']['configurationChecksum'] = 'sha256:' + '0' * 64
        self.js.messages[0].data = canonical_bytes(value)
        self.make_host()
        with self.assertRaisesRegex(ContractError, '^configuration_value_invalid$'):
            await self.host.start()
        self.assertIsNone(self.host._backup._startup)
        self.assertFalse(self.connection.subscribed.is_set())
        await self.host.close()
        self.assertTrue(self.host.done.is_set())

    async def test_enrolled_constructor_and_factory_refuse_ordinary_authority_reader(self):
        ordinary = self.authority
        self.make_host()
        resources = dict(owner=self.owner, schema_ref='config.json',
            schema_resources={'config.json': b'{"type":"object"}'}, issuer_ref=ref('issuer'), signing_seed=SEED,
            checkpoint_host=self.checkpoint, backup_host=self.backup, backup_key_id='backup-key')
        with self.assertRaisesRegex(ContractError, '^configuration_enrolled_authority_required$'):
            ConfigurationHost(ordinary, self.ledger, connection=self.connection,
                              reply_prefix='_INBOX.configuration.', **resources)
        with patch.object(self.connection, 'jetstream', side_effect=AssertionError('unenrolled resource access')):
            with self.assertRaisesRegex(ContractError, '^configuration_enrolled_authority_required$'):
                ConfigurationHost.from_enrolled_host(self.connection, authority=ordinary, stream='OWNER',
                    binding=self.binding, stream_identity=self.identity, retention=self.policy,
                    history=self.history, reply_prefix='_INBOX.configuration', **resources)
        self.assertFalse(self.connection.subscribed.is_set())
