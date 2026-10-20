"""Conversation preservation using the existing private TLS/JWT owner fixture.

Only root runs this module in a serialized AMX_TASK_LIVE slot. Artifact staging
is an explicit provisioner action; the importer's actual credential is read-only
on the selected Object Store and can append only its own archive ledger.
"""
import asyncio
import copy
from datetime import datetime, timedelta, timezone

from nacl.secret import SecretBox
from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from capability_owner.test_live import packet, stamp
from identity.test_authority import ref, SEED
from native_security.nats_credentials import validate
from state_owner.artifacts import OwnerArtifacts
from state_owner.conversation_migration import (MEDIA_TYPE, ConversationMigrationSource,
    ConversationImporter, prepare_conversation_import, validate_conversation_archive)
from state_owner.ledger import OwnerLedger
from state_owner import test_conversation_migration as source_fixture
from state_owner import test_task_live as tls_fixture


class LiveConversationImportTests(tls_fixture.LiveTaskTests):
    seed_ready_task = False
    create_task_host = False
    data_domain = data_kind = 'conversation-archive'
    source_role = 'other-scope'
    broker_stream_limit = 4
    bucket = 'CONVERSATION'
    store_bytes = 3_000_000
    extra_history_messages = 14
    test_tls_task_inspect_reserve_restart_replay_and_refusals = None

    async def connect(self, role):
        if role == 'provisioner':
            # Reuse the reviewed archive readiness rule and existing startup
            # loop/deadline without constructing a client before the listener.
            with (self.directory/'server.private.log').open('rb') as log:
                log.seek(0, 2)
                log.seek(max(0, log.tell()-8192))
                ready = b'Server is ready' in log.read(8192)
            if not ready:
                raise OSError('archive_fixture_broker_not_ready')
        return await super().connect(role)

    def configure_broker_policies(self, policies, reads):
        self.archive_publish = [self.subjects['DATA']]+reads('DATA', 'OBJ_'+self.bucket)
        policies[self.source_role] = {'publish': {'allow': self.archive_publish}, 'subscribe': {'allow': []}}

    def validate_source_credential(self):
        validate(self.credentials[self.source_role].read_bytes(), account_public_key=self.account_public_key,
            publish_subjects=self.archive_publish,
            subscribe_subjects=[self.inbox_prefixes[self.source_role]+'.>'], private_inbox=True)

    def initial_authority(self):
        initial = super().initial_authority()
        grant = copy.deepcopy(initial['state']['grants'][0])
        grant.update(ref=ref('conversation-ledger-import-grant'), contractId='conversation-ledger-import',
            resourceId=self.task_id)
        initial['state']['grants'].append(grant)
        return initial

    async def asyncSetUp(self):
        self.source_test = source_fixture.ConversationSourceTests()
        self.source_test.setUp()
        self.addCleanup(self.source_test.doCleanups)
        self.source, self.key = self.source_test.source, self.source_test.key
        self.import_identity = self.source_test.identity
        self.task_id = self.import_identity['archiveId']
        if self._testMethodName == 'test_tls_har09_coordination_history_repeats_without_announcement':
            self.source, self.historical_journal, self.historical_queue = \
                self.source_test.coordination_source()
            self.source_test.source = self.source
        elif self._testMethodName == 'test_tls_full_history_briefs_lost_reply_recreation_repeat_and_conflict':
            for number in range(self.extra_history_messages):
                self.source_test.store.post('historical-sender', 'virtual:operator', 'note', self.source_test.body,
                    idem_key='large-'+str(number))
            self.source = ConversationMigrationSource(self.source_test.legacy.capture('large.db'),
                source_owner_organization_id='org-one', briefs={self.source_test.brief_path: self.source_test.brief})
            self.source_test.source = self.source
        await super().asyncSetUp()
        provisioner_js = self.connections[0].jetstream()
        # nsc's existing "16m" account grant is 16,000,000 decimal bytes.
        # Three 4-MiB streams leave 3,417,088 bytes. Keep the store below that
        # reservation and retain both complete >1-MiB source versions inside it.
        store = await provisioner_js.create_object_store(bucket=self.bucket, max_bytes=self.store_bytes)
        self.staging = OwnerArtifacts(store, provisioner_js, bucket=self.bucket, owner_hub_id='hub-one',
            store_ref=ref('conversation-artifacts'), max_bytes=self.store_bytes)
        source_js = self.source_connection.jetstream()
        selected_store = await source_js.object_store(self.bucket)
        self.artifacts = OwnerArtifacts(selected_store, source_js, bucket=self.bucket, owner_hub_id='hub-one',
            store_ref=ref('conversation-artifacts'), max_bytes=self.store_bytes)
        await self.stage()

    async def stage(self, source=None, *, encrypted=None):
        source = source or self.source
        bundle = source.bundle(binding=self.bindings['DATA'], key_ref=strict_loads(self.key._reference))
        if encrypted is None:
            encrypted = bytes(SecretBox(self.key.read()).encrypt(bundle.raw))
        # Explicit owned setup staging; never an importer-side upload/grant.
        self.artifact_ref = await self.staging.upload(encrypted, media_type=MEDIA_TYPE)
        self.payload = prepare_conversation_import(source, binding=self.bindings['DATA'],
            key=self.key, artifact_ref=self.artifact_ref)
        self.new_importer(source)
        return bundle

    def new_importer(self, source=None):
        self.archive_ledger = OwnerLedger(self.source_connection.jetstream(), stream='DATA',
            subject=self.subjects['DATA'], binding=self.bindings['DATA'], retention=self.policy,
            stream_identity=self.streams['DATA'], require_completion_budget=True)
        self.importer = ConversationImporter(self.identity.reader, self.archive_ledger,
            source=source or self.source, artifacts=self.artifacts, staged_artifact_ref=self.artifact_ref, key=self.key)

    async def admitted(self, payload=None, *, grant='conversation-ledger-import-grant'):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
            'authorityId': 'authority-one', 'transportRef': ref('transport'), 'grantRef': ref(grant),
            'operationId': self.import_identity['operationId'], 'expectedVersion': 0,
            'contractId': 'conversation-ledger-import', 'payload': payload or self.payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=30))}
        result = await self.identity.ingress.admit(packet(claims, bytes(reversed(SEED))),
            cancellation_ref=ref('conversation-cancel'))
        return result

    async def assert_count(self, count):
        info = await self.source_connection.jetstream().stream_info('DATA')
        self.assertEqual((info.state.messages, info.state.last_seq), (count, count))

    async def test_tls_full_history_briefs_lost_reply_recreation_repeat_and_conflict(self):
        bundle = self.source.bundle(binding=self.bindings['DATA'], key_ref=strict_loads(self.key._reference))
        self.assertGreater(len(bundle.raw), 1_048_576)
        payload = copy.deepcopy(self.payload)
        original_ref = copy.deepcopy(self.artifact_ref)
        admitted = await self.admitted()
        self.assertEqual(admitted.decision.outcome, 'allowed')
        publish = self.archive_ledger._js.publish
        from unittest.mock import patch
        async def lose_reply(*args, **kwargs):
            await publish(*args, **kwargs)
            raise OSError('private fixture lost commit reply')
        with patch.object(self.archive_ledger._js, 'publish', side_effect=lose_reply):
            with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
                await self.importer.handle(admitted.envelope)
        self.new_importer()
        with patch.object(self.artifacts, 'upload', wraps=self.artifacts.upload) as upload:
            recovered = await self.importer.handle((await self.admitted()).envelope)
            repeated = await self.importer.handle((await self.admitted()).envelope)
            upload.assert_not_called()
        self.assertTrue(recovered.replayed and repeated.replayed)
        self.assertEqual(recovered.record, repeated.record)
        record = validate_conversation_archive(recovered.record, self.bindings['DATA'], authority_id='authority-one')
        self.assertEqual(record['state']['manifest'], strict_loads(bundle.manifest))
        self.assertEqual(record['state']['payload'], payload)
        self.assertFalse(record['effects'])
        self.assertEqual(record['artifacts'], [original_ref])
        self.assertNotIn(self.source_test.brief_path.encode(), recovered.record)
        cipher = await self.artifacts.retrieve(original_ref)
        self.assertEqual(SecretBox(self.key.read()).decrypt(cipher), bundle.raw)
        # Reuse the exact source comparison assertions on this larger history.
        self.source_test.test_full_rows_states_raw_json_audit_and_original_brief_bytes()
        self.source_test.store.post('historical-sender', 'virtual:operator', 'note', 'Later source')
        later = ConversationMigrationSource(self.source_test.legacy.capture('later.db'),
            source_owner_organization_id='org-one', briefs={self.source_test.brief_path: self.source_test.brief})
        await self.stage(later)
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.importer.handle((await self.admitted()).envelope)
        await self.assert_count(1)
        for subject in ('$O.CONVERSATION.C.forbidden', '$O.CONVERSATION.M.forbidden',
                '$JS.API.STREAM.MSG.GET.IDENTITY', '$JS.API.STREAM.MSG.GET.OTHER',
                '$JS.API.STREAM.CREATE.OBJ_CONVERSATION', '$JS.API.CONSUMER.CREATE.OBJ_CONVERSATION'):
            count = self.errors[self.source_role].count('permission')
            await self.source_connection.publish(subject, b'{}')
            await self.source_connection.flush(timeout=2)
            await self.wait_permissions(self.source_role, count+1)
        self.assertFalse([error for errors in self.errors.values() for error in errors if error != 'permission'])
        self.success = True

    async def test_tls_har09_coordination_history_repeats_without_announcement(self):
        from unittest.mock import patch
        import taskmgmt.coordination as live_coordination
        bundle = self.source.bundle(binding=self.bindings['DATA'],
            key_ref=strict_loads(self.key._reference))
        with patch.object(live_coordination, 'journal') as journal, \
                patch.object(live_coordination, 'post') as post, \
                patch.object(live_coordination, 'broadcast') as broadcast:
            first = await self.importer.handle((await self.admitted()).envelope)
            self.new_importer()
            repeated = await self.importer.handle((await self.admitted()).envelope)
        self.assertTrue(repeated.replayed)
        self.assertEqual(repeated.record, first.record)
        record = validate_conversation_archive(first.record, self.bindings['DATA'],
            authority_id='authority-one')
        self.assertEqual(record['state']['manifest'], strict_loads(bundle.manifest))
        cipher = await self.artifacts.retrieve(self.artifact_ref)
        frames = [strict_loads(line) for line in SecretBox(self.key.read()).decrypt(cipher).splitlines()]
        preserved = [frame['record'] for frame in frames
            if frame['kind'] == 'coordination-record']
        self.assertEqual(preserved, [*self.historical_journal, *self.historical_queue])
        journal.assert_not_called(); post.assert_not_called(); broadcast.assert_not_called()
        await self.assert_count(1)
        self.success = True

    async def test_tls_current_revocation_during_replay_never_returns_old_complete_record(self):
        from unittest.mock import patch
        first = await self.importer.handle((await self.admitted()).envelope)
        self.new_importer()
        raw = (await self.admitted()).envelope
        retrieve = self.artifacts.retrieve
        async def revoke_during_read(reference):
            result = await retrieve(reference)
            await self.command('identity-revoke', ref('grant'), {'authorityId': 'authority-one',
                'targetRef': ref('conversation-ledger-import-grant')})
            return result
        with patch.object(self.artifacts, 'retrieve', side_effect=revoke_during_read):
            with self.assertRaisesRegex(ContractError, '^conversation_import_access_refused$'):
                await self.importer.handle(raw)
        await self.assert_count(1)
        self.assertEqual((await self.archive_ledger.current()).latest.record, first.record)
        self.success = True

    async def test_tls_wrong_cipher_key_and_brief_withdrawal_refuse(self):
        from unittest.mock import patch
        bundle = self.source.bundle(binding=self.bindings['DATA'], key_ref=strict_loads(self.key._reference))
        await self.stage(encrypted=bytes(SecretBox(bytes([99])*32).encrypt(bundle.raw)))
        with self.assertRaisesRegex(ContractError, '^conversation_import_bundle_unavailable$'):
            await self.importer.handle((await self.admitted()).envelope)
        await self.assert_count(0)
        await self.stage()
        raw = (await self.admitted()).envelope
        retrieve = self.artifacts.retrieve
        async def withdraw_brief(reference):
            result = await retrieve(reference)
            self.source_test.brief._path.chmod(0o644)
            return result
        with patch.object(self.artifacts, 'retrieve', side_effect=withdraw_brief):
            with self.assertRaisesRegex(ContractError, '^conversation_source_file_unavailable$'):
                await self.importer.handle(raw)
        await self.assert_count(0)
        self.success = True
