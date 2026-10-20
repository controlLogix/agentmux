"""Conversation source, private brief/key custody and fenced reference imports."""
import base64
import asyncio
import copy
from datetime import timedelta
import hashlib
import os
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from nacl.secret import SecretBox
from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from identity import test_service as identity_support
from identity.test_authority import NOW, SEED, ref
from identity.test_service import _Clock
from state_owner.artifacts import OwnerArtifacts
from state_owner.conversation_migration import (MEDIA_TYPE, TABLES, ConversationBrief, ConversationKey,
    CoordinationHistory, ConversationMigrationSource, ConversationImporter, conversation_import_identity,
    prepare_conversation_import, validate_conversation_archive)
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.test_ledger import CREATED, FakeJetStream
from state_owner import test_task_migration as legacy_support
from state_owner import test_artifacts as artifact_support


SCOPE = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}


class ConversationSourceTests(unittest.TestCase):
    def setUp(self):
        self.legacy = legacy_support.TaskMigrationTests()
        self.legacy.setUp()
        self.addCleanup(self.legacy.doCleanups)
        self.store, self.root = self.legacy.store, self.legacy.root
        self.identity = conversation_import_identity(ref('legacy-source'), target_hub_id='hub-one', scope=SCOPE)
        self.binding = OwnerBinding('hub-one', 'conversation-archive', self.identity['archiveId'],
            'conversation-archive', canonical_bytes(SCOPE))
        self.body = 'Original brief\n'+'body '*15000
        from hub.server import Hub
        (self.root/'briefs').mkdir(mode=0o700)
        with patch('hub.server.ROOT', str(self.root)):
            self.brief_path = Hub._write_brief(None, 'virtual:operator', self.body)
        os.chmod(self.brief_path, 0o600)
        self.message_ids = []
        for state in ('queued', 'offered', 'typed', 'submitted', 'received', 'acked', 'dead'):
            posted = self.store.post('historical-sender', 'virtual:operator', 'note',
                self.body if state == 'queued' else 'Original '+state,
                ref='original-ref', work_id=self.legacy.parent['id'], idem_key='original-'+state,
                body_ref=self.brief_path if state == 'queued' else None,
                meta={'source': 'historical', 'null': None})
            self.message_ids.append(posted['id'])
            if state != 'queued':
                self.store.bump_attempt('virtual:operator', 'historical retry')
                self.store.delivery_report(posted['id'], 'virtual:operator', state,
                    evidence={'stage': state, 'generation': 7}, error='historical uncertainty')
        self.store.event('message', self.message_ids[0], 'source_note', 'historical-actor', {'raw': 'Original'})
        self.store.event('delivery', 'missing-message>old-recipient', 'received', None, {'unresolved': True})
        self.store.event('agent', 'old-session', 'cli_receipt', 'hub', {'generation': 7, 'upto': self.message_ids[0]})
        self.store.event('agent', 'old-session', 'dead', None, {'unrelatedIdentityEvent': True})
        self.store._outbox('am.agent.alpha.reviewer.pending', {
            'id': 'legacy-pending', 'body': 'Original pending\nbody', 'null': None})
        self.store._outbox('am.agent.alpha.reviewer.sent', {
            'id': 'legacy-sent', 'body': 'Original sent body', 'null': None})
        self.store.outbox_sent([self.store.q1(
            "SELECT seq FROM nats_outbox WHERE subject LIKE '%sent'")['seq']])
        self.snapshot = self.legacy.capture()
        self.brief = ConversationBrief(self.brief_path)
        self.addCleanup(self.brief.close)
        key_path = self.root/'source.key'
        key_path.write_bytes(bytes(range(SecretBox.KEY_SIZE)))
        key_path.chmod(0o600)
        self.key = ConversationKey(key_path, key_ref=ref('conversation-source-key'))
        self.addCleanup(self.key.close)
        self.source = ConversationMigrationSource(self.snapshot, source_owner_organization_id='org-one',
            briefs={self.brief_path: self.brief})

    def coordination_source(self):
        journal_records = [
            {'at': '2026-09-23T20:00:00-04:00', 'kind': 'claim',
             'agent': 'retired-agent', 'subject': 'retired-agent claimed src/a.py',
             'body': 'historical resource interest'},
            {'at': '2026-09-23T20:00:00-04:00', 'kind': 'note',
             'subject': 'actor was not recorded', 'body': 'do not invent one'},
        ]
        queue_records = [
            {'at': '2026-09-23T20:00:01-04:00', 'sender': 'retired-agent',
             'recipient': 'reviewer-one', 'kind': 'claim',
             'body': 'CLAIM src/a.py by retired-agent', 'ref': None},
            {'at': '2026-09-23T20:00:01-04:00', 'sender': 'retired-agent',
             'recipient': 'reviewer-two', 'kind': 'claim',
             'body': 'CLAIM src/a.py by retired-agent', 'ref': None},
        ]
        journal_path = self.root/'coordination-journal.jsonl'
        queue_path = self.root/'coordination-retired-agent.jsonl'
        journal_path.write_bytes(b''.join(canonical_bytes(row)+b'\n' for row in journal_records))
        queue_path.write_bytes(b''.join(canonical_bytes(row)+b'\n' for row in queue_records))
        journal_path.chmod(0o600); queue_path.chmod(0o600)
        sources = (CoordinationHistory(journal_path, kind='journal', name='journal'),
            CoordinationHistory(queue_path, kind='queue', name='retired-agent'))
        for selected in sources:
            self.addCleanup(selected.close)
        source = ConversationMigrationSource(self.snapshot,
            source_owner_organization_id='org-one', briefs={self.brief_path: self.brief},
            coordination=sources)
        return source, journal_records, queue_records

    def bundle(self, source=None):
        return (source or self.source).bundle(binding=self.binding, key_ref=strict_loads(self.key._reference))

    def frames(self, bundle=None):
        return [strict_loads(line) for line in (bundle or self.bundle()).raw.splitlines()]

    def test_full_rows_states_raw_json_audit_and_original_brief_bytes(self):
        bundle = self.bundle()
        self.assertGreater(len(bundle.raw), 65536)
        frames = self.frames(bundle)
        manifest = strict_loads(bundle.manifest)
        for table, (keys, _) in TABLES.items():
            rows = [frame['row'] for frame in frames if frame['kind'] == 'row' and frame['table'] == table]
            where = " WHERE entity IN ('message','delivery','conversation') OR (entity='agent' AND event='cli_receipt')" if table == 'events' else ''
            expected = self.store.q('SELECT * FROM '+table+where+' ORDER BY '+','.join(k+' COLLATE BINARY' for k in keys))
            self.assertEqual(rows, expected)
            self.assertEqual(manifest['families'][table], {'present': True, 'count': len(expected)})
        self.assertEqual({r['row']['state'] for r in frames if r.get('table') == 'deliveries'},
            {'queued', 'offered', 'typed', 'submitted', 'received', 'acked', 'dead'})
        brief_bytes = b''.join(base64.b64decode(f['base64']) for f in frames if f['kind'] == 'brief-bytes')
        self.assertEqual(brief_bytes, self.body.encode())
        self.assertEqual(frames[0]['kind'], 'manifest')
        self.assertEqual(frames[-1]['kind'], 'complete')
        self.assertEqual(bundle.digest, 'sha256:'+hashlib.sha256(bundle.raw).hexdigest())
        events = [f['row'] for f in frames if f.get('table') == 'events']
        self.assertTrue(any(e['event'] == 'cli_receipt' and e['entity'] == 'agent' for e in events))
        self.assertTrue(any(e['entity_id'] == 'missing-message>old-recipient' for e in events))
        self.assertFalse(any(e['event'] == 'dead' and e['entity'] == 'agent' for e in events))

    def test_nats_outbox_is_repeatable_inert_evidence_with_exact_ids_and_fields(self):
        expected = self.store.q('SELECT * FROM nats_outbox ORDER BY seq')
        first = self.bundle()
        repeated = self.bundle()
        self.assertEqual(repeated.raw, first.raw)
        rows = [frame for frame in self.frames(first)
            if frame.get('table') == 'nats_outbox']
        self.assertEqual([frame['row'] for frame in rows], expected)
        self.assertEqual([frame['primaryKey'] for frame in rows], [
            [{'column': 'seq', 'type': 'integer', 'value': row['seq']}]
            for row in expected])
        self.assertEqual(len({frame['memberId'] for frame in rows}), len(expected))
        self.assertEqual([frame['memberId'] for frame in rows], [
            frame['memberId'] for frame in self.frames(repeated)
            if frame.get('table') == 'nats_outbox'])
        self.assertEqual([row['sent'] is None for row in expected], [True, False])
        self.assertEqual(strict_loads(expected[0]['payload'])['body'], 'Original pending\nbody')
        self.assertEqual(strict_loads(first.manifest)['families']['nats_outbox'],
            {'present': True, 'count': len(expected)})

    def test_har09_journal_and_targeted_broadcast_history_is_repeatable_data_only(self):
        source, journal_records, queue_records = self.coordination_source()
        import taskmgmt.coordination as live_coordination
        with patch.object(live_coordination, 'journal') as journal, \
                patch.object(live_coordination, 'post') as post, \
                patch.object(live_coordination, 'broadcast') as broadcast:
            first = source.bundle(binding=self.binding, key_ref=strict_loads(self.key._reference))
            repeated = source.bundle(binding=self.binding, key_ref=strict_loads(self.key._reference))
        self.assertEqual(repeated.raw, first.raw)
        frames = [strict_loads(line) for line in first.raw.splitlines()]
        records = [frame for frame in frames if frame['kind'] == 'coordination-record']
        self.assertEqual([frame['record'] for frame in records], [*journal_records, *queue_records])
        self.assertEqual(records[0]['record']['at'], journal_records[0]['at'])
        self.assertEqual(records[0]['record']['agent'], 'retired-agent')
        self.assertNotIn('agent', records[1]['record'])
        self.assertEqual([frame['record']['recipient'] for frame in records[2:]],
            ['reviewer-one', 'reviewer-two'])
        self.assertEqual(strict_loads(first.manifest)['format'], 'amx-conversation-jsonl-v2')
        journal.assert_not_called(); post.assert_not_called(); broadcast.assert_not_called()

    def test_har09_selection_and_record_substitution_refuse(self):
        source, _, _ = self.coordination_source()
        duplicate = source._coordination[0]
        with self.assertRaisesRegex(ContractError, '^conversation_coordination_selection_invalid$'):
            ConversationMigrationSource(self.snapshot, source_owner_organization_id='org-one',
                briefs={self.brief_path: self.brief}, coordination=(duplicate, duplicate))
        queue = source._coordination[1]
        original = queue._path.read_bytes()
        queue.close()
        changed = strict_loads(original.splitlines()[0])
        changed['sender'] = 'current-agent'
        queue._path.write_bytes(canonical_bytes(changed)+b'\n')
        queue._path.chmod(0o600)
        substituted = CoordinationHistory(queue._path, kind='queue', name='retired-agent')
        self.addCleanup(substituted.close)
        invalid = ConversationMigrationSource(self.snapshot, source_owner_organization_id='org-one',
            briefs={self.brief_path: self.brief}, coordination=(substituted,))
        with self.assertRaisesRegex(ContractError, '^conversation_coordination_source_invalid$'):
            invalid.bundle(binding=self.binding, key_ref=strict_loads(self.key._reference))

    def test_har09_coordination_aggregate_bytes_and_combined_rows_are_bounded(self):
        source, journal_records, queue_records = self.coordination_source()
        arguments = {'binding': self.binding, 'key_ref': strict_loads(self.key._reference)}
        with patch('state_owner.conversation_migration.MAX_COORDINATION_TOTAL_BYTES', 1):
            with self.assertRaisesRegex(ContractError, '^conversation_source_limit$'):
                source.bundle(**arguments)
        manifest = strict_loads(self.bundle().manifest)
        database_rows = sum(family['count'] for family in manifest['families'].values())
        coordination_rows = len(journal_records) + len(queue_records)
        with patch('state_owner.conversation_migration.MAX_ROWS',
                   database_rows + coordination_rows - 1):
            with self.assertRaisesRegex(ContractError, '^conversation_source_limit$'):
                source.bundle(**arguments)

    def test_complete_history_exceeds_single_json_limit_without_truncated_frames(self):
        for number in range(20):
            self.store.post('historical-sender', 'virtual:operator', 'note', self.body,
                idem_key='large-'+str(number))
        source = ConversationMigrationSource(self.legacy.capture('large.db'),
            source_owner_organization_id='org-one', briefs={self.brief_path: self.brief})
        bundle = self.bundle(source)
        self.assertGreater(len(bundle.raw), 1_048_576)
        self.assertEqual(len([f for f in self.frames(bundle) if f.get('table') == 'messages']), 27)
        self.assertEqual(strict_loads(bundle.manifest)['families']['messages']['count'], 27)

    def test_identity_stable_across_capture_revision_and_data_change(self):
        original = self.bundle()
        self.store.post('historical-sender', 'virtual:operator', 'note', 'Later source', idem_key='later')
        source = ConversationMigrationSource(self.legacy.capture('later.db'),
            source_owner_organization_id='org-one', briefs={self.brief_path: self.brief})
        later = self.bundle(source)
        self.assertNotEqual(original.digest, later.digest)
        self.assertEqual(self.identity, conversation_import_identity(ref('legacy-source') | {'revision': 2},
            target_hub_id='hub-one', scope=SCOPE))
        before_ids = {f['row'].get('id'): f['memberId'] for f in self.frames(original) if f.get('table') == 'messages'}
        after_ids = {f['row'].get('id'): f['memberId'] for f in self.frames(later) if f.get('table') == 'messages'}
        for key, member_id in before_ids.items():
            self.assertEqual(after_ids[key], member_id)

    def test_missing_or_extra_brief_selection_refuses_without_path_fetch(self):
        for briefs in ({}, {self.brief_path: self.brief, 'unreferenced-private-path': self.brief}):
            source = ConversationMigrationSource(self.snapshot, source_owner_organization_id='org-one', briefs=briefs)
            with self.assertRaisesRegex(ContractError, '^conversation_brief_selection_mismatch$'):
                self.bundle(source)

    def test_changed_brief_key_permissions_and_parent_use_fixed_errors(self):
        original = self.bundle().raw
        os.chmod(self.brief_path, 0o644)
        with self.assertRaisesRegex(ContractError, '^conversation_source_file_unavailable$'):
            self.bundle()
        os.chmod(self.brief_path, 0o600)
        # Metadata changes revoke the old admission even if bytes are unchanged.
        self.brief.close()
        self.brief = ConversationBrief(self.brief_path)
        self.addCleanup(self.brief.close)
        self.source = ConversationMigrationSource(self.snapshot, source_owner_organization_id='org-one',
            briefs={self.brief_path: self.brief})
        self.assertEqual(self.bundle().raw, original)
        moved = self.root.with_name(self.root.name+'-moved')
        self.root.rename(moved)
        try:
            with self.assertRaises(ContractError) as raised:
                self.bundle()
            self.assertNotIn(str(self.root), str(raised.exception))
            self.assertTrue((moved/'capture.db').is_file())
        finally:
            moved.rename(self.root)
        self.key._path.chmod(0o644)
        with self.assertRaisesRegex(ContractError, '^conversation_source_file_unavailable$'):
            self.key.read()

    def test_brief_substitution_and_digest_mismatch_do_not_repair_source(self):
        other = self.root/'other-brief'
        other.write_bytes(b'Foreign source bytes')
        other.chmod(0o600)
        selected = ConversationBrief(other)
        self.addCleanup(selected.close)
        source = ConversationMigrationSource(self.snapshot, source_owner_organization_id='org-one',
            briefs={self.brief_path: selected})
        with self.assertRaisesRegex(ContractError, '^conversation_brief_digest_mismatch$'):
            self.bundle(source)
        self.assertEqual(self.brief.read(), self.body.encode())

    def test_wrong_organization_project_and_key_owner_refuse(self):
        for scope in (SCOPE | {'organizationId': 'other-org'}, SCOPE | {'projectId': 'project-one'}):
            binding = OwnerBinding('hub-one', 'conversation-archive', self.binding.entity_id,
                'conversation-archive', canonical_bytes(scope))
            with self.assertRaises(ContractError):
                self.source.bundle(binding=binding, key_ref=strict_loads(self.key._reference))
        with self.assertRaises(ContractError):
            self.source.bundle(binding=self.binding, key_ref=ref('key') | {'ownerHubId': 'other-hub'})

    def test_source_size_instruction_and_time_refusals_restore_connection_controls(self):
        db = self.snapshot._db
        limit = db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
        with self.assertRaisesRegex(ContractError, '^conversation_source_limit$'):
            self.source.bundle(binding=self.binding, key_ref=strict_loads(self.key._reference), max_bytes=65536)
        for target, value in (('MAX_SOURCE_INSTRUCTIONS', 10), ('MAX_SOURCE_SECONDS', 0)):
            with patch('state_owner.conversation_migration.'+target, value):
                with self.assertRaises(ContractError):
                    self.bundle()
            self.assertEqual(db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH), limit)
            self.assertEqual(db.execute('WITH RECURSIVE n(x) AS '
                '(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<2000) SELECT sum(x) FROM n').fetchone()[0], 2001000)
        self.assertGreater(len(self.bundle().raw), 65536)

    def test_protected_source_and_brief_content_refuse_without_redaction(self):
        self.store.post('historical-sender', 'virtual:operator', 'note', '{"\\u0067hp_'+'z'*36+'":"original"}')
        source = ConversationMigrationSource(self.legacy.capture('protected.db'),
            source_owner_organization_id='org-one', briefs={self.brief_path: self.brief})
        original = (self.root/'protected.db').read_bytes()
        with self.assertRaisesRegex(ContractError, '^task_import_protected_source$'):
            self.bundle(source)
        self.assertEqual((self.root/'protected.db').read_bytes(), original)

    def test_older_actual_schemas_keep_empty_families_without_upgrade(self):
        from hub.store import Store, MIGRATIONS
        from state_owner.task_migration import capture_tasks
        for version in (1, 2, 3):
            with self.subTest(version=version), patch('hub.store.MIGRATIONS', MIGRATIONS[:version]):
                store = Store(str(self.root/('old-'+str(version)+'.db')))
            self.addCleanup(store.db.close)
            snapshot = capture_tasks(store, self.root/('old-capture-'+str(version)+'.db'),
                source_ref=ref('legacy-source'), application_version='legacy-v'+str(version))
            self.addCleanup(snapshot.close)
            source = ConversationMigrationSource(snapshot, source_owner_organization_id='org-one', briefs={})
            manifest = strict_loads(self.bundle(source).manifest)
            self.assertEqual(manifest['schemaVersion'], version)
            self.assertEqual(manifest['briefCount'], 0)
            for table in ('messages', 'deliveries', 'events', 'nats_outbox'):
                self.assertEqual(manifest['families'][table], {'present': True, 'count': 0})
            self.assertEqual(store.db.execute('PRAGMA user_version').fetchone()[0], version)

    def test_symlink_hardlink_fifo_and_unknown_columns_refuse(self):
        from pathlib import Path
        link = self.root/'brief-symlink'
        link.symlink_to(self.brief_path)
        with self.assertRaisesRegex(ContractError, '^conversation_source_file_unavailable$'):
            ConversationBrief(link)
        hardlink = self.root/'brief-hardlink'
        os.link(self.brief_path, hardlink)
        try:
            with self.assertRaisesRegex(ContractError, '^conversation_source_file_unavailable$'):
                ConversationBrief(hardlink)
        finally:
            hardlink.unlink()
        self.brief.close()
        self.brief = ConversationBrief(self.brief_path)
        self.addCleanup(self.brief.close)
        fifo = self.root/'brief-fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(ContractError, '^conversation_source_file_unavailable$'):
            ConversationBrief(fifo)
        self.store.db.execute('ALTER TABLE messages ADD COLUMN unreviewed TEXT')
        source = ConversationMigrationSource(self.legacy.capture('unknown.db'),
            source_owner_organization_id='org-one', briefs={self.brief_path: self.brief})
        with self.assertRaisesRegex(ContractError, '^conversation_source_schema_invalid$'):
            self.bundle(source)
        self.assertEqual(Path(self.brief_path).read_bytes(), self.body.encode())


class ConversationImportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        identity_support.ServiceTests.setUp(self)
        patch('state_owner.conversation_migration.datetime', _Clock).start()
        self.source_test = ConversationSourceTests()
        self.source_test.setUp()
        self.addCleanup(self.source_test.doCleanups)
        self.source, self.key = self.source_test.source, self.source_test.key
        self.binding, self.identity = self.source_test.binding, self.source_test.identity
        for membership in self.record['state']['memberships']:
            membership['scope'] = copy.deepcopy(SCOPE)
        self.record['state']['grants'][0].update(ref=ref('conversation-import-grant'),
            contractId='conversation-ledger-import', resourceId=self.binding.entity_id, scope=copy.deepcopy(SCOPE))
        self.sync_identity()
        self.connection = SimpleNamespace(is_connected=True)
        self.archive_js = FakeJetStream(self.policy)
        self.archive_js._nc, self.archive_js._prefix = self.connection, '$JS.API'
        self.archive_js.config.subjects = [owner_subject(self.binding)]
        self.object_store = artifact_support.Store()
        artifact_js = artifact_support.JS(self.object_store)
        artifact_js._nc, artifact_js._prefix = self.connection, '$JS.API'
        self.object_store._js, self.object_store._name = artifact_js, 'bucket'
        self.artifacts = OwnerArtifacts(self.object_store, artifact_js, bucket='bucket',
            owner_hub_id='hub-one', store_ref=ref('conversation-artifacts'), max_bytes=4_194_304)

    def sync_identity(self):
        self.js.messages[0].data = canonical_bytes(self.record)

    async def stage(self, source=None):
        source = source or self.source
        bundle = source.bundle(binding=self.binding, key_ref=strict_loads(self.key._reference))
        # Explicit protected fixture staging; the importer never calls upload.
        encrypted = bytes(SecretBox(self.key.read()).encrypt(bundle.raw))
        self.artifact_ref = await self.artifacts.upload(encrypted, media_type=MEDIA_TYPE)
        self.payload = prepare_conversation_import(source, binding=self.binding, key=self.key, artifact_ref=self.artifact_ref)
        self.new_importer(source)
        return bundle, encrypted

    def new_importer(self, source=None):
        self.ledger = OwnerLedger(self.archive_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0),
            require_completion_budget=True)
        self.importer = ConversationImporter(self.service.reader, self.ledger, source=source or self.source,
            artifacts=self.artifacts, staged_artifact_ref=self.artifact_ref, key=self.key)

    async def admitted(self, payload=None):
        claims = {'purpose': 'agentmux-client-possession-v1', 'profileId': 'profile-one', 'hubId': 'hub-one',
            'authorityId': 'authority-one', 'transportRef': ref('transport'), 'grantRef': ref('conversation-import-grant'),
            'operationId': self.identity['operationId'], 'expectedVersion': 0, 'contractId': 'conversation-ledger-import',
            'payload': payload or self.payload, 'approvalRefs': [], 'issuedAt': NOW.isoformat().replace('+00:00', 'Z'),
            'expiresAt': (NOW+timedelta(seconds=30)).isoformat().replace('+00:00', 'Z')}
        request = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})
        admitted = await self.service.ingress.admit(request, cancellation_ref=ref('conversation-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        return admitted.envelope

    async def test_reference_commit_repeat_recreation_no_upload_and_no_plain_paths(self):
        bundle, encrypted = await self.stage()
        raw = await self.admitted()
        with patch.object(self.artifacts, 'upload', wraps=self.artifacts.upload) as upload:
            first = await self.importer.handle(raw)
            self.new_importer()
            repeated = await self.importer.handle(await self.admitted())
            upload.assert_not_called()
        self.assertTrue(repeated.replayed)
        self.assertEqual(repeated.record, first.record)
        self.assertEqual(len(self.archive_js.messages), 1)
        self.assertNotIn(self.source_test.brief_path.encode(), first.record)
        self.assertNotIn(self.source_test.body.encode(), first.record)
        record = validate_conversation_archive(first.record, self.binding, authority_id='authority-one')
        self.assertEqual(record['state']['manifest'], strict_loads(bundle.manifest))
        self.assertEqual(record['artifacts'], [self.artifact_ref])
        self.assertFalse(record['effects'])
        self.assertEqual(SecretBox(self.key.read()).decrypt(encrypted), bundle.raw)

    async def test_har09_repeat_import_preserves_history_without_live_authority_or_delivery(self):
        source, journal_records, queue_records = self.source_test.coordination_source()
        bundle, _ = await self.stage(source)
        import taskmgmt.coordination as live_coordination
        with patch.object(live_coordination, 'journal') as journal, \
                patch.object(live_coordination, 'post') as post, \
                patch.object(live_coordination, 'broadcast') as broadcast:
            first = await self.importer.handle(await self.admitted())
            self.new_importer(source)
            repeated = await self.importer.handle(await self.admitted())
        self.assertTrue(repeated.replayed)
        self.assertEqual(repeated.record, first.record)
        self.assertEqual(len(self.archive_js.messages), 1)
        record = validate_conversation_archive(first.record, self.binding,
            authority_id='authority-one')
        self.assertEqual(record['state']['manifest'], strict_loads(bundle.manifest))
        frames = [strict_loads(line) for line in bundle.raw.splitlines()]
        preserved = [frame['record'] for frame in frames
            if frame['kind'] == 'coordination-record']
        self.assertEqual(preserved, [*journal_records, *queue_records])
        journal.assert_not_called(); post.assert_not_called(); broadcast.assert_not_called()

    async def test_lost_reply_recovers_original_reference_after_owner_recreation(self):
        await self.stage()
        raw = await self.admitted()
        self.archive_js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.importer.handle(raw)
        self.archive_js.lose_ack = False
        self.new_importer()
        repeated = await self.importer.handle(await self.admitted())
        self.assertTrue(repeated.replayed)
        self.assertEqual(len(self.archive_js.messages), 1)

    async def test_corrupt_staging_and_current_revocation_refuse_before_commit(self):
        await self.stage()
        raw = await self.admitted()
        original = self.object_store.data
        self.object_store.data = b'Incomplete staged ciphertext'
        with self.assertRaises(ContractError):
            await self.importer.handle(raw)
        self.assertFalse(self.archive_js.messages)
        self.object_store.data = original
        self.record['state']['grants'][0]['status'] = 'revoked'
        self.sync_identity()
        with patch.object(self.artifacts, 'retrieve', wraps=self.artifacts.retrieve) as retrieve:
            with self.assertRaises(ContractError):
                await self.importer.handle(raw)
            retrieve.assert_not_called()
        self.assertFalse(self.archive_js.messages)

    async def test_revocation_during_artifact_read_and_replay_never_returns_old_receipt(self):
        await self.stage()
        first = await self.importer.handle(await self.admitted())
        retrieve = self.artifacts.retrieve
        async def read_and_revoke(reference):
            value = await retrieve(reference)
            self.record['state']['grants'][0]['status'] = 'revoked'
            self.sync_identity()
            return value
        raw = await self.admitted()
        with patch.object(self.artifacts, 'retrieve', side_effect=read_and_revoke):
            with self.assertRaises(ContractError):
                await self.importer.handle(raw)
        self.assertEqual([m.data for m in self.archive_js.messages], [first.record])

    async def test_key_withdrawal_after_staging_and_on_replay_refuses(self):
        await self.stage()
        first = await self.importer.handle(await self.admitted())
        raw = await self.admitted()
        self.key._path.chmod(0o644)
        with self.assertRaises(ContractError):
            await self.importer.handle(raw)
        self.assertEqual([m.data for m in self.archive_js.messages], [first.record])

    async def test_wrong_selected_artifact_and_connection_domain_store_refuse(self):
        await self.stage()
        raw = await self.admitted(self.payload | {'artifactRef': self.artifact_ref | {'version': 'unselected'}})
        with patch.object(self.artifacts, 'retrieve', wraps=self.artifacts.retrieve) as retrieve:
            with self.assertRaisesRegex(ContractError, '^conversation_import_binding_mismatch$'):
                await self.importer.handle(raw)
            retrieve.assert_not_called()
        self.artifacts._js._prefix = '$JS.foreign.API'
        with self.assertRaisesRegex(ContractError, '^conversation_import_transport_unavailable$'):
            self.new_importer()
        self.artifacts._js._prefix = '$JS.API'
        self.object_store._name = 'foreign-bucket'
        with self.assertRaisesRegex(ContractError, '^conversation_import_transport_unavailable$'):
            self.new_importer()

    async def test_changed_capture_conflicts_under_original_archive_identity(self):
        await self.stage()
        first = await self.importer.handle(await self.admitted())
        self.source_test.store.post('historical-sender', 'virtual:operator', 'note', 'Later source')
        source = ConversationMigrationSource(self.source_test.legacy.capture('later.db'),
            source_owner_organization_id='org-one', briefs={self.source_test.brief_path: self.source_test.brief})
        await self.stage(source)
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.importer.handle(await self.admitted())
        self.assertEqual([m.data for m in self.archive_js.messages], [first.record])

    async def test_unrecognized_later_record_cannot_hide_behind_original_replay(self):
        await self.stage()
        first = await self.importer.handle(await self.admitted())
        later = strict_loads(first.record)
        later.update(recordId='unrecognized', entityVersion=2, previousRevision=1)
        later['operation'].update(operationId='unrecognized', expectedVersion=1)
        later['authorizationDecision']['operationId'] = 'unrecognized'
        await self.ledger.append(later, expected_sequence=1, completion_records=0)
        self.new_importer()
        with self.assertRaisesRegex(ContractError, '^conversation_import_record_invalid$'):
            await self.importer.handle(await self.admitted())
        self.assertEqual(len(self.archive_js.messages), 2)

    async def test_correctly_staged_wrong_key_or_plaintext_refuses_fixed_diagnostic(self):
        bundle, _ = await self.stage()
        for encrypted in (bytes(SecretBox(bytes([99])*32).encrypt(bundle.raw)),
                bytes(SecretBox(self.key.read()).encrypt(bundle.raw+b'Foreign plaintext'))):
            self.artifact_ref = await self.artifacts.upload(encrypted, media_type=MEDIA_TYPE)
            self.payload = prepare_conversation_import(self.source, binding=self.binding,
                key=self.key, artifact_ref=self.artifact_ref)
            self.new_importer()
            with self.assertRaisesRegex(ContractError, '^conversation_import_bundle_unavailable$') as raised:
                await self.importer.handle(await self.admitted())
            self.assertTrue(raised.exception.__suppress_context__)
            self.assertFalse(self.archive_js.messages)
            self.assertEqual(self.object_store.data, encrypted)

    async def test_close_during_read_joins_original_caller_without_closing_borrowed_files(self):
        await self.stage()
        raw = await self.admitted()
        entered, release = asyncio.Event(), asyncio.Event()
        retrieve = self.artifacts.retrieve
        async def blocked(reference):
            entered.set()
            await release.wait()
            return await retrieve(reference)
        with patch.object(self.artifacts, 'retrieve', side_effect=blocked):
            original = asyncio.create_task(self.importer.handle(raw))
            try:
                await asyncio.wait_for(entered.wait(), 2)
                self.importer.close()
            finally:
                release.set()
                result = await asyncio.gather(original, return_exceptions=True)
        self.assertIsInstance(result[0], ContractError)
        self.assertTrue(original.done())
        self.assertFalse(self.archive_js.messages)
        self.assertEqual(len(self.key.read()), 32)
        self.assertEqual(self.source_test.brief.read(), self.source_test.body.encode())

    async def test_current_grant_revocation_after_commit_suppresses_result(self):
        await self.stage()
        raw = await self.admitted()
        append = self.ledger.append
        async def commit_then_revoke(*args, **kwargs):
            result = await append(*args, **kwargs)
            self.record['state']['grants'][0]['status'] = 'revoked'
            self.sync_identity()
            return result
        with patch.object(self.ledger, 'append', side_effect=commit_then_revoke):
            with self.assertRaisesRegex(ContractError, '^conversation_import_access_refused$'):
                await self.importer.handle(raw)
        self.assertEqual(len(self.archive_js.messages), 1)
        validate_conversation_archive(self.archive_js.messages[0].data, self.binding, authority_id='authority-one')

    async def test_record_appended_during_replay_artifact_read_refuses_original_receipt(self):
        await self.stage()
        first = await self.importer.handle(await self.admitted())
        retrieve = self.artifacts.retrieve
        async def read_then_append(reference):
            value = await retrieve(reference)
            later = strict_loads(first.record)
            later.update(recordId='concurrent-later', entityVersion=2, previousRevision=1)
            later['operation'].update(operationId='concurrent-later', expectedVersion=1)
            later['authorizationDecision']['operationId'] = 'concurrent-later'
            await self.ledger.append(later, expected_sequence=1, completion_records=0)
            return value
        raw = await self.admitted()
        with patch.object(self.artifacts, 'retrieve', side_effect=read_then_append):
            with self.assertRaisesRegex(ContractError, '^conversation_import_record_invalid$'):
                await self.importer.handle(raw)
        self.assertEqual(len(self.archive_js.messages), 2)
        self.assertEqual(self.archive_js.messages[0].data, first.record)

    async def test_internal_append_replay_must_match_verified_source_manifest(self):
        await self.stage()
        append = self.ledger.append
        async def race_original_operation(record, **kwargs):
            unverified = copy.deepcopy(record)
            unverified['state']['manifest']['applicationVersion'] = 'unverified-source'
            await append(unverified, **kwargs)
            return await append(record, **kwargs)
        with patch.object(self.ledger, 'append', side_effect=race_original_operation):
            with self.assertRaisesRegex(ContractError, '^conversation_import_record_invalid$'):
                await self.importer.handle(await self.admitted())
        self.assertEqual(len(self.archive_js.messages), 1)
