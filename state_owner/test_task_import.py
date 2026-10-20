"""Actual captured Store, identity admission and atomic fenced task imports."""
import copy
import json
from datetime import timedelta
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from identity.test_authority import ref, SEED, NOW
from identity.test_service import _Clock
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity
from state_owner.task import TaskOwner
from state_owner.task_migration import TaskImporter, prepare_task_import, task_import_identity
from state_owner.test_ledger import FakeJetStream, CREATED
from state_owner import test_task_service as support
from state_owner import test_task_migration as migration_support


class TaskImportTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        support.TaskServiceTests.setUp(self)
        patch('state_owner.task_migration.datetime', _Clock).start()
        source = migration_support.TaskMigrationTests()
        source.setUp()
        self.addCleanup(source.doCleanups)
        self.source = source
        self.snapshot = source.capture()
        self.legacy_id = source.parent['id']
        self.identity = task_import_identity(ref('legacy-source'), self.legacy_id,
            target_hub_id='hub-one', scope=self.scope)
        self.binding = OwnerBinding('hub-one', 'task', self.identity['taskId'], 'task', canonical_bytes(self.scope))
        self.task_js = FakeJetStream(self.policy)
        from state_owner.ledger import owner_subject
        self.task_js.config.subjects = [owner_subject(self.binding)]
        self.ledger = OwnerLedger(self.task_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0),
            require_completion_budget=True)
        self.owner = TaskOwner(self.service.reader, self.ledger)
        self.importer = TaskImporter(self.service.reader, self.ledger, snapshot=self.snapshot, source_repository='alpha')
        for grant in self.record['state']['grants']:
            grant['resourceId'] = self.binding.entity_id
        grant = copy.deepcopy(self.record['state']['grants'][0])
        grant.update(ref=ref('import-grant'), contractId='task-import')
        self.record['state']['grants'].append(grant)
        self.js.messages[0].data = canonical_bytes(self.record)

    new_ledger = support.TaskServiceTests.new_ledger
    reset_task = support.TaskServiceTests.reset_task
    possession = support.TaskServiceTests.possession

    def request(self, *, payload=None, grant=None, contract='task-import'):
        if payload is None:
            payload = prepare_task_import(self.snapshot, self.legacy_id, binding=self.binding, source_repository='alpha')
        claims = {'purpose': 'agentmux-client-possession-v1', 'profileId': 'profile-one', 'hubId': 'hub-one',
            'authorityId': 'authority-one', 'transportRef': ref('transport'), 'grantRef': grant or ref('import-grant'),
            'operationId': self.identity['operationId'] if contract == 'task-import' else 'inspect-imported',
            'expectedVersion': 0, 'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'issuedAt': NOW.isoformat().replace('+00:00','Z'),
            'expiresAt': (NOW+timedelta(seconds=30)).isoformat().replace('+00:00','Z')}
        return canonical_bytes({'schemaVersion':'1.0.0','claims':claims,
            'signature':sign_claims(claims,bytes(reversed(SEED)))})

    async def admitted(self, raw):
        result = await self.service.ingress.admit(raw, cancellation_ref=ref('import-cancel'))
        self.assertEqual(result.decision.outcome, 'allowed')
        return result.envelope

    async def imported(self, payload=None):
        return await self.importer.handle(await self.admitted(self.request(payload=payload)))

    async def test_actual_import_repeat_and_inspect_preserve_unresolved_source(self):
        stored = await self.imported()
        self.assertEqual(stored.sequence, 1)
        state = strict_loads(stored.record)['state']
        self.assertEqual(state['status'], 'reconciliation_required')
        self.assertIsNone(state['assignmentEpoch'])
        self.assertIsNone(state['reservation'])
        self.assertEqual(state['migration']['payload']['sourceRecord'], strict_loads(self.snapshot.task(self.legacy_id)))
        self.assertEqual(state['migration']['payload']['sourceRecord']['work']['state'], 'claimed')
        self.assertIn('old-grant', state['migration']['payload']['sourceRecord']['work']['fed_flags'])
        repeated = await self.imported()
        self.assertTrue(repeated.replayed)
        self.assertEqual(repeated.record, stored.record)
        self.assertEqual(len(self.task_js.messages), 1)
        read = await self.admitted(self.request(payload={'taskId': self.binding.entity_id}, grant=ref('grant'),
            contract='task-inspect'))
        self.assertEqual((await self.owner.handle(read)).record, stored.record)
        self.assertFalse(strict_loads(stored.record)['effects'])

    async def test_lost_ack_restart_recovers_same_record_without_duplicate_or_effect(self):
        raw = await self.admitted(self.request())
        self.task_js.lose_ack = True
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.importer.handle(raw)
        self.task_js.lose_ack = False
        self.importer = TaskImporter(self.service.reader, self.ledger, snapshot=self.snapshot, source_repository='alpha')
        stored = await self.imported()
        self.assertTrue(stored.replayed)
        self.assertEqual(stored.record, self.task_js.messages[0].data)
        self.assertEqual(len(self.task_js.messages), 1)

    async def test_inspect_or_reserve_grants_cannot_import_or_read_private_capture(self):
        for grant in (ref('grant'), ref('reserve-grant')):
            raw = self.request(grant=grant)
            with patch.object(self.snapshot, 'task', wraps=self.snapshot.task) as task:
                try:
                    result = await self.service.ingress.admit(raw, cancellation_ref=ref('import-cancel'))
                except ContractError:
                    result = None
                if result is not None and result.envelope is not None:
                    with self.assertRaises(ContractError):
                        await self.importer.handle(result.envelope)
                task.assert_not_called()
        self.assertFalse(self.task_js.messages)

    async def test_changed_capture_conflicts_under_same_logical_identity(self):
        original = await self.imported()
        self.source.store.db.execute("UPDATE work_items SET title='New source title' WHERE id=?", (self.legacy_id,))
        later = self.source.capture('later.db')
        payload = prepare_task_import(later, self.legacy_id, binding=self.binding, source_repository='alpha')
        self.importer = TaskImporter(self.service.reader, self.ledger, snapshot=later, source_repository='alpha')
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.imported(payload)
        self.assertEqual(len(self.task_js.messages), 1)
        self.assertEqual(self.task_js.messages[0].data, original.record)

    async def test_source_substitution_and_import_tampering_refuse(self):
        pristine = prepare_task_import(self.snapshot, self.legacy_id, binding=self.binding, source_repository='alpha')
        for mutate in (lambda p:p.update(captureDigest='sha256:'+'0'*64),
                lambda p:p['sourceRecord']['work'].update(state='ready'),
                lambda p:p.update(sourceRef=ref('other-source')),
                lambda p:p.update(parentTaskId='unobserved-parent')):
            payload = copy.deepcopy(pristine)
            mutate(payload)
            with self.assertRaises(ContractError):
                await self.imported(payload)
        self.assertFalse(self.task_js.messages)

    async def test_imported_state_cannot_reserve_or_clear_unknown_claim(self):
        stored = await self.imported()
        request = strict_loads(self.possession())
        request['claims']['payload']['taskId'] = self.binding.entity_id
        request['signature'] = sign_claims(request['claims'], bytes(reversed(SEED)))
        with self.assertRaisesRegex(ContractError, '^task_import_reconciliation_required$'):
            await self.owner.prepare_reservation(canonical_bytes(request), ref('cancel'))
        value = strict_loads(stored.record)
        value['state']['assignmentEpoch'] = 0
        from state_owner.ledger import StoredRecord
        with self.assertRaisesRegex(ContractError, '^task_import_record_invalid$'):
            self.owner._retained(StoredRecord(canonical_bytes(value), 1))
        self.assertEqual(self.task_js.messages[0].data, stored.record)

    async def test_child_import_keeps_parent_identity_and_pending_return_obligation(self):
        self.legacy_id = self.source.child['id']
        self.identity = task_import_identity(ref('legacy-source'), self.legacy_id,
            target_hub_id='hub-one', scope=self.scope)
        self.binding = OwnerBinding('hub-one', 'task', self.identity['taskId'], 'task', canonical_bytes(self.scope))
        from state_owner.ledger import owner_subject
        self.task_js.config.subjects = [owner_subject(self.binding)]
        self.ledger = OwnerLedger(self.task_js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0),
            require_completion_budget=True)
        self.owner = TaskOwner(self.service.reader, self.ledger)
        self.importer = TaskImporter(self.service.reader, self.ledger, snapshot=self.snapshot, source_repository='alpha')
        for grant in self.record['state']['grants']:
            grant['resourceId'] = self.binding.entity_id
        self.js.messages[0].data = canonical_bytes(self.record)
        stored = await self.imported()
        payload = strict_loads(stored.record)['state']['migration']['payload']
        expected_parent = task_import_identity(ref('legacy-source'), self.source.parent['id'],
            target_hub_id='hub-one', scope=self.scope)['taskId']
        self.assertEqual(payload['parentTaskId'], expected_parent)
        self.assertEqual(payload['sourceRecord']['work']['parent_id'], self.source.parent['id'])
        self.assertEqual(payload['sourceRecord']['work']['blocked_reason'], 'awaiting origin grant')
        self.assertIn('stable-return', payload['sourceRecord']['work']['fed_flags'])
        self.assertEqual((await self.imported()).record, stored.record)

    async def test_revocation_after_ingress_refuses_import_before_source_read(self):
        admitted = await self.admitted(self.request())
        self.record['state']['grants'][-1]['status'] = 'revoked'
        self.js.messages[0].data = canonical_bytes(self.record)
        with patch.object(self.snapshot, 'task', wraps=self.snapshot.task) as task:
            with self.assertRaises(ContractError):
                await self.importer.handle(admitted)
            task.assert_not_called()
        self.assertFalse(self.task_js.messages)

    async def test_import_keeps_each_resource_claim_repository_without_granting_access(self):
        self.source.store.repo_add('beta')
        self.source.store.db.execute('INSERT INTO claims VALUES (?,?,?,?,?,?)',
            ('beta', 'other/file.py', 'old-holder', self.legacy_id, '2000-01-01T00:00:00Z', '2026-10-09T00:00:00Z'))
        self.snapshot = self.source.capture('claims.db')
        self.importer = TaskImporter(self.service.reader, self.ledger, snapshot=self.snapshot, source_repository='alpha')
        stored = await self.imported()
        record = strict_loads(stored.record)
        claims = record['state']['migration']['payload']['sourceRecord']['claims']
        self.assertEqual([claim['repo'] for claim in claims], ['alpha', 'beta'])
        self.assertEqual(record['state']['status'], 'reconciliation_required')
        self.assertFalse(record['effects'])

    async def test_existing_protected_patterns_refuse_before_append_without_redacting_capture(self):
        synthetic_token = 'ghp_'+'z'*36
        cases = [('body', '-----BEGIN PRIVATE KEY-----\nsynthetic'), ('result', synthetic_token),
            ('requirements', '{"nested":["\\u0067hp_'+'z'*36+'"]}'),
            ('requirements', '{"duplicate":"\\u0067hp_'+'z'*36+'","duplicate":"ordinary"}'),
            ('fed_flags', json.dumps({'nested': {'value': synthetic_token}}))]
        for index, (field, value) in enumerate(cases):
            with self.subTest(field=field):
                self.source.store.db.execute('UPDATE work_items SET body=NULL,result=NULL,requirements=NULL,fed_flags=NULL WHERE id=?',
                    (self.legacy_id,))
                self.source.store.db.execute('UPDATE work_items SET '+field+'=? WHERE id=?', (value, self.legacy_id))
                snapshot = self.source.capture('protected-'+str(index)+'.db')
                before = snapshot.task(self.legacy_id)
                importer = TaskImporter(self.service.reader, self.ledger, snapshot=snapshot, source_repository='alpha')
                payload = prepare_task_import(snapshot, self.legacy_id, binding=self.binding, source_repository='alpha')
                admitted = await self.admitted(self.request(payload=payload))
                with patch.object(self.ledger, 'append', wraps=self.ledger.append) as append:
                    with self.assertRaisesRegex(ContractError, '^task_import_protected_source$'):
                        await importer.handle(admitted)
                    append.assert_not_called()
                self.assertEqual(snapshot.task(self.legacy_id), before)
                self.assertEqual(strict_loads(before)['work'][field], value)
                self.assertFalse(self.task_js.messages)

    async def test_protected_work_audit_detail_refuses_without_importing_other_events(self):
        self.source.store.event('work', self.legacy_id, 'legacy_note', 'operator',
            {'nested': ['Bearer '+'a'*30]})
        snapshot = self.source.capture('protected-audit.db')
        importer = TaskImporter(self.service.reader, self.ledger, snapshot=snapshot, source_repository='alpha')
        payload = prepare_task_import(snapshot, self.legacy_id, binding=self.binding, source_repository='alpha')
        with self.assertRaisesRegex(ContractError, '^task_import_protected_source$'):
            await importer.handle(await self.admitted(self.request(payload=payload)))
        self.assertFalse(self.task_js.messages)

    async def test_json_numeric_key_and_depth_bypasses_refuse_without_append_or_source_change(self):
        escaped_token = '\\u0067hp_'+'z'*36
        cases = [('large-integer', '{"number":'+'1'*5000+',"value":"'+escaped_token+'"}',
            'task_import_protected_source'),
            ('escaped-key', '{"'+escaped_token+'":"ordinary"}', 'task_import_protected_source'),
            ('deep-array', '['*980+'0'+']'*980, 'task_import_source_unavailable')]
        for name, value, code in cases:
            with self.subTest(case=name):
                self.source.store.db.execute('UPDATE work_items SET body=? WHERE id=?', (value, self.legacy_id))
                snapshot = self.source.capture('privacy-'+name+'.db')
                before = snapshot.task(self.legacy_id)
                importer = TaskImporter(self.service.reader, self.ledger, snapshot=snapshot, source_repository='alpha')
                payload = prepare_task_import(snapshot, self.legacy_id, binding=self.binding, source_repository='alpha')
                self.assertLess(len(canonical_bytes(payload)), 65536)
                admitted = await self.admitted(self.request(payload=payload))
                with patch.object(self.ledger, 'append', wraps=self.ledger.append) as append:
                    with self.assertRaisesRegex(ContractError, '^'+code+'$'):
                        await importer.handle(admitted)
                    append.assert_not_called()
                self.assertFalse(self.task_js.messages)
                self.assertEqual(snapshot.task(self.legacy_id), before)
                self.assertEqual(strict_loads(before)['work']['body'], value)
