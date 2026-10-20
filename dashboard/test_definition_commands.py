"""Offline durable-owner fault checks with real file, ledger and artifact code."""
import asyncio
import base64
import copy
from dataclasses import replace
from datetime import datetime, timezone, timedelta
import hashlib
import os
from pathlib import Path
import tempfile
import threading
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.authority import AuthorityReader
from identity.local_browser_session import LocalBrowserContext, _CONTEXT_BRAND
from identity.test_authority import fixture, ref, NOW, SEED
from state_owner.artifacts import OwnerArtifacts
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention
from state_owner.test_ledger import FakeJetStream
from definition_commands import DefinitionCommandOwner, MAX_CATALOG_BYTES
from definition_service import DefinitionScope, DefinitionService, EditIdentity
import ccboard


class Objects:
    def __init__(self):
        self.items = {}

    async def put(self, key, data, meta):
        nuid = 'N' + str(len(self.items))
        self.items[key] = (data, SimpleNamespace(name=key, bucket='bucket', deleted=False,
            is_link=lambda: False, size=len(data), chunks=int(bool(data)), nuid=nuid,
            digest='SHA-256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode()))

    async def get_info(self, key):
        return self.items[key][1]

    async def get_msg(self, stream, *, seq, subject, next, direct):
        for data, info in self.items.values():
            if subject == '$O.bucket.C.' + info.nuid:
                return SimpleNamespace(data=data, seq=seq, subject=subject)
        raise AssertionError('unknown test artifact')


class DefinitionCommandTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.authority_record, self.env = fixture()
        # Signed test credentials are current for the real ledger deadline check.
        self.now = datetime.now(timezone.utc)
        delta = self.now - NOW
        def dates(value):
            if isinstance(value, dict):
                return {key: dates(item) for key, item in value.items()}
            if isinstance(value, list):
                return [dates(item) for item in value]
            if isinstance(value, str) and value.endswith('Z') and 'T' in value:
                try:
                    return (datetime.fromisoformat(value) + delta).isoformat().replace('+00:00', 'Z')
                except ValueError:
                    pass
            return value
        self.authority_record, self.env = dates(self.authority_record), dates(self.env)
        self.env.update(contractId='definition-save', destinationServiceId='definition-owner')
        self.env['payload'] = {'definitionId': 'definition-one', 'scope': 'repo', 'name': 'worker',
                               'expectedChecksum': None, 'definition': {'description': 'Review changes'}}
        self.env['operation']['expectedVersion'] = 0
        self.authority_record['state']['grants'][0].update(contractId='definition-save', resourceId='definition-one',
            definitionTarget={'scope': 'repo', 'name': 'worker'})
        completion_grant = copy.deepcopy(self.authority_record['state']['grants'][0])
        completion_grant.update(ref=ref('completion-grant'), contractId='definition-effect-complete')
        self.authority_record['state']['grants'].append(completion_grant)
        self.resign()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.repo = root / 'repo'
        self.repo.mkdir()
        self.service = DefinitionService(DefinitionScope(self.repo, root / 'home', root / 'global',
                                                         self.env['operation']['scope']['projectId']))
        self.path = self.repo / '.agentmux/agents/worker.md'
        self.binding = OwnerBinding('hub-one', 'definitions', 'catalog-one', 'definition-catalog',
                                    canonical_bytes(self.env['operation']['scope']))
        self.policy = Retention(2_097_152, 262_144)
        self.js = FakeJetStream(self.policy)
        self.js.config = self.policy.stream_config(stream='OWNER', subject=owner_subject(self.binding))
        self.ledger = self.new_ledger()
        self.authority_js = SimpleNamespace(get_msg=AsyncMock(side_effect=self.authority_message))
        self.authority = AuthorityReader(self.authority_js, stream='AUTH', subject='authority.one',
            hub_id='hub-one', entity_id='authority-one', profile_id='profile-one', organization_id='org-one')
        self.objects = Objects()
        self.artifacts = OwnerArtifacts(self.objects, self.objects, bucket='bucket', owner_hub_id='hub-one',
            store_ref={'id': 'definition-content', 'ownerHubId': 'hub-one', 'revision': 1}, max_bytes=65536)
        self.owner = self.new_owner()

    def new_ledger(self):
        return OwnerLedger(self.js, stream='OWNER', subject=owner_subject(self.binding), binding=self.binding,
                           retention=self.policy, stream_identity=StreamIdentity(self.js.created, 0))

    def new_owner(self):
        current = getattr(self, 'owner', None)
        return DefinitionCommandOwner(self.service, self.authority, self.ledger, self.binding, self.artifacts,
                                      writer=current._writer if current is not None else None)

    async def asyncSetUp(self):
        await self.owner.activate_writer()

    async def authority_message(self, *args, **kwargs):
        return SimpleNamespace(subject='authority.one', seq=17, data=canonical_bytes(self.authority_record))

    def resign(self):
        self.env['operation']['payloadDigest'] = payload_digest(self.env['payload'])
        claims = self.env['ingressAttestation']['claims']
        claims.update(operation=copy.deepcopy(self.env['operation']), contractId=self.env['contractId'])
        claims['audience']['serviceId'] = self.env['destinationServiceId']
        self.env['ingressAttestation']['signature'] = sign_claims(claims, SEED)

    async def execute(self):
        return await self.owner.execute(canonical_bytes(self.env))

    def browser_context(self):
        return LocalBrowserContext(canonical_bytes(ref('human')),
            canonical_bytes(self.env['operation']['scope']),
            canonical_bytes({'id': self.authority_record['entityId'],
                'ownerHubId': self.authority_record['ownerHubId'],
                'revision': self.authority_record['entityVersion']}),
            17, self.env['operation']['deadline'], _CONTEXT_BRAND)

    async def test_local_browser_context_uses_current_definition_grant_and_durable_owner(self):
        context = self.browser_context()
        body = {'name': 'worker', 'scope': 'repo', 'description': 'Review changes'}
        receipt = await self.owner.execute_local_browser(
            context, '/api/board/agentdef', body)
        self.assertEqual((receipt.file_status, receipt.definition_version), ('applied', 1))
        self.assertTrue(self.path.exists())
        stored = strict_loads(self.js.messages[0].data)
        self.assertEqual(stored['authorizationDecision']['actorRef'], ref('human'))
        self.assertEqual(stored['effects'][0]['payload']['definitionId'], 'definition-one')
        self.assertNotIn('actor', stored['effects'][0]['payload'])

        denied = copy.deepcopy(self.authority_record['state']['grants'][0])
        denied.update(ref=ref('browser-deny'), decision='denied')
        self.authority_record['state']['grants'].append(denied)
        with self.assertRaisesRegex(ContractError, 'definition_not_authorized'):
            await self.owner.execute_local_browser(context, '/api/board/agentdef', {
                **body, 'checksum': stored['state']['definitions'][0]['checksum']})

    async def test_intent_audit_artifacts_commit_before_file_and_replay_does_not_write(self):
        publish = self.js.publish
        async def checked(*args, **kwargs):
            self.assertFalse(self.path.exists())
            return await publish(*args, **kwargs)
        self.js.publish = checked
        with patch('definition_service.ccboard._record') as audit:
            receipt = await self.execute()
            audit.assert_not_called()
        self.assertEqual((receipt.outcome, receipt.file_status, receipt.definition_version), ('intent-committed', 'applied', 1))
        stored = strict_loads(self.js.messages[0].data)
        self.assertEqual(receipt.effect_id, stored['effects'][0]['effectId'])
        self.assertEqual(receipt.attempt_operation_id, stored['operation']['operationId'])
        self.assertEqual(stored['operation'], self.env['operation'])
        self.assertEqual(stored['authorizationDecision']['actorRef'], self.env['operation']['effectiveActorRef'])
        self.assertEqual(stored['effects'][0]['payload'], self.env['payload'])
        self.assertEqual(len(stored['artifacts']), 2)
        original = self.path.stat()
        self.owner = self.new_owner()
        replay = await self.execute()
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.file_status, 'reconciliation-required')
        self.assertEqual(self.service._file_identity(self.path.stat()), self.service._file_identity(original))
        self.assertEqual(len(self.js.messages), 1)

    async def test_lost_ack_reconciles_original_intent_before_effect(self):
        self.js.lose_ack = True
        receipt = await self.execute()
        self.assertTrue(receipt.replayed)
        self.assertEqual(receipt.file_status, 'applied')
        self.assertEqual(len(self.js.messages), 1)
        self.assertTrue(self.path.exists())

    async def test_uncertain_append_without_retained_outcome_never_executes(self):
        async def fail(*args, **kwargs):
            raise TimeoutError('private connection details')
        self.js.publish = fail
        with self.assertRaisesRegex(ContractError, '^owner_commit_uncertain$'):
            await self.execute()
        self.assertFalse(self.path.exists())
        self.assertEqual(self.js.messages, [])
        self.assertTrue(self.objects.items)  # Unreferenced immutable uploads are retained.

    async def test_revocation_after_commit_blocks_file_and_keeps_intent(self):
        publish = self.js.publish
        async def revoke(*args, **kwargs):
            ack = await publish(*args, **kwargs)
            self.authority_record['state']['grants'][0]['status'] = 'revoked'
            return ack
        self.js.publish = revoke
        with self.assertRaisesRegex(ContractError, '^definition_not_authorized$'):
            await self.execute()
        self.assertFalse(self.path.exists())
        self.assertEqual(len(self.js.messages), 1)

    async def test_external_edit_after_intent_is_preserved(self):
        publish = self.js.publish
        async def edit(*args, **kwargs):
            ack = await publish(*args, **kwargs)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(b'external source')
            return ack
        self.js.publish = edit
        receipt = await self.execute()
        self.assertEqual(receipt.file_status, 'reconciliation-required')
        self.assertEqual(self.path.read_bytes(), b'external source')
        self.assertEqual(len(self.js.messages), 1)

    async def test_restart_retries_only_unchanged_source_after_cancelled_append(self):
        publish = self.js.publish
        async def cancelled(*args, **kwargs):
            await publish(*args, **kwargs)
            raise asyncio.CancelledError()
        self.js.publish = cancelled
        with self.assertRaises(asyncio.CancelledError):
            await self.execute()
        self.assertFalse(self.path.exists())
        self.js.publish = publish
        self.ledger = self.new_ledger()
        self.owner = self.new_owner()
        result = await self.execute()
        self.assertEqual(result.file_status, 'applied')
        self.assertTrue(result.replayed)
        self.assertEqual(len(self.js.messages), 1)

    async def test_update_drop_and_recreate_advance_one_definition_version(self):
        await self.execute()
        for index, contract in enumerate(('definition-save', 'definition-drop', 'definition-save'), 1):
            current = strict_loads(self.js.messages[-1].data)['state']['definitions'][0]
            self.env['contractId'] = contract
            self.env['operation'].update(operationId='edit-' + str(index), expectedVersion=index)
            self.env['payload']['expectedChecksum'] = current['checksum']
            if contract == 'definition-drop':
                self.env['payload'].pop('definition')
            else:
                self.env['payload']['definition'] = {'description': 'Review changes'}
            self.authority_record['state']['grants'][0]['contractId'] = contract
            self.resign()
            receipt = await self.execute()
            self.assertEqual((receipt.file_status, receipt.definition_version), ('applied', index + 1))
            self.assertEqual(self.path.exists(), contract == 'definition-save')

    async def test_second_definition_has_its_own_version_in_one_catalog(self):
        await self.execute()
        self.env['operation'].update(operationId='create-second', expectedVersion=0)
        self.env['payload'].update(definitionId='definition-two', name='second')
        self.authority_record['state']['grants'][0].update(resourceId='definition-two',
            definitionTarget={'scope': 'repo', 'name': 'second'})
        self.resign()
        result = await self.execute()
        self.assertEqual((result.definition_version, result.sequence, result.file_status), (1, 2, 'applied'))
        state = strict_loads(self.js.messages[-1].data)['state']
        self.assertEqual([row['version'] for row in state['definitions']], [1, 1])

    async def test_operation_id_reuse_with_changed_payload_cannot_rewrite_file(self):
        await self.execute()
        original = self.path.read_bytes()
        self.env['payload']['definition']['description'] = 'Changed body'
        self.resign()
        with self.assertRaisesRegex(ContractError, '^owner_operation_conflict$'):
            await self.execute()
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(len(self.js.messages), 1)

    async def test_file_failure_keeps_retained_source_and_does_not_invent_rollback(self):
        await self.execute()
        original = self.path.read_bytes()
        self.env['operation'].update(operationId='update-one', expectedVersion=1)
        self.env['payload'].update(expectedChecksum='sha256:' + hashlib.sha256(original).hexdigest(),
                                    definition={'description': 'Updated body'})
        self.resign()
        with patch('definition_service.os.replace', side_effect=OSError('private failure')):
            result = await self.execute()
        self.assertEqual(result.file_status, 'reconciliation-required')
        self.assertEqual(self.path.read_bytes(), original)
        record = strict_loads(self.js.messages[-1].data)
        self.assertEqual(record['state']['definitions'][0]['version'], 2)
        self.assertIn(original, [data for data, _ in self.objects.items.values()])

    async def test_revocation_at_final_gate_stops_mutation(self):
        original = self.service._preflight_locked
        calls = 0
        def preflight(*args):
            nonlocal calls
            result = original(*args)
            calls += 1
            if calls == 2:  # The effect's file read, after the intent append.
                self.authority_record['state']['grants'][0]['status'] = 'revoked'
            return result
        with patch.object(DefinitionService, '_preflight_locked', side_effect=preflight):
            with self.assertRaisesRegex(ContractError, '^definition_not_authorized$'):
                await self.execute()
        self.assertFalse(self.path.exists())
        self.assertEqual(len(self.js.messages), 1)

    async def test_browser_final_gate_revocation_keeps_retained_operation(self):
        original = self.service._preflight_locked
        calls = 0
        def preflight(*args):
            nonlocal calls
            result = original(*args)
            calls += 1
            if calls == 2:
                self.authority_record['state']['grants'][0]['status'] = 'revoked'
            return result
        from definition_commands import LocalDefinitionOutcomeUnconfirmed
        operation_id = 'browser_' + 'a' * 32
        with patch.object(DefinitionService, '_preflight_locked', side_effect=preflight):
            with self.assertRaises(LocalDefinitionOutcomeUnconfirmed) as raised:
                await self.owner.execute_local_browser(self.browser_context(),
                    '/api/board/agentdef', {'name': 'worker', 'scope': 'repo',
                                           'description': 'Review changes'},
                    operation_id=operation_id)
        self.assertEqual(raised.exception.code, 'definition_not_authorized')
        self.assertEqual(raised.exception.operation_id, operation_id)
        self.assertFalse(self.path.exists())
        self.assertEqual(len(self.js.messages), 1)
        self.assertEqual(strict_loads(self.js.messages[0].data)['operation']['operationId'], operation_id)

    async def test_revocation_during_temporary_write_stops_final_replace(self):
        chmod = os.chmod
        def revoke(*args, **kwargs):
            chmod(*args, **kwargs)
            self.authority_record['state']['grants'][0]['status'] = 'revoked'
        with patch('definition_service.os.chmod', side_effect=revoke):
            with self.assertRaisesRegex(ContractError, '^definition_not_authorized$'):
                await self.execute()
        self.assertFalse(self.path.exists())
        self.assertEqual(list(self.path.parent.glob('*.tmp')), [])
        self.assertEqual(len(self.js.messages), 1)

    async def test_cancelled_file_worker_is_joined_before_owner_lock_releases(self):
        started, release = asyncio.Event(), threading.Event()
        loop = asyncio.get_running_loop()
        original = self.service._mutate_locked
        def mutate(prepared, **kwargs):
            loop.call_soon_threadsafe(started.set)
            release.wait()
            original(prepared, **kwargs)
        try:
            with patch.object(DefinitionService, '_mutate_locked', side_effect=mutate):
                task = asyncio.create_task(self.execute())
                await asyncio.wait_for(started.wait(), 5)
                task.cancel()
                await asyncio.sleep(0)
                self.assertFalse(task.done())
                self.assertTrue(self.owner._lock.locked())
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
            self.assertFalse(self.owner._lock.locked())
            self.assertTrue(self.path.exists())
            self.assertEqual(len(self.js.messages), 1)
            complete = self.effect_request('definition-effect-complete')
            self.assertEqual((await self.owner.execute(complete)).status, 'applied')
        finally:
            release.set()

    async def test_concurrent_duplicate_commands_keep_one_intent(self):
        results = await asyncio.gather(self.execute(), self.execute())
        self.assertEqual(len(self.js.messages), 1)
        self.assertEqual([r.file_status for r in results], ['applied', 'applied'])

    async def test_stale_definition_version_cannot_append_even_with_current_checksum(self):
        await self.execute()
        source = self.path.read_bytes()
        self.env['operation']['operationId'] = 'stale-edit'
        self.env['payload']['expectedChecksum'] = 'sha256:' + hashlib.sha256(source).hexdigest()
        self.resign()
        with self.assertRaises(ccboard.Refused):
            await self.execute()
        self.assertEqual(len(self.js.messages), 1)
        self.assertEqual(self.path.read_bytes(), source)

    async def test_two_receivers_racing_for_same_name_commit_only_one_id(self):
        first = canonical_bytes(self.env)
        self.env['operation']['operationId'] = 'competing-create'
        self.env['payload']['definitionId'] = 'competing-id'
        grant = copy.deepcopy(self.authority_record['state']['grants'][0])
        grant['ref']['id'] = 'competing-grant'
        grant['resourceId'] = 'competing-id'
        self.authority_record['state']['grants'].append(grant)
        self.env['operation']['grantRef'] = grant['ref']
        self.resign()
        second = canonical_bytes(self.env)
        other = self.new_owner()
        publish, arrivals, ready = self.js.publish, 0, asyncio.Event()
        async def race(*args, **kwargs):
            nonlocal arrivals
            arrivals += 1
            if arrivals == 2:
                ready.set()
            await asyncio.wait_for(ready.wait(), 5)
            return await publish(*args, **kwargs)
        self.js.publish = race
        results = await asyncio.gather(self.owner.execute(first), other.execute(second), return_exceptions=True)
        self.assertEqual(len(self.js.messages), 1)
        errors = [r for r in results if isinstance(r, Exception)]
        self.assertEqual([error.code for error in errors], ['owner_revision_conflict'])
        self.assertEqual([r.file_status for r in results if not isinstance(r, Exception)], ['applied'])
        self.assertEqual(len(strict_loads(self.js.messages[0].data)['state']['definitions']), 1)

    async def test_large_save_refused_before_catalog_or_file_change(self):
        self.env['payload']['definition']['model'] = 'x' * (48 * 1024)
        self.resign()
        self.assertLess(len(canonical_bytes(self.env)), 65536)
        with self.assertRaisesRegex(ContractError, '^definition_record_headroom_required$'):
            await self.execute()
        self.assertFalse(self.path.exists())
        self.assertEqual(self.js.messages, [])

    async def test_catalog_growth_preserves_room_for_tombstone(self):
        await self.execute()
        record = strict_loads(self.js.messages[0].data)
        template = record['state']['definitions'][0]
        rows = record['state']['definitions']
        for index in range(1, 128):
            row = {**template, 'definitionId': 'definition-' + str(index), 'name': 'worker-' + str(index)}
            rows.append(row)
            if len(canonical_bytes(record['state'])) > MAX_CATALOG_BYTES:
                rows.pop()
                break
        self.js.messages[0].data = canonical_bytes(record)
        # This retained test state is within the new admission bound; one more
        # ordinary entry would consume the space reserved for later records.
        self.env['operation'].update(operationId='capacity-create', expectedVersion=0)
        self.env['payload'].update(definitionId='new-definition', name='new-worker')
        self.authority_record['state']['grants'][0].update(resourceId='new-definition',
            definitionTarget={'scope': 'repo', 'name': 'new-worker'})
        self.resign()
        with self.assertRaisesRegex(ContractError, '^definition_record_headroom_required$'):
            await self.execute()
        self.assertEqual(len(self.js.messages), 1)
        self.env['contractId'] = 'definition-drop'
        self.env['operation'].update(operationId='capacity-drop', expectedVersion=1)
        self.env['payload'] = {'definitionId': 'definition-one', 'name': 'worker', 'scope': 'repo',
                               'expectedChecksum': template['checksum']}
        self.authority_record['state']['grants'][0].update(contractId='definition-drop', resourceId='definition-one',
            definitionTarget={'scope': 'repo', 'name': 'worker'})
        self.resign()
        result = await self.execute()
        self.assertEqual(result.file_status, 'applied')
        self.assertFalse(self.path.exists())
        self.assertLess(len(self.js.messages[-1].data), 65536)

    async def test_drop_can_use_stream_reconciliation_reserve(self):
        self.policy = Retention(3 * 131072, 131072)
        self.js.config = self.policy.stream_config(stream='OWNER', subject=owner_subject(self.binding))
        self.ledger = self.new_ledger()
        self.owner = self.new_owner()
        await self.execute()
        for index, contract in enumerate(('definition-save', 'definition-drop'), 1):
            entry = strict_loads(self.js.messages[-1].data)['state']['definitions'][0]
            self.env['contractId'] = contract
            self.env['operation'].update(operationId='reserve-' + str(index), expectedVersion=index)
            self.env['payload']['expectedChecksum'] = entry['checksum']
            self.authority_record['state']['grants'][0]['contractId'] = contract
            if contract == 'definition-drop':
                self.env['payload'].pop('definition')
            self.resign()
            result = await self.execute()
            self.assertEqual(result.file_status, 'applied')
        self.assertEqual(len(self.js.messages), 3)

    async def test_unactivated_receiver_cannot_append_or_execute(self):
        staging = DefinitionCommandOwner(self.service, self.authority, self.ledger, self.binding, self.artifacts)
        with self.assertRaises(ccboard.Refused):
            await staging.execute(canonical_bytes(self.env))
        # Authentication is read-only; the missing handoff still prevents intent.
        self.assertEqual(self.js.messages, [])
        self.assertFalse(self.path.exists())

    async def test_handoff_blocks_legacy_and_identity_facades_and_aliases(self):
        alias = self.repo.parent / 'alias'
        alias.symlink_to(self.repo, target_is_directory=True)
        services = [self.service, DefinitionService(DefinitionScope(alias, self.service.scope.home,
                                    self.service.scope.global_root, self.service.scope.project_id))]
        body = {'name': 'worker', 'scope': 'repo', 'description': 'Legacy write'}
        for service in services:
            with self.assertRaises(ccboard.Refused):
                service.legacy_save(None, body)
            with self.assertRaises(ccboard.Refused):
                service.legacy_drop(None, body)
            with self.assertRaises(ccboard.Refused):
                service.save(None, body, EditIdentity('human', service.scope.project_id))
        self.assertFalse(self.path.exists())

    async def test_replacing_receiver_keeps_exclusive_writer_claim(self):
        claim = self.owner._writer
        replacement = DefinitionCommandOwner(self.service, self.authority, self.ledger, self.binding, self.artifacts)
        self.assertIs(await replacement.activate_writer(), claim)
        with self.assertRaises(ccboard.Refused):
            await asyncio.to_thread(self.service.claim_retained_writer, 'repo', b'different-owner')
        with self.assertRaises(ccboard.Refused):
            self.service.legacy_save(None, {'name': 'worker', 'scope': 'repo', 'description': 'Legacy write'})

    async def test_handoff_waits_for_exact_legacy_write_to_finish(self):
        root = self.repo.parent / 'handoff'
        root.mkdir()
        service = DefinitionService(DefinitionScope(root, self.service.scope.home, self.service.scope.global_root,
                                                     self.service.scope.project_id))
        owner = DefinitionCommandOwner(service, self.authority, self.ledger, self.binding, self.artifacts)
        started, release = asyncio.Event(), threading.Event()
        loop = asyncio.get_running_loop()
        original = service._mutate_locked
        def mutate(prepared, **kwargs):
            loop.call_soon_threadsafe(started.set)
            release.wait()
            original(prepared, **kwargs)
        body = {'name': 'worker', 'scope': 'repo', 'description': 'Legacy write'}
        try:
            with patch.object(DefinitionService, '_mutate_locked', side_effect=mutate), patch('definition_service.ccboard._record'):
                legacy = asyncio.create_task(asyncio.to_thread(service.legacy_save, None, body))
                await asyncio.wait_for(started.wait(), 5)
                handoff = asyncio.create_task(owner.activate_writer())
                await asyncio.sleep(0)
                self.assertFalse(handoff.done())
                release.set()
                await legacy
                await handoff
            with self.assertRaises(ccboard.Refused):
                service.legacy_save(None, body)
            self.assertTrue((root / '.agentmux/agents/worker.md').exists())
            self.assertEqual(self.js.messages, [])
        finally:
            release.set()

    def effect_request(self, contract, *, attempt=None, original=None, now=None):
        original = original or strict_loads(self.js.messages[0].data)
        effect = original['effects'][0]
        target = effect['payload']
        self._effect_number = getattr(self, '_effect_number', 0) + 1
        current = strict_loads(self.js.messages[-1].data)['state']['definitions']
        version = next(row['version'] for row in current if row['definitionId'] == target['definitionId'])
        self.env['contractId'] = contract
        self.env['payload'] = {'definitionId': target['definitionId'], 'name': target['name'], 'scope': target['scope'],
            'originalOperationId': original['operation']['operationId'],
            'originalPayloadDigest': original['operation']['payloadDigest'], 'effectId': effect['effectId']}
        if contract != 'definition-effect-query':
            self.env['payload']['attemptOperationId'] = attempt or original['operation']['operationId']
        self.env['operation'].update(operationId='effect-command-' + str(self._effect_number), expectedVersion=version)
        if now is not None:
            self.env['operation']['deadline'] = (now + timedelta(seconds=60)).isoformat().replace('+00:00', 'Z')
            claims = self.env['ingressAttestation']['claims']
            claims['issuedAt'] = (now - timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
            claims['expiresAt'] = (now + timedelta(seconds=60)).isoformat().replace('+00:00', 'Z')
        self.authority_record['state']['grants'][0]['contractId'] = contract
        self.resign()
        return canonical_bytes(self.env)

    async def test_completion_records_owner_observation_without_incrementing_definition(self):
        await self.execute()
        original = self.js.messages[0].data
        before = self.path.stat()
        raw = self.effect_request('definition-effect-complete')
        result = await self.owner.execute(raw)
        self.assertEqual((result.status, result.definition_version, result.receipt_sequence), ('applied', 1, 2))
        retained = strict_loads(self.js.messages[1].data)
        self.assertEqual(retained['state']['definitions'][0]['version'], 1)
        self.assertEqual(retained['effects'], [])
        self.assertEqual(self.js.messages[0].data, original)
        self.assertLessEqual(len(canonical_bytes(retained['definitionEffectReceipt'])), 4096)
        replay = await self.owner.execute(raw)
        self.assertTrue(replay.replayed)
        self.assertEqual(replace(replay, replayed=False), result)
        self.assertEqual(len(self.js.messages), 2)
        self.assertEqual(self.service._file_identity(self.path.stat()), self.service._file_identity(before))

    async def test_fresh_query_and_completion_survive_original_request_expiry(self):
        self.env['operation']['deadline'] = (self.now + timedelta(seconds=30)).isoformat().replace('+00:00', 'Z')
        self.env['ingressAttestation']['claims']['expiresAt'] = self.env['operation']['deadline']
        self.resign()
        original_raw = canonical_bytes(self.env)
        await self.execute()
        later = self.now + timedelta(seconds=40)
        with patch('identity.authority._utc_now', return_value=later):
            with self.assertRaises(ContractError):
                await self.owner.execute(original_raw)
            query = self.effect_request('definition-effect-query', now=later)
            initial = await self.owner.execute(query)
            self.assertEqual(initial.status, 'pending')
            complete = self.effect_request('definition-effect-complete', now=later)
            self.assertEqual((await self.owner.execute(complete)).status, 'applied')
            self.owner = self.new_owner()  # No in-memory observation survives replacement.
            query = self.effect_request('definition-effect-query', now=later)
            result = await self.owner.execute(query)
            self.assertEqual((result.status, result.receipt_sequence), ('applied', 2))
            self.assertEqual(len(self.js.messages), 2)

    async def test_lost_observation_cannot_be_replaced_by_matching_file_bytes(self):
        await self.execute()
        before = self.path.read_bytes()
        self.owner = self.new_owner()
        raw = self.effect_request('definition-effect-complete')
        result = await self.owner.execute(raw)
        self.assertEqual(result.status, 'reconciliation-required')
        self.assertIsNone(result.observed_at)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(len(self.js.messages), 2)

    async def test_fresh_retry_is_retained_before_effect_then_completed_separately(self):
        publish = self.js.publish
        async def cancelled(*args, **kwargs):
            await publish(*args, **kwargs)
            raise asyncio.CancelledError()
        self.js.publish = cancelled
        with self.assertRaises(asyncio.CancelledError):
            await self.execute()
        self.js.publish = publish
        retry = self.effect_request('definition-effect-retry')
        attempt = self.env['operation']['operationId']
        async def checked(*args, **kwargs):
            self.assertFalse(self.path.exists())
            return await publish(*args, **kwargs)
        self.js.publish = checked
        result = await self.owner.execute(retry)
        self.assertEqual((result.status, result.observed_file_status), ('retry-authorized', 'applied'))
        self.assertEqual(strict_loads(self.js.messages[1].data)['definitionEffectReceipt']['attemptOperationId'], attempt)
        self.js.publish = publish
        complete = self.effect_request('definition-effect-complete', attempt=attempt)
        result = await self.owner.execute(complete)
        self.assertEqual((result.status, result.receipt_sequence), ('applied', 3))
        self.assertEqual(strict_loads(self.js.messages[-1].data)['state']['definitions'][0]['version'], 1)

    async def test_completion_lost_ack_reconciles_without_duplicate_receipt(self):
        await self.execute()
        raw = self.effect_request('definition-effect-complete')
        self.js.lose_ack = True
        result = await self.owner.execute(raw)
        self.assertEqual((result.status, result.receipt_sequence), ('applied', 2))
        self.assertEqual((await self.owner.execute(raw)).status, 'applied')
        self.assertEqual(len(self.js.messages), 2)

    async def test_effect_binding_and_caller_completion_claim_are_refused(self):
        await self.execute()
        self.effect_request('definition-effect-complete')
        self.env['payload']['status'] = 'applied'
        self.resign()
        with self.assertRaises(ContractError):
            await self.execute()
        self.env['payload'].pop('status')
        self.env['payload']['effectId'] = 'another-effect'
        self.resign()
        with self.assertRaisesRegex(ContractError, '^definition_effect_binding_mismatch$'):
            await self.execute()
        self.assertEqual(len(self.js.messages), 1)

    async def test_query_revocation_after_retained_reads_does_not_return_old_status(self):
        await self.execute()
        raw = self.effect_request('definition-effect-query')
        original = self.ledger.outcome
        async def revoked(*args, **kwargs):
            result = await original(*args, **kwargs)
            self.authority_record['state']['grants'][0]['status'] = 'revoked'
            return result
        with patch.object(self.ledger, 'outcome', side_effect=revoked):
            with self.assertRaisesRegex(ContractError, '^definition_not_authorized$'):
                await self.owner.execute(raw)
        self.assertEqual(len(self.js.messages), 1)

    async def test_edit_after_completion_uses_definition_version_not_catalog_sequence(self):
        await self.execute()
        original = strict_loads(self.js.messages[0].data)
        await self.owner.execute(self.effect_request('definition-effect-complete'))
        self.env['contractId'] = 'definition-save'
        self.env['operation'].update(operationId='edit-after-completion', expectedVersion=1)
        self.env['payload'] = copy.deepcopy(original['effects'][0]['payload'])
        self.env['payload']['expectedChecksum'] = original['state']['definitions'][0]['checksum']
        self.env['payload']['definition']['description'] = 'Updated after durable completion'
        self.authority_record['state']['grants'][0]['contractId'] = 'definition-save'
        self.resign()
        result = await self.execute()
        self.assertEqual((result.definition_version, result.sequence, result.file_status), (2, 3, 'applied'))
        self.assertIsNone(strict_loads(self.js.messages[-1].data)['state']['definitions'][0].get('effectReceiptRef'))
        progress = await self.owner.execute(self.effect_request('definition-effect-query', original=original))
        self.assertEqual((progress.status, progress.current_definition_version), ('superseded', 2))
        self.assertEqual(len(self.js.messages), 3)

    async def test_new_retry_can_replace_an_expired_pending_retry(self):
        publish = self.js.publish
        async def cancelled(*args, **kwargs):
            await publish(*args, **kwargs)
            raise asyncio.CancelledError()
        self.js.publish = cancelled
        with self.assertRaises(asyncio.CancelledError):
            await self.execute()
        self.js.publish = publish
        first = self.effect_request('definition-effect-retry', now=self.now)
        old_attempt = self.env['operation']['operationId']
        with patch.object(self.owner, '_execute_effect', side_effect=asyncio.CancelledError):
            with self.assertRaises(asyncio.CancelledError):
                await self.owner.execute(first)
        self.assertFalse(self.path.exists())
        later = self.now + timedelta(seconds=70)
        with patch('identity.authority._utc_now', return_value=later):
            with self.assertRaises(ContractError):
                await self.owner.execute(first)
            second = self.effect_request('definition-effect-retry', attempt=old_attempt, now=later)
            current_attempt = self.env['operation']['operationId']
            result = await self.owner.execute(second)
            self.assertEqual((result.attempt_operation_id, result.observed_file_status), (current_attempt, 'applied'))
            complete = self.effect_request('definition-effect-complete', attempt=current_attempt, now=later)
            self.assertEqual((await self.owner.execute(complete)).status, 'applied')
        self.assertEqual(len(self.js.messages), 4)

    async def test_query_works_without_activating_a_writer(self):
        await self.execute()
        await self.owner.execute(self.effect_request('definition-effect-complete'))
        readonly = DefinitionCommandOwner(self.service, self.authority, self.ledger, self.binding, self.artifacts)
        result = await readonly.execute(self.effect_request('definition-effect-query'))
        self.assertEqual(result.status, 'applied')
        self.assertIsNone(readonly._writer)
        self.assertEqual(len(self.js.messages), 2)

    async def test_directory_redirection_does_not_reenable_legacy_writer(self):
        await self.execute()
        original = self.path.read_bytes()
        moved = self.repo / '.agentmux-original'
        self.path.parent.parent.rename(moved)
        outside = self.repo.parent / 'outside'
        (outside / 'agents').mkdir(parents=True)
        (self.repo / '.agentmux').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ccboard.Refused):
            self.service.legacy_save(None, {'name': 'worker', 'scope': 'repo', 'description': 'Redirected write'})
        with self.assertRaises(ccboard.Refused):
            await self.execute()
        self.assertFalse((outside / 'agents/worker.md').exists())
        self.assertEqual((moved / 'agents/worker.md').read_bytes(), original)

    async def test_two_receivers_replaying_one_completion_keep_the_original_receipt(self):
        await self.execute()
        raw = self.effect_request('definition-effect-complete')
        operation_id = self.env['operation']['operationId']
        other = self.new_owner()
        outcome, arrivals, ready = self.ledger.outcome, 0, asyncio.Event()
        async def together(op, digest):
            nonlocal arrivals
            result = await outcome(op, digest)
            if op == operation_id and arrivals < 2:
                arrivals += 1
                if arrivals == 2:
                    ready.set()
                await asyncio.wait_for(ready.wait(), 5)
            return result
        with patch.object(self.ledger, 'outcome', side_effect=together):
            left, right = await asyncio.gather(self.owner.execute(raw), other.execute(raw))
        self.assertEqual(replace(left, replayed=False), replace(right, replayed=False))
        self.assertEqual(len(self.js.messages), 2)
        retained = strict_loads(self.js.messages[-1].data)['definitionEffectReceipt']
        self.assertEqual(left.status, retained['status'])

    async def test_completion_cancellation_and_replay_release_only_matching_observation(self):
        await self.execute()
        attempt = self.env['operation']['operationId']
        observation = self.owner._observations[attempt]
        raw = self.effect_request('definition-effect-complete')
        authorize = self.owner._authorize
        async def cancelled_after_append(request):
            result = await authorize(request)
            if len(self.js.messages) == 2:
                raise asyncio.CancelledError()
            return result
        with patch.object(self.owner, '_authorize', side_effect=cancelled_after_append):
            with self.assertRaises(asyncio.CancelledError):
                await self.owner.execute(raw)
        self.assertNotIn(attempt, self.owner._observations)
        self.assertEqual((await self.owner.execute(raw)).status, 'applied')
        self.assertNotIn(attempt, self.owner._observations)
        unrelated = {**observation, 'effectId': 'another-effect'}
        self.owner._observations[attempt] = unrelated
        await self.owner.execute(raw)
        self.assertIs(self.owner._observations[attempt], unrelated)
        self.assertEqual(len(self.js.messages), 2)

    async def test_superseded_observations_do_not_exhaust_new_effect_capacity(self):
        await self.execute()
        original = strict_loads(self.js.messages[0].data)
        observation = next(iter(self.owner._observations.values()))
        for index in range(127):
            attempt = 'earlier-attempt-' + str(index)
            self.owner._observations[attempt] = {**observation, 'attemptOperationId': attempt}
        self.assertEqual(len(self.owner._observations), 128)
        self.env['operation'].update(operationId='new-version', expectedVersion=1)
        self.env['payload']['expectedChecksum'] = original['state']['definitions'][0]['checksum']
        self.env['payload']['definition']['description'] = 'Next version'
        self.resign()
        result = await self.execute()
        self.assertEqual(result.file_status, 'applied')
        self.assertEqual(set(self.owner._observations), {'new-version'})
        self.assertNotIn('definitionEffectReceipt', strict_loads(self.js.messages[0].data))

    async def test_failed_replace_can_be_retried_with_unchanged_source_and_directory(self):
        await self.execute()
        original = self.path.read_bytes()
        source = self.service._file_identity(self.path.stat())
        parent = self.path.parent.stat()
        self.env['operation'].update(operationId='retryable-update', expectedVersion=1)
        self.env['payload'].update(expectedChecksum='sha256:' + hashlib.sha256(original).hexdigest(),
                                    definition={'description': 'Update after a failed replace'})
        self.resign()
        with patch('definition_service.os.replace', side_effect=OSError('private replace failure')):
            self.assertEqual((await self.execute()).file_status, 'reconciliation-required')
        self.assertEqual(self.service._file_identity(self.path.stat()), source)
        self.assertEqual((self.path.parent.stat().st_dev, self.path.parent.stat().st_ino), (parent.st_dev, parent.st_ino))
        failed = strict_loads(self.js.messages[1].data)
        request = self.effect_request('definition-effect-retry', original=failed)
        result = await self.owner.execute(request)
        self.assertEqual(result.observed_file_status, 'applied')
        self.assertEqual('sha256:' + hashlib.sha256(self.path.read_bytes()).hexdigest(),
                         failed['state']['definitions'][0]['checksum'])

    async def test_persisted_handoff_fence_blocks_a_fresh_legacy_process(self):
        await self.execute()
        source = self.path.read_bytes()
        script = '''
import sys
from pathlib import Path
from definition_service import DefinitionScope, DefinitionService
import ccboard
root = Path(sys.argv[1])
service = DefinitionService(DefinitionScope(root, root.parent / 'home', root.parent / 'global', 'project-one'))
try:
    service.legacy_save(None, {'name': 'worker', 'scope': 'repo', 'description': 'Legacy restart'})
except ccboard.Refused:
    print('legacy-denied')
else:
    raise AssertionError('legacy writer reopened after handoff')
'''
        result = await asyncio.to_thread(subprocess.run, [sys.executable, '-c', script, str(self.repo)],
                                         capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'legacy-denied')
        self.assertEqual(self.path.read_bytes(), source)


if __name__ == '__main__':
    unittest.main()
