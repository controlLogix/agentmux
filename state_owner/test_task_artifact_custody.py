"""Actual task/identity/custody owners with a controlled Object Store boundary."""
import asyncio
import base64
import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.test_authority import ref, SEED, NOW
from identity.test_service import _Clock
from state_owner.artifacts import OwnerArtifacts
from state_owner.backup import restore_backup
from state_owner.task_artifact_custody import TaskArtifactCustody, task_artifact_backup_operation_id
from state_owner.task_host import TaskHost
from state_owner.test_artifacts import Store, JS
from state_owner import test_task_host as support


class TaskArtifactCustodyTests(unittest.IsolatedAsyncioTestCase):
    new_ledger = support.TaskHostTests.new_ledger
    reset_task = support.TaskHostTests.reset_task
    possession = support.TaskHostTests.possession
    request = support.TaskHostTests.request

    def setUp(self):
        support.TaskHostTests.setUp(self)
        patch('state_owner.task_artifact_custody.datetime', _Clock).start()
        state = self.record['state']
        issuer = copy.deepcopy(state['issuers'][0])
        issuer['ref'] = ref('task-issuer')
        state['issuers'].append(issuer)
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('artifact-reader'), identityRef=ref('service'),
            publicKey=base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('='))
        state['transports'].append(transport)
        member = copy.deepcopy(state['memberships'][0])
        member.update(ref=ref('service-member'), identityRef=ref('service'))
        state['memberships'].append(member)
        self.grant = copy.deepcopy(state['grants'][0])
        self.grant.update(ref=ref('artifact-grant'), callerRef=ref('service'), actorRef=ref('service'),
            contractId='task-artifact-backup-read')
        state['grants'].append(self.grant)
        self.authority_changed()

    def authority_changed(self):
        self.js.messages[0].data = canonical_bytes(self.record)

    async def asyncSetUp(self):
        await self.host.close(timeout=None)
        self.store = Store()
        self.store._name = 'bucket'
        self.artifact_js = JS(self.store)
        self.artifact_js._nc, self.artifact_js._prefix = self.connection, '$JS.API'
        self.task_js._nc, self.task_js._prefix = self.connection, '$JS.API'
        self.store._js = self.artifact_js
        self.artifacts = OwnerArtifacts(self.store, self.artifact_js, bucket='bucket', owner_hub_id='hub-one',
            store_ref=ref('task-artifacts'), max_bytes=1024)
        self.reference = await self.artifacts.upload(b'retained task artifact', media_type='text/plain')
        self.original['artifacts'] = [self.reference]
        self.reset_task()
        self.host = self.selected_host()
        self.addAsyncCleanup(self.host.close, timeout=None)

    def selected_host(self, **changes):
        arguments = dict(authority=self.service.reader, ingress=self.service.ingress,
            stream='OWNER', binding=self.binding, stream_identity=self.identity, retention=self.policy,
            history=self.history, checkpoint_host=self.checkpoint, backup_host=self.backup, backup_key_id='backup-one',
            issuer_ref=ref('task-issuer'), signing_seed=SEED, service_identity_ref=ref('service'),
            service_instance_id='ingress-one', requester_reply_prefix='_INBOX.task_caller_00000001',
            account_public_key='A'*56, monotonic=lambda:self.now, clock=lambda:self.now,
            artifacts=self.artifacts, artifact_reader={'transport_ref':ref('artifact-reader'), 'grant_ref':ref('artifact-grant')})
        arguments.update(changes)
        return TaskHost.from_enrolled_host(self.connection, **arguments)

    async def test_actual_host_encrypted_backup_and_fenced_restore_preserve_bytes(self):
        await self.host.start()
        self.host.check_health()
        entry = self.backup.latest()
        self.assertEqual(entry.receipt.cursor, 1)
        with restore_backup(self.backup.backup_directory, entry.receipt.manifest_name,
                expected_digest=entry.receipt.digest, key=self.backup.load_key(entry.key_id),
                binding=self.binding, stream_identity=self.identity, history_path=self.root/'restored.sqlite') as restored:
            self.assertTrue(restored.reconciliation_required)
            self.assertEqual(restored.retrieve(self.reference), b'retained task artifact')
            self.assertEqual(strict_loads(restored.history.record(1).record)['artifacts'], [self.reference])
        self.assertEqual(self.host._artifact_custody._prefix, 1)
        await self.host.close(timeout=None)
        self.assertTrue(self.host.done.is_set())
        self.assertFalse(self.history._closed)

    async def test_missing_explicit_maintenance_grant_refuses_before_object_read(self):
        self.grant['contractId'] = 'task-inspect'
        self.authority_changed()
        with patch.object(self.artifacts, 'retrieve', wraps=self.artifacts.retrieve) as retrieve:
            with self.assertRaises(ContractError):
                await self.host.start()
            retrieve.assert_not_called()
        self.assertFalse(self.host._ready)
        self.assertIsNone(self.backup.latest())
        self.assertEqual(len(self.task_js.messages), 1)

    async def test_unretained_reference_refuses_without_retrieval(self):
        custody = self.host._artifact_custody
        await custody.refresh()
        other = self.reference | {'artifactId':'other-artifact'}
        with patch.object(self.artifacts, 'retrieve', wraps=self.artifacts.retrieve) as retrieve:
            with self.assertRaisesRegex(ContractError, '^task_artifact_reference_not_retained$'):
                await custody.retrieve(other)
            retrieve.assert_not_called()

    async def test_other_metadata_context_refuses_even_with_same_bucket_name(self):
        self.store._js = object()
        with self.assertRaisesRegex(ContractError, '^task_artifacts_configuration$'):
            self.selected_host()

    async def test_revocation_during_read_refuses_bytes_and_backup_receipt(self):
        retrieve = self.artifacts.retrieve
        async def read_then_revoke(reference):
            data = await retrieve(reference)
            self.grant['status'] = 'revoked'
            self.authority_changed()
            return data
        with patch.object(self.artifacts, 'retrieve', side_effect=read_then_revoke):
            with self.assertRaises(ContractError):
                await self.host.start()
        self.assertFalse(self.host._ready)
        self.assertIsNone(self.backup.latest())
        self.assertEqual(strict_loads(self.task_js.messages[0].data)['artifacts'], [self.reference])

    async def test_corrupt_bytes_refuse_without_omitting_reference(self):
        self.store.data = b'corrupt'
        with self.assertRaises(ContractError):
            await self.host.start()
        self.assertIsNone(self.backup.latest())
        self.assertFalse(self.host._ready)
        self.assertEqual(len(self.task_js.messages), 1)

    async def test_shared_ingress_transport_and_task_signer_are_distinct_pins(self):
        custody = self.host._artifact_custody
        await custody.refresh()
        transport = self.record['state']['transports'][-1]
        transport['issuerRef'] = ref('task-issuer')
        self.authority_changed()
        with self.assertRaisesRegex(ContractError, '^task_artifact_reader_unavailable$'):
            await custody.retrieve(self.reference)

        transport['issuerRef'] = ref('issuer')
        self.record['state']['issuers'][-1]['status'] = 'revoked'
        self.authority_changed()
        with self.assertRaisesRegex(ContractError, '^task_artifact_reader_unavailable$'):
            await custody.retrieve(self.reference)

    async def test_signer_withdrawal_at_post_read_source_await_refuses_bytes(self):
        custody = self.host._artifact_custody
        await custody.refresh()
        current = self.host.ledger.current
        async def read_then_withdraw_signer():
            snapshot = await current()
            self.record['state']['issuers'][-1]['status'] = 'revoked'
            self.authority_changed()
            return snapshot
        with patch.object(self.host.ledger, 'current', side_effect=read_then_withdraw_signer):
            with self.assertRaisesRegex(ContractError, '^task_artifact_reader_unavailable$'):
                await custody.retrieve(self.reference)

    async def test_review_required_needs_selected_exact_current_approval(self):
        custody = self.host._artifact_custody
        await custody.refresh()
        self.grant['decision'] = 'review-required'
        self.authority_changed()
        with self.assertRaises(ContractError):
            await custody.retrieve(self.reference)
        payload = {'taskId':self.binding.entity_id,'artifactRef':self.reference,'sourceRevision':1}
        operation = task_artifact_backup_operation_id(self.binding, payload)
        base = self.record['state']['grants'][0]
        approve_grant = copy.deepcopy(base)
        approve_grant.update(ref=ref('approve-artifacts'), contractId='identity-approve', resourceId='artifact-grant')
        self.record['state']['grants'].append(approve_grant)
        self.record['state']['approvals'] = [{'ref':ref('artifact-approval'),'grantRef':ref('artifact-grant'),
            'approverRef':base['actorRef'],'approverGrantRef':ref('approve-artifacts'),
            'payloadDigest':payload_digest(payload),'audience':{'hubId':'hub-one','serviceId':'task-owner'},
            'operationId':operation,'expectedVersion':1,'decision':'approved','status':'active',
            'issuedAt':NOW.isoformat().replace('+00:00','Z'),
            'expiresAt':(NOW+timedelta(seconds=30)).isoformat().replace('+00:00','Z')}]
        self.authority_changed()
        selected = TaskArtifactCustody(self.host.service, self.artifacts, transport_ref=ref('artifact-reader'),
            grant_ref=ref('artifact-grant'), approvals_by_operation={operation:[ref('artifact-approval')]})
        await selected.refresh()
        self.assertEqual(await selected.retrieve(self.reference), b'retained task artifact')
        self.record['state']['approvals'][0]['expectedVersion'] = 2
        self.authority_changed()
        with self.assertRaises(ContractError):
            await selected.retrieve(self.reference)

    async def test_close_during_read_fences_acceptance_and_keeps_original_join(self):
        entered, release = asyncio.Event(), asyncio.Event()
        retrieve = self.artifacts.retrieve
        async def blocked(reference):
            entered.set()
            await release.wait()
            return await retrieve(reference)
        with patch.object(self.artifacts, 'retrieve', side_effect=blocked):
            starting = asyncio.create_task(self.host.start())
            await entered.wait()
            try:
                with self.assertRaisesRegex(ContractError, '^task_host_cleanup_incomplete$'):
                    await self.host.close(timeout=.01)
                original = self.host._closing
                self.assertFalse(original.done() or self.history._closed)
            finally:
                release.set()
                await self.host.close(timeout=None)
                await asyncio.gather(starting, return_exceptions=True)
        self.assertTrue(self.host.done.is_set())
        self.assertIsNone(self.backup.latest())

    async def test_cancelled_direct_backup_tick_stays_owned_through_close(self):
        await self.host.start()
        original_receipt = self.backup.latest().receipt
        self.now += 3601
        entered, release = asyncio.Event(), asyncio.Event()
        retrieve = self.artifacts.retrieve
        async def blocked(reference):
            entered.set()
            await release.wait()
            return await retrieve(reference)
        with patch.object(self.artifacts, 'retrieve', side_effect=blocked):
            tick = asyncio.create_task(self.host._backup.run_due())
            await entered.wait()
            original_job = next(iter(self.host._backup._task_jobs))
            tick.cancel()
            try:
                with self.assertRaisesRegex(ContractError, '^task_host_cleanup_incomplete$'):
                    await self.host.close(timeout=.01)
                self.assertFalse(original_job.done() or tick.done() or self.history._closed)
            finally:
                release.set()
                await self.host.close(timeout=None)
                await asyncio.gather(tick, return_exceptions=True)
        self.assertTrue(original_job.done() and self.host.done.is_set())
        self.assertEqual(self.backup.latest().receipt, original_receipt)
