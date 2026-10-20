"""Signed lifecycle protocol with real owners and offline transport controls.

No thread or network fixture runs here. Native I/O ownership needs the separately
serialized loopback test; replacing to_thread here tests protocol behavior only.
"""
import asyncio
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from identity.test_authority import ref
from integration_owner.credentials import pin_atlassian_config, AtlassianCredentialResolver
from integration_owner.receiver import IntegrationOwner
from integration_owner import test_admission
from integration_owner.test_intent import payload
from state_owner.artifacts import OwnerArtifacts
from state_owner.test_artifacts import JS as ArtifactJS, Store as ArtifactStore
from taskmgmt.test_atlassian_safety import CLOUD
from taskmgmt import atlassian


class CommandTests(unittest.IsolatedAsyncioTestCase):
    resign = test_admission.AdmissionTests.resign
    execute = test_admission.AdmissionTests.execute

    def setUp(self):
        test_admission.AdmissionTests.setUp(self)
        fixture = tempfile.TemporaryDirectory(prefix='agentmux-worker-offline-')
        self.addCleanup(fixture.cleanup)
        config_path = Path(fixture.name) / 'atlassian.json'
        config_path.write_text(json.dumps(CLOUD))
        config_path.chmod(0o600)
        reference = payload()['credentialRef']
        self.config_path, self.reference = config_path, reference
        metadata = dict(provider='jira', config_path=config_path, site_url=CLOUD['base_url'], config_version=1)
        pin = pin_atlassian_config(reference, **metadata)
        resolver = AtlassianCredentialResolver(reference, **metadata, config_pin=pin)
        self.owner = IntegrationOwner(self.authority, self.ledger, self.binding,
            provider='jira', credential_ref=reference, credentials=resolver)
        self.addAsyncCleanup(self.owner.close)
        self.requests = []
        self.response = b'{}'
        self.transport_error = None
        async def inline(function, *args, **kwargs):
            return function(*args, **kwargs)
        inline_patch = patch('integration_owner.workers.asyncio.to_thread', new=inline)
        inline_patch.start()
        self.addCleanup(inline_patch.stop)
        def opening(request, **kwargs):
            self.requests.append(request)
            self.assertGreaterEqual(len(self.js.messages), 2, 'dispatch must follow retained claim')
            latest = strict_loads(self.js.messages[1].data)
            self.assertEqual(latest['state']['phase'], 'dispatch-claimed')
            if self.transport_error is not None:
                raise self.transport_error
            response = Mock()
            response.read.return_value = self.response
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            return response
        self.opener = Mock()
        self.opener.open.side_effect = opening
        transport_patch = patch.object(atlassian.urllib.request, 'build_opener', return_value=self.opener)
        transport_patch.start()
        self.addCleanup(transport_patch.stop)

    async def configure_confluence_update(self):
        content = canonical_bytes({'title': 'Existing title', 'html': '<p>Approved content</p>'})
        store = ArtifactStore()
        artifacts = OwnerArtifacts(store, ArtifactJS(store), bucket='bucket', owner_hub_id='hub-one',
            store_ref={'id': 'store-one', 'ownerHubId': 'hub-one', 'revision': 1}, max_bytes=60000)
        content_ref = await artifacts.upload(content,
            media_type='application/vnd.agentmux.integration-content+json')
        proposal = {**payload(), 'action': 'confluence-update',
            'target': {'spaceKey': 'DOCS', 'pageId': '42', 'expectedVersion': 7},
            'contentRef': content_ref}
        self.envelope['payload'] = proposal
        digest = payload_digest(proposal)
        self.envelope['operation']['payloadDigest'] = digest
        self.record['state']['approvals'][0]['payloadDigest'] = digest
        self.resign()
        await self.owner.close()
        metadata = dict(provider='confluence', config_path=self.config_path,
            site_url=getattr(self, 'site', CLOUD['base_url']), config_version=1)
        pin = pin_atlassian_config(self.reference, **metadata)
        resolver = AtlassianCredentialResolver(self.reference, **metadata, config_pin=pin)
        self.owner = IntegrationOwner(self.authority, self.ledger, self.binding,
            provider='confluence', credential_ref=self.reference, artifacts=artifacts, credentials=resolver)
        self.addAsyncCleanup(self.owner.close)
        return proposal

    def command(self, contract, operation_id, revision, original_digest, attempt_id='attempt-one'):
        state = self.record['state']
        grant = copy.deepcopy(state['grants'][0])
        grant_ref = ref('grant-' + str(len(state['grants'])))
        grant.update(ref=grant_ref, contractId=contract)
        state['grants'].append(grant)
        self.envelope.update(contractId=contract, payload={
            'effectRef': {'id': self.binding.entity_id, 'ownerHubId': 'hub-one', 'revision': revision},
            'originalOperationId': 'operation-one', 'originalPayloadDigest': original_digest,
            'attemptOperationId': attempt_id})
        operation = self.envelope['operation']
        operation.update(operationId=operation_id, expectedVersion=revision,
            payloadDigest=payload_digest(self.envelope['payload']), grantRef=grant_ref, approvalRefs=[])
        if contract == 'integration-attempt-start':
            approve_ref = ref('approve-' + operation_id)
            approval_ref = ref('approval-' + operation_id)
            approver = copy.deepcopy(grant)
            approver.update(ref=approve_ref, contractId='identity-approve', resourceId=grant_ref['id'])
            state['grants'].append(approver)
            approval = copy.deepcopy(state['approvals'][0])
            approval.update(ref=approval_ref, grantRef=grant_ref, approverGrantRef=approve_ref,
                operationId=operation_id, expectedVersion=revision, payloadDigest=operation['payloadDigest'])
            state['approvals'].append(approval)
            operation['approvalRefs'] = [approval_ref]
        self.resign()

    async def claimed(self, *, lose_ack=False):
        initial = await self.execute()
        digest = initial.original_payload_digest
        self.command('integration-attempt-start', 'attempt-one', 1, digest)
        self.js.lose_ack = lose_ack
        reply = await self.execute()
        return digest, reply

    async def test_claim_precedes_one_dispatch_and_completion_retains_observation(self):
        with patch.object(self.ledger, 'append', wraps=self.ledger.append) as append:
            digest, claim = await self.claimed()
            original_start = copy.deepcopy(self.envelope)
            self.assertEqual((claim.status, claim.attempt_operation_id), ('dispatch-claimed', 'attempt-one'))
            self.command('integration-attempt-complete', 'complete-one', 2, digest)
            complete = await self.execute()
            self.assertEqual(complete.wire_payload()['phase'], 'applied')
            self.assertEqual(complete.wire_payload()['attemptOperationId'], 'attempt-one')
            self.assertEqual([call.kwargs['completion_records'] for call in append.await_args_list], [3, 2, 0])
            self.envelope = original_start
            replay = await self.execute()
        self.assertEqual(replay.status, 'applied')
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(len(self.js.messages), 3)
        self.assertEqual(self.owner._worker._tasks, {})

    async def test_lost_claim_ack_never_dispatches_or_automatically_retries(self):
        digest, claim = await self.claimed(lose_ack=True)
        self.assertEqual(claim.status, 'dispatch-claimed')
        self.assertEqual(self.requests, [])
        await self.execute()
        self.assertEqual(self.requests, [])
        self.command('integration-attempt-complete', 'complete-one', 2, digest)
        with self.assertRaises(ContractError):
            await self.execute()
        self.assertEqual(len(self.js.messages), 2)

    async def test_config_rotation_during_claim_refuses_stale_credentials_before_io(self):
        initial = await self.execute()
        digest = initial.original_payload_digest
        self.command('integration-attempt-start', 'attempt-one', 1, digest)
        append = self.ledger.append
        config_path = self.owner._worker._resolver._binding[2]
        async def rotate_after_claim(*args, **kwargs):
            stored = await append(*args, **kwargs)
            config_path.write_text(json.dumps({**CLOUD, 'api_token': 'SYNTHETIC-ROTATED'}))
            return stored
        with patch.object(self.ledger, 'append', new=rotate_after_claim):
            with self.assertRaisesRegex(ContractError, '^integration_request_refused$'):
                await self.execute()
        self.assertEqual(self.requests, [])
        self.assertEqual(self.owner._worker._tasks, {})
        self.assertEqual(len(self.js.messages), 2)
        self.assertEqual(strict_loads(self.js.messages[-1].data)['state']['phase'], 'dispatch-claimed')
        self.command('integration-attempt-complete', 'complete-one', 2, digest)
        complete = await self.execute()
        self.assertEqual(complete.status, 'not-dispatched')
        self.assertEqual(len(self.js.messages), 3)
        self.assertEqual(self.requests, [])

    async def test_queued_worker_rechecks_pin_before_transport(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def queued(function, *args, **kwargs):
            entered.set()
            await release.wait()
            return function(*args, **kwargs)
        with patch('integration_owner.workers.asyncio.to_thread', new=queued):
            try:
                digest, claim = await self.claimed()
                self.assertEqual(claim.status, 'dispatch-claimed')
                await entered.wait()
                path = self.owner._worker._resolver._binding[2]
                path.write_text(json.dumps({**CLOUD, 'api_token': 'SYNTHETIC-ROTATED'}))
            finally:
                release.set()
            self.command('integration-attempt-complete', 'complete-one', 2, digest)
            complete = await self.execute()
        self.assertEqual(complete.status, 'not-dispatched')
        self.assertEqual(self.requests, [])
        self.assertEqual(self.owner._worker._tasks, {})
        self.assertEqual(len(self.js.messages), 3)

    async def test_reconciliation_read_cannot_mark_an_uncertain_transition_applied(self):
        digest, _ = await self.claimed(lose_ack=True)
        self.response = b'{"key":"AMUX-66"}'
        self.command('integration-effect-reconcile', 'reconcile-one', 2, digest)
        reply = await self.execute()
        self.assertEqual(reply.status, 'reconciliation-required')
        self.assertEqual([request.get_method() for request in self.requests], ['GET'])
        self.assertFalse(strict_loads(self.js.messages[-1].data)['state']['observation']['retryAllowed'])

    async def test_queued_reconciliation_rechecks_pin_before_provider_read(self):
        digest, _ = await self.claimed(lose_ack=True)
        self.command('integration-effect-reconcile', 'reconcile-one', 2, digest)
        entered, release = asyncio.Event(), asyncio.Event()
        async def queued(function, *args, **kwargs):
            entered.set()
            await release.wait()
            return function(*args, **kwargs)
        with patch('integration_owner.workers.asyncio.to_thread', new=queued):
            reconciling = asyncio.create_task(self.execute())
            try:
                await entered.wait()
                path = self.owner._worker._resolver._binding[2]
                path.write_text(json.dumps({**CLOUD, 'api_token': 'SYNTHETIC-ROTATED'}))
            finally:
                release.set()
            result = await reconciling
        self.assertEqual(result.status, 'reconciliation-required')
        observed = strict_loads(self.js.messages[-1].data)['state']['observation']
        self.assertEqual(observed['identity']['presence'], 'unavailable')
        self.assertFalse(observed['retryAllowed'])
        self.assertEqual(self.requests, [])
        self.assertEqual(self.owner._worker._tasks, {})

    async def test_late_owned_ack_can_complete_after_another_owner_reconciles(self):
        digest, _ = await self.claimed()
        original_owner = self.owner
        self.owner = IntegrationOwner(self.authority, self.ledger, self.binding,
            provider='jira', credential_ref=payload()['credentialRef'])
        self.addAsyncCleanup(self.owner.close)
        self.command('integration-effect-reconcile', 'reconcile-one', 2, digest)
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        self.owner = original_owner
        self.command('integration-attempt-complete', 'complete-one', 3, digest)
        self.assertEqual((await self.execute()).status, 'applied')
        self.assertEqual(len(self.requests), 1)

    async def test_confluence_update_lost_reply_retains_identity_and_replay_never_puts_again(self):
        proposal = await self.configure_confluence_update()
        initial = await self.execute()
        digest = initial.original_payload_digest
        self.command('integration-attempt-start', 'attempt-one', 1, digest)
        original_start = copy.deepcopy(self.envelope)
        self.transport_error = TimeoutError('synthetic lost reply')
        self.assertEqual((await self.execute()).status, 'dispatch-claimed')
        self.command('integration-attempt-complete', 'complete-one', 2, digest)
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        retained = strict_loads(self.js.messages[-1].data)['state']
        self.assertEqual(retained['intent']['target'], proposal['target'])
        self.assertEqual(retained['observation']['kind'], 'uncertain')
        self.assertFalse(retained['observation']['retryAllowed'])
        self.transport_error = None
        self.response = b'{"id":"42","version":{"number":8}}'
        self.command('integration-effect-reconcile', 'reconcile-one', 3, digest)
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        self.envelope = original_start
        self.assertEqual((await self.execute()).status, 'reconciliation-required')
        self.assertEqual([request.get_method() for request in self.requests], ['PUT', 'GET'])
        update = self.requests[0]
        self.assertTrue(update.full_url.endswith('/content/42'))
        self.assertEqual(json.loads(update.data)['version'], {'number': 8})
        self.assertEqual(len([request for request in self.requests if request.get_method() == 'PUT']), 1)


if __name__ == '__main__':
    unittest.main()
