"""Actual ingress, authority, ledger and history with offline broker controls."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.ingress import EnrolledIngress
from identity.authority import LedgerAuthorityReader
from identity.service import IdentityService
from identity.test_authority import SEED, ref
from integration_owner import test_admission as support
from integration_owner import test_commands as commands
from integration_owner.credentials import pin_atlassian_config, AtlassianCredentialResolver
from integration_owner.receiver import IntegrationOwner
from integration_owner.service import IntegrationRouterService, IntegrationService, verify_receipt
from integration_owner.intent import effect_id
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerBinding, OwnerLedger, owner_subject
from taskmgmt.test_atlassian_safety import CLOUD
from taskmgmt import atlassian


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    setUp = support.AdmissionTests.setUp
    resign = support.AdmissionTests.resign
    command = commands.CommandTests.command

    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='amux-integration-service-')
        self.addCleanup(self.tmp.cleanup)
        self.history = OwnerHistory(Path(self.tmp.name).resolve() / 'history.sqlite', self.binding,
                                    stream_identity=self.ledger._identity)
        self.ledger = OwnerLedger(self.js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.ledger._retention, stream_identity=self.ledger._identity,
            history=self.history, require_completion_budget=True)
        self.owner = IntegrationOwner(self.authority, self.ledger, self.binding,
            provider='jira', credential_ref=self.envelope['payload']['credentialRef'])
        self.subscription = SimpleNamespace(drain=AsyncMock())
        self.connection = SimpleNamespace(subscribe=AsyncMock(return_value=self.subscription),
            flush=AsyncMock(), publish=AsyncMock())
        self.ingress = EnrolledIngress(self.authority, issuer_ref=ref('issuer'), signing_seed=SEED)
        self.checkpoints = []
        async def committed(receipt):
            self.checkpoints.append(receipt)
        self.service = IntegrationService(self.connection, self.owner, self.ingress,
            checkpoint_path=Path(self.tmp.name).resolve() / 'checkpoint.json', checkpoint_committed=committed)
        self.addAsyncCleanup(self.service.close)

    def request(self, *, reply=None, change=None):
        now = datetime.now(timezone.utc)
        operation = self.envelope['operation']
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('transport'), 'grantRef': operation['grantRef'],
            'operationId': operation['operationId'], 'expectedVersion': operation['expectedVersion'],
            'contractId': self.envelope['contractId'], 'payload': copy.deepcopy(self.envelope['payload']),
            'approvalRefs': operation['approvalRefs'],
            'issuedAt': (now - timedelta(seconds=1)).isoformat().replace('+00:00', 'Z'),
            'expiresAt': (now + timedelta(seconds=50)).isoformat().replace('+00:00', 'Z')}
        if reply is not None:
            claims['replySubject'] = reply
        if change:
            claims.update(change)
        return canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, bytes(reversed(SEED)))})

    def receipt(self, response, request):
        return verify_receipt(response, request,
            public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'))

    def terminal_session(self):
        session_id = 'oidc_session_' + 'a' * 32
        caller = copy.deepcopy(self.envelope['operation']['effectiveActorRef'])
        scope = copy.deepcopy(self.envelope['operation']['scope'])
        context = SimpleNamespace(caller_ref=caller, scope=scope)
        session = SimpleNamespace(close=Mock(), authorize=AsyncMock(return_value=context))
        identity = object.__new__(IdentityService)
        identity._oidc_terminal = SimpleNamespace(cancel=AsyncMock())
        identity._oidc_terminal_lock = asyncio.Lock()
        identity._oidc_terminal_sessions = {session_id: {
            'session': session, 'caller': caller, 'scope': scope,
            'expiresAt': datetime.now(timezone.utc) + timedelta(minutes=5)}}
        identity._oidc_terminal_attempts = {}
        identity._oidc_terminal_results = {}
        self.ingress.require_terminal_sessions(identity.authorize_oidc_terminal)
        return identity, session_id, session

    def enable_offline_worker(self):
        config_path = Path(self.tmp.name).resolve() / 'atlassian.json'
        config_path.write_bytes(canonical_bytes(CLOUD))
        config_path.chmod(0o600)
        credential = self.envelope['payload']['credentialRef']
        metadata = dict(provider='jira', config_path=config_path, site_url=CLOUD['base_url'], config_version=1)
        pin = pin_atlassian_config(credential, **metadata)
        resolver = AtlassianCredentialResolver(credential, **metadata, config_pin=pin)
        self.owner = IntegrationOwner(self.authority, self.ledger, self.binding,
            provider='jira', credential_ref=credential, credentials=resolver)
        self.service.owner = self.owner
        async def inline(function, *args, **kwargs):
            return function(*args, **kwargs)
        worker_patch = patch('integration_owner.workers.asyncio.to_thread', new=inline)
        worker_patch.start()
        self.addCleanup(worker_patch.stop)
        response = Mock()
        response.read.return_value = b'{}'
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        transport_patch = patch.object(atlassian.urllib.request, 'build_opener', return_value=opener)
        transport_patch.start()
        self.addCleanup(transport_patch.stop)
        return opener

    async def test_signed_start_complete_and_replay_use_one_worker_and_cached_history(self):
        opener = self.enable_offline_worker()
        await self.service.start()
        request = self.request()
        original = self.receipt(await self.service.handle(request), request)
        digest = original['originalPayloadDigest']
        self.command('integration-attempt-start', 'attempt-one', 1, digest)
        request = self.request()
        claim = self.receipt(await self.service.handle(request), request)
        start_request = request
        self.assertEqual(claim['phase'], 'dispatch-claimed')
        self.command('integration-attempt-complete', 'complete-one', 2, digest)
        request = self.request()
        complete = self.receipt(await self.service.handle(request), request)
        replay = self.receipt(await self.service.handle(start_request), start_request)
        self.assertEqual((complete['phase'], replay['phase']), ('applied', 'applied'))
        self.assertEqual(complete['attemptOperationId'], 'attempt-one')
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(self.owner._worker._tasks, {})
        self.assertEqual(self.history.verified_cursor, 3)

    async def test_signed_lost_claim_reconciles_with_read_only_worker(self):
        opener = self.enable_offline_worker()
        await self.service.start()
        request = self.request()
        digest = self.receipt(await self.service.handle(request), request)['originalPayloadDigest']
        self.command('integration-attempt-start', 'attempt-one', 1, digest)
        self.js.lose_ack = True
        request = self.request()
        claim = self.receipt(await self.service.handle(request), request)
        self.assertEqual(claim['phase'], 'dispatch-claimed')
        opener.open.assert_not_called()
        self.command('integration-effect-reconcile', 'reconcile-one', 2, digest)
        request = self.request()
        result = self.receipt(await self.service.handle(request), request)
        self.assertEqual(result['phase'], 'reconciliation-required')
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(opener.open.call_args.args[0].get_method(), 'GET')

    async def test_host_constructor_pins_named_domain_and_requires_ledger_authority(self):
        kwargs = dict(authority=self.authority, binding=self.binding, provider='jira',
            credential_ref=self.envelope['payload']['credentialRef'], stream='OWNER',
            stream_identity=self.ledger._identity, retention=self.ledger._retention,
            history=self.history, artifacts=None, issuer_ref=ref('issuer'), signing_seed=SEED,
            checkpoint_path=self.service._checkpoint_path, checkpoint_committed=self.service._checkpoint_committed)
        with self.assertRaisesRegex(ContractError, '^integration_enrolled_authority_required$'):
            IntegrationService.from_enrolled_host(self.connection, **kwargs)
        authority_binding = OwnerBinding('hub-one', 'identity', 'authority-one', 'identity-authority',
            canonical_bytes({'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}))
        authority_ledger = OwnerLedger(self.js, stream='AUTHORITY', subject=owner_subject(authority_binding),
            binding=authority_binding, retention=self.ledger._retention, stream_identity=self.ledger._identity)
        kwargs['authority'] = LedgerAuthorityReader(authority_ledger, hub_id='hub-one', entity_id='authority-one',
            profile_id='profile-one', organization_id='org-one')
        self.connection.jetstream = Mock(return_value=self.js)
        composed = IntegrationService.from_enrolled_host(self.connection, **kwargs, jetstream_domain='selected-domain')
        self.connection.jetstream.assert_called_once_with(domain='selected-domain')
        self.assertEqual(composed.subject, self.service.subject)
        self.assertTrue(composed.ledger.completion_budget_required)
        self.assertIs(composed._history, self.history)
        # The composed service has not started and owns no subscription. The
        # existing receiver remains the sole lifecycle owner of this fixture.
        with self.assertRaisesRegex(ContractError, '^integration_jetstream_domain_invalid$'):
            IntegrationService.from_enrolled_host(self.connection, **kwargs, jetstream_domain='bad.domain')

    async def test_exact_subscription_after_recovery_and_signed_intent_replay(self):
        async def subscribe(subject, **kwargs):
            self.assertEqual(subject, 'amx.v1.h.hub-one.o.org-one.integrations.' + self.binding.entity_id + '.command')
            self.assertEqual(self.history.verified_cursor, 0)
            self.assertEqual(kwargs['cb'], self.service._receive)
            self.assertEqual(kwargs['pending_msgs_limit'], 32)
            return self.subscription
        self.connection.subscribe.side_effect = subscribe
        await self.service.start()
        request = self.request()
        first = self.receipt(await self.service.handle(request), request)
        second = self.receipt(await self.service.handle(request), request)
        self.assertEqual(first, second)
        self.assertEqual((first['phase'], first['sequence'], first['attemptOperationId']), ('intent-committed', 1, None))
        self.assertEqual(len(self.js.messages), 1)
        self.assertEqual(self.history.verified_cursor, 1)
        self.assertIsNone(self.owner._worker)
        await self.service.close()
        self.subscription.drain.assert_awaited_once()
        self.assertTrue(self.history._closed)

    async def test_service_requires_start_and_refuses_after_close(self):
        with self.assertRaisesRegex(ContractError, '^integration_service_unavailable$'):
            await self.service.handle(self.request())
        await self.service.start()
        await self.service.close()
        with self.assertRaisesRegex(ContractError, '^integration_service_unavailable$'):
            await self.service.handle(self.request())

    async def test_wrong_possession_or_revoked_current_authority_cannot_append(self):
        await self.service.start()
        request = strict_loads(self.request())
        request['signature'] = sign_claims(request['claims'], SEED)
        with self.assertRaisesRegex(ContractError, '^credential_possession_invalid$'):
            await self.service.handle(canonical_bytes(request))
        self.record['state']['grants'][0]['status'] = 'revoked'
        with self.assertRaises(ContractError):
            await self.service.handle(self.request())
        self.assertEqual(self.js.messages, [])

    async def test_unrelated_registered_command_cannot_enter_owner(self):
        await self.service.start()
        with self.assertRaisesRegex(ContractError, '^integration_command_unsupported$'):
            await self.service.handle(self.request(change={'contractId': 'task-inspect'}))
        self.assertEqual(self.js.messages, [])

    async def test_query_reports_original_identity_from_same_owner(self):
        await self.service.start()
        request = self.request()
        original = self.receipt(await self.service.handle(request), request)
        grant = copy.deepcopy(self.record['state']['grants'][0])
        grant.update(ref=ref('query-grant'), contractId='integration-effect-query')
        self.record['state']['grants'].append(grant)
        self.envelope.update(contractId='integration-effect-query', payload={
            'effectRef': {'id': self.binding.entity_id, 'ownerHubId': 'hub-one', 'revision': 1},
            'originalOperationId': original['originalOperationId'],
            'originalPayloadDigest': original['originalPayloadDigest']})
        self.envelope['operation'].update(operationId='query-one', expectedVersion=1,
            grantRef=ref('query-grant'), approvalRefs=[])
        request = self.request()
        result = self.receipt(await self.service.handle(request), request)
        self.assertEqual((result['operationId'], result['originalOperationId'], result['phase']),
                         ('query-one', 'operation-one', 'intent-committed'))
        self.assertEqual(len(self.js.messages), 1)

    async def test_bound_reply_is_signed_and_substitution_is_silent(self):
        await self.service.start()
        inbox = '_INBOX.' + 'a' * 24
        request = self.request(reply=inbox)
        await self.service._receive(SimpleNamespace(reply=inbox, data=request))
        destination, response = self.connection.publish.await_args.args
        self.assertEqual(destination, inbox)
        self.assertEqual(self.receipt(response, request)['phase'], 'intent-committed')
        with self.assertRaisesRegex(ContractError, '^integration_receipt_binding$'):
            self.receipt(response, self.request(reply=inbox, change={'operationId': 'other-operation'}))
        self.connection.publish.reset_mock()
        for reply, data in ((self.ledger._subject, request), ('_INBOX.' + 'b' * 24, request),
                            (inbox, b'[]'), (inbox, b'not-json'), (inbox, b'{}')):
            await self.service._receive(SimpleNamespace(reply=reply, data=data))
        self.connection.publish.assert_not_awaited()

    async def test_unsigned_failure_is_uncertain_and_contains_no_exception_text(self):
        await self.service.start()
        self.record['state']['grants'][0]['status'] = 'revoked'
        inbox = '_INBOX.' + 'a' * 24
        request = self.request(reply=inbox)
        await self.service._receive(SimpleNamespace(reply=inbox, data=request))
        response = self.connection.publish.await_args.args[1]
        self.assertEqual(strict_loads(response), {'schemaVersion': '1.0.0', 'error': 'integration_outcome_unconfirmed'})
        with self.assertRaisesRegex(ContractError, '^integration_outcome_unconfirmed$'):
            self.receipt(response, request)
        self.assertEqual(self.js.messages, [])

    async def test_current_service_issuer_required_before_subscribe_and_reply(self):
        self.record['state']['issuers'][0]['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, '^integration_issuer_unavailable$'):
            await self.service.start()
        self.connection.subscribe.assert_not_awaited()

    async def test_revocation_after_commit_prevents_signed_reply(self):
        await self.service.start()
        original = self.owner.handle
        async def handle(raw):
            result = await original(raw)
            self.record['state']['grants'][0]['status'] = 'revoked'
            return result
        self.owner.handle = handle
        with self.assertRaisesRegex(ContractError, '^integration_access_refused$'):
            await self.service.handle(self.request())
        self.assertEqual(len(self.js.messages), 1)
        self.connection.publish.assert_not_awaited()

    async def test_revocation_during_final_read_checks_signer_and_caller_together(self):
        # Each subtest uses an exact replay of the original committed request.
        # Revocation changes disclosure, never removes or duplicates the intent.
        await self.service.start()
        request = self.request()
        authority_read = self.authority.current
        handle = self.owner.handle
        for collection, error in (('grants', 'integration_access_refused'),
                                  ('issuers', 'integration_issuer_unavailable')):
            with self.subTest(collection=collection):
                self.record['state'][collection][0]['status'] = 'active'
                async def revoke_on_final_read():
                    self.record['state'][collection][0]['status'] = 'revoked'
                    return await authority_read()
                async def completed(raw):
                    result = await handle(raw)
                    self.authority.current = revoke_on_final_read
                    return result
                self.owner.handle = completed
                try:
                    with self.assertRaisesRegex(ContractError, '^' + error + '$'):
                        await self.service.handle(request)
                    self.assertEqual(len(self.js.messages), 1)
                finally:
                    self.authority.current = authority_read
                    self.owner.handle = handle
                    self.record['state'][collection][0]['status'] = 'active'
        legitimate = self.receipt(await self.service.handle(request), request)
        self.assertEqual(legitimate['phase'], 'intent-committed')
        self.assertEqual(len(self.js.messages), 1)

    async def test_terminal_expiry_while_owner_work_waits_withholds_signed_reply(self):
        identity, session_id, session = self.terminal_session()
        await self.service.start()
        request = self.request(change={'terminalSessionId': session_id})
        entered, release = asyncio.Event(), asyncio.Event()
        original = self.owner.handle

        async def held(raw):
            result = await original(raw)
            entered.set()
            await release.wait()
            return result

        self.owner.handle = held
        pending = asyncio.create_task(self.service.handle(request))
        await asyncio.wait_for(entered.wait(), 1)
        identity._oidc_terminal_sessions[session_id]['expiresAt'] = (
            datetime.now(timezone.utc) - timedelta(seconds=1))
        release.set()
        with self.assertRaisesRegex(ContractError, '^oidc_terminal_session_required$'):
            await pending
        self.assertEqual(len(self.js.messages), 1)
        self.assertEqual(session.authorize.await_count, 1)
        session.close.assert_called_once_with()
        self.assertNotIn(session_id, identity._oidc_terminal_sessions)

    async def test_membership_and_identity_revocation_while_owner_waits_refuse(self):
        _identity, session_id, session = self.terminal_session()
        await self.service.start()
        request = self.request(change={'terminalSessionId': session_id})
        original = self.owner.handle
        for collection in ('memberships', 'identities'):
            with self.subTest(collection=collection):
                entered, release = asyncio.Event(), asyncio.Event()

                async def held(raw):
                    result = await original(raw)
                    entered.set()
                    await release.wait()
                    return result

                self.owner.handle = held
                pending = asyncio.create_task(self.service.handle(request))
                await asyncio.wait_for(entered.wait(), 1)
                self.record['state'][collection][0]['status'] = 'revoked'
                release.set()
                with self.assertRaisesRegex(ContractError, '^integration_access_refused$'):
                    await pending
                self.record['state'][collection][0]['status'] = 'active'
                self.owner.handle = original
        self.assertEqual(len(self.js.messages), 1)
        self.assertEqual(session.authorize.await_count, 2)

    async def test_canceled_start_retains_original_subscription_until_close(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def subscribe(*args, **kwargs):
            entered.set()
            await release.wait()
            return self.subscription
        self.connection.subscribe.side_effect = subscribe
        startup = asyncio.create_task(self.service.start())
        await entered.wait()
        startup.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await startup
        original = self.service._subscribe_task
        closing = asyncio.create_task(self.service.close())
        await asyncio.sleep(0)
        self.assertFalse(original.done())
        self.assertFalse(closing.done())
        release.set()
        await closing
        self.assertIs(original, self.service._subscribe_task)
        self.connection.subscribe.assert_awaited_once()
        self.subscription.drain.assert_awaited_once()

    async def test_concurrent_start_allocates_one_subscription(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def subscribe(*args, **kwargs):
            entered.set()
            await release.wait()
            return self.subscription
        self.connection.subscribe.side_effect = subscribe
        startup = asyncio.create_task(self.service.start())
        await entered.wait()
        with self.assertRaisesRegex(ContractError, '^integration_service_lifecycle$'):
            await self.service.start()
        release.set()
        await startup
        self.connection.subscribe.assert_awaited_once()

    async def test_canceled_close_rejoins_same_drain(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def drain():
            entered.set()
            await release.wait()
        self.subscription.drain.side_effect = drain
        await self.service.start()
        closing = asyncio.create_task(self.service.close())
        await entered.wait()
        original = self.service._drain_task
        closing.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await closing
        self.assertFalse(original.done())
        release.set()
        await self.service.close()
        self.assertIs(original, self.service._drain_task)
        self.subscription.drain.assert_awaited_once()

    async def test_close_joins_reply_publish_before_history_and_worker_close(self):
        await self.service.start()
        entered, release = asyncio.Event(), asyncio.Event()
        async def publish(*args, **kwargs):
            entered.set()
            await release.wait()
        self.connection.publish.side_effect = publish
        inbox = '_INBOX.' + 'a' * 24
        receive = asyncio.create_task(self.service._receive(SimpleNamespace(reply=inbox, data=self.request(reply=inbox))))
        await entered.wait()
        closing = asyncio.create_task(self.service.close())
        await asyncio.sleep(0)
        self.assertFalse(closing.done())
        self.assertFalse(self.history._closed)
        self.assertFalse(self.owner._closed)
        original_reply = next(iter(self.service._callbacks))
        receive.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await receive
        self.assertFalse(original_reply.done())
        release.set()
        await closing
        self.assertTrue(original_reply.done())
        self.assertTrue(self.history._closed)
        self.assertTrue(self.owner._closed)

    async def test_oversized_body_and_closed_signed_receipt(self):
        await self.service.start()
        with self.assertRaisesRegex(ContractError, '^owner_body_limit$'):
            await self.service.handle(b'x' * 65537)
        request = self.request()
        response = strict_loads(await self.service.handle(request))
        response['claims']['extra'] = 'caller-controlled'
        response['signature'] = sign_claims(response['claims'], SEED)
        with self.assertRaisesRegex(ContractError, '^integration_receipt_invalid$'):
            self.receipt(canonical_bytes(response), request)

    async def test_project_router_derives_two_exact_owners_and_rechecks_authority(self):
        services, ledgers = {}, {}

        async def service_factory(binding, original_operation_id):
            self.assertEqual(binding.entity_id,
                effect_id(self.envelope['operation']['scope'], original_operation_id))
            js = support.FakeJetStream(self.ledger._retention)
            js.config.subjects = [owner_subject(binding)]
            history = OwnerHistory(Path(self.tmp.name).resolve() /
                (binding.entity_id + '.sqlite'), binding,
                stream_identity=self.ledger._identity)
            ledger = OwnerLedger(js, stream='OWNER', subject=owner_subject(binding),
                binding=binding, retention=self.ledger._retention,
                stream_identity=self.ledger._identity, history=history,
                require_completion_budget=True)
            owner = IntegrationOwner(self.authority, ledger, binding, provider='jira',
                credential_ref=self.envelope['payload']['credentialRef'])
            async def committed(receipt):
                pass
            service = IntegrationService(self.connection, owner, self.ingress,
                checkpoint_path=Path(self.tmp.name).resolve() /
                    (binding.entity_id + '.checkpoint'),
                checkpoint_committed=committed)
            services[binding.entity_id] = service
            ledgers[binding.entity_id] = js
            return service

        router = IntegrationRouterService(self.connection, self.ingress,
            scope=copy.deepcopy(self.envelope['operation']['scope']), provider='jira',
            credential_ref=self.envelope['payload']['credentialRef'],
            service_factory=service_factory)
        self.addAsyncCleanup(router.close)
        await router.start()
        self.connection.subscribe.assert_awaited_with(
            'amx.v1.h.hub-one.o.org-one.integrations.*.command', cb=router._receive,
            pending_msgs_limit=32, pending_bytes_limit=32 * 65536)

        first_request = self.request()
        first_entity = self.binding.entity_id
        first_subject = router.subject.replace('*', first_entity)
        first = self.receipt(await router.handle(first_request, subject=first_subject),
                             first_request)
        self.assertEqual(first['originalOperationId'], 'operation-one')

        original_grant = self.record['state']['grants'][0]
        second_entity = effect_id(self.envelope['operation']['scope'], 'operation-two')
        second_grant = copy.deepcopy(original_grant)
        second_grant.update(ref=ref('grant-two'), resourceId=second_entity)
        self.record['state']['grants'].append(second_grant)
        second_approver_grant = copy.deepcopy(self.record['state']['grants'][1])
        second_approver_grant.update(ref=ref('approve-grant-two'),
                                     resourceId='grant-two')
        self.record['state']['grants'].append(second_approver_grant)
        second_approval = copy.deepcopy(self.record['state']['approvals'][0])
        second_approval.update(ref=ref('approval-two'), grantRef=ref('grant-two'),
            approverGrantRef=ref('approve-grant-two'), operationId='operation-two')
        self.record['state']['approvals'].append(second_approval)
        self.envelope['payload']['effectRef']['id'] = second_entity
        self.envelope['operation'].update(operationId='operation-two',
            grantRef=ref('grant-two'), approvalRefs=[ref('approval-two')])
        digest = payload_digest(self.envelope['payload'])
        self.envelope['operation']['payloadDigest'] = digest
        second_approval['payloadDigest'] = digest
        self.resign()
        second_request = self.request()
        second_subject = router.subject.replace('*', second_entity)
        second = self.receipt(await router.handle(second_request, subject=second_subject),
                              second_request)

        self.assertEqual(second['originalOperationId'], 'operation-two')
        self.assertEqual(set(services), {first_entity, second_entity})
        self.assertTrue(all(len(js.messages) == 1 for js in ledgers.values()))
        with self.assertRaisesRegex(ContractError, '^integration_access_refused$'):
            await router.handle(second_request, subject=first_subject)

        inbox = '_INBOX.' + 'r' * 24
        routed_request = self.request(reply=inbox)
        for provider, scope in (('github', self.envelope['operation']['scope']),
                ('jira', {**self.envelope['operation']['scope'],
                          'projectId': 'other-project'})):
            route_factory = Mock()
            unrelated = IntegrationRouterService(self.connection, self.ingress,
                scope=scope, provider=provider,
                credential_ref=self.envelope['payload']['credentialRef'],
                service_factory=route_factory)
            await unrelated.start()
            self.connection.publish.reset_mock()
            await unrelated._respond(SimpleNamespace(reply=inbox,
                subject=second_subject, data=routed_request))
            self.connection.publish.assert_not_awaited()
            route_factory.assert_not_called()
            await unrelated.close()

        second_grant['status'] = 'revoked'
        with self.assertRaises(ContractError):
            await router.handle(second_request, subject=second_subject)
        self.assertEqual(len(ledgers[second_entity].messages), 1)
