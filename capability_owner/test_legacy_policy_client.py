"""Actual Hub requests and policy owners with controlled session transport."""
import asyncio
import base64
import copy
from contextvars import ContextVar
import hashlib
import json
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
import weakref

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.client_launch_session import ApplicationClientSession
from hub.fed.runtime import Federation
from hub.server import Hub
from identity.application_client import ApplicationClientKey
from identity.test_knowledge_client import material
from .legacy_policy_client import LegacyPolicyCommandClient
from . import test_federation_policy_transition as support


class LegacyPolicyClientTests(unittest.IsolatedAsyncioTestCase):
    make_owner = support.FederationPolicyTransitionTests.make_owner
    request = support.FederationPolicyTransitionTests.request
    final = support.FederationPolicyTransitionTests.final
    project_request = support.FederationPolicyTransitionTests.project_request
    configuration_host = support.FederationPolicyTransitionTests.configuration_host

    async def asyncSetUp(self):
        await support.FederationPolicyTransitionTests.asyncSetUp(self)
        from state_owner.configuration_host import ConfigurationHost
        factory = ConfigurationHost.from_enrolled_host
        def configured(*args, **kwargs):
            kwargs['reply_prefix'] = '_INBOX.configuration_policy01'
            return factory(*args, **kwargs)
        with patch.object(ConfigurationHost, 'from_enrolled_host', side_effect=configured):
            self.config_host = await self.configuration_host()
        clock = patch('capability_owner.legacy_policy_client.datetime', support.policy_support._Clock)
        clock.start()
        self.addCleanup(clock.stop)
        self.hub = object.__new__(Hub)
        self.hub.store, self.hub.db = self.source._store, self.source.db
        self.hub.stop = threading.Event()
        self.hub.operator_sha = hashlib.sha256(b'operator-secret').hexdigest()
        self.hub._authenticated_callers = weakref.WeakKeyDictionary()
        self.hub._authenticated_caller_context = ContextVar('policy-client-proof', default=None)
        self.fed = object.__new__(Federation)
        self.fed.hub, self.fed.hubdir, self.fed.node = self.hub, str(self.root), 'mac'
        self.fed.cfg, self.fed.policy = self.source._policy.cfg, self.source._policy
        self.fed.connected, self.fed._qualified_board = False, True
        self.fed.verbs, self.fed.plugin_verbs = self.fed._core_verbs(), {}
        self.fed.refresh_policy = AsyncMock(side_effect=lambda: self.source._policy)
        self.hub.fed = self.fed
        selected = material()
        selected.pop('knowledgeCommands')
        selected['scope'] = strict_loads(self.ledger._binding.scope)
        selected['federationPolicyCommands'] = {
            'transportRef': support.policy_support.ref('transport'), 'replyIssuerRef': support.policy_support.ref('issuer'),
            'serviceIdentityRef': support.policy_support.ref('service'),
            'configurationRef': {'id': self.ledger._binding.entity_id, 'ownerHubId': 'hub-one', 'revision': 0},
            'keyRef': support.policy_support.ref('policy-key'), 'authenticatedCaller': 'operator',
            'subject': 'amx.v1.h.hub-one.o.org-one.p.project-one.w._.configuration.' + self.ledger._binding.entity_id + '.command',
            'replyIssuerPublicKey': selected['replyIssuerPublicKey'], 'originDigest': support.policy_support._digest(self.old),
            'owner': copy.deepcopy(self.fixture.owner), 'target': self.target.descriptor,
            'repository': copy.deepcopy(self.repository), 'policyPath': str(self.path), 'localPeer': 'nick',
            'grantRefs': {name: support.policy_support.ref(name) for name in ('configuration-read', 'configuration-set')}}
        self.key = ApplicationClientKey(selected)
        self.commands, self.drop_final_reply, self.drop_before_final = [], False, False
        self.final_entered = self.final_release = None
        self.issued_approval = None
        self.drop_prepared_reply = self.commit_without_projection = False
        self.session = self.new_session()
        self.client = LegacyPolicyCommandClient(self.hub, (self.session,)).bind(self.fed)
        self.hub._policy_commands = self.client
        self.addAsyncCleanup(self.client.close, timeout=None)

    def new_session(self):
        loop = asyncio.get_running_loop()
        session = object.__new__(ApplicationClientSession)
        session._stopped = session._terminal_enrolled = session._terminal_active = session._loop_stopping = False
        session._closing = session._final_closing = session._command_future = session._command_identity = None
        session._loop, session._thread = loop, threading.current_thread()
        selection = self.key.selection
        route = selection['federationPolicyCommands']
        session._federation_policy_enrollment = canonical_bytes({name: selection[name] for name in
            ('hubId', 'profileId', 'authorityId', 'callerRef', 'scope', 'federationPolicyCommands')})
        async def command(*, contract_id, operation_id, expected_version, payload, expires_at,
                          approval_refs, deadline, cleanup_deadline):
            claims = {'purpose': 'agentmux-client-possession-v1',
                **{name: selection[name] for name in ('hubId', 'profileId', 'authorityId')},
                'transportRef': route['transportRef'], 'grantRef': route['grantRefs'][contract_id],
                'operationId': operation_id, 'expectedVersion': expected_version,
                'contractId': contract_id, 'payload': payload, 'approvalRefs': approval_refs,
                'issuedAt': support.policy_support._Clock.now().isoformat().replace('+00:00', 'Z'),
                'expiresAt': expires_at, 'replySubject': self.config_host._reply_prefix + 'legacy-policy'}
            self.commands.append(copy.deepcopy(claims))
            packet = self.key.sign_command(claims, subject=route['subject'], now=support.policy_support._Clock.now())
            document = None if contract_id == 'configuration-read' else strict_loads(base64.b64decode(payload['configurationBytes']))
            if self.drop_before_final and document is not None and document['format'] == 'amx-federation-policy-v1':
                self.drop_before_final = False
                raise TimeoutError('final dispatch outcome unknown')
            if self.commit_without_projection and document is not None and document['format'] == 'amx-federation-policy-v1':
                from state_owner.configuration import ConfigurationOwner
                self.commit_without_projection = False
                admitted = await self.owner.custody._ingress.admit(packet,
                    cancellation_ref=support.policy_support.ref('unprojected-cancel'))
                self.unprojected = admitted.envelope
                await ConfigurationOwner.handle(self.owner, admitted.envelope)
                raise TimeoutError('projection outcome unknown')
            response = await self.transition.client_command(packet, reply_subject=claims['replySubject'])
            if document is not None and document['format'] == 'amx-federation-policy-v1' and self.final_entered is not None:
                self.final_entered.set()
                await self.final_release.wait()
            if self.drop_final_reply and document is not None and document['format'] == 'amx-federation-policy-v1':
                self.drop_final_reply = False
                raise TimeoutError('original final reply lost')
            verified = self.key.verify_command_response(response, packet, subject=route['subject'], now=support.policy_support._Clock.now())
            if verified.kind == 'prepared' and self.drop_prepared_reply:
                self.drop_prepared_reply = False
                raise TimeoutError('preparation reply lost')
            if verified.kind == 'prepared' and self.issued_approval is not None:
                self.add_approval('approved-final', self.issued_approval,
                    self.client._payload(route, expected_version, verified.data))
            return verified
        session._owner = SimpleNamespace(federation_policy_command=command)
        return session

    async def restart_client(self, *, fresh_session=False):
        await self.client.close(timeout=None)
        if fresh_session:
            self.session = self.new_session()
        self.client = LegacyPolicyCommandClient(self.hub, (self.session,)).bind(self.fed)
        self.hub._policy_commands = self.client
        self.addAsyncCleanup(self.client.close, timeout=None)

    def retained(self):
        return self.client._load(strict_loads(self.client._routes[0][1]))

    def replace_authority(self):
        self._gateway_authority_js.messages[0].data = canonical_bytes(self._gateway_authority_record)

    def add_approval(self, identifier, operation, payload):
        self._gateway_authority_record['state']['approvals'].append({
            'ref': support.policy_support.ref(identifier), 'grantRef': support.policy_support.ref('configuration-set'),
            'approverRef': support.policy_support.ref('human'), 'approverGrantRef': support.policy_support.ref('approve-policy'),
            'payloadDigest': payload_digest(payload), 'audience': {'hubId': 'hub-one', 'serviceId': 'configuration-owner'},
            'operationId': operation, 'expectedVersion': payload['configurationRef']['revision'],
            'decision': 'approved', 'status': 'active', 'issuedAt': '2026-10-09T12:00:00Z',
            'expiresAt': '2026-10-09T12:10:00Z'})
        self.replace_authority()

    async def request_hub(self, args, *, lose_hub_reply=False):
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps({
            'token': 'operator-secret', 'verb': 'fed_trust', 'args': args}).encode()), at_eof=lambda: False)
        writer = SimpleNamespace(write=Mock(), drain=AsyncMock(), close=Mock(), is_closing=lambda: False)
        if lose_hub_reply:
            writer.write.side_effect = BrokenPipeError('Hub reply lost')
        try:
            await self.hub.handle_conn(reader, writer, tcp=True)
        except BrokenPipeError:
            if not lose_hub_reply:
                raise
            return None
        return json.loads(writer.write.call_args.args[0])

    async def test_identical_authenticated_request_recovers_locally_committed_result_after_lost_hub_reply(self):
        args = {'peer': 'alice', 'level': 'flag'}
        await self.request_hub(args, lose_hub_reply=True)
        original = self.client._load(strict_loads(self.client._routes[0][1]))
        self.assertEqual(original['phase'], 'committed')
        self.assertEqual(len(self.fixture.js.messages), 1)
        result = await self.request_hub(args)
        self.assertTrue(result['ok'], result)
        retained = self.client._load(strict_loads(self.client._routes[0][1]))
        self.assertEqual(retained['operationId'], original['operationId'])
        self.assertEqual(retained['result'], original['result'])
        self.assertEqual(len(self.fixture.js.messages), 1)
        self.assertEqual(len([item for item in self.commands if item['contractId'] == 'configuration-set']), 2)

    async def test_restart_recovers_original_completed_request_using_current_read_only(self):
        args = {'peer': 'alice', 'level': 'flag'}
        self.assertTrue((await self.request_hub(args))['ok'])
        original = self.retained()
        await self.restart_client()
        next(grant for grant in self._gateway_authority_record['state']['grants']
            if grant['ref'] == support.policy_support.ref('configuration-set'))['decision'] = 'review-required'
        self.replace_authority()
        self.assertTrue((await self.request_hub(args))['ok'])
        self.assertEqual(self.retained(), original)
        self.assertEqual(len(self.fixture.js.messages), 1)
        self.assertEqual(self.commands[-1]['contractId'], 'configuration-read')

    async def test_current_read_revocation_refuses_cached_result(self):
        args = {'peer': 'alice', 'level': 'flag'}
        self.assertTrue((await self.request_hub(args))['ok'])
        original = self.retained()
        next(grant for grant in self._gateway_authority_record['state']['grants']
            if grant['ref'] == support.policy_support.ref('configuration-read'))['status'] = 'revoked'
        self.replace_authority()
        self.assertFalse((await self.request_hub(args))['ok'])
        self.assertEqual(self.retained(), original)
        self.assertEqual(len(self.fixture.js.messages), 1)
        self.assertEqual(len([item for item in self.commands if item['contractId'] == 'configuration-set']), 2)

    async def test_new_explicit_intent_advances_but_reused_operation_cannot_change_payload(self):
        first = {'peer': 'alice', 'level': 'flag', 'operationId': 'policy-original'}
        self.assertTrue((await self.request_hub(first))['ok'])
        self.assertFalse((await self.request_hub(dict(first, level='deny')))['ok'])
        self.assertEqual(len(self.fixture.js.messages), 1)
        second = dict(first, operationId='policy-next')
        self.assertTrue((await self.request_hub(second))['ok'])
        self.assertEqual(self.retained()['operationId'], 'policy-next')
        self.assertEqual(self.retained()['result']['revision'], 2)
        self.assertEqual(len(self.fixture.js.messages), 2)

    async def test_lost_final_reply_restart_recovers_original_pair_without_another_set(self):
        args = {'peer': 'alice', 'level': 'flag'}
        self.drop_final_reply = True
        self.assertFalse((await self.request_hub(args))['ok'])
        original = self.retained()
        self.assertEqual(original['phase'], 'committing')
        self.assertEqual(len(self.fixture.js.messages), 1)
        await self.restart_client(fresh_session=True)
        self.assertTrue((await self.request_hub(args))['ok'])
        recovered = self.retained()
        self.assertEqual(recovered['operationId'], original['operationId'])
        self.assertEqual(recovered['finalPayload'], original['finalPayload'])
        self.assertEqual(recovered['phase'], 'committed')
        self.assertEqual(len(self.fixture.js.messages), 1)
        self.assertEqual(len([item for item in self.commands if item['contractId'] == 'configuration-set']), 2)

    async def test_unknown_final_without_visible_outcome_stays_original_and_blocks_new_intent(self):
        args = {'peer': 'alice', 'level': 'flag'}
        self.drop_before_final = True
        self.assertFalse((await self.request_hub(args))['ok'])
        original = self.retained()
        self.assertEqual(original['phase'], 'committing')
        await self.restart_client(fresh_session=True)
        self.assertFalse((await self.request_hub(args))['ok'])
        self.assertFalse((await self.request_hub(dict(args, level='deny', operationId='new-intent')))['ok'])
        self.assertEqual(self.retained(), original)
        self.assertEqual(self.fixture.js.messages, [])
        self.assertEqual(self.path.read_bytes(), self.old)
        self.assertEqual(len([item for item in self.commands if item['contractId'] == 'configuration-set']), 2)

    async def test_original_final_and_close_are_joined_after_hub_request_cancellation(self):
        args = {'peer': 'alice', 'level': 'flag'}
        self.final_entered, self.final_release = asyncio.Event(), asyncio.Event()
        request = asyncio.create_task(self.request_hub(args))
        close = None
        try:
            async with asyncio.timeout(5):
                await self.final_entered.wait()
            original = self.retained()
            self.assertEqual(original['phase'], 'committing')
            request.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await request
            close = asyncio.create_task(self.client.close(timeout=None))
            await asyncio.sleep(.01)
            self.assertFalse(close.done())
            self.assertTrue(self.client._workers)
        finally:
            self.final_release.set()
            await asyncio.gather(request, return_exceptions=True)
            if close is not None:
                await close
        self.assertEqual(self.client._workers, set())
        await self.restart_client()
        self.assertTrue((await self.request_hub(args))['ok'])
        self.assertEqual(self.retained()['operationId'], original['operationId'])
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_review_required_proposal_and_final_use_their_exact_separate_approvals(self):
        operation = 'reviewed-policy'
        state = self._gateway_authority_record['state']
        grant = next(grant for grant in state['grants'] if grant['ref'] == support.policy_support.ref('configuration-set'))
        grant['decision'] = 'review-required'
        approve = copy.deepcopy(grant)
        approve.update(ref=support.policy_support.ref('approve-policy'), contractId='identity-approve',
            resourceId='configuration-set', decision='allowed')
        state['grants'].append(approve)
        change = {'verb': 'trust', 'arguments': {'peer': 'alice', 'level': 'flag'}}
        desired = support.changed_policy(self.old, change, repository=self.repository)
        proposal = self.owner.preparation_bytes(previous_revision=0, old_policy=self.old, desired_policy=desired, change=change)
        route = self.key.selection['federationPolicyCommands']
        self.add_approval('approved-proposal', operation, self.client._payload(route, 0, proposal))
        # The controlled authority issues a distinct final approval only after
        # receiving the actual prepared descriptor, never for proposal bytes.
        self.issued_approval = operation
        args = {'peer': 'alice', 'level': 'flag', 'operationId': operation,
            'preparationApprovalRefs': [support.policy_support.ref('approved-proposal')],
            'approvalRefs': [support.policy_support.ref('approved-final')]}
        result = await self.request_hub(args)
        self.assertTrue(result['ok'], result)
        signed = [item for item in self.commands if item['contractId'] == 'configuration-set']
        self.assertEqual(signed[0]['approvalRefs'], args['preparationApprovalRefs'])
        self.assertEqual(signed[1]['approvalRefs'], args['approvalRefs'])
        self.assertNotEqual(payload_digest(signed[0]['payload']), payload_digest(signed[1]['payload']))
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_legacy_completed_record_is_reconciled_without_discarding_original_pair(self):
        args = {'peer': 'alice', 'level': 'flag'}
        self.assertTrue((await self.request_hub(args))['ok'])
        original = self.retained()
        original['formatVersion'] = 1
        original.pop('requestDigest')
        enrollment = strict_loads(self.client._routes[0][1])
        await self.hub.db(self.hub.store.db.execute, 'UPDATE fed_state SET v=? WHERE k=?',
            (canonical_bytes(original).decode(), self.client._key(enrollment)))
        await self.restart_client()
        self.assertTrue((await self.request_hub(args))['ok'])
        self.assertEqual(self.retained(), original)
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_lost_preparation_restart_keeps_original_proposal_and_operation(self):
        args = {'peer': 'alice', 'level': 'flag'}
        self.drop_prepared_reply = True
        self.assertFalse((await self.request_hub(args))['ok'])
        original = self.retained()
        self.assertEqual(original['phase'], 'preparing')
        self.assertEqual(self.fixture.js.messages, [])
        await self.restart_client(fresh_session=True)
        self.assertTrue((await self.request_hub(args))['ok'])
        self.assertEqual(self.retained()['operationId'], original['operationId'])
        self.assertEqual(self.retained()['proposal'], original['proposal'])
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_committed_but_unprojected_original_waits_for_distinct_service_recovery(self):
        args = {'peer': 'alice', 'level': 'flag'}
        self.commit_without_projection = True
        self.assertFalse((await self.request_hub(args))['ok'])
        original = self.retained()
        self.assertEqual(original['phase'], 'committing')
        self.assertEqual(len(self.fixture.js.messages), 1)
        self.assertEqual(self.path.read_bytes(), self.old)
        await self.restart_client(fresh_session=True)
        self.assertFalse((await self.request_hub(args))['ok'])
        self.assertEqual(self.retained(), original)
        self.assertEqual(len([item for item in self.commands if item['contractId'] == 'configuration-set']), 2)
        grant = copy.deepcopy(self.backup_grant)
        grant.update(ref=support.policy_support.ref('policy-project'), contractId='federation-policy-project')
        self._gateway_authority_record['state']['grants'].append(grant)
        self.replace_authority()
        desired = support.changed_policy(self.old, original['change'], repository=self.repository)
        project = await self.project_request(self.unprojected, desired)
        await self.transition.project(project)
        self.assertTrue((await self.request_hub(args))['ok'])
        self.assertEqual(self.retained()['operationId'], original['operationId'])
        self.assertEqual(self.retained()['finalPayload'], original['finalPayload'])
        self.assertEqual(self.retained()['phase'], 'committed')
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_fresh_read_metadata_reuses_current_effect_but_new_change_advances(self):
        args = {'peer': 'alice', 'level': 'flag'}
        self.assertTrue((await self.request_hub(args))['ok'])
        original = self.retained()
        self.assertTrue((await self.request_hub(dict(args, readOperationId='fresh-current-read')))['ok'])
        self.assertEqual(self.retained(), original)
        self.assertEqual(len(self.fixture.js.messages), 1)
        self.assertTrue((await self.request_hub(dict(args, level='deny')))['ok'])
        self.assertEqual(self.retained()['change']['arguments']['level'], 'deny')
        self.assertEqual(self.retained()['result']['revision'], 2)
        self.assertNotEqual(self.retained()['operationId'], original['operationId'])
        self.assertEqual(len(self.fixture.js.messages), 2)

    async def test_substituted_local_final_payload_refuses_before_another_command(self):
        args = {'peer': 'alice', 'level': 'flag'}
        self.assertTrue((await self.request_hub(args))['ok'])
        value = self.retained()
        value['finalPayload']['configurationBytes'] = base64.b64encode(b'{}').decode()
        enrollment = strict_loads(self.client._routes[0][1])
        await self.hub.db(self.hub.store.db.execute, 'UPDATE fed_state SET v=? WHERE k=?',
            (canonical_bytes(value).decode(), self.client._key(enrollment)))
        count = len(self.commands)
        result = await self.request_hub(args)
        self.assertFalse(result['ok'])
        self.assertIn('policy_client_conflict', result['error'])
        self.assertEqual(len(self.commands), count)
        self.assertEqual(len(self.fixture.js.messages), 1)

    async def test_invalid_recovery_metadata_refuses_before_using_or_poisoning_session(self):
        args = {'peer': 'alice', 'level': 'flag'}
        for invalid in ({'operationId': 'bad.operation'}, {'readOperationId': 1},
                {'approvalRefs': 'approval'},
                {'preparationApprovalRefs': [{'id': 'approval', 'ownerHubId': 'other', 'revision': 1}]}):
            self.assertFalse((await self.request_hub(dict(args, **invalid)))['ok'])
            self.assertIsNone(self.session._command_future)
            self.assertIsNone(self.retained())
        self.assertEqual(self.commands, [])
        self.assertTrue((await self.request_hub(args))['ok'])
        self.assertEqual(len(self.fixture.js.messages), 1)
