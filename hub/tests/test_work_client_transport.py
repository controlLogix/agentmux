"""Work route signing and retained transport lifetime with controlled broker I/O."""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from hub.client_launch_connection import ConnectionFailure, MessageOutcomeUnconfirmed, selected_publish_subjects
from hub.client_launch_session import ApplicationClientSession, ApplicationSessionFailure
from hub.tests import test_client_launch_connection as connection_support
from hub.tests import test_client_launch_session as session_support
from identity.application_client import ApplicationClientKey, provision_application_client
from identity.test_authority import SEED, ref, fixture as authority_fixture
from identity.test_knowledge_client import material as knowledge_material


def material(*, aggregate=False):
    value = knowledge_material()
    route = value.pop('knowledgeCommands')
    route.update(transportRef=ref('work-transport'), localPeer=None,
        repository={'localName': 'falcon', 'repositoryId': None},
        grantRefs={'federation-work-' + name: ref('work-' + name)
            for name in ('create', 'read', 'inspect', 'outcome')})
    value['workCommands'] = route
    if aggregate:
        value['scope']['projectId'] = None
        route.update(repository=None,
            subject='amx.v1.h.hub-one.o.org-one.p._.w._.capability.storage-owner.command')
        route['grantRefs'].pop('federation-work-create')
    return value


def payload(action='read'):
    value = {'resourceRef': ref('task-one'), 'input': {'query': {'kind': 'list', 'state': None}}}
    if action == 'create':
        value.update(attribution='operator', input={'target': 'role:worker', 'title': 'Original work'})
    elif action == 'inspect':
        value['input'] = {}
    elif action == 'outcome':
        value['input'] = {'contractId': 'federation-work-create', 'operationId': 'original-work',
            'payloadDigest': 'sha256:' + 'a' * 64}
    return value


def claims(key, *, action='read', now=None):
    now = now or datetime.now(timezone.utc)
    route = key.selection['workCommands']
    contract = 'federation-work-' + action
    return {'purpose': 'agentmux-client-possession-v1',
        **{k: key.selection[k] for k in ('hubId', 'profileId', 'authorityId')},
        'transportRef': route['transportRef'], 'grantRef': route['grantRefs'][contract],
        'contractId': contract, 'operationId': action + '-work', 'expectedVersion': 1,
        'payload': payload(action), 'approvalRefs': [], 'replySubject': '_INBOX.abcdefghijklmnop.request_one',
        'issuedAt': now.isoformat().replace('+00:00', 'Z'),
        'expiresAt': (now + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z')}


def signed_reply(request):
    packet = strict_loads(request)
    wanted = packet['claims']
    value = {k: wanted[k] for k in ('hubId', 'profileId', 'authorityId', 'operationId', 'replySubject')}
    value.update(purpose='agentmux-legacy-work-response-v1',
        serviceIdentityRef=ref('service'), serviceInstanceId='ingress-one', signingKeyRef=ref('issuer'),
        requestContractId=wanted['contractId'], requestDigest=payload_digest(packet),
        payloadDigest=payload_digest(wanted['payload']), resourceRef=wanted['payload']['resourceRef'],
        authorityRef=ref('authority-one'), issuedAt=wanted['issuedAt'], validUntil=wanted['expiresAt'],
        result={'row': {'id': 'work-one', 'title': 'Original work'}})
    return canonical_bytes({'schemaVersion': '1.0.0', 'claims': value, 'signature': sign_claims(value, SEED)})


class WorkSigningTests(unittest.TestCase):
    def test_local_and_aggregate_enrollments_have_exact_routes_without_secrets(self):
        for aggregate in (False, True):
            key = ApplicationClientKey(material(aggregate=aggregate))
            selected = key.selection
            self.assertNotIn('seed', selected)
            route = selected['workCommands']
            self.assertEqual(key.command_subject('federation-work-read'), route['subject'])
            self.assertIn(route['subject'], selected_publish_subjects(key))
            self.assertNotIn('>', '.'.join(selected_publish_subjects(key)))
            self.assertIsNone(route['localPeer'])
            self.assertEqual(route['repository'], None if aggregate else {'localName': 'falcon', 'repositoryId': None})

    def test_provisioning_enrolls_distinct_work_transport_with_possession_proof(self):
        value = material()
        selection = {k: v for k, v in value.items() if k not in ('seed', 'purpose')}
        now = datetime.now(timezone.utc)
        with patch('identity.application_client._write_material') as write:
            enrolled = provision_application_client('/private/client-key', selection=selection,
                identity=authority_fixture()[0]['state']['identities'][0],
                issued_at=now.isoformat().replace('+00:00', 'Z'),
                expires_at=(now + timedelta(seconds=4)).isoformat().replace('+00:00', 'Z'))
        retained_key = ApplicationClientKey(write.call_args.args[1])
        transports = enrolled['transports']
        self.assertEqual([entry['record']['ref'] for entry in transports],
            [selection['transportRef'], selection['workCommands']['transportRef']])
        command_transport = transports[1]
        self.assertEqual(command_transport['record']['issuerRef'], selection['replyIssuerRef'])
        from identity.ingress import verify_possession
        proof = {'purpose': 'agentmux-enrollment-possession-v1', 'profileId': selection['profileId'],
            'authorityId': selection['authorityId'], 'credential': command_transport['record']}
        verify_possession(proof, command_transport['proof'], retained_key.public_key)

    def test_enrollment_refuses_substituted_subject_or_shared_transport(self):
        for change in ('subject', 'transport'):
            value = material()
            route = value['workCommands']
            if change == 'subject':
                route['subject'] += '.other'
            else:
                route['transportRef'] = value['transportRef']
            with self.assertRaises(ContractError):
                ApplicationClientKey(value)

    def test_signer_preserves_request_and_refuses_changed_route_grant_resource_and_proof(self):
        key = ApplicationClientKey(material())
        route = key.selection['workCommands']
        now = datetime.now(timezone.utc)
        original = claims(key, now=now)
        raw = key.sign_command(original, subject=route['subject'], now=now)
        self.assertEqual(key.verify_command_request(raw, subject=route['subject'])[0]['claims'], original)
        for field in ('grantRef', 'transportRef', 'resourceRef', 'subject'):
            changed = copy.deepcopy(original)
            subject = route['subject']
            if field in ('grantRef', 'transportRef'):
                changed[field] = ref('foreign')
            elif field == 'resourceRef':
                changed['payload'][field] = ref('foreign')
            else:
                subject += '.other'
            with self.assertRaises(ContractError):
                key.sign_command(changed, subject=subject, now=now)
        changed = strict_loads(raw)
        changed['claims']['payload']['input']['query']['state'] = 'done'
        with self.assertRaises(ContractError):
            key.verify_command_request(canonical_bytes(changed), subject=route['subject'])

    def test_write_read_and_outcome_private_validity_and_original_bindings(self):
        key = ApplicationClientKey(material())
        subject = key.selection['workCommands']['subject']
        for action in ('create', 'read', 'outcome'):
            with self.subTest(action=action):
                now = datetime.now(timezone.utc)
                raw = key.sign_command(claims(key, action=action, now=now), subject=subject, now=now)
                response = signed_reply(raw)
                result = key.verify_command_response(response, raw, subject=subject, now=now)
                private = key.verify_command_response(response, raw, subject=subject, now=now, include_valid_until=True)
                self.assertEqual(private['result'], result)
                self.assertNotIn('validUntil', result)
                self.assertEqual(private['validUntil'], strict_loads(raw)['claims']['expiresAt'])
                substituted = claims(key, action=action, now=now)
                substituted['operationId'] = 'substituted'
                substituted = key.sign_command(substituted, subject=subject, now=now)
                with self.assertRaises(ContractError):
                    key.verify_command_response(response, substituted, subject=subject, now=now)
                with self.assertRaises(ContractError):
                    key.verify_command_response(response, raw, subject=subject, now=now + timedelta(seconds=5))


class WorkConnectionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = connection_support.ClientLaunchConnection()
        await self.fixture.asyncSetUp()
        self.owner, self.client = self.fixture.owner, self.fixture.client
        await self.fixture.connect()
        self.fixture.exchange_fixture()
        self.key = ApplicationClientKey(material())
        self.owner._signer = self.key
        self.owner._publish_subjects = selected_publish_subjects(self.key)
        self.client.max_payload = 1048576
        self.expiry = (datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat()
        self.owner._current_command_binding = AsyncMock(return_value={'validUntil': self.expiry})
        self.owner._require_query_binding = Mock(return_value={'validUntil': self.expiry})
        self.requests = []
        async def publish(subject, raw, *, reply):
            self.assertEqual(subject, self.key.selection['workCommands']['subject'])
            self.requests.append(raw)
            self.fixture.subscription.next_msg.return_value = SimpleNamespace(subject=reply, data=signed_reply(raw))
        self.client.publish.side_effect = publish
        self.addAsyncCleanup(self.owner.close, deadline=self.fixture.deadline(10))

    async def command(self, *, action='read', include_valid_until=False):
        return await self.owner.work_command(contract_id='federation-work-' + action,
            operation_id='original-work', payload=payload(action), expires_at=self.expiry,
            deadline=self.fixture.deadline(2), cleanup_deadline=self.fixture.deadline(3),
            include_valid_until=include_valid_until)

    async def test_work_commands_preserve_signed_request_and_private_write_validity(self):
        value = await self.command(action='create', include_valid_until=True)
        self.assertEqual(value['result']['row']['id'], 'work-one')
        self.assertEqual(self.owner.command_request, self.requests[0])
        self.assertEqual(strict_loads(self.requests[0])['claims']['payload'], payload('create'))
        self.assertEqual(self.client.subscribe.call_args.kwargs['pending_bytes_limit'], 1048576)
        self.assertFalse(self.owner._subscriptions)
        self.assertIsNone(self.owner._exchange_task)
        self.client.close.assert_not_awaited()
        self.owner._current_command_binding.assert_awaited_once()

    async def test_lost_reply_joins_original_and_allows_fresh_authorized_outcome(self):
        self.fixture.subscription.next_msg.side_effect = TimeoutError()
        with self.assertRaises(MessageOutcomeUnconfirmed):
            await self.command(action='create')
        original = self.owner.command_request
        self.assertEqual(original, self.requests[0])
        self.assertFalse(self.owner._subscriptions)
        self.assertIsNone(self.owner._exchange_task)
        self.fixture.subscription.unsubscribe.assert_awaited_once()
        self.client.close.assert_not_awaited()
        self.fixture.subscription.next_msg.side_effect = None
        recovered = await self.command(action='outcome', include_valid_until=True)
        self.assertEqual(recovered['result']['row']['id'], 'work-one')
        self.assertNotEqual(self.requests[1], original)
        self.assertEqual(len(self.requests), 2)

    async def test_verified_joined_reply_crossing_final_deadline_keeps_recovery_connection(self):
        deadline = self.fixture.deadline(0.75)
        cleanup_deadline = self.fixture.deadline(3)
        verified = []
        verify = self.key.verify_command_response
        check_binding = self.owner._require_query_binding
        def verify_original(*args, **kwargs):
            result = verify(*args, **kwargs)
            verified.append(result)
            return result
        def check_original(epoch):
            result = check_binding(epoch)
            if verified:
                # Model work after valid checks, without extending either deadline.
                while time.monotonic() <= deadline:
                    time.sleep(0.001)
            return result
        with patch.object(self.key, 'verify_command_response', side_effect=verify_original), \
                patch.object(self.owner, '_require_query_binding', side_effect=check_original):
            with self.assertRaises(ConnectionFailure) as caught:
                await self.owner.work_command(contract_id='federation-work-inspect',
                    operation_id='original-work', payload=payload('inspect'),
                    expires_at=self.expiry, deadline=deadline, cleanup_deadline=cleanup_deadline)
        self.assertEqual(len(verified), 1)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.owner.command_request, self.requests[0])
        self.assertIsNone(self.owner._exchange_task)
        self.assertFalse(self.owner._subscriptions)
        self.fixture.subscription.unsubscribe.assert_awaited_once()
        self.assertIs(type(caught.exception._cause), ConnectionFailure)
        self.assertEqual(str(caught.exception._cause), 'application_connection_deadline')
        self.assertIs(type(caught.exception), MessageOutcomeUnconfirmed)
        self.client.close.assert_not_awaited()
        recovered = await self.command(action='outcome', include_valid_until=True)
        self.assertEqual(recovered['result']['row']['id'], 'work-one')
        self.assertEqual(len(self.requests), 2)

    async def test_cancellation_joins_original_exchange_before_closing_connection(self):
        entered, joined = asyncio.Event(), asyncio.Event()
        async def pending_reply(**_options):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                joined.set()
        self.fixture.subscription.next_msg.side_effect = pending_reply
        original = asyncio.create_task(self.command(action='create'))
        await entered.wait()
        exchange = self.owner._exchange_task
        retained = self.owner.command_request
        original.cancel()
        with self.assertRaises(ConnectionFailure):
            await original
        self.assertTrue(joined.is_set())
        self.assertTrue(exchange.done())
        self.assertIs(self.owner._exchange_task, exchange)
        self.assertEqual(self.owner.command_request, retained)
        self.assertEqual(self.requests, [retained])
        self.fixture.subscription.unsubscribe.assert_awaited_once()
        self.client.close.assert_awaited_once()

    async def test_post_reply_binding_deadline_failure_still_closes_connection(self):
        verify = self.key.verify_command_response
        verified = []
        def verify_original(*args, **kwargs):
            result = verify(*args, **kwargs)
            verified.append(result)
            return result
        def binding(_epoch):
            if verified:
                raise ConnectionFailure('application_connection_deadline', self.owner)
            return {'validUntil': self.expiry}
        with patch.object(self.key, 'verify_command_response', side_effect=verify_original), \
                patch.object(self.owner, '_require_query_binding', side_effect=binding):
            with self.assertRaises(ConnectionFailure) as caught:
                await self.command(action='inspect')
        self.assertIs(type(caught.exception), ConnectionFailure)
        self.assertEqual(str(caught.exception._cause), 'application_connection_deadline')
        self.assertEqual(len(verified), 1)
        self.client.close.assert_awaited_once()

    async def test_invalid_signed_reply_still_closes_connection(self):
        async def publish(subject, raw, *, reply):
            self.requests.append(raw)
            response = strict_loads(signed_reply(raw))
            response['claims']['operationId'] = 'substituted-operation'
            self.fixture.subscription.next_msg.return_value = SimpleNamespace(
                subject=reply, data=canonical_bytes(response))
        self.client.publish.side_effect = publish
        with self.assertRaises(ConnectionFailure) as caught:
            await self.command(action='inspect')
        self.assertIs(type(caught.exception), ConnectionFailure)
        self.assertIsInstance(caught.exception._cause, ContractError)
        self.assertEqual(len(self.requests), 1)
        self.client.close.assert_awaited_once()

    async def test_expired_effect_authority_never_publishes_and_failure_is_secret_free(self):
        self.expiry = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        with self.assertRaises(ConnectionFailure) as failure:
            await self.command(action='create')
        self.assertEqual(str(failure.exception), 'application_command_unconfirmed')
        self.assertNotIn('Original work', repr(failure.exception))
        self.client.publish.assert_not_awaited()
        self.client.close.assert_awaited_once()


class WorkSessionTests(unittest.TestCase):
    def test_read_binding_timeouts_retain_closed_owner_and_original_future(self):
        for stage in ('discovery', 'binding'):
            with self.subTest(stage=stage):
                fixture = connection_support.ClientLaunchConnection()
                session_fixture = session_support.ClientLaunchSession()
                session = ApplicationClientSession(session_fixture.selected())
                entered, finished = threading.Event(), threading.Event()
                observations = []

                async def opening(*_args, **_kwargs):
                    await fixture.asyncSetUp()
                    admission_key = fixture.authentication_fixture()
                    value = material(aggregate=True)
                    value.update(admission_key.selection)
                    key = ApplicationClientKey(value)
                    fixture.owner._signer = key
                    fixture.owner._publish_subjects = selected_publish_subjects(key)
                    fixture.client.max_payload = 1048576
                    original_subscribe = fixture.client.subscribe.side_effect

                    async def subscribe(subject, **options):
                        subscription = await original_subscribe(subject, **options)
                        receive = subscription.next_msg.side_effect

                        async def next_msg(**arguments):
                            request = strict_loads(fixture.requests[-1])['claims']
                            if request['purpose'] == 'agentmux-application-' + stage + '-request-v1':
                                observations.append(request)
                                entered.set()
                                # The real exchange deadline ends this wait.
                                await asyncio.Event().wait()
                            return await receive(**arguments)

                        subscription.next_msg.side_effect = next_msg
                        return subscription

                    fixture.client.subscribe.side_effect = subscribe
                    await fixture.connect()
                    return fixture.owner

                with patch('hub.client_launch_session.open_application_client', side_effect=opening):
                    session.start(deadline=time.monotonic() + 4)
                try:
                    arguments = self.arguments(action='read')
                    frozen = canonical_bytes(arguments)
                    with self.assertRaises(ApplicationSessionFailure):
                        session.work_command(**arguments, deadline=time.monotonic() + .5)
                    self.assertTrue(entered.wait(1))
                    original, identity = session._command_future, session._command_identity
                    original.add_done_callback(lambda _future: finished.set())
                    self.assertTrue(finished.wait(2))
                    error = original.exception()
                    self.assertIs(type(error), ConnectionFailure)
                    self.assertEqual(str(error), 'application_command_unconfirmed')
                    self.assertEqual(str(error._cause), 'application_binding_unavailable')
                    self.assertEqual(str(error._cause._cause), 'application_request_unconfirmed')
                    self.assertIsInstance(error._cause._cause._cause, TimeoutError)
                    self.assertEqual(len(observations), 1)
                    self.assertEqual(len(fixture.requests), 1 if stage == 'discovery' else 2)
                    self.assertTrue(all('contractId' not in strict_loads(raw)['claims']
                                        for raw in fixture.requests))
                    self.assertIsNone(fixture.owner.command_request)
                    self.assertTrue(fixture.owner._closing)
                    self.assertTrue(fixture.owner._close_task.done())
                    self.assertIsNone(fixture.owner._close_task.exception())
                    self.assertTrue(fixture.owner._exchange_task.done())
                    self.assertFalse(fixture.owner._subscriptions)
                    fixture.client.close.assert_awaited_once()
                    before = tuple(fixture.requests)
                    with self.assertRaises(ApplicationSessionFailure) as refusal:
                        session.work_command(**self.arguments(action='inspect'))
                    diagnostic = refusal.exception._command_diagnostic
                    self.assertEqual(diagnostic['stage'], 'identity-mismatch')
                    self.assertEqual(diagnostic['futureContract'], 'federation-work-read')
                    self.assertEqual(diagnostic['futureState'], 'done')
                    self.assertGreater(diagnostic['deadlineRemaining'], 0)
                    self.assertIs(session._command_future, original)
                    self.assertIs(session._command_identity, identity)
                    self.assertEqual(tuple(fixture.requests), before)
                    self.assertEqual(canonical_bytes(arguments), frozen)
                finally:
                    self.assertTrue(session.close(deadline=time.monotonic() + 4))
                    session.join_final()
                    self.assertFalse(session._thread.is_alive())

    def test_actual_owner_final_deadline_allows_original_operation_outcome(self):
        fixture = WorkConnectionTests()
        session_fixture = session_support.ClientLaunchSession()
        session = ApplicationClientSession(session_fixture.selected())
        verified, active_command = [], []
        async def opening(*_args, **_kwargs):
            await fixture.asyncSetUp()
            owner = fixture.owner
            original_command = owner.work_command
            original_verify = fixture.key.verify_command_response
            original_binding = owner._require_query_binding
            async def command(**arguments):
                active_command[:] = [arguments['deadline'], arguments['contract_id']]
                return await original_command(**arguments)
            def verify(*args, **kwargs):
                result = original_verify(*args, **kwargs)
                verified.append(result)
                return result
            def binding(epoch):
                result = original_binding(epoch)
                if len(verified) == 1 and active_command[1] == 'federation-work-create':
                    while time.monotonic() <= active_command[0]:
                        time.sleep(0.001)
                return result
            owner.work_command = command
            fixture.key.verify_command_response = verify
            owner._require_query_binding = binding
            return owner
        with patch('hub.client_launch_session.open_application_client', side_effect=opening):
            session.start(deadline=time.monotonic() + 4)
        try:
            original = self.arguments(action='create')
            with self.assertRaises(ApplicationSessionFailure):
                session.work_command(**original, deadline=time.monotonic() + 0.25)
            retained = session._command_future
            if retained is not None:
                finished = threading.Event()
                retained.add_done_callback(lambda _future: finished.set())
                self.assertTrue(finished.wait(2))
                self.assertIs(type(retained.exception()), MessageOutcomeUnconfirmed)
            fixture.client.close.assert_not_awaited()
            query = self.arguments(action='outcome')
            query['payload']['input']['payloadDigest'] = payload_digest(original['payload'])
            result = session.work_command(**query)
            self.assertEqual(result['row']['id'], 'work-one')
            self.assertEqual(len(fixture.requests), 2)
            first, second = [strict_loads(raw)['claims'] for raw in fixture.requests]
            self.assertEqual(first['operationId'], original['operation_id'])
            self.assertEqual(first['payload'], original['payload'])
            self.assertEqual(first['contractId'], 'federation-work-create')
            self.assertEqual(second['contractId'], 'federation-work-outcome')
            self.assertEqual(second['payload']['input']['operationId'], original['operation_id'])
            self.assertEqual(second['payload']['input']['payloadDigest'], payload_digest(first['payload']))
            self.assertIsNone(session._command_future)
        finally:
            self.assertTrue(session.close(deadline=time.monotonic() + 4))
            session.join_final()
            self.assertFalse(session._thread.is_alive())

    def open_session(self, work_command):
        fixture = session_support.ClientLaunchSession()
        key = ApplicationClientKey(material())
        owner = fixture.owner(enrollment=key.selection)
        owner.work_command = work_command
        session = ApplicationClientSession(fixture.selected())
        async def opening(*_args, **_kwargs):
            return owner
        with patch('hub.client_launch_session.open_application_client', side_effect=opening):
            session.start(deadline=time.monotonic() + 3)
        self.addCleanup(session.join_final)
        return session, owner

    def arguments(self, *, action='read'):
        return {'contract_id': 'federation-work-' + action, 'operation_id': 'original-work',
            'payload': payload(action), 'expires_at': (datetime.now(timezone.utc) + timedelta(seconds=4)).isoformat()}

    def test_public_enrollment_and_private_write_validity_use_same_owner_loop(self):
        calls = []
        async def command(**arguments):
            calls.append((threading.get_ident(), arguments))
            return {'result': {'row': {'id': 'work-one'}}, 'validUntil': arguments['expires_at']}
        session, owner = self.open_session(command)
        selected = session.work_enrollment()
        self.assertNotIn('seed', selected)
        selected['workCommands']['localNode'] = 'substituted'
        self.assertEqual(session.work_enrollment()['workCommands']['localNode'], 'mac')
        result = session.work_command(**self.arguments(action='create'), include_valid_until=True)
        self.assertEqual(result['result']['row']['id'], 'work-one')
        self.assertTrue(calls[0][1]['include_valid_until'])
        self.assertEqual(calls[0][0], session._thread.ident)
        self.assertEqual(owner.close_calls, 0)

    def test_waiter_timeout_retains_original_and_cannot_submit_a_replacement(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        async def command(**arguments):
            calls.append(arguments)
            entered.set()
            while not release.is_set():
                await asyncio.sleep(0.001)
            return {'row': {'id': 'work-one'}}
        session, _ = self.open_session(command)
        arguments = self.arguments(action='create')
        try:
            with self.assertRaises(ApplicationSessionFailure):
                session.work_command(**arguments, deadline=time.monotonic() + 0.05)
            self.assertTrue(entered.is_set())
            original = session._command_future
            with self.assertRaises(ApplicationSessionFailure):
                session.work_command(**{**arguments, 'operation_id': 'replacement'}, deadline=time.monotonic() + 0.1)
            self.assertIs(session._command_future, original)
            release.set()
            self.assertEqual(session.work_command(**arguments)['row']['id'], 'work-one')
            self.assertEqual(len(calls), 1)
        finally:
            release.set()

    def test_joined_lost_reply_allows_fresh_outcome_but_other_failure_is_retained(self):
        calls = []
        async def command(**arguments):
            calls.append(arguments)
            if len(calls) == 1:
                raise MessageOutcomeUnconfirmed('application_message_outcome_unconfirmed', None)
            return {'row': {'id': 'work-one'}}
        session, _ = self.open_session(command)
        with self.assertRaises(ApplicationSessionFailure):
            session.work_command(**self.arguments(action='create'))
        self.assertIsNone(session._command_future)
        self.assertEqual(session.work_command(**self.arguments(action='outcome'))['row']['id'], 'work-one')
        self.assertEqual(len(calls), 2)

    def test_unjoined_failure_cannot_be_replaced(self):
        async def command(**_arguments):
            raise ConnectionFailure('application_connection_cleanup_pending', None)
        session, _ = self.open_session(command)
        with self.assertRaises(ApplicationSessionFailure):
            session.work_command(**self.arguments(action='create'))
        original = session._command_future
        with self.assertRaises(ApplicationSessionFailure):
            session.work_command(**self.arguments(action='outcome'))
        self.assertIs(session._command_future, original)
